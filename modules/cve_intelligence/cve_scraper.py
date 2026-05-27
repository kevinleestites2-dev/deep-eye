"""
CVE Intelligence Scraper
Scrapes CVE data from multiple sources and stores in SQLite database
Enhanced with Playwright for NIST, MITRE API, and Exploit-DB integration

Features:
- Multi-source scraping (NIST NVD, MITRE, Exploit-DB, CISA KEV, GitHub)
- Intelligent caching with 7-day refresh
- Async HTTP requests for performance
- Browser automation for dynamic content
- RSS feed monitoring for latest vulnerabilities
"""

import sqlite3
import json
import time
import requests
import re
import asyncio
import aiohttp
import os
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from utils.logger import get_logger

logger = get_logger(__name__)

# Optional dependencies (graceful degradation if not available)
try:
    from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not available - enhanced scraping features disabled")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logger.warning("BeautifulSoup not available - HTML parsing features limited")


class CVEScraper:
    """Scrape and manage CVE intelligence database with multi-source support."""
    
    # Additional CVE data sources beyond API
    CVE_SOURCES = {
        "nvd_web": {
            "url": "https://nvd.nist.gov/vuln/detail/{cve_id}",
            "type": "html",
            "description": "National Vulnerability Database (Web)"
        },
        "cve_mitre": {
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "type": "html",
            "description": "MITRE CVE Dictionary"
        },
        "vulners": {
            "url": "https://vulners.com/search?query={cve_id}",
            "type": "html",
            "description": "Vulners Database"
        },
        "github_poc": {
            "url": "https://github.com/search?q={cve_id}+poc",
            "type": "html",
            "description": "GitHub PoC Search"
        }
    }
    
    # Sources for latest vulnerabilities
    LATEST_VULN_SOURCES = {
        "nvd_rss": {
            "url": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
            "type": "rss",
            "description": "NVD RSS Feed"
        },
        "cisa_kev": {
            "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "type": "json",
            "description": "CISA Known Exploited Vulnerabilities"
        }
    }
    
    def __init__(self, db_path: str = "data/cve_intelligence.db", use_browser: bool = False):
        """
        Initialize CVE scraper with database path.
        
        Args:
            db_path: Path to SQLite database
            use_browser: Enable Playwright-based browser scraping for enhanced data collection
        """
        self.db_path = db_path
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        })
        
        # Multi-source configuration
        self.cve_sources = self.CVE_SOURCES
        self.latest_vuln_sources = {
            "nvd_rss": "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
            "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        }
        
        # Playwright browser (lazy initialization)
        self.playwright = None
        self.browser = None
        self.use_browser = use_browser and PLAYWRIGHT_AVAILABLE
        
        if self.use_browser:
            logger.info("Playwright-based enhanced scraping enabled")
        
        # Create database directory if not exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Cache directory for scraped data
        self.cache_dir = Path(db_path).parent / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
    
    async def _get_browser(self):
        """Get or initialize Playwright browser."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.error("Playwright not available - install with: pip install playwright && playwright install")
            return None
        
        if not self.browser:
            try:
                self.playwright = await async_playwright().start()
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=['--disable-gpu', '--no-sandbox']
                )
                logger.info("Playwright browser initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Playwright browser: {e}")
                return None
        
        return self.browser
    
    async def _close_browser(self):
        """Close Playwright browser and cleanup."""
        if self.browser:
            try:
                await self.browser.close()
            except Exception:
                pass
        if self.playwright:
            try:
                await self.playwright.stop()
            except Exception:
                pass
    
    def _init_database(self):
        """Initialize CVE database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # CVE table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_entries (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                cvss_vector TEXT,
                published_date TEXT,
                modified_date TEXT,
                affected_products TEXT,
                attack_vector TEXT,
                exploit_available BOOLEAN,
                reference_urls TEXT,
                cwe_id TEXT,
                assigner_org TEXT,
                vendor TEXT,
                product TEXT,
                versions TEXT,
                problem_type TEXT,
                raw_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Check if cve_exploits needs migration for unique constraint
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='cve_exploits'")
        result = cursor.fetchone()
        needs_migration = False
        
        if result:
            table_sql = result[0]
            # Check if UNIQUE constraint exists
            if 'UNIQUE' not in table_sql.upper():
                needs_migration = True
                logger.info("Migrating cve_exploits table to add unique constraint...")
                
                # Create new table with unique constraint
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cve_exploits_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT,
                        exploit_type TEXT,
                        exploit_payload TEXT,
                        exploit_description TEXT,
                        exploit_date TEXT,
                        exploit_platform TEXT,
                        exploit_author TEXT,
                        download_link TEXT,
                        title_link TEXT,
                        source TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id),
                        UNIQUE(cve_id, exploit_description, exploit_type)
                    )
                ''')
                
                # Copy unique records only (excluding ID and created_at to let them auto-generate)
                cursor.execute('''
                    INSERT OR IGNORE INTO cve_exploits_new 
                    (cve_id, exploit_type, exploit_payload, exploit_description, exploit_date, 
                     exploit_platform, exploit_author, download_link, title_link, source)
                    SELECT DISTINCT cve_id, exploit_type, exploit_payload, exploit_description, 
                           exploit_date, exploit_platform, exploit_author, download_link, 
                           title_link, source
                    FROM cve_exploits
                    GROUP BY cve_id, exploit_description, exploit_type
                ''')
                
                duplicates_removed = cursor.execute('SELECT COUNT(*) FROM cve_exploits').fetchone()[0] - \
                                   cursor.execute('SELECT COUNT(*) FROM cve_exploits_new').fetchone()[0]
                
                # Drop old table and rename new one
                cursor.execute('DROP TABLE cve_exploits')
                cursor.execute('ALTER TABLE cve_exploits_new RENAME TO cve_exploits')
                
                logger.info(f"Migration completed - removed {duplicates_removed} duplicates")
        
        if not needs_migration:
            # CVE exploits table with unique constraint
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cve_exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    exploit_type TEXT,
                    exploit_payload TEXT,
                    exploit_description TEXT,
                    exploit_date TEXT,
                    exploit_platform TEXT,
                    exploit_author TEXT,
                    download_link TEXT,
                    title_link TEXT,
                    source TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id),
                    UNIQUE(cve_id, exploit_description, exploit_type)
                )
            ''')
        
        # Technology mapping table with unique constraint
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT,
                technology TEXT,
                version_affected TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id),
                UNIQUE(cve_id, technology)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON cve_entries(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_published ON cve_entries(published_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_technology ON cve_technologies(technology)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cvss_score ON cve_entries(cvss_score)')
        
        conn.commit()
        conn.close()
        logger.info(f"CVE database initialized: {self.db_path}")
    
    def validate_cve(self, cve_id: str) -> tuple[bool, Optional[str]]:
        """
        Validate the format and year of a CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        pattern = r"CVE-(\d{4})-(\d{4,})"
        match = re.match(pattern, cve_id)
        
        if not match:
            return False, "Invalid format. Correct format is CVE-YYYY-XXXX."
        
        year = int(match.group(1))
        sequence = int(match.group(2))
        current_year = datetime.now().year
        
        # Validate year
        if year < 1999 or year > current_year:
            return False, f"Year should be between 1999 and {current_year}."
        
        # Validate sequence number
        if sequence < 1:
            return False, "Sequence number (XXXX) must be 0001 or higher."
        
        return True, None
    
    def check_cve_status(self, cve_id: str) -> Optional[str]:
        """
        Check the status of a CVE ID (PUBLISHED, RESERVED, REJECTED).
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            CVE status or None if check fails
        """
        try:
            url = f"https://cveawg.mitre.org/api/cve-id/{cve_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('state')
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to check CVE status for {cve_id}: {e}")
            return None
    
    async def _validate_link_async(self, session: aiohttp.ClientSession, link: str) -> bool:
        """Asynchronously validate if a link is accessible."""
        try:
            async with session.get(link, timeout=aiohttp.ClientTimeout(total=20)) as response:
                return response.status == 200
        except Exception:
            return False
    
    async def fetch_nist_data_browser(self, cve_id: str) -> Dict:
        """
        Fetch detailed CVE data from NIST using Playwright.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary containing NIST CVE data
        """
        if not self.use_browser:
            logger.warning("Browser scraping not enabled")
            return {"error": "Browser not enabled"}
        
        browser = await self._get_browser()
        if not browser:
            return {"error": "Browser not available"}
        
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        
        try:
            page = await browser.new_page()
            await page.goto(url, timeout=30000)
            await page.wait_for_load_state('networkidle')
            
            # Extract CVE ID and description
            try:
                cve_id_elem = await page.text_content('//*[@id="vulnDetailTableView"]/tbody/tr/td/h2/span')
                description = await page.text_content('//*[@id="vulnDetailTableView"]/tbody/tr/td/div/div[1]/p')
            except Exception as e:
                await page.close()
                logger.error(f"Failed to extract basic CVE data: {e}")
                return {"error": f"CVE not found or page structure changed: {e}"}
            
            # Extract CVSS score and vector (try multiple versions)
            base_score = "Not Available"
            vector = "Not Available"
            
            cvss_xpaths = [
                ('//*[@id="Cvss3NistCalculatorAnchor"]', '//*[@id="Vuln3CvssPanel"]/div/div[3]/span/span'),
                ('//*[@id="Cvss3CnaCalculatorAnchor"]', '//*[@id="Vuln3CvssPanel"]/div/div[3]/span/span'),
                ('//*[@id="Cvss2CalculatorAnchor"]', '//*[@id="Vuln2CvssPanel"]/div/div[3]/span/span'),
            ]
            
            for score_xpath, vector_xpath in cvss_xpaths:
                try:
                    base_score = await page.text_content(score_xpath)
                    vector = await page.text_content(vector_xpath)
                    if base_score and vector:
                        break
                except Exception:
                    continue
            
            # Extract reference links
            links = []
            try:
                ref_rows = await page.locator('//*[@id="vulnHyperlinksPanel"]/table/tbody/tr').all()
                for row in ref_rows:
                    try:
                        link = await row.locator('td[1]/a').get_attribute("href")
                        if link:
                            links.append(link)
                    except Exception:
                        continue
            except Exception as e:
                logger.debug(f"Could not extract reference links: {e}")
            
            await page.close()
            
            # Validate reference links asynchronously
            async def fetch_valid_links():
                async with aiohttp.ClientSession() as session:
                    tasks = [self._validate_link_async(session, link) for link in links]
                    results = await asyncio.gather(*tasks)
                    return [link for link, is_valid in zip(links, results) if is_valid]
            
            try:
                ref_links = await fetch_valid_links()
            except Exception:
                ref_links = links  # Fallback to all links if validation fails
            
            nist_data = {
                "cve_id": cve_id_elem,
                "description": description,
                "base_score": base_score,
                "vector": vector,
                "references": ref_links
            }
            
            logger.info(f"Successfully scraped NIST data for {cve_id}")
            return nist_data
            
        except Exception as e:
            logger.error(f"Error scraping NIST data for {cve_id}: {e}")
            return {"error": str(e)}
    
    def fetch_nist_data_selenium(self, cve_id: str) -> Dict:
        """
        Fetch detailed CVE data from NIST using browser automation (sync wrapper).
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary containing NIST CVE data
        """
        try:
            return asyncio.run(self.fetch_nist_data_browser(cve_id))
        except Exception as e:
            logger.error(f"Error in NIST data fetch wrapper: {e}")
            return {"error": str(e)}
    
    async def fetch_mitre_data_async(self, cve_id: str) -> Dict:
        """
        Fetch CVE data from MITRE CVE API asynchronously.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary containing MITRE CVE data
        """
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        try:
                            metadata = data['cveMetadata']
                            containers = data['containers']['cna']
                            affected = containers['affected'][0] if containers.get('affected') else {}
                            descriptions = containers['descriptions'][0]['value'] if containers.get('descriptions') else ''
                            problem_type = containers['problemTypes'][0]['descriptions'][0]['description'] if containers.get('problemTypes') else 'N/A'
                            
                            references = [ref['url'] for ref in containers.get('references', []) if 'url' in ref]
                            
                            # Validate references asynchronously
                            valid_refs = []
                            if references:
                                tasks = [self._validate_link_async(session, ref) for ref in references]
                                results = await asyncio.gather(*tasks)
                                valid_refs = [ref for ref, is_valid in zip(references, results) if is_valid]
                            
                            mitre_data = {
                                "assigner_org": metadata.get('assignerShortName', 'N/A'),
                                "published": metadata.get('datePublished', 'N/A'),
                                "updated": metadata.get('dateUpdated', 'N/A'),
                                "vendor": affected.get('vendor', 'N/A'),
                                "product": affected.get('product', 'N/A'),
                                "versions": affected.get('versions', [{}])[0].get('version', 'N/A') if affected.get('versions') else 'N/A',
                                "description": descriptions,
                                "problem_type": problem_type,
                                "references": valid_refs[:5],  # Limit to first 5 references
                            }
                            
                            logger.info(f"Successfully fetched MITRE data for {cve_id}")
                            return mitre_data
                            
                        except KeyError as e:
                            logger.error(f"Unexpected MITRE data structure for {cve_id}: {e}")
                            return {"error": "Unexpected data structure"}
                    else:
                        logger.error(f"Failed to fetch MITRE data for {cve_id}: HTTP {response.status}")
                        return {"error": f"Failed to fetch MITRE data: {response.status}"}
                        
        except Exception as e:
            logger.error(f"Error fetching MITRE data for {cve_id}: {e}")
            return {"error": str(e)}
    
    def fetch_mitre_data(self, cve_id: str) -> Dict:
        """
        Fetch CVE data from MITRE CVE API (synchronous wrapper).
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary containing MITRE CVE data
        """
        try:
            return asyncio.run(self.fetch_mitre_data_async(cve_id))
        except Exception as e:
            logger.error(f"Error in MITRE data fetch wrapper: {e}")
            return {"error": str(e)}
    
    async def fetch_exploit_db_data_browser(self, cve_id: str) -> List[Dict]:
        """
        Fetch exploit data from Exploit-DB using Playwright.
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            List of exploit dictionaries
        """
        if not self.use_browser:
            logger.warning("Browser scraping not enabled for Exploit-DB")
            return []
        
        browser = await self._get_browser()
        if not browser:
            return []
        
        url = f"https://www.exploit-db.com/search?cve={cve_id}"
        exploit_data_list = []
        
        try:
            page = await browser.new_page()
            await page.goto(url, timeout=30000)
            await page.wait_for_load_state('networkidle')
            
            page_count = 0
            max_pages = 5  # Limit pagination
            
            while page_count < max_pages:
                try:
                    # Wait for table to load
                    await page.wait_for_selector('#exploits-table tbody tr', timeout=5000)
                    rows = await page.locator('#exploits-table tbody tr').all()
                    
                    if not rows:
                        logger.debug(f"No exploit rows found for {cve_id}")
                        break
                    
                    for row in rows:
                        try:
                            # Extract exploit data
                            title_link = await row.locator('td:nth-child(5) a').get_attribute('href')
                            date = await row.locator('td:nth-child(1)').text_content()
                            exploit_type = await row.locator('td:nth-child(6)').text_content()
                            platform = await row.locator('td:nth-child(7)').text_content()
                            author = await row.locator('td:nth-child(8)').text_content()
                            download_link = await row.locator('td:nth-child(2) a').get_attribute('href')
                            
                            exploit_data = {
                                "title_link": f"https://www.exploit-db.com{title_link}" if title_link else "",
                                "date": date.strip() if date else "",
                                "type": exploit_type.strip() if exploit_type else "",
                                "platform": platform.strip() if platform else "",
                                "author": author.strip() if author else "",
                                "download_link": f"https://www.exploit-db.com{download_link}" if download_link else ""
                            }
                            
                            exploit_data_list.append(exploit_data)
                            
                        except Exception as e:
                            logger.debug(f"Failed to extract exploit row: {e}")
                            continue
                    
                    # Try to navigate to next page
                    try:
                        next_button = page.locator('#exploits-table_next a')
                        is_disabled = await next_button.get_attribute('class')
                        
                        if is_disabled and 'disabled' in is_disabled:
                            break
                        
                        await next_button.click()
                        await page.wait_for_load_state('networkidle')
                        page_count += 1
                        
                    except Exception:
                        break  # No more pages
                        
                except PlaywrightTimeout:
                    logger.debug(f"Timeout waiting for Exploit-DB page for {cve_id}")
                    break
                except Exception as e:
                    logger.debug(f"Error processing Exploit-DB page: {e}")
                    break
            
            await page.close()
            logger.info(f"Found {len(exploit_data_list)} exploits for {cve_id} from Exploit-DB")
            
        except Exception as e:
            logger.error(f"Error scraping Exploit-DB for {cve_id}: {e}")
        
        return exploit_data_list
    
    def fetch_exploit_db_data(self, cve_id: str) -> List[Dict]:
        """
        Fetch exploit data from Exploit-DB (sync wrapper).
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            List of exploit dictionaries
        """
        try:
            return asyncio.run(self.fetch_exploit_db_data_browser(cve_id))
        except Exception as e:
            logger.error(f"Error in Exploit-DB fetch wrapper: {e}")
            return []
    
    def scrape_cve_complete(self, cve_id: str) -> Dict:
        """
        Perform complete CVE scraping from all sources (NIST, MITRE, Exploit-DB).
        
        Args:
            cve_id: CVE identifier
        
        Returns:
            Dictionary containing all CVE data from multiple sources
        """
        # Validate CVE format
        is_valid, error_msg = self.validate_cve(cve_id)
        if not is_valid:
            return {"error": error_msg}
        
        # Check CVE status
        status = self.check_cve_status(cve_id)
        if status in ["RESERVED", "REJECTED"]:
            return {"error": f"CVE {cve_id} is {status}"}
        
        logger.info(f"Starting complete scrape for {cve_id}")
        
        result = {
            "cve_id": cve_id,
            "nist_data": {},
            "mitre_data": {},
            "exploit_data": [],
            "scrape_timestamp": datetime.now().isoformat()
        }
        
        # Fetch NIST data (with browser if available)
        if self.use_browser:
            result["nist_data"] = self.fetch_nist_data_selenium(cve_id)
        else:
            logger.info("Browser not enabled, skipping detailed NIST scrape")
        
        # Fetch MITRE data
        result["mitre_data"] = self.fetch_mitre_data(cve_id)
        
        # Fetch Exploit-DB data
        if self.use_browser:
            result["exploit_data"] = self.fetch_exploit_db_data(cve_id)
        
        # Store in database
        self._store_complete_cve_data(result)
        
        return result
    
    def _store_complete_cve_data(self, cve_data: Dict) -> bool:
        """
        Store complete CVE data from all sources into database.
        
        Args:
            cve_data: Complete CVE data dictionary
        
        Returns:
            True if successful, False otherwise
        """
        try:
            cve_id = cve_data.get('cve_id')
            nist = cve_data.get('nist_data', {})
            mitre = cve_data.get('mitre_data', {})
            exploits = cve_data.get('exploit_data', [])
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Combine description from both sources
            description = nist.get('description') or mitre.get('description', '')
            
            # Parse CVSS score
            cvss_score = 0.0
            if isinstance(nist.get('base_score'), str) and nist.get('base_score') != 'Not Available':
                try:
                    cvss_score = float(nist.get('base_score', '0').split()[0])
                except (ValueError, IndexError, AttributeError):
                    cvss_score = 0.0
            
            # Determine severity
            severity = self._score_to_severity(cvss_score)
            
            # Combine references
            all_refs = nist.get('references', []) + mitre.get('references', [])
            
            # Insert/Update CVE entry
            cursor.execute('''
                INSERT OR REPLACE INTO cve_entries 
                (cve_id, description, severity, cvss_score, cvss_vector, published_date, 
                 modified_date, affected_products, reference_urls, assigner_org, vendor, 
                 product, versions, problem_type, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                description,
                severity,
                cvss_score,
                nist.get('vector', ''),
                mitre.get('published', ''),
                mitre.get('updated', ''),
                json.dumps([mitre.get('product', '')]),
                json.dumps(all_refs),
                mitre.get('assigner_org', ''),
                mitre.get('vendor', ''),
                mitre.get('product', ''),
                mitre.get('versions', ''),
                mitre.get('problem_type', ''),
                json.dumps(cve_data)
            ))
            
            # Store technology mappings
            if mitre.get('product'):
                cursor.execute('''
                    INSERT OR IGNORE INTO cve_technologies (cve_id, technology, version_affected)
                    VALUES (?, ?, ?)
                ''', (cve_id, mitre.get('product'), mitre.get('versions', '*')))
            
            # Store exploits
            for exploit in exploits:
                cursor.execute('''
                    INSERT OR IGNORE INTO cve_exploits 
                    (cve_id, exploit_type, exploit_date, exploit_platform, 
                     exploit_author, download_link, title_link, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    exploit.get('type', ''),
                    exploit.get('date', ''),
                    exploit.get('platform', ''),
                    exploit.get('author', ''),
                    exploit.get('download_link', ''),
                    exploit.get('title_link', ''),
                    'Exploit-DB'
                ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Successfully stored complete CVE data for {cve_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error storing complete CVE data: {e}")
            return False
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity level."""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def _parse_html_source(self, html: str, source: str, cve_id: str = None) -> Dict:
        """
        Parse CVE data from HTML sources (NVD detail page, MITRE, Vulners, GitHub).
        
        Args:
            html: HTML content to parse
            source: Source identifier (nvd_web, cve_mitre, vulners, github_poc)
            cve_id: CVE ID being scraped (optional, for logging)
            
        Returns:
            CVE dictionary with parsed data
        """
        if not BS4_AVAILABLE:
            logger.warning("BeautifulSoup not available, cannot parse HTML")
            return {}
        
        result = {"raw_data": {}}
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            if source == 'nvd_web':
                # Parse NVD individual CVE detail page (using reference code selectors)
                # Get description
                vuln_description = soup.find("p", {"data-testid": "vuln-description"})
                if vuln_description:
                    result["description"] = vuln_description.text.strip()
                
                # Get CVSS v3 score (primary)
                cvss_element = soup.find("a", {"id": "Cvss3NistCalculatorAnchor"})
                if cvss_element:
                    cvss_text = cvss_element.text.strip()
                    import re
                    cvss_match = re.search(r'([\d\.]+)', cvss_text)
                    if cvss_match:
                        result["cvss_score"] = float(cvss_match.group(1))
                        result["severity"] = self._score_to_severity(result["cvss_score"])
                
                # Fallback to data-testid selector
                if "cvss_score" not in result:
                    cvss3_elem = soup.select_one('a[data-testid="vuln-cvss3-panel-score"]')
                    if cvss3_elem:
                        try:
                            cvss_score = float(cvss3_elem.get_text(strip=True))
                            result["cvss_score"] = cvss_score
                            result["severity"] = self._score_to_severity(cvss_score)
                        except ValueError:
                            pass
                
                # Get references (hyperlinks table)
                references = []
                ref_table = soup.find("table", {"data-testid": "vuln-hyperlinks-table"})
                if ref_table:
                    for row in ref_table.find_all("tr")[1:]:  # Skip header row
                        cells = row.find_all("td")
                        if len(cells) >= 2:
                            link = cells[0].find("a")
                            if link and link.get("href"):
                                references.append({
                                    "url": link["href"],
                                    "name": link.text.strip(),
                                    "source": "nvd"
                                })
                
                result["references"] = references
                
                # Get affected products (CPE table)
                affected_products = []
                technologies = []
                cpe_table = soup.find("table", {"data-testid": "vuln-software-cpe-table"})
                if cpe_table:
                    for row in cpe_table.find_all("tr")[1:]:  # Skip header row
                        cells = row.find_all("td")
                        if len(cells) >= 1:
                            cpe_text = cells[0].text.strip()
                            if cpe_text:
                                affected_products.append(cpe_text)
                                # Extract vendor:product from CPE
                                parts = cpe_text.split(':')
                                if len(parts) >= 5:
                                    product = f"{parts[3]}:{parts[4]}"
                                    if product not in technologies:
                                        technologies.append(product)
                
                result["affected_products"] = affected_products
                result["technologies"] = technologies
            
            elif source == 'cve_mitre':
                # Parse MITRE CVE detail page (using reference code selectors)
                # Extract description from table row 4
                desc_elem = soup.select_one('div#GeneratedTable table tr:nth-of-type(4) td')
                if desc_elem:
                    result["description"] = desc_elem.get_text(strip=True)
                
                # Extract references from last table row
                references = []
                refs_elem = soup.select('div#GeneratedTable table tr:last-of-type td ul li a')
                for link in refs_elem:
                    if link.get('href'):
                        references.append({
                            "url": link["href"],
                            "name": link.text.strip(),
                            "source": "mitre"
                        })
                
                result["references"] = references
            
            elif source == 'vulners':
                # Parse Vulners search results
                result_elem = soup.select_one('div.search-result')
                if result_elem:
                    desc = result_elem.select_one('div.description')
                    if desc:
                        result["description"] = desc.get_text(strip=True)
                    
                    # CVSS score
                    cvss_elem = result_elem.select_one('span.cvss-score')
                    if cvss_elem:
                        try:
                            cvss_score = float(cvss_elem.get_text(strip=True))
                            result["cvss_score"] = cvss_score
                            result["severity"] = self._score_to_severity(cvss_score)
                        except ValueError:
                            pass
            
            elif source == 'github_poc':
                # Parse GitHub search results for PoCs (using reference code approach)
                pocs = []
                
                # Try new GitHub UI
                repo_items = soup.select('div.search-title a')
                for link in repo_items[:5]:  # Top 5 results
                    href = link.get('href', '')
                    if href:
                        pocs.append({
                            "title": link.text.strip(),
                            "url": 'https://github.com' + href,
                            "description": ""
                        })
                
                # Try old GitHub UI (repo-list-item)
                if not pocs:
                    repo_list = soup.find_all("div", {"class": "repo-list-item"})
                    for repo in repo_list[:5]:
                        repo_link = repo.find("a", {"class": "v-align-middle"})
                        if repo_link:
                            repo_description = repo.find("p", {"class": "mb-1"})
                            pocs.append({
                                "title": repo_link.text.strip(),
                                "url": "https://github.com" + repo_link["href"],
                                "description": repo_description.text.strip() if repo_description else ""
                            })
                
                if pocs:
                    result["pocs"] = pocs
                    result["exploit_available"] = True
            
            if result and len(result) > 1:  # More than just raw_data
                result['source'] = source
                logger.debug(f"Parsed CVE data from {source}: {list(result.keys())}")
            else:
                logger.debug(f"No data extracted from {source}")
                return {}
            
        except Exception as e:
            logger.error(f"Error parsing HTML from {source} for {cve_id}: {e}")
            return {}
        
        return result
    
    def _parse_json_source(self, data: Dict, source: str) -> List[Dict]:
        """
        Parse CVE data from JSON sources (CISA KEV, Vulners API).
        
        Args:
            data: JSON data dictionary
            source: Source identifier (cisa_kev, vulners)
            
        Returns:
            List of CVE dictionaries
        """
        cves = []
        try:
            if source == 'cisa_kev':
                # Parse CISA Known Exploited Vulnerabilities
                vulns = data.get('vulnerabilities', [])
                for vuln in vulns:
                    cve_id = vuln.get('cveID', '')
                    if cve_id:
                        cves.append({
                            'cve_id': cve_id,
                            'description': vuln.get('vulnerabilityName', ''),
                            'vendor': vuln.get('vendorProject', ''),
                            'product': vuln.get('product', ''),
                            'date_added': vuln.get('dateAdded', ''),
                            'due_date': vuln.get('dueDate', ''),
                            'required_action': vuln.get('requiredAction', ''),
                            'exploited': True,
                            'source': source
                        })
            
            elif source == 'vulners':
                # Parse Vulners API response
                results = data.get('data', {}).get('search', [])
                for item in results:
                    source_data = item.get('_source', {})
                    cve_id = source_data.get('id', '')
                    if cve_id.startswith('CVE-'):
                        cvss = source_data.get('cvss', {})
                        cves.append({
                            'cve_id': cve_id,
                            'description': source_data.get('description', ''),
                            'cvss_score': cvss.get('score', 0.0),
                            'published_date': source_data.get('published', ''),
                            'modified_date': source_data.get('modified', ''),
                            'source': source
                        })
            
            logger.info(f"Parsed {len(cves)} CVEs from {source}")
            
        except Exception as e:
            logger.error(f"Error parsing JSON from {source}: {e}")
        
        return cves
    
    def _parse_rss_source(self, xml: str, source: str) -> List[Dict]:
        """
        Parse CVE data from RSS/XML feeds.
        
        Args:
            xml: XML/RSS content
            source: Source identifier (nvd_rss)
            
        Returns:
            List of CVE dictionaries
        """
        if not BS4_AVAILABLE:
            logger.warning("BeautifulSoup not available, cannot parse RSS")
            return []
        
        cves = []
        try:
            soup = BeautifulSoup(xml, 'xml')
            
            if source == 'nvd_rss':
                # Parse NVD RSS feed
                entries = soup.find_all('entry')
                for entry in entries:
                    cve_id_elem = entry.find('vuln:cve-id')
                    if cve_id_elem:
                        cve_id = cve_id_elem.get_text(strip=True)
                        
                        summary_elem = entry.find('summary')
                        description = summary_elem.get_text(strip=True) if summary_elem else ''
                        
                        # Extract CVSS
                        cvss_elem = entry.find('vuln:cvss')
                        cvss_score = 0.0
                        if cvss_elem:
                            score_elem = cvss_elem.find('vuln:base_metrics')
                            if score_elem and score_elem.get('score'):
                                try:
                                    cvss_score = float(score_elem['score'])
                                except ValueError:
                                    pass
                        
                        published_elem = entry.find('published')
                        published = published_elem.get_text(strip=True) if published_elem else ''
                        
                        cves.append({
                            'cve_id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'severity': self._score_to_severity(cvss_score),
                            'published_date': published,
                            'source': source
                        })
            
            logger.info(f"Parsed {len(cves)} CVEs from {source}")
            
        except Exception as e:
            logger.error(f"Error parsing RSS from {source}: {e}")
        
        return cves
    
    async def scrape_latest_vulnerabilities(self, max_items: int = 100) -> List[Dict]:
        """
        Scrape latest vulnerabilities from multiple RSS/JSON sources.
        
        Args:
            max_items: Maximum number of items to fetch per source
            
        Returns:
            List of latest CVE dictionaries
        """
        logger.info("Scraping latest vulnerabilities from all sources")
        all_cves = []
        
        for source_name, source_url in self.latest_vuln_sources.items():
            try:
                logger.info(f"Fetching from {source_name}: {source_url}")
                
                if source_name == 'nvd_rss':
                    # Fetch RSS feed
                    response = self.session.get(source_url, timeout=30)
                    response.raise_for_status()
                    cves = self._parse_rss_source(response.text, source_name)
                    all_cves.extend(cves[:max_items])
                
                elif source_name == 'cisa_kev':
                    # Fetch CISA KEV JSON
                    response = self.session.get(source_url, timeout=30)
                    response.raise_for_status()
                    data = response.json()
                    cves = self._parse_json_source(data, source_name)
                    all_cves.extend(cves[:max_items])
                
                # Rate limiting
                await asyncio.sleep(2)
                
            except Exception as e:
                logger.error(f"Error fetching from {source_name}: {e}")
        
        logger.info(f"Total latest CVEs fetched: {len(all_cves)}")
        return all_cves
    
    async def scrape_from_all_sources(self, cve_list: List[str]) -> int:
        """
        Scrape CVE details from all configured sources (NVD Web, MITRE, Vulners, GitHub).
        
        Args:
            cve_list: List of CVE IDs to scrape
            
        Returns:
            Number of CVEs successfully updated
        """
        logger.info(f"Scraping {len(cve_list)} CVEs from all sources")
        updated = 0
        
        for i, cve_id in enumerate(cve_list, 1):
            logger.info(f"[{i}/{len(cve_list)}] Processing {cve_id}")
            cve_enriched = False
            
            # Try each source
            for source_name, source_config in self.cve_sources.items():
                try:
                    url = source_config['url'].format(cve_id=cve_id)
                    logger.debug(f"  Fetching from {source_name}: {url}")
                    
                    response = self.session.get(url, timeout=15)
                    if response.status_code == 200:
                        # Parse HTML response for this specific CVE
                        cve_data = self._parse_html_source(response.text, source_name, cve_id)
                        
                        # Update database if we got any data
                        if cve_data:
                            # Add CVE ID if not in parsed data
                            if 'cve_id' not in cve_data:
                                cve_data['cve_id'] = cve_id
                            
                            if self._update_cve_data_from_source(cve_id, cve_data):
                                logger.info(f"  ✓ Enriched from {source_name}")
                                cve_enriched = True
                    
                    # Rate limiting (1 second between requests)
                    await asyncio.sleep(1)
                    
                except Exception as e:
                    logger.debug(f"  ✗ Error from {source_name}: {e}")
                    continue
            
            if cve_enriched:
                updated += 1
        
        logger.info(f"Successfully enriched {updated}/{len(cve_list)} CVEs from multi-source scraping")
        return updated
    
    def _update_cve_data_from_source(self, cve_id: str, source_data: Dict) -> bool:
        """
        Update CVE database entry with data from additional source.
        Uses smart merging logic from reference implementation.
        
        Args:
            cve_id: CVE identifier
            source_data: Data dictionary from source
            
        Returns:
            True if successful
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if CVE exists
            cursor.execute('SELECT cve_id, description, cvss_score FROM cve_entries WHERE cve_id = ?', (cve_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Smart update: only update if source has better data
                update_fields = []
                values = []
                
                # Update description if current is empty
                if source_data.get('description') and (not existing[1] or existing[1].strip() == ''):
                    update_fields.append('description = ?')
                    values.append(source_data['description'])
                
                # Update CVSS score if source has higher score
                if source_data.get('cvss_score'):
                    current_score = existing[2] if existing[2] else 0.0
                    if source_data['cvss_score'] > current_score:
                        update_fields.append('cvss_score = ?')
                        values.append(source_data['cvss_score'])
                        update_fields.append('severity = ?')
                        values.append(self._score_to_severity(source_data['cvss_score']))
                
                if source_data.get('vendor'):
                    update_fields.append('vendor = ?')
                    values.append(source_data['vendor'])
                
                if source_data.get('product'):
                    update_fields.append('product = ?')
                    values.append(source_data['product'])
                
                if source_data.get('exploit_available'):
                    update_fields.append('exploit_available = ?')
                    values.append(1)
                
                if update_fields:
                    values.append(cve_id)
                    query = f"UPDATE cve_entries SET {', '.join(update_fields)} WHERE cve_id = ?"
                    cursor.execute(query, values)
            else:
                # Insert new entry
                cursor.execute('''
                    INSERT INTO cve_entries 
                    (cve_id, description, severity, cvss_score, vendor, product, published_date, exploit_available)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    source_data.get('description', ''),
                    self._score_to_severity(source_data.get('cvss_score', 0.0)),
                    source_data.get('cvss_score', 0.0),
                    source_data.get('vendor', ''),
                    source_data.get('product', ''),
                    source_data.get('published_date', ''),
                    1 if source_data.get('exploit_available') else 0
                ))
            
            # Add technologies if provided (avoid duplicates)
            if source_data.get('technologies'):
                for tech in source_data['technologies']:
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_technologies (cve_id, technology)
                        VALUES (?, ?)
                    ''', (cve_id, tech))
            
            # Add affected products if provided
            if source_data.get('affected_products'):
                for product in source_data['affected_products']:
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_technologies (cve_id, technology)
                        VALUES (?, ?)
                    ''', (cve_id, product))
            
            # Add PoCs if provided (using reference code approach)
            if source_data.get('pocs'):
                for poc in source_data['pocs']:
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_exploits 
                        (cve_id, exploit_type, exploit_description, source)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        cve_id,
                        'PoC',
                        poc.get('url', ''),
                        source_data.get('source', 'Unknown')
                    ))
            
            # Add references if provided
            if source_data.get('references'):
                for ref in source_data['references']:
                    # Store in exploits table with type 'Reference'
                    cursor.execute('''
                        INSERT OR IGNORE INTO cve_exploits 
                        (cve_id, exploit_type, exploit_description, source)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        cve_id,
                        'Reference',
                        ref.get('url', ''),
                        ref.get('source', 'Unknown')
                    ))
            
            # Add exploit info if marked as exploited
            if source_data.get('exploited'):
                cursor.execute('''
                    INSERT OR IGNORE INTO cve_exploits 
                    (cve_id, exploit_type, exploit_description, source, exploit_date)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    'Known Exploited',
                    f"CISA KEV: Actively exploited in the wild",  # Non-null description for unique constraint
                    source_data.get('source', 'Unknown'),
                    source_data.get('date_added', '')
                ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Error updating CVE {cve_id} from source: {e}")
            return False
    
    def scrape_nvd_cves(self, days_back: int = 30, limit: int = 1000, use_cache: bool = True):
        """
        Scrape CVEs from NVD (National Vulnerability Database) with multi-source fallback.
        
        Args:
            days_back: Number of days to look back
            limit: Maximum number of CVEs to fetch
            use_cache: Whether to use cached data if available (7-day cache)
        """
        logger.info(f"Scraping CVEs from NVD (last {days_back} days, limit: {limit})")
        
        # Check cache first
        cache_file = os.path.join(self.cache_dir, f"nvd_cves_{days_back}d.json")
        if use_cache and os.path.exists(cache_file):
            cache_age = time.time() - os.path.getmtime(cache_file)
            if cache_age < (7 * 24 * 60 * 60):  # 7 days in seconds
                logger.info(f"Using cached NVD data (age: {cache_age/3600:.1f} hours)")
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cached_data = json.load(f)
                        logger.info(f"Loaded {len(cached_data)} CVEs from cache")
                        # Store in database
                        stored = sum(1 for cve in cached_data if self._store_cve_from_dict(cve))
                        logger.info(f"Stored {stored} CVEs from cache in database")
                        return stored
                except Exception as e:
                    logger.warning(f"Failed to load cache: {e}, fetching fresh data")
        
        # Try NVD API v2.0 first
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # NVD API requires specific datetime format without microseconds
        params = {
            'lastModStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'lastModEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': min(limit, 2000)
        }
        
        stored = 0
        all_cves = []
        
        try:
            # Add delay to respect NVD rate limits (no API key = 5 requests per 30 seconds)
            time.sleep(6)
            
            response = self.session.get(base_url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get('vulnerabilities', [])
            logger.info(f"Found {len(vulnerabilities)} CVEs from NVD API")
            
            # Store in database and cache
            for vuln in vulnerabilities:
                if self._store_cve_nvd(vuln):
                    stored += 1
                    # Extract for cache
                    cve = vuln.get('cve', {})
                    all_cves.append({
                        'cve_id': cve.get('id', ''),
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'published': cve.get('published', ''),
                        'source': 'nvd_api'
                    })
            
            # Save to cache
            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump(all_cves, f, indent=2)
                logger.info(f"Cached {len(all_cves)} CVEs to {cache_file}")
            except Exception as e:
                logger.warning(f"Failed to save cache: {e}")
            
            logger.info(f"Stored {stored} CVEs in database from NVD API")
            return stored
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to scrape NVD API: {e}")
            logger.info("Attempting fallback to alternative sources...")
            
            # Fallback to RSS feed
            try:
                rss_url = self.latest_vuln_sources.get('nvd_rss')
                if rss_url:
                    response = self.session.get(rss_url, timeout=30)
                    response.raise_for_status()
                    cves = self._parse_rss_source(response.text, 'nvd_rss')
                    
                    for cve_data in cves[:limit]:
                        if self._update_cve_data_from_source(cve_data['cve_id'], cve_data):
                            stored += 1
                    
                    logger.info(f"Stored {stored} CVEs from NVD RSS fallback")
                    return stored
            except Exception as rss_error:
                logger.error(f"RSS fallback also failed: {rss_error}")
            
            return 0
        except Exception as e:
            logger.error(f"Error processing NVD data: {e}")
            return 0
    
    def _store_cve_from_dict(self, cve_dict: Dict) -> bool:
        """
        Store CVE from dictionary format (used for cache).
        
        Args:
            cve_dict: CVE data dictionary
            
        Returns:
            True if successful
        """
        try:
            cve_id = cve_dict.get('cve_id', '')
            if not cve_id:
                return False
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR IGNORE INTO cve_entries 
                (cve_id, description, published_date, severity, cvss_score)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                cve_id,
                cve_dict.get('description', ''),
                cve_dict.get('published', ''),
                cve_dict.get('severity', 'UNKNOWN'),
                cve_dict.get('cvss_score', 0.0)
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"Error storing CVE from dict: {e}")
            return False
    
    def _store_cve_nvd(self, vuln_data: Dict) -> bool:
        """Store NVD CVE data in database."""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                return False
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else ''
            
            # Extract CVSS score and severity
            metrics = cve.get('metrics', {})
            cvss_score = 0.0
            severity = 'UNKNOWN'
            
            # Try CVSS v3.1
            if 'cvssMetricV31' in metrics:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0.0)
                severity = self._cvss2_to_severity(cvss_score)
            
            # Extract dates
            published = cve.get('published', '')
            modified = cve.get('lastModified', '')
            
            # Extract affected products
            configurations = cve.get('configurations', [])
            affected = self._extract_affected_products(configurations)
            
            # Extract references
            references = cve.get('references', [])
            ref_urls = [ref.get('url', '') for ref in references[:5]]
            
            # Extract CWE
            weaknesses = cve.get('weaknesses', [])
            cwe_id = ''
            if weaknesses:
                cwe_desc = weaknesses[0].get('description', [])
                if cwe_desc:
                    cwe_id = cwe_desc[0].get('value', '')
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cve_entries 
                (cve_id, description, severity, cvss_score, published_date, 
                 modified_date, affected_products, reference_urls, cwe_id, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_id,
                description,
                severity,
                cvss_score,
                published,
                modified,
                json.dumps(affected),
                json.dumps(ref_urls),
                cwe_id,
                json.dumps(vuln_data)
            ))
            
            # Store technology mappings
            for tech in affected:
                cursor.execute('''
                    INSERT OR IGNORE INTO cve_technologies (cve_id, technology, version_affected)
                    VALUES (?, ?, ?)
                ''', (cve_id, tech.get('product', ''), tech.get('version', '')))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.debug(f"Error storing CVE {vuln_data.get('cve', {}).get('id', 'unknown')}: {e}")
            return False
    
    def _extract_affected_products(self, configurations: List) -> List[Dict]:
        """Extract affected products from CVE configurations."""
        products = []
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        cpe_uri = cpe.get('criteria', '')
                        # Parse CPE: cpe:2.3:a:vendor:product:version:...
                        parts = cpe_uri.split(':')
                        if len(parts) >= 5:
                            products.append({
                                'vendor': parts[3],
                                'product': parts[4],
                                'version': parts[5] if len(parts) > 5 else '*'
                            })
        
        return products
    
    def _cvss2_to_severity(self, score: float) -> str:
        """Convert CVSS v2 score to severity."""
        if score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def scrape_exploit_db(self, limit: int = 100):
        """
        Scrape recent exploits from Exploit-DB.
        Note: This requires browser automation to be enabled.
        """
        logger.info(f"Scraping exploits from Exploit-DB (limit: {limit})")
        
        if not self.use_browser:
            logger.warning("Browser automation not enabled - cannot scrape Exploit-DB")
            return 0
        
        # Get CVEs from database that don't have exploits yet
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT cve_id 
            FROM cve_entries 
            WHERE cve_id NOT IN (SELECT DISTINCT cve_id FROM cve_exploits WHERE source = 'Exploit-DB')
            LIMIT ?
        ''', (limit,))
        
        cves_to_check = [row[0] for row in cursor.fetchall()]
        stored = 0
        browser_failed = False
        
        for cve_id in cves_to_check:
            # Skip if browser already failed
            if browser_failed:
                break
                
            try:
                exploits = self.fetch_exploit_db_data(cve_id)
                
                for exploit in exploits:
                    try:
                        cursor.execute('''
                            INSERT OR IGNORE INTO cve_exploits 
                            (cve_id, exploit_type, exploit_date, exploit_platform, 
                             exploit_author, download_link, title_link, source)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            cve_id,
                            exploit.get('type', ''),
                            exploit.get('date', ''),
                            exploit.get('platform', ''),
                            exploit.get('author', ''),
                            exploit.get('download_link', ''),
                            exploit.get('title_link', ''),
                            'Exploit-DB'
                        ))
                        stored += 1
                    except Exception as e:
                        logger.debug(f"Error storing exploit for {cve_id}: {e}")
            except Exception as e:
                error_msg = str(e)
                if "'NoneType' object has no attribute 'send'" in error_msg or "ERR_CONNECTION_RESET" in error_msg:
                    logger.warning(f"Browser connection failed, stopping Exploit-DB scraping: {e}")
                    browser_failed = True
                    break
                else:
                    logger.debug(f"Error fetching exploits for {cve_id}: {e}")
        
        conn.commit()
        conn.close()
        
        logger.info(f"Stored {stored} exploits from Exploit-DB")
        return stored
    
    def get_cves_for_technology(self, technology: str, limit: int = 50) -> List[Dict]:
        """Get CVEs matching a specific technology."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT c.cve_id, c.description, c.severity, c.cvss_score, 
                   c.published_date, c.exploit_available
            FROM cve_entries c
            JOIN cve_technologies t ON c.cve_id = t.cve_id
            WHERE t.technology LIKE ? OR c.description LIKE ?
            ORDER BY c.cvss_score DESC
            LIMIT ?
        ''', (f'%{technology}%', f'%{technology}%', limit))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'cve_id': row[0],
                'description': row[1],
                'severity': row[2],
                'cvss_score': row[3],
                'published_date': row[4],
                'exploit_available': row[5]
            })
        
        conn.close()
        return results
    
    def get_exploits_for_cve(self, cve_id: str) -> List[Dict]:
        """Get exploit payloads for a specific CVE."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT exploit_type, exploit_payload, exploit_description, source
            FROM cve_exploits
            WHERE cve_id = ?
        ''', (cve_id,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                'type': row[0],
                'payload': row[1],
                'description': row[2],
                'source': row[3]
            })
        
        conn.close()
        return results
    
    def get_database_stats(self) -> Dict:
        """Get CVE database statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total CVEs
        cursor.execute('SELECT COUNT(*) FROM cve_entries')
        total_cves = cursor.fetchone()[0]
        
        # By severity
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM cve_entries 
            GROUP BY severity
        ''')
        by_severity = dict(cursor.fetchall())
        
        # Total exploits
        cursor.execute('SELECT COUNT(*) FROM cve_exploits')
        total_exploits = cursor.fetchone()[0]
        
        # Total technologies
        cursor.execute('SELECT COUNT(DISTINCT technology) FROM cve_technologies')
        total_techs = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_cves': total_cves,
            'by_severity': by_severity,
            'total_exploits': total_exploits,
            'total_technologies': total_techs,
            'database_path': self.db_path
        }

