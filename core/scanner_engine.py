"""
Deep Eye Scanner Engine
Orchestrates the entire scanning process
"""

import time
import threading
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from datetime import datetime

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.console import Console

from core.vulnerability_scanner import VulnerabilityScanner
from core.ai_payload_generator import AIPayloadGenerator
from core.plugin_manager import PluginManager
from core.pentest_state_manager import PentestStateManager, PentestPhase
from core.subdomain_scanner import SubdomainScanner
from modules.reconnaissance.recon_engine import ReconEngine
from modules.browser_automation.smart_tester import SmartBrowserTester
from modules.secrets_scanner.secrets_detector import SecretsDetector
from utils.http_client import HTTPClient
from utils.parser import URLParser, ResponseParser
from utils.notification_manager import NotificationManager
from utils.logger import get_logger

console = Console()
logger = get_logger(__name__)


class ScannerEngine:
    """Main scanner engine that orchestrates the penetration testing process."""
    
    def __init__(
        self,
        target_url: str,
        config: Dict,
        ai_manager,
        depth: int = 2,
        threads: int = 5,
        proxy: Optional[str] = None,
        custom_headers: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        verbose: bool = False
    ):
        """Initialize the scanner engine."""
        self.target_url = target_url
        self.config = config
        self.ai_manager = ai_manager
        self.depth = depth
        self.threads = threads
        self.verbose = verbose
        
        # Initialize components
        self.http_client = HTTPClient(
            proxy=proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            config=config
        )
        
        self.vulnerability_scanner = VulnerabilityScanner(
            config=config,
            http_client=self.http_client
        )
        
        self.ai_payload_generator = AIPayloadGenerator(
            ai_manager=ai_manager,
            config=config
        )
        
        self.recon_engine = ReconEngine(
            config=config,
            http_client=self.http_client
        )
        
        self.plugin_manager = PluginManager(
            http_client=self.http_client,
            config=config
        )
        
        # Load custom plugins
        if config.get('plugin_manager', {}).get('enabled', False):
            self.plugin_manager.load_plugins()
        
        self.notification_manager = NotificationManager(config)
        
        
        # Subdomain scanner
        self.subdomain_scanner = SubdomainScanner(self, config)

        # Secrets scanner
        secrets_config = config.get('secrets_scanner', {})
        self.secrets_scanner = None
        if secrets_config.get('enabled', True):
            self.secrets_scanner = SecretsDetector(config)
            logger.info("Secrets scanner initialized")

        # State tracking and management
        self.state_manager = PentestStateManager(target_url)
        self.visited_urls: Set[str] = set()
        self.urls_to_scan: List[str] = [target_url]
        self.vulnerabilities: List[Dict] = []
        self.scan_results: Dict = {}
        self.lock = threading.Lock()

        # Advanced filtering configuration
        advanced_config = config.get('advanced', {})
        self.exclude_extensions = advanced_config.get('exclude_extensions', [
            '.jpg', '.jpeg', '.png', '.gif', '.css', '.js',
            '.woff', '.woff2', '.ttf', '.svg', '.ico'
        ])
        self.exclude_patterns = advanced_config.get('exclude_patterns', [])
        logger.info(f"URL filtering enabled: {len(self.exclude_extensions)} extensions, {len(self.exclude_patterns)} patterns")

        # Initialize CVE matcher for vulnerability enrichment
        self.cve_matcher = None
        experimental_config = config.get('experimental', {})
        if experimental_config.get('enable_cve_matching', False):
            try:
                from modules.cve_intelligence.cve_matcher import CVEMatcher
                from pathlib import Path
                db_path = Path(experimental_config.get('cve_database_path', 'data/cve_intelligence.db'))
                if db_path.exists():
                    self.cve_matcher = CVEMatcher(str(db_path))
                    logger.info("CVE matcher initialized for vulnerability enrichment")
                else:
                    logger.info("CVE database not found. Run: python scripts/update_cve_database.py")
            except Exception as e:
                logger.debug(f"CVE matcher initialization failed: {e}")
        
        # Statistics
        self.start_time = None
        self.end_time = None
        
    def _should_include_url(self, url: str) -> bool:
        """
        Check if URL should be included based on advanced filtering rules.

        Args:
            url: URL to check

        Returns:
            True if URL should be included, False otherwise
        """
        from pathlib import Path
        import re

        # Check exclude_extensions
        if self.exclude_extensions:
            url_path = Path(urlparse(url).path)
            url_ext = url_path.suffix.lower()
            if url_ext and url_ext in [ext.lower() for ext in self.exclude_extensions]:
                logger.debug(f"Excluding URL due to extension {url_ext}: {url}")
                return False

        # Check exclude_patterns
        if self.exclude_patterns:
            for pattern in self.exclude_patterns:
                try:
                    if re.search(pattern, url):
                        logger.debug(f"Excluding URL due to pattern '{pattern}': {url}")
                        return False
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")

        return True

    def crawl(self, url: str, current_depth: int = 0) -> List[str]:
        """Crawl a URL and extract links."""
        if current_depth >= self.depth or url in self.visited_urls:
            return []
        
        with self.lock:
            self.visited_urls.add(url)
        
        try:
            response = self.http_client.get(url)
            if not response:
                return []
            
            parser = ResponseParser(response)
            links = parser.extract_links(base_url=url)
            
            # Filter links to same domain and apply exclusion rules
            parsed_target = urlparse(self.target_url)
            same_domain_links = []

            for link in links:
                parsed_link = urlparse(link)
                if parsed_link.netloc == parsed_target.netloc:
                    if link not in self.visited_urls:
                        # Apply advanced filtering
                        if self._should_include_url(link):
                            same_domain_links.append(link)
                        else:
                            logger.debug(f"Excluded URL (filtered): {link}")

            return same_domain_links
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")
            return []
    
    def crawl_recursive(self) -> Set[str]:
        """Recursively crawl the target website using parallel workers."""
        self.state_manager.set_phase(PentestPhase.CRAWLING)
        console.print("[bold blue]🕷️  Starting web crawler...[/bold blue]")

        all_urls = set([self.target_url])
        queue = [(self.target_url, 0)]
        lock = threading.Lock()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:

            task = progress.add_task(
                f"[cyan]Crawling (depth: {self.depth})...",
                total=None
            )

            with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
                while queue:
                    # Grab a batch from the queue
                    batch = []
                    while queue and len(batch) < self.threads:
                        batch.append(queue.pop(0))

                    # Filter out items beyond depth
                    batch = [(url, depth) for url, depth in batch if depth < self.depth]
                    if not batch:
                        continue

                    # Crawl batch in parallel
                    futures = {executor.submit(self.crawl, url, depth): (url, depth) for url, depth in batch}

                    for future in futures:
                        try:
                            new_links = future.result(timeout=self.timeout * 3)
                            _, depth = futures[future]
                            with lock:
                                for link in new_links:
                                    if link not in all_urls:
                                        all_urls.add(link)
                                        queue.append((link, depth + 1))
                                        self.state_manager.update_urls(discovered=1)
                        except Exception as e:
                            logger.debug(f"Crawl worker error: {e}")

                    progress.update(
                        task,
                        description=f"[cyan]Crawling... Found {len(all_urls)} URLs"
                    )

        console.print(f"[green]✓[/green] Crawling complete. Found {len(all_urls)} URLs\n")
        return all_urls
    
    def scan_url(self, url: str, recon_data: Optional[Dict] = None) -> List[Dict]:
        """Scan a single URL for vulnerabilities."""
        vulnerabilities = []

        try:
            # Check if URL should be scanned (apply advanced filters)
            if not self._should_include_url(url):
                logger.info(f"Skipping filtered URL: {url}")
                self.state_manager.update_urls(tested=1)
                return vulnerabilities

            self.state_manager.current_url_testing = url

            # Get AI-generated payloads for this URL
            response = self.http_client.get(url)
            if not response:
                self.state_manager.update_urls(tested=1)
                return vulnerabilities
            
            context = {
                'url': url,
                'response': response,
                'headers': dict(response.headers)
            }
            
            # Add OSINT data to context if available from reconnaissance
            if recon_data and 'osint' in recon_data:
                context['osint_data'] = recon_data['osint']
            
            # Generate intelligent payloads
            payloads = self.ai_payload_generator.generate_payloads(context)
            
            # Run vulnerability scans with state tracking
            scan_results = self.vulnerability_scanner.scan(
                url=url,
                payloads=payloads,
                context=context,
                state_manager=self.state_manager
            )
            
            vulnerabilities.extend(scan_results)
            
            # Run browser-based tests if enabled
            if self.config.get('advanced', {}).get('enable_javascript_rendering', False):
                try:
                    # Instantiate browser tester locally for thread safety
                    browser_tester = SmartBrowserTester(self.config)
                    browser_vulns = browser_tester.test_browser_sync(url, payloads)
                    vulnerabilities.extend(browser_vulns)
                    logger.info(f"Browser automation completed: found {len(browser_vulns)} vulnerabilities")
                except TimeoutError:
                    logger.error(f"Browser testing timed out for {url}. Continuing with other tests...")
                except Exception as e:
                    logger.error(f"Browser testing failed for {url}: {e}. Continuing with other tests...")
                    # Continue with the scan even if browser testing fails
            
            # Run custom plugins
            if self.config.get('plugin_manager', {}).get('enabled', False):
                plugin_results = self.plugin_manager.scan_with_plugins(url, context)
                vulnerabilities.extend(plugin_results)

            # Scan for secrets and credentials
            if self.secrets_scanner:
                try:
                    logger.debug(f"Scanning for secrets in {url}")
                    secrets = self.secrets_scanner.scan_response(url, response, context)
                    if secrets:
                        logger.info(f"Found {len(secrets)} secrets in {url}")
                        # Convert secrets to vulnerability format
                        for secret in secrets:
                            secret_vuln = {
                                'type': f'Secret Exposure - {secret["type"]}',
                                'severity': secret['severity'],
                                'url': secret['url'],
                                'location': secret['location'],
                                'evidence': secret['masked_value'],
                                'context': secret.get('context', ''),
                                'description': f'Potentially leaked {secret["type"]} detected',
                                'recommendation': 'Immediately rotate the exposed credential. Remove sensitive data from client-side code. Use environment variables for secrets.'
                            }
                            vulnerabilities.append(secret_vuln)
                except Exception as e:
                    logger.error(f"Error scanning for secrets in {url}: {e}")

            # Enrich vulnerabilities with CVE information if enabled
            if self.cve_matcher:
                enriched_vulns = []
                for vuln in vulnerabilities:
                    enriched_vuln = self.cve_matcher.enrich_vulnerability(vuln)
                    enriched_vulns.append(enriched_vuln)
                vulnerabilities = enriched_vulns
                logger.debug(f"Enriched {len(vulnerabilities)} vulnerabilities with CVE data")

            # Update state with found vulnerabilities
            for vuln in vulnerabilities:
                self.state_manager.add_vulnerability(vuln.get('severity', 'info'))

                # Send critical vulnerability alerts
                if vuln.get('severity', '').lower() == 'critical':
                    try:
                        self.notification_manager.send_critical_vulnerability(vuln, self.target_url)
                    except Exception as e:
                        logger.debug(f"Error sending critical vulnerability alert: {e}")
            
            self.state_manager.update_urls(tested=1)
            
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
        
        return vulnerabilities
    
    def scan_all_urls(self, urls: Set[str], recon_data: Optional[Dict] = None):
        """Scan all discovered URLs for vulnerabilities."""
        self.state_manager.set_phase(PentestPhase.VULNERABILITY_SCANNING)
        console.print("[bold blue]🔍 Starting vulnerability scanning...[/bold blue]")
        console.print(f"[dim]Phase: {self.state_manager.current_phase.value}[/dim]\n")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Scanning for vulnerabilities...",
                total=len(urls)
            )
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self.scan_url, url, recon_data): url
                    for url in urls
                }
                
                # Add timeout to prevent stuck tasks (60 seconds per URL scan)
                scan_timeout = self.config.get('scanner', {}).get('scan_url_timeout', 60)
                
                for future in as_completed(future_to_url):
                    url = future_to_url[future]
                    try:
                        # Add timeout for individual result retrieval
                        vulns = future.result(timeout=scan_timeout)
                        with self.lock:
                            self.vulnerabilities.extend(vulns)
                        
                        progress.advance(task)
                        
                        # Show detailed progress with state
                        critical = sum(1 for v in self.vulnerabilities if v.get('severity') == 'critical')
                        high = sum(1 for v in self.vulnerabilities if v.get('severity') == 'high')
                        
                        progress.update(
                            task,
                            description=f"[cyan]Scanning... {len(self.vulnerabilities)} vulns (🔴{critical} 🟠{high})"
                        )
                        
                    except (FuturesTimeoutError, TimeoutError) as e:
                        logger.warning(f"Timeout scanning {url} after {scan_timeout}s - skipping")
                        progress.advance(task)
                        continue
                    except Exception as e:
                        logger.error(f"Error processing {url}: {e}")
                        progress.advance(task)
        
        console.print(f"[green]✓[/green] Vulnerability scanning complete. Found {len(self.vulnerabilities)} issues\n")
    
    def run_reconnaissance(self) -> Dict:
        """Run reconnaissance modules."""
        self.state_manager.set_phase(PentestPhase.RECONNAISSANCE)
        console.print("[bold blue]🔎 Running reconnaissance...[/bold blue]")
        console.print(f"[dim]Phase: {self.state_manager.current_phase.value}[/dim]\n")
        recon_results = self.recon_engine.run(self.target_url)
        console.print("[green]✓[/green] Reconnaissance complete\n")
        return recon_results
    
    def scan(
        self,
        enable_recon: bool = False,
        full_scan: bool = False,
        quick_scan: bool = False,
        scan_subdomains: bool = False
    ) -> Dict:
        """
        Execute the complete scanning process.
        
        Args:
            enable_recon: Enable reconnaissance phase
            full_scan: Enable all vulnerability tests
            quick_scan: Run only basic tests
            scan_subdomains: Enable subdomain discovery and scanning (experimental)
            
        Returns:
            Dictionary containing scan results
        """
        self.start_time = datetime.now()
        self.state_manager.set_phase(PentestPhase.INITIALIZATION)
        
        results = {
            'target': self.target_url,
            'start_time': self.start_time.isoformat(),
            'config': {
                'depth': self.depth,
                'threads': self.threads,
                'recon_enabled': enable_recon,
                'scan_mode': 'full' if full_scan else 'quick' if quick_scan else 'standard',
                'browser_enabled': self.config.get('advanced', {}).get('enable_javascript_rendering', False),
                'screenshot_enabled': self.config.get('advanced', {}).get('screenshot_enabled', False),
                'subdomain_scanning': scan_subdomains
            }
        }
        
        # Phase 1: Reconnaissance (optional)
        recon_data = None
        if enable_recon:
            recon_data = self.run_reconnaissance()
            results['reconnaissance'] = recon_data
        
        # Phase 1.5: Subdomain Discovery & Scanning (experimental)
        if scan_subdomains:
            subdomain_results = self.subdomain_scanner.discover_and_scan(
                self.target_url,
                aggressive=self.config.get('experimental', {}).get('aggressive_subdomain_enum', True)
            )
            results['subdomain_scan'] = subdomain_results
            
            # Aggregate subdomain vulnerabilities into main results
            for subdomain, sub_result in subdomain_results.get('scan_results', {}).items():
                for vuln in sub_result.get('vulnerabilities', []):
                    # Mark as subdomain vulnerability
                    vuln['source'] = 'subdomain'
                    vuln['subdomain'] = subdomain

                    # Enrich with CVE data if enabled
                    if self.cve_matcher:
                        vuln = self.cve_matcher.enrich_vulnerability(vuln)

                    self.vulnerabilities.append(vuln)
        
        # Phase 2: Web Crawling
        discovered_urls = self.crawl_recursive()
        results['urls_crawled'] = len(discovered_urls)
        results['discovered_urls'] = list(discovered_urls)
        
        # Phase 3: Vulnerability Scanning
        if quick_scan:
            # Scan only main URL in quick mode
            self.scan_all_urls({self.target_url}, recon_data)
        else:
            self.scan_all_urls(discovered_urls, recon_data)
        
        # Compile results
        results['vulnerabilities'] = self.vulnerabilities
        results['severity_summary'] = self._calculate_severity_summary()

        # RAG enrichment (Group F) — auto-link findings to similar CVEs
        rag_config = self.config.get('rag', {})
        if rag_config.get('enabled', False):
            try:
                from modules.cve_intelligence.rag_index import CVERagIndex
                rag = CVERagIndex(self.config)
                cve_db_path = self.config.get('cve_intelligence', {}).get(
                    'database_path', 'data/cve_intelligence.db'
                )
                # Auto-rebuild if stale
                if rag_config.get('auto_rebuild', True) and rag.is_stale(cve_db_path):
                    rag.build(cve_db_path, interactive=False)
                    if rag.is_loaded():
                        rag.save()
                else:
                    rag.load()

                if rag.is_loaded():
                    for vuln in self.vulnerabilities:
                        query = (
                            f"{vuln.get('type', '')} {vuln.get('parameter', '')} "
                            f"{str(vuln.get('evidence', ''))[:200]}"
                        )
                        hits = rag.search(query, top_k=3)
                        if hits and not vuln.get('cve_references'):
                            vuln['cve_references'] = [h['cve_id'] for h in hits]
                            vuln['rag_matched'] = True
                    logger.info("RAG enrichment applied")
            except Exception as e:
                logger.error(f"RAG enrichment failed: {e}")

        # Compliance framework enrichment (Group B)
        compliance_config = self.config.get('compliance', {})
        if compliance_config.get('enabled', False):
            try:
                from utils.compliance import enrich_vulnerabilities
                framework_keys = compliance_config.get(
                    'frameworks', ['pci_dss', 'soc2', 'iso_27001']
                )
                enrich_vulnerabilities(self.vulnerabilities, framework_keys)
                logger.info(f"Compliance enrichment applied: {framework_keys}")
            except Exception as e:
                logger.error(f"Compliance enrichment failed: {e}")

        # AI Triage (Group C) — runs AFTER RAG/compliance, BEFORE bounty writer
        try:
            from modules.ai_triage import AITriage, BountyWriter
            triage = AITriage(self.ai_manager, self.config)
            if triage.is_enabled():
                triage.triage_vulnerabilities(self.vulnerabilities)
                # Re-sync results vulnerabilities list (FPs may have been dropped)
                results['vulnerabilities'] = self.vulnerabilities
                results['severity_summary'] = self._calculate_severity_summary()
                logger.info("AI triage applied")

            bounty = BountyWriter(self.ai_manager, self.config)
            if bounty.is_enabled():
                bounty.generate_reports(self.vulnerabilities)
                logger.info("Bounty reports generated")
        except Exception as e:
            logger.error(f"AI triage / bounty writer failed: {e}")

        # Add pentest state information
        results['pentest_state'] = self.state_manager.get_state_dict()
        
        self.end_time = datetime.now()
        self.state_manager.set_phase(PentestPhase.REPORTING)
        results['end_time'] = self.end_time.isoformat()
        results['duration'] = str(self.end_time - self.start_time)
        
        # Display state summary
        console.print("\n")
        self.state_manager.display_summary()
        
        # Send scan completion notification
        try:
            self.notification_manager.send_scan_complete(results)
        except Exception as e:
            logger.error(f"Error sending notification: {e}")
        
        self.state_manager.set_phase(PentestPhase.COMPLETED)
        
        return results
    
    def _calculate_severity_summary(self) -> Dict[str, int]:
        """Calculate vulnerability severity summary."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
