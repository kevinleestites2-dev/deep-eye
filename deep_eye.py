#!/usr/bin/env python3
"""
Deep Eye - Advanced AI-Driven Penetration Testing Tool
Main Entry Point
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional, Dict
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

from core.scanner_engine import ScannerEngine
from core.report_generator import ReportGenerator
from utils.logger import setup_logger
from utils.config_loader import ConfigLoader
from ai_providers.provider_manager import AIProviderManager

console = Console()
logger = setup_logger()

BANNER = """
╔══════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                          ║
║  ⠀⠀⠀⠀⡀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀              
║  ⠀⢸⠉⣹⠋⠉⢉⡟⢩⢋⠋⣽⡻⠭⢽⢉⠯⠭⠭⠭⢽⡍⢹⡍⠙⣯⠉⠉⠉⠉⠉⣿⢫⠉⠉⠉⢉⡟⠉⢿⢹⠉⢉⣉⢿⡝⡉⢩⢿⣻⢍⠉⠉⠩⢹⣟⡏⠉⠹⡉⢻⡍⡇  
║  ⠀⢸⢠⢹⠀⠀⢸⠁⣼⠀⣼⡝⠀⠀⢸⠘⠀⠀⠀⠀⠈⢿⠀⡟⡄⠹⣣⠀⠀⠐⠀⢸⡘⡄⣤⠀⡼⠁⠀⢺⡘⠉⠀⠀⠀⠫⣪⣌⡌⢳⡻⣦⠀⠀⢃⡽⡼⡀⠀⢣⢸⠸⡇      
║  ⠀⢸⡸⢸⠀⠀⣿⠀⣇⢠⡿⠀⠀⠀⠸⡇⠀⠀⠀⠀⠀⠘⢇⠸⠘⡀⠻⣇⠀⠀⠄⠀⡇⢣⢛⠀⡇⠀⠀⣸⠇⠀⠀⠀⠀⠀⠘⠄⢻⡀⠻⣻⣧⠀⠀⠃⢧⡇⠀⢸⢸⡇⡇  
║  ⠀⢸⡇⢸⣠⠀⣿⢠⣿⡾⠁⠀⢀⡀⠤⢇⣀⣐⣀⠀⠤⢀⠈⠢⡡⡈⢦⡙⣷⡀⠀⠀⢿⠈⢻⣡⠁⠀⢀⠏⠀⠀⠀⢀⠀⠄⣀⣐⣀⣙⠢⡌⣻⣷⡀⢹⢸⡅⠀⢸⠸⡇⡇  
║  ⠀⢸⡇⢸⣟⠀⢿⢸⡿⠀⣀⣶⣷⣾⡿⠿⣿⣿⣿⣿⣿⣶⣬⡀⠐⠰⣄⠙⠪⣻⣦⡀⠘⣧⠀⠙⠄⠀⠀⠀⠀⠀⣨⣴⣾⣿⠿⣿⣿⣿⣿⣿⣶⣯⣿⣼⢼⡇⠀⢸⡇⡇⡇  
║  ⠀⢸⢧⠀⣿⡅⢸⣼⡷⣾⣿⡟⠋⣿⠓⢲⣿⣿⣿⡟⠙⣿⠛⢯⡳⡀⠈⠓⠄⡈⠚⠿⣧⣌⢧⠀⠀⠀⠀⠀⣠⣺⠟⢫⡿⠓⢺⣿⣿⣿⠏⠙⣏⠛⣿⣿⣾⡇⢀⡿⢠⠀⡇  
║  ⠀⢸⢸⠀⢹⣷⡀⢿⡁⠀⠻⣇⠀⣇⠀⠘⣿⣿⡿⠁⠐⣉⡀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⠓⠳⠄⠀⠀⠀⠀⠋⠀⠘⡇⠀⠸⣿⣿⠟⠀⢈⣉⢠⡿⠁⣼⠁⣼⠃⣼⠀⡇  
║  ⠀⢸⠸⣀⠈⣯⢳⡘⣇⠀⠀⠈⡂⣜⣆⡀⠀⠀⢀⣀⡴⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢽⣆⣀⠀⠀⠀⣀⣜⠕⡊⠀⣸⠇⣼⡟⢠⠏⠀⡇  
║  ⠀⢸⠀⡟⠀⢸⡆⢹⡜⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠋⣾⡏⡇⡎⡇⠀⡇  
║  ⠀⢸⠀⢃⡆⠀⢿⡄⠑⢽⣄⠀⠀⠀⢀⠂⠠⢁⠈⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠄⡐⢀⠂⠀⠀⣠⣮⡟⢹⣯⣸⣱⠁⠀⡇  
║  ⠀⠈⠉⠉⠋⠉⠉⠋⠉⠉⠉⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠋⡟⠉⠉⡿⠋⠋⠋⠉⠉⠁  
║                                                                               
║                  Advanced AI-Driven Penetration Testing Tool                 
║                      Version 1.3.0 - Code Name (Hestia)                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════╝
"""


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deep Eye - AI-Driven Penetration Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan with target from CLI:
    python deep_eye.py -u https://example.com
  
  Scan with target from config:
    python deep_eye.py --config myconfig.yaml
  
  Verbose mode:
    python deep_eye.py -u https://example.com -v
  
Note: All scan options are configured in config.yaml
      Use --config to specify a custom configuration file
        """
    )
    
    # Essential options only
    parser.add_argument(
        '-u', '--url',
        type=str,
        help='Target URL to scan (overrides config)'
    )
    
    parser.add_argument(
        '-c', '--config',
        type=str,
        default='config/config.yaml',
        help='Configuration file path (default: config/config.yaml)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Deep Eye v1.3.0 (Hestia)',
        help='Show version and exit'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Disable banner display'
    )
    
    return parser.parse_args()


def display_banner():
    """Display the Deep Eye banner."""
    console.print(BANNER, style="bold cyan")
    console.print("⚠️  [bold yellow]Use only on authorized targets[/bold yellow] ⚠️\n")


def validate_config(config: Dict, target_url: str) -> bool:
    """Validate configuration and target URL."""
    # Validate URL
    if not target_url:
        console.print("[bold red]Error:[/bold red] Target URL is required. Specify in config or use -u option.")
        return False
    
    if not target_url.startswith(('http://', 'https://')):
        console.print("[bold red]Error:[/bold red] URL must start with http:// or https://")
        return False
    
    # Validate scanner settings
    scanner_config = config.get('scanner', {})
    depth = scanner_config.get('default_depth', 2)
    threads = scanner_config.get('default_threads', 5)
    
    if depth < 1 or depth > 10:
        console.print("[bold red]Error:[/bold red] Depth must be between 1 and 10 (check config)")
        return False
    
    if threads < 1 or threads > 50:
        console.print("[bold red]Error:[/bold red] Threads must be between 1 and 50 (check config)")
        return False
    
    return True


def main():
    """Main execution function."""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Display banner
        if not args.no_banner:
            display_banner()
        
        # Load configuration
        console.print("[bold blue]Loading configuration...[/bold blue]")
        config = ConfigLoader.load(args.config)
        
        # Get scanner config
        scanner_config = config.get('scanner', {})
        
        # Target URL: CLI overrides config
        target_url = args.url or scanner_config.get('target_url', '')
        
        # Validate configuration
        if not validate_config(config, target_url):
            sys.exit(1)
        
        # Get all settings from config
        depth = scanner_config.get('default_depth', 2)
        threads = scanner_config.get('default_threads', 5)
        ai_provider = scanner_config.get('ai_provider', 'openai')
        enable_recon = scanner_config.get('enable_recon', False)
        full_scan = scanner_config.get('full_scan', False)
        quick_scan = scanner_config.get('quick_scan', False)
        proxy = scanner_config.get('proxy') or None
        custom_headers = scanner_config.get('custom_headers', {})
        cookies = scanner_config.get('cookies', {})
        verbose = args.verbose
        
        # Initialize AI Provider
        console.print(f"[bold blue]Initializing AI Provider: {ai_provider}[/bold blue]")
        ai_manager = AIProviderManager(config)
        ai_manager.set_provider(ai_provider)
        
        # Initialize Scanner Engine
        console.print("[bold blue]Initializing Scanner Engine...[/bold blue]")
        scanner = ScannerEngine(
            target_url=target_url,
            config=config,
            ai_manager=ai_manager,
            depth=depth,
            threads=threads,
            proxy=proxy,
            custom_headers=custom_headers,
            cookies=cookies,
            verbose=verbose
        )
        
        # Display scan configuration
        scan_mode = 'Full Scan' if full_scan else 'Quick Scan' if quick_scan else 'Standard Scan'
        scan_info = Panel(
            f"""[bold]Target:[/bold] {target_url}
[bold]Depth:[/bold] {depth}
[bold]Threads:[/bold] {threads}
[bold]AI Provider:[/bold] {ai_provider}
[bold]Scan Mode:[/bold] {scan_mode}
[bold]Reconnaissance:[/bold] {'Enabled' if enable_recon else 'Disabled'}""",
            title="Scan Configuration",
            border_style="green"
        )
        console.print(scan_info)
        
        # Start scanning
        console.print("\n[bold green]Starting scan...[/bold green]\n")
        
        results = scanner.scan(
            enable_recon=enable_recon,
            full_scan=full_scan,
            quick_scan=quick_scan
        )
        
        # Generate report (from config)
        reporting_config = config.get('reporting', {})
        if reporting_config.get('enabled', True):
            console.print("\n[bold blue]Generating report...[/bold blue]")
            report_gen = ReportGenerator(config)
            
            # Get output settings from config
            output_dir = reporting_config.get('output_directory', 'reports')
            output_filename = reporting_config.get('output_filename', '')
            report_format = reporting_config.get('default_format', 'html')
            
            # Create output directory if it doesn't exist
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            # Generate filename if not specified
            if not output_filename:
                from datetime import datetime
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                domain = Path(target_url).stem.replace(':', '_')
                output_filename = f"deep_eye_{domain}_{timestamp}.{report_format}"
            
            output_path = str(Path(output_dir) / output_filename)
            
            report_gen.generate(
                results=results,
                output_path=output_path,
                format=report_format
            )
            
            console.print(f"[bold green]✓[/bold green] Report saved to: {output_path}")
        
        # Display summary
        vuln_count = len(results.get('vulnerabilities', []))
        severity_counts = results.get('severity_summary', {})
        
        summary = Panel(
            f"""[bold]Total Vulnerabilities:[/bold] {vuln_count}
[bold red]Critical:[/bold red] {severity_counts.get('critical', 0)}
[bold yellow]High:[/bold yellow] {severity_counts.get('high', 0)}
[bold blue]Medium:[/bold blue] {severity_counts.get('medium', 0)}
[bold green]Low:[/bold green] {severity_counts.get('low', 0)}
[bold]URLs Crawled:[/bold] {results.get('urls_crawled', 0)}
[bold]Scan Duration:[/bold] {results.get('duration', 'N/A')}""",
            title="Scan Summary",
            border_style="cyan"
        )
        console.print("\n", summary)
        
        console.print("\n[bold green]Scan completed successfully![/bold green] 🎉\n")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"\n[bold red]Error:[/bold red] {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
