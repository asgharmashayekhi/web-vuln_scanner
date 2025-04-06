#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner.
This is the main module that orchestrates the scanning process.
"""

import os
import time
import logging
import argparse
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse

# Import scanner modules
from tests.sqli_scanner import SQLiScanner
from tests.xss_scanner import XSSScanner
from tests.csrf_scanner import CSRFScanner

# Import utility modules
from utils.proxy_handler import ProxyHandler, get_tor_status
from utils.report_generator import ReportGenerator


print("="*60)
print(" Web Vulnerability Scanner v1.0")
print(" Developed by Asghar Moshayekhi")
print("="*60)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scanner')

class VulnerabilityScanner:
    """
    Main vulnerability scanner class.
    Orchestrates the scanning process using multiple specialized scanners.
    """
    
    def __init__(self, url: str, proxy: Optional[str] = None,
                 output_file: str = 'vuln_report.html',
                 scan_types: Optional[List[str]] = None,
                 threads: int = 5, timeout: int = 10,
                 delay: int = 1, user_agent_rotate: bool = False,
                 verbose: bool = False):
        """
        Initialize the vulnerability scanner.
        
        Args:
            url (str): Target URL to scan
            proxy (str, optional): Proxy URL
            output_file (str): Path to save the report
            scan_types (list, optional): List of vulnerability types to scan for
            threads (int): Number of threads to use
            timeout (int): Request timeout in seconds
            delay (int): Delay between requests in seconds
            user_agent_rotate (bool): Whether to rotate user agents
            verbose (bool): Enable verbose output
        """
        self.target_url = url
        self.proxy = proxy
        self.output_file = output_file
        
        # Default to all scan types if none specified
        self.scan_types = scan_types if scan_types else ['sqli', 'xss', 'csrf']
        
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.user_agent_rotate = user_agent_rotate
        self.verbose = verbose
        
        # Set logger level based on verbose flag
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # Store scan results
        self.vulnerabilities = []
        
        # Common scanner parameters
        self.scanner_params = {
            'proxy': proxy,
            'timeout': timeout,
            'delay': delay,
            'user_agent_rotate': user_agent_rotate,
            'verbose': verbose
        }
        
        # Initialize proxy handler
        self.proxy_handler = None
        if proxy:
            self.proxy_handler = ProxyHandler(proxy, verbose=verbose)
        
        # Initialize report generator
        self.report_generator = ReportGenerator(verbose=verbose)
    
    def _validate_target_url(self) -> bool:
        """
        Validate the target URL.
        
        Returns:
            bool: True if URL is valid, False otherwise
        """
        try:
            parsed_url = urlparse(self.target_url)
            return all([parsed_url.scheme, parsed_url.netloc])
        except Exception as e:
            logger.error(f"Invalid target URL: {e}")
            return False
    
    def _rotate_proxy_ip(self) -> bool:
        """
        Rotate the proxy IP (if using Tor).
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.proxy_handler:
            logger.warning("No proxy handler available, cannot rotate IP")
            return False
        
        return self.proxy_handler.renew_tor_ip()
    
    def _run_sqli_scan(self) -> List[Dict[str, Any]]:
        """
        Run SQL Injection scan.
        
        Returns:
            list: List of detected vulnerabilities
        """
        logger.info("Starting SQL Injection scan")
        scanner = SQLiScanner(self.target_url, **self.scanner_params)
        vulnerabilities = scanner.scan()
        logger.info(f"SQL Injection scan completed, found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_xss_scan(self) -> List[Dict[str, Any]]:
        """
        Run Cross-Site Scripting scan.
        
        Returns:
            list: List of detected vulnerabilities
        """
        logger.info("Starting Cross-Site Scripting scan")
        scanner = XSSScanner(self.target_url, **self.scanner_params)
        vulnerabilities = scanner.scan()
        logger.info(f"Cross-Site Scripting scan completed, found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def _run_csrf_scan(self) -> List[Dict[str, Any]]:
        """
        Run Cross-Site Request Forgery scan.
        
        Returns:
            list: List of detected vulnerabilities
        """
        logger.info("Starting Cross-Site Request Forgery scan")
        scanner = CSRFScanner(self.target_url, **self.scanner_params)
        vulnerabilities = scanner.scan()
        logger.info(f"Cross-Site Request Forgery scan completed, found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    def scan(self) -> str:
        """
        Run the vulnerability scan.
        
        Returns:
            str: Path to the generated report file
        """
        # Validate target URL
        if not self._validate_target_url():
            logger.error(f"Invalid target URL: {self.target_url}")
            return ""
        
        # Start timing the scan
        start_time = time.time()
        
        logger.info(f"Starting vulnerability scan on {self.target_url}")
        logger.info(f"Scan types: {', '.join(self.scan_types)}")
        
        # Check proxy status if using proxy
        if self.proxy:
            logger.info(f"Using proxy: {self.proxy}")
            if self.proxy.startswith('socks5://127.0.0.1:') and 'tor' in self.scan_types:
                is_tor_running, tor_status = get_tor_status()
                if is_tor_running:
                    logger.info("Tor is running")
                    if tor_status and tor_status.get('version'):
                        logger.info(f"Tor version: {tor_status.get('version')}")
                else:
                    logger.warning("Tor does not appear to be running. SOCKS proxy may not work.")
        
        # Run the selected scans
        if 'sqli' in self.scan_types:
            sqli_vulnerabilities = self._run_sqli_scan()
            self.vulnerabilities.extend(sqli_vulnerabilities)
            
            # Optional: rotate IP after each scan type
            if self.proxy_handler and len(self.scan_types) > 1:
                self._rotate_proxy_ip()
        
        if 'xss' in self.scan_types:
            xss_vulnerabilities = self._run_xss_scan()
            self.vulnerabilities.extend(xss_vulnerabilities)
            
            # Optional: rotate IP after each scan type
            if self.proxy_handler and len(self.scan_types) > 1:
                self._rotate_proxy_ip()
        
        if 'csrf' in self.scan_types:
            csrf_vulnerabilities = self._run_csrf_scan()
            self.vulnerabilities.extend(csrf_vulnerabilities)
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        # Generate report
        report_path = self.report_generator.generate_html_report(
            target_url=self.target_url,
            vulnerabilities=self.vulnerabilities,
            scan_types=self.scan_types,
            scan_duration=scan_duration,
            output_file=self.output_file
        )
        
        logger.info(f"Vulnerability scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} total vulnerabilities")
        logger.info(f"Report saved to {report_path}")
        
        return report_path


def parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    
    parser.add_argument('--url', type=str, required=True,
                      help='Target URL to scan')
    
    parser.add_argument('--output', type=str, default='vuln_report.html',
                      help='Output file for HTML report (default: vuln_report.html)')
    
    parser.add_argument('--proxy', type=str,
                      help='Proxy server to use (e.g., socks5://127.0.0.1:9050 for Tor)')
    
    parser.add_argument('--scan-type', type=str, nargs='+', choices=['sqli', 'xss', 'csrf', 'all'],
                      default=['all'], help='Specify scan types (default: all)')
    
    parser.add_argument('--threads', type=int, default=5,
                      help='Number of threads to use for scanning (default: 5)')
    
    parser.add_argument('--timeout', type=int, default=10,
                      help='Request timeout in seconds (default: 10)')
    
    parser.add_argument('--delay', type=int, default=1,
                      help='Delay between requests in seconds (default: 1)')
    
    parser.add_argument('--user-agent-rotate', action='store_true',
                      help='Enable User-Agent rotation')
    
    parser.add_argument('--verbose', action='store_true',
                      help='Enable verbose output')
    
    return parser.parse_args()


def main() -> None:
    """
    Main function to run the scanner from command line.
    """
    # Parse command line arguments
    args = parse_arguments()
    
    # Process scan types
    scan_types = []
    if 'all' in args.scan_type:
        scan_types = ['sqli', 'xss', 'csrf']
    else:
        scan_types = args.scan_type
    
    # Create scanner instance
    scanner = VulnerabilityScanner(
        url=args.url,
        proxy=args.proxy,
        output_file=args.output,
        scan_types=scan_types,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        user_agent_rotate=args.user_agent_rotate,
        verbose=args.verbose
    )
    
    # Run the scan
    scanner.scan()


if __name__ == '__main__':
    # This code is executed when the script is run directly
    main()


# Example usage for import scenarios
def run_sample_scan() -> None:
    """
    Run a sample scan on a demo vulnerable website.
    """
    # Target a known vulnerable test site
    scanner = VulnerabilityScanner(
        url="http://testphp.vulnweb.com",
        scan_types=['sqli', 'xss'],
        output_file="sample_scan_report.html",
        verbose=True
    )
    
    scanner.scan() 