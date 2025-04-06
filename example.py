#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------
# Web Vulnerability Scanner - Developed by Asghar Mashayekhi
# Date: April 2025
# Github: https://github.com/asgharmashayekhi/web-vuln_scanner.git
# ------------------------------------------------------


"""
Web Vulnerability Scanner Example.

This script demonstrates how to use the web vulnerability scanner.
"""

import os
import sys
import webbrowser
from pathlib import Path


print("="*60)
print(" Web Vulnerability Scanner v1.0")
print(" Developed by Asghar Moshayekhi")
print("="*60)

# Add parent directory to path to make imports work when running this script directly
current_dir = Path(__file__).parent.absolute()
parent_dir = current_dir.parent
sys.path.append(str(parent_dir))

from web_vuln_scanner import VulnerabilityScanner

def main():
    """Run a sample vulnerability scan on a test website."""
    print("Web Vulnerability Scanner Example")
    print("=================================")
    
    # Define target (using a known vulnerable test site)
    target_url = "http://testphp.vulnweb.com"
    
    print(f"Target URL: {target_url}")
    print("Scan types: SQL Injection, XSS")
    print("This may take a few minutes...")
    
    # Create output report file in current directory
    output_file = os.path.join(os.getcwd(), "example_scan_report.html")
    
    # Initialize and run the scanner
    scanner = VulnerabilityScanner(
        url=target_url,
        scan_types=['sqli', 'xss'],
        output_file=output_file,
        delay=1,  # Be nice to the test site
        verbose=True
    )
    
    # Run the scan
    report_path = scanner.scan()
    
    # Open the report in the default browser if scan was successful
    if report_path:
        print(f"\nScan completed! Report saved to: {report_path}")
        print("Opening report in browser...")
        try:
            webbrowser.open(f"file://{os.path.abspath(report_path)}")
        except Exception as e:
            print(f"Couldn't open browser automatically: {e}")
            print(f"Please open the report manually: {report_path}")
    else:
        print("\nScan failed. Check the logs for more information.")

if __name__ == "__main__":
    main() 