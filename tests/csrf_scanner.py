#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# ------------------------------------------------------
# Web Vulnerability Scanner - Developed by Asghar Mashayekhi
# Date: April 2025
# Github: https://github.com/asgharmashayekhi/web-vuln_scanner.git
# ------------------------------------------------------


"""
Cross-Site Request Forgery (CSRF) Scanner Module.
This module implements scanning functionality to detect CSRF vulnerabilities.
"""

import re
import logging
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from .base_scanner import BaseScanner

# Configure logging
logger = logging.getLogger('csrf_scanner')

class CSRFScanner(BaseScanner):
    """
    Cross-Site Request Forgery vulnerability scanner.
    Detects potential CSRF vulnerabilities in web applications.
    """
    
    def __init__(self, url: str, **kwargs):
        """
        Initialize CSRF scanner with specific CSRF testing parameters.
        
        Args:
            url (str): The target URL to scan
            **kwargs: Additional arguments to pass to the base scanner
        """
        super().__init__(url, **kwargs)
        
        # Common CSRF token names to look for
        self.csrf_token_names = [
            'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
            'csrf_token', 'xsrf_token', 'security_token', 'request_token',
            'anticsrf', 'anti-csrf', '__RequestVerificationToken',
            'CSRFToken', 'XSRF-TOKEN', '_csrf_token', '_csrf',
            'csrf-token', 'xsrf-token', '_RequestVerificationToken'
        ]
        
        # Common CSRF header names
        self.csrf_header_names = [
            'X-CSRF-Token', 'X-XSRF-Token', 'X-CSRFToken',
            'X-Requested-With', 'RequestVerificationToken',
            'X-CSRF-Protection', 'CSRF-Token', 'XSRF-TOKEN'
        ]
        
        # Initialize found forms
        self.forms_info = []
        
        # Track already tested URLs to avoid duplicates
        self.tested_urls = set()
        
    def _extract_forms(self, url: str) -> List[Dict[str, Any]]:
        """
        Extract forms from a webpage.
        
        Args:
            url (str): URL to extract forms from
            
        Returns:
            list: List of forms with their details
        """
        response = self.make_request(url)
        if not response:
            return []
        
        forms = []
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for form in soup.find_all('form'):
            form_details = {}
            form_details['action'] = form.get('action', '')
            form_details['method'] = form.get('method', 'get').lower()
            
            # Only analyze POST forms (GET forms are typically not vulnerable to CSRF)
            if form_details['method'] != 'post':
                continue
            
            # Extract input fields
            inputs = []
            for input_tag in form.find_all('input'):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                
                if input_name:  # Skip inputs without name
                    inputs.append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })
            
            form_details['inputs'] = inputs
            
            # Store the full form HTML for reference
            form_details['html'] = str(form)
            
            # Store cookies that were sent with the request
            form_details['cookies'] = response.cookies
            
            # Store headers for later analysis
            form_details['headers'] = response.headers
            
            forms.append(form_details)
        
        return forms
    
    def _has_csrf_token(self, form: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Check if a form has a CSRF token.
        
        Args:
            form (dict): Form details
            
        Returns:
            tuple: (has_token, token_name)
        """
        for input_field in form['inputs']:
            input_name = input_field['name'].lower()
            
            # Check if input name matches common CSRF token patterns
            for token_name in self.csrf_token_names:
                if token_name.lower() in input_name:
                    # If token exists but has no value, it might still be vulnerable
                    if input_field['value']:
                        return True, input_field['name']
                    else:
                        logger.debug(f"Empty CSRF token found: {input_field['name']}")
        
        # Check for token in the form attributes
        if 'data-csrf' in form['html'] or 'data-token' in form['html']:
            return True, 'data-attribute'
        
        # No CSRF token found in the form
        return False, None
    
    def _has_csrf_cookie(self, form: Dict[str, Any]) -> bool:
        """
        Check if cookies contain CSRF tokens.
        
        Args:
            form (dict): Form details with cookies
            
        Returns:
            bool: True if CSRF tokens are found in cookies
        """
        if not form['cookies']:
            return False
            
        for cookie_name in form['cookies'].keys():
            for token_name in self.csrf_token_names:
                if token_name.lower() in cookie_name.lower():
                    return True
        
        return False
    
    def _has_csrf_header(self, form: Dict[str, Any]) -> bool:
        """
        Check if response headers contain CSRF-related values.
        
        Args:
            form (dict): Form details with headers
            
        Returns:
            bool: True if CSRF headers are found
        """
        if not form['headers']:
            return False
            
        for header_name in form['headers'].keys():
            for csrf_header in self.csrf_header_names:
                if csrf_header.lower() == header_name.lower():
                    return True
        
        # Check for Set-Cookie headers that might contain CSRF tokens
        if 'Set-Cookie' in form['headers']:
            cookies_str = form['headers']['Set-Cookie']
            for token_name in self.csrf_token_names:
                if token_name.lower() in cookies_str.lower():
                    return True
        
        return False
    
    def _check_same_site_cookie(self, form: Dict[str, Any]) -> bool:
        """
        Check if cookies have SameSite attribute set to protect against CSRF.
        
        Args:
            form (dict): Form details with cookies
            
        Returns:
            bool: True if SameSite=Strict or SameSite=Lax is set
        """
        # Check direct access to headers for Set-Cookie
        if 'Set-Cookie' in form['headers']:
            cookies_str = form['headers']['Set-Cookie']
            
            # Check for SameSite attribute
            if 'SameSite=Strict' in cookies_str or 'SameSite=strict' in cookies_str:
                return True
            
            # Lax provides some protection but not as strong as Strict
            if 'SameSite=Lax' in cookies_str or 'SameSite=lax' in cookies_str:
                return True
        
        # Also check the cookies object directly
        for cookie in form['cookies']:
            if hasattr(cookie, 'same_site'):
                if cookie.same_site in ['Strict', 'strict', 'Lax', 'lax']:
                    return True
        
        return False
    
    def _crawl_and_identify_forms(self) -> List[Dict[str, Any]]:
        """
        Perform basic crawling to identify POST forms that might be vulnerable to CSRF.
        
        Returns:
            list: List of forms with their details
        """
        logger.info("Crawling to identify forms for CSRF testing...")
        
        # Start with the target URL
        to_visit = {self.target_url}
        visited = set()
        forms_info = []
        
        # Limit the crawling depth and number of URLs
        max_urls = 20
        
        while to_visit and len(visited) < max_urls:
            current_url = to_visit.pop()
            
            if current_url in visited:
                continue
                
            visited.add(current_url)
            
            # Get the page and extract forms
            response = self.make_request(current_url)
            if not response:
                continue
                
            # Extract forms from the page
            page_forms = self._extract_forms(current_url)
            
            if page_forms:
                logger.debug(f"Found {len(page_forms)} POST forms on {current_url}")
                
                for form in page_forms:
                    # Convert relative form action URLs to absolute
                    form['full_action_url'] = urljoin(current_url, form['action']) if form['action'] else current_url
                    form['source_url'] = current_url
                    forms_info.append(form)
            
            # Parse the HTML content to find more links
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract links for further crawling
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                # Skip empty links, anchors, and external links
                if not href or href.startswith('#') or href.startswith('javascript:'):
                    continue
                    
                # Convert relative URL to absolute
                link = urljoin(current_url, href)
                
                # Ensure we stay within the same domain
                if urlparse(link).netloc == urlparse(self.target_url).netloc:
                    to_visit.add(link)
        
        logger.info(f"Crawling complete. Found {len(forms_info)} POST forms for CSRF testing")
        return forms_info
    
    def _test_form_for_csrf(self, form: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a form for CSRF vulnerability.
        
        Args:
            form (dict): Form details
            
        Returns:
            dict: Vulnerability assessment
        """
        # Initialize the vulnerability assessment
        vulnerability = {
            'url': form['full_action_url'],
            'source_url': form['source_url'],
            'method': form['method'].upper(),
            'is_vulnerable': False,
            'details': [],
            'token_type': None
        }
        
        # Check for CSRF token in form
        has_token, token_name = self._has_csrf_token(form)
        if has_token:
            vulnerability['token_type'] = f"Form token: {token_name}"
            vulnerability['details'].append(f"Form contains a CSRF token field: {token_name}")
        else:
            vulnerability['details'].append("No CSRF token found in form")
            vulnerability['is_vulnerable'] = True
        
        # Check for CSRF token in cookies
        has_cookie_token = self._has_csrf_cookie(form)
        if has_cookie_token:
            vulnerability['token_type'] = "Cookie token"
            vulnerability['details'].append("CSRF token found in cookies")
            # Having a cookie token alone doesn't guarantee protection
            # unless it's properly validated
        
        # Check for CSRF protection headers
        has_csrf_header = self._has_csrf_header(form)
        if has_csrf_header:
            vulnerability['token_type'] = "Header-based protection"
            vulnerability['details'].append("CSRF protection headers detected")
            # Headers alone may not be enough without proper validation
        
        # Check for SameSite cookie attribute
        has_samesite = self._check_same_site_cookie(form)
        if has_samesite:
            vulnerability['details'].append("SameSite cookie attribute detected (helps prevent CSRF)")
            vulnerability['is_vulnerable'] = False
        
        # If no CSRF protection is found at all, mark as vulnerable
        if not (has_token or has_cookie_token or has_csrf_header or has_samesite):
            vulnerability['is_vulnerable'] = True
            vulnerability['details'].append("No CSRF protection mechanism detected")
        
        # Extra check - if there's a hidden field that looks like a random token
        # but it's not specifically named as a CSRF token, consider it might be a custom implementation
        has_hidden_token = False
        for input_field in form['inputs']:
            if input_field['type'] == 'hidden' and input_field['value'] and len(input_field['value']) > 10:
                if not has_token:  # Only consider this if we didn't already find a named CSRF token
                    has_hidden_token = True
                    vulnerability['details'].append(f"Found hidden field that may be a custom CSRF token: {input_field['name']}")
                    vulnerability['token_type'] = f"Possible custom token: {input_field['name']}"
        
        # Update vulnerability status if a hidden token was found
        if has_hidden_token and not has_token:
            vulnerability['is_vulnerable'] = False
        
        return vulnerability
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for Cross-Site Request Forgery vulnerabilities.
        
        Returns:
            list: List of detected vulnerabilities
        """
        logger.info(f"Starting CSRF scan on {self.target_url}")
        start_time = time.time()
        
        # Crawl and identify forms for testing
        self.forms_info = self._crawl_and_identify_forms()
        
        # Test each form for CSRF vulnerabilities
        for form in self.forms_info:
            # Skip if we've already tested this form action URL
            if form['full_action_url'] in self.tested_urls:
                continue
                
            self.tested_urls.add(form['full_action_url'])
            
            # Test the form for CSRF
            vulnerability = self._test_form_for_csrf(form)
            
            # If the form is vulnerable, add it to our findings
            if vulnerability['is_vulnerable']:
                details_str = " | ".join(vulnerability['details'])
                
                self.add_vulnerability(
                    vuln_type='Cross-Site Request Forgery (CSRF)',
                    url=vulnerability['url'],
                    title='CSRF Vulnerability in Form',
                    severity='medium',
                    description='Form lacks proper CSRF protection, allowing attackers to forge requests.',
                    details=f"Source URL: {vulnerability['source_url']} | {details_str}",
                    recommendation='Implement anti-CSRF tokens, validate Origin/Referer headers, use SameSite cookies, or implement custom request verification.'
                )
            else:
                logger.debug(f"Form at {form['full_action_url']} appears to have CSRF protection: {vulnerability['token_type']}")
        
        scan_duration = time.time() - start_time
        logger.info(f"CSRF scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} CSRF vulnerabilities")
        
        return self.vulnerabilities 