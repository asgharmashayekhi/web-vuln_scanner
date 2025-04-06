#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Base scanner class for all vulnerability scanners.
This module provides the foundation for all vulnerability scanner implementations.
"""

import requests
from urllib.parse import urljoin, urlparse
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('base_scanner')

class BaseScanner(ABC):
    """
    Abstract base class for all vulnerability scanners.
    Provides common functionality and defines the interface that all scanner classes must implement.
    """
    
    def __init__(self, url: str, proxy: Optional[str] = None, 
                 timeout: int = 10, delay: int = 1, 
                 user_agent_rotate: bool = False, verbose: bool = False):
        """
        Initialize the base scanner.
        
        Args:
            url (str): The target URL to scan
            proxy (str, optional): Proxy URL (e.g., 'socks5://127.0.0.1:9050')
            timeout (int): Request timeout in seconds
            delay (int): Delay between requests in seconds
            user_agent_rotate (bool): Whether to rotate user agents
            verbose (bool): Enable verbose output
        """
        self.target_url = url
        self.base_url = self._get_base_url(url)
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.vulnerabilities = []
        self.session = self._setup_session(proxy)
        self.user_agent_rotate = user_agent_rotate
        
        # Set logger level based on verbose flag
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        logger.debug(f"Initialized {self.__class__.__name__} for {url}")
    
    def _get_base_url(self, url: str) -> str:
        """
        Extract the base URL from the given URL.
        
        Args:
            url (str): The URL to parse
            
        Returns:
            str: The base URL
        """
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    def _setup_session(self, proxy: Optional[str] = None) -> requests.Session:
        """
        Set up a requests session with the specified proxy if provided.
        
        Args:
            proxy (str, optional): Proxy URL
            
        Returns:
            requests.Session: Configured session object
        """
        session = requests.Session()
        
        # Configure proxy if provided
        if proxy:
            if proxy.startswith('socks'):
                # Ensure PySocks is installed for SOCKS proxy support
                try:
                    import socks
                except ImportError:
                    logger.error("PySocks is required for SOCKS proxy support")
                    raise ImportError("PySocks is required for SOCKS proxy support")
            
            session.proxies = {
                'http': proxy,
                'https': proxy
            }
            logger.debug(f"Proxy configured: {proxy}")
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        return session
    
    def rotate_user_agent(self) -> None:
        """
        Rotate the user agent if user_agent_rotate is enabled.
        """
        if not self.user_agent_rotate:
            return
        
        try:
            from fake_useragent import UserAgent
            ua = UserAgent()
            self.session.headers.update({'User-Agent': ua.random})
            logger.debug(f"Rotated User-Agent: {self.session.headers['User-Agent']}")
        except ImportError:
            logger.warning("fake-useragent not installed. Cannot rotate user agents.")
        except Exception as e:
            logger.warning(f"Failed to rotate user agent: {e}")
    
    def make_request(self, url: str, method: str = 'GET', 
                   data: Optional[Dict[str, Any]] = None, 
                   params: Optional[Dict[str, Any]] = None,
                   headers: Optional[Dict[str, str]] = None,
                   allow_redirects: bool = True) -> Optional[requests.Response]:
        """
        Make an HTTP request with error handling and rate limiting.
        
        Args:
            url (str): URL to request
            method (str): HTTP method (GET, POST, etc.)
            data (dict, optional): POST data
            params (dict, optional): Query parameters
            headers (dict, optional): Additional headers
            allow_redirects (bool): Whether to follow redirects
            
        Returns:
            requests.Response or None: Response object or None if the request failed
        """
        full_url = urljoin(self.base_url, url) if not url.startswith('http') else url
        
        # Rotate user agent if enabled
        self.rotate_user_agent()
        
        # Add any custom headers
        current_headers = self.session.headers.copy()
        if headers:
            current_headers.update(headers)
        
        # Log request details if verbose
        if self.verbose:
            logger.debug(f"Making {method} request to {full_url}")
            if params:
                logger.debug(f"Params: {params}")
            if data:
                logger.debug(f"Data: {data}")
        
        try:
            # Apply rate limiting
            time.sleep(self.delay)
            
            # Make the request
            response = self.session.request(
                method=method,
                url=full_url,
                data=data,
                params=params,
                headers=current_headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects
            )
            
            # Log response details if verbose
            if self.verbose:
                logger.debug(f"Response status: {response.status_code}")
                logger.debug(f"Response headers: {response.headers}")
            
            return response
        
        except requests.exceptions.Timeout:
            logger.error(f"Request to {full_url} timed out after {self.timeout} seconds")
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error when requesting {full_url}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request to {full_url} failed: {e}")
        
        return None
    
    def add_vulnerability(self, vuln_type: str, url: str, title: str, 
                       severity: str, description: str, 
                       details: Optional[str] = None, 
                       recommendation: Optional[str] = None) -> None:
        """
        Add a detected vulnerability to the list.
        
        Args:
            vuln_type (str): Type of vulnerability (SQLi, XSS, etc.)
            url (str): The URL where the vulnerability was found
            title (str): Title of the vulnerability
            severity (str): Severity level (high, medium, low, info)
            description (str): Description of the vulnerability
            details (str, optional): Technical details
            recommendation (str, optional): Recommended fix
        """
        vulnerability = {
            'type': vuln_type,
            'url': url,
            'title': title,
            'severity': severity.lower(),
            'description': description,
            'details': details,
            'recommendation': recommendation,
            'timestamp': time.time()
        }
        
        self.vulnerabilities.append(vulnerability)
        
        # Log the found vulnerability
        log_method = logger.critical if severity.lower() == 'high' else \
                    logger.error if severity.lower() == 'medium' else \
                    logger.warning if severity.lower() == 'low' else logger.info
        
        log_method(f"{vuln_type} - {title} found at {url} - {severity} severity")
    
    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Get all detected vulnerabilities.
        
        Returns:
            list: List of vulnerability dictionaries
        """
        return self.vulnerabilities
    
    @abstractmethod
    def scan(self) -> List[Dict[str, Any]]:
        """
        Abstract method that all scanner classes must implement.
        Performs the actual vulnerability scan.
        
        Returns:
            list: List of detected vulnerabilities
        """
        pass 