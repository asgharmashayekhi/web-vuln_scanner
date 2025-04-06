#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proxy Handler Module.
This module provides functionality for using and managing proxy connections,
including Tor for anonymous scanning.
"""

import time
import socket
import logging
import requests
from typing import Optional, Dict, Any, Tuple
from stem import Signal
from stem.control import Controller
from contextlib import contextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('proxy_handler')

class ProxyHandler:
    """
    Handler for proxy connections, including Tor.
    """
    
    def __init__(self, proxy_url: Optional[str] = None, 
                 tor_control_port: int = 9051,
                 tor_auth_password: Optional[str] = None,
                 check_connection: bool = True,
                 verbose: bool = False):
        """
        Initialize proxy handler.
        
        Args:
            proxy_url (str, optional): Proxy URL (e.g., 'socks5://127.0.0.1:9050' for Tor)
            tor_control_port (int): Tor control port for sending signals
            tor_auth_password (str, optional): Password for Tor control authentication
            check_connection (bool): Whether to check proxy connection on initialization
            verbose (bool): Enable verbose output
        """
        self.proxy_url = proxy_url
        self.tor_control_port = tor_control_port
        self.tor_auth_password = tor_auth_password
        self.verbose = verbose
        
        # Configure logger level based on verbose flag
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # Check if using Tor
        self.is_tor = proxy_url and 'socks5://127.0.0.1:' in proxy_url
        
        # Set up proxy settings for requests
        self.proxies = None
        if proxy_url:
            self.proxies = {
                'http': proxy_url,
                'https': proxy_url
            }
            logger.debug(f"Proxy configured: {proxy_url}")
        
        # Check if proxy is working
        if check_connection and proxy_url:
            if self.check_proxy_connection():
                logger.info(f"Successfully connected through proxy: {proxy_url}")
            else:
                logger.warning(f"Failed to connect through proxy: {proxy_url}")
    
    def check_proxy_connection(self) -> bool:
        """
        Check if the proxy connection is working.
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            # Try to make a request to a reliable service
            response = requests.get(
                'https://httpbin.org/ip',
                proxies=self.proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                ip_info = response.json()
                if self.verbose:
                    logger.debug(f"Connected through IP: {ip_info.get('origin')}")
                return True
            else:
                logger.warning(f"Proxy connection check failed with status code: {response.status_code}")
                return False
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect through proxy: {e}")
            return False
    
    def get_current_ip(self) -> Optional[str]:
        """
        Get the current public IP address.
        
        Returns:
            str or None: Public IP address or None if failed
        """
        try:
            # Try to get the current IP address
            response = requests.get(
                'https://httpbin.org/ip',
                proxies=self.proxies,
                timeout=10
            )
            
            if response.status_code == 200:
                ip_info = response.json()
                return ip_info.get('origin')
            else:
                logger.warning(f"Failed to get current IP with status code: {response.status_code}")
                return None
        
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get current IP: {e}")
            return None
    
    @contextmanager
    def tor_controller_session(self) -> Optional[Controller]:
        """
        Context manager for Tor controller sessions.
        
        Yields:
            Controller or None: Tor controller object or None if failed
        """
        controller = None
        try:
            # Connect to Tor controller
            controller = Controller.from_port(port=self.tor_control_port)
            
            # Authenticate
            if self.tor_auth_password:
                controller.authenticate(password=self.tor_auth_password)
            else:
                controller.authenticate()
            
            logger.debug("Successfully connected to Tor controller")
            yield controller
        
        except Exception as e:
            logger.error(f"Failed to connect to Tor controller: {e}")
            yield None
        
        finally:
            # Close the controller connection
            if controller:
                controller.close()
    
    def renew_tor_ip(self) -> bool:
        """
        Request a new Tor circuit to change the exit node IP.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.is_tor:
            logger.warning("Not using Tor proxy, cannot renew IP")
            return False
        
        try:
            with self.tor_controller_session() as controller:
                if not controller:
                    return False
                
                # Send NEWNYM signal to get a new circuit
                controller.signal(Signal.NEWNYM)
                
                # Wait for the new circuit to be established
                time.sleep(5)
                
                # Verify IP has changed (optional)
                old_ip = self.get_current_ip()
                new_ip = self.get_current_ip()
                
                if old_ip != new_ip:
                    logger.info(f"Tor IP successfully changed from {old_ip} to {new_ip}")
                    return True
                else:
                    logger.warning("Tor IP did not change after renewal request")
                    return False
        
        except Exception as e:
            logger.error(f"Failed to renew Tor IP: {e}")
            return False
    
    def get_session(self) -> requests.Session:
        """
        Create a requests session configured with the proxy.
        
        Returns:
            requests.Session: Configured session
        """
        session = requests.Session()
        
        if self.proxies:
            session.proxies = self.proxies
        
        return session


def get_tor_status() -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Check if Tor is running and get status information.
    
    Returns:
        tuple: (is_running, status_info)
    """
    # First check if Tor SOCKS port is open
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    
    result = sock.connect_ex(('127.0.0.1', 9050))
    sock.close()
    
    if result != 0:
        logger.warning("Tor SOCKS port (9050) is not open")
        return False, None
    
    # Try to connect to the control port
    try:
        with Controller.from_port(port=9051) as controller:
            try:
                # Try to authenticate with empty password
                controller.authenticate()
                
                # Get Tor version
                version = controller.get_version()
                
                # Get circuit information
                circuits = controller.get_circuits()
                circuit_count = len(circuits)
                
                # Get network status
                status = {
                    'version': version,
                    'circuit_count': circuit_count,
                    'is_authenticated': True
                }
                
                return True, status
            
            except Exception as e:
                logger.debug(f"Tor control authentication failed: {e}")
                # We can still report Tor is running, just can't get detailed status
                return True, {'is_authenticated': False}
    
    except Exception as e:
        logger.debug(f"Failed to connect to Tor control port: {e}")
        # SOCKS port is open but control port is not
        return True, {'is_authenticated': False, 'control_port': 'unavailable'} 