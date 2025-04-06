#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Report Generator Module.
This module provides functionality for generating HTML reports of vulnerability scan results.
"""

import os
import datetime
import logging
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('report_generator')

class ReportGenerator:
    """
    Generates HTML reports from vulnerability scan results.
    """
    
    def __init__(self, template_dir: Optional[str] = None, verbose: bool = False):
        """
        Initialize the report generator.
        
        Args:
            template_dir (str, optional): Directory containing the report templates
            verbose (bool): Enable verbose output
        """
        self.verbose = verbose
        
        # Set logger level based on verbose flag
        if verbose:
            logger.setLevel(logging.DEBUG)
        
        # Set up the template directory
        # If no template directory is provided, use the default templates directory
        if template_dir is None:
            # Get the directory where this script is located
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # Go up one level to the package root, then into templates
            template_dir = os.path.join(os.path.dirname(current_dir), 'templates')
        
        logger.debug(f"Using template directory: {template_dir}")
        
        # Set up Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=True
        )
    
    def _group_vulnerabilities_by_type(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group vulnerabilities by their type.
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            
        Returns:
            dict: Dictionary with vulnerability types as keys and lists of vulnerabilities as values
        """
        grouped = {}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Other')
            if vuln_type not in grouped:
                grouped[vuln_type] = []
            grouped[vuln_type].append(vuln)
        
        return grouped
    
    def _count_vulnerabilities_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count vulnerabilities by severity level.
        
        Args:
            vulnerabilities (list): List of vulnerability dictionaries
            
        Returns:
            dict: Dictionary with severity levels as keys and counts as values
        """
        counts = {
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def generate_html_report(self, target_url: str, vulnerabilities: List[Dict[str, Any]], 
                          scan_types: List[str], scan_duration: float,
                          output_file: str) -> str:
        """
        Generate an HTML report of the vulnerability scan results.
        
        Args:
            target_url (str): URL that was scanned
            vulnerabilities (list): List of vulnerability dictionaries
            scan_types (list): List of vulnerability types that were scanned for
            scan_duration (float): Duration of the scan in seconds
            output_file (str): File to save the report to
            
        Returns:
            str: Path to the saved report file
        """
        logger.info(f"Generating HTML report to {output_file}")
        
        # Get report template
        template = self.env.get_template('report_template.html')
        
        # Prepare template data
        scan_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        grouped_vulnerabilities = self._group_vulnerabilities_by_type(vulnerabilities)
        severity_counts = self._count_vulnerabilities_by_severity(vulnerabilities)
        
        # Create template context
        context = {
            'target_url': target_url,
            'scan_date': scan_date,
            'scan_duration': round(scan_duration, 2),
            'scan_types': scan_types,
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': grouped_vulnerabilities,
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'info_count': severity_counts['info']
        }
        
        # Render template
        report_html = template.render(**context)
        
        # Save the report to a file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_html)
        
        logger.info(f"HTML report saved to {output_file}")
        
        return output_file 