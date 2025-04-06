#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# ------------------------------------------------------
# Web Vulnerability Scanner - Developed by Asghar Mashayekhi
# Date: April 2025
# Github: https://github.com/asgharmashayekhi/web-vuln_scanner.git
# ------------------------------------------------------


"""
Web Vulnerability Scanner Package.

This package provides functionality for scanning web applications for common security vulnerabilities.
"""

from .scanner import VulnerabilityScanner, run_sample_scan

__version__ = '1.0.0'
__author__ = 'Asghar Moshayekhi <dallvllon@gmail.com>'


__all__ = ['VulnerabilityScanner', 'run_sample_scan'] 