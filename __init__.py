#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner Package.

This package provides functionality for scanning web applications for common security vulnerabilities.
"""

from .scanner import VulnerabilityScanner, run_sample_scan

__version__ = '1.0.0'
__author__ = 'Asghar Moshayekhi <dallvllon@gmail.com>'


__all__ = ['VulnerabilityScanner', 'run_sample_scan'] 