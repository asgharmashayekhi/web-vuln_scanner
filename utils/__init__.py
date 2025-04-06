#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Vulnerability Scanner Utils Package.

This package contains utility modules for the vulnerability scanner.
"""

from .proxy_handler import ProxyHandler, get_tor_status
from .report_generator import ReportGenerator

__all__ = ['ProxyHandler', 'get_tor_status', 'ReportGenerator'] 