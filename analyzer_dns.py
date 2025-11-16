# analyzer_dns.py
"""
DNS Traffic Analyzer Module

This module analyzes DNS traffic to detect and analyze DNS queries and responses,
including potential security threats like DNS tunneling, data exfiltration, and more.

Key Features:
- Parses DNS packets with support for various record types
- Detects potential DNS tunneling attempts
- Identifies suspicious domain patterns
- Provides detailed analysis and statistics
- Supports both IPv4 and IPv6

ماژول تحلیل‌گر ترافیک DNS
این ماژول ترافیک DNS را برای تشخیص و تحلیل کوئری‌ها و پاسخ‌های DNS،
از جمله تهدیدات امنیتی احتمالی مانند تونل‌زنی DNS و استخراج داده‌ها تحلیل می‌کند.

ویژگی‌های کلیدی:
- تجزیه بسته‌های DNS با پشتیبانی از انواع رکوردهای مختلف
- تشخیص تلاش‌های احتمالی تونل‌زنی DNS
- شناسایی الگوهای مشکوک در نام دامنه‌ها
- ارائه تحلیل و آمار دقیق
- پشتیبانی از هر دو پروتکل IPv4 و IPv6
"""

import json
import os
import re
import socket
import struct
import sys
import binascii
import ipaddress
import logging
from collections import defaultdict, Counter
from datetime import datetime
from typing import (
    List, Dict, Any, Optional, Tuple, Union, Set, DefaultDict, 
    Iterator, Callable, TypeVar, cast, NamedTuple, AnyStr
)

# Type aliases for better code readability
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
DNSRecord = Dict[str, Any]
DNSQuery = Dict[str, Any]
DNSResponse = Dict[str, Any]
DNSPacket = Dict[str, Any]

# Constants for DNS protocol
MAX_DNS_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253
MAX_DNS_MESSAGE_LENGTH = 65535
MAX_COMPRESSION_POINTERS = 100  # Prevent compression pointer loops

# Path configuration
RAW_PATH = os.path.join("results", "raw_packets.json")
OUT_PATH = os.path.join("results", "dns_analysis.json")
LOG_PATH = os.path.join("logs", "dns_analyzer.log")

# Ensure directories exist
os.makedirs(os.path.dirname(RAW_PATH) or ".", exist_ok=True)
os.makedirs(os.path.dirname(OUT_PATH) or ".", exist_ok=True)
os.makedirs(os.path.dirname(LOG_PATH) or "logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_PATH, encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

def handle_exception(exc_type, exc_value, exc_traceback):
    """Handle uncaught exceptions and log them."""
    if issubclass(exc_type, KeyboardInterrupt):
        # Allow keyboard interrupts to be handled normally
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logger.critical("Uncaught exception", 
                   exc_info=(exc_type, exc_value, exc_traceback))

sys.excepthook = handle_exception

# DNS record types (IANA assigned)
DNS_RECORD_TYPES = {
    # Basic records
    1: 'A',        # IPv4 address
    2: 'NS',       # Name server
    5: 'CNAME',    # Canonical name
    6: 'SOA',      # Start of authority
    
    # Common records
    12: 'PTR',     # Pointer
    15: 'MX',      # Mail exchange
    16: 'TXT',     # Text
    28: 'AAAA',    # IPv6 address
    33: 'SRV',     # Service locator
    
    # Security records
    43: 'DS',      # Delegation signer
    46: 'RRSIG',   # DNSSEC signature
    47: 'NSEC',    # Next secure
    48: 'DNSKEY',  # DNS key
    
    # Modern records
    64: 'SVCB',    # Service binding
    65: 'HTTPS',   # HTTPS binding
    
    # QTYPEs (can also appear in queries)
    255: 'ANY',    # All records
    252: 'AXFR',   # Zone transfer
    251: 'IXFR'    # Incremental zone transfer
}

# DNS response codes (RCODE)
DNS_RCODES = {
    0: 'NOERROR',  # No error
    1: 'FORMERR',  # Format error
    2: 'SERVFAIL', # Server failure
    3: 'NXDOMAIN', # Non-existent domain
    4: 'NOTIMP',   # Not implemented
    5: 'REFUSED',  # Query refused
    9: 'NOTAUTH'   # Server not authoritative for zone
}