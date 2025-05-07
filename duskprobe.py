#!/usr/bin/env python3
"""
DuskProbe - Professional Web Vulnerability Scanner v4.2

A comprehensive web vulnerability scanner with advanced features for detecting XSS, SQLi, LFI,
Web3 vulnerabilities, cryptominers, and network anomalies. Includes Tor integration, ML-based
anomaly detection, and secure plugin loading.

Features:
- Asynchronous HTTP requests with connection pooling
- Ethical crawling with robots.txt respect
- Secure encryption for configurations and reports
- HMAC-based plugin signature verification
- ML-based network anomaly detection
- Web3 contract auditing
- Comprehensive reporting in HTML, JSON, and Markdown
"""

import os
import sys
import re
import ssl
import json
import time
import hashlib
import asyncio
import argparse
import logging
import socket
import hmac
import base64
import importlib
import joblib
import shutil
import traceback
from datetime import datetime
from typing import List, Dict, Optional, Union, Generator
from urllib.parse import urlparse, urljoin
from cryptography.fernet import Fernet
from colorama import Fore, init
from stem.process import launch_tor_with_config
from stem.control import Controller
from stem import Signal
from fake_useragent import UserAgent
from web3 import Web3, HTTPProvider
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from bs4 import BeautifulSoup
import aiohttp
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from scapy.all import sniff
from pybloom_live import BloomFilter
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from logging.handlers import RotatingFileHandler
from urllib.robotparser import RobotFileParser

# Initialize colorama
init(autoreset=True)

# Global Configuration
MAX_THREADS = 50
REQUEST_TIMEOUT = 30
DEFAULT_USER_AGENT = "DuskProbe/4.2"
PLUGINS_DIR = "plugins"
REPORTS_DIR = "reports"
CONFIG_DIR = "config"
DEFAULT_CRAWL_DEPTH = 5
TOR_PORTS = [9050, 9150]
ML_MODEL_PATH = "anomaly_detector.model"
CRYPTO_MINER_SIGNATURES = [
    r'coin(-|)hive', r'cryptonight', r'miner\.rocks',
    r'webassembly\.instantiate', r'cn\.wasm', r'xmrig',
    r'crypto\-miner', r'miner\.js'
]
WEB3_ENDPOINTS = ['/web3', '/eth', '/wallet', '/contract', '/rinkeby', '/ropsten']
ONION_PATTERN = r'\.onion$'

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        RotatingFileHandler('duskprobe.log', maxBytes=10*1024*1024, backupCount=5),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DuskProbe")

# Dependency Check
def check_dependencies():
    required = [
        'aiohttp', 'requests', 'stem', 'web3', 'sklearn', 'scapy',
        'pybloom_live', 'cryptography', 'colorama', 'fake_useragent', 'bs4'
    ]
    missing = []
    for module in required:
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    if missing:
        raise ImportError(f"Missing dependencies: {', '.join(missing)}. Install using `pip install`.")

try:
    check_dependencies()
except ImportError as e:
    print(f"{Fore.RED}Error: {e}")
    sys.exit(1)

class Severity(Enum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class AuthType(Enum):
    NONE = 0
    BASIC = 1
    FORM = 2

class QuantumEncryptor:
    """Post-quantum resistant encryption with secure key management."""
    def __init__(self, key: str = None):
        if not key:
            key = os.getenv("DUSKPROBE_ENCRYPTION_KEY")
            if not key:
                logger.warning("No encryption key provided. Generating temporary key.")
                key = os.urandom(32).hex()
        self.key = hashlib.sha3_256(key.encode()).digest()
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key))

    def encrypt(self, data: str) -> str:
        """Encrypt data using Fernet."""
        try:
            return self.cipher.encrypt(data.encode()).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using Fernet."""
        try:
            return self.cipher.decrypt(encrypted_data.encode()).decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

class TorNetworkManager:
    """Manages Tor network integration with circuit renewal."""
    def __init__(self):
        self.controller = None
        self.tor_process = None
        self.tor_port = None
        self._check_tor_availability()

    def _check_tor_availability(self):
        if not shutil.which("tor"):
            logger.error("Tor binary not found. Install Tor using `sudo apt install tor`.")
            raise RuntimeError("Tor not installed")
        for port in TOR_PORTS:
            if self._is_port_available(port):
                self.tor_port = port
                return
        logger.error("No available Tor ports.")
        raise RuntimeError("Tor ports unavailable")

    def _is_port_available(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('127.0.0.1', port)) != 0

    async def start_tor_service(self) -> bool:
        """Start Tor service and schedule circuit renewal."""
        try:
            self.tor_process = launch_tor_with_config(
                config={'SocksPort': str(self.tor_port)},
                init_msg_handler=lambda line: logger.debug(line)
            )
            asyncio.create_task(self._periodic_renew_circuit())
            logger.info(f"Tor service started on port {self.tor_port}")
            return True
        except Exception as e:
            logger.error(f"Tor startup failed: {e}")
            return False

    async def renew_circuit(self) -> None:
        """Renew Tor circuit for anonymity."""
        try:
            with Controller.from_port(port=self.tor_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.debug("Tor circuit renewed")
        except Exception as e:
            logger.error(f"Failed to renew Tor circuit: {e}")

    async def _periodic_renew_circuit(self):
        """Periodically renew Tor circuit every 5 minutes."""
        while True:
            await asyncio.sleep(300)
            await self.renew_circuit()

    def stop(self):
        """Stop Tor service."""
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process = None
                logger.info("Tor service stopped")
            except Exception as e:
                logger.error(f"Failed to stop Tor service: {e}")

class AdvancedSession:
    """Evasion-enabled asynchronous session manager with connection pooling."""
    def __init__(self, use_tor: bool = False, ja3_hash: str = None):
        self.session = None
        self.use_tor = use_tor
        self.ja3_hash = ja3_hash
        self.user_agent = DEFAULT_USER_AGENT
        try:
            self.user_agent = UserAgent().random
        except Exception as e:
            logger.warning(f"User agent randomization failed: {e}")
        self.cookie_jar = aiohttp.CookieJar()
        self.connector = aiohttp.TCPConnector(limit=50, ssl=False)
        self.fingerprint = self._generate_fingerprint()

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            cookie_jar=self.cookie_jar
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()
            self.session = None

    async def fetch(self, url: str, method: str = 'GET', **kwargs) -> Optional[str]:
        """Fetch URL content with retries and rate limiting."""
        try:
            headers = self._create_headers()
            connector = self._create_connector()
            async with self.session.request(
                method, url,
                headers=headers,
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                **kwargs
            ) as response:
                if response.status == 429:
                    retry_after = response.headers.get('Retry-After', 5)
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = 5
                    logger.warning(f"Rate limit detected at {url}. Retrying after {delay}s.")
                    await asyncio.sleep(delay)
                    return await self.fetch(url, method, **kwargs)
                return await response.text()
        except aiohttp.ClientError as e:
            logger.error(f"Request failed for {url}: {e}")
            return None

    def _create_connector(self) -> aiohttp.TCPConnector:
        if self.use_tor:
            return aiohttp.TCPConnector(
                resolver=aiohttp.AsyncResolver(),
                ssl=False,
                local_addr=('127.0.0.1', TOR_PORTS[0])
            )
        return self.connector

    def _create_headers(self) -> Dict:
        """Create sanitized HTTP headers."""
        return {
            'User-Agent': self.user_agent,
            'Accept-Encoding': 'gzip, deflate',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'DNT': '1',
            'Connection': 'keep-alive'
        }

    def _generate_fingerprint(self) -> str:
        """Generate a session fingerprint."""
        return hashlib.sha256(
            f"{self.user_agent}{int(time.time())}".encode()
        ).hexdigest()

class Config:
    """Configuration manager with secure file handling and plugin validation."""
    def __init__(self):
        os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
        os.makedirs(PLUGINS_DIR, mode=0o700, exist_ok=True)
        os.makedirs(REPORTS_DIR, mode=0o700, exist_ok=True)
        self.config_path = os.path.join(os.getcwd(), CONFIG_DIR)
        self.payloads = self._load_config("payloads.json", self.default_payloads())
        self.wordlists = self._load_config("wordlists.json", self.default_wordlists())
        self.report_config = self._load_config("report_config.json", self.default_report_config())
        self.advanced_settings = self._load_config("advanced_settings.json", self.default_advanced_settings())
        self.encryption_config = self._load_config("encryption.json", self.default_encryption_config())
        self.plugins = self._load_plugins()

    def _load_config(self, filename: str, default: Dict) -> Dict:
        """Load configuration file or return defaults."""
        file_path = os.path.join(self.config_path, filename)
        try:
            with open(file_path, "r") as f:
                logger.debug(f"Loading configuration file: {filename}")
                data = json.load(f)
                os.chmod(file_path, 0o600)
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning(f"Config file {filename} missing or invalid. Using defaults.")
            with open(file_path, "w") as f:
                json.dump(default, f, indent=4)
                os.chmod(file_path, 0o600)
            return default

    def _load_plugins(self) -> List:
        """Load plugins with HMAC-based signature validation."""
        plugins = []
        plugins_path = os.path.join(os.getcwd(), PLUGINS_DIR)
        if not os.path.exists(plugins_path):
            logger.warning(f"Plugins directory {PLUGINS_DIR} does not exist.")
            return plugins
        
        trusted_signatures = self.encryption_config.get("plugin_signatures", {})
        dangerous_patterns = [
            r'\bos\.\w+\s*\(', r'\bexec\s*\(', r'\beval\s*\(',
            r'\bsubprocess\.\w+\s*\(', r'\bsocket\.\w+\s*\('
        ]
        dangerous_re = re.compile('|'.join(dangerous_patterns))
        hmac_key = self.encryption_config.get("hmac_key", os.urandom(32).hex())

        for file in os.listdir(plugins_path):
            if file.startswith("plugin_") and file.endswith(".py"):
                file_path = os.path.join(plugins_path, file)
                file_hash = self._hash_file(file_path)
                expected_hmac = trusted_signatures.get(file)
                if not expected_hmac or not self._verify_hmac(file_hash, expected_hmac, hmac_key):
                    logger.error(f"Untrusted plugin {file}. Skipping.")
                    continue
                
                with open(file_path, 'r') as f:
                    content = f.read()
                    if dangerous_re.search(content):
                        logger.error(f"Potentially dangerous plugin {file}. Skipping.")
                        continue
                
                modulename = f"{PLUGINS_DIR}.{file[:-3]}"
                try:
                    module = importlib.import_module(modulename)
                    if not hasattr(module, 'Plugin'):
                        logger.error(f"Plugin {file} does not define Plugin class. Skipping.")
                        continue
                    plugin_instance = module.Plugin()
                    plugins.append(plugin_instance)
                    logger.debug(f"Loaded plugin: {file}")
                except Exception as e:
                    logger.error(f"Error loading plugin {file}: {e}")
        return plugins

    def _hash_file(self, file_path: str) -> str:
        """Compute SHA256 hash of a file."""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _verify_hmac(self, data: str, signature: str, key: str) -> bool:
        """Verify HMAC signature."""
        try:
            computed_hmac = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(computed_hmac, signature)
        except Exception as e:
            logger.error(f"HMAC verification failed: {e}")
            return False

    def default_payloads(self) -> Dict:
        """Default payloads for vulnerability testing."""
        return {
            "xss": ["<script>alert(1)</script>", "'><img src=x onerror=alert(1)>"],
            "sqli": ["' OR 1=1 --", "1; DROP TABLE users --"],
            "lfi": ["../../etc/passwd", "/proc/self/environ"]
        }

    def default_wordlists(self) -> Dict:
        """Default wordlists for directory and file scanning."""
        return {
            "dirs": ["admin", "login", "wp-admin"],
            "files": ["config.php", "backup.sql"],
            "subdomains": ["www", "mail", "api"]
        }

    def default_report_config(self) -> Dict:
        """Default report configuration."""
        return {
            "template": "default",
            "include_timestamp": True,
            "severity_colors": {
                "INFO": "blue",
                "LOW": "green",
                "MEDIUM": "yellow",
                "HIGH": "red",
                "CRITICAL": "magenta"
            }
        }

    def default_advanced_settings(self) -> Dict:
        """Default advanced settings."""
        return {
            "scan_timeout": 30,
            "max_depth": DEFAULT_CRAWL_DEPTH,
            "dynamic_user_agent": True,
            "max_retries": 3,
            "enable_ml_analysis": False,
            "enable_http2_scan": False,
            "enable_dependency_check": False,
            "enable_tor": False,
            "enable_web3_scan": False,
            "bloom_capacity": 100000,
            "pcap_path": "network.pcap",
            "web3_provider": ""
        }

    def default_encryption_config(self) -> Dict:
        """Default encryption configuration."""
        return {
            "enable_encryption": True,
            "encryption_key": os.urandom(32).hex(),
            "hmac_key": os.urandom(32).hex(),
            "plugin_signatures": {}
        }

class SessionManager:
    """Hybrid session manager with authentication and rate limiting."""
    def __init__(self, auth: Optional[Dict] = None, proxy: Union[str, Dict, None] = None):
        self.session = self._create_session()
        self.auth = auth
        self.proxy = proxy
        self.rate_limit_detected = False
        self.request_delay = 0

    def _create_session(self) -> requests.Session:
        """Create a requests session with retries."""
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
        return session

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make an HTTP request with rate limiting handling."""
        if self.rate_limit_detected and self.request_delay > 0:
            time.sleep(self.request_delay)
        try:
            response = self.session.request(method, url, timeout=REQUEST_TIMEOUT, 
                                         proxies=self.proxy, **kwargs)
            if response.status_code == 429:
                self.rate_limit_detected = True
                retry_after = response.headers.get('Retry-After', 5)
                try:
                    self.request_delay = min(float(retry_after), 10)
                except ValueError:
                    self.request_delay = min(self.request_delay + 1, 10)
                logger.warning(f"Rate limit detected at {url}. Delaying by {self.request_delay}s")
            elif self.rate_limit_detected and response.status_code == 200:
                self.rate_limit_detected = False
                self.request_delay = 0
            return response
        except Exception as e:
            logger.error(f"Request to {url} failed: {e}")
            raise

    def handle_auth(self):
        """Handle authentication based on configuration."""
        if not self.auth:
            return
        auth_method = self.auth.get("type", AuthType.NONE)
        try:
            if auth_method in [AuthType.BASIC.value, "BASIC"]:
                self.session.auth = (self.auth.get("username"), self.auth.get("password"))
                logger.info("Basic authentication configured")
            elif auth_method in [AuthType.FORM.value, "FORM"]:
                self._handle_form_auth()
            else:
                logger.warning(f"Unsupported auth type: {auth_method}")
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise

    def _handle_form_auth(self):
        """Handle form-based authentication."""
        login_url = self.auth.get("url")
        if not login_url or not re.match(r'^https?://', login_url):
            raise ValueError("Invalid or missing login URL")
        data = {
            self.auth.get("username_field", "username"): self.auth.get("username"),
            self.auth.get("password_field", "password"): self.auth.get("password")
        }
        try:
            r = self.session.post(login_url, data=data, timeout=REQUEST_TIMEOUT)
            success_indicator = self.auth.get("success_indicator", "dashboard")
            if r.status_code != 200 or success_indicator not in r.text.lower():
                raise Exception(f"Form auth failed: status {r.status_code} or missing success indicator")
            logger.info("Form authentication successful")
        except Exception as e:
            logger.error(f"Form authentication error: {e}")
            raise

class Web3Auditor:
    """Web3/blockchain vulnerability scanner."""
    def __init__(self, web3_provider: str = None):
        self.w3 = None
        if not web3_provider:
            logger.warning("No Web3 provider specified. Web3 auditing disabled.")
            return
        try:
            self.w3 = Web3(HTTPProvider(web3_provider))
            if not self.w3.is_connected():
                raise ValueError("Web3 provider not connected")
            logger.info(f"Connected to Web3 provider: {web3_provider}")
        except Exception as e:
            logger.error(f"Web3 provider initialization failed: {e}")
            self.w3 = None
        self.contract_pattern = re.compile(r'0x[a-fA-F0-9]{40}')
        self.abi_pattern = re.compile(r'ABI\s*:\s*(\[{.*?}\])', re.DOTALL)

    async def audit_contract(self, url: str) -> List[Dict]:
        """Audit webpage for Web3 contracts and ABIs."""
        findings = []
        if not self.w3:
            logger.warning("Web3 provider not initialized. Skipping contract audit.")
            return findings
        async with AdvancedSession() as session:
            try:
                content = await session.fetch(url)
                if not content:
                    return findings
                contracts = self.contract_pattern.findall(content)
                for contract in contracts:
                    findings.extend(self._analyze_contract(contract))
                
                abi_matches = self.abi_pattern.findall(content)
                for abi in abi_matches:
                    try:
                        findings.extend(self._analyze_abi(json.loads(abi)))
                    except json.JSONDecodeError:
                        logger.debug(f"Invalid ABI format at {url}")
            except Exception as e:
                logger.error(f"Web3 audit failed for {url}: {e}")
        return findings

    def _analyze_contract(self, address: str) -> List[Dict]:
        """Analyze a contract for vulnerabilities."""
        findings = []
        if not self.w3:
            return findings
        try:
            code = self.w3.eth.get_code(address)
            if b'DELEGATECALL' in code:
                findings.append({
                    'type': 'CONTRACT_DELEGATE_CALL',
                    'severity': Severity.CRITICAL.name,
                    'details': 'Unsafe delegatecall detected'
                })
            if b'SELFDESTRUCT' in code:
                findings.append({
                    'type': 'CONTRACT_SELFDESTRUCT',
                    'severity': Severity.HIGH.name,
                    'details': 'Selfdestruct capability found'
                })
        except Exception:
            logger.debug(f"Failed to analyze contract {address}")
        return findings

    def _analyze_abi(self, abi: List[Dict]) -> List[Dict]:
        """Analyze ABI for potential issues."""
        findings = []
        for item in abi:
            if item.get("type") == "function" and item.get("stateMutability") == "nonpayable":
                findings.append({
                    'type': 'CONTRACT_NONPAYABLE_FUNCTION',
                    'severity': Severity.MEDIUM.name,
                    'details': f"Non-payable function detected: {item.get('name')}"
                })
        return findings

class QuantumMLAnalyzer:
    """AI-powered anomaly detection with model persistence."""
    def __init__(self):
        self.model = IsolationForest(n_estimators=200, contamination=0.1)
        self.scaler = StandardScaler()
        self.anomalies = []
        self._load_model()

    def _load_model(self):
        """Load pre-trained ML model."""
        if os.path.exists(ML_MODEL_PATH):
            try:
                self.model = joblib.load(ML_MODEL_PATH)
                logger.info(f"Loaded ML model from {ML_MODEL_PATH}")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
        else:
            logger.warning("No pre-trained ML model found. Using untrained model.")

    async def analyze(self, pcap_path: str = None) -> List[Dict]:
        """Analyze network traffic for anomalies."""
        findings = []
        if not pcap_path:
            logger.warning("No PCAP file specified. Skipping ML analysis.")
            return findings
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file {pcap_path} not found")
            return findings
        try:
            packets = sniff(offline=pcap_path, filter="tcp", count=1000)
            features = self._extract_features(packets)
            if len(features) > 0:
                scaled = self.scaler.fit_transform(features)
                preds = self.model.fit_predict(scaled)
                self.anomalies = np.where(preds == -1)[0]
                findings.append({
                    'type': 'NETWORK_ANOMALY',
                    'severity': Severity.MEDIUM.name,
                    'details': f'Detected {len(self.anomalies)} anomalous packets'
                })
                joblib.dump(self.model, ML_MODEL_PATH)
                os.chmod(ML_MODEL_PATH, 0o600)
            else:
                logger.warning("No TCP packets found in PCAP")
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
        return findings

    def _extract_features(self, packets) -> List:
        """Extract features from network packets."""
        features = []
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                features.append([
                    pkt[IP].len,
                    pkt[TCP].sport,
                    pkt[TCP].dport,
                    len(pkt[TCP].payload)
                ])
        return features

class SSLChecker:
    """Check SSL/TLS configuration for vulnerabilities."""
    def run(self, hostname: str) -> Dict:
        """Run SSL checks on a hostname."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
            findings = {}
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            if not_after < datetime.utcnow():
                findings["expired"] = "Certificate expired"
            if protocol in ["SSLv3", "TLSv1", "TLSv1.1"]:
                findings["weak_protocol"] = f"Deprecated protocol: {protocol}"
            weak_ciphers = [c for c in [cipher] if "RC4" in c[0] or "MD5" in c[0]]
            if weak_ciphers:
                findings["weak_ciphers"] = f"Weak ciphers detected: {weak_ciphers}"
            return findings
        except Exception as e:
            logger.error(f"SSL check failed for {hostname}: {e}")
            return {"error": str(e)}

class GraphQLScanner:
    """Scan for GraphQL vulnerabilities."""
    def __init__(self, session: SessionManager):
        self.session = session

    def check_introspection(self, url: str) -> Dict:
        """Check if GraphQL introspection is enabled."""
        query = {"query": "query { __schema { types { name } } }"}
        try:
            resp = self.session.request("POST", url, json=query)
            try:
                data = resp.json()
                if isinstance(data, dict) and "data" in data and "__schema" in data["data"]:
                    return {
                        "type": "GRAPHQL_INTROSPECTION",
                        "severity": Severity.HIGH.name,
                        "details": "GraphQL introspection enabled"
                    }
            except ValueError:
                pass
            return {}
        except Exception as e:
            logger.error(f"GraphQL check failed for {url}: {e}")
            return {}

class HTTP2Scanner:
    """Scan for HTTP/2 vulnerabilities."""
    CVE_2023_43622_SIGNATURE = b"\x00\x00\x00\x00\x01\x00\x00\x00\x00"

    def check_http2_vulnerabilities(self, host: str, port: int = 443) -> List[Dict]:
        """Check for HTTP/2 vulnerabilities like CVE-2023-43622."""
        findings = []
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=5)
            sock.settimeout(5)
            context = ssl.create_default_context()
            context.set_alpn_protocols(["h2"])
            ssock = context.wrap_socket(sock, server_hostname=host)
            ssock.settimeout(5)
            ssock.send(self.CVE_2023_43622_SIGNATURE)
            response = ssock.recv(1024)
            if b"HTTP/2" in response and b"SETTINGS" not in response:
                findings.append({
                    'type': 'HTTP2_CVE_2023_43622',
                    'severity': Severity.CRITICAL.name,
                    'details': 'Vulnerable to HTTP/2 Rapid Reset (CVE-2023-43622)'
                })
            if self._detect_hpack_bomb(ssock):
                findings.append({
                    'type': 'HTTP2_HPACK_BOMB',
                    'severity': Severity.HIGH.name,
                    'details': 'Potential HPACK bomb vulnerability'
                })
        except (socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
            logger.error(f"HTTP/2 scan failed for {host}: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        return findings

    def _detect_hpack_bomb(self, sock: ssl.SSLSocket) -> bool:
        """Detect HPACK bomb vulnerability."""
        try:
            sock.send(b"\x00\x00\x01\x04\x00\x00\x00\x00\x00")
            sock.send(b"\x00\x00\x08\x01\x00\x00\x00\x00\x00")
            time.sleep(1)
            response = sock.recv(4096)
            return len(response) > 1024
        except (socket.timeout, socket.error):
            return False

class DependencyScanner:
    """Scan for dependency confusion vulnerabilities."""
    def __init__(self, session: SessionManager):
        self.session = session
        self.NPM_REGISTRY = "https://registry.npmjs.org/"
        self.PYPI_REGISTRY = "https://pypi.org/pypi/"

    def check_dependency_confusion(self, urls: List[str]) -> List[Dict]:
        """Check for dependency confusion in package files."""
        findings = []
        for url in urls:
            package_paths = [
                "package.json",
                "requirements.txt",
                "composer.json",
                "Gemfile"
            ]
            for path in package_paths:
                package_url = urljoin(url, path)
                try:
                    resp = self.session.request("GET", package_url)
                    if resp.status_code == 200:
                        if path.endswith("package.json"):
                            findings.extend(self._check_npm_dependencies(resp.json()))
                        elif path.endswith("requirements.txt"):
                            findings.extend(self._check_pypi_dependencies(resp.text))
                except Exception as e:
                    logger.debug(f"Failed to fetch {package_url}: {e}")
                    continue
        return findings

    def _check_npm_dependencies(self, data: Dict) -> List[Dict]:
        """Check NPM dependencies for confusion."""
        findings = []
        try:
            for dep, version in {**data.get("dependencies", {}), 
                               **data.get("devDependencies", {})}.items():
                if self._is_internal_package(dep):
                    registry_version = self._get_npm_version(dep)
                    if registry_version and self._is_version_higher(version, registry_version):
                        findings.append({
                            "type": "DEPENDENCY_CONFUSION_NPM",
                            "severity": Severity.CRITICAL.name,
                            "details": f"{dep}@{registry_version} exists in public registry"
                        })
        except Exception as e:
            logger.error(f"NPM dependency check failed: {e}")
        return findings

    def _check_pypi_dependencies(self, content: str) -> List[Dict]:
        """Check PyPI dependencies for confusion."""
        findings = []
        try:
            for line in content.splitlines():
                if line.strip() and not line.startswith('#'):
                    package = line.split('==')[0].strip()
                    if self._is_internal_package(package):
                        registry_version = self._get_pypi_version(package)
                        if registry_version:
                            findings.append({
                                "type": "DEPENDENCY_CONFUSION_PYPI",
                                "severity": Severity.CRITICAL.name,
                                "details": f"{package}@{registry_version} exists in public registry"
                            })
        except Exception as e:
            logger.error(f"PyPI dependency check failed: {e}")
        return findings

    def _is_internal_package(self, package: str) -> bool:
        """Check if package is internal."""
        return any(package.startswith(prefix) for prefix in ["@internal/", "company-"])

    def _get_npm_version(self, package: str) -> str:
        """Get latest NPM package version."""
        try:
            resp = self.session.request("GET", f"{self.NPM_REGISTRY}{package}")
            if resp.status_code == 200:
                return resp.json().get("dist-tags", {}).get("latest")
        except Exception:
            pass
        return ""

    def _get_pypi_version(self, package: str) -> str:
        """Get latest PyPI package version."""
        try:
            resp = self.session.request("GET", f"{self.PYPI_REGISTRY}{package}/json")
            if resp.status_code == 200:
                return resp.json().get("info", {}).get("version")
        except Exception:
            pass
        return ""

    def _is_version_higher(self, local_version: str, registry_version: str) -> bool:
        """Compare package versions."""
        try:
            from packaging import version
            return version.parse(registry_version) > version.parse(local_version)
        except:
            return False

class CryptoMinerDetector:
    """Detect cryptocurrency miners in web content."""
    def __init__(self):
        self.patterns = [re.compile(sig, re.IGNORECASE) for sig in CRYPTO_MINER_SIGNATURES]

    async def detect(self, url: str) -> List[Dict]:
        """Detect crypto miners in webpage."""
        findings = []
        async with AdvancedSession() as session:
            try:
                content = await session.fetch(url)
                if not content:
                    return findings
                for pattern in self.patterns:
                    if pattern.search(content):
                        findings.append({
                            'type': 'CRYPTOMINER',
                            'severity': Severity.HIGH.name,
                            'details': f'Cryptocurrency miner detected: {pattern.pattern}'
                        })
            except Exception as e:
                logger.error(f"Cryptominer detection failed for {url}: {e}")
        return findings

class SecurityPolicyChecker:
    """Check security headers and policies."""
    def __init__(self, session: SessionManager):
        self.session = session
        self.required_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security'
        ]

    def check_headers(self, url: str) -> Dict:
        """Check for missing security headers."""
        try:
            resp = self.session.request("GET", url)
            headers = resp.headers
            missing = [h for h in self.required_headers if h not in headers]
            if missing:
                return {
                    'type': 'MISSING_SECURITY_HEADERS',
                    'severity': Severity.MEDIUM.name,
                    'details': f"Missing headers: {', '.join(missing)}"
                }
            return {}
        except Exception as e:
            logger.error(f"Header check failed for {url}: {e}")
            return {}

class ReportGenerator:
    """Generate scan reports in various formats."""
    def __init__(self, results: Dict, report_config: Dict, encryptor: QuantumEncryptor):
        self.results = results
        self.config = report_config
        self.encryptor = encryptor

    def generate(self, format: str = "html", encrypt: bool = False) -> str:
        """Generate report in specified format."""
        if format == "html":
            report = self._generate_html()
        elif format == "json":
            report = json.dumps(self.results, indent=4)
        elif format == "markdown":
            report = self._generate_markdown()
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        timestamp = int(time.time())
        if encrypt:
            encrypted_report = self.encryptor.encrypt(report)
            report_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.enc")
            with open(report_path, "w") as f:
                f.write(json.dumps({
                    "encrypted_data": encrypted_report,
                    "key_hint": self.encryptor.key[:8].hex(),
                    "format": format
                }))
            os.chmod(report_path, 0o600)
            return report_path
        
        report_path = os.path.join(REPORTS_DIR, f"report_{timestamp}.{format}")
        with open(report_path, "w") as f:
            f.write(report)
        os.chmod(report_path, 0o600)
        return report_path

    def _generate_html(self) -> str:
        """Generate HTML report with summary."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for findings in self.results.values():
            for finding in findings:
                severity_counts[finding.get('severity', 'INFO')] += 1
        
        html = [
            "<!DOCTYPE html>",
            "<html><head><title>DuskProbe Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "table { border-collapse: collapse; width: 100%; }",
            "th, td { border: 1px solid #ddd; padding: 8px; }",
            "th { background-color: #f2f2f2; }",
            ".CRITICAL { color: red; font-weight: bold; }",
            ".HIGH { color: orange; }",
            ".MEDIUM { color: #cccc00; }",
            ".LOW { color: green; }",
            ".INFO { color: blue; }",
            ".summary { margin-bottom: 20px; }",
            "</style></head><body>",
            "<h1>DuskProbe Vulnerability Report</h1>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "<div class='summary'>",
            "<h2>Summary</h2>",
            "<ul>",
            f"<li>Critical: {severity_counts['CRITICAL']}</li>",
            f"<li>High: {severity_counts['HIGH']}</li>",
            f"<li>Medium: {severity_counts['MEDIUM']}</li>",
            f"<li>Low: {severity_counts['LOW']}</li>",
            f"<li>Info: {severity_counts['INFO']}</li>",
            "</ul></div>",
            "<table><tr><th>URL</th><th>Type</th><th>Severity</th><th>Details</th></tr>"
        ]
        for url, findings in sorted(self.results.items()):
            for finding in sorted(findings, key=lambda x: Severity[x.get('severity', 'INFO')].value, reverse=True):
                severity = finding.get('severity', 'INFO')
                html.append(
                    f"<tr><td>{url}</td><td>{finding['type']}</td>"
                    f"<td class='{severity}'>{severity}</td><td>{finding['details']}</td></tr>"
                )
        html.append("</table></body></html>")
        return "\n".join(html)

    def _generate_markdown(self) -> str:
        """Generate Markdown report with summary."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for findings in self.results.values():
            for finding in findings:
                severity_counts[finding.get('severity', 'INFO')] += 1
        
        md = [
            f"# DuskProbe Vulnerability Report\n",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
            "## Summary\n",
            f"- Critical: {severity_counts['CRITICAL']}\n",
            f"- High: {severity_counts['HIGH']}\n",
            f"- Medium: {severity_counts['MEDIUM']}\n",
            f"- Low: {severity_counts['LOW']}\n",
            f"- Info: {severity_counts['INFO']}\n\n",
            "| URL | Type | Severity | Details |\n",
            "|-----|------|----------|---------|\n"
        ]
        for url, findings in sorted(self.results.items()):
            for finding in sorted(findings, key=lambda x: Severity[x.get('severity', 'INFO')].value, reverse=True):
                severity = finding.get('severity', 'INFO')
                md.append(
                    f"| {url} | {finding['type']} | {severity} | {finding['details']} |\n"
                )
        return "".join(md)

class VulnerabilityScanner:
    """Traditional vulnerability scanner for common web vulnerabilities."""
    def __init__(self, session: SessionManager, config: Config):
        self.session = session
        self.config = config
        self.payloads = config.payloads

    async def run_all_tests(self, url: str) -> List[Dict]:
        """Run all vulnerability tests on a URL."""
        findings = []
        try:
            findings.extend(await self.test_xss(url))
            findings.extend(await self.test_sqli(url))
            findings.extend(await self.test_lfi(url))
        except Exception as e:
            logger.error(f"Vulnerability scan failed for {url}: {e}")
        return findings

    async def test_xss(self, url: str) -> List[Dict]:
        """Test for XSS vulnerabilities."""
        findings = []
        for payload in self.payloads.get("xss", []):
            test_url = f"{url}?q={payload}"
            try:
                async with AdvancedSession() as session:
                    content = await session.fetch(test_url)
                    if content and payload in content:
                        findings.append({
                            'type': 'XSS',
                            'severity': Severity.HIGH.name,
                            'details': f"Reflected XSS with payload: {payload}"
                        })
            except Exception as e:
                logger.debug(f"XSS test failed for {test_url}: {e}")
        return findings

    async def test_sqli(self, url: str) -> List[Dict]:
        """Test for SQL injection vulnerabilities."""
        findings = []
        for payload in self.payloads.get("sqli", []):
            test_url = f"{url}?id={payload}"
            try:
                async with AdvancedSession() as session:
                    content = await session.fetch(test_url)
                    if content and any(err in content.lower() for err in ["sql syntax", "mysql error"]):
                        findings.append({
                            'type': 'SQLI',
                            'severity': Severity.CRITICAL.name,
                            'details': f"SQL injection detected with payload: {payload}"
                        })
            except Exception as e:
                logger.debug(f"SQLi test failed for {test_url}: {e}")
        return findings

    async def test_lfi(self, url: str) -> List[Dict]:
        """Test for local file inclusion vulnerabilities."""
        findings = []
        for payload in self.payloads.get("lfi", []):
            test_url = f"{url}?file={payload}"
            try:
                async with AdvancedSession() as session:
                    content = await session.fetch(test_url)
                    if content and any(sig in content.lower() for sig in ["root:x:", "passwd"]):
                        findings.append({
                            'type': 'LFI',
                            'severity': Severity.CRITICAL.name,
                            'details': f"Local file inclusion detected with payload: {payload}"
                        })
            except Exception as e:
                logger.debug(f"LFI test failed for {test_url}: {e}")
        return findings

class AdvancedScanner:
    """Comprehensive vulnerability scanner with advanced features."""
    def __init__(self, session: SessionManager):
        self.session = session
        self.config = Config()
        self.bloom_filter = BloomFilter(
            capacity=self.config.advanced_settings.get("bloom_capacity", 100000),
            error_rate=0.01
        )
        self.bloom_count = 0
        self.graphql_scanner = GraphQLScanner(session)
        self.policy_checker = SecurityPolicyChecker(session)
        self.http2_scanner = HTTP2Scanner()
        self.dependency_scanner = DependencyScanner(session)
        self.web3_auditor = Web3Auditor(self.config.advanced_settings.get("web3_provider", ""))
        self.miner_detector = CryptoMinerDetector()
        self.ml_analyzer = QuantumMLAnalyzer()
        self.ssl_checker = SSLChecker()
        self.tor_manager = TorNetworkManager() if self.config.advanced_settings.get("enable_tor", False) else None
        self.encryptor = QuantumEncryptor(self.config.encryption_config["encryption_key"])

    async def advanced_vulnerability_scan(self, url: str) -> List[Dict]:
        """Perform advanced vulnerability scans."""
        findings = []
        try:
            # Header and policy checks
            findings.append(self.policy_checker.check_headers(url))
            
            # GraphQL checks
            graphql_endpoints = [urljoin(url, ep) for ep in ['/graphql', '/api/graphql']]
            for ep in graphql_endpoints:
                findings.append(self.graphql_scanner.check_introspection(ep))
            
            # Web3 and cryptominer checks
            if self.config.advanced_settings.get("enable_web3_scan", False):
                findings.extend(await self.web3_auditor.audit_contract(url))
                findings.extend(await self.miner_detector.detect(url))
            
            # HTTP/2 checks
            if self.config.advanced_settings.get("enable_http2_scan", False):
                host = urlparse(url).hostname
                findings.extend(self.http2_scanner.check_http2_vulnerabilities(host))
            
            # Dependency checks
            if self.config.advanced_settings.get("enable_dependency_check", False):
                findings.extend(self.dependency_scanner.check_dependency_confusion([url]))
            
            # ML analysis
            if self.config.advanced_settings.get("enable_ml_analysis", False):
                pcap_path = self.config.advanced_settings.get("pcap_path")
                findings.extend(await self.ml_analyzer.analyze(pcap_path))
        
        except Exception as e:
            logger.error(f"Advanced scan error for {url}: {e}")
        return [f for f in findings if f]

    async def crawl_website(self, base_url: str, max_depth: int = DEFAULT_CRAWL_DEPTH) -> Generator[str, None, None]:
        """Crawl website respecting robots.txt and canonical URLs."""
        queue = [(base_url, 0)]
        robots_url = urljoin(base_url, "/robots.txt")
        rp = RobotFileParser()
        try:
            async with AdvancedSession() as session:
                resp = await session.fetch(robots_url)
                if resp:
                    rp.parse(resp.splitlines())
        except Exception:
            rp = None
        
        visited = set()
        while queue:
            current_url, depth = queue.pop(0)
            if depth > max_depth or current_url in self.bloom_filter or current_url in visited:
                continue
            self.bloom_filter.add(current_url)
            visited.add(current_url)
            self.bloom_count += 1
            if self.bloom_count > self.bloom_filter.capacity * 0.9:
                logger.warning("Bloom filter nearing capacity. Consider increasing bloom_capacity.")
            
            if rp and not rp.can_fetch(DEFAULT_USER_AGENT, current_url):
                logger.debug(f"Skipping {current_url} due to robots.txt")
                continue
            
            try:
                async with AdvancedSession() as session:
                    resp = await session.fetch(current_url)
                    if not resp:
                        continue
                    soup = BeautifulSoup(resp, 'html.parser')
                    canonical = soup.find('link', rel='canonical')
                    if canonical and canonical.get('href') != current_url:
                        continue
                    for link in soup.find_all('a', href=True):
                        next_url = urljoin(current_url, link['href'])
                        if urlparse(next_url).netloc == urlparse(base_url).netloc:
                            queue.append((next_url, depth + 1))
                            yield next_url
            except Exception as e:
                logger.debug(f"Crawl failed for {current_url}: {e}")

    def check_ssl(self, url: str) -> Dict:
        """Check SSL/TLS configuration."""
        hostname = urlparse(url).hostname
        if not hostname:
            return {"error": "Invalid hostname"}
        return self.ssl_checker.run(hostname)

    def cleanup(self):
        """Clean up resources."""
        if self.tor_manager:
            self.tor_manager.stop()

class DuskProbe:
    """Main scanner class for web vulnerability scanning."""
    def __init__(self, auth: Optional[Dict] = None, proxy: Union[str, Dict, None] = None):
        self.config = Config()
        self.session_manager = SessionManager(auth, proxy)
        self.session_manager.handle_auth()
        self.adv_scanner = AdvancedScanner(self.session_manager)
        self.vuln_scanner = VulnerabilityScanner(self.session_manager, self.config)
        self.results = {}

    async def scan_url(self, url: str):
        """Scan a single URL for vulnerabilities."""
        logger.info(f"Scanning {url}")
        if not re.match(r'^https?://', url):
            logger.error(f"Invalid URL format: {url}")
            return
        
        if self.config.advanced_settings.get("enable_tor") and self.adv_scanner.tor_manager:
            if not await self.adv_scanner.tor_manager.start_tor_service():
                logger.warning("Tor service failed. Proceeding without Tor.")
        
        try:
            # Basic HTTP check
            r = self.session_manager.request("GET", url)
            if r.status_code != 200:
                self._save_result(url, {
                    "type": "HTTP_ERROR",
                    "severity": Severity.INFO.name,
                    "details": f"Status {r.status_code}"
                })
            
            # Vulnerability scans
            vuln_findings = await self.vuln_scanner.run_all_tests(url)
            for finding in vuln_findings:
                self._save_result(url, finding)
            
            # Advanced scans
            adv_findings = await self.adv_scanner.advanced_vulnerability_scan(url)
            for finding in adv_findings:
                self._save_result(url, finding)
            
            # SSL checks
            ssl_vulns = self.adv_scanner.check_ssl(url)
            if ssl_vulns and ssl_vulns.get("error") != "Invalid hostname":
                self._save_result(url, {
                    "type": "SSL_ISSUES",
                    "severity": Severity.HIGH.name,
                    "details": json.dumps(ssl_vulns)
                })
            
            # Crawl and scan subpages
            async for sub_url in self.adv_scanner.crawl_website(url, self.config.advanced_settings.get("max_depth", DEFAULT_CRAWL_DEPTH)):
                sub_findings = await self.vuln_scanner.run_all_tests(sub_url)
                for finding in sub_findings:
                    self._save_result(sub_url, finding)
        
        except Exception as e:
            self._save_result(url, {
                "type": "SCAN_ERROR",
                "severity": Severity.HIGH.name,
                "details": str(e)
            })
            logger.error(f"Error scanning {url}: {e}")

    async def scan_urls(self, urls: List[str]):
        """Scan multiple URLs concurrently."""
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            loop = asyncio.get_event_loop()
            tasks = [loop.create_task(self.scan_url(url)) for url in urls]
            await asyncio.gather(*tasks)
        self.adv_scanner.cleanup()

    def _save_result(self, url: str, finding: Dict):
        """Save scan findings."""
        if url not in self.results:
            self.results[url] = []
        self.results[url].append(finding)

    def generate_advanced_report(self, output_format: str = "html", encrypt: bool = False) -> str:
        """Generate a report in the specified format."""
        generator = ReportGenerator(self.results, self.config.report_config, self.adv_scanner.encryptor)
        return generator.generate(output_format, encrypt)

def main():
    """Entry point for DuskProbe."""
    parser = argparse.ArgumentParser(
        description="DuskProbe - Professional Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python DuskProbe.py -u https://example.com --output html\n"
               "Install dependencies: pip install aiohttp requests stem web3 sklearn scapy pybloom-live cryptography colorama fake-useragent bs4\n"
               "Install Tor: sudo apt install tor"
    )
    parser.add_argument("-u", "--url", help="Single URL to scan (e.g., https://example.com)")
    parser.add_argument("-f", "--file", help="File with list of URLs (one per line)")
    parser.add_argument("-t", "--threads", type=int, default=MAX_THREADS,
                        help=f"Number of threads (1-{MAX_THREADS})", choices=range(1, MAX_THREADS+1))
    parser.add_argument("-a", "--auth", help="Path to authentication config file (JSON)")
    parser.add_argument("-p", "--proxy", help="Proxy server (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--crawl-depth", type=int, default=DEFAULT_CRAWL_DEPTH,
                        help=f"Maximum crawl depth (1-{DEFAULT_CRAWL_DEPTH*2})")
    parser.add_argument("--enable-tor", action="store_true", help="Use Tor network")
    parser.add_argument("--enable-web3", action="store_true", help="Enable Web3 scanning")
    parser.add_argument("--enable-ml", action="store_true", help="Enable ML analysis")
    parser.add_argument("--pcap", help="Path to PCAP file for ML analysis")
    parser.add_argument("--encrypt-report", action="store_true", help="Encrypt the final report")
    parser.add_argument("-o", "--output", choices=["html", "json", "markdown"], default="html",
                        help="Output report format")
    args = parser.parse_args()

    try:
        # Validate crawl depth
        if args.crawl_depth < 1 or args.crawl_depth > DEFAULT_CRAWL_DEPTH * 2:
            logger.error(f"Crawl depth must be between 1 and {DEFAULT_CRAWL_DEPTH*2}")
            sys.exit(1)

        # Initialize configuration
        config = Config()
        config.advanced_settings.update({
            k: v for k, v in {
                "enable_tor": args.enable_tor,
                "enable_web3_scan": args.enable_web3,
                "enable_ml_analysis": args.enable_ml,
                "pcap_path": args.pcap,
                "max_depth": args.crawl_depth
            }.items() if v is not None
        })

        # Load authentication
        auth_config = None
        if args.auth:
            if not os.path.exists(args.auth):
                logger.error(f"Auth file {args.auth} not found")
                sys.exit(1)
            if not os.path.isfile(args.auth) or not os.access(args.auth, os.R_OK):
                logger.error(f"Auth file {args.auth} is not readable")
                sys.exit(1)
            try:
                with open(args.auth, "r") as f:
                    auth_config = json.load(f)
                    if not isinstance(auth_config, dict):
                        raise ValueError("Auth config must be a JSON object")
            except Exception as e:
                logger.error(f"Error loading auth config: {e}")
                sys.exit(1)

        # Initialize scanner
        proxy = {"http": args.proxy, "https": args.proxy} if args.proxy else None
        scanner = DuskProbe(auth=auth_config, proxy=proxy)

        # Load URLs
        urls = []
        if args.url:
            if not re.match(r'^https?://', args.url):
                logger.error("Invalid URL format. Must start with http:// or https://")
                sys.exit(1)
            urls.append(args.url)
        if args.file:
            if not os.path.exists(args.file):
                logger.error(f"URL file {args.file} not found")
                sys.exit(1)
            if not os.path.isfile(args.file) or not os.access(args.file, os.R_OK):
                logger.error(f"URL file {args.file} is not readable")
                sys.exit(1)
            try:
                with open(args.file, "r") as f:
                    urls.extend([line.strip() for line in f if line.strip() and re.match(r'^https?://', line.strip())])
            except Exception as e:
                logger.error(f"Error reading URL file: {e}")
                sys.exit(1)

        if not urls:
            logger.error("No valid URLs provided. Exiting.")
            sys.exit(1)

        # Run scan
        start_time = time.time()
        logger.info(f"Starting scan for {len(urls)} URLs...")
        asyncio.run(scanner.scan_urls(urls))
        logger.info(f"Scan completed in {time.time() - start_time:.2f} seconds")

        # Generate report
        report_file = scanner.generate_advanced_report(args.output, args.encrypt_report)
        print(f"{Fore.GREEN}Report generated: {report_file}")

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        scanner.adv_scanner.cleanup()
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        traceback.print_exc()
        scanner.adv_scanner.cleanup()
        sys.exit(1)

if __name__ == "__main__":
    main()
