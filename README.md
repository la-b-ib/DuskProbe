
# DuskProbe: Professional Industry–Standard Web Vulnerability Scanner

DuskProbe is a comprehensive, single-file Python-based web vulnerability scanner engineered for security professionals. It includes over 100 advanced features like multi-threaded and distributed scanning, plugin-based extensibility, client-side testing, encryption, detailed reporting, and modern web security standards. This tool is designed to detect a wide array of vulnerabilities in web applications and APIs.

---

## Features

-  **Vulnerability Scanning:** XSS, SQLi, LFI, XXE, Command Injection, JWT weaknesses, CSRF, SSRF, Open Redirects, CRLF, Header Injection, and more.
-  **Reconnaissance:** WHOIS, DNSSEC checks, IP reputation, CDN detection.
-  **ML-based Anomaly Detection:** Auto-detect unknown behaviors using statistical anomaly detection (in progress).
-  **Client-side Scanning:** DOM XSS and JS execution using Selenium WebDriver.
-  **Plugin System:** Dynamically loads plugins from `plugins/` directory.
-  **Reporting:** Generates HTML, Markdown, PDF, and JSON reports with risk levels.
-  **Secure Architecture:** Encrypted configuration, tokenized API keys, audit logging.
-  **Distributed Scanning:** Spread targets across multiple nodes using `ClusterManager`.
-  **SIEM Integration:** Forward logs to SIEMs with JSON formatting.
-  **Periodic Scans (Daemon Mode):** Automatically rescan targets at regular intervals.
-  **Fuzzing Engine:** Injects payloads into URL parameters using custom wordlists.
-  **Single File Core:** Packs over 2K lines of code into a single executable for portability.

---

## Requirements

- **Python:** 3.8+
- **Dependencies:**

  ```bash
  pip install requests beautifulsoup4 tqdm colorama selenium webdriver-manager
  ```

- **External Tools:**
  - `sslscan` installed (or a secure Python wrapper if needed)

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/la-b-ib/duskprobe.git
cd duskprobe
```

### 2. Set Up Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate     # Windows
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Ensure `sslscan` is Installed (Linux/macOS)

```bash
sudo apt install sslscan
# OR
brew install sslscan
```

---

## Configuration

Place all configuration files under the `config/` directory:

- `payloads.json`
- `wordlists.json`
- `report_config.json`
- `auth_config.json`
- `intel_sources.json`
- `encryption.json`

---

## Usage

### Basic Scan

```bash
python duskprobe.py -u https://example.com
```

### Scan from URL List

```bash
python duskprobe.py -f urls.txt
```

### Enable Selenium for Client-side JS Scanning

```bash
python duskprobe.py -u https://example.com --enable-selenium
```

### Use Proxy (e.g., Burp Suite)

```bash
python duskprobe.py -u https://example.com -p http://127.0.0.1:8080
```

### Custom Report Format

```bash
python duskprobe.py -u https://example.com -o markdown
```

### Daemon Mode (Auto-Rescan Every Hour)

```bash
python duskprobe.py -f urls.txt --daemon --rescan-interval 3600
```

---

## Plugin System

- Plugins live in the `plugins/` folder.
- Each plugin must follow the structure:

```python
class Plugin:
    def run(self, url, session):
        # Perform check and return results
        return {"plugin_name": "example", "result": "vulnerable"}
```

- Loaded automatically if filename starts with `plugin_`.

---

## Architecture

### Core Modules

- **SessionManager:** Manages HTTP sessions, headers, proxies, and retries.
- **AdvancedScanner:** Handles web crawling, SSL scan, parameter fuzzing, client-side scanning.
- **VulnerabilityScanner:** Injects payloads for SQLi, XSS, etc., and inspects responses.
- **ReconModule:** Handles WHOIS, DNSSEC, CDN detection, IP intel.
- **ExternalIntelligence:** Pulls threat intel data from public feeds.
- **ClusterManager:** Allows distribution of scans across nodes.
- **ReportGenerator:** Creates formatted reports in HTML, PDF, JSON, etc.

### Execution Flow

1. Load target(s)
2. Perform recon and enumerate endpoints
3. Crawl and identify injectable points
4. Run vulnerability tests (via core + plugins)
5. Store logs, generate report, and send to SIEM if configured

---

## Recon Details

- Uses `socket` + `whois` + `dns.resolver` for:
  - IP address
  - IP reputation (e.g., abuseIPDB API)
  - Domain WHOIS info
  - DNSSEC status
  - CDN or WAF detection

---

## Report Format (Markdown Example)

```markdown
## Scan Report: example.com

**Target:** https://example.com  
**Date:** 2025-04-14  
**Scanner Version:** 1.0.0  
**Scan Duration:** 3m 14s  

---

### Vulnerabilities Detected

| Vulnerability       | Endpoint              | Severity | Description                   |
|---------------------|------------------------|----------|-------------------------------|
| Reflected XSS       | /search?q=test         | High     | Unescaped input in query param |
| SQL Injection       | /product?id=5          | Critical | MySQL error visible           |

---

### Recon Summary

- WHOIS: Registrar = Namecheap
- DNSSEC: Not Enabled
- CDN: Cloudflare Detected
- SSL Grade: A (via `sslscan`)

---

### Recommendations

- Escape all user input (XSS)
- Use parameterized queries (SQLi)
- Enable DNSSEC and secure headers
```

---

## Encryption & Logging

- **Encrypt/Decrypt Sensitive Data:**

```python
from crypto_utils import encrypt_data, decrypt_data

encrypted = encrypt_data("apikey123", key="mysecret")
decrypted = decrypt_data(encrypted, key="mysecret")
```

- **Audit Log Sample:**

```json
{
  "timestamp": "2025-04-14T12:00:23Z",
  "target": "https://example.com",
  "module": "xss_test",
  "status": "vulnerable",
  "details": "payload=<script>alert(1)</script>"
}
```

---

## Distributed Scanning

To set up scanning across multiple servers:

1. Start a node with the DuskProbe agent.
2. Connect via `ClusterManager` config (e.g., IP and port).
3. Assign a batch of URLs to each worker.
4. Merge results post-scan.

---

## Future Roadmap

- Add support for:
  - WebSockets security fuzzing
  - GraphQL API testing
  - Cloud/storage service scanning (AWS S3, Azure blobs)
  - Container misconfigurations
  - Advanced Machine Learning–based anomaly detection

---

## Contributing

```bash
git clone https://github.com/la-b-ib/duskprobe.git
cd duskprobe
git checkout -b my-new-feature
# Make changes, commit and push
```

Then open a pull request with your enhancements.

---
## License

MIT License. See `LICENSE` file for details.

---

## Contact Information

For any inquiries, contributions, or support requests, please feel free to reach out via the following channels:

-  Project Maintainer: [Labib Bin Shahed](https://github.com/la-b-ib)
-  Email: [labib-x@protonmail.com](mailto:labib-x@protonmail.com)
-  Website: [la-b-ib.github.io](https://la-b-ib.github.io)
-  GitHub Repository: [DuskProbe on GitHub](https://github.com/la-b-ib/DuskProbe)


---

Empower your security operations with **DuskProbe** — The next generation in intelligent, secure, and extensible vulnerability scanning.
**Built for modern defenders. Powered by Python.**  
Secure your web stack with **DuskProbe**.
