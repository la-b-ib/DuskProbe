


# DuskProbe Security Policy

**Version**: 4.2\
**Last Updated**: May 08, 2025\
**Description**: This document outlines the security policy for DuskProbe, a professional web vulnerability scanner. It covers built-in security features, secure usage guidelines, vulnerability handling, and best practices to ensure safe and responsible operation.

## 1. Security Features

DuskProbe incorporates robust security mechanisms to protect the tool, its users, and scanned systems from misuse, unauthorized access, and vulnerabilities.

### 1.1 Input Validation
- **URL Validation**: Enforces `https?://` regex to prevent invalid or malicious URLs (e.g., `file://`, `ftp://`).
- **File Path Sanitization**: Validates configuration, plugin, and report file paths to prevent directory traversal attacks.
- **JSON Config Validation**: Ensures JSON configs (`auth.json`, `payloads.json`, etc.) are well-formed and contain expected fields to prevent injection.

### 1.2 Encryption
- **Fernet Encryption**: Uses Fernet (symmetric encryption with AES-128 in CBC mode and PKCS7 padding) with SHA3-256 derived keys for:
  - Configuration files (`config/*.json`).
  - Generated reports (`reports/report_*.{html,json,md,enc}`).
  - Key hints stored in encrypted reports for decryption.
- **Environment Variable Support**: Allows secure key storage via `DUSKPROBE_ENCRYPTION_KEY`.

### 1.3 Plugin Security
- **HMAC-Based Verification**:
  - Plugins require SHA256 HMAC signatures in `config/encryption.json`.
  - Validates plugin integrity and authenticity before loading.
- **Dangerous Code Detection**:
  - Regex checks for risky patterns (e.g., `os.system`, `exec`, `subprocess.run`, `eval`).
  - Rejects plugins with potentially malicious code.
- **Isolated Execution**: Plugins run in a controlled environment with no direct access to system resources.

### 1.4 File System Security
- **Permissions**:
  - Directories (`plugins`, `reports`, `config`): 0o700 (owner read/write/execute only).
  - Files (configs, reports, ML models): 0o600 (owner read/write only).
- **Secure Creation**: Uses `os.makedirs` with explicit permissions and `os.chmod` to enforce access controls.
- **Log Rotation**: Prevents disk exhaustion with 10MB log files (`duskprobe.log`) and 5 backups.

### 1.5 Network Security
- **Tor Integration**:
  - Optional Tor support for anonymity with periodic circuit renewal (every 5 minutes).
  - Uses ports 9050/9150 with strict port availability checks.
- **Rate Limiting**:
  - Handles HTTP 429 responses with dynamic delays based on `Retry-After` headers (max 10s).
  - Prevents IP bans or denial-of-service risks.
- **Sanitized Headers**:
  - HTTP headers in `AdvancedSession` are predefined to prevent header injection.
  - Randomized User-Agent via `fake_useragent` to reduce fingerprinting.
- **Connection Pooling**:
  - Limits `aiohttp` connections to 50 to avoid overwhelming target servers.
- **SSL/TLS Checks**:
  - Validates certificates, protocols, and ciphers to detect weak configurations (e.g., SSLv3, RC4).

### 1.6 Authentication Handling
- **Secure Storage**: Authentication credentials (Basic or Form-based) are read from `auth.json` with 0o600 permissions.
- **Form Authentication**:
  - Validates login URLs and success indicators to prevent phishing or misconfiguration.
  - Uses POST requests with sanitized payloads.
- **Basic Authentication**:
  - Configures `requests.Session.auth` securely without exposing credentials in logs.

### 1.7 Logging
- **No Sensitive Data**: Logs exclude credentials, encryption keys, or payload contents.
- **Structured Format**: Uses `logging` with DEBUG, INFO, WARNING, ERROR levels for traceability.
- **Secure Storage**: Logs stored in `duskprobe.log` with 0o600 permissions.

## 2. Secure Usage Guidelines

To ensure DuskProbe is used safely and responsibly, adhere to the following guidelines.

### 2.1 Authorization
- **Obtain Permission**: Only scan systems you own or have explicit permission to test. Unauthorized scanning may violate laws (e.g., CFAA, GDPR).
- **Scope Definition**: Define and adhere to the scan scope to avoid impacting unintended systems.

### 2.2 Environment Setup
- **Isolated Environment**:
  - Run DuskProbe in a virtual environment (e.g., `venv`) to isolate dependencies.
  - Use a dedicated user with minimal privileges (`sudo -u duskprobe python DuskProbe.py`).
- **Secure Storage**:
  - Store `config/`, `reports/`, and `plugins/` in a secure, non-world-readable location.
  - Backup encryption keys (`DUSKPROBE_ENCRYPTION_KEY`) in a secure vault.
- **Network Isolation**:
  - Run scans behind a firewall or VPN to protect the scanning host.
  - Use Tor (`--enable-tor`) for anonymity when scanning public systems.

### 2.3 Configuration
- **Encryption Key**:
  - Set a strong `DUSKPROBE_ENCRYPTION_KEY` (minimum 32 characters, high entropy).
  - Avoid hardcoding keys in `encryption.json`; use environment variables.
- **Plugin Validation**:
  - Generate HMAC signatures for trusted plugins:
    ```python
    import hmac, hashlib
    file_hash = "sha256_hash_of_plugin_file"
    hmac_key = "your_hmac_key"
    print(hmac.new(hmac_key.encode(), file_hash.encode(), hashlib.sha256).hexdigest())
    ```
  - Add signatures to `config/encryption.json` under `plugin_signatures`.
- **Authentication Config**:
  - Use `auth.json` for credentials and verify permissions (0o600).
  - Validate `success_indicator` for form authentication to ensure correct login.
- **Payloads**:
  - Review `payloads.json` to ensure non-destructive payloads.
  - Avoid overly aggressive payloads that could disrupt target systems.

### 2.4 Scanning Practices
- **Rate Limiting**:
  - Reduce `--threads` (default: 50) for sensitive targets to avoid overwhelming servers.
  - Monitor `duskprobe.log` for 429 errors and adjust delays if needed.
- **Crawl Depth**:
  - Limit `--crawl-depth` (default: 5) to avoid excessive crawling of large sites.
  - Respect `robots.txt` to comply with site policies.
- **Tor Usage**:
  - Enable `--enable-tor` only for authorized scans requiring anonymity.
  - Verify Tor binary (`tor`) is installed and ports are free.
- **Web3 and ML**:
  - Configure a valid Web3 provider (e.g., Infura) in `advanced_settings.json` for `--enable-web3`.
  - Provide a pre-captured PCAP file for `--enable-ml` to avoid runtime packet capture.
- **Report Handling**:
  - Use `--encrypt-report` for sensitive scans to protect findings.
  - Store reports in a secure location and verify decryption keys.

### 2.5 Plugin Development
- **Code Safety**:
  - Avoid system-level operations (`os`, `subprocess`, `socket`).
  - Implement a `run` method returning a dictionary with `type`, `severity`, and `details`.
- **Signature Generation**:
  - Compute SHA256 hash of the plugin file and generate HMAC with `hmac_key`.
  - Test plugins in a sandbox before deployment.
- **Minimal Privileges**:
  - Plugins should not require elevated permissions or network access beyond `SessionManager`.

## 3. Vulnerability Handling

### 3.1 Reporting Vulnerabilities in DuskProbe
- **Contact**: Report security issues to `security@x.ai`.
- **Details Required**:
  - Affected component (e.g., `QuantumEncryptor`, `Plugin Loader`).
  - Steps to reproduce.
  - Impact (e.g., code execution, data exposure).
  - Proof-of-concept (if applicable).
- **Response Time**:
  - Acknowledgment within 48 hours.
  - Fix timeline based on severity (Critical: 7 days, High: 14 days, Medium/Low: 30 days).
- **Responsible Disclosure**:
  - Do not publicly disclose issues until a fix is released.
  - xAI will credit reporters unless anonymity is requested.

### 3.2 Handling Vulnerabilities Found by DuskProbe
- **Verification**:
  - Manually verify findings (e.g., XSS, SQLi) to rule out false positives.
  - Use `--output json` for detailed analysis.
- **Reporting to System Owners**:
  - Share encrypted reports (`--encrypt-report`) with authorized parties only.
  - Include severity, details, and remediation steps.
- **Remediation Guidance**:
  - XSS: Sanitize inputs, implement CSP.
  - SQLi: Use parameterized queries.
  - LFI: Restrict file access, validate paths.
  - Web3: Audit contracts for `DELEGATECALL`, `SELFDESTRUCT`.
  - HTTP/2: Patch servers for CVE-2023-43622.
  - Dependency Confusion: Use private registries or scope packages.
  - Cryptominers: Remove malicious scripts, monitor resources.
  - SSL: Upgrade to TLSv1.2+, disable weak ciphers.

## 4. Best Practices

### 4.1 Pre-Scan Checklist
- Verify target ownership or explicit permission.
- Backup `config/` and `plugins/` directories.
- Test configurations in a staging environment.
- Ensure Tor (`--enable-tor`) and Web3 (`--enable-web3`) settings are correct.

### 4.2 During Scanning
- Monitor `duskprobe.log` for errors or rate-limiting warnings.
- Use minimal `--threads` for initial scans to assess target stability.
- Limit `--crawl-depth` for large sites to avoid excessive requests.
- Enable `--encrypt-report` for sensitive targets.

### 4.3 Post-Scan
- Review reports for accuracy and prioritize critical/high-severity issues.
- Securely delete temporary files (e.g., unencrypted reports).
- Rotate encryption keys periodically and update `encryption.json`.
- Update plugins and re-sign with new HMAC signatures.

### 4.4 Regular Maintenance
- **Dependency Updates**:
  - Run `pip install --upgrade aiohttp requests stem web3 scikit-learn scapy pybloom-live cryptography colorama fake-useragent beautifulsoup4`.
  - Verify compatibility before upgrading.
- **Tor Updates**:
  - Update Tor binary (`sudo apt update && sudo apt install tor`).
- **Plugin Audits**:
  - Re-validate plugin signatures after modifications.
  - Remove unused plugins to reduce attack surface.
- **Log Review**:
  - Check `duskprobe.log` for unauthorized access attempts or errors.
  - Archive old logs securely.

## 5. Technical Security Specifications

### 5.1 Encryption
- **Algorithm**: Fernet (AES-128-CBC, HMAC-SHA256).
- **Key Derivation**: SHA3-256 from user-provided key or random 32-byte key.
- **Key Storage**: Environment variable (`DUSKPROBE_ENCRYPTION_KEY`) or `encryption.json` (0o600).

### 5.2 Plugin Verification
- **Signature**: HMAC-SHA256 with 32-byte key.
- **Dangerous Patterns**:
  ```regex
  \bos\.\w+\s*\(|\bexec\s*\(|\beval\s*\(|\bsubprocess\.\w+\s*\(|\bsocket\.\w+\s*\(
  ```
- **Validation Process**:
  1. Compute SHA256 hash of plugin file.
  2. Verify HMAC against `plugin_signatures` in `encryption.json`.
  3. Scan for dangerous patterns.
  4. Load plugin if both checks pass.

### 5.3 File Permissions
| Resource | Path | Permissions |
| --- | --- | --- |
| Configs | `config/*.json` | 0o600 |
| Reports | `reports/report_*` | 0o600 |
| ML Model | `anomaly_detector.model` | 0o600 |
| Logs | `duskprobe.log` | 0o600 |
| Directories | `plugins/`, `reports/`, `config/` | 0o700 |

### 5.4 Network
- **Tor**:
  - SocksPort: 9050 or 9150.
  - Circuit Renewal: Every 300s via `NEWNYM` signal.
- **HTTP**:
  - Timeout: 30s.
  - Max Connections: 50 (`aiohttp.TCPConnector`).
  - Retry Policy: 3 retries for 429, 500, 502, 503, 504 (`urllib3.Retry`).
- **Headers**:
  - `User-Agent`: Randomized via `fake_useragent` or `DuskProbe/4.2`.
  - `Accept-Encoding`: `gzip, deflate`.
  - `DNT`: `1`.

### 5.5 Logging
- **Format**: `%(asctime)s - %(levelname)s - %(message)s`.
- **Rotation**: 10MB, 5 backups.
- **Sensitive Data Exclusion**:
  - Credentials, keys, and payloads are not logged.
  - URLs and findings are logged minimally (e.g., no full response bodies).

## 6. Compliance

- **Ethical Scanning**: DuskProbe respects `robots.txt` and rate-limiting headers to comply with web server policies.
- **Data Protection**:
  - Encrypted reports and configs ensure GDPR/CCPA compliance for sensitive data.
  - No external data sharing or telemetry.
- **Legal**:
  - Users are responsible for ensuring compliance with local laws (e.g., CFAA, EU Cybersecurity Act).
  - xAI disclaims liability for unauthorized or illegal use.

## 7. Incident Response

### 7.1 If Compromised
- **Isolate System**:
  - Stop DuskProbe (`Ctrl+C`) and terminate Tor processes.
  - Disconnect the scanning host from the network.
- **Assess Impact**:
  - Review `duskprobe.log` for unauthorized actions.
  - Check `config/` and `plugins/` for tampering.
- **Mitigate**:
  - Rotate encryption keys and update `encryption.json`.
  - Re-sign plugins with new HMAC signatures.
  - Reinstall dependencies in a clean environment.
- **Report**:
  - Notify `security@x.ai` with details of the incident.

### 7.2 If Misused
- **Detect Misuse**:
  - Monitor for excessive scan activity or unauthorized targets in logs.
  - Check for plugins bypassing signature checks.
- **Response**:
  - Revoke access to compromised keys or configs.
  - Ban offending users from xAI services per terms of use.
  - Report illegal activity to authorities if required.




---


## Project Documentation

<div style="display: flex; gap: 10px; margin: 15px 0; align-items: center; flex-wrap: wrap;">

[![License](https://img.shields.io/badge/License-See_FILE-007EC7?style=for-the-badge&logo=creativecommons)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Policy_%7C_Reporting-FF6D00?style=for-the-badge&logo=owasp)](SECURITY.md)
[![Contributing](https://img.shields.io/badge/Contributing-Guidelines-2E8B57?style=for-the-badge&logo=git)](CONTRIBUTING.md)
[![Code of Conduct](https://img.shields.io/badge/Code_of_Conduct-Community_Standards-FF0000?style=for-the-badge&logo=opensourceinitiative)](CODE_OF_CONDUCT.md)

</div>

## Contact Information



  
[![Email](https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:labib.45x@gmail.com)
[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/la-b-ib)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/la-b-ib/)
[![Portfolio](https://img.shields.io/badge/Website-0A5C78?style=for-the-badge&logo=internet-explorer&logoColor=white)](https://la-b-ib.github.io/)
[![X](https://img.shields.io/badge/X-000000?style=for-the-badge&logo=twitter&logoColor=white)](https://x.com/la_b_ib_)






---

