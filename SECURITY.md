#  Security Policy

##  Project: DuskProbe  
**DuskProbe** is a professional, industry-standard web vulnerability scanner designed with secure development practices and features to ensure resilience, integrity, and confidentiality throughout its usage and lifecycle.

---

##  Supported Versions

We support and patch only the **latest stable release** of DuskProbe. Please keep your instance up to date.

| Version       | Supported? | Notes                       |
|---------------|------------|-----------------------------|
| Latest (Main) | ✅ Yes      | Actively maintained        |
| Older versions| ❌ No       | Please upgrade immediately |

---

##  Reporting a Vulnerability

We take all security vulnerabilities seriously. If you discover a vulnerability:

-  Email us directly at: [labib-x@protonmail.com](mailto:labib-x@protonmail.com)  
-  Create a private security advisory via GitHub:  
  [https://github.com/la-b-ib/DuskProbe/security/advisories](https://github.com/la-b-ib/DuskProbe/security/advisories)

Please **do not create public issues** for security problems. We aim to respond within **48 hours** and resolve valid issues with a patch or mitigation as soon as possible.

---

##  Secure Development Practices

DuskProbe is developed with the following practices:

- **PEP 8 + PEP 257 Compliance:** Clean, readable, and secure Python code.
- **HMAC–based encryption** for configuration and scan artifacts.
- **Input sanitization** and payload validation to avoid misuse or injection.
- **Timeouts, retries, and error handling** to prevent misuse or denial-of-service.
- **Audit logging** for forensic traceability.
- **Secure third-party dependencies** only (vetted, minimal, actively maintained).

---

##  Vulnerability Categories Actively Tested

DuskProbe itself is protected against the same classes of vulnerabilities it scans for, including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Remote File Inclusion (RFI)
- Command Injection
- Local File Inclusion (LFI)
- Server-Side Template Injection (SSTI)
- JWT Weaknesses
- Insecure Deserialization
- Information Disclosure via Headers, Caching, etc.

---

##  Data Handling & Encryption

- All sensitive data (like credentials, scan results, tokens) are stored using **AES or HMAC-SHA256 encryption**.
- Configuration files support secure loading with **integrity validation**.
- Files like `auth_config.json` and `encryption.json` are never stored in plain text in repositories.

---

##  Responsible Disclosure Timeline

| Step                           | Timeframe                |
|--------------------------------|--------------------------|
| Initial Acknowledgement        | within 48 hours          |
| Triage & Investigation         | within 5 business days   |
| Patch / Fix Release            | 7–14 business days       |
| Public Disclosure (if needed)  | After patch is available |

---

##  CI/CD & GitHub Security

While GitHub Actions is not mandatory, future workflows will include:

- **Linting** via `pylint`
- **Security scanning** via `bandit`
- **Dependency checks** via `pip-audit`
- **Build validation** before merges

All workflows will run in **isolated runners** with **permission boundaries** and will never expose secrets.

---

##  Security Updates

DuskProbe publishes updates in the following places:

- GitHub Releases: [https://github.com/la-b-ib/DuskProbe/releases](https://github.com/la-b-ib/DuskProbe/releases)
- Changelog: See `CHANGELOG.md`
- Security Notices: Via advisories page

---

##  Third-Party Libraries

We only use dependencies that are:

- Actively maintained
- Have OSI-approved licenses
- Reviewed for known CVEs
- Downloaded from **PyPI** only (no external scripts)

---

##  Tools We Use for Internal Audits

- `bandit` – Static analysis for security vulnerabilities.
- `pip-audit` – Checks for insecure or vulnerable Python packages.
- `trivy` – Container scanning (if applicable in Docker deployments).
- Manual peer-review & code audits

---

##  Contact

- **Maintainer:** Labib Bin Shahed  
- **Email:** [labib-x@protonmail.com](mailto:labib-x@protonmail.com)  
- **GitHub:** [@la-b-ib](https://github.com/la-b-ib)  
- **Website:** [https://la-b-ib.github.io](https://la-b-ib.github.io)

---

