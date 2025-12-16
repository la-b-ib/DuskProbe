Here is a comprehensive, professional, and technical `README.md` file tailored specifically to the **DuskProbe v5.0** source code provided.

---

#🛡️ DuskProbe v5.0**Enterprise-Grade Asynchronous Web Vulnerability Scanner & Reconnaissance Platform**

**DuskProbe** is a high-performance, asynchronous security assessment tool designed for modern web applications. Built on `aiohttp` and `Streamlit`, it combines deep passive reconnaissance with active vulnerability scanning to detect critical security flaws ranging from OWASP Top 10 issues to complex logic vulnerabilities.

---

##🚀 Key Features###🧠 Advanced Intelligence & Reconnaissance* **Deep Infrastructure Mapping:** Detects Cloud providers (AWS, GCP, Azure), CDNs (Cloudflare, Akamai), WAFs, and Load Balancers.
* **Tech Stack Fingerprinting:** Identifies CMS, Frameworks (React, Vue, Django, Laravel), and Server versions using heuristic header and content analysis.
* **OSINT Integration:** Native support for **Shodan**, **Censys**, **URLScan.io**, **VirusTotal**, and **AlienVault OTX**.
* **DNS & SSL Analysis:** Comprehensive DNS enumeration (A, MX, TXT, Zone Transfers) and SSL/TLS cipher suite analysis using `SSLyze`.
* **Historical Data:** Wayback Machine integration to analyze historical snapshots for hidden endpoints.

###⚡ Vulnerability Scanning EngineDuskProbe utilizes a highly concurrent scanning engine to detect:

* **Injection Attacks:** SQLi (Blind/Error/Time), NoSQLi, LDAP, XPath, and Template Injection (SSTI).
* **Client-Side Risks:** Advanced XSS (Reflected/DOM), CSRF, and CORS misconfigurations.
* **Server-Side Flaws:** SSRF (Cloud Metadata/Internal Network), LFI/RFI, XXE, and OS Command Injection.
* **Modern Web Threats:**
* **JWT Analysis:** Weak algorithms ('None'), missing signatures, and sensitive data leakage.
* **GraphQL:** Introspection abuse and injection.
* **IDOR:** Behavioral analysis for Insecure Direct Object References.
* **WebSockets:** CSWSH and injection via socket messages.
* **Deserialization:** Detection of PHP, Java, Python, and Node.js serialization flaws.



###📊 Reporting & Visualization* **Executive Dashboards:** Real-time metrics on risk scores, severity distribution, and attack vectors.
* **Professional Exports:** Generates detailed reports in **HTML** (Executive style), **JSON** (Machine readable), **CSV**, and **TXT**.
* **OWASP 2025 Compliance:** Automatic categorization of findings against the latest OWASP framework.
* **Visual Analytics:** Interactive charts for severity spectrums, attack surfaces, and historical trends.

---

##🏗️ ArchitectureDuskProbe relies on an asynchronous core to handle high-concurrency scanning without blocking the UI.

---

##📦 Installation###Prerequisites* Python 3.9+
* pip (Python Package Manager)

###Setup1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/duskprobe.git
cd duskprobe

```


2. **Install Dependencies**
```bash
pip install -r requirements.txt

```


*Note: Ensure you have `rich`, `streamlit`, `aiohttp`, `pandas`, `plotly`, and other core libraries installed.*
3. **Run the Application**
```bash
streamlit run duskprobe.py

```



---

##🛠️ Usage Guide###1. The InterfaceUpon launching, DuskProbe opens in your default browser at `http://localhost:8501`.

* **Scanner Tab:** Input single or batch URLs, configure scan profiles (Quick, Full, API-Specific), and initiate scans.
* **Results & Analytics:** View real-time findings, detailed request/response data, and filter by severity.
* **Reconnaissance:** Deep dive into DNS, SSL, and Infrastructure data.
* **Configuration:** Fine-tune concurrency threads, timeouts, user-agents, and headers.

###2. Configuration Profiles* **Quick Scan:** Fast check for high-level headers and critical misconfigurations.
* **Full Scan:** Deep crawl and active payload testing for all vulnerability classes.
* **API Security:** Focused scan on JSON/XML endpoints, JWTs, and GraphQL.
* **Custom:** Select specific modules (e.g., only check for XSS and SQLi).

###3. API IntegrationTo enable OSINT features, navigate to the **Configuration** tab and enter your API keys for:

* Shodan
* Censys
* VirusTotal
* AlienVault OTX

---

##🛡️ Detection Capabilities| Category | Checks Included |
| --- | --- |
| **Injection** | SQLi, NoSQLi, Command Injection, LDAP, XPath, SSTI |
| **Auth & Session** | JWT Manipulation, IDOR, Session Fixation, Weak Cookies |
| **XML / Parsers** | XXE (External Entities), Billion Laughs, DTD retrieval |
| **Misconfig** | CORS, Security Headers, Debug Mode, Backup Files |
| **Network** | SSRF (Cloud Metadata), Port Scanning, DNS Zone Transfer |
| **Logic** | Rate Limiting Bypass, Business Logic Flaws |

---

##⚠️ Legal Disclaimer**DuskProbe is intended for authorized security testing and educational purposes only.**

You must have explicit written permission from the system owner before scanning any target. Unauthorized use of this tool to scan targets you do not own or have permission to test is illegal and strictly prohibited. The authors are not responsible for any misuse or damage caused by this tool.

---

##🤝 ContributingContributions are welcome! Please submit a Pull Request or open an Issue to discuss improvements.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

##📄 LicenseDistributed under the MIT License. See `LICENSE` for more information.

---

**Author:** Labib Bin Shahed
**Version:** 5.0.0
