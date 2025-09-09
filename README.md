

## DuskProbe  <a href=""><img align="right" width="150" height="150" src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/hidden.gif"></a> 

**DuskProbe is a professional-grade web vulnerability scanner designed for ethical security testing. Optimized for Google Colab, it performs comprehensive assessments to detect common web vulnerabilities and generates detailed, exportable reports.**

---

## 🚀 Overview

DuskProbe v4.5 identifies vulnerabilities such as:

- Cross-Site Scripting (XSS)
- SQL Injection (SQLi)
- Local File Inclusion (LFI)
- Open Redirects
- Insecure Direct Object References (IDOR)
- Cross-Site Request Forgery (CSRF)
- Cryptominer detection
- Missing or misconfigured security headers

It supports optional Tor integration for anonymity and includes site crawling for deeper analysis.

---

## 🔍 Preview 
![DuskProbe Desktop Preview 1](https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/desktop.png)
![DuskProbe Desktop Preview 2](https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/desktop%20(1).png)
![DuskProbe Desktop Preview 3](https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/desktop%20(2).png)

<hr>


## ✨ Key Features

| Feature | Description |
|--------|-------------|
| ✅ Comprehensive Checks | XSS, SQLi, LFI, IDOR, CSRF, Open Redirects, Cryptominers, Security Headers |
| 🧠 Google Colab Optimized | Lightweight, fast, and interactive |
| 📊 Detailed Reporting | HTML, Markdown, Text formats + CSV export |
| 🌐 Site Crawling | Depth-limited crawling to map site structure |
| 🕵️ Tor Support | Optional anonymity via Tor |
| 🧾 Ethical Prompts | Mandatory age and authorization checks |
| 🛠️ Logging | Rotating file handlers for audit and debugging |

---

## 📦 Installation

### ✅ Prerequisites

- Python 3.6+
- Google Colab (recommended) or local Python environment
- Internet connection

### 📥 Dependencies

In Google Colab, dependencies are auto-installed:

```bash
pip install -q requests beautifulsoup4 colorama fake-useragent urllib3
pip install -q aiohttp cryptography scikit-learn pybloom-live pandas numpy
apt-get update -qq && apt-get install -y -qq tor
```

For local use, install manually using the commands above.

---

## 🧪 Usage

### 🔧 Clone the Repository

```bash
git clone https://github.com/yourusername/duskprobe.git
cd duskprobe
```

### 🟢 Run in Google Colab

- Copy the code into a Colab notebook
- Execute the notebook and follow prompts

### 💻 Run Locally

```bash
python duskprobe.py
```

---

## 🧭 Interactive Prompts

- Confirm age (18+) and ethical authorization
- Enter target URL (e.g., `https://example.com`)
- Choose Tor usage (optional)
- Enable crawling (optional)
- Export findings to CSV (optional)

---

## 📁 Output

- Reports saved in `/content/reports/` (HTML, Markdown, Text)
- Logs saved in `/content/logs/`
- CSV export available in Colab
- Site structure displayed as a DataFrame (if crawling enabled)

---

## 📄 Sample Output

```
🛡️  DUSKPROBE v4.5 - ENHANCED SECURITY SCANNER
⚠️  ETHICAL AND LEGAL DISCLAIMER:
This tool is for educational and authorized security testing only.

✅ SCAN COMPLETE!
Scan time: 12.34 seconds
Critical: 0 | High: 2 | Total: 5
Report saved: /content/reports/duskprobe_report_20250909_202205.html
Data exported: /content/reports/duskprobe_data_20250909_202205.csv
Log file: /content/logs/duskprobe_20250909_202205.log
```

---

## 📊 Report Formats

- **HTML**: Styled with risk meter and detailed findings
- **Markdown**: Easy to share and document
- **Text**: Human-readable summary

Each report includes:

- Site Info: URL, domain, IP, server, technologies
- Executive Summary: Risk score and severity breakdown
- Detailed Findings: Type, severity, evidence, recommendations
- Site Structure: Pages, depth, links, forms (if crawling enabled)

---

## 🔐 Security Checks

| Check | Description |
|-------|-------------|
| XSS | Reflected XSS via payloads |
| SQLi | SQL error detection |
| LFI | Sensitive file access attempts |
| Security Headers | CSP, HSTS, X-Frame-Options, etc. |
| Cryptominers | Unauthorized mining script detection |
| Open Redirect | Unvalidated redirect testing |
| IDOR | Unauthorized resource access |
| CSRF | Missing token detection |

---

## ⚖️ Ethical & Legal Disclaimer

DuskProbe is intended for **educational and authorized** security testing only. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical.

---

## ⚠️ Limitations

- **Colab-Specific**: Optimized for Colab; local setup may vary
- **Rate Limits**: Some sites may block automated requests
- **False Positives/Negatives**: Manual verification recommended
- **Tor Support**: Requires proper Tor and Stem configuration

---

## 🤝 Contributing

We welcome contributions!

```bash
# Fork and clone
git checkout -b feature/YourFeature
git commit -m 'Add YourFeature'
git push origin feature/YourFeature
```

Then open a pull request.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

- Built with Python, pandas, BeautifulSoup, and other open-source tools
- Inspired by the need for accessible, ethical web security testing
- Thanks to the open-source security community for payload inspiration

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

