# <samp> DuskProbe

<samp>
 
**DuskProbe is a web application security testing framework built for authorized professionals, penetration testers, and lawful security assessments. Leveraging an asynchronous engine with aiohttp and Streamlit, it unifies deep passive reconnaissance with active vulnerability scanning to uncover critical flaws — from OWASP Top 10 risks to advanced business logic vulnerabilities — ensuring comprehensive coverage of modern web attack surfaces.**


<details>

**<summary>Project Details</summary>**

<details>
  
**<summary>DuskProbe Preview</summary>**

<p align="left">
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/1.png" width="24%" />
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/2.png" width="24%" />
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/3.png" width="24%" />
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/4.png" width="24%" />
  
</p>

<p align="left">
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/5.png" width="24%" />
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/6.png" width="24%" />
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/7.png" width="24%" />
  <img src="https://raw.githubusercontent.com/la-b-ib/DuskProbe/main/preview/8.png" width="24%" />
  
</p>

</details>


<details>
  
**<summary>Mission Statement</summary>**

**To empower cybersecurity professionals with a comprehensive, reliable, and ethical web application security testing platform that adheres to industry standards and best practices while maintaining accuracy and efficiency.**

</details>

<details>
  
**<summary>Technical Details</summary>**
 

- **Reconnaissance: Advanced intelligence gathering with deep infrastructure mapping across cloud providers (AWS, GCP, Azure), CDNs (Cloudflare, Akamai), WAFs, and load balancers. Includes tech stack fingerprinting, native OSINT integrations, DNS/SSL analysis via SSLyze, and Wayback snapshots for hidden endpoint discovery.**

- **Performance & Scalability: High‑speed asynchronous scanning with adaptive rate limiting, optimized memory management, real‑time progress tracking, and resilient error recovery for scalable assessments.**  

- **Vulnerability Detection: Concurrent engine identifies injection vectors (SQLi, NoSQLi, LDAP, SSTI), client‑side risks (XSS, CSRF, CORS), and server‑side flaws (SSRF, LFI/RFI, XXE, OS command). Extended coverage includes JWT misconfigurations, GraphQL introspection/injection, IDOR analysis, WebSocket threats (CSWSH, message injection), and deserialization flaws across PHP, Java, Python, and Node.js — ensuring comprehensive protection against modern web attack surfaces.**  

</details>




<details>
  
**<summary>Detection Capabilities</summary>**
 
| Category        | Checks Included                                         | Attack Surface                  | Detection Method                  | Severity |
|-----------------|---------------------------------------------------------|---------------------------------|-----------------------------------|----------|
| **Injection**   | SQLi, NoSQLi, Command Injection, LDAP, XPath, SSTI      | DB queries, interpreters, input | Payload fuzzing, error heuristics | High     |
| **Auth & Session** | JWT Manipulation, IDOR, Session Fixation, Weak Cookies | Tokens, cookies, session flows  | Token tampering, behavioral tests | High     |
| **XML / Parsers** | XXE, Billion Laughs, DTD retrieval                     | XML parsers, SOAP endpoints     | Malformed XML payload injection   | High     |
| **Misconfig**   | CORS, Security Headers, Debug Mode, Backup Files        | Web server configs, headers     | Header analysis, file discovery   | Medium   |
| **Network**     | SSRF, Port Scanning, DNS Zone Transfer                  | Cloud metadata, DNS, sockets    | SSRF payloads, DNS enumeration    | High     |
| **Logic**       | Rate Limiting Bypass, Business Logic Flaws              | API endpoints, workflows        | Sequence replay, anomaly testing  | Medium   |

</details>

<details>
  
**<summary>Legal Disclaimer</summary>** 
```javascript

Use only with explicit authorization from system owners. Comply fully with all applicable cybersecurity laws/regulations. Conduct scans solely for legitimate security testing purposes
  
```
</details>
