# DuskProbe v5.0 - Complete Architecture & Code Analysis

This document provides a comprehensive analysis of the DuskProbe web vulnerability scanner, including detailed file structure and code architecture diagrams.

## Project Overview

DuskProbe is a state-of-the-art cybersecurity assessment tool designed for professional security testing. It features:

- **Advanced asynchronous vulnerability scanning** with high-performance concurrent processing
- **Comprehensive security checks** covering OWASP Top 10 2025 vulnerabilities
- **Professional HTML/JSON reporting** with executive summaries and technical intelligence
- **Shell-optimized version** for command-line usage with rich terminal UI
- **Modular architecture** with pluggable security testing modules
- **Advanced reconnaissance capabilities** with 62+ intelligence gathering components

## File Structure Analysis

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#ff6b6b'}, 'flowchart': {'rankSpacing': 80, 'nodeSpacing': 50, 'curve': 'basis'}, 'layout': {'hierarchySeparation': 80, 'nodeSeparation': 50, 'edgeSeparation': 20}}}%%
graph LR
    A[DuskProbe Root]
    A --> B[Documentation Files]
    A --> C[duskprobe/ - Main Package]
    A --> D[preview/ - Media Assets]
    
    B --> B1[README.md - Comprehensive Documentation]
    B --> B2[LICENSE - MIT License]
    B --> B3[CODE_OF_CONDUCT.md - Community Standards]
    B --> B4[CONTRIBUTING.md - Contribution Guidelines]
    B --> B5[SECURITY.md - Security Policy]
    
    C --> C1[duskprobe.py - Main Application 7996 lines]
    C --> C2[requirements.txt - Dependencies]
    C --> C3[install.sh - Installation Script]
    C --> C4[logs/ - Log Directory]
    C --> C5[old version/ - Legacy Code]
    C --> C6[report/ - Sample Reports]
    
    C4 --> C4A[sample log.log - Example Logging]
    
    C5 --> C5A[DuskProbe.ipynb - Jupyter Notebook Version]
    
    C6 --> C6A[sample report.html - HTML Report Sample]
    C6 --> C6B[sample report.pdf - PDF Report Sample]
    
    D --> D1[gif/ - Animated GIFs 13 files]
    D --> D2[img/ - Screenshots]
    
    D1 --> D1A[bitcoin-lock.gif]
    D1 --> D1B[crime-scene.gif]
    D1 --> D1C[cybersecurity.gif]
    D1 --> D1D[data-safety.gif]
    D1 --> D1E[delivery.gif]
    D1 --> D1F[folder.gif]
    D1 --> D1G[hacking.gif]
    D1 --> D1H[mission.gif]
    D1 --> D1I[people-chart.gif]
    D1 --> D1J[performance.gif]
    D1 --> D1K[ssl.gif]
    D1 --> D1L[team.gif]
    D1 --> D1M[web-code.gif]
    
    D2 --> D2A[html report/ - HTML Report Screenshots]
    D2 --> D2B[shell report/ - Terminal Report Screenshots]
    
    D2A --> D2A1[desktop 1.png]
    D2A --> D2A2[desktop 2.png]
    D2A --> D2A3[desktop 3.png]
    
    D2B --> D2B1[desktop.png - 10 terminal screenshots]
    
    style A fill:#ff1744,stroke:#d50000,stroke-width:4px,color:#fff
    style C1 fill:#00e676,stroke:#00c853,stroke-width:3px,color:#000
    style C fill:#2196f3,stroke:#1976d2,stroke-width:3px,color:#fff
    style B fill:#9c27b0,stroke:#7b1fa2,stroke-width:3px,color:#fff
    style D fill:#ff9800,stroke:#f57c00,stroke-width:3px,color:#000
    style B1 fill:#e91e63,stroke:#c2185b,stroke-width:2px,color:#fff
    style B2 fill:#673ab7,stroke:#512da8,stroke-width:2px,color:#fff
    style B3 fill:#3f51b5,stroke:#303f9f,stroke-width:2px,color:#fff
    style B4 fill:#009688,stroke:#00796b,stroke-width:2px,color:#fff
    style B5 fill:#4caf50,stroke:#388e3c,stroke-width:2px,color:#fff
    style C2 fill:#ff5722,stroke:#e64a19,stroke-width:2px,color:#fff
    style C3 fill:#795548,stroke:#5d4037,stroke-width:2px,color:#fff
    style C4 fill:#607d8b,stroke:#455a64,stroke-width:2px,color:#fff
    style C5 fill:#ffc107,stroke:#ffa000,stroke-width:2px,color:#000
    style C6 fill:#cddc39,stroke:#afb42b,stroke-width:2px,color:#000
    style D1 fill:#e1bee7,stroke:#8e24aa,stroke-width:2px,color:#000
    style D2 fill:#ffcdd2,stroke:#f44336,stroke-width:2px,color:#000
```

## Python Code Architecture

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#ff4757'}, 'flowchart': {'rankSpacing': 75, 'nodeSpacing': 45, 'curve': 'basis'}, 'layout': {'hierarchySeparation': 75, 'nodeSeparation': 45, 'edgeSeparation': 15}}}%%
graph LR
    A[DuskProbe v5.0 - Main Python Application 7996 lines]
    A --> B[Import System & Dependencies]
    A --> C[Configuration Management Layer]
    A --> D[Asynchronous Network Layer]
    A --> E[Security Engine Core]
    A --> F[Advanced Reconnaissance System]
    A --> G[Professional Reporting Engine]
    A --> H[CLI Interface & Control Flow]
    A --> I[Main Execution Pipeline]
    
    %% Import System & Dependencies
    B --> B1[Core Python Imports]
    B --> B2[Third-Party Libraries]
    B --> B3[Optional Security Libraries]
    B --> B4[Advanced Reconnaissance Tools]
    
    B1 --> B1A[os, re, json, socket, logging]
    B1 --> B1B[argparse, sys, asyncio, aiohttp]
    B1 --> B1C[pathlib.Path, datetime]
    B1 --> B1D[urllib.parse, typing]
    
    B2 --> B2A[rich.console.Console]
    B2 --> B2B[rich.table.Table]
    B2 --> B2C[rich.progress.Progress]
    B2 --> B2D[rich.panel.Panel]
    B2 --> B2E[beautifulsoup4, pandas, yaml]
    
    B3 --> B3A[shodan - IP Intelligence]
    B3 --> B3B[whois - Domain Analysis]
    B3 --> B3C[builtwith - Tech Stack]
    B3 --> B3D[waybackpy - Historical Data]
    B3 --> B3E[dns.resolver - DNS Tools]
    B3 --> B3F[sslyze - SSL/TLS Analysis]
    B3 --> B3G[selenium - Browser Automation]
    B3 --> B3H[nmap - Port Scanning]
    
    B4 --> B4A[scapy - Packet Analysis]
    B4 --> B4B[censys - Search Engine]
    B4 --> B4C[vulners - Vulnerability DB]
    B4 --> B4D[sublist3r - Subdomain Discovery]
    B4 --> B4E[paramiko - SSH Operations]
    B4 --> B4F[stem - Tor Integration]
    
    %% Configuration Management Layer
    C --> C1[DuskProbeConfig Class - Lines 245-310]
    
    C1 --> C1A[__init__ - Constructor Method]
    C1 --> C1B[_load_config_file - YAML Config Parser]
    C1 --> C1C[_setup_logging - Advanced Logging System]
    
    C1A --> C1A1[args - Command Line Arguments]
    C1A --> C1A2[reports_dir - Output Directory Path]
    C1A --> C1A3[logs_dir - Logging Directory Path]
    C1A --> C1A4[console - Rich Console Instance]
    
    C1B --> C1B1[YAML Safe Loading]
    C1B --> C1B2[Config Override Logic]
    C1B --> C1B3[Error Handling & Validation]
    
    C1C --> C1C1[RotatingFileHandler - 5MB Max]
    C1C --> C1C2[RichHandler - Console Output]
    C1C --> C1C3[Log Level Management]
    C1C --> C1C4[Timestamped Log Files]
    
    %% Asynchronous Network Layer
    D --> D1[AsyncSession Class - Lines 315-420]
    
    D1 --> D1A[__init__ - Session Initialization]
    D1 --> D1B[get - Async GET Method]
    D1 --> D1C[post - Async POST Method]
    D1 --> D1D[close - Resource Cleanup]
    D1 --> D1E[__aenter__ / __aexit__ - Context Manager]
    
    D1A --> D1A1[semaphore - Concurrency Limit 100]
    D1A --> D1A2[response_cache - Request Cache Dict]
    D1A --> D1A3[aiohttp.ClientSession Configuration]
    D1A --> D1A4[TCPConnector - Connection Pool 200]
    D1A --> D1A5[ClientTimeout - 3 Second Limit]
    D1A --> D1A6[Custom Headers - User Agent Rotation]
    
    D1B --> D1B1[Cache Lookup - Duplicate Prevention]
    D1B --> D1B2[Semaphore Control - Rate Limiting]
    D1B --> D1B3[Content Size Limiting - 100KB Max]
    D1B --> D1B4[Error Handling - Timeout & ClientError]
    D1B --> D1B5[Response Caching - 1000 Entry Limit]
    
    D1C --> D1C1[POST Data Handling]
    D1C --> D1C2[Custom Headers Support]
    D1C --> D1C3[Redirect Following]
    D1C --> D1C4[Content Length Limiting]
    
    %% Security Engine Core
    E --> E1[SecurityChecker Class - Lines 425-2800]
    
    E1 --> E1A[__init__ - Payload & Pattern Initialization]
    E1 --> E1B[get_site_info - Comprehensive Site Analysis]
    E1 --> E1C[check_vulnerability - Main Vulnerability Scanner]
    E1 --> E1D[full_check - Complete Security Assessment]
    E1 --> E1E[check_headers - Security Header Validation]
    
    E1A --> E1A1[Payload Database Initialization]
    E1A --> E1A2[Error Pattern Compilation]
    E1A --> E1A3[File Indicator Patterns]
    E1A --> E1A4[Cloud Metadata Patterns]
    
    E1A1 --> E1A1A[XSS Payloads - 14 Advanced Variants]
    E1A1 --> E1A1B[SQLi Payloads - 15 Database Types]
    E1A1 --> E1A1C[LFI Payloads - 15 Path Traversal]
    E1A1 --> E1A1D[RFI Payloads - 4 Remote Inclusion]
    E1A1 --> E1A1E[CMD Injection - 14 OS Commands]
    E1A1 --> E1A1F[SSRF Payloads - 11 Internal Targets]
    E1A1 --> E1A1G[XXE Payloads - 3 XML External Entity]
    E1A1 --> E1A1H[Template Injection - 9 Engine Types]
    E1A1 --> E1A1I[NoSQL Injection - 7 Database Variants]
    E1A1 --> E1A1J[LDAP Injection - 5 Directory Attacks]
    E1A1 --> E1A1K[XPath Injection - 4 XML Queries]
    E1A1 --> E1A1L[Sensitive Files - 25 Critical Paths]
    E1A1 --> E1A1M[Open Redirect - 7 Bypass Methods]
    E1A1 --> E1A1N[CRLF Injection - 4 Header Injection]
    
    E1B --> E1B1[_analyze_server_hosting - Server Intelligence]
    E1B --> E1B2[_analyze_backend_stack - Technology Detection]
    E1B --> E1B3[_analyze_frontend_stack - Client Analysis]
    E1B --> E1B4[_analyze_network_protocol - Protocol Assessment]
    E1B --> E1B5[_perform_reconnaissance - Intelligence Gathering]
    
    E1C --> E1C1[Quick Detection Methods]
    E1C --> E1C2[Deep Pattern Analysis]
    E1C --> E1C3[POST-Based Vulnerability Checks]
    E1C --> E1C4[Finding Creation & CVSS Scoring]
    
    E1C1 --> E1C1A[_quick_detect_xss - Immediate XSS Detection]
    E1C1 --> E1C1B[_quick_detect_sqli - Fast SQL Error Detection]
    E1C1 --> E1C1C[_quick_detect_lfi - File Inclusion Indicators]
    E1C1 --> E1C1D[_quick_detect_command_injection - OS Command Output]
    E1C1 --> E1C1E[_quick_detect_ssrf - Cloud Metadata Detection]
    E1C1 --> E1C1F[_quick_detect_sensitive_file - Configuration Files]
    E1C1 --> E1C1G[_quick_detect_nosql - NoSQL Error Patterns]
    E1C1 --> E1C1H[_quick_detect_ldap - LDAP Directory Errors]
    E1C1 --> E1C1I[_quick_detect_xpath - XPath Syntax Errors]
    E1C1 --> E1C1J[_quick_detect_open_redirect - Location Headers]
    E1C1 --> E1C1K[_quick_detect_crlf - Header Injection Detection]
    
    E1C2 --> E1C2A[_detect_xss - Advanced XSS Analysis]
    E1C2 --> E1C2B[_detect_sqli - Database Error Patterns]
    E1C2 --> E1C2C[_detect_lfi - File System Indicators]
    E1C2 --> E1C2D[_detect_command_injection - Command Output Analysis]
    E1C2 --> E1C2E[_detect_ssrf - Internal Network Access]
    E1C2 --> E1C2F[_detect_xxe - XML External Entity]
    E1C2 --> E1C2G[_detect_template_injection - Template Engine Errors]
    E1C2 --> E1C2H[_detect_nosql_injection - NoSQL Database Errors]
    E1C2 --> E1C2I[_detect_ldap_injection - Directory Service Errors]
    E1C2 --> E1C2J[_detect_xpath_injection - XML Query Errors]
    E1C2 --> E1C2K[_detect_open_redirect - Redirect Analysis]
    E1C2 --> E1C2L[_detect_crlf_injection - HTTP Header Manipulation]
    E1C2 --> E1C2M[_detect_sensitive_file - Configuration Detection]
    
    E1C4 --> E1C4A[_create_finding - OWASP 2025 Compliance]
    E1C4 --> E1C4B[_calculate_risk_score - CVSS Calculation]
    E1C4 --> E1C4C[_get_compliance_impact - Regulatory Mapping]
    E1C4 --> E1C4D[_assess_exploitability - Attack Complexity]
    E1C4 --> E1C4E[_get_discovery_method - Detection Classification]
    
    E1D --> E1D1[Priority Task Management]
    E1D --> E1D2[Batch Processing - 25 Task Groups]
    E1D --> E1D3[Progress Tracking Integration]
    E1D --> E1D4[Advanced Discovery Analysis]
    
    E1D1 --> E1D1A[High Priority - Critical Vulnerabilities]
    E1D1 --> E1D1B[Medium Priority - Standard Vulnerabilities]
    E1D1 --> E1D1C[Specialized Injection Types]
    E1D1 --> E1D1D[Header Security Validation]
    
    %% Advanced Reconnaissance System
    F --> F1[Intelligence Gathering Methods]
    F --> F2[Technology Detection Systems]
    F --> F3[Network & Infrastructure Analysis]
    F --> F4[Advanced Discovery Engines]
    
    F1 --> F1A[_detect_cloud_provider - AWS/GCP/Azure Detection]
    F1 --> F1B[_detect_cdn - Content Delivery Network ID]
    F1 --> F1C[_detect_load_balancer - Traffic Distribution]
    F1 --> F1D[_detect_waf - Web Application Firewall]
    F1 --> F1E[_detect_programming_language - Backend Tech]
    F1 --> F1F[_detect_web_framework - Framework ID]
    F1 --> F1G[_detect_database_technology - Database Hints]
    F1 --> F1H[_detect_application_server - Server Software]
    
    F2 --> F2A[_detect_js_frameworks - JavaScript Libraries]
    F2 --> F2B[_detect_css_frameworks - Styling Systems]
    F2 --> F2C[_detect_build_tools - Development Tools]
    F2 --> F2D[_detect_package_managers - Dependency Managers]
    F2 --> F2E[_detect_ui_libraries - Component Systems]
    F2 --> F2F[_detect_pwa_features - Progressive Web Apps]
    F2 --> F2G[_detect_spa_indicators - Single Page Apps]
    F2 --> F2H[_detect_third_party_integrations - External Services]
    
    F3 --> F3A[_detect_http_version - Protocol Version]
    F3 --> F3B[_assess_protocol_security - Security Assessment]
    F3 --> F3C[_analyze_network_performance - Latency Analysis]
    F3 --> F3D[_analyze_dns_configuration - DNS Records]
    F3 --> F3E[_perform_basic_port_scan - Open Port Detection]
    F3 --> F3F[_analyze_security_headers - Header Validation]
    F3 --> F3G[_analyze_compression - Content Encoding]
    F3 --> F3H[_analyze_cookies - Cookie Security]
    F3 --> F3I[_analyze_cors_configuration - CORS Policy]
    
    F4 --> F4A[_advanced_webpage_discovery - Page Enumeration]
    F4 --> F4B[_advanced_file_leak_detection - Sensitive Files]
    F4 --> F4C[_advanced_parameter_enumeration - Parameter Mining]
    F4 --> F4D[_website_structure_mapping - Site Architecture]
    F4 --> F4E[_comprehensive_vulnerability_scan - Full Assessment]
    F4 --> F4F[_advanced_shodan_reconnaissance - IP Intelligence]
    F4 --> F4G[_advanced_whois_analysis - Domain Intelligence]
    F4 --> F4H[_advanced_technology_detection - Stack Analysis]
    F4 --> F4I[_wayback_machine_analysis - Historical Data]
    F4 --> F4J[_advanced_dns_reconnaissance - DNS Intelligence]
    F4 --> F4K[_advanced_ssl_analysis - Certificate Analysis]
    F4 --> F4L[_advanced_http_analysis - Protocol Deep Dive]
    F4 --> F4M[_network_packet_analysis - Traffic Analysis]
    
    %% Professional Reporting Engine
    G --> G1[Report Class - Multi-Format Output]
    
    G1 --> G1A[generate_report - Main Report Generator]
    G1 --> G1B[_generate_html_report - Professional HTML]
    G1 --> G1C[_generate_json_report - Machine Readable]
    G1 --> G1D[_generate_csv_report - Data Analysis]
    G1 --> G1E[_display_terminal_report - Rich Console]
    
    G1A --> G1A1[Result Processing & Validation]
    G1A --> G1A2[Format Detection & Routing]
    G1A --> G1A3[Executive Summary Generation]
    G1A --> G1A4[Technical Intelligence Compilation]
    G1A --> G1A5[OWASP 2025 Compliance Mapping]
    
    G1B --> G1B1[HTML Template Processing]
    G1B --> G1B2[Bungee Typography Integration]
    G1B --> G1B3[Interactive Charts & Graphs]
    G1B --> G1B4[CVSS Score Visualization]
    G1B --> G1B5[Vulnerability Category Organization]
    G1B --> G1B6[Remediation Action Plans]
    
    G1C --> G1C1[JSON Schema Validation]
    G1C --> G1C2[API Integration Format]
    G1C --> G1C3[Automation-Ready Output]
    G1C --> G1C4[Timestamp & Metadata]
    
    G1E --> G1E1[Rich Table Formatting]
    G1E --> G1E2[Color-Coded Severity Levels]
    G1E --> G1E3[Progress Bar Integration]
    G1E --> G1E4[Panel-Based Layout]
    G1E --> G1E5[ASCII Art & Branding]
    
    %% CLI Interface & Control Flow
    H --> H1[Argument Processing System]
    H --> H2[Rich Console Integration]
    H --> H3[Progress Management]
    H --> H4[Error Handling & Recovery]
    
    H1 --> H1A[create_parser - Command Line Parser]
    H1 --> H1B[URL Validation & Processing]
    H1 --> H1C[Batch File Processing]
    H1 --> H1D[Output Format Selection]
    H1 --> H1E[Configuration Override Handling]
    
    H2 --> H2A[Console Initialization]
    H2 --> H2B[Legal Disclaimer Display]
    H2 --> H2C[Professional Header Display]
    H2 --> H2D[Footer & Credits Display]
    
    H3 --> H3A[Progress Column Configuration]
    H3 --> H3B[Task Creation & Management]
    H3 --> H3C[Real-time Progress Updates]
    H3 --> H3D[Completion Status Tracking]
    
    %% Main Execution Pipeline
    I --> I1[main - Primary Async Function]
    I --> I2[run_scan - Individual URL Scanner]
    I --> I3[simple_crawl - Website Crawling]
    I --> I4[Utility Functions]
    
    I1 --> I1A[Configuration Initialization]
    I1 --> I1B[Dependency Validation]
    I1 --> I1C[URL Collection & Processing]
    I1 --> I1D[Concurrent Scan Execution]
    I1 --> I1E[Result Aggregation]
    I1 --> I1F[Final Report Generation]
    I1 --> I1G[Exit Code Determination]
    
    I2 --> I2A[AsyncSession Context Creation]
    I2 --> I2B[SecurityChecker Initialization]
    I2 --> I2C[Full Security Assessment]
    I2 --> I2D[Error Handling & Recovery]
    I2 --> I2E[Result Return Processing]
    
    I3 --> I3A[Link Extraction from HTML]
    I3 --> I3B[URL Normalization & Filtering]
    I3 --> I3C[Depth-Limited Crawling]
    I3 --> I3D[Duplicate URL Prevention]
    
    I4 --> I4A[setup_signal_handlers - Graceful Shutdown]
    I4 --> I4B[display_banner - Professional Branding]
    I4 --> I4C[display_professional_footer - Credits]
    I4 --> I4D[check_dependencies - Validation]
    
    %% Styling - Ultra Vibrant Color Scheme
    style A fill:#e91e63,stroke:#ad1457,stroke-width:5px,color:#fff
    style E fill:#00e676,stroke:#00c853,stroke-width:4px,color:#000
    style D fill:#2196f3,stroke:#1565c0,stroke-width:4px,color:#fff
    style F fill:#ff9800,stroke:#ef6c00,stroke-width:4px,color:#000
    style G fill:#9c27b0,stroke:#6a1b9a,stroke-width:4px,color:#fff
    style H fill:#ff5722,stroke:#d84315,stroke-width:4px,color:#fff
    style I fill:#4caf50,stroke:#2e7d32,stroke-width:4px,color:#fff
    style B fill:#673ab7,stroke:#4527a0,stroke-width:3px,color:#fff
    style C fill:#009688,stroke:#00695c,stroke-width:3px,color:#fff
    style E1A1 fill:#ffeb3b,stroke:#f57f17,stroke-width:3px,color:#000
    style E1C1 fill:#03a9f4,stroke:#0277bd,stroke-width:3px,color:#fff
    style E1C2 fill:#8bc34a,stroke:#558b2f,stroke-width:3px,color:#000
    style B1 fill:#f44336,stroke:#c62828,stroke-width:2px,color:#fff
    style B2 fill:#3f51b5,stroke:#283593,stroke-width:2px,color:#fff
    style B3 fill:#795548,stroke:#4e342e,stroke-width:2px,color:#fff
    style B4 fill:#607d8b,stroke:#37474f,stroke-width:2px,color:#fff
    style C1 fill:#e1bee7,stroke:#7b1fa2,stroke-width:2px,color:#000
    style D1 fill:#b3e5fc,stroke:#0277bd,stroke-width:2px,color:#000
    style F1 fill:#fff3e0,stroke:#ef6c00,stroke-width:2px,color:#000
    style G1 fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px,color:#000
```

## Jupyter Notebook Code Architecture

```mermaid
%%{init: {'theme':'base', 'themeVariables': {'primaryColor':'#ff6b6b'}, 'flowchart': {'rankSpacing': 70, 'nodeSpacing': 40, 'curve': 'basis'}, 'layout': {'hierarchySeparation': 70, 'nodeSeparation': 40, 'edgeSeparation': 10}}}%%
graph LR
    A[DuskProbe v4.5 Jupyter Notebook - 1056 lines]
    A --> B[Cell Structure Analysis]
    A --> C[Import & Dependency Management]
    A --> D[Core Scanner Classes]
    A --> E[Vulnerability Detection Engine]
    A --> F[Colab Integration Layer]
    A --> G[Interactive Report Generation]
    A --> H[Data Analysis & Visualization]
    
    %% Cell Structure Analysis
    B --> B1[Cell 1 - Project Header & Documentation]
    B --> B2[Cell 2 - Automatic Dependency Installation]
    B --> B3[Cell 3 - Complete Code Documentation]
    B --> B4[Cell 4 - Standard Library Imports]
    B --> B5[Cell 5 - Google Colab Detection]
    B --> B6[Cell 6 - Optional Imports with Fallbacks]
    B --> B7[Cell 7-15 - Core Implementation Cells]
    B --> B8[Cell 16+ - Interactive Execution Cells]
    
    B1 --> B1A[Project Title & Version Info]
    B1 --> B1B[Enhanced Features Description]
    B1 --> B1C[Professional Report Formatting Notes]
    B1 --> B1D[Performance & Error Handling Info]
    
    B2 --> B2A[Automated pip Installation]
    B2 --> B2B[System Package Installation]
    B2 --> B2C[Tor Installation for Anonymity]
    B2 --> B2D[Success Confirmation Message]
    
    %% Import & Dependency Management
    C --> C1[Standard Library Block]
    C --> C2[Third-Party Library Block]
    C --> C3[Colab-Specific Imports]
    C --> C4[Conditional Import Handling]
    
    C1 --> C1A[os - Operating System Interface]
    C1 --> C1B[re - Regular Expression Operations]
    C1 --> C1C[json - JSON Data Handling]
    C1 --> C1D[time - Time-Related Functions]
    C1 --> C1E[socket - Network Communication]
    C1 --> C1F[base64 - Base64 Encoding/Decoding]
    C1 --> C1G[hashlib - Cryptographic Hashing]
    C1 --> C1H[subprocess - Process Management]
    C1 --> C1I[logging - Event Logging System]
    C1 --> C1J[urllib.parse - URL Manipulation]
    C1 --> C1K[pathlib.Path - File System Paths]
    C1 --> C1L[datetime - Date/Time Objects]
    C1 --> C1M[typing - Type Hints Support]
    C1 --> C1N[urllib3.util.retry - Request Retry Logic]
    C1 --> C1O[requests.adapters - HTTP Adapters]
    
    C2 --> C2A[requests - HTTP Request Library]
    C2 --> C2B[pandas - Data Analysis Framework]
    C2 --> C2C[numpy - Numerical Computing]
    
    C3 --> C3A[google.colab.output - Colab Output Control]
    C3 --> C3B[IPython.display - Rich Display System]
    C3 --> C3C[IS_COLAB - Environment Detection Flag]
    
    C4 --> C4A[BeautifulSoup - HTML Parsing]
    C4 --> C4B[colorama - Terminal Color Support]
    C4 --> C4C[fake_useragent - User Agent Rotation]
    C4 --> C4D[Fallback Classes for Missing Dependencies]
    
    %% Core Scanner Classes
    D --> D1[WebScanner Class - Main Scanner Engine]
    D --> D2[RequestHandler Class - HTTP Management]
    D --> D3[VulnerabilityChecker Class - Security Tests]
    D --> D4[ReportGenerator Class - Output Generation]
    
    D1 --> D1A[__init__ - Scanner Initialization]
    D1 --> D1B[scan_target - Main Scanning Method]
    D1 --> D1C[setup_session - HTTP Session Configuration]
    D1 --> D1D[cleanup - Resource Management]
    
    D1A --> D1A1[target_url - URL to Scan]
    D1A --> D1A2[scan_results - Results Storage]
    D1A --> D1A3[session - Requests Session]
    D1A --> D1A4[user_agents - UA Rotation List]
    D1A --> D1A5[vulnerability_tests - Test Registry]
    
    D1B --> D1B1[URL Validation & Normalization]
    D1B --> D1B2[Initial Site Information Gathering]
    D1B --> D1B3[Security Header Analysis]
    D1B --> D1B4[Vulnerability Test Execution]
    D1B --> D1B5[Results Compilation & Scoring]
    
    D2 --> D2A[make_request - HTTP Request Handler]
    D2 --> D2B[handle_redirects - Redirect Management]
    D2 --> D2C[parse_response - Response Processing]
    D2 --> D2D[error_handling - Exception Management]
    
    D2A --> D2A1[Request Timeout Configuration]
    D2A --> D2A2[Header Manipulation]
    D2A --> D2A3[SSL Certificate Handling]
    D2A --> D2A4[Retry Logic Implementation]
    
    D3 --> D3A[test_xss - Cross-Site Scripting]
    D3 --> D3B[test_sql_injection - SQL Injection]
    D3 --> D3C[test_lfi - Local File Inclusion]
    D3 --> D3D[test_open_redirect - Open Redirect]
    D3 --> D3E[test_idor - Insecure Direct Object Reference]
    D3 --> D3F[test_csrf - Cross-Site Request Forgery]
    D3 --> D3G[test_security_headers - Header Validation]
    D3 --> D3H[test_cryptominers - Mining Script Detection]
    
    %% Vulnerability Detection Engine
    E --> E1[Payload Management System]
    E --> E2[Pattern Recognition Engine]
    E --> E3[Response Analysis Framework]
    E --> E4[Risk Assessment Logic]
    
    E1 --> E1A[XSS Payload Database]
    E1 --> E1B[SQL Injection Payload Set]
    E1 --> E1C[LFI Path Traversal Payloads]
    E1 --> E1D[Open Redirect Test URLs]
    E1 --> E1E[IDOR Parameter Variations]
    E1 --> E1F[CSRF Token Bypass Methods]
    
    E1A --> E1A1[Basic Script Injection]
    E1A --> E1A2[Event Handler Injection]
    E1A --> E1A3[JavaScript Protocol Usage]
    E1A --> E1A4[HTML Entity Encoding Bypass]
    E1A --> E1A5[SVG-based XSS Vectors]
    
    E1B --> E1B1[Union-based Injection]
    E1B --> E1B2[Boolean-based Blind SQL]
    E1B --> E1B3[Time-based Blind SQL]
    E1B --> E1B4[Error-based Information Extraction]
    E1B --> E1B5[Second-order SQL Injection]
    
    E2 --> E2A[Error Message Pattern Matching]
    E2 --> E2B[Success Indicator Detection]
    E2 --> E2C[Behavior-based Analysis]
    E2 --> E2D[Response Time Analysis]
    
    E2A --> E2A1[Database Error Patterns]
    E2A --> E2A2[Server Error Messages]
    E2A --> E2A3[Application Framework Errors]
    E2A --> E2A4[Custom Error Page Detection]
    
    E3 --> E3A[HTTP Status Code Analysis]
    E3 --> E3B[Content-Length Comparison]
    E3 --> E3C[Response Header Examination]
    E3 --> E3D[Content Pattern Analysis]
    
    E4 --> E4A[CVSS Score Calculation]
    E4 --> E4B[Exploitability Assessment]
    E4 --> E4C[Impact Evaluation]
    E4 --> E4D[Risk Prioritization]
    
    %% Colab Integration Layer
    F --> F1[Interactive Input System]
    F --> F2[Progress Display Management]
    F --> F3[Cell Output Formatting]
    F --> F4[Error Handling for Colab]
    
    F1 --> F1A[URL Input Prompts]
    F1 --> F1B[Scan Configuration Options]
    F1 --> F1C[Output Format Selection]
    F1 --> F1D[Advanced Options Menu]
    
    F2 --> F2A[Real-time Progress Bars]
    F2 --> F2B[Status Message Updates]
    F2 --> F2C[Time Estimation Display]
    F2 --> F2D[Completion Notifications]
    
    F3 --> F3A[HTML Rich Output Generation]
    F3 --> F3B[Markdown Report Formatting]
    F3 --> F3C[Interactive Chart Creation]
    F3 --> F3D[Color-coded Result Display]
    
    %% Interactive Report Generation
    G --> G1[Pandas DataFrame Integration]
    G --> G2[HTML Report Generation]
    G --> G3[CSV Export Functionality]
    G --> G4[Interactive Visualization]
    
    G1 --> G1A[Vulnerability Results DataFrame]
    G1 --> G1B[Site Information DataFrame]
    G1 --> G1C[Security Header Analysis DataFrame]
    G1 --> G1D[Risk Assessment Summary DataFrame]
    
    G1A --> G1A1[Vulnerability Type Classification]
    G1A --> G1A2[Severity Level Assignment]
    G1A --> G1A3[Detection Confidence Scoring]
    G1A --> G1A4[Remediation Recommendation Mapping]
    
    G2 --> G2A[Professional HTML Template]
    G2 --> G2B[CSS Styling Integration]
    G2 --> G2C[JavaScript Chart Libraries]
    G2 --> G2D[Executive Summary Generation]
    
    G3 --> G3A[Raw Data CSV Export]
    G3 --> G3B[Summary Statistics CSV]
    G3 --> G3C[Timeline-based Export]
    G3 --> G3D[Compliance Report CSV]
    
    G4 --> G4A[Vulnerability Distribution Charts]
    G4 --> G4B[Risk Level Heat Maps]
    G4 --> G4C[Timeline Analysis Graphs]
    G4 --> G4D[Comparative Analysis Charts]
    
    %% Data Analysis & Visualization
    H --> H1[Statistical Analysis Engine]
    H --> H2[Trend Analysis System]
    H --> H3[Comparative Assessment]
    H --> H4[Predictive Risk Modeling]
    
    H1 --> H1A[Vulnerability Frequency Analysis]
    H1 --> H1B[Risk Distribution Statistics]
    H1 --> H1C[Detection Rate Calculations]
    H1 --> H1D[Time-to-Detection Metrics]
    
    H2 --> H2A[Historical Vulnerability Trends]
    H2 --> H2B[Risk Evolution Tracking]
    H2 --> H2C[Seasonal Pattern Recognition]
    H2 --> H2D[Improvement Rate Analysis]
    
    H3 --> H3A[Industry Benchmark Comparison]
    H3 --> H3B[Best Practice Compliance Scoring]
    H3 --> H3C[Peer Group Analysis]
    H3 --> H3D[Regulatory Standard Mapping]
    
    H4 --> H4A[Future Risk Projection]
    H4 --> H4B[Attack Vector Probability]
    H4 --> H4C[Impact Severity Forecasting]
    H4 --> H4D[Remediation Priority Optimization]
    
    %% Notebook-Specific Ultra Vibrant Styling
    style A fill:#e91e63,stroke:#ad1457,stroke-width:5px,color:#fff
    style D fill:#00bcd4,stroke:#00838f,stroke-width:4px,color:#fff
    style E fill:#3f51b5,stroke:#283593,stroke-width:4px,color:#fff
    style F fill:#4caf50,stroke:#2e7d32,stroke-width:4px,color:#fff
    style G fill:#ff9800,stroke:#ef6c00,stroke-width:4px,color:#000
    style H fill:#9c27b0,stroke:#6a1b9a,stroke-width:4px,color:#fff
    style B fill:#ff5722,stroke:#d84315,stroke-width:3px,color:#fff
    style C fill:#2196f3,stroke:#1565c0,stroke-width:3px,color:#fff
    style B1 fill:#ffeb3b,stroke:#f57f17,stroke-width:2px,color:#000
    style B2 fill:#8bc34a,stroke:#558b2f,stroke-width:2px,color:#000
    style B3 fill:#ff4081,stroke:#c2185b,stroke-width:2px,color:#fff
    style B4 fill:#7c4dff,stroke:#512da8,stroke-width:2px,color:#fff
    style C1 fill:#40e0d0,stroke:#00695c,stroke-width:2px,color:#000
    style C2 fill:#ffa726,stroke:#e65100,stroke-width:2px,color:#000
    style C3 fill:#ab47bc,stroke:#7b1fa2,stroke-width:2px,color:#fff
    style C4 fill:#66bb6a,stroke:#2e7d32,stroke-width:2px,color:#fff
    style D1 fill:#42a5f5,stroke:#1565c0,stroke-width:2px,color:#fff
    style D2 fill:#26c6da,stroke:#00838f,stroke-width:2px,color:#000
    style D3 fill:#5c6bc0,stroke:#283593,stroke-width:2px,color:#fff
    style D4 fill:#78909c,stroke:#37474f,stroke-width:2px,color:#fff
```

## Detailed Code Structure Analysis

### Core Classes and Methods

#### 1. DuskProbeConfig Class
**Purpose**: Centralized configuration management
- **Location**: Lines 245-310
- **Key Responsibilities**:
  - Command-line argument processing
  - YAML configuration file loading
  - Logging system setup with rotating file handlers
  - Directory structure creation (reports/, logs/)

#### 2. AsyncSession Class  
**Purpose**: High-performance asynchronous HTTP client
- **Location**: Lines 315-420
- **Key Features**:
  - **Concurrency**: 100 simultaneous connections
  - **Caching**: Response caching to avoid duplicate requests
  - **Optimization**: 3-second timeouts, connection pooling
  - **Methods**: `get()`, `post()`, connection management

#### 3. SecurityChecker Class
**Purpose**: Core vulnerability detection engine
- **Location**: Lines 425-2800
- **Comprehensive Payload Database**:
  - **XSS**: 14 sophisticated payloads including DOM-based, reflected, stored
  - **SQL Injection**: 15 payloads covering Union, Boolean, Time-based, Error-based
  - **LFI**: 15 payloads for Linux/Windows file inclusion
  - **Command Injection**: 14 OS command execution payloads
  - **SSRF**: 11 server-side request forgery payloads targeting cloud metadata
  - **Template Injection**: 9 payloads for Jinja2, Twig, Smarty engines

### Advanced Detection Methods

#### Quick Detection Engine
**Purpose**: Fast vulnerability identification with early returns
- `_quick_detect_xss()`: Immediate XSS pattern matching
- `_quick_detect_sqli()`: SQL error pattern recognition
- `_quick_detect_lfi()`: File inclusion indicators
- `_quick_detect_command_injection()`: Command output detection
- `_quick_detect_ssrf()`: Cloud metadata service detection

#### Comprehensive Reconnaissance System
**Purpose**: Enterprise-grade intelligence gathering
- **Server Analysis**: Cloud provider detection, CDN identification, WAF detection
- **Technology Stack**: Programming language, framework, database detection
- **Network Protocol**: HTTP version, security headers, TLS configuration
- **Intelligence Sources**: Integration with Shodan, WHOIS, DNS, SSL analysis

### OWASP 2025 Compliance Framework

#### Vulnerability Classification System
**Purpose**: Professional vulnerability management with CVSS scoring
- **Categories**: 6 major vulnerability categories with color coding
  - 🔓 Authentication & Access Control
  - 🧬 Injection & Execution Risks  
  - 🕸️ Client-Side & Browser Exploits
  - 📡 Network & Protocol-Level Issues
  - 🧱 Infrastructure & Configuration
  - 🧠 Logic & Business Layer

#### Risk Assessment Features
- **CVSS v3.1 Scoring**: Professional vulnerability severity assessment
- **CVE References**: Real CVE identifiers for each vulnerability type
- **Compliance Mapping**: PCI DSS, OWASP, ISO 27001, GDPR alignment
- **Business Impact**: Clear business risk communication
- **Remediation Guidance**: Actionable security recommendations

### Reporting System Architecture

#### Multi-Format Output Engine
**Purpose**: Professional reporting for different audiences
- **HTML Reports**: Interactive reports with Bungee typography
- **JSON Reports**: Machine-readable for automation
- **CSV Reports**: Data analysis and spreadsheet integration
- **Terminal Reports**: Rich console output with colors and tables

### Advanced Features

#### Optional Dependencies Integration
**Purpose**: Enhanced capabilities when additional libraries are available
- **Shodan**: IP intelligence and service enumeration
- **WHOIS**: Domain registration analysis
- **Builtwith**: Technology stack detection
- **Wayback Machine**: Historical analysis
- **DNS Tools**: Advanced DNS reconnaissance
- **SSLyze**: SSL/TLS configuration analysis
- **Selenium**: Browser automation for dynamic content
- **Nmap**: Port scanning capabilities

#### Performance Optimizations
**Purpose**: Maximum scanning speed and efficiency
- **Batch Processing**: 25-task batches with progress updates
- **Connection Pooling**: 200 connection limit, 50 per host
- **Smart Caching**: Response caching with 1000 entry limit
- **Content Limiting**: 100KB content size limits for speed
- **Concurrent Execution**: 100 simultaneous vulnerability checks

### Security and Legal Compliance

#### Ethical Usage Framework
**Purpose**: Legal compliance and responsible disclosure
- **Legal Disclaimer**: Prominent warning about authorized use only
- **Exit Codes**: 0-3 severity levels for automation integration
- **Logging**: Comprehensive audit trails
- **Rate Limiting**: Respectful scanning with configurable delays

## Installation and Deployment

### Automated Installation (install.sh)
- **Python Version Check**: Requires Python 3.8+
- **Dependency Installation**: Automated pip package installation
- **Tor Integration**: Optional anonymity features
- **Cross-Platform**: Linux, macOS, Windows support

### Dependencies Overview
- **Core**: aiohttp, beautifulsoup4, rich, pandas, pyyaml
- **Optional**: 25+ advanced security libraries
- **Development**: pytest, black, flake8 for code quality

## Legacy Evolution

### Version History
- **v5.0**: Complete rewrite with async architecture, OWASP 2025 compliance
- **v4.5**: Shell-optimized version (current main)
- **v4.0**: Enhanced reporting and security checks
- **Previous versions**: Jupyter notebook-based approach

The legacy Jupyter notebook version (1056 lines) shows the evolution from interactive notebook-based scanning to the current enterprise-grade command-line tool.

## Key Technical Achievements

1. **High-Performance Architecture**: 100x concurrent connections with intelligent batching
2. **Comprehensive Vulnerability Coverage**: 25+ security testing modules, 62+ reconnaissance components
3. **Professional Reporting**: Industry-standard HTML/JSON/CSV output formats
4. **OWASP 2025 Compliance**: Complete alignment with latest security standards
5. **Enterprise Features**: CVSS scoring, CVE mapping, compliance reporting
6. **Modular Design**: Pluggable architecture for easy extension
7. **Advanced Intelligence**: Integration with 8+ threat intelligence sources

This architecture represents a sophisticated, production-ready web vulnerability scanner designed for professional cybersecurity assessments with comprehensive coverage, high performance, and enterprise-grade reporting capabilities.
