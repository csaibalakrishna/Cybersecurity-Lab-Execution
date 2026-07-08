# SOC Analyst Playbook

A hands-on cybersecurity portfolio documenting practical malware analysis, network investigations, vulnerability assessments, detection engineering, endpoint security, and web application security using industry-standard tools in a controlled laboratory environment.

---

## About This Repository

This repository showcases my hands-on learning journey toward becoming a **Security Operations Center (SOC) Analyst**.

The labs are designed to simulate real-world security investigations and defensive workflows using widely adopted cybersecurity tools. Rather than focusing only on theory, each exercise emphasizes practical analysis, documentation, and defensive thinking.

Every lab includes:

- Objectives
- Lab Environment
- Methodology
- Step-by-Step Procedure
- Analysis & Findings
- Indicators of Compromise (IOCs)
- MITRE ATT&CK Mapping (where applicable)
- Defensive Recommendations
- Key Takeaways

The goal of this repository is to strengthen practical Blue Team skills through structured, repeatable security investigations performed in an isolated laboratory environment.

---

# Repository Highlights

- **15 Hands-on Security Labs**
- **10+ Industry Security Tools**
- **Malware Analysis & Reverse Engineering**
- **Network Traffic Investigation**
- **Detection Engineering**
- **Vulnerability Assessment**
- **Web Application Security Testing**
- **Endpoint Security**
- **MITRE ATT&CK Mapping**
- **Professional Investigation Documentation**

---

# Repository Contents

## Malware Analysis & Reverse Engineering

These labs focus on identifying malicious indicators, analyzing Windows executables, reverse engineering binaries, and understanding malware behavior through static analysis.

| Lab | Topic | Tools |
|-----|------|------|
| Lab 01 | Static Malware Signature Detection | YARA |
| Lab 02 | Windows PE Malware Classification | YARA |
| Lab 03 | Static Malware Analysis | Radare2 |
| Lab 04 | Malware Reverse Engineering | Ghidra |

---

## Endpoint Security & Vulnerability Management

These exercises demonstrate host security hardening, vulnerability assessment, password auditing, network enumeration, and controlled vulnerability validation.

| Lab | Topic | Tools |
|-----|------|------|
| Lab 05 | SSH Brute Force Protection | Fail2Ban |
| Lab 08 | Vulnerability Assessment | Nessus Essentials |
| Lab 10 | Internal Network Security Assessment | Nmap |
| Lab 11 | Controlled Vulnerability Validation | Metasploit Framework |
| Lab 14 | Password Strength Assessment | Hydra |

---

## Network Security, Traffic Analysis & Detection Engineering

These labs focus on analyzing network traffic, identifying malicious communications, investigating Indicators of Compromise (IOCs), and building detection capabilities.

| Lab | Topic | Tools |
|-----|------|------|
| Lab 06 | Command & Control (C2) Traffic Analysis | Wireshark |
| Lab 07 | Malware Traffic Detection | Snort IDS |
| Lab 09 | Network Traffic Investigation & Data Exposure Analysis | Wireshark |
| Lab 15 | Detection & Analysis of DoS Attacks | HPing3, Wireshark, Snort IDS |

---

## Web Application Security

These labs demonstrate practical web application security testing against intentionally vulnerable applications to identify common security flaws and recommend defensive controls.

| Lab | Topic | Tools |
|-----|------|------|
| Lab 12 | SQL Injection Security Assessment | Burp Suite |
| Lab 13 | Cross-Site Scripting (XSS) & Cross-Site Request Forgery (CSRF) Assessment | Burp Suite |

---

# Tools & Technologies

## Malware Analysis

- YARA
- Radare2
- Ghidra

### Skills

- Malware Analysis
- Static Malware Analysis
- Windows PE Analysis
- Malware Classification
- Reverse Engineering
- Windows API Analysis
- Signature Development

---

## Network Security

- Wireshark
- Snort IDS
- HPing3
- Nmap

### Skills

- Packet Capture & Analysis
- Network Enumeration
- Traffic Investigation
- Command & Control (C2) Analysis
- Network Forensics
- Intrusion Detection
- Detection Engineering

---

## Vulnerability Management

- Nessus Essentials
- Metasploit Framework

### Skills

- Vulnerability Assessment
- Vulnerability Validation
- Security Risk Analysis
- Risk Prioritization
- Security Recommendations

---

## Web Application Security

- Burp Suite
- OWASP Mutillidae
- DVWA

### Skills

- SQL Injection Testing
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- HTTP Request Analysis
- Secure Web Application Testing

---

## Endpoint Security

- Fail2Ban
- Hydra

### Skills

- Password Strength Assessment
- Authentication Security
- SSH Hardening
- Brute Force Detection
- Brute Force Mitigation

---

## Operating Systems

- Kali Linux
- Ubuntu Linux
- Metasploitable 2

---

# Skills Demonstrated

## Security Operations

- Incident Investigation
- Security Monitoring
- IOC Analysis
- Detection Engineering
- Defensive Security Analysis
- Technical Documentation

## Malware Analysis

- Static Malware Analysis
- Malware Classification
- Reverse Engineering
- Windows PE Analysis
- Signature Development

## Network Security

- Packet Analysis
- Network Traffic Investigation
- Network Enumeration
- Intrusion Detection
- Network Forensics

## Vulnerability Management

- Vulnerability Assessment
- Vulnerability Validation
- Risk Analysis
- Security Hardening

## Web Security

- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- HTTP Security Analysis

## Endpoint Security

- Password Auditing
- SSH Hardening
- Authentication Security
- Brute Force Protection

---

# SOC Skills Mapping

| SOC Responsibility | Demonstrated In |
|---------------------------|--------------------------------------------|
| Malware Investigation | Labs 01–04 |
| Network Traffic Analysis | Labs 06, 09, 15 |
| Vulnerability Assessment | Labs 08, 10, 11 |
| Detection Engineering | Labs 01, 02, 07, 15 |
| Web Application Security | Labs 12, 13 |
| Endpoint Security | Labs 05, 14 |
| Incident Investigation | Multiple Labs |
| MITRE ATT&CK Mapping | Multiple Labs |

---

# MITRE ATT&CK Coverage

The documented investigations demonstrate techniques and defensive analysis related to multiple stages of the MITRE ATT&CK framework, including:

- Initial Access
- Execution
- Persistence
- Discovery
- Credential Access
- Collection
- Command and Control
- Impact

---

# Repository Structure

```
Cybersecurity-Lab-Execution/
│
├── lab01-yara-signature-detection
├── lab02-yara-malware-classification
├── lab03-radare2-static-analysis
├── lab04-ghidra-reverse-engineering
├── lab05-fail2ban-brute-force-protection
├── lab06-wireshark-c2-analysis
├── lab07-snort-malware-detection
├── lab08-nessus-vulnerability-assessment
├── lab09-wireshark-data-exfiltration
├── lab10-nmap-network-assessment
├── lab11-metasploit-vulnerability-validation
├── lab12-burp-sql-injection
├── lab13-burp-xss-csrf
├── lab14-hydra-password-assessment
└── lab15-dos-detection-hping3-snort
```

---

# Learning Outcomes

Through these practical investigations, I gained hands-on experience in:

- Malware analysis and reverse engineering
- Malware signature development using YARA
- Windows PE executable analysis
- Command & Control (C2) traffic investigation
- Packet capture and network traffic analysis using Wireshark
- Vulnerability assessment with Nessus Essentials
- Internal network enumeration using Nmap
- Controlled vulnerability validation using Metasploit
- SQL Injection testing
- Cross-Site Scripting (XSS) analysis
- Cross-Site Request Forgery (CSRF) assessment
- Password auditing using Hydra
- SSH brute-force protection with Fail2Ban
- Intrusion Detection System (IDS) deployment using Snort
- Custom Snort rule development
- Detection and investigation of Denial-of-Service (DoS) attacks
- Security monitoring and incident investigation
- Mapping security findings to the MITRE ATT&CK framework
- Documenting investigations using professional security reporting practices

---

# Future Learning Roadmap

This repository will continue to evolve as I expand my practical Blue Team skillset. Planned additions include:

- Windows Sysmon Log Analysis
- Wazuh SIEM Home Lab
- Splunk Security Monitoring
- Sigma Rule Development
- Advanced Threat Hunting
- Active Directory Security Labs
- Incident Response Playbooks
- Detection Engineering Scenarios

---

# Disclaimer

All activities documented in this repository were performed exclusively within isolated laboratory environments using virtual machines and intentionally vulnerable applications.

The techniques demonstrated are intended solely for cybersecurity education, research, and authorized defensive security testing. No unauthorized systems or production environments were targeted.
