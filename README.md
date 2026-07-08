# SOC Analyst Playbook

> A hands-on cybersecurity portfolio documenting practical malware analysis, vulnerability assessments, network investigations, detection engineering, and web application security using industry-standard tools in a controlled laboratory environment.

---

# About This Repository

This repository documents my practical learning journey toward becoming a **Security Operations Center (SOC) Analyst**.

Each lab focuses on solving real-world cybersecurity scenarios using widely adopted security tools rather than only explaining theoretical concepts. Every exercise is documented with objectives, methodology, analysis, observations, MITRE ATT&CK mappings, defensive recommendations, and key takeaways to reinforce practical Blue Team skills.

The primary goal of this repository is to build a strong foundation in malware analysis, network security, vulnerability management, detection engineering, incident investigation, and web application security through hands-on experimentation.

---

# Repository Contents

## Malware Analysis & Reverse Engineering

These labs focus on identifying malicious indicators, analyzing Windows executables, reverse engineering binaries, and understanding malware behavior through static analysis.

| Lab | Topic | Tools |
|------|------|------|
| Lab 01 | Static Malware Signature Detection | YARA |
| Lab 02 | Windows PE Malware Classification | YARA |
| Lab 03 | Static Malware Analysis | Radare2 |
| Lab 04 | Malware Reverse Engineering | Ghidra |

---

## Endpoint Security & Vulnerability Management

These exercises demonstrate host security hardening, vulnerability assessment, password auditing, network enumeration, and controlled vulnerability validation.

| Lab | Topic | Tools |
|------|------|------|
| Lab 05 | SSH Brute Force Protection | Fail2Ban |
| Lab 08 | Vulnerability Assessment | Nessus Essentials |
| Lab 10 | Internal Network Security Assessment | Nmap |
| Lab 11 | Controlled Vulnerability Validation | Metasploit Framework |
| Lab 14 | Password Strength Assessment | Hydra |

---

## Network Security, Traffic Analysis & Detection Engineering

These labs focus on monitoring network traffic, identifying malicious communications, analyzing Indicators of Compromise (IOCs), intrusion detection, and network attack detection.

| Lab | Topic | Tools |
|------|------|------|
| Lab 06 | Command & Control (C2) Traffic Analysis | Wireshark |
| Lab 07 | Malware Traffic Detection | Snort IDS |
| Lab 09 | Network Traffic Investigation & Data Exposure Analysis | Wireshark |
| Lab 15 | Detection & Analysis of DoS Attacks | HPing3, Wireshark, Snort IDS |

---

## Web Application Security

These labs demonstrate practical web application security testing using vulnerable applications to identify common security flaws and recommend defensive controls.

| Lab | Topic | Tools |
|------|------|------|
| Lab 12 | SQL Injection Security Assessment | Burp Suite |
| Lab 13 | Cross-Site Scripting (XSS) & Cross-Site Request Forgery (CSRF) Assessment | Burp Suite |

---

# Tools & Technologies

### Malware Analysis

- YARA
- Radare2
- Ghidra

### Network Security

- Wireshark
- Snort IDS
- HPing3
- Nmap

### Vulnerability Assessment

- Nessus Essentials
- Metasploit Framework

### Web Application Security

- Burp Suite
- OWASP Mutillidae
- DVWA

### Endpoint Security

- Fail2Ban
- Hydra

### Operating Systems

- Kali Linux
- Ubuntu Linux
- Metasploitable 2

---

# Skills Demonstrated

### Malware Analysis

- Static Malware Analysis
- Windows PE Analysis
- Malware Classification
- Reverse Engineering
- Windows API Analysis
- Malware Signature Development

### Network Security

- Network Enumeration
- Packet Capture & Analysis
- Network Traffic Investigation
- Command & Control (C2) Analysis
- Network Forensics

### Vulnerability Management

- Vulnerability Assessment
- Vulnerability Validation
- Security Risk Analysis
- Vulnerability Prioritization
- Security Recommendations

### Web Application Security

- SQL Injection Testing
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- HTTP Request Analysis
- Secure Web Application Testing

### Detection Engineering

- Intrusion Detection
- Snort Rule Development
- Signature-Based Detection
- IOC Analysis
- Threat Detection
- Security Monitoring

### Endpoint Security

- Password Strength Assessment
- Authentication Security
- SSH Hardening
- Brute Force Detection
- Brute Force Mitigation

---

# MITRE ATT&CK Coverage

The documented labs demonstrate techniques and defensive analysis related to multiple phases of the MITRE ATT&CK framework, including:

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

```text
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

Through these practical labs, I gained hands-on experience with:

- Malware analysis and reverse engineering
- Malware signature development using YARA
- Static analysis of Windows PE executables
- Command and Control (C2) traffic analysis
- Network packet inspection using Wireshark
- Vulnerability assessment with Nessus
- Internal network enumeration using Nmap
- Controlled vulnerability validation with Metasploit
- SQL Injection assessment
- Cross-Site Scripting (XSS) analysis
- Cross-Site Request Forgery (CSRF) assessment
- Password strength auditing using Hydra
- SSH brute-force protection with Fail2Ban
- Intrusion Detection System (IDS) deployment using Snort
- Custom Snort rule development
- Detection and analysis of Denial-of-Service (DoS) attacks
- Security monitoring and incident investigation

---

# Disclaimer

All activities documented in this repository were performed exclusively within isolated laboratory environments using virtual machines and intentionally vulnerable applications. The techniques demonstrated are intended solely for cybersecurity education, research, and authorized defensive security testing. No unauthorized systems or production environments were targeted.

---

⭐ If you find this repository useful, consider giving it a star.
