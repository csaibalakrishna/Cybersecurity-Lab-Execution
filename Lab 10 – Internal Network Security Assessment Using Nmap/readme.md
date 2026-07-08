# Lab 10 – Internal Network Security Assessment Using Nmap

## Overview

This lab demonstrates the use of **Nmap (Network Mapper)** to perform an internal network security assessment. The objective is to identify active hosts, discover open ports, detect running services, determine operating system information, and assess the security posture of a target system.

A controlled laboratory environment consisting of Kali Linux and Metasploitable 2 was used to simulate an enterprise network. Various Nmap scanning techniques were performed to enumerate exposed services and identify potential security risks that could be exploited by an attacker.

This exercise reflects the reconnaissance and asset discovery phase commonly performed by Blue Teams, vulnerability management teams, and security analysts.

---

# Objectives

- Perform network host discovery.
- Identify open TCP and UDP ports.
- Detect running services and application versions.
- Perform operating system fingerprinting.
- Analyze exposed services and potential security risks.
- Document security findings and remediation recommendations.

---

# Background

Network enumeration is one of the first steps in every security assessment.

Before vulnerabilities can be identified, analysts must understand:

- Which hosts are active
- Which ports are exposed
- Which services are running
- Which operating systems are deployed
- Which services may introduce security risks

Nmap is one of the most widely used network discovery and security auditing tools. It enables administrators and security professionals to build an inventory of network assets while identifying unnecessary exposure that could increase an organization's attack surface.

---

# Lab Environment

| Component | Details |
|-----------|---------|
| Scanner | Kali Linux |
| Target | Metasploitable 2 |
| Tool | Nmap |
| Scan Type | Internal Network Enumeration |

---

# Tools Used

- Nmap
- Kali Linux
- Linux Terminal

---

# Network Discovery

A basic host scan was performed to verify that the target system was reachable.

```bash
nmap <TARGET_IP>
```

The scan identified active hosts and their accessible network services.

---

# Port Scanning

Open ports were identified to determine which services were exposed.

Verbose scan:

```bash
sudo nmap -v <TARGET_IP>
```

Display only open ports:

```bash
nmap --open <TARGET_IP>
```

Scan a specific port:

```bash
nmap -p 80 <TARGET_IP>
```

---

# Service Version Detection

Service version detection was performed to identify the applications running on discovered ports.

```bash
nmap -sV <TARGET_IP>
```

This scan identifies:

- Service name
- Version number
- Application banner
- Product information

Knowing software versions assists analysts in identifying outdated or vulnerable services.

---

# Operating System Detection

Operating system fingerprinting was performed using:

```bash
sudo nmap -O <TARGET_IP>
```

Additional fingerprinting:

```bash
sudo nmap -O --osscan-guess <TARGET_IP>
```

Operating system detection provides valuable information for vulnerability assessment and attack surface analysis.

---

# Aggressive Scan

A comprehensive assessment was performed using:

```bash
sudo nmap -A <TARGET_IP>
```

Aggressive scanning combines multiple capabilities including:

- OS Detection
- Service Detection
- Script Scanning
- Traceroute

This provides a detailed overview of the target system.

---

# SYN Scan

Half-open TCP scanning was performed using:

```bash
sudo nmap -sS <TARGET_IP>
```

The SYN scan is faster and less intrusive than a full TCP connection scan.

---

# TCP Connect Scan

```bash
sudo nmap -sT <TARGET_IP>
```

This scan establishes a complete TCP connection with the target service.

---

# UDP Scan

UDP services were identified using:

```bash
sudo nmap -sU <TARGET_IP>
```

UDP scanning is useful for discovering services such as:

- DNS
- SNMP
- DHCP
- TFTP

---

# Service Enumeration Summary

The assessment successfully identified:

- Active host
- Open TCP ports
- Running network services
- Operating system details
- Service versions
- Exposed attack surface

---

# Analysis & Observations

The network assessment revealed multiple publicly accessible services running on the target host.

Examples of observations included:

- Multiple open TCP ports
- Publicly accessible network services
- Service version information
- Operating system fingerprint
- Legacy software components
- Potential attack vectors

The collected information provides attackers with valuable intelligence during the reconnaissance phase while simultaneously helping defenders identify unnecessary exposure.

---

# Risk Assessment

Open services increase the organization's attack surface.

Potential risks include:

| Risk | Impact |
|------|--------|
| Unnecessary Open Ports | Increased attack surface |
| Outdated Services | Exploitation of known vulnerabilities |
| Banner Disclosure | Information leakage |
| Legacy Protocols | Weak security controls |
| Unpatched Software | Remote compromise |

---

# SOC Analyst Perspective

Network enumeration is not only performed by penetration testers—it is also a critical Blue Team activity.

SOC analysts routinely use network discovery tools to:

- Maintain asset inventories.
- Identify unauthorized devices.
- Detect newly exposed services.
- Verify security baselines.
- Validate firewall configurations.
- Support vulnerability management programs.

Unexpected open ports or newly discovered services may indicate unauthorized software installations or configuration drift, both of which warrant further investigation.

---

# MITRE ATT&CK Context

Reconnaissance and service enumeration provide information that attackers commonly use during the early stages of an intrusion.

| ATT&CK Tactic | Technique | Description |
|--------------|-----------|-------------|
| Discovery | T1046 | Network Service Discovery |
| Discovery | T1018 | Remote System Discovery |
| Discovery | T1082 | System Information Discovery |
| Reconnaissance | T1595 | Active Scanning |

> **Note:** This lab focuses on defensive network assessment. The ATT&CK techniques listed represent activities commonly associated with reconnaissance and discovery rather than malicious exploitation.

---

# Detection Opportunities

Security teams can identify unauthorized scanning activity through:

- Firewall logs
- IDS/IPS alerts
- NetFlow
- Zeek
- Suricata
- Snort
- Endpoint telemetry
- SIEM correlation rules

Common indicators include:

- Sequential port scanning
- SYN scan patterns
- High connection rates
- Service enumeration attempts
- OS fingerprinting activity

---

# Defensive Recommendations

- Disable unnecessary network services.
- Close unused ports.
- Restrict management interfaces.
- Apply the latest security patches.
- Implement network segmentation.
- Monitor for reconnaissance activity.
- Deploy IDS/IPS to detect network scanning.
- Perform regular vulnerability assessments.

---

# Key Takeaways

- Performed internal network discovery using Nmap.
- Identified exposed ports and running services.
- Conducted operating system fingerprinting.
- Performed service version detection.
- Assessed the target's security posture.
- Documented findings and remediation recommendations.

---

# References

- Nmap Official Documentation
- Nmap Network Scanning Guide
- MITRE ATT&CK Framework
- NIST SP 800-115 – Technical Guide to Information Security Testing and Assessment
- OWASP Testing Guide

---

# Disclaimer

This assessment was performed in an isolated laboratory environment against authorized systems for educational and defensive cybersecurity purposes. All scans were conducted on systems owned or designated for testing, and no unauthorized networks were targeted.
