# Lab 15 – Detection and Analysis of Denial-of-Service (DoS) Attacks Using HPing3, Wireshark, and Snort IDS

## Overview

This lab demonstrates the simulation, monitoring, and detection of Denial-of-Service (DoS) attacks in a controlled laboratory environment. Using HPing3, ICMP Flood and TCP SYN Flood traffic were generated against authorized target systems to simulate common network-based denial-of-service attacks.

Network traffic was analyzed using Wireshark while Snort Intrusion Detection System (IDS) monitored and generated alerts based on both default and custom detection rules. The objective was not only to understand how DoS attacks affect network services but also to demonstrate how defenders detect, analyze, and respond to malicious traffic.

This exercise reflects a typical Security Operations Center (SOC) workflow where suspicious network activity is investigated using multiple defensive security tools.

---

# Objectives

- Simulate ICMP Flood and TCP SYN Flood attacks.
- Capture malicious network traffic using Wireshark.
- Configure and validate Snort IDS.
- Develop custom Snort detection rules.
- Analyze IDS alerts generated during attack simulation.
- Understand defensive monitoring of denial-of-service attacks.

---

# Background

Denial-of-Service (DoS) attacks attempt to exhaust the resources of a target system, preventing legitimate users from accessing network services.

Common forms include:

- ICMP Flood
- SYN Flood
- UDP Flood
- HTTP Flood

One of the primary responsibilities of Security Operations Centers is identifying these attacks quickly through network monitoring, intrusion detection systems, and packet analysis.

HPing3 is commonly used for generating custom network traffic, Wireshark provides packet-level visibility, and Snort enables signature-based intrusion detection.

---

# Lab Environment

| Component | Details |
|-----------|---------|
| Attacker Machine | Kali Linux |
| Target Machine | Ubuntu Linux / Metasploitable 2 |
| Packet Analyzer | Wireshark |
| Intrusion Detection System | Snort IDS |
| Traffic Generator | HPing3 |

---

# Tools Used

- HPing3
- Wireshark
- Snort IDS
- Kali Linux
- Ubuntu Linux
- Metasploitable 2

---

# Installing Snort

Update packages:

```bash
sudo apt update
```

Install Snort:

```bash
sudo apt install snort -y
```

Verify installation:

```bash
snort -V
```

Configure Snort:

```bash
sudo nano /etc/snort/snort.conf
```

Validate configuration:

```bash
sudo snort -T -c /etc/snort/snort.conf
```

Start Snort:

```bash
sudo snort -A console -c /etc/snort/snort.conf
```

The Snort setup, configuration, rule validation, and monitoring process follows the workflow described in the uploaded lab material. :contentReference[oaicite:0]{index=0}

---

# Configuring Custom Detection Rules

Custom rules were added to:

```text
/etc/snort/rules/local.rules
```

Example rules included:

### ICMP Detection

```snort
alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"ICMP Packet Detected"; sid:5889; rev:1;)
```

### FTP Connection Detection

```snort
alert tcp any any -> $HOME_NET 21 (msg:"FTP Connection Attempt"; sid:60001; rev:1;)
```

### SSH Connection Detection

```snort
alert tcp any any -> $HOME_NET 22 (msg:"SSH Connection Attempt"; sid:60002; rev:1;)
```

These rules generate alerts whenever matching network traffic is observed. :contentReference[oaicite:1]{index=1}

---

# ICMP Flood Simulation

Baseline connectivity was first verified:

```bash
ping <TARGET_IP>
```

Packet capture was started using Wireshark.

HPing3 was then used to generate ICMP traffic.

Example:

```bash
sudo hping3 -1 -c 1 <TARGET_IP>
```

Flood mode:

```bash
sudo hping3 -1 --faster <TARGET_IP>
```

The generated ICMP traffic was successfully captured and analyzed. :contentReference[oaicite:2]{index=2}

---

# TCP SYN Flood Simulation

TCP SYN packets were generated against the target web server.

Example:

```bash
sudo hping3 -S -c 1 -p 80 <TARGET_IP>
```

Flood mode:

```bash
sudo hping3 -S --flood -p 80 <TARGET_IP>
```

During the simulation, the target experienced increased response times while Wireshark captured the high volume of SYN packets. :contentReference[oaicite:3]{index=3}

---

# Network Traffic Analysis

Wireshark was used to inspect captured traffic.

Observed traffic included:

- ICMP Echo Requests
- ICMP Echo Replies
- TCP SYN packets
- Incomplete TCP handshakes
- Increased packet rate during flood simulation

Packet analysis confirmed the characteristics of both ICMP Flood and SYN Flood attacks.

---

# Snort Detection

Snort monitored network traffic throughout the simulation.

Observed detections included:

- ICMP activity
- FTP connection attempts
- SSH connection attempts
- Network reconnaissance
- High packet volumes during flood simulations

Custom Snort rules successfully generated alerts when matching traffic was observed. :contentReference[oaicite:4]{index=4}

---

# Analysis & Observations

The simulated attacks demonstrated how excessive network traffic can impact service availability.

Key observations included:

- Increased ICMP traffic during flood simulation.
- Large number of TCP SYN packets.
- Delayed response from the target service.
- Successful packet capture using Wireshark.
- Real-time alert generation by Snort.
- Detection of custom rule signatures.

Combining packet analysis with IDS monitoring provided visibility into both attack generation and defensive detection.

---

# SOC Analyst Perspective

Denial-of-Service attacks are routinely monitored by Security Operations Centers because they directly affect service availability.

SOC analysts investigate:

- Sudden spikes in network traffic.
- High volumes of SYN packets.
- ICMP flooding.
- IDS alerts.
- Firewall logs.
- Network telemetry.

By correlating packet captures with Snort alerts, analysts can quickly identify attack patterns, determine affected systems, and initiate appropriate incident response procedures.

---

# MITRE ATT&CK Context

The observed activities correspond to several ATT&CK techniques.

| ATT&CK Tactic | Technique | Description |
|--------------|-----------|-------------|
| Impact | T1498 | Network Denial of Service |
| Discovery | T1046 | Network Service Discovery |
| Reconnaissance | T1595 | Active Scanning |

> **Note:** All traffic generation and detection activities were performed within an isolated laboratory environment using authorized systems.

---

# Detection Opportunities

Organizations can detect similar attacks using:

- Snort IDS
- Suricata IDS
- Zeek
- Wireshark
- NetFlow
- Firewall Logs
- SIEM Platforms
- Network Detection and Response (NDR)

Indicators include:

- High ICMP packet rates.
- Excessive TCP SYN packets.
- Incomplete TCP handshakes.
- Network latency spikes.
- Repeated IDS alerts.
- Sudden increases in bandwidth utilization.

---

# Defensive Recommendations

- Deploy IDS/IPS solutions.
- Enable SYN cookies.
- Configure firewall rate limiting.
- Apply ingress and egress filtering.
- Monitor network traffic continuously.
- Implement DDoS mitigation controls.
- Regularly tune IDS detection rules.

---

# Key Takeaways

- Simulated ICMP Flood and SYN Flood attacks using HPing3.
- Captured malicious traffic using Wireshark.
- Configured and validated Snort IDS.
- Developed custom Snort detection rules.
- Generated IDS alerts for simulated attacks.
- Understood how defensive monitoring supports incident detection and response.

---

# References

- HPing3 Documentation
- Snort Official Documentation
- Wireshark Documentation
- MITRE ATT&CK Framework
- NIST SP 800-61 – Computer Security Incident Handling Guide

---

# Disclaimer

This project was conducted entirely within an isolated laboratory environment using authorized virtual machines for educational and defensive cybersecurity purposes. All attack simulations, traffic generation, and intrusion detection activities were performed on systems specifically designated for security testing.
