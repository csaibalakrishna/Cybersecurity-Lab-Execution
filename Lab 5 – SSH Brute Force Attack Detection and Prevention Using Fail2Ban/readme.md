# Lab 5 – SSH Brute Force Attack Detection and Prevention Using Fail2Ban

## Overview

This lab demonstrates how **Fail2Ban** can be used to detect and mitigate SSH brute-force attacks by monitoring authentication logs and automatically blocking malicious IP addresses.

A brute-force attack was simulated using **Hydra** from a Kali Linux machine against an Ubuntu system running an SSH service. Fail2Ban monitored repeated failed login attempts, identified the attack, and dynamically added firewall rules to ban the attacker's IP address.

This lab highlights how automated intrusion prevention enhances Linux server security by preventing unauthorized access attempts.

---

# Objectives

- Configure Fail2Ban to monitor SSH authentication logs.
- Simulate an SSH brute-force attack using Hydra.
- Automatically block malicious IP addresses.
- Analyze authentication logs.
- Verify automatic banning and manual unbanning of attacker IPs.
- Understand automated intrusion prevention mechanisms.

---

# Background

Brute-force attacks remain one of the most common methods used to compromise publicly exposed SSH services.

Attackers repeatedly attempt different username and password combinations until valid credentials are discovered.

Fail2Ban is an open-source Intrusion Prevention System (IPS) that continuously monitors log files for suspicious authentication activity. When predefined thresholds are exceeded, it automatically updates firewall rules to block the offending IP address for a configurable duration.

This significantly reduces the effectiveness of password guessing attacks while requiring minimal administrative intervention.

---

# Lab Environment

| Component | Details |
|-----------|---------|
| Attacker Machine | Kali Linux |
| Target Machine | Ubuntu Linux |
| Detection Tool | Fail2Ban |
| Attack Tool | Hydra |
| Target Service | OpenSSH |
| Firewall | iptables / nftables (managed by Fail2Ban) |

---

# Tools Used

- Fail2Ban
- Hydra
- OpenSSH Server
- Linux Terminal

---

# Installing Fail2Ban

Update the package repository:

```bash
sudo apt update
```

Install Fail2Ban:

```bash
sudo apt install fail2ban
```

Verify that the SSH service is running:

```bash
sudo systemctl status ssh
```

---

# Configuring Fail2Ban

Create a local configuration file:

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Edit the configuration:

```bash
sudo nano /etc/fail2ban/jail.local
```

Configure the SSH jail:

```ini
[sshd]
enabled = true
port = ssh
maxretry = 3
findtime = 600
bantime = 600
```

Restart Fail2Ban:

```bash
sudo systemctl restart fail2ban
```

---

# Simulating a Brute Force Attack

A brute-force attack was simulated from the Kali Linux system using Hydra.

```bash
hydra -l ubuntu -P /usr/share/wordlists/rockyou.txt ssh://<TARGET_IP>
```

Hydra repeatedly attempted SSH authentication using passwords from the RockYou wordlist.

---

# Monitoring Fail2Ban

View the status of the SSH jail:

```bash
sudo fail2ban-client status sshd
```

Example output:

```text
Status for the jail: sshd

Currently banned: 1

Banned IP list:
192.168.x.x
```

---

# Monitoring Authentication Logs

Authentication events can be monitored in real time:

```bash
tail -f /var/log/auth.log
```

The log records:

- Failed authentication attempts
- Successful logins
- SSH session activity
- Fail2Ban detection events

---

# Removing a Banned IP

To manually remove an IP address from the ban list:

```bash
sudo fail2ban-client set sshd unbanip <ATTACKER_IP>
```

Once removed, the attacker can again establish SSH connections if valid credentials are supplied.

---

# How Fail2Ban Works

The detection workflow consists of four stages:

### 1. Log Monitoring

Fail2Ban continuously monitors authentication logs for failed login attempts.

---

### 2. Pattern Matching

Regular expression filters identify repeated authentication failures originating from the same IP address.

---

### 3. Threshold Evaluation

If the number of failed login attempts exceeds the configured value (`maxretry`) within the specified `findtime`, the activity is classified as suspicious.

---

### 4. Automatic Blocking

Fail2Ban dynamically updates firewall rules to deny future connections from the offending IP address for the configured `bantime`.

---

# Analysis & Observations

During the simulated attack:

- Hydra generated repeated SSH authentication failures.
- Fail2Ban detected excessive failed login attempts.
- The attacker's IP address exceeded the configured retry threshold.
- A firewall rule was automatically created to block further SSH connections.
- Authentication logs confirmed detection and enforcement.
- Manual unbanning successfully restored access.

The experiment demonstrates automated protection against brute-force attacks without requiring continuous administrator intervention.

---

# SOC Analyst Perspective

Brute-force attacks are among the most frequently observed attack techniques against internet-facing services.

SOC analysts routinely investigate alerts generated from repeated authentication failures across:

- SSH
- RDP
- VPN gateways
- Web applications
- Email services

Fail2Ban acts as an automated response mechanism by converting suspicious authentication events into immediate defensive actions.

Understanding how Fail2Ban correlates log events with firewall enforcement helps analysts distinguish between normal authentication failures and active attack campaigns.

---

# MITRE ATT&CK Context

This lab demonstrates defensive measures against techniques commonly observed during credential attacks.

| ATT&CK Tactic | Technique | Description |
|--------------|-----------|-------------|
| Credential Access | T1110 – Brute Force | Attackers repeatedly attempt different passwords against SSH accounts. |
| Initial Access | T1078 – Valid Accounts | Successful brute-force attacks may result in unauthorized account access. |
| Defense | Mitigation | Fail2Ban automatically blocks attacker IP addresses after repeated failures. |

---

# Detection Opportunities

Security teams can identify brute-force activity using:

- SSH authentication logs
- Syslog
- Fail2Ban alerts
- Firewall logs
- SIEM correlation rules
- Endpoint authentication events

Common indicators include:

- Multiple failed logins from the same IP
- High authentication failure rates
- Rapid password guessing attempts
- Temporary IP bans
- Repeated login attempts against multiple accounts

---

# Key Takeaways

- Configured Fail2Ban to protect SSH services.
- Simulated an SSH brute-force attack using Hydra.
- Observed automatic IP banning based on authentication failures.
- Analyzed SSH authentication logs.
- Understood how automated intrusion prevention improves Linux server security.
- Gained practical experience with defensive security controls commonly deployed in enterprise environments.

---

# References

- Fail2Ban Official Documentation
- Hydra Documentation
- OpenSSH Documentation
- MITRE ATT&CK Framework
- OWASP Authentication Cheat Sheet

---

# Disclaimer

This lab was conducted in a controlled virtual environment for educational and defensive cybersecurity purposes. The brute-force attack was performed only against a test system owned by the researcher, and no unauthorized systems were targeted.
