# Lab 13 – Web Application Security Assessment Using Burp Suite (XSS & CSRF)

## Overview

This lab demonstrates the use of **Burp Suite Community Edition** to assess a deliberately vulnerable web application for **Cross-Site Scripting (XSS)** and **Cross-Site Request Forgery (CSRF)** vulnerabilities.

The assessment was performed against the **Damn Vulnerable Web Application (DVWA)** running on Metasploitable 2. Both manual browser testing and Burp Suite request interception were used to identify insecure input handling, session management weaknesses, and unauthorized request execution.

The objective was to understand how client-side vulnerabilities can compromise user sessions and how improper request validation may allow attackers to perform unauthorized actions on behalf of authenticated users.

---

# Objectives

- Configure Burp Suite as an intercepting proxy.
- Identify Stored and Reflected XSS vulnerabilities.
- Demonstrate cookie exposure through JavaScript execution.
- Capture and replay HTTP requests using Burp Suite.
- Analyze CSRF request manipulation.
- Recommend defensive controls against common web attacks.

---

# Background

Modern web applications rely heavily on user input and authenticated HTTP requests.

Improper validation of user-supplied data can introduce vulnerabilities that attackers may exploit to:

- Execute malicious JavaScript
- Steal session cookies
- Hijack authenticated sessions
- Modify user information
- Perform unauthorized actions

Two of the most common web application vulnerabilities are:

### Cross-Site Scripting (XSS)

Cross-Site Scripting occurs when an application allows untrusted JavaScript to execute inside another user's browser.

Depending on implementation, XSS may be:

- Stored (Persistent)
- Reflected
- DOM-Based

Successful XSS attacks may result in:

- Session hijacking
- Cookie theft
- Credential theft
- Defacement
- Browser redirection

---

### Cross-Site Request Forgery (CSRF)

CSRF occurs when an authenticated user's browser is tricked into sending unauthorized requests to a trusted application.

Because the browser automatically includes session cookies, the application may execute the forged request without verifying user intent.

Typical impacts include:

- Password changes
- Email modifications
- Account takeover
- Administrative actions

---

# Lab Environment

| Component | Details |
|-----------|---------|
| Testing Machine | Kali Linux |
| Target Machine | Metasploitable 2 |
| Vulnerable Application | DVWA |
| Proxy Tool | Burp Suite Community Edition |
| Browser | Firefox |

---

# Tools Used

- Burp Suite Community Edition
- Firefox
- Kali Linux
- Metasploitable 2
- DVWA

---

# Burp Suite Configuration

Burp Suite was configured as an intercepting proxy.

Default Listener:

```
127.0.0.1:8080
```

Firefox was configured to forward HTTP traffic through Burp Suite.

The Burp CA Certificate was imported into Firefox to enable HTTPS interception when required. :contentReference[oaicite:1]{index=1}

---

# Stored Cross-Site Scripting (Stored XSS)

The Stored XSS module within DVWA was used to evaluate persistent script execution.

A JavaScript payload was submitted through the guestbook functionality.

The application permanently stored the malicious input.

Whenever another user viewed the page, the injected script executed automatically.

Observed behavior:

- User input permanently stored
- JavaScript executed on page load
- Browser alert displayed
- Payload persisted after page refresh

This confirms the presence of a Stored XSS vulnerability. :contentReference[oaicite:2]{index=2}

---

# Reflected Cross-Site Scripting (Reflected XSS)

The Reflected XSS module was tested using JavaScript injected through URL parameters and form inputs.

Observed behavior:

- Script executed immediately
- Payload not permanently stored
- JavaScript executed only for the crafted request

Unlike Stored XSS, the payload disappeared after the request completed.

---

# Session Cookie Exposure

JavaScript was used to access browser cookies during the Stored XSS demonstration.

The payload successfully accessed the active session cookie.

This illustrates how XSS may expose sensitive authentication tokens if browser protections such as HttpOnly are absent.

---

# Cross-Site Request Forgery (CSRF)

The CSRF module within DVWA was used to evaluate request validation.

Password change requests were intercepted before reaching the server.

Captured requests included:

- HTTP Method
- Request Parameters
- Session Cookies
- Password Fields

The intercepted request was modified and replayed through Burp Suite Repeater.

The server accepted the manipulated request and processed the password change, demonstrating insufficient protection against forged requests. :contentReference[oaicite:3]{index=3}

---

# HTTP Request Analysis

Burp Suite captured complete HTTP requests and responses.

Captured information included:

- Request headers
- Cookies
- POST parameters
- Authentication tokens
- Server responses

Intercepting traffic allows analysts to inspect application behavior and validate security controls.

---

# Analysis & Observations

The assessment identified multiple web application security weaknesses.

Observed findings included:

- Stored XSS vulnerability
- Reflected XSS vulnerability
- Session cookie exposure
- Missing CSRF protection
- Successful request replay
- Inadequate input validation

These issues demonstrate how improper server-side validation and weak session management may lead to account compromise.

---

# Security Findings

| Finding | Risk |
|----------|------|
| Stored XSS | Critical |
| Reflected XSS | High |
| Session Cookie Exposure | High |
| Missing CSRF Protection | High |
| Improper Input Validation | High |

---

# SOC Analyst Perspective

SOC analysts frequently investigate alerts generated by Web Application Firewalls (WAFs), SIEM platforms, and Endpoint Detection and Response (EDR) tools involving suspicious web application activity.

Understanding XSS and CSRF attacks enables analysts to:

- Investigate malicious HTTP requests.
- Detect suspicious JavaScript payloads.
- Analyze session hijacking attempts.
- Correlate authentication anomalies.
- Support web application incident response.

Knowledge of Burp Suite also helps analysts reproduce suspicious requests and validate security findings during investigations.

---

# MITRE ATT&CK Context

The demonstrated vulnerabilities align with several ATT&CK techniques involving web application exploitation and credential abuse.

| ATT&CK Tactic | Technique | Description |
|--------------|-----------|-------------|
| Initial Access | T1190 | Exploit Public-Facing Application |
| Credential Access | T1539 | Steal Web Session Cookie |
| Collection | T1056 | Input Capture |
| Defense Evasion | T1550 | Use of Stolen Session Cookies |

> **Note:** These mappings represent techniques that attackers may leverage when exploiting XSS and CSRF vulnerabilities. All testing was performed within an isolated laboratory environment.

---

# Detection Opportunities

Organizations can identify similar attacks using:

- Web Application Firewall (WAF)
- Burp Suite Logger
- Web Server Logs
- SIEM Platforms
- IDS / IPS
- Browser Security Headers
- CSP Reporting

Indicators include:

- Suspicious JavaScript payloads
- Unexpected POST requests
- Missing CSRF tokens
- Session anomalies
- Multiple password change requests
- Abnormal user behavior

---

# Defensive Recommendations

- Validate and sanitize all user input.
- Encode output before rendering.
- Implement Content Security Policy (CSP).
- Enable HttpOnly and Secure cookie attributes.
- Implement anti-CSRF tokens.
- Verify request origin.
- Enforce SameSite cookie policies.
- Perform regular web application security assessments.

---

# Key Takeaways

- Configured Burp Suite for web application testing.
- Identified Stored and Reflected XSS vulnerabilities.
- Demonstrated session cookie exposure.
- Intercepted and replayed HTTP requests.
- Validated CSRF weaknesses.
- Understood secure web application design principles.

---

# References

- OWASP Cross-Site Scripting Prevention Cheat Sheet
- OWASP CSRF Prevention Cheat Sheet
- PortSwigger Web Security Academy
- Burp Suite Documentation
- OWASP Top 10
- MITRE ATT&CK Framework

---

# Disclaimer

This assessment was conducted exclusively within an isolated laboratory environment using the intentionally vulnerable Damn Vulnerable Web Application (DVWA). All testing was performed on authorized systems for educational and defensive cybersecurity purposes.
