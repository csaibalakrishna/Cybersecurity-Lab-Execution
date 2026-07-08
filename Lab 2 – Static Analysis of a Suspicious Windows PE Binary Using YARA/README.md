# Lab 2 – Static Analysis of a Suspicious Windows PE Binary Using YARA

## Overview

This lab demonstrates how **YARA** can be used to perform static analysis on a suspicious Windows Portable Executable (PE) file without executing it. A custom YARA rule was developed to identify malware-related indicators such as process injection APIs, command execution strings, and persistence mechanisms commonly observed in Windows malware.

Instead of relying on behavioral analysis, the binary was examined using signature-based detection techniques to determine whether it exhibited characteristics commonly associated with Trojans or backdoors.

---

# Objectives

- Perform static analysis without executing the binary.
- Create a custom YARA rule for malware detection.
- Identify suspicious Windows API calls.
- Detect persistence-related artifacts.
- Understand how signature-based malware detection works.

---

# Background

Static malware analysis is the process of inspecting a binary without executing it. This approach allows analysts to identify suspicious characteristics while minimizing the risk of system compromise.

YARA is one of the most widely used tools for signature-based malware detection. It enables analysts to classify files by searching for predefined strings, binary patterns, and Portable Executable (PE) characteristics.

In this lab, a Windows PE sample was modified by embedding malware-related strings commonly associated with process injection and persistence techniques. A custom YARA rule was then used to identify these indicators.

---

# Lab Environment

| Component | Details |
|-----------|---------|
| Operating System | Kali Linux |
| Tool | YARA |
| Analysis Type | Static Malware Analysis |
| Target File | `suspicious.bin` |
| File Format | Windows Portable Executable (PE32) |

---

# Tools Used

- YARA
- Linux Terminal
- `strings`
- `file`

---

# Project Structure

```text
lab2/
│
├── README.md
├── windows_malware_generic.yar
├── suspicious.bin
└── screenshots/
```

---

# Verifying the Binary

The binary was first verified to confirm that it was a Windows Portable Executable.

```bash
file suspicious.bin
```

Expected output:

```text
PE32 executable for MS Windows
```

This confirms that the file is a Windows executable suitable for static analysis.

---

# YARA Rule

```yara
rule windows_malware_generic
{
    meta:
        author = "Students"
        description = "Generic Windows PE malware detection using static indicators"
        malware_type = "Trojan / Backdoor (Generic)"

    strings:
        $api1 = "CreateRemoteThread" ascii nocase
        $api2 = "VirtualAllocEx" ascii nocase
        $api3 = "WriteProcessMemory" ascii nocase
        $cmd  = "cmd.exe" ascii nocase
        $reg  = "CurrentVersion\\Run" ascii nocase

    condition:
        uint16(0) == 0x5A4D and
        (any of ($api*) or $cmd or $reg)
}
```

---

# Rule Explanation

## Meta Information

Provides descriptive information about the rule.

| Field | Description |
|--------|-------------|
| author | Rule author |
| description | Purpose of the rule |
| malware_type | Intended malware classification |

---

## Strings

The rule searches for several Windows API names and persistence indicators that frequently appear in malware.

| Indicator | Reason |
|-----------|--------|
| CreateRemoteThread | Process injection |
| VirtualAllocEx | Remote memory allocation |
| WriteProcessMemory | Injecting code into another process |
| cmd.exe | Command execution |
| CurrentVersion\\Run | Registry persistence |

---

## Condition

```yara
uint16(0) == 0x5A4D
```

Ensures the file begins with the **MZ** header, indicating a Windows Portable Executable.

The rule then checks whether any suspicious API or persistence string exists within the binary.

---

# Execution Steps

Verify the file:

```bash
file suspicious.bin
```

Extract readable strings:

```bash
strings -a suspicious.bin | grep -Ei "CreateRemoteThread|cmd.exe"
```

Execute the YARA rule:

```bash
yara windows_malware_generic.yar suspicious.bin
```

---

# Analysis & Observations

During static analysis, several suspicious indicators were identified within the binary.

Observed indicators included:

- CreateRemoteThread
- VirtualAllocEx
- WriteProcessMemory
- cmd.exe
- CurrentVersion\Run

The presence of these indicators suggests functionality commonly associated with malware techniques such as process injection, remote code execution, and persistence.

Since the analysis relied entirely on static inspection, the binary was never executed.

---

# Why These Indicators Matter

### CreateRemoteThread

Frequently used by malware to create threads inside another process after injecting malicious code.

---

### VirtualAllocEx

Allocates memory inside a remote process, enabling payload injection.

---

### WriteProcessMemory

Writes shellcode or malicious payloads into another process.

---

### cmd.exe

Often used by malware to execute operating system commands.

---

### Registry Run Key

The `CurrentVersion\Run` registry location is commonly abused to maintain persistence after system reboot.

---

# SOC Analyst Perspective

Static analysis is often the first stage of malware triage in a Security Operations Center.

Rather than executing an unknown binary immediately, analysts inspect its structure and embedded artifacts to determine whether further investigation is required.

YARA enables analysts to rapidly identify suspicious files based on known indicators, reducing analysis time and improving incident prioritization.

In enterprise environments, YARA rules are frequently integrated into:

- Malware analysis pipelines
- Threat hunting workflows
- Email security gateways
- Endpoint Detection and Response (EDR) platforms
- Digital forensic investigations

---

# MITRE ATT&CK Context

The indicators detected in this lab are commonly associated with the following ATT&CK techniques:

| Tactic | Technique | Description |
|---------|-----------|-------------|
| Defense Evasion | T1055 – Process Injection | APIs such as `CreateRemoteThread`, `VirtualAllocEx`, and `WriteProcessMemory` are frequently used during process injection. |
| Execution | T1059.003 – Windows Command Shell | Use of `cmd.exe` may indicate command execution capabilities. |
| Persistence | T1547.001 – Registry Run Keys / Startup Folder | Registry autorun entries can be used to establish persistence across reboots. |

> **Note:** This analysis identifies static indicators only. The presence of these strings does not confirm that the binary actively performs these techniques without dynamic analysis.

---

# Detection Opportunities

Security teams can detect similar activity using:

- YARA scanning
- Windows Event Logs
- Sysmon
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- Elastic Security
- Splunk Enterprise Security
- Microsoft Sentinel

Useful telemetry includes:

- Process creation events
- Registry modifications
- Memory allocation activity
- Process injection alerts
- Command-line execution logs

---

# Key Takeaways

- Performed static malware analysis without executing the binary.
- Developed a custom YARA rule for Windows PE detection.
- Identified suspicious API calls and persistence indicators.
- Understood how malware signatures are used for rapid file classification.
- Gained practical experience with one of the most widely used malware analysis tools in defensive security.

---

# References

- YARA Documentation
- MITRE ATT&CK Framework
- Microsoft Windows API Documentation
- Malware Unicorn – Static Malware Analysis
- SANS FOR610 Malware Analysis Resources

---

# Disclaimer

This project is intended solely for cybersecurity education and defensive security research. The analyzed binary was used in a controlled laboratory environment, and no live malware was executed during this exercise.
