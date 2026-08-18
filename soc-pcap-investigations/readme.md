# SOC PCAP Investigations

A practical network investigation series focused on developing **SOC Analyst / Blue Team detection and investigation skills through publicly available PCAP files**.

The objective is not simply to identify an attack from a provided answer or write a generic Wireshark tutorial. The goal is to practice the actual investigation process a SOC analyst would follow when presented with suspicious network traffic.

---

## 🎯 Challenge Objective

The challenge is to investigate **one attack scenario at a time**, using network traffic captured in publicly available PCAP datasets.

For each investigation, the objective is to answer:

- What happened?
- Which host was involved?
- What traffic was suspicious?
- What evidence supports the hypothesis?
- How can the attack be confirmed or rejected?
- What Indicators of Compromise (IOCs) can be extracted?
- What would a SOC analyst do in response?

The emphasis is on **evidence-based investigation rather than assumption-driven analysis**.

---

# 🔎 Investigation Philosophy

The core principle of this series is:

> **Don't force the hypothesis. Follow the evidence.**

A suspicious packet does not automatically mean an attack.

For example:

- High packet volume ≠ malicious activity
- SYN packets ≠ automatically a port scan
- HTTP traffic ≠ automatically malicious
- External IP ≠ automatically malicious
- Suspicious domain ≠ automatically compromised host

The investigation should progressively build evidence before reaching a conclusion.

---

# 🧭 Investigation Workflow

Each case follows a structured SOC investigation methodology:

```text
Public PCAP
    │
    ▼
Initial Traffic Review
    │
    ▼
Identify Hosts & Protocols
    │
    ▼
Establish Normal Traffic Baseline
    │
    ▼
Form Initial Hypothesis
    │
    ▼
Filter Suspicious Traffic
    │
    ▼
Protocol / Application Analysis
    │
    ▼
Follow TCP / HTTP Streams
    │
    ▼
Correlate Network Events
    │
    ▼
Extract IOCs
    │
    ▼
Build Attack Timeline
    │
    ▼
Confirm / Reject Hypothesis
    │
    ▼
Evidence-Based Conclusion
    │
    ▼
SOC Response Recommendations
