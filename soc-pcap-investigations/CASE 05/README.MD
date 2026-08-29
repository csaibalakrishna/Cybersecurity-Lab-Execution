# Day 5 — DNS-Based Covert Command Channel Analysis

## 1. Executive Summary

A packet capture named `dns_convert_chan_client.pcapng` was investigated to determine whether the observed DNS traffic contained suspicious or covert activity.

The investigation identified repeated DNS TXT record queries involving `covertmessage2.research.net`. Multiple DNS responses contained Base64-encoded strings. Decoding these strings revealed command-like content, including file creation, DNS lookups, shell script execution, service status checks, and DNS configuration inspection.

The capture contains evidence consistent with a DNS-based covert command delivery channel, where DNS TXT records were used to transport encoded instructions.

However, the PCAP alone does not prove that the delivered commands were executed successfully on the endpoint. It provides evidence of command-like data being delivered through DNS responses.

---

## 2. Investigation Scope

| Field | Detail |
|---|---|
| **PCAP** | `dns_convert_chan_client.pcapng` |
| **Total Packets** | 1,026 |
| **Packets Matching DNS Filter** | 462 |

**Primary Internal Hosts**

| Host | Observed Role |
|---|---|
| `10.150.1.34` | DNS client / suspected receiving endpoint |
| `10.150.1.33` | DNS server responding to client requests |

**Additional observed external DNS-related addresses:**

- `91.189.91.98`
- `185.125.190.97`

These external addresses were observed in the capture but were not the primary focus of the covert-channel investigation.

---

## 3. Initial Network Observations

Endpoint statistics showed that the majority of traffic was exchanged between `10.150.1.34` and `10.150.1.33`.

The suspicious DNS communication pattern:

```
Client: 10.150.1.34
        ↓ DNS TXT Query

DNS Server: 10.150.1.33
        ↓ DNS TXT Response containing encoded data

Client: 10.150.1.34
```

The recurring queried domain was `covertmessage2.research.net`.

**Evidence**

![Wireshark Endpoints view](./Screenshot_2026-08-29_17_08_57.png)
*Screenshot_2026-08-29_17_08_57.png — Wireshark Endpoints view identifying the two hosts involved in the DNS communication*

---

## 4. DNS Traffic Analysis

Filters used to isolate suspicious traffic:

| Purpose | Filter |
|---|---|
| DNS traffic | `dns` |
| DNS traffic using port 53 | `dns && udp.port == 53` |
| DNS queries involving research.net | `dns.flags.response == 0 && dns.qry.name contains "research.net"` |
| DNS responses involving research.net | `dns.flags.response == 1 && dns.qry.name contains "research.net"` |

**Result:** 104 packets displayed for queries, 104 packets displayed for responses — a matching request-response pattern.

**Evidence**

![Filtered DNS traffic overview](./Screenshot_2026-08-29_17_09_07.png)
*Screenshot_2026-08-29_17_09_07.png — filtered DNS traffic overview, including repeated queries and responses involving research.net*

![DNS requests for research.net](./Screenshot_2026-08-29_17_09_20.png)
*Screenshot_2026-08-29_17_09_20.png — DNS traffic filtered for requests involving research.net*

![DNS responses for research.net](./Screenshot_2026-08-29_17_09_32.png)
*Screenshot_2026-08-29_17_09_32.png — filtered DNS response packets for research.net*

---

## 5. Suspicious DNS TXT Record Activity

The DNS client repeatedly requested TXT records associated with `covertmessage2.research.net`.

DNS TXT records are a legitimate record type, commonly used for:

- Domain verification
- Email security policies (SPF, DKIM)
- Service configuration

However, in this investigation, multiple TXT responses contained encoded data that decoded into command-like instructions — making the traffic suspicious because TXT records were apparently being used as a transport mechanism for encoded operational instructions.

---

## 6. Key Evidence

### Evidence 1 — DNS TXT Record Response

```
Frame 152
Source:            10.150.1.33
Destination:        10.150.1.34
Protocol:            DNS
Source Port:        53
Destination Port:   54461

Name: covertmessage2.research.net
Type: TXT
```

Returned TXT value:

```
dG91Y2ggL2hvbWUvc3R1ZGVudC9hcHJpbDE3LnR4dA==
```

After Base64 decoding:

```
touch /home/student/april17.txt
```

**Interpretation:** the returned data represents a Linux command intended to create a file named `april17.txt` at `/home/student/`.

**Evidence**

![DNS TXT response with encoded string](./Screenshot_2026-08-29_17_10_36.png)
*Screenshot_2026-08-29_17_10_36.png — specific DNS TXT response containing an encoded Base64 string*

---

## 7. Decoded DNS TXT Payloads

Multiple Base64-encoded TXT values were identified and decoded.

| Encoded TXT Data | Decoded Content |
|---|---|
| `dG91Y2ggL2hvbWUvc3R1ZGVudC9hcHJpbDE3LnR4dA==` | `touch /home/student/april17.txt` |
| `bnNsb29rdXAgOC44LjguOA==` | `nslookup 8.8.8.8` |
| `ZWNobyAnaGknID4gL2hvbWUvc3R1ZGVudC9hcHJpbDE3LnR4dA` | `echo 'hi' > /home/student/april17.txt` |
| `bnNsb29rdXAgcmVzZWFyY2gubmV0` | `nslookup research.net` |
| `YmFzaCAvaG9tZS9zdHVkZW50L3Rlc3Quc2g=` | `bash /home/student/test.sh` |
| `c3lzdGVtY3RsIHN0YXR1cyBjb3ZlcnRfY2hhbm5lbC5zZXJ2aWNl` | `systemctl status covert_channel.service` |
| `Y2F0IC9ldGMvcmVzb2x2LmNvbmY=` | `cat /etc/resolv.conf` |

**Evidence**

![Encoded to decoded mapping](./Screenshot_2026-08-29_17_13_15.png)
*Screenshot_2026-08-29_17_13_15.png — mapping of encoded DNS TXT strings to their decoded command values*

---

## 8. Analysis of Decoded Instructions

### 8.1 File Creation
```
touch /home/student/april17.txt
```
Would create an empty file named `april17.txt` at `/home/student/`.

### 8.2 File Content Modification
```
echo 'hi' > /home/student/april17.txt
```
Would write `hi` to `/home/student/april17.txt`.

### 8.3 DNS Lookup Activity
```
nslookup 8.8.8.8
nslookup research.net
```
Performs DNS lookups against `8.8.8.8` and `research.net`.

### 8.4 Shell Script Execution
```
bash /home/student/test.sh
```
Would attempt to execute `/home/student/test.sh`. The PCAP provides evidence this command-like instruction was delivered — it does **not** provide evidence the script actually executed.

### 8.5 Service Inspection
```
systemctl status covert_channel.service
```
Checks the status of `covert_channel.service`. The service name is notable because it explicitly references a potential covert channel. The PCAP alone cannot confirm whether the service was actually running on the endpoint.

### 8.6 DNS Configuration Inspection
```
cat /etc/resolv.conf
```
Would display the contents of `/etc/resolv.conf` — DNS resolver configuration on Linux systems.

---

## 9. Communication Pattern

```
10.150.1.34
    │
    │ DNS TXT Query
    │ covertmessage2.research.net
    ▼
10.150.1.33
    │
    │ DNS TXT Response
    │ Base64-encoded payload
    ▼
10.150.1.34
```

The repeated pattern consisted of: the client requesting DNS information → the DNS server returning a TXT response → the TXT record containing encoded data → the encoded data decoding into command-like instructions.

This pattern is inconsistent with ordinary hostname-to-IP resolution alone.

---

## 10. Why DNS Can Be Used for Command Delivery

A common misconception is that DNS is only used to convert domain names into IP addresses. DNS supports multiple record types:

- **A** — IPv4 addresses
- **AAAA** — IPv6 addresses
- **MX** — Mail servers
- **CNAME** — Domain aliases
- **NS** — Name servers
- **TXT** — Text data

A DNS TXT record can contain arbitrary textual information. A client-side program can retrieve and decode that data:

```
Client asks DNS server
        │
        ▼
"Do you have a TXT record for this domain?"
        │
        ▼
DNS server returns encoded text
        │
        ▼
Client-side program processes the returned data
```

This allows DNS infrastructure to potentially be abused as a covert communication channel.

---

## 11. Indicators of Suspicious Activity

**Network Indicators**

| Indicator | Value |
|---|---|
| Suspected DNS Client | `10.150.1.34` |
| DNS Server | `10.150.1.33` |
| Suspicious Domain | `covertmessage2.research.net` |
| DNS Record Type | TXT |
| Communication Protocol | DNS |
| DNS Port | 53 |
| Matching Queries | 104 |
| Matching Responses | 104 |

**Host-Level Artifacts Referenced in Payloads**

- `/home/student/april17.txt`
- `/home/student/test.sh`
- `/etc/resolv.conf`
- `covert_channel.service`

---

## 12. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol: DNS | [T1071.004](https://attack.mitre.org/techniques/T1071/004/) |
| Defense Evasion | Deobfuscate/Decode Files or Information | [T1140](https://attack.mitre.org/techniques/T1140/) |
| Execution | Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) |

- **T1071.004** — the communication channel uses DNS requests and responses to exchange data, consistent with using DNS as an application-layer C2 protocol.
- **T1140** — the returned data was Base64-encoded and required decoding before its command-like content became readable.
- **T1059** — several decoded payloads contain shell command syntax, including `touch`, `echo`, `bash`, `cat`, `systemctl`.

**Important evidence limitation:** these mappings describe the observed or inferred behavior represented by the network traffic. The PCAP does **not** independently prove successful command execution, successful shell script execution, creation or modification of the referenced file, existence or active execution of `covert_channel.service`, or endpoint compromise. The investigation should not claim confirmed endpoint execution based solely on this PCAP.

---

## 13. Investigation Timeline

```
1. Client initiates DNS query
           ↓
2. Query requests information associated with research.net
           ↓
3. DNS server returns a response
           ↓
4. TXT record contains encoded data
           ↓
5. Encoded data is Base64-decoded
           ↓
6. Decoded data contains command-like instructions
```

This sequence repeated across the observed DNS traffic.

---

## 14. Assessment

The evidence strongly supports the conclusion that the DNS traffic was being used to transport encoded command-like data. Characteristics that make the activity suspicious:

- Repeated DNS TXT queries (104 matching queries, 104 matching responses)
- Repeated communication between the same internal hosts
- Base64-encoded TXT payloads
- Decoded payloads containing Linux command syntax
- References to a shell script and a service explicitly named `covert_channel.service`
- Repeated operational instructions delivered through DNS responses

**Assessment:** the analyzed PCAP contains evidence consistent with a DNS-based covert command delivery mechanism. DNS TXT responses were used to transmit Base64-encoded data that decoded into Linux command-like instructions. While the network evidence confirms delivery of these payloads to the DNS client, successful execution of the commands cannot be confirmed without endpoint telemetry or additional host-based evidence.

---

## 15. Final Conclusion

The investigation identified suspicious DNS activity between `10.150.1.34` and `10.150.1.33`. Repeated DNS TXT queries to `covertmessage2.research.net` resulted in DNS responses containing Base64-encoded values. Decoding these values revealed command-like instructions involving file creation, file modification, DNS lookups, shell script execution, service status inspection, and DNS configuration inspection.

The overall traffic pattern is consistent with a DNS-based covert command channel or simulated DNS command-and-control mechanism.

The network evidence confirms command-like payload delivery through DNS TXT records, but does not independently confirm execution or successful endpoint compromise.

---

## 16. Recommended Defensive Actions

1. Investigate systems generating unusually frequent DNS TXT queries.
2. Monitor DNS responses containing encoded or high-entropy TXT data.
3. Review repeated queries to unusual or internally controlled domains.
4. Correlate DNS activity with endpoint process execution.
5. Inspect DNS clients for processes repeatedly querying TXT records.
6. Review the referenced artifacts: `/home/student/april17.txt`, `/home/student/test.sh`, `/etc/resolv.conf`, `covert_channel.service`.
7. Add DNS telemetry to SIEM detection rules for repeated TXT-record activity.
8. Correlate suspicious DNS traffic with endpoint logs before declaring command execution or compromise.

---

## 17. Analyst Verdict

| Field | Assessment |
|---|---|
| **Severity** | Medium to High, depending on endpoint confirmation |
| **Confidence in DNS-based command delivery** | High |
| **Confidence in command execution** | Not confirmed from PCAP alone |
| **Recommended Next Step** | Endpoint investigation and correlation with host telemetry |

---

## Evidence

| # | Screenshot | Content |
|---|---|---|
| 1 | `Screenshot_2026-08-29_17_08_57.png` | Wireshark Endpoints view — the two hosts involved |
| 2 | `Screenshot_2026-08-29_17_09_07.png` | Filtered DNS traffic overview |
| 3 | `Screenshot_2026-08-29_17_09_20.png` | DNS requests filtered for research.net |
| 4 | `Screenshot_2026-08-29_17_09_32.png` | DNS responses filtered for research.net |
| 5 | `Screenshot_2026-08-29_17_10_36.png` | DNS TXT response with encoded Base64 string |
| 6 | `Screenshot_2026-08-29_17_13_15.png` | Encoded-to-decoded TXT string mapping

---

## Folder Structure

```
day05-dns-covert-channel/
├── README.md
├── Screenshot_2026-08-29_17_08_57.png
├── Screenshot_2026-08-29_17_09_07.png
├── Screenshot_2026-08-29_17_09_20.png
├── Screenshot_2026-08-29_17_09_32.png
├── Screenshot_2026-08-29_17_10_36.png
└── Screenshot_2026-08-29_17_13_15.png

---

## PCAP Source

**Source:** [RIT Repository — Dataset 2](https://repository.rit.edu/data/2/)

---

## Disclaimer

This investigation was performed using a publicly available network traffic capture for cybersecurity education and defensive security training. The conclusions documented here are limited to the network evidence available in the PCAP and do not confirm endpoint execution or compromise.
