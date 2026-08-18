# Network Traffic Analysis Investigation — SOC Case Report

**Suspicious Infrastructure:** `mpzfprxfdn.serveftp.com` / `69.64.49.212`

The investigation focused entirely on network traffic analysis. Malware reverse engineering was intentionally outside the scope of this case.

---

## 1. Case Reference

- **Source:** Malware-Traffic-Analysis.net
- **Case:** 2015-02-24 — Helping out an inexperienced analyst
- **Case Link:** https://www.malware-traffic-analysis.net/2015/02/24/index.html

---

## 2. Investigation Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux |
| Analysis Tool | Wireshark |
| Evidence | `2015-02-24-traffic-analysis-exercise.pcap` |
| Internal Host | `10.10.100.139` |
| Total Packets | 9,950 |
| Main Protocols | TCP, HTTP, DNS |
| Investigation Focus | Network traffic and payload delivery |

---

## 3. Initial Network Observation

The first step was to understand the overall network traffic before making assumptions about malicious activity.

The PCAP contained approximately 9,950 packets and showed the internal host `10.10.100.139` communicating with numerous external systems.

Initial observations included:

- Multiple TCP connections
- TCP SYN packets
- TCP RST packets
- HTTP traffic
- HTTPS/TLS traffic
- DNS queries
- Communication with multiple external IP addresses

At first, the large number of TCP connections and SYN/RST packets appeared potentially consistent with reconnaissance or scanning activity. However, this hypothesis was not accepted immediately.

> A SOC analyst should not classify activity as malicious based only on packet counts, SYN packets, RST packets, or the number of external connections.

Further investigation was required.

---

## 4. Endpoint Analysis

Wireshark's `Statistics → Endpoints → IPv4` was used to identify the hosts communicating in the capture.

The primary internal workstation identified during the investigation was `10.10.100.139`. The endpoint statistics showed that this host was highly active in the capture.

**Figure 1** — IPv4 endpoint statistics from the PCAP (`Screenshot_2026-08-18_14_20_22.png`).

---

## 5. Establishing a Baseline with Legitimate Traffic

Before investigating suspicious connections, legitimate traffic was examined to establish a baseline.

One example was a Microsoft Network Connectivity Status Indicator (NCSI) request.

**Observed Traffic**

```
Source:            10.10.100.139
Destination:        2.16.162.26
Destination Port:   80

HTTP Request:  GET /ncsi.txt HTTP/1.1
Host:          www.msftncsi.com
User-Agent:    Microsoft NCSI

Response:      HTTP/1.1 200 OK
Content-Type:  text/plain
Body:          Microsoft NCSI
```

This behavior is consistent with a normal Microsoft connectivity check.

**Figure 2** — Legitimate Microsoft NCSI connectivity-check traffic observed in the PCAP.

**SOC Finding:** This traffic was classified as benign. This step was important because it prevented the investigation from incorrectly treating every external connection from the workstation as malicious.

---

## 6. Identifying Suspicious Infrastructure

Further investigation focused on HTTP traffic originating from `10.10.100.139`.

A suspicious external infrastructure was identified:

- **Internal Host:** `10.10.100.139`
- **Destination IP:** `69.64.49.212`
- **Domain:** `mpzfprxfdn.serveftp.com`

The host made HTTP requests to resources hosted on this infrastructure. One of the observed requests was:

```
GET /tdstest/1b346b77c2e9991535ede3925f5463e598/ HTTP/1.1
```

The traffic was isolated using a Wireshark filter similar to:

```
http contains "mpzfprxfdn.serveftp.com"
```

**Figure 3** — HTTP traffic between the internal workstation and suspicious infrastructure `69.64.49.212`.

---

## 7. HTTP Stream Investigation

The suspicious packets were investigated using: `Right Click Packet → Follow → HTTP Stream`.

This allowed the HTTP requests and responses to be reconstructed instead of analyzing individual packets independently.

The investigation revealed a sequence of HTTP requests:

```
10.10.100.139
      |
      v
69.64.49.212
      |
      v
mpzfprxfdn.serveftp.com
```

The HTTP traffic contained multiple suspicious resources and payload-delivery activity.

---

## 8. Suspicious Iframe

The initial website response contained a hidden iframe referencing:

```
http://mpzfprxfdn.serveftp.com/tdstest/1b346b77c2e9991535ede3925f5463e598/
```

The iframe caused the browser to communicate with a separate external infrastructure. This was an important indicator because the original website appeared legitimate, while the returned content redirected the browser toward another server.

**Important SOC Distinction**

The PCAP proves that the host requested the website and subsequently communicated with the iframe infrastructure. The PCAP does **not** independently prove that a human manually clicked the URL.

Therefore, the investigation uses:

- ✅ "The host accessed/requested the website"
- ❌ "The user clicked the malicious URL"

This distinction is important when writing professional incident reports.

---

## 9. Flash Payload Delivery

The suspicious infrastructure subsequently delivered a Flash object.

The HTTP response contained:

- **Filename:** `sigauyhf817.swf`
- **Content-Type:** `application/x-shockwave-flash`
- **Content-Length:** 10,451 bytes

The payload began with `CWS`, which is consistent with a compressed Flash SWF object.

**PCAP Evidence**

```
Content-Disposition: inline; filename=sigauyhf817.swf
Content-Length: 10451
Content-Type: application/x-shockwave-flash
```

*Screenshot availability: A dedicated screenshot of the SWF response headers was not captured during the investigation. The finding is retained as PCAP/HTTP-stream evidence.*

---

## 10. Java Web Start Payload Delivery

The same suspicious infrastructure was also observed delivering a Java Web Start payload.

The client used the following Java user agent:

```
Mozilla/4.0 (Windows 7 6.1) Java/1.7.0_09
```

The server returned:

```
HTTP/1.1 200 OK
Content-Disposition: inline; filename=IZpHm6dg.jnlp
Content-Length: 441
Content-Type: application/x-java-jnlp-file
```

The JNLP content referenced a JAR hosted by the same suspicious server, and specified `main-class="jabsh"`. The JNLP therefore provided instructions for retrieving a Java archive and specified a Java main class.

*Screenshot availability: A dedicated screenshot showing the complete JNLP response was not captured during the investigation. The finding is retained as PCAP/HTTP-stream evidence.*

---

## 11. Java JAR Payload Delivery

Following the JNLP request, the Java client requested the referenced JAR. The server returned:

```
HTTP/1.1 200 OK
Content-Disposition: inline; filename=fbigwamn05.jar
Content-Length: 7932
Content-Type: application/java-archive
```

The HTTP stream also exposed Java archive content including:

```
META-INF/MANIFEST.MF
jabsh.class
bulbo.class
dazes.class
mart38.class
rosae.class
jure9.class
```

This provides strong network evidence that a Java archive payload was delivered to the workstation.

**Figure 4** — HTTP response showing delivery of `fbigwamn05.jar` as a Java archive.

The screenshot visibly shows:

- Source: `69.64.49.212`
- Destination: `10.10.100.139`
- HTTP 200 OK
- Filename: `fbigwamn05.jar`
- Content-Length: 7932
- Content-Type: `application/java-archive`

---

## 12. Additional Payload Activity

The investigation also identified additional requests to the same suspicious infrastructure. One subsequent response contained:

- **Content-Type:** `application/octet-stream`
- **Content-Length:** 182,528 bytes

This was treated as potential subsequent-stage payload activity. No attempt was made to execute or reverse engineer this payload because the objective of this case was network traffic investigation rather than malware analysis.

---

## 13. Investigation Timeline

```
04:05:00
    |
    +-- Legitimate Microsoft NCSI connectivity check
    |
    v
04:06:15
    |
    +-- Suspicious web infrastructure
    |
    +-- Hidden iframe / redirected traffic
    |
    +-- Flash SWF delivered
    |
    v
04:06:56
    |
    +-- Java Web Start (JNLP) delivered
    |
    +-- JNLP references Java JAR
    |
    v
04:06:56 - 04:06:57
    |
    +-- fbigwamn05.jar downloaded
    |
    v
Subsequent traffic
    |
    +-- Additional binary payload requested
```

---

## 14. Indicators of Compromise / Investigation Artifacts

| Indicator | Value |
|---|---|
| Internal Host | `10.10.100.139` |
| Suspicious Domain | `mpzfprxfdn.serveftp.com` |
| Suspicious IP | `69.64.49.212` |
| Suspicious URI | `/tdstest/1b346b77c2e9991535ede3925f5463e598/` |
| Flash Payload | `sigauyhf817.swf` (10,451 bytes, `application/x-shockwave-flash`) |
| Java Web Start Payload | `IZpHm6dg.jnlp` (`application/x-java-jnlp-file`) |
| Java Archive | `fbigwamn05.jar` (7,932 bytes, `application/java-archive`) |
| Java Main Class | `jabsh` |

---

## 15. Evidence Classification

| Observation | Classification | Reason |
|---|---|---|
| Microsoft NCSI request | Benign | Consistent with connectivity-check behavior |
| Google/web traffic | Benign/Unconfirmed | Normal web browsing can generate similar traffic |
| Multiple SYN/RST packets | Suspicious but insufficient | Does not independently prove scanning |
| Hidden iframe | Suspicious | Redirects browser toward separate infrastructure |
| mpzfprxfdn.serveftp.com | Highly Suspicious | Associated with payload-delivery activity |
| 69.64.49.212 | Highly Suspicious | Hosted suspicious payload-delivery traffic |
| SWF download | Suspicious | Flash content delivered through suspicious infrastructure |
| JNLP download | Highly Suspicious | Java Web Start payload delivery |
| JAR download | Highly Suspicious | Java archive delivered after JNLP |
| Additional binary | Suspicious | Subsequent payload-like network transfer |

---

## 16. Final Assessment

**Verdict:** High-confidence suspicious/malicious web-based payload delivery.

The network evidence shows a coherent sequence:

```
Web request
     |
     v
Suspicious iframe
     |
     v
External payload-delivery infrastructure
     |
     +------> Flash SWF
     |
     +------> Java Web Start JNLP
                    |
                    v
                 Java JAR
                    |
                    v
             Additional binary
```

The strongest evidence is the combination of:

- Suspicious iframe redirection
- Communication with `mpzfprxfdn.serveftp.com`
- Flash SWF delivery
- Java Web Start JNLP delivery
- JNLP reference to a JAR
- Subsequent JAR download

This is substantially stronger evidence than simply observing multiple external TCP connections.

---

## 17. What the PCAP Proves

**Confirmed**

- `10.10.100.139` communicated with suspicious infrastructure.
- The host accessed suspicious HTTP resources.
- A Flash SWF was delivered.
- A Java Web Start JNLP file was delivered.
- The JNLP referenced a JAR.
- `fbigwamn05.jar` was downloaded.
- Additional binary payload traffic followed.

**Not Confirmed by Network Traffic Alone**

- A human definitely clicked the URL.
- The SWF definitely executed.
- The JAR definitely executed.
- The endpoint was successfully compromised.
- Persistence was established.
- Data was exfiltrated.

Those conclusions would require endpoint telemetry, malware analysis, or additional forensic evidence.

---

## 18. Recommended SOC Response

1. Isolate `10.10.100.139`.
2. Preserve the PCAP and relevant network evidence.
3. Block the identified suspicious infrastructure.
4. Search the environment for connections to `mpzfprxfdn.serveftp.com`.
5. Search the environment for connections to `69.64.49.212`.
6. Search endpoint telemetry for Java or JNLP execution.
7. Search endpoint telemetry for Flash execution.
8. Search for the filenames `IZpHm6dg.jnlp` and `fbigwamn05.jar`.
9. Determine whether other hosts received the same payloads.
10. Perform endpoint malware analysis if execution is suspected.
11. Escalate the incident based on endpoint findings.

---

## 19. Wireshark Techniques Practiced

| Technique | Filter / Path |
|---|---|
| Endpoint Analysis | `Statistics → Endpoints → IPv4` |
| Protocol Analysis | `Statistics → Protocol Hierarchy` |
| HTTP Filtering | `http` |
| HTTP Request Filtering | `http.request` |
| Suspicious Domain Filtering | `http contains "mpzfprxfdn.serveftp.com"` |
| TCP Filtering | `tcp` |
| HTTP Stream Reconstruction | Right Click Packet → Follow → HTTP Stream |

**Investigation Methodology**

```
Observe
   ↓
Form Hypothesis
   ↓
Collect Evidence
   ↓
Test Hypothesis
   ↓
Reject False Positives
   ↓
Follow Suspicious Traffic
   ↓
Reconstruct Attack Chain
   ↓
Make Evidence-Based Conclusion
```

---

## 20. Lessons Learned

1. **External traffic is not automatically malicious** — Microsoft NCSI traffic demonstrated that legitimate applications can generate external HTTP connections.
2. **SYN/RST activity is not enough to prove a port scan** — TCP behavior must be interpreted in context.
3. **Packet count is not an IOC** — A high number of packets can be useful for prioritizing investigation, but packet volume alone does not prove malicious activity.
4. **Follow the traffic instead of forcing the hypothesis** — The initial scan hypothesis was weakened after legitimate web traffic was identified, and the investigation shifted toward application-layer analysis.
5. **HTTP streams provide context** — Reconstructing an HTTP stream makes it possible to understand the sequence: Request → Response → Redirect → Payload → Subsequent Request.
6. **SOC conclusions must be evidence-bounded** — The PCAP provides strong evidence of suspicious payload delivery. It does not independently prove successful code execution or complete endpoint compromise.

---

## 21. Screenshots Included

| Screenshot | Description |
|---|---|
| `Screenshot_2026-08-18_14_20_00.png` | Wireshark packet overview showing the captured traffic |
| `Screenshot_2026-08-18_14_20_22.png` | IPv4 endpoint statistics |
| `Screenshot_2026-08-18_14_21_54.png` | Microsoft NCSI HTTP request |
| `Screenshot_2026-08-18_14_22_23.png` | HTTP traffic filtered for the suspicious infrastructure |
| `Screenshot_2026-08-18_14_27_03.png` | HTTP response showing delivery of `fbigwamn05.jar` |

---

## 22. Case Reference

- **Source:** Malware-Traffic-Analysis.net
- **Case:** 2015-02-24 — Helping out an inexperienced analyst
- **Case Link:** https://www.malware-traffic-analysis.net/2015/02/24/index.html

---

## 23. Final SOC Takeaway

The most important lesson from this investigation was not identifying a specific malware family. The key skill was learning how to investigate network traffic systematically:

```
Do not assume
      ↓
Observe the traffic
      ↓
Establish a baseline
      ↓
Identify anomalies
      ↓
Follow the suspicious connection
      ↓
Inspect the application layer
      ↓
Correlate multiple events
      ↓
Build the timeline
      ↓
Separate confirmed evidence from assumptions
      ↓
Make an evidence-based SOC conclusion
```

This investigation demonstrates the ability to use Wireshark for practical network investigation rather than simply knowing packet filters.
