# Cybersecurity Lab

Network traffic analysis labs using **Wireshark** and **Python (Pyshark)** — packet capturing, protocol analysis, and traffic-pattern detection.

## What is Wireshark?

[Wireshark](https://www.wireshark.org/) is a free, open-source network protocol analyzer. It captures packets traveling across a network interface in real time and lets you inspect them down to the byte level — headers, payloads, flags, timing, everything. It's one of the standard tools for network troubleshooting, protocol learning, and security analysis.

**Typical workflow:**
1. Pick a network interface (Wi-Fi, Ethernet).
2. Start capturing — Wireshark logs every packet crossing that interface.
3. Apply a **display filter** (e.g. `http`, `dns`, `arp`, `tcp.flags.syn == 1`) to narrow down what you're looking at.
4. Click into individual packets to see layer-by-layer breakdowns (Ethernet → IP → TCP/UDP → application protocol).
5. Stop the capture and optionally save it as a `.pcap` file for later analysis (including scripted analysis in Python, as done here).

## Lab Exercises (Wireshark)

| # | Exercise | What it covers |
|---|---|---|
| 1 | Capturing Network Traffic | Selecting an interface, starting/stopping a capture, generating traffic by browsing |
| 2 | Analyzing HTTP Traffic | Filtering with `http`, inspecting request/response headers (`User-Agent`, `Host`, `Accept`) |
| 3 | Identifying Network Issues | Using `tcp.analysis.flags` to spot retransmissions, out-of-order packets, and delays |
| 4 | Analyzing DNS Traffic | Filtering with `dns`, examining queries vs. responses, record types (A, AAAA), response codes |
| 5 | Understanding ARP Traffic | Filtering with `arp`, seeing how MAC addresses get resolved from IPs |
| 6 | Filter Deep-Dive | Systematic pass through filters — TCP/UDP/ICMP, ports (80/443), TCP flags (SYN/ACK), DNS, HTTP methods, retransmissions, packet length, MAC/IP ranges, DHCP, TLS handshakes/records |

Full write-up with steps and screenshots is in [`cybersecurity-lab .pdf`](./cybersecurity-lab%20.pdf).

## Python Scripts (Pyshark-based analysis)

These parse saved `.pcap` files programmatically instead of clicking through the Wireshark UI — same underlying data, scripted for repeatable analysis and summaries.

| Script | Purpose |
|---|---|
| `analyze_packets.py` | Basic packet inventory — number, length, highest protocol layer, summary info for every packet |
| `http_analysis.py` | Counts and logs HTTP, TCP, and IP packets separately with source/destination detail |
| `dns_analysis.py` / `dns_queries.py` | Splits DNS traffic into queries vs. responses and tallies each |
| `suspicious_traffic.py` | Flags destination IPs receiving an unusually high packet count (simple threshold-based anomaly detection) |
| `tcp_flow.py` | Reconstructs unique TCP flows (src IP, src port, dst IP, dst port) and reports packet count + total bytes per flow |
| `geolocation.py` | Extracts source IPs and resolves country/region/city via an IP geolocation API, tallying unique locations |
| `exp7.py`, `exp8.py` | Additional experiment scripts *(see PDF for exact exercise text)* |

### Requirements

\`\`\`bash
pip install pyshark
\`\`\`

Pyshark requires \`tshark\` (bundled with Wireshark) to be installed and on your \`PATH\`.

### Running a script

\`\`\`bash
python3 tcp_flow.py
\`\`\`

Each script reads a \`.pcap\` file (\`http_traffic.pcap\`, \`net.pcap\`, or \`dnsss.pcap\` — update the \`pcap_file\` variable in the script if needed) and prints its analysis to the terminal.

## Sample Captures

- \`http_traffic.pcap\` — general browsing traffic (HTTP, DNS, TCP)
- \`net.pcap\` — broader network capture used for TCP flow analysis
- \`dnsss.pcap\` — DNS-focused capture

## Notes

- All captures were made locally for learning purposes — no external network scanning was performed.
- Full lab documentation (objectives, steps, and Wireshark screenshots for each exercise) lives in the accompanying PDF.
