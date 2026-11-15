# Automated PCAP Forensics Analyzer

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Engine-Scapy%20%2B%20dpkt-0ea5e9?style=for-the-badge)](https://scapy.net/)
[![Rich CLI](https://img.shields.io/badge/CLI-Rich%20TUI-a855f7?style=for-the-badge)](https://github.com/Textualize/rich)
[![Jinja2 Reports](https://img.shields.io/badge/Reports-JSON%20%7C%20MD%20%7C%20HTML-10b981?style=for-the-badge)](https://jinja.palletsprojects.com/)
[![Docker Ready](https://img.shields.io/badge/Docker-Non--Root%20Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)](pyproject.toml)

A production-grade, memory-safe Digital Forensics & Incident Response (DFIR) command-line tool that streams `.pcap` and `.pcapng` packet captures sequentially from disk, reconstructs bidirectional network sessions, recovers cleartext credentials and artifacts, detects DNS DGA & tunneling anomalies, carves transferred HTTP objects with cryptographic hashes and magic-byte MIME verification, correlates local Threat Intelligence watchlists, and exports standalone **JSON**, **Markdown**, and **dark-mode HTML** investigation reports.

---

## Architecture & Streaming Forensics Pipeline

```text
                        ┌───────────────────────────────────────┐
                        │   .pcap / .pcapng Capture Evidence    │
                        │  (Streamed via scapy.utils.PcapReader)│
                        └───────────────────┬───────────────────┘
                                            │ Sequential Packet Stream (O(1) RAM per packet)
                                            ▼
                        ┌───────────────────────────────────────┐
                        │     Core Ingestion Engine (core/)     │
                        │  • Chain-of-custody MD5 / SHA-256     │
                        │  • Bidirectional flow aggregator      │
                        │  • Protocol stats & Top Talkers       │
                        │  • TLS ClientHello SNI extraction     │
                        └───────────────────┬───────────────────┘
                                            │ Ephemeral PacketContext Dispatch
            ┌───────────────────────────────┼───────────────────────────────┐
            ▼                               ▼                               ▼
┌───────────────────────┐     ┌──────────────────────────┐    ┌──────────────────────────┐
│  Cleartext Analyzer   │     │   DNS Forensics Engine   │    │  HTTP Stream Carver &    │
│ analyzers/cleartext.py│     │analyzers/dns_forensics.py│    │  Threat Intel Matcher    │
│ • HTTP methods/URIs   │     │ • Passive DNS (A/AAAA/   │    │   analyzers/carver.py    │
│ • Base64 Basic Auth   │     │   CNAME/TXT) via dpkt    │    │ • Seq-ordered TCP stream │
│ • POST form/JSON creds│     │ • Shannon Entropy (DGA)  │    │   reassembly (200 OK)    │
│ • FTP USER/PASS/RETR  │     │ • Long-label & TXT/NULL  │    │ • Chunked & GZIP decode  │
│ • SMTP envelope/hdrs  │     │   tunneling detection    │    │ • Magic-byte MIME +      │
│ • Telnet IAC-stripped │     │ • Per-host NXDOMAIN rate │    │   spoofing detection     │
└───────────┬───────────┘     └────────────┬─────────────┘    │ • MD5/SHA-256 quarantine │
            │                              │                  │ • data/iocs.json matcher │
            └──────────────────────────────┼──────────────────┴────────────┬─────────────┘
                                           ▼                               │
                        ┌───────────────────────────────────────┐          │
                        │   Unified Risk Scoring, Findings &    │◄─────────┘
                        │     Chronological Incident Timeline   │
                        └───────────────────┬───────────────────┘
                                            │
            ┌───────────────────────────────┼───────────────────────────────┐
            ▼                               ▼                               ▼
  ┌───────────────────┐         ┌───────────────────────┐       ┌───────────────────────┐
  │ Rich Terminal UI  │         │  JSON & Markdown      │       │ Standalone Dark-Mode  │
  │ Real-time progress│         │  Investigation Reports│       │ HTML DFIR Dashboard   │
  │ & triage tables   │         │  (SIEM / Git-ready)   │       │ (Offline, XSS-safe)   │
  └───────────────────┘         └───────────────────────┘       └───────────────────────┘
```

---

## Key Capabilities

| Module | Capabilities |
| :--- | :--- |
| **Streaming Ingestion & Flows** (`core/engine.py`) | Memory-safe packet streaming via `scapy.utils.PcapReader` (natively supports both `.pcap` and `.pcapng`), chain-of-custody MD5/SHA-256 file hashing, bidirectional flow aggregation, protocol distribution (`TCP`, `UDP`, `ICMP`, `ARP`, `DNS`, `HTTP`, `TLS`), top talkers, and TLS ClientHello SNI extraction via `dpkt.ssl`. |
| **Cleartext Forensics** (`analyzers/cleartext.py`) | Parses HTTP requests via `dpkt.http.Request` (methods, hosts, URIs, `User-Agent`, Base64-decoded `Authorization: Basic`, `Bearer` tokens, URL-encoded & JSON `POST` credentials, suspicious URI heuristics), FTP control commands & `USER`/`PASS`/`RETR`/`STOR`, SMTP `MAIL FROM`/`RCPT TO`/`DATA` RFC-5322 email headers & `AUTH`, and Telnet IAC-stripped interactive sessions & credentials. |
| **DNS Forensics** (`analyzers/dns_forensics.py`) | Parses UDP and TCP DNS via `dpkt.dns.DNS`, builds a Passive DNS table (`A`, `AAAA`, `CNAME`, `TXT`), calculates label **Shannon Entropy** ($H = -\sum p_i \log_2 p_i$) to flag DGA domains, detects abnormally long encoded tunneling labels, flags high `TXT`/`NULL` query volumes and subdomain cardinality bursts, and computes per-host `NXDOMAIN` failure rates. |
| **HTTP Carving & Threat Intel** (`analyzers/carver.py`) | Sequence-ordered, memory-bounded TCP stream reassembler handling out-of-order segments, retransmissions, `Transfer-Encoding: chunked`, and `Content-Encoding: gzip/deflate`. Computes `MD5`/`SHA-256`, detects true **magic-byte MIME types** (PE/ELF/Mach-O/PDF/ZIP/OOXML/PNG/PowerShell/Bash/etc.), flags **MIME masquerading**, quarantines carved payloads as read-only non-executable (`0444`), and matches IPs/CIDRs, domains/subdomains, URLs, User-Agents, and file hashes against `data/iocs.json`. |
| **Multi-Format Reporting** (`reporters/report_builder.py`) | Exports machine-readable **JSON**, structured **Markdown**, and a **100% offline standalone dark-mode HTML dashboard** (Jinja2 autoescaped to prevent stored XSS from malicious PCAP payloads, featuring live search, severity filters, SVG risk gauge, and one-click IoC/hash copy). |

---

## Quick Start

### 1. Local Installation

```bash
git clone https://github.com/laithfarhat-cell/Automated-PCAP-Forensics-Analyzer.git
cd Automated-PCAP-Forensics-Analyzer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# Optional: install editable CLI entry point (`pcap-forensics`)
pip install -e .
```

### 2. Generate a Synthetic Multi-Stage Incident PCAP

Test every analyzer immediately without needing external captures:

```bash
python scripts/generate_sample_pcap.py -o samples/sample_incident.pcap
```

This creates a deterministic, benign synthetic capture containing ARP/ICMP baseline, TLS SNI beaconing, HTTP Basic Auth & POST credential theft, an out-of-order PE dropper masqueraded as `image/png`, a chunked PowerShell script, a gzipped PDF, FTP file retrieval, SMTP email exfiltration, Telnet commands, high-entropy DNS DGA `NXDOMAIN` bursts, and DNS `TXT` tunneling.

### 3. Run the Forensics Analyzer

```bash
python main.py \
  -f samples/sample_incident.pcap \
  --ioc data/iocs.json \
  --extract-files \
  -oJ -oM -oH \
  --output-dir ./forensics_output
```

Or using the shorthand `-oA` (all formats) and installed console script:

```bash
pcap-forensics -f samples/sample_incident.pcap --extract-files -oA --output-dir ./case_001
```

### 4. Docker Execution (Non-Root Isolated Container)

```bash
docker build -t pcap-forensics-analyzer .

docker run --rm \
  -v "$(pwd)/samples:/captures:ro" \
  -v "$(pwd)/forensics_output:/output" \
  pcap-forensics-analyzer \
  -f /captures/sample_incident.pcap \
  --ioc /app/data/iocs.json \
  --extract-files -oA \
  --output-dir /output
```

---

## CLI Reference

| Flag | Long Option | Default | Description |
| :--- | :--- | :--- | :--- |
| `-f` | `--file <CAPTURE>` | *(required)* | Input `.pcap` or `.pcapng` packet capture file. |
| | `--ioc <IOC_JSON>` | `data/iocs.json` | Local Threat Intelligence watchlist JSON (auto-loaded if present). |
| | `--no-ioc` | `False` | Disable watchlist matching even when `data/iocs.json` exists. |
| | `--extract-files` | `False` | Save carved HTTP `200 OK` payloads into `<output-dir>/extracted_artifacts/` with read-only non-executable `0444` permissions. |
| `-oJ` | `--json [PATH]` | `None` | Export JSON report (optional custom path; defaults to `<output-dir>/<stem>_report.json`). |
| `-oM` | `--markdown [PATH]` | `None` | Export Markdown report (optional custom path; defaults to `<output-dir>/<stem>_report.md`). |
| `-oH` | `--html [PATH]` | `None` | Export standalone dark-mode HTML dashboard (defaults to `<output-dir>/<stem>_report.html`). |
| `-oA` | `--all` | `False` | Export JSON, Markdown, and HTML reports into `--output-dir`. |
| | `--output-dir <DIR>` | `forensics_output` | Directory for generated reports and `extracted_artifacts/`. |
| | `--entropy-threshold` | `3.5` | Shannon entropy threshold (bits) for flagging DGA domain labels. |
| | `--max-stream-mb` | `25` | Per-stream TCP reassembly buffer cap in MB for memory safety. |
| | `--fail-on-critical` | `False` | Exit with status code `2` if any `CRITICAL` finding is detected (for CI/SOAR pipelines). |
| `-v` | `--verbose` | `False` | Show extended terminal tables (more findings + passive DNS preview). |
| `-q` | `--quiet` | `False` | Suppress terminal output while writing requested report files. |
| | `--no-color` | `False` | Disable ANSI colors in CLI output. |
| | `--version` | — | Print analyzer version and exit. |

---

## Threat Intelligence Watchlist Schema (`data/iocs.json`)

The matcher supports both rich structured entries (with MITRE ATT&CK mappings, severity, tags, and CIDR ranges) and simple indicator string lists:

```json
{
  "schema_version": "1.0.0",
  "malicious_ips": [
    {
      "ip": "198.51.100.42",
      "severity": "CRITICAL",
      "threat_type": "Command & Control (C2) Server",
      "source": "Internal DFIR Watchlist",
      "mitre_attack": ["T1071.001", "T1573"]
    },
    {
      "cidr": "198.51.100.128/25",
      "severity": "MEDIUM",
      "threat_type": "Bulletproof Hosting Range"
    }
  ],
  "malicious_domains": [
    {
      "domain": "malicious-c2.example",
      "severity": "CRITICAL",
      "threat_type": "Adversary C2 Infrastructure",
      "mitre_attack": ["T1071.001", "T1041"]
    }
  ],
  "malicious_hashes": [
    {
      "md5": "e02c395e05c24d8efb4a91aa5110fbec",
      "sha256": "c094389fb726101109311b34a1108283b40aa0b95c5a72285e1bead5071df5f6",
      "severity": "CRITICAL",
      "threat_type": "Known Synthetic PE Dropper",
      "mitre_attack": ["T1105", "T1036.005"]
    }
  ],
  "suspicious_user_agents": [
    {
      "pattern": "EvilBot/1.0",
      "severity": "HIGH",
      "threat_type": "Known Malicious HTTP Automation Agent"
    }
  ]
}
```

---

## Sample Output Preview

### Terminal Triage Output (`rich`)

```text
╭───────────────── AUTOMATED PCAP FORENSICS ANALYZER  v1.0.0 ──────────────────╮
│  Target: samples/sample_incident.pcap  |  IoC Watchlist: data/iocs.json  |   │
│  File Carving: Disk Quarantine ON                                            │
╰──────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────── Executive Forensics Summary ─────────────────────────╮
│         Verdict:   CRITICAL (100/100)   Analysis Time:   0.07s               │
│        Packets /   132 pkts (15.43 KB)  Flows / Hosts:   29 flows / 9 IPs    │
│  Capture Window:   2026-11-15 18:00:00  Format / Size:   PCAP (17.52 KB)     │
│        SHA-256:    5553456177506aef…    Severity Tally:  CRIT:15 HIGH:34     │
╰──────────────────────────────────────────────────────────────────────────────╯

                             Protocol Distribution
  Protocol     Packets     Share   Distribution                    Byte Volume
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  TCP               84     63.6%   █████████████░░░░░░░                8.92 KB
  UDP               40     30.3%   ██████░░░░░░░░░░░░░░                6.05 KB
  ICMP               6      4.5%   █░░░░░░░░░░░░░░░░░░░                  390 B
  ARP                2      1.5%   ░░░░░░░░░░░░░░░░░░░░                   84 B
  DNS               40     30.3%   ██████░░░░░░░░░░░░░░                6.05 KB
  HTTP              13      9.8%   ██░░░░░░░░░░░░░░░░░░                4.05 KB
  TLS                2      1.5%   ░░░░░░░░░░░░░░░░░░░░                  206 B

                      Recovered Cleartext Credentials (4)
  Protocol     Source -> Destination        Username     Password / Token
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  HTTP-Basic   10.10.20.15 -> 198.51.100.42 admin        SuperSecret123!
  HTTP-POST    10.10.20.15 -> 198.51.100.42 jdoe         Winter2026!
  FTP          10.10.20.15 -> 10.10.20.21   backup_svc   ExfilPass!2026
  Telnet       10.10.20.22 -> 10.10.20.1    root         toor2026!

                         Carved HTTP 200 OK Objects (4)
  ID         Filename              Size   Declared -> Magic MIME
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ART-0001   export.json           27 B   application/json -> application/json
  ART-0002   update_patch.exe   1.42 KB   image/png -> application/x-dosexec [MISMATCH]
  ART-0003   stage2.ps1           242 B   text/plain -> text/x-powershell
  ART-0004   invoice_2026.pdf     232 B   application/pdf -> application/pdf
```

### Markdown Report Excerpt

```markdown
## 8. Carved HTTP Objects & File Hashes

| ID | Filename | Size | Declared Content-Type | Magic-Byte MIME | Mismatch | MD5 | SHA-256 |
| :--- | :--- | ---: | :--- | :--- | :---: | :--- | :--- |
| `ART-0002` | `update_patch.exe` | 1.42 KB | `image/png` | `application/x-dosexec` | **YES** | `e02c395e...` | `c094389f...` |
| `ART-0003` | `stage2.ps1` | 242 B | `text/plain` | `text/x-powershell` | No | `1c8e...` | `074b9cfd...` |
| `ART-0004` | `invoice_2026.pdf` | 232 B | `application/pdf` | `application/pdf` | No | `9b2a...` | `3f368bc3...` |
```

---

## Security & Memory-Safety Design

- **Zero `rdpcap` Loading**: Streams packets sequentially via `scapy.utils.PcapReader` / `PcapNgReader`, immediately discarding raw Scapy packet objects after extracting an ephemeral `PacketContext`.
- **Bounded Reassembly & Decompression Caps**: Per-stream TCP reassembly buffers (`--max-stream-mb`) and `gzip`/`deflate` decompression ceilings (50 MB) prevent OOM and zip-bomb denial of service on hostile or multi-gigabyte captures.
- **Quarantined Non-Executable Carving**: Carved artifacts are strictly sanitized against directory traversal (`../../`), prefixed with their SHA-256 fingerprint, written solely inside `extracted_artifacts/`, and locked to mode `0444` (read-only, non-executable).
- **XSS-Safe Standalone HTML**: Jinja2 HTML autoescaping neutralizes `<script>` payloads injected inside hostile HTTP headers/URIs, and zero external CDN assets allow safe offline analysis in air-gapped DFIR labs.

---

## Project Layout

```text
Automated-PCAP-Forensics-Analyzer/
├── main.py                         # Argparse CLI entry point & Rich terminal dashboard
├── core/
│   ├── __init__.py
│   ├── engine.py                   # Streaming PcapReader engine, flow & metadata aggregator
│   └── models.py                   # Canonical DFIR dataclasses & formatters
├── analyzers/
│   ├── __init__.py
│   ├── cleartext.py                # HTTP, FTP, SMTP, and Telnet forensic parser
│   ├── dns_forensics.py            # Passive DNS, Shannon entropy DGA, tunneling & NXDOMAIN
│   └── carver.py                   # TCP stream HTTP object carver, magic MIME & Threat Intel
├── reporters/
│   ├── __init__.py
│   ├── report_builder.py           # JSON, Markdown, and HTML report generator
│   └── templates/
│       ├── report.html.j2          # Standalone dark-mode interactive HTML dashboard
│       └── report.md.j2            # Structured GitHub-flavored Markdown template
├── data/
│   └── iocs.json                   # Configurable Threat Intelligence watchlist
├── scripts/
│   └── generate_sample_pcap.py     # Synthetic multi-stage incident PCAP/PCAPNG generator
├── tests/
│   └── test_analyzer.py            # Unit & end-to-end pytest verification suite
├── pyproject.toml
├── requirements.txt
├── Dockerfile
├── .gitignore
└── README.md
```

---

## Running Tests

```bash
pytest
```

All tests verify streaming `.pcap` and `.pcapng` parity, cleartext credential recovery, Telnet IAC stripping, Shannon entropy calculations, DNS tunneling/DGA/NXDOMAIN detection, TCP DNS parsing, out-of-order HTTP carving, quarantine file permissions (`0444`), Threat Intel CIDR & subdomain matching, HTML XSS escaping, and CLI exit codes.
