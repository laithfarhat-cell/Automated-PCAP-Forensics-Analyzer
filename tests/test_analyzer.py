"""Comprehensive end-to-end and unit test suite for Automated PCAP Forensics Analyzer."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import struct
from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap, wrpcapng

import main as cli_main
from analyzers.carver import ThreatIntelMatcher, _sanitize_filename, detect_magic_mime, is_mime_mismatch
from analyzers.cleartext import strip_telnet_iac
from analyzers.dns_forensics import shannon_entropy
from core.engine import PcapEngine
from reporters.report_builder import ReportBuilder
from scripts.generate_sample_pcap import (
    SYNTHETIC_PDF_DOC,
    SYNTHETIC_PE_DROPPER,
    SYNTHETIC_PS1_SCRIPT,
    build_sample_packets,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IOCS = REPO_ROOT / "data" / "iocs.json"


@pytest.fixture(scope="module")
def sample_pcap(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("captures")
    pcap_path = d / "incident.pcap"
    wrpcap(str(pcap_path), build_sample_packets())
    return pcap_path


@pytest.fixture(scope="module")
def sample_pcapng(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("captures_ng")
    pcapng_path = d / "incident.pcapng"
    wrpcapng(str(pcapng_path), build_sample_packets())
    return pcapng_path


# ----------------------------------------------------------------------
# 1. Streaming PCAP & PCAPNG Ingestion + Flow Reconstruction
# ----------------------------------------------------------------------
def test_pcap_and_pcapng_streaming_ingestion(sample_pcap: Path, sample_pcapng: Path, tmp_path: Path) -> None:
    progress_calls: list[tuple[int, int, int]] = []

    engine_pcap = PcapEngine(
        pcap_path=sample_pcap,
        ioc_path=DEFAULT_IOCS,
        extract_files=True,
        extract_dir=tmp_path / "artifacts_pcap",
    )
    report_pcap = engine_pcap.analyze(
        progress_callback=lambda br, tb, pc: progress_calls.append((br, tb, pc)),
        progress_interval=25,
    )

    assert len(progress_calls) >= 2
    assert report_pcap.metadata.capture_format == "PCAP"
    assert report_pcap.metadata.total_packets == 132
    assert report_pcap.metadata.duration_seconds > 4.0
    assert len(report_pcap.metadata.file_sha256) == 64
    assert len(report_pcap.metadata.file_md5) == 32

    # All 7 required protocol buckets present with accurate non-zero counts
    pdist = report_pcap.metadata.protocol_distribution
    for proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS"):
        assert proto in pdist
        assert pdist[proto]["packets"] > 0

    # TLS SNI extracted cleanly
    assert "beacon.malicious-c2.example" in report_pcap.metadata.tls_snis

    # Bidirectional flow aggregation check
    assert report_pcap.metadata.total_flows > 0
    assert any(fl.src_to_dst_packets > 0 and fl.dst_to_src_packets > 0 for fl in report_pcap.flows)

    # PCAPNG streaming parity check
    engine_ng = PcapEngine(pcap_path=sample_pcapng, ioc_path=DEFAULT_IOCS, extract_files=False)
    report_ng = engine_ng.analyze()
    assert report_ng.metadata.capture_format == "PCAPNG"
    assert report_ng.metadata.total_packets == report_pcap.metadata.total_packets
    assert report_ng.metadata.total_flows == report_pcap.metadata.total_flows


# ----------------------------------------------------------------------
# 2. Cleartext Protocol Artifact Recovery (HTTP, FTP, SMTP, Telnet)
# ----------------------------------------------------------------------
def test_cleartext_artifact_recovery(sample_pcap: Path) -> None:
    report = PcapEngine(pcap_path=sample_pcap, ioc_path=DEFAULT_IOCS).analyze()

    # Credentials across HTTP-Basic, HTTP-POST, FTP, Telnet
    creds_by_proto = {c.protocol: c for c in report.credentials}
    assert "HTTP-Basic" in creds_by_proto
    assert creds_by_proto["HTTP-Basic"].username == "admin"
    assert creds_by_proto["HTTP-Basic"].password == "SuperSecret123!"

    assert "HTTP-POST" in creds_by_proto
    assert creds_by_proto["HTTP-POST"].username == "jdoe"
    assert creds_by_proto["HTTP-POST"].password == "Winter2026!"

    assert "FTP" in creds_by_proto
    assert creds_by_proto["FTP"].username == "backup_svc"
    assert creds_by_proto["FTP"].password == "ExfilPass!2026"

    assert "Telnet" in creds_by_proto
    assert creds_by_proto["Telnet"].username == "root"
    assert creds_by_proto["Telnet"].password == "toor2026!"

    # HTTP details
    assert len(report.http_artifacts) >= 5
    post_reqs = [h for h in report.http_artifacts if h.method == "POST"]
    assert post_reqs and post_reqs[0].post_params["role"] == ["domain_admin"]

    # FTP session commands & retrieved file
    assert len(report.ftp_sessions) == 1
    assert report.ftp_sessions[0].auth_status == "success"
    assert "RETR payroll_2026.csv" in report.ftp_sessions[0].transferred_files

    # SMTP envelope & headers
    assert len(report.smtp_sessions) == 1
    smtp = report.smtp_sessions[0]
    assert "finance@corp.example" in smtp.mail_from
    assert any("drop@malicious-c2.example" in r for r in smtp.rcpt_to)
    assert smtp.subject == "Q4 Payroll Export [CONFIDENTIAL]"

    # Telnet commands with IAC stripped
    assert len(report.telnet_sessions) == 1
    assert "whoami" in report.telnet_sessions[0].commands
    assert "cat /etc/passwd" in report.telnet_sessions[0].commands


def test_strip_telnet_iac() -> None:
    raw = b"\xff\xfd\x18\xff\xfb\x01hello\xff\xfa\x18\x00xterm\xff\xf0 world"
    assert strip_telnet_iac(raw) == b"hello world"


# ----------------------------------------------------------------------
# 3. DNS Forensics (Passive DNS, Shannon Entropy, DGA, Tunneling, NXDOMAIN)
# ----------------------------------------------------------------------
def test_shannon_entropy_math() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert abs(shannon_entropy("ab") - 1.0) < 1e-6
    assert shannon_entropy("xk9q2m8z7v4w1p6n") >= 3.8


def test_dns_forensics_detections(sample_pcap: Path) -> None:
    report = PcapEngine(pcap_path=sample_pcap, ioc_path=DEFAULT_IOCS).analyze()

    pdns_map = {r.domain: r for r in report.passive_dns}
    assert "c2.malicious-c2.example" in pdns_map
    assert "198.51.100.42" in pdns_map["c2.malicious-c2.example"].resolved_ips
    assert "cdn.corp.example" in pdns_map
    assert "edge.corp.example" in pdns_map["cdn.corp.example"].cnames
    assert "2001:db8::10" in pdns_map["edge.corp.example"].resolved_ips

    anomaly_types = {a.anomaly_type for a in report.dns_anomalies}
    assert "DGA_HIGH_ENTROPY" in anomaly_types
    assert "DNS_TUNNELING_LONG_LABEL" in anomaly_types
    assert "DNS_TUNNELING_TXT_NULL" in anomaly_types
    assert "DNS_TUNNELING_HIGH_SUBDOMAINS" in anomaly_types
    assert "HIGH_NXDOMAIN_RATE" in anomaly_types
    assert report.dns_stats["nxdomain_count"] == 8
    assert report.dns_stats["nxdomain_rate_pct"] >= 35.0


def test_tcp_dns_parsing(tmp_path: Path) -> None:
    dns_msg = bytes(
        DNS(
            id=0x5555,
            qr=1,
            rd=1,
            ra=1,
            rcode=0,
            qd=DNSQR(qname="tcp-only.corp.example", qtype="A"),
            an=[DNSRR(rrname="tcp-only.corp.example", type="A", rdata="192.0.2.55")],
        )
    )
    tcp_dns_payload = struct.pack("!H", len(dns_msg)) + dns_msg
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.53", dst="10.0.0.10")
        / TCP(sport=53, dport=45000, flags="PA", seq=100, ack=200)
        / Raw(load=tcp_dns_payload)
    )
    pcap_file = tmp_path / "tcp_dns.pcap"
    wrpcap(str(pcap_file), [pkt])
    report = PcapEngine(pcap_path=pcap_file).analyze()
    pdns = {r.domain: r for r in report.passive_dns}
    assert "tcp-only.corp.example" in pdns
    assert "192.0.2.55" in pdns["tcp-only.corp.example"].resolved_ips


# ----------------------------------------------------------------------
# 4. HTTP Object Carving, Magic Bytes, Quarantine Safety & Threat Intel
# ----------------------------------------------------------------------
def test_http_carving_and_quarantine_safety(sample_pcap: Path, tmp_path: Path) -> None:
    extract_dir = tmp_path / "extracted_artifacts"
    report = PcapEngine(
        pcap_path=sample_pcap,
        ioc_path=DEFAULT_IOCS,
        extract_files=True,
        extract_dir=extract_dir,
    ).analyze()

    by_name = {c.filename: c for c in report.carved_artifacts}
    assert "update_patch.exe" in by_name
    assert "stage2.ps1" in by_name
    assert "invoice_2026.pdf" in by_name

    # Out-of-order + retransmitted PE dropper carved with byte-for-byte identical hashes
    pe = by_name["update_patch.exe"]
    assert pe.sha256 == hashlib.sha256(SYNTHETIC_PE_DROPPER).hexdigest()
    assert pe.md5 == hashlib.md5(SYNTHETIC_PE_DROPPER).hexdigest()
    assert pe.detected_mime_type == "application/x-dosexec"
    assert pe.declared_content_type == "image/png"
    assert pe.mime_mismatch is True
    assert pe.is_executable is True
    assert pe.saved_path is not None

    # Verify quarantined file on disk is non-executable read-only (0o444)
    pe_disk = Path(pe.saved_path)
    assert pe_disk.is_file()
    assert pe_disk.read_bytes() == SYNTHETIC_PE_DROPPER
    mode = stat.S_IMODE(os.stat(pe_disk).st_mode)
    assert (mode & 0o111) == 0  # Strictly non-executable

    # Chunked PowerShell script
    ps1 = by_name["stage2.ps1"]
    assert ps1.sha256 == hashlib.sha256(SYNTHETIC_PS1_SCRIPT).hexdigest()
    assert ps1.detected_mime_type == "text/x-powershell"
    assert ps1.is_script is True

    # GZIP-decoded PDF
    pdf = by_name["invoice_2026.pdf"]
    assert pdf.sha256 == hashlib.sha256(SYNTHETIC_PDF_DOC).hexdigest()
    assert pdf.detected_mime_type == "application/pdf"
    assert pdf.mime_mismatch is False


def test_magic_mime_and_filename_sanitization() -> None:
    assert detect_magic_mime(b"\x7fELF\x02\x01").mime_type == "application/x-elf"
    assert detect_magic_mime(b"\x89PNG\r\n\x1a\n\x00").mime_type == "image/png"
    assert detect_magic_mime(b"#!/bin/bash\necho hi").mime_type == "text/x-shellscript"
    assert is_mime_mismatch("image/jpeg", "application/x-dosexec") is True
    assert is_mime_mismatch("application/pdf", "application/pdf") is False
    assert _sanitize_filename("../../../../etc/cron.d/evil.exe") == "evil.exe"


def test_threat_intel_matcher_cidr_and_subdomain(sample_pcap: Path) -> None:
    matcher = ThreatIntelMatcher(DEFAULT_IOCS)
    assert matcher.loaded is True
    matcher.check_ip("198.51.100.200", 1000.0, "CIDR range test")
    matcher.check_domain("deep.sub.malicious-c2.example", 1001.0, "Subdomain match test")
    matched = {(m.indicator_type, m.indicator) for m in matcher.matches}
    assert ("ip", "198.51.100.200") in matched
    assert ("domain", "deep.sub.malicious-c2.example") in matched

    # End-to-end sample PCAP watchlist correlation
    report = PcapEngine(pcap_path=sample_pcap, ioc_path=DEFAULT_IOCS).analyze()
    hit_types = {m.indicator_type for m in report.ioc_matches}
    assert {"ip", "domain", "md5", "sha256", "user_agent"}.issubset(hit_types)


# ----------------------------------------------------------------------
# 5. Multi-Format Reporting & XSS Autoescaping Security
# ----------------------------------------------------------------------
def test_reports_and_html_xss_escaping(tmp_path: Path) -> None:
    xss_payload = "<script>alert('pwned')</script>"
    http_req = (
        f"GET /search?q={xss_payload} HTTP/1.1\r\n"
        f"Host: victim.example\r\n"
        f"User-Agent: {xss_payload}\r\n\r\n"
    ).encode("utf-8")
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")
        / IP(src="10.0.0.5", dst="10.0.0.80")
        / TCP(sport=50000, dport=80, flags="PA", seq=1, ack=1)
        / Raw(load=http_req)
    )
    pcap_file = tmp_path / "xss.pcap"
    wrpcap(str(pcap_file), [pkt])

    report = PcapEngine(pcap_path=pcap_file).analyze()
    builder = ReportBuilder()

    json_path = builder.write_json(report, tmp_path / "out.json")
    md_path = builder.write_markdown(report, tmp_path / "out.md")
    html_path = builder.write_html(report, tmp_path / "out.html")

    parsed = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == "1.0.0"
    assert len(parsed["cleartext_artifacts"]["http_requests"]) == 1

    md_text = md_path.read_text(encoding="utf-8")
    assert "## 1. Executive Summary" in md_text
    assert "## 3. Incident Timeline" in md_text
    assert "## 8. Carved HTTP Objects & File Hashes" in md_text

    html_text = html_path.read_text(encoding="utf-8")
    # Unescaped script injection must NEVER appear in rendered HTML
    assert "<script>alert('pwned')</script>" not in html_text
    assert "&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;" in html_text
    # Standalone guarantee: zero external CDN stylesheet/script URLs
    assert "https://cdn" not in html_text
    assert "<link rel=\"stylesheet\" href=\"http" not in html_text


# ----------------------------------------------------------------------
# 6. CLI Interface End-to-End Tests
# ----------------------------------------------------------------------
def test_cli_end_to_end(sample_pcap: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "cli_out"
    rc = cli_main.main(
        [
            "-f",
            str(sample_pcap),
            "--ioc",
            str(DEFAULT_IOCS),
            "--extract-files",
            "-oJ",
            "-oM",
            "-oH",
            "--output-dir",
            str(out_dir),
            "--quiet",
        ]
    )
    assert rc == 0
    assert (out_dir / "incident_report.json").is_file()
    assert (out_dir / "incident_report.md").is_file()
    assert (out_dir / "incident_report.html").is_file()
    assert (out_dir / "extracted_artifacts").is_dir()
    assert len(list((out_dir / "extracted_artifacts").iterdir())) == 4

    # --fail-on-critical returns exit code 2 when CRITICAL findings exist
    rc_crit = cli_main.main(
        ["-f", str(sample_pcap), "--ioc", str(DEFAULT_IOCS), "--fail-on-critical", "--quiet"]
    )
    assert rc_crit == 2

    # Non-existent file returns exit code 1
    rc_missing = cli_main.main(["-f", str(tmp_path / "does_not_exist.pcap"), "--quiet"])
    assert rc_missing == 1
