"""Memory-safe streaming PCAP/PCAPNG ingestion engine and forensic orchestrator.

Streams packets sequentially via ``scapy.utils.PcapReader`` (which natively handles both
``.pcap`` and ``.pcapng`` captures without loading captures into RAM), tracks bidirectional
network flows, computes capture metadata and protocol breakdowns, extracts TLS SNIs via
``dpkt.ssl``, dispatches packets to all DFIR analyzers, and correlates Threat Intelligence.
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

import dpkt

# Suppress noisy Scapy runtime interface warnings in headless/containerized DFIR labs
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgReader, PcapReader

from analyzers.carver import HTTPCarver, ThreatIntelMatcher
from analyzers.cleartext import CleartextAnalyzer
from analyzers.dns_forensics import DNSForensicsAnalyzer
from core.models import (
    SEVERITY_RANK,
    CaptureMetadata,
    FlowRecord,
    ForensicFinding,
    ForensicReportData,
    PacketContext,
    TimelineEvent,
)

TOOL_VERSION = "1.0.0"

HTTP_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"HTTP/1.",
)

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
)

CORE_PROTOCOLS = ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "Other")


def _compute_file_hashes(path: Path, chunk_size: int = 65536) -> tuple[str, str]:
    """Stream-hash the input PCAP file for chain-of-custody verification."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _extract_tls_sni(payload: bytes) -> Optional[str]:
    """Extract Server Name Indication (SNI) from a TLS ClientHello record via dpkt.ssl."""
    if len(payload) < 6:
        return None
    # TLS record content type 0x16 (Handshake), version 0x03 0x00..0x04
    if payload[0] != 0x16 or payload[1] != 0x03 or payload[2] > 0x04:
        return None
    try:
        records, _ = dpkt.ssl.tls_multi_factory(payload)
        for rec in records:
            if rec.type != 22:  # Handshake
                continue
            hs = dpkt.ssl.TLSHandshake(rec.data)
            if hs.type != 1:  # ClientHello
                continue
            client_hello = hs.data
            for ext_type, ext_data in getattr(client_hello, "extensions", []):
                if ext_type == 0 and len(ext_data) >= 5:
                    # SNI extension: 2-byte list len, 1-byte name type (0=host_name), 2-byte name len
                    name_type = ext_data[2]
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    if name_type == 0 and 5 + name_len <= len(ext_data):
                        sni = ext_data[5 : 5 + name_len].decode("ascii", errors="ignore").strip().lower()
                        if sni:
                            return sni
    except Exception:
        return None
    return None


def _looks_like_tls(payload: bytes, src_port: Optional[int], dst_port: Optional[int]) -> bool:
    if len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03 and payload[2] <= 0x04:
        return True
    if (src_port == 443 or dst_port == 443) and payload:
        return True
    return False


def _decode_tcp_flags(flags_int: int) -> list[str]:
    return [name for bit, name in TCP_FLAG_BITS if flags_int & bit]


def _canonical_flow_key(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
) -> tuple[str, int, str, int, str]:
    """Create a canonical bidirectional key independent of packet direction."""
    ep_a = (src_ip, src_port)
    ep_b = (dst_ip, dst_port)
    if ep_a <= ep_b:
        return (ep_a[0], ep_a[1], ep_b[0], ep_b[1], proto)
    return (ep_b[0], ep_b[1], ep_a[0], ep_a[1], proto)


class PcapEngine:
    """Memory-safe streaming PCAP forensics engine and analyzer pipeline."""

    def __init__(
        self,
        pcap_path: str | Path,
        ioc_path: Optional[str | Path] = None,
        extract_files: bool = False,
        extract_dir: Optional[str | Path] = None,
        entropy_threshold: float = 3.5,
        max_stream_mb: int = 25,
    ) -> None:
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.is_file():
            raise FileNotFoundError(f"Capture file not found: {self.pcap_path}")

        self.extract_files = extract_files
        self.extract_dir = Path(extract_dir) if extract_dir else Path("extracted_artifacts")
        self.max_stream_bytes = max(1, max_stream_mb) * 1024 * 1024

        # Initialize modular analyzers
        self.cleartext_analyzer = CleartextAnalyzer()
        self.dns_analyzer = DNSForensicsAnalyzer(entropy_threshold=entropy_threshold)
        self.http_carver = HTTPCarver(
            extract_files=extract_files,
            extract_dir=self.extract_dir,
            max_stream_bytes=self.max_stream_bytes,
        )
        self.threat_intel = ThreatIntelMatcher(watchlist_path=ioc_path)

        # Streaming state accumulators
        self._flows: dict[tuple[str, int, str, int, str], FlowRecord] = {}
        self._proto_packets: Counter[str] = Counter()
        self._proto_bytes: Counter[str] = Counter()
        self._highest_packets: Counter[str] = Counter()
        self._highest_bytes: Counter[str] = Counter()

        self._src_packets: Counter[str] = Counter()
        self._src_bytes: Counter[str] = Counter()
        self._dst_packets: Counter[str] = Counter()
        self._dst_bytes: Counter[str] = Counter()
        self._host_packets: Counter[str] = Counter()
        self._host_bytes: Counter[str] = Counter()
        self._ip_first_seen: dict[str, float] = {}
        self._ip_last_seen: dict[str, float] = {}

        self._tls_snis: dict[str, tuple[float, str]] = {}
        self._total_packets: int = 0
        self._total_bytes: int = 0
        self._first_ts: Optional[float] = None
        self._last_ts: Optional[float] = None

    def analyze(
        self,
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
        progress_interval: int = 100,
    ) -> ForensicReportData:
        """Stream packets sequentially from disk, run all analyzers, and build the report."""
        file_size = os.path.getsize(self.pcap_path)
        file_md5, file_sha256 = _compute_file_hashes(self.pcap_path)
        capture_format = "PCAP"

        with PcapReader(str(self.pcap_path)) as reader:
            if isinstance(reader, PcapNgReader):
                capture_format = "PCAPNG"

            for pkt_idx, pkt in enumerate(reader, start=1):
                ctx = self._extract_packet_context(pkt_idx, pkt)
                self._update_metrics_and_flows(ctx)

                # Dispatch ephemeral PacketContext to all streaming analyzers
                self.cleartext_analyzer.process_packet(ctx)
                self.dns_analyzer.process_packet(ctx)
                self.http_carver.process_packet(ctx)

                if progress_callback and (pkt_idx % progress_interval == 0):
                    bytes_read = self._safe_tell(reader, file_size)
                    progress_callback(bytes_read, file_size, pkt_idx)

        # Final progress notification
        if progress_callback:
            progress_callback(file_size, file_size, self._total_packets)

        # Flush streaming buffers & run aggregate anomaly checks
        self.cleartext_analyzer.finalize()
        self.dns_analyzer.finalize()
        self.http_carver.finalize()

        # Cross-reference all observed artifacts against Threat Intelligence watchlist
        self._correlate_threat_intel()

        # Assemble final metadata, findings, risk score, timeline, and recommendations
        metadata = self._build_metadata(file_size, file_md5, file_sha256, capture_format)
        flows_sorted = sorted(self._flows.values(), key=lambda f: (-f.byte_volume, -f.packet_count))
        findings = self._compile_findings()
        timeline = self._build_timeline(findings)
        severity_counts, risk_score, risk_level = self._compute_risk(findings)
        recommendations = self._generate_recommendations(findings)

        return ForensicReportData(
            tool_version=TOOL_VERSION,
            generated_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            metadata=metadata,
            flows=flows_sorted,
            http_artifacts=self.cleartext_analyzer.http_artifacts,
            credentials=self.cleartext_analyzer.credentials,
            ftp_sessions=self.cleartext_analyzer.ftp_sessions,
            smtp_sessions=self.cleartext_analyzer.smtp_sessions,
            telnet_sessions=self.cleartext_analyzer.telnet_sessions,
            passive_dns=self.dns_analyzer.passive_dns,
            dns_anomalies=self.dns_analyzer.anomalies,
            dns_stats=self.dns_analyzer.get_statistics(),
            carved_artifacts=self.http_carver.carved_artifacts,
            ioc_matches=self.threat_intel.matches,
            ioc_watchlist_path=self.threat_intel.watchlist_path,
            ioc_watchlist_loaded=self.threat_intel.loaded,
            findings=findings,
            timeline=timeline,
            recommendations=recommendations,
            risk_score=risk_score,
            risk_level=risk_level,
            severity_counts=severity_counts,
        )

    @staticmethod
    def _safe_tell(reader: Any, file_size: int) -> int:
        try:
            pos = int(reader.f.tell())
            return min(pos, file_size)
        except Exception:
            return 0

    def _extract_packet_context(self, index: int, pkt: Packet) -> PacketContext:
        """Convert a Scapy packet into a lightweight PacketContext without retaining pkt."""
        ts = float(getattr(pkt, "time", 0.0))
        wire_len = int(getattr(pkt, "wirelen", None) or len(pkt))

        eth_src: Optional[str] = None
        eth_dst: Optional[str] = None
        if pkt.haslayer(Ether):
            eth = pkt[Ether]
            eth_src = str(eth.src)
            eth_dst = str(eth.dst)

        network_proto = "Other"
        transport_proto = "Other"
        src_ip: Optional[str] = None
        dst_ip: Optional[str] = None
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_seq: Optional[int] = None
        tcp_ack: Optional[int] = None
        tcp_flags = 0
        payload = b""
        app_protocol = ""
        tls_sni: Optional[str] = None

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            network_proto = "ARP"
            transport_proto = "ARP"
            src_ip = str(arp.psrc)
            dst_ip = str(arp.pdst)
        elif pkt.haslayer(IP):
            ip = pkt[IP]
            network_proto = "IPv4"
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
        elif pkt.haslayer(IPv6):
            ip6 = pkt[IPv6]
            network_proto = "IPv6"
            src_ip = str(ip6.src)
            dst_ip = str(ip6.dst)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            transport_proto = "TCP"
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_seq = int(tcp.seq)
            tcp_ack = int(tcp.ack)
            tcp_flags = int(tcp.flags)
            payload = self._extract_transport_payload(tcp)
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            transport_proto = "UDP"
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            payload = self._extract_transport_payload(udp)
        elif pkt.haslayer(ICMP) or pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply):
            transport_proto = "ICMP"

        # Application-layer classification
        if transport_proto in ("UDP", "TCP") and (src_port in (53, 5353, 5355) or dst_port in (53, 5353, 5355)):
            app_protocol = "DNS"
        elif transport_proto == "TCP":
            if payload.startswith(HTTP_PREFIXES) or (
                (src_port in (80, 8000, 8080, 8888) or dst_port in (80, 8000, 8080, 8888))
                and payload
                and not _looks_like_tls(payload, src_port, dst_port)
            ):
                app_protocol = "HTTP"
            elif _looks_like_tls(payload, src_port, dst_port):
                app_protocol = "TLS"
                tls_sni = _extract_tls_sni(payload)
            elif src_port == 21 or dst_port == 21:
                app_protocol = "FTP"
            elif src_port in (25, 587, 2525) or dst_port in (25, 587, 2525):
                app_protocol = "SMTP"
            elif src_port == 23 or dst_port == 23:
                app_protocol = "TELNET"

        return PacketContext(
            index=index,
            timestamp=ts,
            wire_len=wire_len,
            eth_src=eth_src,
            eth_dst=eth_dst,
            network_proto=network_proto,
            src_ip=src_ip,
            dst_ip=dst_ip,
            transport_proto=transport_proto,
            src_port=src_port,
            dst_port=dst_port,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
            tcp_flags=tcp_flags,
            payload=payload,
            app_protocol=app_protocol,
            tls_sni=tls_sni,
        )

    @staticmethod
    def _extract_transport_payload(layer: Packet) -> bytes:
        """Extract raw application-layer bytes above TCP/UDP cleanly."""
        inner = layer.payload
        if inner is None or len(inner) == 0:
            return b""
        # Guard against Ethernet padding bytes attached directly as Padding layer
        if inner.__class__.__name__ == "Padding":
            return b""
        if isinstance(inner, Raw):
            return bytes(inner.load)
        # If Scapy dissected DNS/HTTP/etc., serialize the layer back to exact wire bytes
        return bytes(inner)

    def _update_metrics_and_flows(self, ctx: PacketContext) -> None:
        self._total_packets += 1
        self._total_bytes += ctx.wire_len

        if ctx.timestamp > 0:
            if self._first_ts is None or ctx.timestamp < self._first_ts:
                self._first_ts = ctx.timestamp
            if self._last_ts is None or ctx.timestamp > self._last_ts:
                self._last_ts = ctx.timestamp

        # Protocol counters (transport + recognized app protocols)
        t_proto = ctx.transport_proto if ctx.transport_proto in ("TCP", "UDP", "ICMP", "ARP") else "Other"
        self._proto_packets[t_proto] += 1
        self._proto_bytes[t_proto] += ctx.wire_len

        if ctx.app_protocol in ("DNS", "HTTP", "TLS"):
            self._proto_packets[ctx.app_protocol] += 1
            self._proto_bytes[ctx.app_protocol] += ctx.wire_len
            highest = ctx.app_protocol
        else:
            highest = t_proto

        self._highest_packets[highest] += 1
        self._highest_bytes[highest] += ctx.wire_len

        # Host talker counters
        if ctx.src_ip:
            self._src_packets[ctx.src_ip] += 1
            self._src_bytes[ctx.src_ip] += ctx.wire_len
            self._host_packets[ctx.src_ip] += 1
            self._host_bytes[ctx.src_ip] += ctx.wire_len
            if ctx.src_ip not in self._ip_first_seen:
                self._ip_first_seen[ctx.src_ip] = ctx.timestamp
            self._ip_last_seen[ctx.src_ip] = ctx.timestamp

        if ctx.dst_ip:
            self._dst_packets[ctx.dst_ip] += 1
            self._dst_bytes[ctx.dst_ip] += ctx.wire_len
            self._host_packets[ctx.dst_ip] += 1
            self._host_bytes[ctx.dst_ip] += ctx.wire_len
            if ctx.dst_ip not in self._ip_first_seen:
                self._ip_first_seen[ctx.dst_ip] = ctx.timestamp
            self._ip_last_seen[ctx.dst_ip] = ctx.timestamp

        # Bidirectional flow tracking
        if ctx.src_ip and ctx.dst_ip:
            s_port = ctx.src_port or 0
            d_port = ctx.dst_port or 0
            key = _canonical_flow_key(ctx.src_ip, s_port, ctx.dst_ip, d_port, t_proto)
            flow = self._flows.get(key)
            if flow is None:
                flow_id = f"FLW-{len(self._flows) + 1:05d}"
                flow = FlowRecord(
                    flow_id=flow_id,
                    src_ip=ctx.src_ip,
                    src_port=s_port,
                    dst_ip=ctx.dst_ip,
                    dst_port=d_port,
                    protocol=t_proto,
                    first_seen=ctx.timestamp,
                    last_seen=ctx.timestamp,
                )
                self._flows[key] = flow

            flow.packet_count += 1
            flow.byte_volume += ctx.wire_len
            if ctx.timestamp < flow.first_seen or flow.first_seen == 0.0:
                flow.first_seen = ctx.timestamp
            if ctx.timestamp > flow.last_seen:
                flow.last_seen = ctx.timestamp

            if ctx.src_ip == flow.src_ip and s_port == flow.src_port:
                flow.src_to_dst_packets += 1
                flow.src_to_dst_bytes += ctx.wire_len
            else:
                flow.dst_to_src_packets += 1
                flow.dst_to_src_bytes += ctx.wire_len

            if ctx.app_protocol:
                flow.app_protocols.add(ctx.app_protocol)
            if ctx.transport_proto == "TCP" and ctx.tcp_flags:
                flow.tcp_flags_seen.update(_decode_tcp_flags(ctx.tcp_flags))
            if ctx.tls_sni:
                flow.tls_sni = ctx.tls_sni
                self._tls_snis[ctx.tls_sni] = (
                    ctx.timestamp,
                    f"TLS ClientHello {ctx.src_ip}:{s_port} -> {ctx.dst_ip}:{d_port}",
                )

            ctx.flow_key = flow.flow_id

    def _correlate_threat_intel(self) -> None:
        """Cross-reference all observed IPs, domains, URLs, UAs, and file hashes against IoCs."""
        if not self.threat_intel.loaded:
            return

        # 1. Check all flow endpoints (IPs) and TLS SNIs
        for flow in self._flows.values():
            ctx_str = f"Flow {flow.flow_id}: {flow.src_ip}:{flow.src_port} <-> {flow.dst_ip}:{flow.dst_port} ({flow.protocol})"
            self.threat_intel.check_ip(flow.src_ip, flow.first_seen, ctx_str)
            self.threat_intel.check_ip(flow.dst_ip, flow.first_seen, ctx_str)
            if flow.tls_sni:
                self.threat_intel.check_domain(flow.tls_sni, flow.first_seen, f"TLS SNI on {ctx_str}")

        # 2. Check all Passive DNS domains and resolved IPs
        for pdns in self.dns_analyzer.passive_dns:
            self.threat_intel.check_domain(
                pdns.domain,
                pdns.first_seen,
                f"DNS query ({pdns.query_count}x) from {', '.join(pdns.client_ips[:3])}",
            )
            for cname in pdns.cnames:
                self.threat_intel.check_domain(cname, pdns.first_seen, f"DNS CNAME for {pdns.domain}")
            for ip in pdns.resolved_ips:
                self.threat_intel.check_ip(ip, pdns.first_seen, f"DNS resolution for {pdns.domain}")

        # 3. Check cleartext HTTP hosts, URLs, User-Agents, and SMTP domains
        for http_art in self.cleartext_analyzer.http_artifacts:
            host_clean = http_art.host.split(":", 1)[0].strip().lower()
            self.threat_intel.check_domain(
                host_clean,
                http_art.timestamp,
                f"HTTP {http_art.method} from {http_art.src_ip} -> {http_art.full_url}",
            )
            self.threat_intel.check_url(
                http_art.full_url,
                http_art.timestamp,
                f"HTTP {http_art.method} from {http_art.src_ip}",
            )
            if http_art.user_agent:
                self.threat_intel.check_user_agent(
                    http_art.user_agent,
                    http_art.timestamp,
                    f"HTTP request {http_art.src_ip} -> {http_art.full_url}",
                )

        for domain, (dom_ts, dom_ctx) in self.cleartext_analyzer.observed_domains.items():
            self.threat_intel.check_domain(domain, dom_ts, dom_ctx)

        # 4. Check all carved HTTP file MD5 & SHA-256 hashes
        for carved in self.http_carver.carved_artifacts:
            ctx_str = f"Carved artifact {carved.artifact_id} ({carved.filename}) from {carved.full_url}"
            self.threat_intel.check_hash(carved.md5, "md5", carved.timestamp, ctx_str)
            self.threat_intel.check_hash(carved.sha256, "sha256", carved.timestamp, ctx_str)

    def _build_metadata(
        self,
        file_size: int,
        file_md5: str,
        file_sha256: str,
        capture_format: str,
    ) -> CaptureMetadata:
        total_pkts = self._total_packets
        duration = (
            max(0.0, self._last_ts - self._first_ts)
            if (self._first_ts is not None and self._last_ts is not None)
            else 0.0
        )

        proto_dist: dict[str, dict[str, Any]] = {}
        for proto in CORE_PROTOCOLS:
            pkts = self._proto_packets.get(proto, 0)
            bvol = self._proto_bytes.get(proto, 0)
            pct = round((pkts / total_pkts) * 100.0, 2) if total_pkts else 0.0
            proto_dist[proto] = {"packets": pkts, "bytes": bvol, "percentage": pct}

        highest_dist: dict[str, dict[str, Any]] = {}
        for proto, pkts in self._highest_packets.most_common():
            bvol = self._highest_bytes.get(proto, 0)
            pct = round((pkts / total_pkts) * 100.0, 2) if total_pkts else 0.0
            highest_dist[proto] = {"packets": pkts, "bytes": bvol, "percentage": pct}

        top_src = [
            {
                "ip": ip,
                "packets": self._src_packets[ip],
                "bytes": bvol,
                "share_pct": round((bvol / self._total_bytes) * 100.0, 2) if self._total_bytes else 0.0,
            }
            for ip, bvol in self._src_bytes.most_common(10)
        ]
        top_dst = [
            {
                "ip": ip,
                "packets": self._dst_packets[ip],
                "bytes": bvol,
                "share_pct": round((bvol / self._total_bytes) * 100.0, 2) if self._total_bytes else 0.0,
            }
            for ip, bvol in self._dst_bytes.most_common(10)
        ]
        top_hosts = [
            {
                "ip": ip,
                "total_packets": self._host_packets[ip],
                "total_bytes": bvol,
                "sent_bytes": self._src_bytes.get(ip, 0),
                "recv_bytes": self._dst_bytes.get(ip, 0),
                "sent_packets": self._src_packets.get(ip, 0),
                "recv_packets": self._dst_packets.get(ip, 0),
            }
            for ip, bvol in self._host_bytes.most_common(10)
        ]

        top_flows = [
            fl.to_dict()
            for fl in sorted(self._flows.values(), key=lambda f: (-f.byte_volume, -f.packet_count))[:15]
        ]

        return CaptureMetadata(
            file_path=str(self.pcap_path),
            file_name=self.pcap_path.name,
            file_size=file_size,
            file_md5=file_md5,
            file_sha256=file_sha256,
            capture_format=capture_format,
            total_packets=total_pkts,
            total_bytes=self._total_bytes,
            first_packet_time=self._first_ts,
            last_packet_time=self._last_ts,
            duration_seconds=duration,
            unique_ips=len(self._host_packets),
            total_flows=len(self._flows),
            protocol_distribution=proto_dist,
            highest_layer_distribution=highest_dist,
            top_talkers_src=top_src,
            top_talkers_dst=top_dst,
            top_talkers_hosts=top_hosts,
            top_flows=top_flows,
            tls_snis=sorted(self._tls_snis.keys()),
        )

    def _compile_findings(self) -> list[ForensicFinding]:
        """Synthesize unified, prioritized findings from all analyzer modules."""
        findings: list[ForensicFinding] = []
        counter = 0

        def add_finding(
            timestamp: float,
            severity: str,
            category: str,
            title: str,
            description: str,
            src_ip: Optional[str] = None,
            dst_ip: Optional[str] = None,
            artifact_ref: Optional[str] = None,
            mitre: Optional[list[str]] = None,
        ) -> None:
            nonlocal counter
            counter += 1
            findings.append(
                ForensicFinding(
                    finding_id=f"FND-{counter:04d}",
                    timestamp=timestamp,
                    severity=severity,
                    category=category,
                    title=title,
                    description=description,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    artifact_ref=artifact_ref,
                    mitre_attack=mitre or [],
                )
            )

        # 1. Threat Intelligence IoC Matches
        for match in self.threat_intel.matches:
            add_finding(
                timestamp=match.first_seen,
                severity=match.severity,
                category="Threat Intel",
                title=f"IoC Match ({match.indicator_type.upper()}): {match.indicator}",
                description=(
                    f"{match.threat_type} — {match.description} "
                    f"[Hits: {match.hit_count}; Source: {match.source}]"
                ),
                artifact_ref=match.contexts[0] if match.contexts else match.indicator,
                mitre=match.mitre_attack or ["T1071"],
            )

        # 2. Carved File Findings (Executables, MIME Masquerading, Suspicious Scripts)
        for carved in self.http_carver.carved_artifacts:
            if carved.mime_mismatch:
                sev = "CRITICAL" if carved.is_executable else "HIGH"
                add_finding(
                    timestamp=carved.timestamp,
                    severity=sev,
                    category="File Carving",
                    title=f"MIME Type Masquerading Detected: {carved.filename}",
                    description=(
                        f"HTTP 200 OK payload declared Content-Type '{carved.declared_content_type}' "
                        f"but magic bytes identify '{carved.detected_mime_type}' ({carved.magic_description}). "
                        f"SHA-256: {carved.sha256}"
                    ),
                    src_ip=carved.server_ip,
                    dst_ip=carved.client_ip,
                    artifact_ref=carved.artifact_id,
                    mitre=["T1036", "T1105"],
                )
            elif carved.is_executable:
                add_finding(
                    timestamp=carved.timestamp,
                    severity="HIGH",
                    category="File Carving",
                    title=f"Executable Transferred Over Cleartext HTTP: {carved.filename}",
                    description=(
                        f"{carved.magic_description} ({carved.size_bytes} bytes) downloaded from "
                        f"{carved.full_url}. SHA-256: {carved.sha256}"
                    ),
                    src_ip=carved.server_ip,
                    dst_ip=carved.client_ip,
                    artifact_ref=carved.artifact_id,
                    mitre=["T1105"],
                )
            elif carved.is_script:
                add_finding(
                    timestamp=carved.timestamp,
                    severity="MEDIUM",
                    category="File Carving",
                    title=f"Script Payload Transferred Over HTTP: {carved.filename}",
                    description=(
                        f"{carved.magic_description} ({carved.size_bytes} bytes) carved from "
                        f"{carved.full_url}. SHA-256: {carved.sha256}"
                    ),
                    src_ip=carved.server_ip,
                    dst_ip=carved.client_ip,
                    artifact_ref=carved.artifact_id,
                    mitre=["T1059", "T1105"],
                )

        # 3. Cleartext Credential Exposures
        for cred in self.cleartext_analyzer.credentials:
            add_finding(
                timestamp=cred.timestamp,
                severity="HIGH",
                category="Cleartext Credentials",
                title=f"Cleartext {cred.protocol} Credentials Exposed ({cred.username})",
                description=(
                    f"Recovered cleartext authentication for user '{cred.username}' over {cred.protocol} "
                    f"from {cred.src_ip} to {cred.dst_ip}:{cred.dst_port}. Context: {cred.context}"
                ),
                src_ip=cred.src_ip,
                dst_ip=cred.dst_ip,
                artifact_ref=cred.protocol,
                mitre=["T1552", "T1040"],
            )

        # 4. DNS Forensics Anomalies (DGA, Tunneling, NXDOMAIN Spikes)
        dns_title_map = {
            "DGA_HIGH_ENTROPY": "DGA High-Entropy Domain",
            "DNS_TUNNELING_LONG_LABEL": "DNS Tunneling (Abnormally Long Label)",
            "DNS_TUNNELING_TXT_NULL": "DNS Tunneling (Elevated TXT/NULL Volume)",
            "DNS_TUNNELING_HIGH_SUBDOMAINS": "DNS Tunneling (High Subdomain Cardinality)",
            "HIGH_NXDOMAIN_RATE": "High NXDOMAIN Failure Rate",
        }
        for anom in self.dns_analyzer.anomalies:
            mitre_map = {
                "DGA_HIGH_ENTROPY": ["T1568.002"],
                "DNS_TUNNELING_LONG_LABEL": ["T1071.004", "T1048.003"],
                "DNS_TUNNELING_TXT_NULL": ["T1071.004", "T1048.003"],
                "DNS_TUNNELING_HIGH_SUBDOMAINS": ["T1071.004", "T1048.003"],
                "HIGH_NXDOMAIN_RATE": ["T1568.002"],
            }
            label = dns_title_map.get(anom.anomaly_type, anom.anomaly_type.replace("_", " ").title())
            add_finding(
                timestamp=anom.timestamp,
                severity=anom.severity,
                category="DNS Forensics",
                title=f"{label}: {anom.domain[:64]}",
                description=anom.details,
                src_ip=anom.src_ip,
                dst_ip=anom.dst_ip,
                artifact_ref=anom.domain,
                mitre=mitre_map.get(anom.anomaly_type, ["T1071.004"]),
            )

        # 5. Suspicious Cleartext HTTP Requests (excluding already-emitted cred findings)
        for http_art in self.cleartext_analyzer.http_artifacts:
            non_cred = [
                ind
                for ind in http_art.suspicious_indicators
                if "Cleartext" not in ind and "Missing User-Agent" not in ind
            ]
            if non_cred:
                add_finding(
                    timestamp=http_art.timestamp,
                    severity="MEDIUM",
                    category="HTTP Anomaly",
                    title=f"Suspicious HTTP {http_art.method} to {http_art.host}{http_art.uri[:48]}",
                    description="; ".join(non_cred) + f". User-Agent: '{http_art.user_agent or 'N/A'}'",
                    src_ip=http_art.src_ip,
                    dst_ip=http_art.dst_ip,
                    artifact_ref=http_art.full_url,
                    mitre=["T1071.001"],
                )

        # 6. Cleartext Telnet / FTP File Exfiltration Activity
        for ftp in self.cleartext_analyzer.ftp_sessions:
            if ftp.transferred_files:
                add_finding(
                    timestamp=ftp.last_seen,
                    severity="MEDIUM",
                    category="Cleartext Transfer",
                    title=f"Unencrypted FTP File Transfer ({', '.join(ftp.transferred_files[:3])})",
                    description=(
                        f"FTP session ({ftp.src_ip} -> {ftp.dst_ip}:{ftp.dst_port}, user '{ftp.username or 'unknown'}') "
                        f"requested file transfers: {', '.join(ftp.transferred_files)}."
                    ),
                    src_ip=ftp.src_ip,
                    dst_ip=ftp.dst_ip,
                    artifact_ref=", ".join(ftp.transferred_files),
                    mitre=["T1048.003"],
                )

        for telnet in self.cleartext_analyzer.telnet_sessions:
            if telnet.commands:
                add_finding(
                    timestamp=telnet.last_seen,
                    severity="MEDIUM",
                    category="Cleartext Remote Access",
                    title=f"Unencrypted Telnet Remote Shell Activity ({len(telnet.commands)} commands)",
                    description=(
                        f"Interactive Telnet session between {telnet.src_ip} and {telnet.dst_ip}:{telnet.dst_port}. "
                        f"Observed commands: {', '.join(telnet.commands[:5])}"
                    ),
                    src_ip=telnet.src_ip,
                    dst_ip=telnet.dst_ip,
                    artifact_ref="Telnet",
                    mitre=["T1021", "T1059"],
                )

        findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.timestamp))
        return findings

    def _build_timeline(self, findings: list[ForensicFinding]) -> list[TimelineEvent]:
        """Construct a chronological incident timeline combining findings and key protocol milestones."""
        events: list[TimelineEvent] = []
        for f in findings:
            events.append(
                TimelineEvent(
                    timestamp=f.timestamp,
                    severity=f.severity,
                    category=f.category,
                    source=f.src_ip or "N/A",
                    destination=f.dst_ip or (f.artifact_ref or "N/A"),
                    summary=f.title,
                )
            )

        for smtp in self.cleartext_analyzer.smtp_sessions:
            events.append(
                TimelineEvent(
                    timestamp=smtp.first_seen,
                    severity="LOW",
                    category="SMTP Email",
                    source=smtp.src_ip,
                    destination=f"{smtp.dst_ip}:{smtp.dst_port}",
                    summary=(
                        f"SMTP message from {smtp.mail_from or 'unknown'} to "
                        f"{', '.join(smtp.rcpt_to) or 'unknown'} (Subject: '{smtp.subject or 'N/A'}')"
                    ),
                )
            )

        events.sort(key=lambda e: (e.timestamp, -SEVERITY_RANK.get(e.severity, 0)))
        return events

    @staticmethod
    def _compute_risk(findings: list[ForensicFinding]) -> tuple[dict[str, int], int, str]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity if f.severity in counts else "INFO"
            counts[sev] += 1

        raw_score = (
            counts["CRITICAL"] * 35
            + counts["HIGH"] * 18
            + counts["MEDIUM"] * 8
            + counts["LOW"] * 3
        )
        score = min(100, raw_score)
        if counts["CRITICAL"] > 0 or score >= 80:
            level = "CRITICAL"
        elif counts["HIGH"] > 0 or score >= 50:
            level = "HIGH"
        elif counts["MEDIUM"] > 0 or score >= 20:
            level = "MEDIUM"
        elif counts["LOW"] > 0 or score > 0:
            level = "LOW"
        else:
            level = "CLEAN"
        return counts, score, level

    def _generate_recommendations(self, findings: list[ForensicFinding]) -> list[str]:
        recs: list[str] = []
        categories = {f.category for f in findings}

        if self.threat_intel.matches:
            recs.append(
                "Isolate affected internal hosts immediately and block all matched malicious IPs/domains at perimeter firewalls, proxies, and DNS resolvers."
            )
        if any(c.is_executable or c.mime_mismatch for c in self.http_carver.carved_artifacts):
            recs.append(
                "Submit carved executable SHA-256 hashes to enterprise EDR/sandbox platforms (e.g., VirusTotal, Joe Sandbox) and hunt endpoints for matching file writes or process executions."
            )
        if self.cleartext_analyzer.credentials:
            recs.append(
                "Rotate all exposed credentials recovered from cleartext HTTP, FTP, SMTP, and Telnet traffic immediately, and enforce encrypted transports (HTTPS, SFTP, SMTPS, SSH)."
            )
        if self.dns_analyzer.anomalies:
            recs.append(
                "Investigate hosts exhibiting DGA entropy, DNS tunneling (long labels / TXT spikes), or high NXDOMAIN rates for C2 implants and enforce DNS egress inspection/RPZ blocking."
            )
        if "Cleartext Transfer" in categories or "Cleartext Remote Access" in categories:
            recs.append(
                "Audit unauthorized FTP/Telnet services on the network, verify whether sensitive data (e.g., CSV/finance exports) was exfiltrated, and disable legacy plaintext services."
            )
        if not recs:
            recs.append(
                "No high-confidence malicious indicators were triggered; retain capture hashes for audit trail and correlate baseline flows with host telemetry as needed."
            )
        return recs
