"""Canonical forensic data models shared across ingestion, analyzers, and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Standardized DFIR severity classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            "CRITICAL": 5,
            "HIGH": 4,
            "MEDIUM": 3,
            "LOW": 2,
            "INFO": 1,
        }
        return order[self.value]


SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def format_utc_timestamp(ts: Optional[float]) -> str:
    """Format a POSIX epoch timestamp as an ISO-8601 UTC string."""
    if ts is None or ts <= 0:
        return "N/A"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def format_bytes(num_bytes: int | float) -> str:
    """Format a byte count into a human-readable string."""
    size = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def format_duration(seconds: float) -> str:
    """Format a duration in seconds into a concise human-readable form."""
    if seconds < 0:
        seconds = 0.0
    if seconds < 1.0:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60.0:
        return f"{seconds:.2f} s"
    minutes, rem = divmod(seconds, 60.0)
    if minutes < 60:
        return f"{int(minutes)}m {rem:.1f}s"
    hours, minutes = divmod(minutes, 60.0)
    return f"{int(hours)}h {int(minutes)}m {rem:.0f}s"


@dataclass(slots=True)
class PacketContext:
    """Lightweight normalized representation of a single streamed packet.

    Engine passes this ephemeral view to analyzers so raw Scapy packet objects
    can be immediately garbage-collected after each packet is processed.
    """

    index: int
    timestamp: float
    wire_len: int
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None
    network_proto: str = "Other"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    transport_proto: str = "Other"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: int = 0
    payload: bytes = b""
    app_protocol: str = ""
    flow_key: Optional[str] = None
    tls_sni: Optional[str] = None


@dataclass
class FlowRecord:
    """Bidirectional network flow / conversation statistics."""

    flow_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    packet_count: int = 0
    byte_volume: int = 0
    src_to_dst_packets: int = 0
    dst_to_src_packets: int = 0
    src_to_dst_bytes: int = 0
    dst_to_src_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    app_protocols: set[str] = field(default_factory=set)
    tcp_flags_seen: set[str] = field(default_factory=set)
    tls_sni: Optional[str] = None

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "app_protocols": sorted(self.app_protocols),
            "packet_count": self.packet_count,
            "byte_volume": self.byte_volume,
            "src_to_dst_packets": self.src_to_dst_packets,
            "dst_to_src_packets": self.dst_to_src_packets,
            "src_to_dst_bytes": self.src_to_dst_bytes,
            "dst_to_src_bytes": self.dst_to_src_bytes,
            "first_seen": self.first_seen,
            "first_seen_utc": format_utc_timestamp(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_utc": format_utc_timestamp(self.last_seen),
            "duration_seconds": round(self.duration, 6),
            "tcp_flags_seen": sorted(self.tcp_flags_seen),
            "tls_sni": self.tls_sni,
        }


@dataclass
class CaptureMetadata:
    """Overall capture file metadata, protocol breakdown, and top talkers."""

    file_path: str
    file_name: str
    file_size: int
    file_md5: str
    file_sha256: str
    capture_format: str = "PCAP"
    total_packets: int = 0
    total_bytes: int = 0
    first_packet_time: Optional[float] = None
    last_packet_time: Optional[float] = None
    duration_seconds: float = 0.0
    unique_ips: int = 0
    total_flows: int = 0
    protocol_distribution: dict[str, dict[str, Any]] = field(default_factory=dict)
    highest_layer_distribution: dict[str, dict[str, Any]] = field(default_factory=dict)
    top_talkers_src: list[dict[str, Any]] = field(default_factory=list)
    top_talkers_dst: list[dict[str, Any]] = field(default_factory=list)
    top_talkers_hosts: list[dict[str, Any]] = field(default_factory=list)
    top_flows: list[dict[str, Any]] = field(default_factory=list)
    tls_snis: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_size_human": format_bytes(self.file_size),
            "file_md5": self.file_md5,
            "file_sha256": self.file_sha256,
            "capture_format": self.capture_format,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "total_bytes_human": format_bytes(self.total_bytes),
            "first_packet_time": self.first_packet_time,
            "first_packet_utc": format_utc_timestamp(self.first_packet_time),
            "last_packet_time": self.last_packet_time,
            "last_packet_utc": format_utc_timestamp(self.last_packet_time),
            "duration_seconds": round(self.duration_seconds, 6),
            "duration_human": format_duration(self.duration_seconds),
            "unique_ips": self.unique_ips,
            "total_flows": self.total_flows,
            "protocol_distribution": self.protocol_distribution,
            "highest_layer_distribution": self.highest_layer_distribution,
            "top_talkers_src": self.top_talkers_src,
            "top_talkers_dst": self.top_talkers_dst,
            "top_talkers_hosts": self.top_talkers_hosts,
            "top_flows": self.top_flows,
            "tls_snis": self.tls_snis,
        }


@dataclass
class HTTPArtifact:
    """Extracted cleartext HTTP request artifact."""

    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    host: str
    uri: str
    full_url: str
    http_version: str = "1.1"
    user_agent: str = ""
    referer: str = ""
    content_type: str = ""
    cookie: str = ""
    auth_type: str = ""
    auth_raw: str = ""
    auth_decoded_user: str = ""
    auth_decoded_pass: str = ""
    post_params: dict[str, list[str]] = field(default_factory=dict)
    body_preview: str = ""
    suspicious_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "timestamp_utc": format_utc_timestamp(self.timestamp),
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "method": self.method,
            "host": self.host,
            "uri": self.uri,
            "full_url": self.full_url,
            "http_version": self.http_version,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "content_type": self.content_type,
            "cookie": self.cookie,
            "auth_type": self.auth_type,
            "auth_raw": self.auth_raw,
            "auth_decoded_user": self.auth_decoded_user,
            "auth_decoded_pass": self.auth_decoded_pass,
            "post_params": self.post_params,
            "body_preview": self.body_preview,
            "suspicious_indicators": self.suspicious_indicators,
        }


@dataclass
class CredentialArtifact:
    """Recovered cleartext credential or authentication token."""

    timestamp: float
    protocol: str
    src_ip: str
    dst_ip: str
    dst_port: int
    username: str
    password: str
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "timestamp_utc": format_utc_timestamp(self.timestamp),
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "username": self.username,
            "password": self.password,
            "context": self.context,
        }


@dataclass
class FTPSessionArtifact:
    """Reconstructed FTP control session artifact."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: float
    last_seen: float
    username: str = ""
    password: str = ""
    auth_status: str = "unknown"
    commands: list[dict[str, Any]] = field(default_factory=list)
    transferred_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "first_seen": self.first_seen,
            "first_seen_utc": format_utc_timestamp(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_utc": format_utc_timestamp(self.last_seen),
            "username": self.username,
            "password": self.password,
            "auth_status": self.auth_status,
            "commands": self.commands,
            "transferred_files": self.transferred_files,
        }


@dataclass
class SMTPSessionArtifact:
    """Reconstructed SMTP email session artifact."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: float
    last_seen: float
    helo: str = ""
    mail_from: str = ""
    rcpt_to: list[str] = field(default_factory=list)
    subject: str = ""
    from_header: str = ""
    to_header: str = ""
    date_header: str = ""
    x_mailer: str = ""
    auth_user: str = ""
    auth_pass: str = ""
    commands: list[str] = field(default_factory=list)
    body_preview: str = ""
    attachments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "first_seen": self.first_seen,
            "first_seen_utc": format_utc_timestamp(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_utc": format_utc_timestamp(self.last_seen),
            "helo": self.helo,
            "mail_from": self.mail_from,
            "rcpt_to": self.rcpt_to,
            "subject": self.subject,
            "from_header": self.from_header,
            "to_header": self.to_header,
            "date_header": self.date_header,
            "x_mailer": self.x_mailer,
            "auth_user": self.auth_user,
            "auth_pass": self.auth_pass,
            "commands": self.commands,
            "body_preview": self.body_preview,
            "attachments": self.attachments,
        }


@dataclass
class TelnetSessionArtifact:
    """Reconstructed Telnet session commands and login telemetry."""

    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: float
    last_seen: float
    commands: list[str] = field(default_factory=list)
    transcript_preview: str = ""
    credentials_detected: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "first_seen": self.first_seen,
            "first_seen_utc": format_utc_timestamp(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_utc": format_utc_timestamp(self.last_seen),
            "commands": self.commands,
            "transcript_preview": self.transcript_preview,
            "credentials_detected": self.credentials_detected,
        }


@dataclass
class PassiveDNSRecord:
    """Passive DNS mapping record aggregating queries and resolutions for a domain."""

    domain: str
    resolved_ips: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    query_types: list[str] = field(default_factory=list)
    query_count: int = 0
    response_count: int = 0
    nxdomain_count: int = 0
    client_ips: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    max_label_entropy: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "resolved_ips": self.resolved_ips,
            "cnames": self.cnames,
            "txt_records": self.txt_records,
            "query_types": self.query_types,
            "query_count": self.query_count,
            "response_count": self.response_count,
            "nxdomain_count": self.nxdomain_count,
            "client_ips": self.client_ips,
            "first_seen": self.first_seen,
            "first_seen_utc": format_utc_timestamp(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_utc": format_utc_timestamp(self.last_seen),
            "max_label_entropy": round(self.max_label_entropy, 4),
        }


@dataclass
class DNSAnomaly:
    """Detected DNS forensic anomaly (DGA, tunneling, or NXDOMAIN spike)."""

    anomaly_type: str
    severity: str
    timestamp: float
    src_ip: str
    dst_ip: str
    domain: str
    score: float
    details: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "timestamp_utc": format_utc_timestamp(self.timestamp),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "domain": self.domain,
            "score": round(self.score, 4),
            "details": self.details,
            "evidence": self.evidence,
        }


@dataclass
class CarvedArtifact:
    """HTTP response object carved from reassembled TCP streams."""

    artifact_id: str
    timestamp: float
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    http_method: str
    host: str
    uri: str
    full_url: str
    status_code: int
    filename: str
    saved_path: Optional[str]
    size_bytes: int
    md5: str
    sha256: str
    declared_content_type: str
    detected_mime_type: str
    magic_description: str
    mime_mismatch: bool = False
    is_executable: bool = False
    is_script: bool = False
    is_archive: bool = False
    transfer_encoding: str = ""
    content_encoding: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "timestamp": self.timestamp,
            "timestamp_utc": format_utc_timestamp(self.timestamp),
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "http_method": self.http_method,
            "host": self.host,
            "uri": self.uri,
            "full_url": self.full_url,
            "status_code": self.status_code,
            "filename": self.filename,
            "saved_path": self.saved_path,
            "size_bytes": self.size_bytes,
            "size_human": format_bytes(self.size_bytes),
            "md5": self.md5,
            "sha256": self.sha256,
            "declared_content_type": self.declared_content_type,
            "detected_mime_type": self.detected_mime_type,
            "magic_description": self.magic_description,
            "mime_mismatch": self.mime_mismatch,
            "is_executable": self.is_executable,
            "is_script": self.is_script,
            "is_archive": self.is_archive,
            "transfer_encoding": self.transfer_encoding,
            "content_encoding": self.content_encoding,
        }


@dataclass
class IoCMatch:
    """Threat intelligence watchlist hit correlated against capture observations."""

    indicator: str
    indicator_type: str
    severity: str
    threat_type: str
    source: str
    description: str
    mitre_attack: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    hit_count: int = 1
    contexts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "severity": self.severity,
            "threat_type": self.threat_type,
            "source": self.source,
            "description": self.description,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "first_seen_utc": format_utc_timestamp(self.first_seen),
            "last_seen": self.last_seen,
            "last_seen_utc": format_utc_timestamp(self.last_seen),
            "hit_count": self.hit_count,
            "contexts": self.contexts,
        }


@dataclass
class ForensicFinding:
    """Unified high-level forensic finding for triage, executive summary, and timelines."""

    finding_id: str
    timestamp: float
    severity: str
    category: str
    title: str
    description: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    artifact_ref: Optional[str] = None
    mitre_attack: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "timestamp_utc": format_utc_timestamp(self.timestamp),
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "artifact_ref": self.artifact_ref,
            "mitre_attack": self.mitre_attack,
        }


@dataclass
class TimelineEvent:
    """Chronological forensic timeline entry."""

    timestamp: float
    severity: str
    category: str
    source: str
    destination: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "timestamp_utc": format_utc_timestamp(self.timestamp),
            "severity": self.severity,
            "category": self.category,
            "source": self.source,
            "destination": self.destination,
            "summary": self.summary,
        }


@dataclass
class ForensicReportData:
    """Complete aggregated investigation dataset emitted by PcapEngine."""

    tool_version: str
    generated_at_utc: str
    metadata: CaptureMetadata
    flows: list[FlowRecord] = field(default_factory=list)
    http_artifacts: list[HTTPArtifact] = field(default_factory=list)
    credentials: list[CredentialArtifact] = field(default_factory=list)
    ftp_sessions: list[FTPSessionArtifact] = field(default_factory=list)
    smtp_sessions: list[SMTPSessionArtifact] = field(default_factory=list)
    telnet_sessions: list[TelnetSessionArtifact] = field(default_factory=list)
    passive_dns: list[PassiveDNSRecord] = field(default_factory=list)
    dns_anomalies: list[DNSAnomaly] = field(default_factory=list)
    dns_stats: dict[str, Any] = field(default_factory=dict)
    carved_artifacts: list[CarvedArtifact] = field(default_factory=list)
    ioc_matches: list[IoCMatch] = field(default_factory=list)
    ioc_watchlist_path: Optional[str] = None
    ioc_watchlist_loaded: bool = False
    findings: list[ForensicFinding] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "CLEAN"
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "tool": "Automated PCAP Forensics Analyzer",
            "tool_version": self.tool_version,
            "generated_at_utc": self.generated_at_utc,
            "executive_summary": {
                "risk_score": self.risk_score,
                "risk_level": self.risk_level,
                "severity_counts": self.severity_counts,
                "total_findings": len(self.findings),
                "ioc_hits": len(self.ioc_matches),
                "credentials_recovered": len(self.credentials),
                "dns_anomalies": len(self.dns_anomalies),
                "carved_artifacts": len(self.carved_artifacts),
                "recommendations": self.recommendations,
            },
            "capture_metadata": self.metadata.to_dict(),
            "incident_timeline": [ev.to_dict() for ev in self.timeline],
            "findings": [f.to_dict() for f in self.findings],
            "threat_intelligence": {
                "watchlist_path": self.ioc_watchlist_path,
                "watchlist_loaded": self.ioc_watchlist_loaded,
                "matches": [m.to_dict() for m in self.ioc_matches],
            },
            "cleartext_artifacts": {
                "credentials": [c.to_dict() for c in self.credentials],
                "http_requests": [h.to_dict() for h in self.http_artifacts],
                "ftp_sessions": [f.to_dict() for f in self.ftp_sessions],
                "smtp_sessions": [s.to_dict() for s in self.smtp_sessions],
                "telnet_sessions": [t.to_dict() for t in self.telnet_sessions],
            },
            "dns_forensics": {
                "statistics": self.dns_stats,
                "anomalies": [a.to_dict() for a in self.dns_anomalies],
                "passive_dns": [r.to_dict() for r in self.passive_dns],
            },
            "carved_artifacts": [c.to_dict() for c in self.carved_artifacts],
            "network_flows": [fl.to_dict() for fl in self.flows],
        }
