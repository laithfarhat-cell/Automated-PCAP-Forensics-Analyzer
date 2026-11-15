"""DNS forensics, passive DNS reconstruction, DGA entropy scoring, and tunneling detection.

Parses UDP and TCP DNS packets via ``dpkt.dns.DNS`` to:
- Build a passive DNS table mapping domains to resolved A/AAAA IPs, CNAMEs, and TXT records.
- Compute Shannon entropy across queried domain labels to detect Domain Generation Algorithms (DGA).
- Identify DNS tunneling via abnormally long subdomain labels, high TXT/NULL query volumes,
  and excessive unique-subdomain cardinality per base domain.
- Detect high NXDOMAIN failure rates per client and across the capture.
"""

from __future__ import annotations

import math
import re
import socket
import struct
from collections import Counter, defaultdict
from typing import Any

import dpkt

from core.models import DNSAnomaly, PacketContext, PassiveDNSRecord

DNS_PORTS = {53, 5353, 5355}

DNS_QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    65: "HTTPS",
    255: "ANY",
}

DNS_RCODE_MAP: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp", "co.nz", "com.br", "com.cn", "co.in",
    "com.sg", "com.hk", "co.za", "com.mx", "co.kr",
}

HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
BASE32_RE = re.compile(r"^[a-z2-7=]{20,}$", re.IGNORECASE)
BASE64_URL_RE = re.compile(r"^[A-Za-z0-9_-]{24,}$")


def shannon_entropy(label: str) -> float:
    """Compute Shannon entropy in bits per character for a string."""
    if not label:
        return 0.0
    counts = Counter(label.lower())
    length = len(label)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_base_domain(domain: str) -> str:
    """Extract the registrable base domain (eTLD+1 approximation) from a FQDN."""
    cleaned = domain.strip(".").lower()
    if not cleaned:
        return ""
    parts = cleaned.split(".")
    if len(parts) <= 2:
        return cleaned
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def extract_analyzable_labels(domain: str) -> list[str]:
    """Return non-TLD domain labels (subdomains + SLD) suitable for entropy inspection."""
    cleaned = domain.strip(".").lower()
    if not cleaned or cleaned.endswith((".arpa", ".local")):
        return []
    parts = [p for p in cleaned.split(".") if p and not p.startswith("_")]
    if len(parts) <= 1:
        return parts
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return parts[:-2]
    return parts[:-1]


class DNSForensicsAnalyzer:
    """Streaming DNS analyzer for passive DNS, DGA entropy, tunneling, and NXDOMAIN spikes."""

    def __init__(
        self,
        entropy_threshold: float = 3.5,
        min_dga_label_len: int = 8,
        long_label_threshold: int = 35,
        long_qname_threshold: int = 75,
        txt_null_threshold: int = 5,
        unique_subdomain_threshold: int = 8,
        nxdomain_min_count: int = 5,
        nxdomain_rate_threshold: float = 0.30,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_dga_label_len = min_dga_label_len
        self.long_label_threshold = long_label_threshold
        self.long_qname_threshold = long_qname_threshold
        self.txt_null_threshold = txt_null_threshold
        self.unique_subdomain_threshold = unique_subdomain_threshold
        self.nxdomain_min_count = nxdomain_min_count
        self.nxdomain_rate_threshold = nxdomain_rate_threshold

        self._passive_dns: dict[str, PassiveDNSRecord] = {}
        self._anomalies: list[DNSAnomaly] = []
        self._seen_dga_domains: set[str] = set()
        self._seen_long_domains: set[str] = set()

        # Counters & aggregation state
        self.total_dns_packets: int = 0
        self.total_queries: int = 0
        self.total_responses: int = 0
        self.qtype_counts: Counter[str] = Counter()
        self.rcode_counts: Counter[str] = Counter()

        # Per-client NXDOMAIN tracking
        self._client_responses: Counter[str] = Counter()
        self._client_nxdomains: Counter[str] = Counter()
        self._client_nxdomain_samples: dict[str, list[str]] = defaultdict(list)
        self._client_nxdomain_last_ts: dict[str, float] = {}
        self._client_dns_server: dict[str, str] = {}

        # Per base-domain tunneling tracking
        self._base_txt_null_count: Counter[str] = Counter()
        self._base_txt_bytes: Counter[str] = Counter()
        self._base_txt_clients: dict[str, set[str]] = defaultdict(set)
        self._base_txt_last_ts: dict[str, float] = {}
        self._base_unique_subdomains: dict[str, set[str]] = defaultdict(set)
        self._base_subdomain_clients: dict[str, set[str]] = defaultdict(set)
        self._base_subdomain_last_ts: dict[str, float] = {}

        # Observed artifacts for Threat Intel correlation
        self.observed_domains: set[str] = set()
        self.observed_resolved_ips: dict[str, set[str]] = defaultdict(set)

    @property
    def passive_dns(self) -> list[PassiveDNSRecord]:
        return sorted(
            self._passive_dns.values(),
            key=lambda r: (-r.query_count, -r.max_label_entropy, r.domain),
        )

    @property
    def anomalies(self) -> list[DNSAnomaly]:
        return self._anomalies

    def get_statistics(self) -> dict[str, Any]:
        nx_total = self.rcode_counts.get("NXDOMAIN", 0)
        nx_rate = (nx_total / self.total_responses) if self.total_responses else 0.0
        return {
            "total_dns_packets": self.total_dns_packets,
            "total_queries": self.total_queries,
            "total_responses": self.total_responses,
            "unique_domains": len(self._passive_dns),
            "nxdomain_count": nx_total,
            "nxdomain_rate": round(nx_rate, 4),
            "nxdomain_rate_pct": round(nx_rate * 100.0, 2),
            "query_type_breakdown": dict(self.qtype_counts.most_common()),
            "response_code_breakdown": dict(self.rcode_counts.most_common()),
            "anomaly_count": len(self._anomalies),
        }

    def process_packet(self, ctx: PacketContext) -> None:
        """Parse and analyze a DNS packet if present."""
        if not ctx.payload or not ctx.src_ip or not ctx.dst_ip:
            return
        if ctx.transport_proto not in ("UDP", "TCP"):
            return
        if ctx.src_port not in DNS_PORTS and ctx.dst_port not in DNS_PORTS:
            return

        dns_payload = ctx.payload
        if ctx.transport_proto == "TCP":
            if len(dns_payload) < 14:
                return
            declared_len = struct.unpack("!H", dns_payload[:2])[0]
            if declared_len > len(dns_payload) - 2:
                return
            dns_payload = dns_payload[2 : 2 + declared_len]

        try:
            dns = dpkt.dns.DNS(dns_payload)
        except Exception:
            return

        # Sanity validation: require at least one question or answer
        if not dns.qd and not dns.an:
            return

        self.total_dns_packets += 1
        is_response = bool(dns.qr)

        if not is_response:
            self._handle_query(ctx, dns)
        else:
            self._handle_response(ctx, dns)

    def _get_or_create_record(self, domain: str, ts: float) -> PassiveDNSRecord:
        rec = self._passive_dns.get(domain)
        if rec is None:
            rec = PassiveDNSRecord(domain=domain, first_seen=ts, last_seen=ts)
            self._passive_dns[domain] = rec
        else:
            rec.last_seen = max(rec.last_seen, ts)
            if ts < rec.first_seen or rec.first_seen == 0.0:
                rec.first_seen = ts
        return rec

    def _handle_query(self, ctx: PacketContext, dns: dpkt.dns.DNS) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        self.total_queries += 1

        for q in dns.qd:
            qname = str(getattr(q, "name", "")).strip(".").lower()
            if not qname:
                continue
            qtype_num = int(getattr(q, "type", 0))
            qtype_str = DNS_QTYPE_MAP.get(qtype_num, f"TYPE{qtype_num}")
            self.qtype_counts[qtype_str] += 1
            self.observed_domains.add(qname)

            rec = self._get_or_create_record(qname, ctx.timestamp)
            rec.query_count += 1
            if qtype_str not in rec.query_types:
                rec.query_types.append(qtype_str)
            if ctx.src_ip not in rec.client_ips:
                rec.client_ips.append(ctx.src_ip)

            # Evaluate label Shannon entropy & tunneling heuristics
            self._inspect_query_anomalies(ctx, qname, qtype_str, rec)

    def _handle_response(self, ctx: PacketContext, dns: dpkt.dns.DNS) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        self.total_responses += 1

        # In a DNS response, dst_ip is the querying client and src_ip is the DNS server
        client_ip = ctx.dst_ip
        server_ip = ctx.src_ip
        rcode_num = int(getattr(dns, "rcode", 0))
        rcode_str = DNS_RCODE_MAP.get(rcode_num, f"RCODE{rcode_num}")
        self.rcode_counts[rcode_str] += 1
        self._client_responses[client_ip] += 1
        self._client_dns_server[client_ip] = server_ip

        queried_names: list[str] = []
        for q in dns.qd:
            qname = str(getattr(q, "name", "")).strip(".").lower()
            if not qname:
                continue
            queried_names.append(qname)
            self.observed_domains.add(qname)
            rec = self._get_or_create_record(qname, ctx.timestamp)
            rec.response_count += 1
            if client_ip not in rec.client_ips:
                rec.client_ips.append(client_ip)
            if rcode_num == 3:  # NXDOMAIN
                rec.nxdomain_count += 1

        if rcode_num == 3:  # NXDOMAIN
            self._client_nxdomains[client_ip] += 1
            self._client_nxdomain_last_ts[client_ip] = ctx.timestamp
            samples = self._client_nxdomain_samples[client_ip]
            for qn in queried_names:
                if qn not in samples and len(samples) < 15:
                    samples.append(qn)

        # Parse answer resource records (A, AAAA, CNAME, TXT, NULL, etc.)
        for rr in dns.an:
            rr_name = str(getattr(rr, "name", "")).strip(".").lower()
            if not rr_name and queried_names:
                rr_name = queried_names[0]
            if not rr_name:
                continue

            self.observed_domains.add(rr_name)
            rec = self._get_or_create_record(rr_name, ctx.timestamp)
            rr_type = int(getattr(rr, "type", 0))

            if rr_type == dpkt.dns.DNS_A and hasattr(rr, "ip"):
                try:
                    ip_str = socket.inet_ntoa(rr.ip)
                    if ip_str not in rec.resolved_ips:
                        rec.resolved_ips.append(ip_str)
                    self.observed_resolved_ips[rr_name].add(ip_str)
                    # Also propagate resolved IP to the original CNAME query target
                    for qn in queried_names:
                        if qn != rr_name:
                            qrec = self._get_or_create_record(qn, ctx.timestamp)
                            if ip_str not in qrec.resolved_ips:
                                qrec.resolved_ips.append(ip_str)
                            self.observed_resolved_ips[qn].add(ip_str)
                except OSError:
                    pass
            elif rr_type == dpkt.dns.DNS_AAAA and hasattr(rr, "ip6"):
                try:
                    ip6_str = socket.inet_ntop(socket.AF_INET6, rr.ip6)
                    if ip6_str not in rec.resolved_ips:
                        rec.resolved_ips.append(ip6_str)
                    self.observed_resolved_ips[rr_name].add(ip6_str)
                except OSError:
                    pass
            elif rr_type == dpkt.dns.DNS_CNAME and hasattr(rr, "cname"):
                cname_val = str(rr.cname).strip(".").lower()
                if cname_val:
                    self.observed_domains.add(cname_val)
                    if cname_val not in rec.cnames:
                        rec.cnames.append(cname_val)
            elif rr_type == dpkt.dns.DNS_TXT:
                txt_items = getattr(rr, "text", None)
                if txt_items:
                    decoded_parts: list[str] = []
                    for item in txt_items:
                        if isinstance(item, bytes):
                            decoded_parts.append(item.decode("utf-8", errors="replace"))
                        else:
                            decoded_parts.append(str(item))
                    txt_str = "".join(decoded_parts)
                    if txt_str and txt_str not in rec.txt_records:
                        rec.txt_records.append(txt_str[:300])
                    base = extract_base_domain(rr_name)
                    if base:
                        self._base_txt_bytes[base] += len(txt_str)

    def _inspect_query_anomalies(
        self,
        ctx: PacketContext,
        qname: str,
        qtype_str: str,
        rec: PassiveDNSRecord,
    ) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None

        if qname.endswith((".arpa", ".local")):
            return

        labels = extract_analyzable_labels(qname)
        base_domain = extract_base_domain(qname)

        # 1. Shannon entropy calculation for DGA detection
        max_ent = 0.0
        max_ent_label = ""
        longest_label = ""
        for lbl in labels:
            if len(lbl) > len(longest_label):
                longest_label = lbl
            ent = shannon_entropy(lbl)
            if len(lbl) >= self.min_dga_label_len and ent > max_ent:
                max_ent = ent
                max_ent_label = lbl

        if max_ent > rec.max_label_entropy:
            rec.max_label_entropy = max_ent

        # Check for abnormal subdomain length (DNS Tunneling)
        is_long_label = len(longest_label) >= self.long_label_threshold
        is_long_qname = len(qname) >= self.long_qname_threshold
        encoded_pattern = ""
        if HEX_RE.match(longest_label):
            encoded_pattern = "hex-encoded"
        elif BASE32_RE.match(longest_label):
            encoded_pattern = "base32-encoded"
        elif BASE64_URL_RE.match(longest_label) and len(longest_label) >= self.long_label_threshold:
            encoded_pattern = "base64/urlsafe-encoded"

        if (is_long_label or is_long_qname) and qname not in self._seen_long_domains:
            self._seen_long_domains.add(qname)
            severity = "HIGH" if (is_long_label and (encoded_pattern or max_ent >= 3.3)) else "MEDIUM"
            enc_note = f" ({encoded_pattern} pattern)" if encoded_pattern else ""
            self._anomalies.append(
                DNSAnomaly(
                    anomaly_type="DNS_TUNNELING_LONG_LABEL",
                    severity=severity,
                    timestamp=ctx.timestamp,
                    src_ip=ctx.src_ip,
                    dst_ip=ctx.dst_ip,
                    domain=qname,
                    score=float(max(len(longest_label), len(qname))),
                    details=(
                        f"Abnormally long DNS label ({len(longest_label)} chars, total QNAME {len(qname)} chars)"
                        f"{enc_note} in {qtype_str} query; strongly indicative of DNS tunneling/exfiltration."
                    ),
                    evidence={
                        "qtype": qtype_str,
                        "longest_label_len": len(longest_label),
                        "qname_len": len(qname),
                        "label_entropy": round(shannon_entropy(longest_label), 4),
                        "encoding_hint": encoded_pattern or "none",
                        "base_domain": base_domain,
                    },
                )
            )
        elif max_ent >= self.entropy_threshold and qname not in self._seen_dga_domains:
            # Flag potential DGA when not already flagged as a long-label tunneling payload
            self._seen_dga_domains.add(qname)
            digit_ratio = sum(ch.isdigit() for ch in max_ent_label) / max(1, len(max_ent_label))
            severity = "HIGH" if (max_ent >= 3.75 or (max_ent >= 3.5 and digit_ratio >= 0.2)) else "MEDIUM"
            self._anomalies.append(
                DNSAnomaly(
                    anomaly_type="DGA_HIGH_ENTROPY",
                    severity=severity,
                    timestamp=ctx.timestamp,
                    src_ip=ctx.src_ip,
                    dst_ip=ctx.dst_ip,
                    domain=qname,
                    score=max_ent,
                    details=(
                        f"High Shannon entropy ({max_ent:.2f} bits) on domain label '{max_ent_label}' "
                        f"(threshold: {self.entropy_threshold:.2f}); potential DGA C2 domain."
                    ),
                    evidence={
                        "label": max_ent_label,
                        "label_length": len(max_ent_label),
                        "entropy_bits": round(max_ent, 4),
                        "digit_ratio": round(digit_ratio, 3),
                        "qtype": qtype_str,
                        "base_domain": base_domain,
                    },
                )
            )

        # 2. Track TXT / NULL query volumes per base domain
        if qtype_str in ("TXT", "NULL") and base_domain:
            self._base_txt_null_count[base_domain] += 1
            self._base_txt_clients[base_domain].add(ctx.src_ip)
            self._base_txt_last_ts[base_domain] = ctx.timestamp

        # 3. Track unique subdomains per base domain (tunneling/beacon indicator)
        if base_domain and qname != base_domain:
            sub = qname[: -(len(base_domain) + 1)]
            if sub and sub != "www":
                self._base_unique_subdomains[base_domain].add(sub)
                self._base_subdomain_clients[base_domain].add(ctx.src_ip)
                self._base_subdomain_last_ts[base_domain] = ctx.timestamp

    def finalize(self) -> None:
        """Evaluate aggregate DNS anomalies (TXT/NULL spikes, subdomain bursts, NXDOMAIN rates)."""
        # 1. High TXT / NULL query volume anomalies
        for base_domain, count in self._base_txt_null_count.items():
            txt_bytes = self._base_txt_bytes.get(base_domain, 0)
            if count >= self.txt_null_threshold or txt_bytes >= 512:
                clients = sorted(self._base_txt_clients.get(base_domain, set()))
                src_ip = clients[0] if clients else "multiple"
                severity = "HIGH" if (count >= self.txt_null_threshold * 2 or txt_bytes >= 512) else "MEDIUM"
                self._anomalies.append(
                    DNSAnomaly(
                        anomaly_type="DNS_TUNNELING_TXT_NULL",
                        severity=severity,
                        timestamp=self._base_txt_last_ts.get(base_domain, 0.0),
                        src_ip=src_ip,
                        dst_ip="DNS-Resolver",
                        domain=base_domain,
                        score=float(count),
                        details=(
                            f"Elevated TXT/NULL query volume to base domain '{base_domain}': "
                            f"{count} queries ({txt_bytes} bytes TXT payload returned); "
                            f"consistent with DNS C2 / data tunneling."
                        ),
                        evidence={
                            "txt_null_queries": count,
                            "txt_response_bytes": txt_bytes,
                            "client_ips": clients,
                        },
                    )
                )

        # 2. High unique subdomain cardinality per base domain
        for base_domain, subs in self._base_unique_subdomains.items():
            if len(subs) >= self.unique_subdomain_threshold:
                avg_len = sum(len(s) for s in subs) / len(subs)
                avg_ent = sum(shannon_entropy(s.replace(".", "")) for s in subs) / len(subs)
                if avg_len >= 12 or avg_ent >= 3.2:
                    clients = sorted(self._base_subdomain_clients.get(base_domain, set()))
                    src_ip = clients[0] if clients else "multiple"
                    self._anomalies.append(
                        DNSAnomaly(
                            anomaly_type="DNS_TUNNELING_HIGH_SUBDOMAINS",
                            severity="HIGH",
                            timestamp=self._base_subdomain_last_ts.get(base_domain, 0.0),
                            src_ip=src_ip,
                            dst_ip="DNS-Resolver",
                            domain=base_domain,
                            score=float(len(subs)),
                            details=(
                                f"{len(subs)} unique high-entropy/encoded subdomains queried under '{base_domain}' "
                                f"(avg length {avg_len:.1f}, avg entropy {avg_ent:.2f} bits); "
                                f"strong indicator of DNS tunneling or DGA burst."
                            ),
                            evidence={
                                "unique_subdomains": len(subs),
                                "avg_subdomain_len": round(avg_len, 2),
                                "avg_subdomain_entropy": round(avg_ent, 4),
                                "sample_subdomains": sorted(subs)[:8],
                                "client_ips": clients,
                            },
                        )
                    )

        # 3. High NXDOMAIN failure rate per client IP
        for client_ip, nx_count in self._client_nxdomains.items():
            total_resp = self._client_responses.get(client_ip, 0)
            if total_resp <= 0:
                continue
            rate = nx_count / total_resp
            if nx_count >= self.nxdomain_min_count and rate >= self.nxdomain_rate_threshold:
                severity = "HIGH" if rate >= 0.50 or nx_count >= 10 else "MEDIUM"
                samples = self._client_nxdomain_samples.get(client_ip, [])
                self._anomalies.append(
                    DNSAnomaly(
                        anomaly_type="HIGH_NXDOMAIN_RATE",
                        severity=severity,
                        timestamp=self._client_nxdomain_last_ts.get(client_ip, 0.0),
                        src_ip=client_ip,
                        dst_ip=self._client_dns_server.get(client_ip, "DNS-Resolver"),
                        domain=samples[0] if samples else "multiple-domains",
                        score=round(rate * 100.0, 2),
                        details=(
                            f"Host {client_ip} experienced an elevated NXDOMAIN failure rate of "
                            f"{rate * 100:.1f}% ({nx_count}/{total_resp} DNS responses); "
                            f"characteristic of active DGA malware or sinkholed C2 infrastructure."
                        ),
                        evidence={
                            "client_ip": client_ip,
                            "nxdomain_count": nx_count,
                            "total_responses": total_resp,
                            "nxdomain_rate_pct": round(rate * 100.0, 2),
                            "sample_nxdomains": samples[:10],
                        },
                    )
                )

        # Sort anomalies by severity desc then timestamp asc
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        self._anomalies.sort(key=lambda a: (-sev_order.get(a.severity, 0), a.timestamp))
