"""Cleartext application-layer protocol forensic analyzer.

Recovers forensic evidence from unencrypted HTTP, FTP, SMTP, and Telnet traffic:
- HTTP: methods, hosts, URIs, User-Agents, Base64-decoded Authorization: Basic headers,
  URL-encoded and JSON POST parameters, and suspicious request heuristics.
- FTP: control session commands, USER/PASS authentication pairs, and file transfer names.
- SMTP: session commands, AUTH credentials, MAIL FROM / RCPT TO envelopes, and RFC-5322 headers.
- Telnet: IAC-stripped interactive transcripts, login credentials, and executed commands.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from email.parser import Parser as EmailParser
from typing import Any, Optional
from urllib.parse import parse_qs

import dpkt

from core.models import (
    CredentialArtifact,
    FTPSessionArtifact,
    HTTPArtifact,
    PacketContext,
    SMTPSessionArtifact,
    TelnetSessionArtifact,
)

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 3000, 5000}
FTP_PORTS = {21, 2121}
SMTP_PORTS = {25, 587, 2525}
TELNET_PORTS = {23, 2323}

SUSPICIOUS_UA_TOKENS = (
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "hydra",
    "gobuster",
    "dirbuster",
    "wfuzz",
    "ffuf",
    "metasploit",
    "powershell",
    "mshta",
    "certutil",
    "bitsadmin",
    "python-requests",
    "python-urllib",
    "curl/",
    "wget/",
    "evilbot",
    "cobalt",
    "meterpreter",
)

SUSPICIOUS_URI_PATTERNS = [
    (re.compile(r"\.\./|\.\.\\", re.IGNORECASE), "Path traversal sequence in URI"),
    (re.compile(r"(union\s+select|or\s+1=1|sleep\(|benchmark\()", re.IGNORECASE), "Possible SQL injection payload"),
    (re.compile(r"(/etc/passwd|/etc/shadow|cmd\.exe|powershell|/bin/sh)", re.IGNORECASE), "OS command/file access pattern in URI"),
    (re.compile(r"(<script|javascript:|onerror=)", re.IGNORECASE), "Possible XSS payload in URI"),
    (re.compile(r"\.(exe|dll|ps1|bat|vbs|hta|scr|elf)(\?|$)", re.IGNORECASE), "Executable or script resource requested"),
]

CREDENTIAL_USER_KEYS = {"user", "username", "login", "uname", "email", "userid", "account", "uid"}
CREDENTIAL_PASS_KEYS = {"pass", "password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "auth", "key"}

TCP_FIN = 0x01
TCP_RST = 0x04

FTP_COMMANDS = {
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV",
    "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR",
    "RNTO", "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST",
    "STAT", "HELP", "NOOP", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT", "EPRT", "EPSV",
    "SIZE", "MDTM",
}

SMTP_COMMANDS = {
    "EHLO", "HELO", "MAIL", "RCPT", "DATA", "RSET", "NOOP", "QUIT", "VRFY", "EXPN",
    "AUTH", "STARTTLS", "HELP",
}


def _safe_b64decode(raw: str) -> Optional[str]:
    """Safely Base64-decode a string with automatic padding repair."""
    token = raw.strip()
    if not token:
        return None
    pad = len(token) % 4
    if pad:
        token += "=" * (4 - pad)
    try:
        decoded = base64.b64decode(token, validate=False)
        return decoded.decode("utf-8", errors="replace")
    except Exception:
        return None


def strip_telnet_iac(data: bytes) -> bytes:
    """Strip Telnet IAC (0xFF) negotiation and subnegotiation sequences."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        byte = data[i]
        if byte == 0xFF:  # IAC
            if i + 1 >= n:
                break
            cmd = data[i + 1]
            if cmd == 0xFF:  # Escaped 0xFF literal
                out.append(0xFF)
                i += 2
            elif cmd in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL, WONT, DO, DONT + option
                i += 3
            elif cmd == 0xFA:  # SB ... IAC SE
                end = data.find(b"\xff\xf0", i + 2)
                if end == -1:
                    break
                i = end + 2
            else:
                i += 2
        else:
            out.append(byte)
            i += 1
    return bytes(out)


def _apply_backspaces(text: str) -> str:
    """Resolve terminal backspace/DEL characters for cleaner command reconstruction."""
    buf: list[str] = []
    for ch in text:
        if ch in ("\x08", "\x7f"):
            if buf:
                buf.pop()
        elif ch == "\x00":
            continue
        else:
            buf.append(ch)
    return "".join(buf)


@dataclass
class _HTTPStreamBuffer:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen: float
    last_seen: float
    buffer: bytearray = field(default_factory=bytearray)
    seen_seqs: set[tuple[int, int]] = field(default_factory=set)
    truncated: bool = False


@dataclass
class _FTPSessionState:
    artifact: FTPSessionArtifact
    pending_user: str = ""
    client_buf: bytearray = field(default_factory=bytearray)
    server_buf: bytearray = field(default_factory=bytearray)
    seen_seqs: set[tuple[str, int, int]] = field(default_factory=set)


@dataclass
class _SMTPSessionState:
    artifact: SMTPSessionArtifact
    in_data_mode: bool = False
    awaiting_auth_login_user: bool = False
    awaiting_auth_login_pass: bool = False
    data_buffer: bytearray = field(default_factory=bytearray)
    client_buf: bytearray = field(default_factory=bytearray)
    seen_seqs: set[tuple[str, int, int]] = field(default_factory=set)


@dataclass
class _TelnetSessionState:
    artifact: TelnetSessionArtifact
    client_line_buf: str = ""
    last_server_prompt: str = ""
    pending_username: str = ""
    transcript_parts: list[str] = field(default_factory=list)
    seen_seqs: set[tuple[str, int, int]] = field(default_factory=set)


class CleartextAnalyzer:
    """Streaming cleartext protocol forensic analyzer for HTTP, FTP, SMTP, and Telnet."""

    def __init__(self, max_stream_bytes: int = 512 * 1024) -> None:
        self.max_stream_bytes = max_stream_bytes
        self.http_artifacts: list[HTTPArtifact] = []
        self.credentials: list[CredentialArtifact] = []
        self.ftp_sessions: list[FTPSessionArtifact] = []
        self.smtp_sessions: list[SMTPSessionArtifact] = []
        self.telnet_sessions: list[TelnetSessionArtifact] = []
        self.observed_domains: dict[str, tuple[float, str]] = {}
        self.observed_urls: list[tuple[str, float, str]] = []
        self.observed_user_agents: list[tuple[str, float, str]] = []

        self._http_streams: dict[tuple[str, int, str, int], _HTTPStreamBuffer] = {}
        self._ftp_states: dict[tuple[str, int, str, int], _FTPSessionState] = {}
        self._smtp_states: dict[tuple[str, int, str, int], _SMTPSessionState] = {}
        self._telnet_states: dict[tuple[str, int, str, int], _TelnetSessionState] = {}
        self._cred_dedup: set[tuple[str, str, str, str, str]] = set()

    def process_packet(self, ctx: PacketContext) -> None:
        """Inspect a single streamed TCP packet for cleartext application artifacts."""
        if ctx.transport_proto != "TCP" or not ctx.src_ip or not ctx.dst_ip:
            return
        if ctx.src_port is None or ctx.dst_port is None:
            return

        payload = ctx.payload
        fin_or_rst = bool(ctx.tcp_flags & (TCP_FIN | TCP_RST))

        if payload:
            self._route_payload(ctx, payload)

        if fin_or_rst:
            self._close_http_stream((ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port))

    def _route_payload(self, ctx: PacketContext, payload: bytes) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        assert ctx.src_port is not None and ctx.dst_port is not None

        dir_key = (ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port)
        rev_key = (ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port)

        # 1. HTTP client->server requests
        if (
            dir_key in self._http_streams
            or payload.startswith(HTTP_METHODS)
            or (ctx.dst_port in HTTP_PORTS and self._looks_like_http_request(payload))
        ):
            self._handle_http_segment(ctx, dir_key, payload)
            return

        # 2. FTP control sessions
        if (
            dir_key in self._ftp_states
            or rev_key in self._ftp_states
            or ctx.dst_port in FTP_PORTS
            or ctx.src_port in FTP_PORTS
            or self._looks_like_ftp(payload)
        ):
            self._handle_ftp_segment(ctx, payload)
            return

        # 3. SMTP sessions
        if (
            dir_key in self._smtp_states
            or rev_key in self._smtp_states
            or ctx.dst_port in SMTP_PORTS
            or ctx.src_port in SMTP_PORTS
            or self._looks_like_smtp(payload)
        ):
            self._handle_smtp_segment(ctx, payload)
            return

        # 4. Telnet sessions
        if (
            dir_key in self._telnet_states
            or rev_key in self._telnet_states
            or ctx.dst_port in TELNET_PORTS
            or ctx.src_port in TELNET_PORTS
            or (len(payload) >= 3 and payload[0] == 0xFF and payload[1] in (0xFB, 0xFC, 0xFD, 0xFE))
        ):
            self._handle_telnet_segment(ctx, payload)

    @staticmethod
    def _looks_like_http_request(payload: bytes) -> bool:
        return payload.startswith(HTTP_METHODS) and b"HTTP/" in payload[:256]

    @staticmethod
    def _looks_like_ftp(payload: bytes) -> bool:
        head = payload[:12].upper()
        if head.startswith((b"USER ", b"PASS ", b"220 ")):
            # Differentiate FTP vs SMTP 220 banner
            if head.startswith(b"220 ") and b"SMTP" in payload[:128].upper():
                return False
            return True
        return False

    @staticmethod
    def _looks_like_smtp(payload: bytes) -> bool:
        upper = payload[:64].upper()
        if upper.startswith((b"EHLO ", b"HELO ", b"MAIL FROM:", b"RCPT TO:")):
            return True
        if upper.startswith(b"220 ") and b"SMTP" in payload[:128].upper():
            return True
        return False

    # ------------------------------------------------------------------
    # HTTP Processing
    # ------------------------------------------------------------------
    def _handle_http_segment(
        self,
        ctx: PacketContext,
        dir_key: tuple[str, int, str, int],
        payload: bytes,
    ) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        assert ctx.src_port is not None and ctx.dst_port is not None

        stream = self._http_streams.get(dir_key)
        if stream is None:
            stream = _HTTPStreamBuffer(
                src_ip=ctx.src_ip,
                src_port=ctx.src_port,
                dst_ip=ctx.dst_ip,
                dst_port=ctx.dst_port,
                first_seen=ctx.timestamp,
                last_seen=ctx.timestamp,
            )
            self._http_streams[dir_key] = stream

        # Deduplicate exact TCP retransmissions
        if ctx.tcp_seq is not None:
            sig = (ctx.tcp_seq, len(payload))
            if sig in stream.seen_seqs:
                return
            stream.seen_seqs.add(sig)

        stream.last_seen = ctx.timestamp
        if len(stream.buffer) + len(payload) <= self.max_stream_bytes:
            stream.buffer.extend(payload)
        else:
            remaining = max(0, self.max_stream_bytes - len(stream.buffer))
            if remaining:
                stream.buffer.extend(payload[:remaining])
            stream.truncated = True

        self._drain_http_stream(stream, final=False)

    def _close_http_stream(self, dir_key: tuple[str, int, str, int]) -> None:
        stream = self._http_streams.pop(dir_key, None)
        if stream is not None and stream.buffer:
            self._drain_http_stream(stream, final=True)

    def _drain_http_stream(self, stream: _HTTPStreamBuffer, final: bool) -> None:
        """Extract all complete HTTP requests currently buffered in a TCP stream."""
        while stream.buffer:
            data = bytes(stream.buffer)

            # Align to next HTTP method if leading garbage exists
            if not data.startswith(HTTP_METHODS):
                next_pos = self._find_next_http_method(data)
                if next_pos == -1:
                    if final:
                        stream.buffer.clear()
                    return
                del stream.buffer[:next_pos]
                data = bytes(stream.buffer)

            header_end = data.find(b"\r\n\r\n")
            sep_len = 4
            if header_end == -1:
                header_end = data.find(b"\n\n")
                sep_len = 2
            if header_end == -1:
                if final:
                    stream.buffer.clear()
                return

            header_block = data[:header_end]
            body_start = header_end + sep_len

            # Determine expected body length from headers
            content_length = 0
            is_chunked = False
            for line in header_block.split(b"\n")[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    k_low = k.strip().lower()
                    v_clean = v.strip().lower()
                    if k_low == b"content-length":
                        try:
                            content_length = max(0, int(v_clean))
                        except ValueError:
                            content_length = 0
                    elif k_low == b"transfer-encoding" and b"chunked" in v_clean:
                        is_chunked = True

            if is_chunked:
                end_marker = data.find(b"0\r\n\r\n", body_start)
                if end_marker == -1:
                    if not final:
                        return
                    msg_end = len(data)
                else:
                    msg_end = end_marker + 5
            else:
                msg_end = body_start + content_length
                if len(data) < msg_end:
                    if not final:
                        return
                    msg_end = len(data)

            raw_msg = data[:msg_end]
            del stream.buffer[:msg_end]
            self._parse_http_request(stream, raw_msg)

    @staticmethod
    def _find_next_http_method(data: bytes) -> int:
        positions = [data.find(m) for m in HTTP_METHODS]
        valid = [p for p in positions if p != -1]
        return min(valid) if valid else -1

    def _parse_http_request(self, stream: _HTTPStreamBuffer, raw_msg: bytes) -> None:
        method = ""
        uri = ""
        version = "1.1"
        headers: dict[str, str] = {}
        body = b""

        try:
            req = dpkt.http.Request(raw_msg)
            method = str(req.method)
            uri = str(req.uri)
            version = str(req.version)
            headers = {
                str(k).lower(): (", ".join(v) if isinstance(v, list) else str(v))
                for k, v in req.headers.items()
            }
            body = bytes(req.body) if req.body else b""
        except (dpkt.NeedData, dpkt.UnpackError, Exception):
            # Fallback manual parse for truncated or non-compliant requests
            sep = b"\r\n\r\n" if b"\r\n\r\n" in raw_msg else b"\n\n"
            head_part, _, body = raw_msg.partition(sep)
            lines = head_part.decode("latin-1", errors="replace").splitlines()
            if not lines:
                return
            parts = lines[0].split()
            if len(parts) < 2:
                return
            method = parts[0].upper()
            uri = parts[1]
            if len(parts) >= 3 and "/" in parts[2]:
                version = parts[2].split("/", 1)[1]
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

        if not method or not uri:
            return

        host = headers.get("host", "").strip() or stream.dst_ip
        clean_host = host.split(":", 1)[0].strip().lower()
        if clean_host and not self._is_ip_literal(clean_host):
            if clean_host not in self.observed_domains:
                self.observed_domains[clean_host] = (
                    stream.last_seen,
                    f"HTTP Host header from {stream.src_ip} -> {stream.dst_ip}:{stream.dst_port}",
                )

        if uri.startswith(("http://", "https://")):
            full_url = uri
        else:
            full_url = f"http://{host}{uri}"

        user_agent = headers.get("user-agent", "")
        referer = headers.get("referer", "")
        content_type = headers.get("content-type", "")
        cookie = headers.get("cookie", "")
        auth_header = headers.get("authorization", "")

        auth_type = ""
        auth_raw = ""
        auth_user = ""
        auth_pass = ""
        suspicious: list[str] = []

        # Inspect Authorization headers
        if auth_header:
            parts = auth_header.split(None, 1)
            auth_type = parts[0]
            auth_raw = parts[1].strip() if len(parts) > 1 else ""
            if auth_type.lower() == "basic" and auth_raw:
                decoded = _safe_b64decode(auth_raw)
                if decoded is not None:
                    if ":" in decoded:
                        auth_user, auth_pass = decoded.split(":", 1)
                    else:
                        auth_user = decoded
                    suspicious.append("Cleartext HTTP Basic Authentication header recovered")
                    self._add_credential(
                        timestamp=stream.last_seen,
                        protocol="HTTP-Basic",
                        src_ip=stream.src_ip,
                        dst_ip=stream.dst_ip,
                        dst_port=stream.dst_port,
                        username=auth_user,
                        password=auth_pass,
                        context=f"{method} {full_url}",
                    )
            elif auth_type.lower() in ("bearer", "digest", "ntlm"):
                suspicious.append(f"Cleartext HTTP {auth_type} Authorization token observed")
                self._add_credential(
                    timestamp=stream.last_seen,
                    protocol=f"HTTP-{auth_type}",
                    src_ip=stream.src_ip,
                    dst_ip=stream.dst_ip,
                    dst_port=stream.dst_port,
                    username=f"<{auth_type} Token>",
                    password=auth_raw[:120],
                    context=f"{method} {full_url}",
                )

        # Inspect POST/PUT/PATCH body parameters
        post_params: dict[str, list[str]] = {}
        body_preview = ""
        if body:
            body_text = body.decode("utf-8", errors="replace")
            body_preview = body_text[:500]
            ct_lower = content_type.lower()
            if "application/x-www-form-urlencoded" in ct_lower or (
                method in ("POST", "PUT", "PATCH") and "=" in body_text and not body_text.lstrip().startswith("{")
            ):
                parsed_qs = parse_qs(body_text, keep_blank_values=True)
                post_params = {k: v for k, v in parsed_qs.items()}
                self._check_form_credentials(stream, method, full_url, post_params, suspicious)
            elif "application/json" in ct_lower or body_text.lstrip().startswith("{"):
                try:
                    obj = json.loads(body_text)
                    if isinstance(obj, dict):
                        flat_params = {str(k): [str(v)] for k, v in obj.items() if not isinstance(v, (dict, list))}
                        post_params = flat_params
                        self._check_form_credentials(stream, method, full_url, flat_params, suspicious)
                except Exception:
                    pass

        # Suspicious User-Agent checks
        ua_low = user_agent.lower()
        if not user_agent:
            suspicious.append("Missing User-Agent header")
        else:
            self.observed_user_agents.append((user_agent, stream.last_seen, f"{stream.src_ip} -> {full_url}"))
            for token in SUSPICIOUS_UA_TOKENS:
                if token in ua_low:
                    suspicious.append(f"Suspicious User-Agent token detected: '{token}'")
                    break

        # Suspicious URI checks
        for pattern, desc in SUSPICIOUS_URI_PATTERNS:
            if pattern.search(uri):
                suspicious.append(desc)

        if self._is_ip_literal(clean_host):
            suspicious.append(f"Direct IP literal HTTP Host header ({clean_host})")

        artifact = HTTPArtifact(
            timestamp=stream.last_seen,
            src_ip=stream.src_ip,
            src_port=stream.src_port,
            dst_ip=stream.dst_ip,
            dst_port=stream.dst_port,
            method=method,
            host=host,
            uri=uri,
            full_url=full_url,
            http_version=version,
            user_agent=user_agent,
            referer=referer,
            content_type=content_type,
            cookie=cookie[:300],
            auth_type=auth_type,
            auth_raw=auth_raw[:160],
            auth_decoded_user=auth_user,
            auth_decoded_pass=auth_pass,
            post_params=post_params,
            body_preview=body_preview,
            suspicious_indicators=suspicious,
        )
        self.http_artifacts.append(artifact)
        self.observed_urls.append((full_url, stream.last_seen, f"{stream.src_ip} -> {stream.dst_ip}:{stream.dst_port}"))

    def _check_form_credentials(
        self,
        stream: _HTTPStreamBuffer,
        method: str,
        full_url: str,
        params: dict[str, list[str]],
        suspicious: list[str],
    ) -> None:
        found_user = ""
        found_pass = ""
        for k, vals in params.items():
            k_low = k.strip().lower()
            val = vals[0] if vals else ""
            if not val:
                continue
            if k_low in CREDENTIAL_USER_KEYS or any(tok in k_low for tok in ("user", "login", "email")):
                if not found_user:
                    found_user = val
            if k_low in CREDENTIAL_PASS_KEYS or any(tok in k_low for tok in ("pass", "pwd", "secret", "token")):
                if not found_pass:
                    found_pass = val

        if found_pass:
            suspicious.append("Cleartext credentials submitted in HTTP body parameters")
            self._add_credential(
                timestamp=stream.last_seen,
                protocol="HTTP-POST",
                src_ip=stream.src_ip,
                dst_ip=stream.dst_ip,
                dst_port=stream.dst_port,
                username=found_user or "<unknown>",
                password=found_pass,
                context=f"{method} {full_url}",
            )

    # ------------------------------------------------------------------
    # FTP Processing
    # ------------------------------------------------------------------
    def _handle_ftp_segment(self, ctx: PacketContext, payload: bytes) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        assert ctx.src_port is not None and ctx.dst_port is not None

        dir_key = (ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port)
        rev_key = (ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port)

        if dir_key in self._ftp_states:
            state = self._ftp_states[dir_key]
            is_client = True
        elif rev_key in self._ftp_states:
            state = self._ftp_states[rev_key]
            is_client = False
        else:
            if ctx.dst_port in FTP_PORTS or payload[:5].upper().startswith((b"USER ", b"PASS ")):
                client_ip, client_port, server_ip, server_port = ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port
                is_client = True
            else:
                client_ip, client_port, server_ip, server_port = ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port
                is_client = False

            key = (client_ip, client_port, server_ip, server_port)
            artifact = FTPSessionArtifact(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=server_ip,
                dst_port=server_port,
                first_seen=ctx.timestamp,
                last_seen=ctx.timestamp,
            )
            state = _FTPSessionState(artifact=artifact)
            self._ftp_states[key] = state

        direction = "C->S" if is_client else "S->C"
        if ctx.tcp_seq is not None:
            sig = (direction, ctx.tcp_seq, len(payload))
            if sig in state.seen_seqs:
                return
            state.seen_seqs.add(sig)

        state.artifact.last_seen = ctx.timestamp
        buf = state.client_buf if is_client else state.server_buf
        if len(buf) + len(payload) <= self.max_stream_bytes:
            buf.extend(payload)

        while b"\n" in buf:
            idx = buf.find(b"\n")
            raw_line = bytes(buf[: idx + 1])
            del buf[: idx + 1]
            line = raw_line.decode("latin-1", errors="replace").strip()
            if not line:
                continue
            self._process_ftp_line(state, is_client, line, ctx.timestamp)

    def _process_ftp_line(
        self, state: _FTPSessionState, is_client: bool, line: str, ts: float
    ) -> None:
        if is_client:
            parts = line.split(None, 1)
            cmd = parts[0].upper()
            arg = parts[1].strip() if len(parts) > 1 else ""
            if cmd in FTP_COMMANDS:
                state.artifact.commands.append({"timestamp": ts, "direction": "C->S", "text": line})
                if cmd == "USER":
                    state.pending_user = arg
                    state.artifact.username = arg
                elif cmd == "PASS":
                    state.artifact.password = arg
                    self._add_credential(
                        timestamp=ts,
                        protocol="FTP",
                        src_ip=state.artifact.src_ip,
                        dst_ip=state.artifact.dst_ip,
                        dst_port=state.artifact.dst_port,
                        username=state.pending_user or state.artifact.username or "<unknown>",
                        password=arg,
                        context=f"FTP control session to {state.artifact.dst_ip}:{state.artifact.dst_port}",
                    )
                elif cmd in ("RETR", "STOR", "APPE") and arg:
                    entry = f"{cmd} {arg}"
                    if entry not in state.artifact.transferred_files:
                        state.artifact.transferred_files.append(entry)
        else:
            state.artifact.commands.append({"timestamp": ts, "direction": "S->C", "text": line[:200]})
            if line.startswith("230"):
                state.artifact.auth_status = "success"
            elif line.startswith("530"):
                state.artifact.auth_status = "failed"

    # ------------------------------------------------------------------
    # SMTP Processing
    # ------------------------------------------------------------------
    def _handle_smtp_segment(self, ctx: PacketContext, payload: bytes) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        assert ctx.src_port is not None and ctx.dst_port is not None

        dir_key = (ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port)
        rev_key = (ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port)

        if dir_key in self._smtp_states:
            state = self._smtp_states[dir_key]
            is_client = True
        elif rev_key in self._smtp_states:
            state = self._smtp_states[rev_key]
            is_client = False
        else:
            if ctx.dst_port in SMTP_PORTS or payload[:10].upper().startswith((b"EHLO ", b"HELO ", b"MAIL FROM:")):
                client_ip, client_port, server_ip, server_port = ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port
                is_client = True
            else:
                client_ip, client_port, server_ip, server_port = ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port
                is_client = False

            key = (client_ip, client_port, server_ip, server_port)
            artifact = SMTPSessionArtifact(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=server_ip,
                dst_port=server_port,
                first_seen=ctx.timestamp,
                last_seen=ctx.timestamp,
            )
            state = _SMTPSessionState(artifact=artifact)
            self._smtp_states[key] = state

        direction = "C->S" if is_client else "S->C"
        if ctx.tcp_seq is not None:
            sig = (direction, ctx.tcp_seq, len(payload))
            if sig in state.seen_seqs:
                return
            state.seen_seqs.add(sig)

        state.artifact.last_seen = ctx.timestamp
        if not is_client:
            return

        if len(state.client_buf) + len(payload) <= self.max_stream_bytes:
            state.client_buf.extend(payload)

        self._drain_smtp_client(state, ctx.timestamp)

    def _drain_smtp_client(self, state: _SMTPSessionState, ts: float) -> None:
        buf = state.client_buf
        while b"\n" in buf:
            idx = buf.find(b"\n")
            raw_line = bytes(buf[: idx + 1])
            del buf[: idx + 1]
            text_line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")

            if state.in_data_mode:
                if text_line == ".":
                    state.in_data_mode = False
                    self._parse_smtp_data(state)
                    state.data_buffer.clear()
                else:
                    if len(state.data_buffer) + len(raw_line) <= self.max_stream_bytes:
                        state.data_buffer.extend(raw_line)
                continue

            if not text_line:
                continue

            # Handle AUTH LOGIN challenge-response lines
            if state.awaiting_auth_login_user:
                decoded = _safe_b64decode(text_line) or text_line
                state.artifact.auth_user = decoded
                state.awaiting_auth_login_user = False
                state.awaiting_auth_login_pass = True
                continue
            if state.awaiting_auth_login_pass:
                decoded = _safe_b64decode(text_line) or text_line
                state.artifact.auth_pass = decoded
                state.awaiting_auth_login_pass = False
                self._add_credential(
                    timestamp=ts,
                    protocol="SMTP",
                    src_ip=state.artifact.src_ip,
                    dst_ip=state.artifact.dst_ip,
                    dst_port=state.artifact.dst_port,
                    username=state.artifact.auth_user or "<unknown>",
                    password=decoded,
                    context=f"SMTP AUTH LOGIN to {state.artifact.dst_ip}:{state.artifact.dst_port}",
                )
                continue

            upper = text_line.upper()
            verb = upper.split(None, 1)[0] if upper.split() else ""
            if verb in SMTP_COMMANDS or upper.startswith(("MAIL FROM:", "RCPT TO:")):
                state.artifact.commands.append(text_line[:240])

            if upper.startswith(("EHLO ", "HELO ")):
                state.artifact.helo = text_line.split(None, 1)[1].strip()
            elif upper.startswith("MAIL FROM:"):
                addr = text_line.split(":", 1)[1].strip()
                state.artifact.mail_from = addr
                self._extract_email_domain(addr, ts, f"SMTP MAIL FROM {addr} ({state.artifact.src_ip} -> {state.artifact.dst_ip})")
            elif upper.startswith("RCPT TO:"):
                addr = text_line.split(":", 1)[1].strip()
                if addr and addr not in state.artifact.rcpt_to:
                    state.artifact.rcpt_to.append(addr)
                self._extract_email_domain(addr, ts, f"SMTP RCPT TO {addr} ({state.artifact.src_ip} -> {state.artifact.dst_ip})")
            elif upper == "DATA":
                state.in_data_mode = True
            elif upper.startswith("AUTH PLAIN "):
                token = text_line.split(None, 2)[2].strip()
                decoded = _safe_b64decode(token)
                if decoded:
                    parts = decoded.split("\x00")
                    user = parts[1] if len(parts) >= 3 else (parts[0] if parts else "")
                    pwd = parts[2] if len(parts) >= 3 else (parts[1] if len(parts) >= 2 else "")
                    state.artifact.auth_user = user
                    state.artifact.auth_pass = pwd
                    if pwd:
                        self._add_credential(
                            timestamp=ts,
                            protocol="SMTP",
                            src_ip=state.artifact.src_ip,
                            dst_ip=state.artifact.dst_ip,
                            dst_port=state.artifact.dst_port,
                            username=user or "<unknown>",
                            password=pwd,
                            context=f"SMTP AUTH PLAIN to {state.artifact.dst_ip}:{state.artifact.dst_port}",
                        )
            elif upper.startswith("AUTH LOGIN"):
                parts = text_line.split(None, 2)
                if len(parts) == 3:
                    state.artifact.auth_user = _safe_b64decode(parts[2]) or parts[2]
                    state.awaiting_auth_login_pass = True
                else:
                    state.awaiting_auth_login_user = True

    def _parse_smtp_data(self, state: _SMTPSessionState) -> None:
        raw_email = state.data_buffer.decode("utf-8", errors="replace")
        if not raw_email.strip():
            return
        try:
            msg = EmailParser().parsestr(raw_email)
            state.artifact.subject = str(msg.get("Subject", "")).strip()
            state.artifact.from_header = str(msg.get("From", "")).strip()
            state.artifact.to_header = str(msg.get("To", "")).strip()
            state.artifact.date_header = str(msg.get("Date", "")).strip()
            state.artifact.x_mailer = str(msg.get("X-Mailer", "")).strip()

            if msg.is_multipart():
                body_chunks: list[str] = []
                for part in msg.walk():
                    fname = part.get_filename()
                    if fname and fname not in state.artifact.attachments:
                        state.artifact.attachments.append(fname)
                    elif part.get_content_type() == "text/plain" and not body_chunks:
                        payload = part.get_payload(decode=False)
                        if isinstance(payload, str):
                            body_chunks.append(payload.strip())
                state.artifact.body_preview = "\n".join(body_chunks)[:400]
            else:
                payload = msg.get_payload(decode=False)
                if isinstance(payload, str):
                    state.artifact.body_preview = payload.strip()[:400]
        except Exception:
            state.artifact.body_preview = raw_email[:400]

    def _extract_email_domain(self, addr: str, ts: float, context: str) -> None:
        m = re.search(r"@([A-Za-z0-9.-]+)", addr)
        if m:
            domain = m.group(1).strip(".").lower()
            if domain and "." in domain and not self._is_ip_literal(domain):
                if domain not in self.observed_domains:
                    self.observed_domains[domain] = (ts, context)

    # ------------------------------------------------------------------
    # Telnet Processing
    # ------------------------------------------------------------------
    def _handle_telnet_segment(self, ctx: PacketContext, payload: bytes) -> None:
        assert ctx.src_ip is not None and ctx.dst_ip is not None
        assert ctx.src_port is not None and ctx.dst_port is not None

        dir_key = (ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port)
        rev_key = (ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port)

        if dir_key in self._telnet_states:
            state = self._telnet_states[dir_key]
            is_client = True
        elif rev_key in self._telnet_states:
            state = self._telnet_states[rev_key]
            is_client = False
        else:
            if ctx.dst_port in TELNET_PORTS:
                client_ip, client_port, server_ip, server_port = ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port
                is_client = True
            else:
                client_ip, client_port, server_ip, server_port = ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port
                is_client = False

            key = (client_ip, client_port, server_ip, server_port)
            artifact = TelnetSessionArtifact(
                src_ip=client_ip,
                src_port=client_port,
                dst_ip=server_ip,
                dst_port=server_port,
                first_seen=ctx.timestamp,
                last_seen=ctx.timestamp,
            )
            state = _TelnetSessionState(artifact=artifact)
            self._telnet_states[key] = state

        direction = "C->S" if is_client else "S->C"
        if ctx.tcp_seq is not None:
            sig = (direction, ctx.tcp_seq, len(payload))
            if sig in state.seen_seqs:
                return
            state.seen_seqs.add(sig)

        state.artifact.last_seen = ctx.timestamp
        cleaned = strip_telnet_iac(payload)
        if not cleaned:
            return
        text = cleaned.decode("latin-1", errors="replace")

        if is_client:
            state.client_line_buf += text
            while "\n" in state.client_line_buf or "\r" in state.client_line_buf:
                # Split at earliest CR/LF
                cr = state.client_line_buf.find("\r")
                lf = state.client_line_buf.find("\n")
                splits = [p for p in (cr, lf) if p != -1]
                pos = min(splits)
                raw_cmd = state.client_line_buf[:pos]
                # Skip \r\n or \r\x00 pair
                next_idx = pos + 1
                if next_idx < len(state.client_line_buf) and state.client_line_buf[next_idx] in ("\n", "\x00"):
                    next_idx += 1
                state.client_line_buf = state.client_line_buf[next_idx:]

                cmd = _apply_backspaces(raw_cmd).strip()
                if not cmd:
                    continue

                prompt_low = state.last_server_prompt.lower()
                if any(tok in prompt_low for tok in ("login:", "username:", "user:")):
                    state.pending_username = cmd
                    state.last_server_prompt = ""
                    state.transcript_parts.append(f"[CLIENT] {cmd}")
                elif any(tok in prompt_low for tok in ("password:", "pass:")):
                    user = state.pending_username or "<unknown>"
                    state.artifact.credentials_detected.append({"username": user, "password": cmd})
                    self._add_credential(
                        timestamp=ctx.timestamp,
                        protocol="Telnet",
                        src_ip=state.artifact.src_ip,
                        dst_ip=state.artifact.dst_ip,
                        dst_port=state.artifact.dst_port,
                        username=user,
                        password=cmd,
                        context=f"Telnet login to {state.artifact.dst_ip}:{state.artifact.dst_port}",
                    )
                    state.last_server_prompt = ""
                    state.transcript_parts.append("[CLIENT] <password>")
                else:
                    state.artifact.commands.append(cmd)
                    state.transcript_parts.append(f"[CLIENT] {cmd}")
        else:
            stripped = _apply_backspaces(text).strip()
            if stripped:
                state.last_server_prompt = stripped[-120:]
                if len(state.transcript_parts) < 100:
                    state.transcript_parts.append(f"[SERVER] {stripped[:200]}")

    # ------------------------------------------------------------------
    # Finalization & Helpers
    # ------------------------------------------------------------------
    def finalize(self) -> None:
        """Flush all remaining in-memory cleartext session buffers at EOF."""
        for key in list(self._http_streams.keys()):
            self._close_http_stream(key)

        for state in self._ftp_states.values():
            if state.client_buf:
                leftover = state.client_buf.decode("latin-1", errors="replace").strip()
                if leftover:
                    self._process_ftp_line(state, True, leftover, state.artifact.last_seen)
            if state.artifact.commands or state.artifact.username:
                self.ftp_sessions.append(state.artifact)
        self._ftp_states.clear()

        for state in self._smtp_states.values():
            if state.in_data_mode and state.data_buffer:
                self._parse_smtp_data(state)
            if state.artifact.commands or state.artifact.mail_from or state.artifact.subject:
                self.smtp_sessions.append(state.artifact)
        self._smtp_states.clear()

        for state in self._telnet_states.values():
            leftover = _apply_backspaces(state.client_line_buf).strip()
            if leftover:
                state.artifact.commands.append(leftover)
                state.transcript_parts.append(f"[CLIENT] {leftover}")
            state.artifact.transcript_preview = "\n".join(state.transcript_parts)[:1200]
            if state.artifact.commands or state.artifact.credentials_detected or state.artifact.transcript_preview:
                self.telnet_sessions.append(state.artifact)
        self._telnet_states.clear()

    def _add_credential(
        self,
        timestamp: float,
        protocol: str,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        username: str,
        password: str,
        context: str,
    ) -> None:
        dedup_key = (protocol, src_ip, dst_ip, username, password)
        if dedup_key in self._cred_dedup:
            return
        self._cred_dedup.add(dedup_key)
        self.credentials.append(
            CredentialArtifact(
                timestamp=timestamp,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                username=username,
                password=password,
                context=context,
            )
        )

    @staticmethod
    def _is_ip_literal(value: str) -> bool:
        if not value:
            return False
        if ":" in value:  # IPv6
            return True
        parts = value.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return True
        return False
