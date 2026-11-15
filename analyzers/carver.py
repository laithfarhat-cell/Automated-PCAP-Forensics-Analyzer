"""HTTP object carving via TCP stream reassembly and Threat Intelligence watchlist matching.

Provides:
- Pure-Python magic-byte MIME type inspection and Content-Type masquerading detection.
- Sequence-ordered, memory-bounded TCP stream reassembly for HTTP/1.x response carving (200 OK),
  supporting Content-Length, Transfer-Encoding: chunked, gzip/deflate decoding, and safe
  quarantined extraction (read-only, non-executable) into ``extracted_artifacts/``.
- ThreatIntelMatcher cross-referencing observed IPs/CIDRs, domains/subdomains, URLs,
  User-Agents, and MD5/SHA-256 hashes against a local JSON watchlist (``data/iocs.json``).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import ipaddress
import json
import os
import re
import zipfile
import zlib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlparse

import dpkt

from core.models import CarvedArtifact, IoCMatch, PacketContext

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04

HTTP_REQ_PREFIXES = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
)

MAX_DECOMPRESSED_BYTES = 50 * 1024 * 1024  # 50 MB zip-bomb safety cap

EXTENSION_BY_MIME: dict[str, str] = {
    "application/x-dosexec": ".exe",
    "application/x-elf": ".elf",
    "application/x-mach-binary": ".macho",
    "application/pdf": ".pdf",
    "application/zip": ".zip",
    "application/gzip": ".gz",
    "application/x-7z-compressed": ".7z",
    "application/x-rar-compressed": ".rar",
    "application/x-bzip2": ".bz2",
    "application/x-xz": ".xz",
    "application/x-tar": ".tar",
    "application/x-ole-storage": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/java-archive": ".jar",
    "application/x-sqlite3": ".sqlite",
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "text/x-powershell": ".ps1",
    "text/x-shellscript": ".sh",
    "text/x-python": ".py",
    "text/x-batch": ".bat",
    "application/javascript": ".js",
    "text/html": ".html",
    "application/xml": ".xml",
    "application/json": ".json",
    "text/plain": ".txt",
}

EXECUTABLE_MIMES = {
    "application/x-dosexec",
    "application/x-elf",
    "application/x-mach-binary",
    "application/java-archive",
}

SCRIPT_MIMES = {
    "text/x-powershell",
    "text/x-shellscript",
    "text/x-python",
    "text/x-batch",
    "application/javascript",
}

ARCHIVE_MIMES = {
    "application/zip",
    "application/gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-tar",
}


@dataclass(slots=True)
class MagicDetection:
    """Result of magic-byte inspection on a carved payload."""

    mime_type: str
    description: str
    is_executable: bool = False
    is_script: bool = False
    is_archive: bool = False


def detect_magic_mime(data: bytes) -> MagicDetection:
    """Detect file MIME type and forensic classification purely from magic bytes."""
    if not data:
        return MagicDetection("application/x-empty", "Empty payload")

    # Binary magic signatures
    if data.startswith(b"MZ") and len(data) >= 2:
        return MagicDetection("application/x-dosexec", "Windows PE/DOS Executable (MZ)", is_executable=True)
    if data.startswith(b"\x7fELF"):
        return MagicDetection("application/x-elf", "Linux/Unix ELF Executable", is_executable=True)
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return MagicDetection("application/x-mach-binary", "macOS Mach-O Binary", is_executable=True)
    if data.startswith(b"%PDF-"):
        return MagicDetection("application/pdf", "PDF Document")
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return _inspect_zip_magic(data)
    if data.startswith(b"\x1f\x8b\x08"):
        return MagicDetection("application/gzip", "GZIP Compressed Archive", is_archive=True)
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return MagicDetection("application/x-7z-compressed", "7-Zip Archive", is_archive=True)
    if data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return MagicDetection("application/x-rar-compressed", "RAR Archive", is_archive=True)
    if data.startswith(b"BZh"):
        return MagicDetection("application/x-bzip2", "BZIP2 Archive", is_archive=True)
    if data.startswith(b"\xfd7zXZ\x00"):
        return MagicDetection("application/x-xz", "XZ Compressed Archive", is_archive=True)
    if len(data) > 262 and data[257:262] == b"ustar":
        return MagicDetection("application/x-tar", "POSIX TAR Archive", is_archive=True)
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return MagicDetection("image/png", "PNG Image")
    if data.startswith(b"\xff\xd8\xff"):
        return MagicDetection("image/jpeg", "JPEG Image")
    if data.startswith((b"GIF87a", b"GIF89a")):
        return MagicDetection("image/gif", "GIF Image")
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return MagicDetection("image/webp", "WebP Image")
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return MagicDetection("application/x-ole-storage", "Microsoft OLE2 Compound Document")
    if data.startswith(b"SQLite format 3\x00"):
        return MagicDetection("application/x-sqlite3", "SQLite 3 Database")
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return MagicDetection("application/vnd.tcpdump.pcap", "Packet Capture File")

    # Text & script heuristics
    sample = data[:4096]
    if b"\x00" not in sample:
        try:
            text = sample.decode("utf-8")
        except UnicodeDecodeError:
            text = sample.decode("latin-1", errors="ignore")

        stripped = text.lstrip()
        low = stripped.lower()

        if stripped.startswith("#!"):
            first_line = stripped.splitlines()[0].lower()
            if "python" in first_line:
                return MagicDetection("text/x-python", "Python Script", is_script=True)
            return MagicDetection("text/x-shellscript", "Shell Script", is_script=True)

        if any(tok in low for tok in ("invoke-expression", "new-object net.webclient", "-encodedcommand", "invoke-webrequest", "start-process", "$env:", "param(")):
            return MagicDetection("text/x-powershell", "PowerShell Script", is_script=True)

        if low.startswith("@echo off") or ("cmd.exe /c" in low and "echo " in low):
            return MagicDetection("text/x-batch", "Windows Batch Script", is_script=True)

        if low.startswith(("<!doctype html", "<html")):
            return MagicDetection("text/html", "HTML Document")

        if low.startswith("<?xml"):
            return MagicDetection("application/xml", "XML Document")

        if stripped.startswith(("{", "[")):
            try:
                json.loads(data.decode("utf-8"))
                return MagicDetection("application/json", "JSON Document")
            except Exception:
                pass

        if any(tok in low for tok in ("function(", "document.write", "window.location", "eval(", "const ", "let ")) and (";" in low or "{" in low):
            return MagicDetection("application/javascript", "JavaScript Source", is_script=True)

        if any(tok in low for tok in ("import os", "import sys", "def ", "if __name__ ==")):
            return MagicDetection("text/x-python", "Python Script", is_script=True)

        # Check printable ratio
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
        if text and (printable / len(text)) >= 0.90:
            return MagicDetection("text/plain", "Plain Text Document")

    return MagicDetection("application/octet-stream", "Generic Binary Data")


def _inspect_zip_magic(data: bytes) -> MagicDetection:
    """Refine ZIP archives into Office OOXML or JAR where detectable."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if any(n.startswith("word/") for n in names):
                return MagicDetection(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "Microsoft Word OOXML Document (DOCX)",
                    is_archive=True,
                )
            if any(n.startswith("xl/") for n in names):
                return MagicDetection(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "Microsoft Excel OOXML Spreadsheet (XLSX)",
                    is_archive=True,
                )
            if any(n.startswith("ppt/") for n in names):
                return MagicDetection(
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "Microsoft PowerPoint OOXML Presentation (PPTX)",
                    is_archive=True,
                )
            if "META-INF/MANIFEST.MF" in names:
                return MagicDetection(
                    "application/java-archive",
                    "Java Archive (JAR)",
                    is_executable=True,
                    is_archive=True,
                )
    except Exception:
        pass
    return MagicDetection("application/zip", "ZIP Archive", is_archive=True)


def is_mime_mismatch(declared_content_type: str, detected_mime: str) -> bool:
    """Return True if declared Content-Type meaningfully contradicts magic-byte MIME."""
    if not declared_content_type or not detected_mime:
        return False
    declared = declared_content_type.split(";", 1)[0].strip().lower()
    detected = detected_mime.lower()
    if not declared or declared == detected:
        return False

    # Generic catch-all types are not spoofing unless they hide an executable? Actually
    # application/octet-stream is legitimate for binaries, so don't false-positive on it.
    if declared in ("application/octet-stream", "binary/octet-stream"):
        return False
    # Serving scripts as text/plain is very common and not necessarily masquerading
    if declared == "text/plain" and detected.startswith("text/"):
        return False
    if declared in ("application/x-javascript", "text/javascript") and detected == "application/javascript":
        return False
    if declared == "text/xml" and detected == "application/xml":
        return False
    if declared in ("application/x-msdownload", "application/vnd.microsoft.portable-executable") and detected == "application/x-dosexec":
        return False
    if declared in ("application/x-zip-compressed", "application/x-zip") and detected == "application/zip":
        return False
    if declared == "image/jpg" and detected == "image/jpeg":
        return False

    # Any remaining mismatch where binary/executable/image/pdf types diverge is flagged
    if detected in EXECUTABLE_MIMES or declared.startswith("image/") or declared == "application/pdf":
        return True
    if declared.startswith("text/") and detected not in ("text/plain", "text/html", "application/json", "application/xml") and not detected.startswith("text/"):
        return True
    return False


def _sanitize_filename(name: str, fallback_ext: str = ".bin") -> str:
    """Strictly sanitize a carved filename to prevent path traversal or shell issues."""
    cleaned = unquote(name or "").replace("\\", "/")
    cleaned = os.path.basename(cleaned).strip()
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", cleaned)
    cleaned = cleaned.lstrip(".")
    if not cleaned or cleaned in (".", ".."):
        cleaned = f"carved_object{fallback_ext}"
    if len(cleaned) > 100:
        stem, ext = os.path.splitext(cleaned)
        cleaned = stem[:88] + ext[:12]
    return cleaned


def _find_chunked_body_end(data: bytes, body_start: int) -> int:
    """Return byte offset immediately after a complete HTTP chunked body, or -1 if incomplete."""
    pos = body_start
    total = len(data)
    while True:
        crlf = data.find(b"\r\n", pos)
        if crlf == -1:
            return -1
        size_line = data[pos:crlf].split(b";", 1)[0].strip()
        if not size_line:
            return -1
        try:
            chunk_size = int(size_line, 16)
        except ValueError:
            return -1
        pos = crlf + 2
        if chunk_size == 0:
            # Terminal chunk: either immediate \r\n or trailer headers terminated by \r\n\r\n
            if data[pos : pos + 2] == b"\r\n":
                return pos + 2
            trailer_end = data.find(b"\r\n\r\n", pos)
            if trailer_end != -1:
                return trailer_end + 4
            return -1
        if pos + chunk_size + 2 > total:
            return -1
        pos += chunk_size + 2


def _safe_decompress(body: bytes, content_encoding: str) -> bytes:
    """Decompress gzip/deflate HTTP payloads with a strict memory cap."""
    enc = content_encoding.lower().strip()
    if not enc or enc == "identity":
        return body
    try:
        if "gzip" in enc:
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as gf:
                out = gf.read(MAX_DECOMPRESSED_BYTES + 1)
                return out[:MAX_DECOMPRESSED_BYTES]
        if "deflate" in enc:
            decomp = zlib.decompressobj()
            out = decomp.decompress(body, MAX_DECOMPRESSED_BYTES)
            return out
    except Exception:
        return body
    return body


class _TCPSequenceBuffer:
    """Memory-bounded, sequence-ordered TCP byte stream reassembler."""

    def __init__(self, max_bytes: int = 25 * 1024 * 1024) -> None:
        self.max_bytes = max_bytes
        self.next_seq: Optional[int] = None
        self.assembled: bytearray = bytearray()
        self.pending: dict[int, bytes] = {}
        self.pending_bytes: int = 0
        self.truncated: bool = False

    def set_initial_seq_from_syn(self, syn_seq: int) -> None:
        if self.next_seq is None:
            self.next_seq = (syn_seq + 1) & 0xFFFFFFFF

    def add_segment(self, seq: Optional[int], data: bytes) -> None:
        if not data or self.truncated:
            return

        if seq is None:
            self._append_bounded(data)
            return

        if self.next_seq is None:
            self.next_seq = seq

        diff = (seq - self.next_seq) & 0xFFFFFFFF
        if diff == 0:
            self._append_bounded(data)
            self.next_seq = (self.next_seq + len(data)) & 0xFFFFFFFF
            self._flush_pending()
        elif diff >= 0x80000000:
            # Segment starts before next_seq (retransmission or partial overlap)
            overlap = (self.next_seq - seq) & 0xFFFFFFFF
            if overlap < len(data):
                fresh = data[overlap:]
                self._append_bounded(fresh)
                self.next_seq = (self.next_seq + len(fresh)) & 0xFFFFFFFF
                self._flush_pending()
        else:
            # Out-of-order future segment
            if self.pending_bytes + len(data) <= self.max_bytes:
                existing = self.pending.get(seq)
                if existing is None or len(data) > len(existing):
                    if existing is not None:
                        self.pending_bytes -= len(existing)
                    self.pending[seq] = data
                    self.pending_bytes += len(data)

    def _flush_pending(self) -> None:
        while self.pending and self.next_seq is not None:
            # Find any pending segment at or overlapping next_seq
            progressed = False
            for seq in sorted(self.pending.keys(), key=lambda s: ((s - self.next_seq) & 0xFFFFFFFF)):
                diff = (seq - self.next_seq) & 0xFFFFFFFF
                if diff == 0:
                    seg = self.pending.pop(seq)
                    self.pending_bytes -= len(seg)
                    self._append_bounded(seg)
                    self.next_seq = (self.next_seq + len(seg)) & 0xFFFFFFFF
                    progressed = True
                    break
                elif diff >= 0x80000000:
                    seg = self.pending.pop(seq)
                    self.pending_bytes -= len(seg)
                    overlap = (self.next_seq - seq) & 0xFFFFFFFF
                    if overlap < len(seg):
                        fresh = seg[overlap:]
                        self._append_bounded(fresh)
                        self.next_seq = (self.next_seq + len(fresh)) & 0xFFFFFFFF
                    progressed = True
                    break
                else:
                    # Earliest remaining segment is still ahead of next_seq
                    break
            if not progressed:
                break

    def force_flush_all(self) -> None:
        """At stream EOF, append any remaining out-of-order segments in sequence order."""
        if not self.pending:
            return
        base = self.next_seq or 0
        for seq in sorted(self.pending.keys(), key=lambda s: ((s - base) & 0xFFFFFFFF)):
            self._append_bounded(self.pending[seq])
        self.pending.clear()
        self.pending_bytes = 0

    def _append_bounded(self, data: bytes) -> None:
        avail = self.max_bytes - len(self.assembled)
        if avail <= 0:
            self.truncated = True
            return
        if len(data) <= avail:
            self.assembled.extend(data)
        else:
            self.assembled.extend(data[:avail])
            self.truncated = True


@dataclass
class _HTTPRequestMeta:
    timestamp: float
    method: str
    host: str
    uri: str


@dataclass
class _HTTPConversationState:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    last_seen: float
    c2s_buf: _TCPSequenceBuffer
    s2c_buf: _TCPSequenceBuffer
    pending_requests: deque[_HTTPRequestMeta] = field(default_factory=deque)
    seen_c2s_offset: int = 0


class HTTPCarver:
    """Reassembles HTTP TCP streams, carves 200 OK payloads, computes hashes, and checks MIME types."""

    def __init__(
        self,
        extract_files: bool = False,
        extract_dir: Optional[Path] = None,
        max_stream_bytes: int = 25 * 1024 * 1024,
    ) -> None:
        self.extract_files = extract_files
        self.extract_dir = extract_dir
        self.max_stream_bytes = max_stream_bytes
        self.carved_artifacts: list[CarvedArtifact] = []
        self._conversations: dict[tuple[str, int, str, int], _HTTPConversationState] = {}
        self._artifact_counter = 0

    def process_packet(self, ctx: PacketContext) -> None:
        """Feed a TCP packet into the HTTP stream reassembler."""
        if ctx.transport_proto != "TCP" or not ctx.src_ip or not ctx.dst_ip:
            return
        if ctx.src_port is None or ctx.dst_port is None:
            return

        dir_key = (ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port)
        rev_key = (ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port)

        is_syn = bool(ctx.tcp_flags & TCP_SYN) and not ctx.payload
        is_fin_rst = bool(ctx.tcp_flags & (TCP_FIN | TCP_RST))

        conv = self._conversations.get(dir_key)
        is_client = True
        if conv is None:
            conv = self._conversations.get(rev_key)
            if conv is not None:
                is_client = False

        # Start tracking a conversation when we observe HTTP request/response or SYN on HTTP-like ports
        if conv is None:
            if ctx.payload.startswith(HTTP_REQ_PREFIXES):
                conv = self._create_conversation(ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port, ctx.timestamp)
                is_client = True
            elif ctx.payload.startswith(b"HTTP/1."):
                conv = self._create_conversation(ctx.dst_ip, ctx.dst_port, ctx.src_ip, ctx.src_port, ctx.timestamp)
                is_client = False
            elif is_syn and (ctx.dst_port in {80, 8000, 8080, 8081, 8888, 3000, 5000}):
                conv = self._create_conversation(ctx.src_ip, ctx.src_port, ctx.dst_ip, ctx.dst_port, ctx.timestamp)
                if ctx.tcp_seq is not None:
                    conv.c2s_buf.set_initial_seq_from_syn(ctx.tcp_seq)
                return
            else:
                return

        conv.last_seen = ctx.timestamp

        # Record SYN-ACK initial sequence number for server->client stream
        if is_syn and ctx.tcp_seq is not None:
            if is_client:
                conv.c2s_buf.set_initial_seq_from_syn(ctx.tcp_seq)
            else:
                conv.s2c_buf.set_initial_seq_from_syn(ctx.tcp_seq)
            return

        if ctx.payload:
            if is_client:
                conv.c2s_buf.add_segment(ctx.tcp_seq, ctx.payload)
                self._extract_pending_requests(conv)
            else:
                conv.s2c_buf.add_segment(ctx.tcp_seq, ctx.payload)
                self._drain_http_responses(conv, final=False)

        if is_fin_rst:
            # Flush server stream if server closed connection (or RST)
            if not is_client or bool(ctx.tcp_flags & TCP_RST):
                conv.s2c_buf.force_flush_all()
                self._drain_http_responses(conv, final=True)
                self._conversations.pop((conv.client_ip, conv.client_port, conv.server_ip, conv.server_port), None)

    def _create_conversation(
        self, client_ip: str, client_port: int, server_ip: str, server_port: int, ts: float
    ) -> _HTTPConversationState:
        conv = _HTTPConversationState(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            last_seen=ts,
            c2s_buf=_TCPSequenceBuffer(max_bytes=256 * 1024),
            s2c_buf=_TCPSequenceBuffer(max_bytes=self.max_stream_bytes),
        )
        self._conversations[(client_ip, client_port, server_ip, server_port)] = conv
        return conv

    def _extract_pending_requests(self, conv: _HTTPConversationState) -> None:
        """Scan client->server HTTP requests so carved responses can be matched to URIs/hosts."""
        buf = conv.c2s_buf.assembled
        while True:
            data = bytes(buf)
            if not data:
                return
            if not data.startswith(HTTP_REQ_PREFIXES):
                positions = [data.find(m) for m in HTTP_REQ_PREFIXES]
                valid = [p for p in positions if p != -1]
                if not valid:
                    return
                del buf[: min(valid)]
                data = bytes(buf)

            hdr_end = data.find(b"\r\n\r\n")
            if hdr_end == -1:
                return

            head = data[:hdr_end].decode("latin-1", errors="replace")
            lines = head.splitlines()
            if not lines:
                del buf[: hdr_end + 4]
                continue

            parts = lines[0].split()
            method = parts[0].upper() if parts else "GET"
            uri = parts[1] if len(parts) >= 2 else "/"
            host = conv.server_ip
            content_length = 0
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    k_low = k.strip().lower()
                    if k_low == "host":
                        host = v.strip()
                    elif k_low == "content-length":
                        try:
                            content_length = max(0, int(v.strip()))
                        except ValueError:
                            content_length = 0

            msg_end = hdr_end + 4 + content_length
            if len(data) < msg_end:
                return

            conv.pending_requests.append(
                _HTTPRequestMeta(timestamp=conv.last_seen, method=method, host=host, uri=uri)
            )
            del buf[:msg_end]

    def _drain_http_responses(self, conv: _HTTPConversationState, final: bool) -> None:
        """Parse and carve all complete HTTP responses from the server->client buffer."""
        buf = conv.s2c_buf.assembled
        while buf:
            data = bytes(buf)
            if not data.startswith(b"HTTP/1."):
                idx = data.find(b"HTTP/1.")
                if idx == -1:
                    if final:
                        buf.clear()
                    return
                del buf[:idx]
                data = bytes(buf)

            hdr_end = data.find(b"\r\n\r\n")
            sep_len = 4
            if hdr_end == -1:
                hdr_end = data.find(b"\n\n")
                sep_len = 2
            if hdr_end == -1:
                if final:
                    buf.clear()
                return

            header_block = data[:hdr_end]
            body_start = hdr_end + sep_len

            status_line = header_block.split(b"\n", 1)[0].decode("latin-1", errors="replace").strip()
            parts = status_line.split()
            if len(parts) < 2:
                del buf[:body_start]
                continue
            try:
                status_code = int(parts[1])
            except ValueError:
                del buf[:body_start]
                continue

            content_length: Optional[int] = None
            is_chunked = False
            for line in header_block.split(b"\n")[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    k_low = k.strip().lower()
                    v_low = v.strip().lower()
                    if k_low == b"content-length":
                        try:
                            content_length = max(0, int(v_low))
                        except ValueError:
                            content_length = None
                    elif k_low == b"transfer-encoding" and b"chunked" in v_low:
                        is_chunked = True

            if status_code in (204, 304) or (100 <= status_code < 200):
                msg_end = body_start
            elif is_chunked:
                msg_end = _find_chunked_body_end(data, body_start)
                if msg_end == -1:
                    if not final:
                        return
                    msg_end = len(data)
            elif content_length is not None:
                msg_end = body_start + content_length
                if len(data) < msg_end:
                    if not final:
                        return
                    msg_end = len(data)
            else:
                # Connection: close framing — wait until FIN/EOF or next HTTP/1.
                next_http = data.find(b"HTTP/1.", body_start)
                if next_http != -1:
                    msg_end = next_http
                elif final:
                    msg_end = len(data)
                else:
                    return

            raw_response = data[:msg_end]
            del buf[:msg_end]
            req_meta = conv.pending_requests.popleft() if conv.pending_requests else None

            if status_code == 200:
                self._carve_response(conv, raw_response, req_meta)

    def _carve_response(
        self,
        conv: _HTTPConversationState,
        raw_response: bytes,
        req_meta: Optional[_HTTPRequestMeta],
    ) -> None:
        headers: dict[str, str] = {}
        body = b""
        status_code = 200

        try:
            resp = dpkt.http.Response(raw_response)
            status_code = int(resp.status)
            headers = {
                str(k).lower(): (", ".join(v) if isinstance(v, list) else str(v))
                for k, v in resp.headers.items()
            }
            body = bytes(resp.body) if resp.body else b""
        except Exception:
            # Fallback manual parse for truncated / non-strict responses
            sep = b"\r\n\r\n" if b"\r\n\r\n" in raw_response else b"\n\n"
            head_part, _, body = raw_response.partition(sep)
            for line in head_part.decode("latin-1", errors="replace").splitlines()[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

        if status_code != 200 or not body:
            return

        transfer_encoding = headers.get("transfer-encoding", "")
        content_encoding = headers.get("content-encoding", "")
        declared_ct = headers.get("content-type", "")
        content_disp = headers.get("content-disposition", "")

        carved_bytes = _safe_decompress(body, content_encoding)
        if not carved_bytes:
            return

        md5_hex = hashlib.md5(carved_bytes).hexdigest()
        sha256_hex = hashlib.sha256(carved_bytes).hexdigest()
        magic = detect_magic_mime(carved_bytes)
        mismatch = is_mime_mismatch(declared_ct, magic.mime_type)

        self._artifact_counter += 1
        artifact_id = f"ART-{self._artifact_counter:04d}"

        method = req_meta.method if req_meta else "GET"
        host = req_meta.host if req_meta else conv.server_ip
        uri = req_meta.uri if req_meta else "/"
        full_url = uri if uri.startswith(("http://", "https://")) else f"http://{host}{uri}"

        # Derive filename from Content-Disposition -> URI path -> fallback
        raw_name = ""
        if content_disp:
            m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";\r\n]+)"?', content_disp, re.IGNORECASE)
            if m:
                raw_name = m.group(1).strip()
        if not raw_name and uri:
            parsed_path = urlparse(uri).path
            if parsed_path and not parsed_path.endswith("/"):
                raw_name = os.path.basename(parsed_path)

        fallback_ext = EXTENSION_BY_MIME.get(magic.mime_type, ".bin")
        filename = _sanitize_filename(raw_name, fallback_ext=fallback_ext)
        if "." not in filename:
            filename = f"{filename}{fallback_ext}"

        saved_path: Optional[str] = None
        if self.extract_files and self.extract_dir is not None:
            saved_path = self._write_quarantined_file(filename, sha256_hex, carved_bytes)

        self.carved_artifacts.append(
            CarvedArtifact(
                artifact_id=artifact_id,
                timestamp=conv.last_seen,
                client_ip=conv.client_ip,
                client_port=conv.client_port,
                server_ip=conv.server_ip,
                server_port=conv.server_port,
                http_method=method,
                host=host,
                uri=uri,
                full_url=full_url,
                status_code=status_code,
                filename=filename,
                saved_path=saved_path,
                size_bytes=len(carved_bytes),
                md5=md5_hex,
                sha256=sha256_hex,
                declared_content_type=declared_ct or "unspecified",
                detected_mime_type=magic.mime_type,
                magic_description=magic.description,
                mime_mismatch=mismatch,
                is_executable=magic.is_executable,
                is_script=magic.is_script,
                is_archive=magic.is_archive,
                transfer_encoding=transfer_encoding,
                content_encoding=content_encoding,
            )
        )

    def _write_quarantined_file(self, filename: str, sha256_hex: str, payload: bytes) -> str:
        """Write carved payload safely into extracted_artifacts/ as read-only non-executable."""
        assert self.extract_dir is not None
        self.extract_dir.mkdir(parents=True, exist_ok=True)
        out_name = f"{sha256_hex[:12]}_{filename}"
        out_path = self.extract_dir / out_name

        # If existing read-only file from a previous run exists, make writable before replacing
        if out_path.exists():
            try:
                os.chmod(out_path, 0o644)
            except OSError:
                pass

        with open(out_path, "wb") as fh:
            fh.write(payload)

        # Enforce non-executable read-only permissions (quarantine safety)
        try:
            os.chmod(out_path, 0o444)
        except OSError:
            pass
        return str(out_path)

    def finalize(self) -> None:
        """Flush all remaining open HTTP streams at capture EOF."""
        for conv in list(self._conversations.values()):
            conv.s2c_buf.force_flush_all()
            self._drain_http_responses(conv, final=True)
        self._conversations.clear()


# ======================================================================
# Threat Intelligence Watchlist Matcher
# ======================================================================
@dataclass
class _IoCEntry:
    value: str
    indicator_type: str
    severity: str = "HIGH"
    threat_type: str = "Threat Intel Match"
    source: str = "Local Watchlist"
    description: str = ""
    mitre_attack: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


class ThreatIntelMatcher:
    """Cross-references observed network indicators and file hashes against data/iocs.json."""

    def __init__(self, watchlist_path: Optional[str | Path] = None) -> None:
        self.watchlist_path: Optional[str] = str(watchlist_path) if watchlist_path else None
        self.loaded: bool = False
        self._ip_exact: dict[str, _IoCEntry] = {}
        self._ip_networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, _IoCEntry]] = []
        self._domains: dict[str, _IoCEntry] = {}
        self._hashes: dict[str, _IoCEntry] = {}
        self._user_agents: list[tuple[str, _IoCEntry]] = []
        self._urls: list[tuple[str, _IoCEntry]] = []
        self._matches: dict[tuple[str, str], IoCMatch] = {}

        if watchlist_path:
            self.load_watchlist(watchlist_path)

    def load_watchlist(self, path: str | Path) -> bool:
        """Load and index a JSON IoC watchlist (supports structured dicts or simple lists)."""
        p = Path(path)
        self.watchlist_path = str(p)
        if not p.is_file():
            self.loaded = False
            return False

        with open(p, "r", encoding="utf-8") as fh:
            raw = json.load(fh)

        if not isinstance(raw, dict):
            self.loaded = False
            return False

        self._load_ips(raw.get("malicious_ips", []))
        self._load_domains(raw.get("malicious_domains", []))
        self._load_hashes(raw.get("malicious_hashes", []))
        self._load_user_agents(raw.get("suspicious_user_agents", []))
        self._load_urls(raw.get("malicious_urls", []))
        self.loaded = True
        return True

    @staticmethod
    def _parse_entry(item: Any, default_type: str, value_keys: tuple[str, ...]) -> Optional[_IoCEntry]:
        if isinstance(item, str):
            val = item.strip()
            return _IoCEntry(value=val, indicator_type=default_type) if val else None
        if isinstance(item, dict):
            val = ""
            for k in value_keys:
                if item.get(k):
                    val = str(item[k]).strip()
                    break
            if not val:
                return None
            return _IoCEntry(
                value=val,
                indicator_type=str(item.get("type", default_type)).lower(),
                severity=str(item.get("severity", "HIGH")).upper(),
                threat_type=str(item.get("threat_type", "Threat Intel Match")),
                source=str(item.get("source", "Local Watchlist")),
                description=str(item.get("description", "")),
                mitre_attack=list(item.get("mitre_attack", [])),
                tags=list(item.get("tags", [])),
            )
        return None

    def _load_ips(self, items: Any) -> None:
        if isinstance(items, dict):
            items = [{"ip": k, **(v if isinstance(v, dict) else {"description": str(v)})} for k, v in items.items()]
        for item in items or []:
            entry = self._parse_entry(item, "ip", ("ip", "indicator", "value", "cidr"))
            if not entry:
                continue
            if "/" in entry.value:
                try:
                    net = ipaddress.ip_network(entry.value, strict=False)
                    self._ip_networks.append((net, entry))
                    continue
                except ValueError:
                    pass
            self._ip_exact[entry.value.lower()] = entry

    def _load_domains(self, items: Any) -> None:
        if isinstance(items, dict):
            items = [{"domain": k, **(v if isinstance(v, dict) else {"description": str(v)})} for k, v in items.items()]
        for item in items or []:
            entry = self._parse_entry(item, "domain", ("domain", "indicator", "value"))
            if entry:
                self._domains[entry.value.strip(".").lower()] = entry

    def _load_hashes(self, items: Any) -> None:
        if isinstance(items, dict):
            items = [{"hash": k, **(v if isinstance(v, dict) else {"description": str(v)})} for k, v in items.items()]
        for item in items or []:
            if isinstance(item, dict):
                # Allow entries containing both md5 and sha256 fields simultaneously
                for h_key, h_type in (("sha256", "sha256"), ("md5", "md5"), ("hash", "hash"), ("indicator", "hash"), ("value", "hash")):
                    hval = item.get(h_key)
                    if hval:
                        hv = str(hval).strip().lower()
                        inferred = "sha256" if len(hv) == 64 else ("md5" if len(hv) == 32 else h_type)
                        self._hashes[hv] = _IoCEntry(
                            value=hv,
                            indicator_type=inferred,
                            severity=str(item.get("severity", "CRITICAL")).upper(),
                            threat_type=str(item.get("threat_type", "Known Malicious Payload")),
                            source=str(item.get("source", "Local Watchlist")),
                            description=str(item.get("description", "")),
                            mitre_attack=list(item.get("mitre_attack", [])),
                            tags=list(item.get("tags", [])),
                        )
            elif isinstance(item, str):
                hv = item.strip().lower()
                if hv:
                    inferred = "sha256" if len(hv) == 64 else ("md5" if len(hv) == 32 else "hash")
                    self._hashes[hv] = _IoCEntry(value=hv, indicator_type=inferred, severity="CRITICAL")

    def _load_user_agents(self, items: Any) -> None:
        for item in items or []:
            entry = self._parse_entry(item, "user_agent", ("pattern", "user_agent", "indicator", "value"))
            if entry:
                self._user_agents.append((entry.value.lower(), entry))

    def _load_urls(self, items: Any) -> None:
        for item in items or []:
            entry = self._parse_entry(item, "url", ("url", "indicator", "value"))
            if entry:
                self._urls.append((entry.value.lower(), entry))

    def check_ip(self, ip: str, timestamp: float, context: str) -> None:
        if not self.loaded or not ip:
            return
        ip_clean = ip.strip().lower()
        entry = self._ip_exact.get(ip_clean)
        if entry is not None:
            self._record_match(entry, ip_clean, "ip", timestamp, context)
            return
        if self._ip_networks:
            try:
                addr = ipaddress.ip_address(ip_clean)
                for net, net_entry in self._ip_networks:
                    if addr in net:
                        self._record_match(net_entry, ip_clean, "ip", timestamp, context)
                        return
            except ValueError:
                pass

    def check_domain(self, domain: str, timestamp: float, context: str) -> None:
        if not self.loaded or not domain:
            return
        d = domain.strip(".").lower()
        if not d:
            return
        # Match exact domain or any parent suffix (e.g. sub.malicious-c2.example -> malicious-c2.example)
        parts = d.split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            entry = self._domains.get(candidate)
            if entry is not None:
                self._record_match(entry, d, "domain", timestamp, context)
                return

    def check_hash(self, digest: str, hash_type: str, timestamp: float, context: str) -> None:
        if not self.loaded or not digest:
            return
        h = digest.strip().lower()
        entry = self._hashes.get(h)
        if entry is not None:
            self._record_match(entry, h, hash_type, timestamp, context)

    def check_user_agent(self, user_agent: str, timestamp: float, context: str) -> None:
        if not self.loaded or not user_agent or not self._user_agents:
            return
        ua_low = user_agent.lower()
        for pat, entry in self._user_agents:
            if pat in ua_low:
                self._record_match(entry, user_agent, "user_agent", timestamp, context)

    def check_url(self, url: str, timestamp: float, context: str) -> None:
        if not self.loaded or not url or not self._urls:
            return
        u_low = url.lower()
        for pat, entry in self._urls:
            if pat in u_low:
                self._record_match(entry, url, "url", timestamp, context)

    def _record_match(
        self,
        entry: _IoCEntry,
        observed_indicator: str,
        indicator_type: str,
        timestamp: float,
        context: str,
    ) -> None:
        key = (indicator_type, observed_indicator)
        existing = self._matches.get(key)
        if existing is None:
            self._matches[key] = IoCMatch(
                indicator=observed_indicator,
                indicator_type=indicator_type,
                severity=entry.severity,
                threat_type=entry.threat_type,
                source=entry.source,
                description=entry.description or f"Matched watchlist {indicator_type} indicator ({entry.value})",
                mitre_attack=list(entry.mitre_attack),
                tags=list(entry.tags),
                first_seen=timestamp,
                last_seen=timestamp,
                hit_count=1,
                contexts=[context] if context else [],
            )
        else:
            existing.hit_count += 1
            if timestamp > 0:
                if existing.first_seen == 0.0 or timestamp < existing.first_seen:
                    existing.first_seen = timestamp
                if timestamp > existing.last_seen:
                    existing.last_seen = timestamp
            if context and context not in existing.contexts and len(existing.contexts) < 12:
                existing.contexts.append(context)

    @property
    def matches(self) -> list[IoCMatch]:
        sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return sorted(
            self._matches.values(),
            key=lambda m: (-sev_order.get(m.severity, 0), -m.hit_count, m.indicator),
        )
