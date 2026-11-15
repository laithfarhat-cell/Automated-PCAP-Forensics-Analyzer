#!/usr/bin/env python3
"""Automated PCAP Forensics Analyzer — Production DFIR Command-Line Interface.

Streams .pcap / .pcapng packet captures safely from disk, reconstructs bidirectional flows,
recovers cleartext protocol artifacts (HTTP/FTP/SMTP/Telnet), detects DNS DGA & tunneling,
carves HTTP objects with cryptographic hashes & magic-byte MIME checks, correlates local
Threat Intelligence watchlists, and generates JSON, Markdown, and standalone HTML reports.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.table import Table
from rich.text import Text

from core.engine import TOOL_VERSION, PcapEngine
from core.models import ForensicReportData, format_bytes, format_duration, format_utc_timestamp
from reporters.report_builder import ReportBuilder

AUTO_OUTPUT_SENTINEL = "__AUTO__"

SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "cyan",
    "INFO": "dim white",
    "CLEAN": "bold green",
}


def _default_ioc_path() -> Optional[Path]:
    """Locate default data/iocs.json relative to CWD or package directory."""
    candidates = [
        Path.cwd() / "data" / "iocs.json",
        Path(__file__).resolve().parent / "data" / "iocs.json",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="pcap-forensics",
        description=(
            "Automated PCAP Forensics Analyzer — Memory-safe DFIR packet capture investigation "
            "engine for flow reconstruction, cleartext recovery, DNS tunneling/DGA detection, "
            "HTTP file carving, Threat Intel matching, and multi-format reporting."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -f samples/sample_incident.pcap --extract-files -oJ -oM -oH --output-dir ./reports\n"
            "  python main.py -f capture.pcapng --ioc data/iocs.json -oH incident_report.html\n"
            "  python main.py -f capture.pcap -oA --output-dir ./case_2026_01\n"
        ),
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        metavar="CAPTURE",
        help="Path to input .pcap or .pcapng capture file",
    )
    parser.add_argument(
        "--ioc",
        metavar="IOC_JSON",
        default=None,
        help="Path to Threat Intelligence IoC watchlist JSON (defaults to data/iocs.json if present)",
    )
    parser.add_argument(
        "--no-ioc",
        action="store_true",
        help="Disable Threat Intelligence watchlist correlation even if data/iocs.json exists",
    )
    parser.add_argument(
        "--extract-files",
        action="store_true",
        help="Carve and save HTTP 200 OK payloads into <output-dir>/extracted_artifacts/ (non-executable)",
    )
    parser.add_argument(
        "-oJ",
        "--json",
        nargs="?",
        const=AUTO_OUTPUT_SENTINEL,
        default=None,
        metavar="PATH",
        help="Generate JSON forensic report (optional explicit output path; defaults to <output-dir>/<stem>_report.json)",
    )
    parser.add_argument(
        "-oM",
        "--markdown",
        nargs="?",
        const=AUTO_OUTPUT_SENTINEL,
        default=None,
        metavar="PATH",
        help="Generate Markdown forensic report (optional explicit output path; defaults to <output-dir>/<stem>_report.md)",
    )
    parser.add_argument(
        "-oH",
        "--html",
        nargs="?",
        const=AUTO_OUTPUT_SENTINEL,
        default=None,
        metavar="PATH",
        help="Generate standalone dark-mode HTML report (optional explicit output path; defaults to <output-dir>/<stem>_report.html)",
    )
    parser.add_argument(
        "-oA",
        "--all",
        action="store_true",
        help="Generate all three report formats (JSON, Markdown, and HTML) inside --output-dir",
    )
    parser.add_argument(
        "--output-dir",
        default="forensics_output",
        metavar="DIR",
        help="Base output directory for reports and extracted_artifacts/ (default: ./forensics_output)",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=3.5,
        metavar="FLOAT",
        help="Shannon entropy threshold in bits for DGA domain flagging (default: 3.5)",
    )
    parser.add_argument(
        "--max-stream-mb",
        type=int,
        default=25,
        metavar="MB",
        help="Maximum TCP reassembly memory buffer per HTTP stream in MB (default: 25)",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Return exit code 2 if one or more CRITICAL findings are detected (useful for CI/SOC pipelines)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color styling in terminal output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress terminal summary tables (still writes requested report files)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show extended terminal tables including passive DNS and top flows",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {TOOL_VERSION}",
    )
    return parser


def _resolve_report_path(arg_value: Optional[str], output_dir: Path, stem: str, ext: str) -> Optional[Path]:
    if arg_value is None:
        return None
    if arg_value == AUTO_OUTPUT_SENTINEL:
        return output_dir / f"{stem}_report.{ext}"
    return Path(arg_value)


def _render_banner(console: Console, pcap_path: Path, ioc_path: Optional[Path], extract_files: bool) -> None:
    title = Text("AUTOMATED PCAP FORENSICS ANALYZER", style="bold cyan")
    title.append(f"  v{TOOL_VERSION}", style="dim white")
    subtitle = (
        f"[bold]Target:[/bold] {pcap_path}  |  "
        f"[bold]IoC Watchlist:[/bold] {ioc_path if ioc_path else 'Disabled'}  |  "
        f"[bold]File Carving:[/bold] {'Disk Quarantine ON' if extract_files else 'In-Memory Hash Only'}"
    )
    console.print(Panel(subtitle, title=title, border_style="cyan", box=box.ROUNDED, padding=(0, 2)))


def _render_summary(console: Console, report: ForensicReportData, elapsed: float, verbose: bool) -> None:
    meta = report.metadata
    verdict_style = SEVERITY_STYLES.get(report.risk_level, "bold white")

    # 1. Executive Summary & Chain-of-Custody Panel
    summary_grid = Table.grid(padding=(0, 3))
    summary_grid.add_column(style="bold cyan", justify="right")
    summary_grid.add_column()
    summary_grid.add_column(style="bold cyan", justify="right")
    summary_grid.add_column()

    verdict_text = Text(f" {report.risk_level} ({report.risk_score}/100) ", style=verdict_style)
    summary_grid.add_row("Verdict:", verdict_text, "Analysis Time:", f"{elapsed:.2f}s")
    summary_grid.add_row(
        "Packets / Volume:",
        f"{meta.total_packets:,} pkts ({format_bytes(meta.total_bytes)})",
        "Flows / Hosts:",
        f"{meta.total_flows:,} flows / {meta.unique_ips:,} IPs",
    )
    summary_grid.add_row(
        "Capture Window:",
        f"{format_utc_timestamp(meta.first_packet_time)} ({format_duration(meta.duration_seconds)})",
        "Format / Size:",
        f"{meta.capture_format} ({format_bytes(meta.file_size)})",
    )
    summary_grid.add_row(
        "Evidence SHA-256:",
        f"[dim]{meta.file_sha256[:24]}…[/dim]",
        "Severity Tally:",
        (
            f"[bold red]CRIT:{report.severity_counts['CRITICAL']}[/bold red] "
            f"[red]HIGH:{report.severity_counts['HIGH']}[/red] "
            f"[yellow]MED:{report.severity_counts['MEDIUM']}[/yellow] "
            f"[cyan]LOW:{report.severity_counts['LOW']}[/cyan]"
        ),
    )
    console.print(Panel(summary_grid, title="[bold]Executive Forensics Summary[/bold]", border_style="blue", box=box.ROUNDED))

    # 2. Protocol Distribution Table
    proto_table = Table(
        title="Protocol Distribution",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
        expand=True,
    )
    proto_table.add_column("Protocol", style="bold")
    proto_table.add_column("Packets", justify="right")
    proto_table.add_column("Share", justify="right")
    proto_table.add_column("Distribution", width=26)
    proto_table.add_column("Byte Volume", justify="right")

    for proto, stats in meta.protocol_distribution.items():
        pct = float(stats["percentage"])
        filled = int(round(min(pct, 100.0) / 5.0))
        bar = f"[cyan]{'█' * filled}[/cyan][dim]{'░' * (20 - filled)}[/dim]"
        proto_table.add_row(
            proto,
            f"{stats['packets']:,}",
            f"{pct:5.1f}%",
            bar,
            format_bytes(stats["bytes"]),
        )
    console.print(proto_table)

    # 3. Top Talkers Table
    if meta.top_talkers_hosts:
        talker_table = Table(
            title="Top Talkers (Combined Host Volume)",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            expand=True,
        )
        talker_table.add_column("#", justify="right", style="dim", width=3)
        talker_table.add_column("Host IP", style="bold")
        talker_table.add_column("Packets", justify="right")
        talker_table.add_column("Total Bytes", justify="right")
        talker_table.add_column("Sent", justify="right", style="green")
        talker_table.add_column("Received", justify="right", style="blue")

        for idx, h in enumerate(meta.top_talkers_hosts[:8], start=1):
            talker_table.add_row(
                str(idx),
                h["ip"],
                f"{h['total_packets']:,}",
                format_bytes(h["total_bytes"]),
                format_bytes(h["sent_bytes"]),
                format_bytes(h["recv_bytes"]),
            )
        console.print(talker_table)

    # 4. High-Severity & Prioritized Forensic Findings Table
    if report.findings:
        findings_table = Table(
            title=f"Prioritized Forensic Findings ({len(report.findings)} total)",
            box=box.ROUNDED,
            header_style="bold magenta",
            expand=True,
            show_lines=True,
        )
        findings_table.add_column("Severity", width=10, justify="center")
        findings_table.add_column("Category", width=18)
        findings_table.add_column("Title & Forensic Context")
        findings_table.add_column("MITRE", width=16)

        limit = 35 if verbose else 18
        for f in report.findings[:limit]:
            sev_badge = Text(f" {f.severity} ", style=SEVERITY_STYLES.get(f.severity, "white"))
            detail_text = f"[bold]{f.title}[/bold]\n[dim]{f.description[:220]}[/dim]"
            findings_table.add_row(
                sev_badge,
                f.category,
                detail_text,
                ", ".join(f.mitre_attack) if f.mitre_attack else "-",
            )
        console.print(findings_table)
        if len(report.findings) > limit:
            console.print(
                f"[dim]Showing top {limit} of {len(report.findings)} findings. Use --verbose or inspect exported reports for full details.[/dim]"
            )
    else:
        console.print(Panel("[bold green]No malicious or suspicious findings detected.[/bold green]", border_style="green"))

    # 5. Recovered Cleartext Credentials Table
    if report.credentials:
        cred_table = Table(
            title=f"Recovered Cleartext Credentials ({len(report.credentials)})",
            box=box.SIMPLE_HEAVY,
            header_style="bold red",
            expand=True,
        )
        cred_table.add_column("Protocol", style="bold yellow")
        cred_table.add_column("Source -> Destination")
        cred_table.add_column("Username", style="bold cyan")
        cred_table.add_column("Password / Token", style="bold red")
        cred_table.add_column("Context", style="dim")

        for c in report.credentials[:15]:
            cred_table.add_row(
                c.protocol,
                f"{c.src_ip} -> {c.dst_ip}:{c.dst_port}",
                c.username,
                c.password,
                c.context[:60],
            )
        console.print(cred_table)

    # 6. Carved HTTP Objects Table
    if report.carved_artifacts:
        carve_table = Table(
            title=f"Carved HTTP 200 OK Objects ({len(report.carved_artifacts)})",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            expand=True,
        )
        carve_table.add_column("ID", style="dim", width=8)
        carve_table.add_column("Filename", style="bold")
        carve_table.add_column("Size", justify="right")
        carve_table.add_column("Declared -> Magic MIME")
        carve_table.add_column("SHA-256 (prefix)")

        for c in report.carved_artifacts[:15]:
            mime_str = f"{c.declared_content_type} -> {c.detected_mime_type}"
            if c.mime_mismatch:
                mime_str = f"[bold red]{mime_str} [MISMATCH][/bold red]"
            carve_table.add_row(
                c.artifact_id,
                c.filename,
                format_bytes(c.size_bytes),
                mime_str,
                c.sha256[:32] + "...",
            )
        console.print(carve_table)

    # 7. Verbose Passive DNS view
    if verbose and report.passive_dns:
        pdns_table = Table(
            title=f"Passive DNS Table (top 20 of {len(report.passive_dns)})",
            box=box.SIMPLE_HEAVY,
            header_style="bold cyan",
            expand=True,
        )
        pdns_table.add_column("Domain")
        pdns_table.add_column("Resolved IPs")
        pdns_table.add_column("Queries", justify="right")
        pdns_table.add_column("NXDOMAIN", justify="right")
        pdns_table.add_column("Max Entropy", justify="right")
        for r in report.passive_dns[:20]:
            ent_style = "bold red" if r.max_label_entropy >= 3.5 else "white"
            pdns_table.add_row(
                r.domain[:60],
                ", ".join(r.resolved_ips[:3]) or "-",
                str(r.query_count),
                str(r.nxdomain_count),
                f"[{ent_style}]{r.max_label_entropy:.2f}[/{ent_style}]",
            )
        console.print(pdns_table)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point returning POSIX exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    console = Console(no_color=args.no_color, quiet=args.quiet)
    err_console = Console(stderr=True, no_color=args.no_color)

    pcap_path = Path(args.file)
    if not pcap_path.is_file():
        err_console.print(f"[bold red]Error:[/bold red] Capture file not found: {pcap_path}")
        return 1

    # Resolve IoC watchlist path
    ioc_path: Optional[Path] = None
    if not args.no_ioc:
        if args.ioc:
            ioc_path = Path(args.ioc)
            if not ioc_path.is_file():
                err_console.print(f"[bold red]Error:[/bold red] IoC watchlist file not found: {ioc_path}")
                return 1
        else:
            ioc_path = _default_ioc_path()

    output_dir = Path(args.output_dir)
    extract_dir = output_dir / "extracted_artifacts"

    if args.all:
        args.json = args.json or AUTO_OUTPUT_SENTINEL
        args.markdown = args.markdown or AUTO_OUTPUT_SENTINEL
        args.html = args.html or AUTO_OUTPUT_SENTINEL

    stem = pcap_path.stem
    json_out = _resolve_report_path(args.json, output_dir, stem, "json")
    md_out = _resolve_report_path(args.markdown, output_dir, stem, "md")
    html_out = _resolve_report_path(args.html, output_dir, stem, "html")

    _render_banner(console, pcap_path, ioc_path, args.extract_files)

    try:
        engine = PcapEngine(
            pcap_path=pcap_path,
            ioc_path=ioc_path,
            extract_files=args.extract_files,
            extract_dir=extract_dir,
            entropy_threshold=args.entropy_threshold,
            max_stream_mb=args.max_stream_mb,
        )
    except Exception as exc:
        err_console.print(f"[bold red]Initialization Error:[/bold red] {exc}")
        return 1

    start_time = time.perf_counter()
    file_size = pcap_path.stat().st_size

    try:
        if args.quiet:
            report = engine.analyze()
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Streaming Capture[/bold cyan]"),
                BarColumn(bar_width=32),
                TaskProgressColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TextColumn("[dim]{task.fields[pkts]:,} pkts[/dim]"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                task_id = progress.add_task("ingest", total=max(1, file_size), pkts=0)

                def _on_progress(bytes_read: int, total_bytes: int, pkt_count: int) -> None:
                    progress.update(
                        task_id,
                        completed=min(bytes_read, total_bytes),
                        total=max(1, total_bytes),
                        pkts=pkt_count,
                    )

                report = engine.analyze(progress_callback=_on_progress, progress_interval=50)
    except Exception as exc:
        err_console.print(f"[bold red]Analysis Error:[/bold red] Failed while streaming {pcap_path}: {exc}")
        return 1

    elapsed = time.perf_counter() - start_time
    _render_summary(console, report, elapsed, verbose=args.verbose)

    # Export requested forensic reports
    builder = ReportBuilder()
    generated_files: list[tuple[str, Path]] = []

    try:
        if json_out:
            generated_files.append(("JSON Report", builder.write_json(report, json_out)))
        if md_out:
            generated_files.append(("Markdown Report", builder.write_markdown(report, md_out)))
        if html_out:
            generated_files.append(("HTML Dashboard", builder.write_html(report, html_out)))
    except Exception as exc:
        err_console.print(f"[bold red]Reporting Error:[/bold red] {exc}")
        return 1

    if generated_files or (args.extract_files and report.carved_artifacts):
        out_lines = [f"[bold green]✓[/bold green] [bold]{label}:[/bold] {path}" for label, path in generated_files]
        if args.extract_files and report.carved_artifacts:
            saved_count = sum(1 for c in report.carved_artifacts if c.saved_path)
            out_lines.append(
                f"[bold green]✓[/bold green] [bold]Carved Artifacts ({saved_count} quarantined, mode 0444):[/bold] {extract_dir}"
            )
        console.print(Panel("\n".join(out_lines), title="[bold green]Output Artifacts[/bold green]", border_style="green", box=box.ROUNDED))

    if args.fail_on_critical and report.severity_counts.get("CRITICAL", 0) > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
