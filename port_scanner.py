#!/usr/bin/env python3
"""
port_scanner_enhanced.py

Async port scanner with banner grabbing, regex-based service/version detection,
JSON/CSV export, logging, optional nmap integration, rate-limiting, and jitter.

Usage:
    python port_scanner_enhanced.py target [--start START] [--end END] [options]

Example:
    python port_scanner_enhanced.py 192.168.1.10 --start 1 --end 1024 --json results.json --csv results.csv

Requirements:
    - Python 3.8+
    - If using --use-nmap, ensure `nmap` is installed and on PATH.

Legal:
    Only scan systems you own or have permission to scan.
"""

import argparse
import asyncio
import csv
import json
import logging
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional

# ----------------------------
# Configuration / Defaults
# ----------------------------

# Make public api explicit for imports (helpful but not required) --
__all__ = [
    "scan_range",
    "analyze_results",
    "now_ts",
    "CONNECT_TIMEOUT",
    "READ_TIMEOUT",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_JITTER",
]


DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
DEFAULT_CONCURRENCY = 200
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 2.0
DEFAULT_RATE_DELAY = 0.0  # base seconds between starts of tasks (adds jitter)
DEFAULT_JITTER = 0.02  # up to this many seconds of random jitter added to rate delay
BANNER_READ_BYTES = 2048
LOG_FILENAME = "port_scanner.log"
SCAN_LIMITS = {"max_port_range": 2000, "max_concurrency": 2000}


# ----------------------------
# Formatting JSON results to Human-Readable Text
# ----------------------------

def format_scan_results(results_json):
    """
    Turn the scan JSON dict into a human-readable terminal-style report (plain text).
    """
    import datetime
    lines = []
    lines.append("=" * 60)
    lines.append(f"Scan report for {results_json.get('target')} ({results_json.get('resolved_ip')})")
    lines.append(f"Port range: {results_json.get('start')}-{results_json.get('end')}")
    ts = results_json.get("scanned_at")
    try:
        ts_str = datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts_str = str(ts)
    lines.append(f"Scanned at: {ts_str}")
    lines.append(f"Found {len(results_json.get('results', []))} open ports\n")

    for r in results_json.get("results", []):
        port = r.get("port")
        service = r.get("detected_service") or "unknown"
        rtt = r.get("rtt_ms", 0.0)
        lines.append(f"- Port {port:5d} | Service: {service:12} | RTT: {rtt:.1f} ms")
        if r.get("insecure_note"):
            lines.append(f"    ⚠ {r['insecure_note']}")
        if r.get("banner"):
            banner_lines = [ln.strip() for ln in r["banner"].splitlines() if ln.strip()]
            snippet = " | ".join(banner_lines[:3])
            if snippet:
                lines.append(f"    Banner: {snippet}")
    lines.append("=" * 60)
    return "\n".join(lines)

# ----------------------------

# ----------------------------
# Service fingerprint database (regex based)
# Expand this DB to add more signatures as needed.
# ----------------------------
BANNER_SIGNATURES = [
    # (service_name, regex_pattern, optional description_template)
    ("ssh", re.compile(r"^SSH-(?P<version>[\d\.]+).*", re.IGNORECASE), "OpenSSH {version}"),
    ("http", re.compile(r"(?i)http/\d\.\d"), "HTTP"),
    ("apache", re.compile(r"(?i)apache/?(?P<version>[\d\.]+)?"), "Apache {version}"),
    ("nginx", re.compile(r"(?i)nginx/?(?P<version>[\d\.]+)?"), "nginx {version}"),
    ("iis", re.compile(r"(?i)microsoft-iis/?(?P<version>[\d\.]+)?"), "Microsoft-IIS {version}"),
    ("smtp", re.compile(r"(?i)smtp"), "SMTP"),
    ("mysql", re.compile(r"(?i)mysql"), "MySQL"),
    ("postgresql", re.compile(r"(?i)postgresql"), "PostgreSQL"),
    ("rdp", re.compile(r"(?i)rdp|ms-rdp"), "RDP"),
    ("vnc", re.compile(r"(?i)vnc"), "VNC"),
    ("ftp", re.compile(r"(?i)ftp"), "FTP"),
    ("telnet", re.compile(r"(?i)telnet"), "Telnet"),
    ("mongodb", re.compile(r"(?i)mongo(db)?"), "MongoDB"),
    ("redis", re.compile(r"(?i)redis"), "Redis"),
    # Add more tailored signatures as you gather more banners
]

# Map common ports to service hints and warnings for quick notes
COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    5432: "postgresql",
    5900: "vnc",
    3389: "rdp",
    8080: "http-proxy",
}

INSECURE_NOTES = {
    "telnet": "Telnet transmits credentials in cleartext. Prefer SSH.",
    "ftp": "FTP is unencrypted — prefer SFTP/FTPS.",
    "http": "HTTP is unencrypted. Prefer HTTPS.",
    "mysql": "Database port exposed — restrict access, use strong auth and firewalling.",
    "vnc": "VNC may allow unauthenticated access if misconfigured.",
    "rdp": "Exposed RDP is frequently targeted — use VPN or RDP gateway.",
    "microsoft-ds": "SMB/Windows sharing should be restricted; legacy SMBv1 is insecure.",
}

# ----------------------------
# Utility functions
# ----------------------------
def now_ts() -> str:
    return datetime.utcnow().isoformat() + "Z"


def setup_logging(log_file: str = LOG_FILENAME, level=logging.INFO):
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def resolve_host(host: str) -> Optional[str]:
    try:
        return socket.gethostbyname(host)
    except Exception as e:
        logging.error("Host resolution failed for %s: %s", host, e)
        return None


def match_banner_signatures(banner: str) -> Dict[str, Optional[str]]:
    """
    Try to match banner against our signatures.
    Returns dict with keys: 'service', 'description'
    """
    if not banner:
        return {"service": None, "description": None}
    b = banner.strip()
    for svc, regex, desc_tpl in BANNER_SIGNATURES:
        m = regex.search(b)
        if m:
            version = None
            try:
                version = m.groupdict().get("version") or m.groupdict().get("v") or None
            except Exception:
                version = None
            if version:
                try:
                    desc = desc_tpl.format(version=version)
                except Exception:
                    desc = desc_tpl
            else:
                desc = desc_tpl.split("{")[0].strip()
            return {"service": svc, "description": desc}
    # heuristics: look for plain words
    low = b.lower()
    if "http" in low:
        return {"service": "http", "description": "HTTP"}
    if "ssh" in low:
        return {"service": "ssh", "description": "SSH"}
    if "smtp" in low or "esmtp" in low:
        return {"service": "smtp", "description": "SMTP"}
    return {"service": None, "description": None}


# ----------------------------
# Async port probe
# ----------------------------
async def probe_port(
    host: str,
    port: int,
    semaphore: asyncio.Semaphore,
    connect_timeout: float,
    read_timeout: float,
    rate_delay: float,
    jitter: float,
) -> Optional[Dict]:
    """
    Attempt to connect, optionally send a small probe, read banner.
    Returns None on closed/refused/error. Otherwise returns a dict with port, banner, elapsed_ms.
    """
    await asyncio.sleep(rate_delay + random.uniform(0, jitter))
    async with semaphore:
        start = time.perf_counter()
        try:
            # create TCP connection
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=connect_timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            # closed or filtered or refused
            return None
        except Exception as e:
            logging.debug("Unhandled connect exception for %s:%d %s", host, port, e)
            return None

        banner = ""
        try:
            # For HTTP-like ports, send a HEAD to elicit a server header
            try:
                if port in (80, 8080, 8000, 8888):
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                else:
                    # a newline can sometimes trigger an initial banner
                    writer.write(b"\r\n")
                await writer.drain()
            except Exception:
                pass

            try:
                data = await asyncio.wait_for(reader.read(BANNER_READ_BYTES), timeout=read_timeout)
                if data:
                    banner = data.decode(errors="replace").strip()
            except asyncio.TimeoutError:
                # no banner returned within read timeout is still a valid open port
                banner = ""
            except Exception:
                banner = ""
        finally:
            # close writer
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {"port": port, "banner": banner, "elapsed_ms": elapsed_ms}


# ----------------------------
# Nmap integration (optional)
# ----------------------------
import os
import shutil
import subprocess
import logging
from typing import Optional

def run_nmap_service_scan(target: str, ports: str = "1-1024", aggressive: bool = False, timeout: int = 900) -> Optional[str]:
    """
    Run nmap on target. Attempts to adapt flags when running unprivileged.
    Returns nmap stdout (with appended stderr if non-zero exit), or None if nmap is absent.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        logging.warning("nmap not found on PATH. Skipping nmap scan.")
        return None

    # Heuristic: raw SYN (-sS) is likely only possible when running as root.
    can_do_sS = False
    try:
        can_do_sS = (os.geteuid() == 0)
    except Exception:
        can_do_sS = False

    # Base pieces
    base_args = ["-p", ports, "-Pn"]  # skip ping to avoid ICMP/firewall blocking surprises

    # Build initial candidate commands (from most aggressive to most conservative)
    commands = []

    if aggressive:
        if can_do_sS:
            # best-effort: SYN + aggressive + OS detection
            commands.append([nmap_bin] + base_args + ["-sS", "-A", "-O", target])
        else:
            # not privileged: try TCP connect but with -A and -O (may fail due to -O)
            commands.append([nmap_bin] + base_args + ["-sT", "-A", "-O", target])

            # Next fallback: remove -O (OS detect) but keep -A
            commands.append([nmap_bin] + base_args + ["-sT", "-A", target])

            # Next fallback: safe aggressive scan for unprivileged containers
            commands.append([
                nmap_bin,
                *base_args,
                "-sT", "-sV",
                "--script", "default,vuln",
                "--version-intensity", "9",
                target
            ])

    else:
        # non-aggressive: prefer service/version detection
        if can_do_sS:
            commands.append([nmap_bin] + base_args + ["-sV", "--version-intensity", "0", target])
        else:
            commands.append([nmap_bin] + base_args + ["-sT", "-sV", "--version-intensity", "0", target])

    # Run through candidate commands until one succeeds or we exhaust options.
    last_stdout = ""
    last_stderr = ""
    for idx, cmd in enumerate(commands):
        logging.info("Attempting nmap candidate %d: %s", idx + 1, " ".join(cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            last_stdout, last_stderr = stdout, stderr

            if proc.returncode == 0:
                logging.info("nmap candidate %d succeeded.", idx + 1)
                return stdout
            else:
                # If permission-related failure, log it and continue to next fallback
                combined = (stderr + "\n" + stdout).lower()
                if "operation not permitted" in combined or "socket troubles" in combined or "permission denied" in combined:
                    logging.warning("nmap candidate %d failed with permission error; will try a less-privileged command.", idx + 1)
                    logging.debug("nmap stderr: %s", stderr)
                    # try next candidate
                    continue
                else:
                    # non-permission failure — log and still try next candidate if available
                    logging.warning("nmap candidate %d returned non-zero exit %s; stderr: %s", idx + 1, proc.returncode, stderr.strip())
                    continue
        except subprocess.TimeoutExpired:
            logging.error("nmap candidate %d timed out after %s seconds", idx + 1, timeout)
            last_stdout += "\n\n# nmap timeout"
            continue
        except Exception as exc:
            logging.exception("Exception while running nmap candidate %d: %s", idx + 1, exc)
            last_stdout += f"\n\n# exception: {exc}"
            continue

    # If we reached here, all commands failed. Return best-effort output (stdout + stderr) for debugging.
    combined_out = (last_stdout or "") + ("\n\n# nmap stderr:\n" + (last_stderr or "")) if (last_stdout or last_stderr) else None
    logging.error("All nmap attempts failed. Returning combined output for debugging.")
    return combined_out


def parse_nmap_simple(nmap_output: str) -> List[Dict]:
    """
    Very simple parser for nmap -sV output to harvest found open ports and service lines.
    This is intentionally minimal and best-effort.
    """
    results = []
    if not nmap_output:
        return results
    # Nmap has a table like:
    # PORT     STATE SERVICE VERSION
    # 22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu
    lines = nmap_output.splitlines()
    in_table = False
    for line in lines:
        if re.match(r"PORT\s+STATE\s+SERVICE", line):
            in_table = True
            continue
        if in_table:
            line = line.strip()
            if not line:
                break
            # Example: "22/tcp open ssh OpenSSH 7.6p1 Ubuntu"
            m = re.match(r"(\d+)\/tcp\s+(\S+)\s+(\S+)\s*(.*)$", line)
            if m:
                port = int(m.group(1))
                state = m.group(2)
                service = m.group(3)
                version = m.group(4).strip()
                results.append({"port": port, "state": state, "service": service, "version": version})
    return results


# ----------------------------
# Reporting / Export
# ----------------------------
def export_json(path: str, host: str, ip: str, start: int, end: int, scan_results: List[Dict]):
    payload = {
        "scanned_at": now_ts(),
        "target": host,
        "resolved_ip": ip,
        "port_range": {"start": start, "end": end},
        "results": scan_results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    logging.info("Saved JSON report to %s", path)


def export_csv(path: str, host: str, ip: str, scan_results: List[Dict]):
    fieldnames = [
        "scanned_at",
        "target",
        "resolved_ip",
        "port",
        "state",
        "service_hint",
        "detected_service",
        "version",
        "banner_snippet",
        "insecure_note",
        "rtt_ms",
    ]
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        scanned_at = now_ts()
        for r in scan_results:
            writer.writerow(
                {
                    "scanned_at": scanned_at,
                    "target": host,
                    "resolved_ip": ip,
                    "port": r.get("port"),
                    "state": r.get("state"),
                    "service_hint": r.get("service_hint"),
                    "detected_service": r.get("detected_service"),
                    "version": r.get("version"),
                    "banner_snippet": (r.get("banner") or "").replace("\n", " | ")[:500],
                    "insecure_note": r.get("insecure_note") or "",
                    "rtt_ms": round(r.get("rtt_ms", 0), 2),
                }
            )
    logging.info("Saved CSV report to %s", path)


# ----------------------------
# Main scan orchestration
# ----------------------------
async def scan_range(
    host: str,
    start_port: int,
    end_port: int,
    concurrency: int,
    connect_timeout: float,
    read_timeout: float,
    rate_delay: float,
    jitter: float,
):
    """
    Perform async probes across the given port range. Returns list of result dicts.
    """
    ip = resolve_host(host)
    if not ip:
        raise RuntimeError(f"Could not resolve host {host}")

    logging.info("Scanning %s (%s) ports %d-%d (concurrency=%d)", host, ip, start_port, end_port, concurrency)
    sem = asyncio.Semaphore(concurrency)

    tasks = []
    # to avoid creating 65k coroutines at once, chunk the range in reasonable batches
    ports = list(range(start_port, end_port + 1))
    for p in ports:
        # small incremental rate control: stagger start times via rate_delay + jitter inside probe
        task = asyncio.create_task(
            probe_port(host, p, sem, connect_timeout, read_timeout, rate_delay, jitter)
        )
        tasks.append(task)

    # gather with return_exceptions=False so exceptions bubble (we'll catch below)
    results = []
    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
        except Exception as e:
            logging.debug("Probe raised: %s", e)
            continue
        if res:
            # res contains port, banner, elapsed_ms
            results.append(res)
    logging.info("Active probes complete. Found %d open-ish ports.", len(results))
    return ip, results


def run_scan_sync(host: str, start: int, end: int, concurrency: int,
                  connect_timeout: float = CONNECT_TIMEOUT, read_timeout: float = READ_TIMEOUT,
                  rate_delay: float = DEFAULT_RATE_DELAY, jitter: float = DEFAULT_JITTER):
    """
    Helper to run the async scan_range from synchronous code (e.g. Flask).
    Returns (ip, raw_results) or raises an exception on failure.
    """
    return asyncio.run(scan_range(host, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter))



def analyze_results(raw_results: List[Dict]) -> List[Dict]:
    """
    Enrich raw probe results with service detection, hints, notes.
    """
    enriched = []
    for r in raw_results:
        port = r.get("port")
        banner = r.get("banner", "") or ""
        rtt = r.get("elapsed_ms", 0.0)

        # quick hint from known common ports
        service_hint = COMMON_PORTS.get(port)

        # signature-based detection
        sig = match_banner_signatures(banner)
        detected_service = sig.get("service") or service_hint or "unknown"
        description = sig.get("description")

        # try to parse version from banner heuristics
        version = None
        if description and " " in description:
            # if description like "OpenSSH 7.6p1", attempt to capture numbers
            m = re.search(r"(\d+(?:\.\d+)+)", description)
            if m:
                version = m.group(1)
        else:
            # try to find version-like pattern in banner
            m = re.search(r"v(?:ersion)?\s*[:/]?\s*(\d+(?:\.\d+)+)", banner, re.IGNORECASE)
            if m:
                version = m.group(1)
            else:
                m2 = re.search(r"([\w-]+)[/ ]([\d\.]+)", banner)
                if m2:
                    version = m2.group(2)

        insecure_note = INSECURE_NOTES.get(detected_service) or INSECURE_NOTES.get(service_hint, None)

        enriched.append(
            {
                "port": port,
                "state": "open",
                "service_hint": service_hint,
                "detected_service": detected_service,
                "version": version,
                "banner": banner,
                "insecure_note": insecure_note,
                "rtt_ms": rtt,
            }
        )
    # Sort by port number
    enriched.sort(key=lambda x: x["port"])
    return enriched


def print_report(host: str, ip: str, start: int, end: int, results_enriched: List[Dict]):
    print("=" * 60)
    print(f"Scan report for {host} ({ip}) ports {start}-{end}")
    print(f"Scanned at: {now_ts()}")
    print(f"Found {len(results_enriched)} open ports\n")
    for r in results_enriched:
        print(f"- Port {r['port']:5d} | Service: {r['detected_service'] or 'unknown':12} | RTT {r['rtt_ms']:.1f} ms")
        if r.get("insecure_note"):
            print(f"    ⚠ {r['insecure_note']}")
        if r.get("banner"):
            lines = [ln.strip() for ln in r["banner"].splitlines() if ln.strip()]
            snippet = " | ".join(lines[:3])
            if snippet:
                print(f"    Banner: {snippet}")
    print("=" * 60)


# ----------------------------
# CLI
# ----------------------------
def build_argparser():
    p = argparse.ArgumentParser(prog="port_scanner_enhanced", description="Async Port Scanner with banner grabbing and exports")
    p.add_argument("target", help="Hostname or IP to scan")
    p.add_argument("--start", "-s", type=int, default=DEFAULT_START_PORT, help=f"Start port (default {DEFAULT_START_PORT})")
    p.add_argument("--end", "-e", type=int, default=DEFAULT_END_PORT, help=f"End port (default {DEFAULT_END_PORT})")
    p.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY, help=f"Max concurrent probes (default {DEFAULT_CONCURRENCY})")
    p.add_argument("--connect-timeout", type=float, default=CONNECT_TIMEOUT, help="TCP connect timeout seconds")
    p.add_argument("--read-timeout", type=float, default=READ_TIMEOUT, help="Banner read timeout seconds")
    p.add_argument("--rate-delay", type=float, default=DEFAULT_RATE_DELAY, help="Base delay (seconds) before each probe starts (adds to jitter). Default 0.0")
    p.add_argument("--jitter", type=float, default=DEFAULT_JITTER, help="Max jitter (seconds) added randomly to each probe start")
    p.add_argument("--json", type=str, help="Path to write JSON report")
    p.add_argument("--csv", type=str, help="Path to write CSV report")
    p.add_argument("--log", type=str, default=LOG_FILENAME, help="Log filename")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--use-nmap", action="store_true", help="If available, run nmap -sV and include its output in log (does not replace banner detection)")
    p.add_argument("--nmap-ports", default=None, help="When using --use-nmap, specify ports for nmap (e.g. 1-1024). Default: same range as scanner")
    p.add_argument("--no-banner", action="store_true", help="Do not attempt to read banners (faster but less info)")
    return p


def main():
    # If user runs script with no args, fall back to interactive prompts for convenience.
    # If args are provided, keep normal argparse behavior.
    if len(sys.argv) == 1:
        try:
            host = input("Target (hostname or IP) [e.g. 127.0.0.1]: ").strip()
            if not host:
                print("No host provided. Exiting.")
                sys.exit(1)
            start = input(f"Start port [default {DEFAULT_START_PORT}]: ").strip() or str(DEFAULT_START_PORT)
            end = input(f"End port [default {DEFAULT_END_PORT}]: ").strip() or str(DEFAULT_END_PORT)
            concurrency = input(f"Concurrency [default {DEFAULT_CONCURRENCY}]: ").strip() or str(DEFAULT_CONCURRENCY)
            # convert types and validate
            start = int(start); end = int(end); concurrency = int(concurrency)
            setup_logging(log_file=LOG_FILENAME, level=logging.INFO)
        except (EOFError, KeyboardInterrupt):
            print("\nNo input provided. Exiting.")
            sys.exit(1)
        except ValueError:
            print("Ports and concurrency must be integers. Exiting.")
            sys.exit(1)

        # Safety checks
        if start < 1 or end > 65535 or start > end:
            print("Invalid port range. Use 1-65535 and ensure start <= end.")
            sys.exit(1)

        ip = resolve_host(host)
        if not ip:
            print(f"Could not resolve host {host}. Exiting.")
            sys.exit(1)

        logging.info("Starting interactive scan of %s (%s)", host, ip)
        try:
            ip_addr, raw_results = asyncio.run(
                scan_range(host, start, end, concurrency, CONNECT_TIMEOUT, READ_TIMEOUT, DEFAULT_RATE_DELAY, DEFAULT_JITTER)
            )
        except KeyboardInterrupt:
            logging.warning("Scan interrupted by user.")
            sys.exit(1)
        except Exception as e:
            logging.error("Scan failed: %s", e)
            sys.exit(1)

        enriched = analyze_results(raw_results)
        print_report(host, ip_addr, start, end, enriched)
        sys.exit(0)

    # If args are present, use existing argparse flow
    args = build_argparser().parse_args()
    setup_logging(log_file=args.log, level=logging.DEBUG if args.verbose else logging.INFO)

    # Safety checks on ports
    if args.start < 1 or args.end > 65535 or args.start > args.end:
        print("Invalid port range. Use 1-65535 and ensure start <= end.")
        sys.exit(1)

    # Resolve
    ip = resolve_host(args.target)
    if not ip:
        print(f"Could not resolve host {args.target}. Exiting.")
        sys.exit(1)

    logging.info("Starting scan of %s (%s)", args.target, ip)
    logging.info("Options: start=%d end=%d concurrency=%d rate_delay=%s jitter=%s", args.start, args.end, args.concurrency, args.rate_delay, args.jitter)

    # Optional nmap run (non-blocking alternative: run before asyncio)
    nmap_output = None
    if args.use_nmap:
        nmap_ports = args.nmap_ports or f"{args.start}-{args.end}"
        try:
            nmap_output = run_nmap_service_scan(args.target, ports=nmap_ports)
            if nmap_output:
                nmap_parsed = parse_nmap_simple(nmap_output)
                logging.info("Parsed %d nmap entries.", len(nmap_parsed))
                for entry in nmap_parsed:
                    logging.info("nmap: port %s state %s service %s version %s", entry.get("port"), entry.get("state"), entry.get("service"), entry.get("version"))
        except Exception as e:
            logging.warning("nmap scan attempt failed: %s", e)

    # Run asyncio scan
    try:
        read_timeout = args.read_timeout
        ip_addr, raw_results = asyncio.run(
            scan_range(
                args.target,
                args.start,
                args.end,
                args.concurrency,
                args.connect_timeout,
                (0.01 if args.no_banner else read_timeout),
                args.rate_delay,
                args.jitter,
            )
        )
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logging.error("Scan failed: %s", e)
        sys.exit(1)

    # Analyze results
    enriched = analyze_results(raw_results)

    # If nmap results exist, try to merge version info for matching ports
    if nmap_output:
        parsed_nmap = parse_nmap_simple(nmap_output)
        nm_by_port = {e["port"]: e for e in parsed_nmap}
        for r in enriched:
            p = r["port"]
            if p in nm_by_port:
                nm = nm_by_port[p]
                if nm.get("version"):
                    r["version"] = nm.get("version")
                if nm.get("service"):
                    r["detected_service"] = nm.get("service")

    # Print to terminal
    print_report(args.target, ip_addr, args.start, args.end, enriched)

    # Exports
    if args.json:
        try:
            export_json(args.json, args.target, ip_addr, args.start, args.end, enriched)
        except Exception as e:
            logging.error("Failed to write JSON: %s", e)
    if args.csv:
        try:
            export_csv(args.csv, args.target, ip_addr, enriched)
        except Exception as e:
            logging.error("Failed to write CSV: %s", e)

    logging.info("Scan finished.")



if __name__ == "__main__":
    main()
