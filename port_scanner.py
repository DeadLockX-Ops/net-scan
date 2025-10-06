#!/usr/bin/env python3
"""
port_scanner.py  (enhanced)

Async port scanner with banner grabbing, regex-based service/version detection,
JSON/CSV export, logging, optional nmap integration (including aggressive -A),
rate-limiting, jitter, and improved merging/printing of results.

Preserves all functionality from the previous version and adds:
 - explicit IP vs hostname handling
 - improved nmap invocation (normal and aggressive modes)
 - better parsing of nmap -A output (ports, traceroute, OS hints, script output)
 - merging of nmap-found ports into the scanner results
 - clear terminal-style output (includes nmap summary if available)

LEGAL: only scan hosts you own / have permission to scan.
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
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

# ----------------------------
# Configuration / Defaults
# ----------------------------
DEFAULT_START_PORT = 1
DEFAULT_END_PORT = 1024
DEFAULT_CONCURRENCY = 200
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 2.0
DEFAULT_RATE_DELAY = 0.0
DEFAULT_JITTER = 0.02
BANNER_READ_BYTES = 2048
LOG_FILENAME = "port_scanner.log"
SCAN_LIMITS = {"max_port_range": 2000, "max_concurrency": 2000}

# ----------------------------
# Common Ports & Insecure Notes
# ----------------------------
COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 139: "netbios-ssn", 143: "imap", 443: "https",
    445: "microsoft-ds", 3306: "mysql", 5432: "postgresql", 5900: "vnc", 3389: "rdp",
    8080: "http-proxy"
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
# Banner Signatures (Regex)
# ----------------------------
BANNER_SIGNATURES = [
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
]

# ----------------------------
# Utilities
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
    """
    If input is already a valid IP, return it. Otherwise resolve the hostname.
    Returns string IP or None on failure.
    """
    try:
        ipaddress.ip_address(host)
        logging.info("Input is a valid IP address: %s", host)
        return host
    except ValueError:
        pass

    try:
        info = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        addr = info[0][4][0]
        logging.info("Resolved hostname %s to IP %s", host, addr)
        return addr
    except Exception as e:
        logging.error("Host resolution failed for %s: %s", host, e)
        return None

def match_banner_signatures(banner: str) -> Dict[str, Optional[str]]:
    if not banner:
        return {"service": None, "description": None}
    b = banner.strip()
    for svc, regex, desc_tpl in BANNER_SIGNATURES:
        m = regex.search(b)
        if m:
            version = None
            try:
                version = m.groupdict().get("version") if m.groupdict() else None
            except Exception:
                version = None
            desc = desc_tpl.format(version=version) if version else desc_tpl.split("{")[0].strip()
            return {"service": svc, "description": desc}
    low = b.lower()
    if "http" in low: return {"service": "http", "description": "HTTP"}
    if "ssh" in low: return {"service": "ssh", "description": "SSH"}
    if "smtp" in low or "esmtp" in low: return {"service": "smtp", "description": "SMTP"}
    return {"service": None, "description": None}

# ----------------------------
# Async Port Probe
# ----------------------------
async def probe_port(
    host: str, port: int, semaphore: asyncio.Semaphore,
    connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float
) -> Optional[Dict]:
    await asyncio.sleep(rate_delay + random.uniform(0, jitter))
    async with semaphore:
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=connect_timeout)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
            return None
        banner = ""
        try:
            # send a small probe: HEAD for web, newline otherwise
            try:
                if port in (80, 8080, 8000, 8888):
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                else:
                    writer.write(b"\r\n")
                await writer.drain()
            except Exception:
                pass

            try:
                data = await asyncio.wait_for(reader.read(BANNER_READ_BYTES), timeout=read_timeout)
                banner = data.decode(errors="replace").strip() if data else ""
            except asyncio.TimeoutError:
                banner = ""
            except Exception:
                banner = ""
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return {"port": port, "banner": banner, "elapsed_ms": elapsed_ms}

# ----------------------------
# Async Scan Range
# ----------------------------
async def scan_range(host: str, start_port: int, end_port: int, concurrency: int,
                     connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float
) -> Tuple[str, List[Dict]]:
    ip = resolve_host(host)
    if not ip:
        raise RuntimeError(f"Could not resolve host {host}")
    logging.info("Scanning %s (%s) ports %d-%d (concurrency=%d)", host, ip, start_port, end_port, concurrency)
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(probe_port(host, p, sem, connect_timeout, read_timeout, rate_delay, jitter))
             for p in range(start_port, end_port + 1)]
    results = []
    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
            if res:
                results.append(res)
        except Exception as e:
            logging.debug("Probe raised: %s", e)
    logging.info("Active probes complete. Found %d open-ish ports.", len(results))
    return ip, results

def run_scan_sync(host: str, start: int, end: int, concurrency: int,
                  connect_timeout: float = CONNECT_TIMEOUT, read_timeout: float = READ_TIMEOUT,
                  rate_delay: float = DEFAULT_RATE_DELAY, jitter: float = DEFAULT_JITTER) -> Tuple[str, List[Dict]]:
    return asyncio.run(scan_range(host, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter))

# ----------------------------
# Results Analysis
# ----------------------------
def analyze_results(raw_results: List[Dict]) -> List[Dict]:
    enriched = []
    for r in raw_results:
        port = r.get("port")
        banner = r.get("banner", "") or ""
        rtt = r.get("elapsed_ms", 0.0)
        service_hint = COMMON_PORTS.get(port)
        sig = match_banner_signatures(banner)
        detected_service = sig.get("service") or service_hint or "unknown"
        description = sig.get("description")
        version = None
        if description and " " in description:
            m = re.search(r"(\d+(?:\.\d+)+)", description)
            if m:
                version = m.group(1)
        else:
            m = re.search(r"v(?:ersion)?\s*[:/]?\s*(\d+(?:\.\d+)+)", banner, re.IGNORECASE)
            if m:
                version = m.group(1)
            else:
                m2 = re.search(r"([\w-]+)[/ ]([\d\.]+)", banner)
                if m2:
                    version = m2.group(2)
        insecure_note = INSECURE_NOTES.get(detected_service) or INSECURE_NOTES.get(service_hint)
        enriched.append({
            "port": port,
            "state": "open",
            "service_hint": service_hint,
            "detected_service": detected_service,
            "version": version,
            "banner": banner,
            "insecure_note": insecure_note,
            "rtt_ms": rtt,
        })
    enriched.sort(key=lambda x: x["port"])
    return enriched

# ----------------------------
# JSON/CSV Export
# ----------------------------
def export_json(path: str, host: str, ip: str, start: int, end: int, scan_results: List[Dict]):
    payload = {"scanned_at": now_ts(), "target": host, "resolved_ip": ip,
               "port_range": {"start": start, "end": end}, "results": scan_results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    logging.info("Saved JSON report to %s", path)

def export_csv(path: str, host: str, ip: str, scan_results: List[Dict]):
    fieldnames = ["scanned_at", "target", "resolved_ip", "port", "state", "service_hint",
                  "detected_service", "version", "banner_snippet", "insecure_note", "rtt_ms"]
    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        scanned_at = now_ts()
        for r in scan_results:
            writer.writerow({
                "scanned_at": scanned_at, "target": host, "resolved_ip": ip,
                "port": r.get("port"), "state": r.get("state"), "service_hint": r.get("service_hint"),
                "detected_service": r.get("detected_service"), "version": r.get("version"),
                "banner_snippet": (r.get("banner") or "").replace("\n", " | ")[:500],
                "insecure_note": r.get("insecure_note") or "", "rtt_ms": round(r.get("rtt_ms", 0), 2)
            })
    logging.info("Saved CSV report to %s", path)


def format_scan_results(result_obj: Dict) -> str:
    """
    Produce a plain-text formatted scan report from the result object produced
    by run_scan_task / run_scan_sync + analyze_results in app.py.

    If result_obj contains a parsed nmap dict under the key "_nmap", include
    a formatted Nmap OS & Network Information block.
    """
    host = result_obj.get("target", "<unknown>")
    ip = result_obj.get("resolved_ip", "<unknown>")
    start = result_obj.get("start", DEFAULT_START_PORT)
    end = result_obj.get("end", DEFAULT_END_PORT)
    results = result_obj.get("results", [])
    scanned_at = result_obj.get("scanned_at")
    try:
        ts_str = datetime.utcfromtimestamp(float(scanned_at)).strftime("%Y-%m-%d %H:%M:%S") + " UTC" if scanned_at else now_ts()
    except Exception:
        ts_str = now_ts()

    lines = []
    lines.append("=" * 60)
    lines.append(f"Scan report for {host} ({ip})")
    lines.append(f"Port range: {start}-{end}")
    lines.append(f"Scanned at: {ts_str}")
    lines.append(f"Found {len(results)} open ports")
    lines.append("")

    # port lines
    for r in results:
        port = r.get("port")
        svc = r.get("detected_service") or r.get("service_hint") or "unknown"
        rtt = r.get("rtt_ms", 0.0)
        lines.append(f"- Port {port:5d} | Service: {svc:12} | RTT {float(rtt):.1f} ms")
        if r.get("insecure_note"):
            lines.append(f"    ⚠ {r['insecure_note']}")
        banner = r.get("banner") or ""
        if banner:
            snippet_lines = [ln.strip() for ln in banner.splitlines() if ln.strip()][:3]
            if snippet_lines:
                snippet = " | ".join(snippet_lines)
                if len(snippet) > 400:
                    snippet = snippet[:400] + "..."
                lines.append(f"    Banner: {snippet}")

    lines.append("=" * 60)

    # If Nmap info present, append a full Nmap block
    nmap_info = result_obj.get("_nmap")
    if nmap_info:
        lines.append("")  # blank line
        lines.append("=" * 60)
        lines.append("Nmap OS & Network Information")
        lines.append("=" * 60)
        lines.append("")  # blank line

        # OS Detection (raw text or a friendly fallback)
        os_text = nmap_info.get("os_text")
        if os_text:
            lines.append("OS Detection: " + os_text.strip())
        else:
            # if os_guesses exist, don't repeat them in os_text
            if not nmap_info.get("os_guesses"):
                if nmap_info.get("host_up") is False:
                    lines.append("OS Detection: Host appears down / unreachable")
                else:
                    lines.append("OS Detection: (no specific OS detected)")

        # Aggressive OS guesses (if any)
        if nmap_info.get("os_guesses"):
            lines.append("Aggressive OS Guesses:")
            for guess, pct in nmap_info.get("os_guesses", []):
                if pct:
                    lines.append(f"  - {guess} ({pct}%)")
                else:
                    lines.append(f"  - {guess}")

        # Network distance & service info
        if nmap_info.get("network_distance"):
            # parse/print as user expects (e.g. "Network Distance: 17 hops")
            nd = nmap_info.get("network_distance")
            lines.append("")
            lines.append(f"{nd}")
        if nmap_info.get("service_info"):
            lines.append(f"Service Info: {nmap_info.get('service_info')}")

        # Ports reported by nmap (if any)
        if nmap_info.get("ports"):
            lines.append("")  # blank
            lines.append("Nmap reported ports:")
            for p in nmap_info["ports"]:
                ver = (" " + p.get("version")) if p.get("version") else ""
                lines.append(f"  - {p.get('port')}: {p.get('state')} {p.get('service')}{ver}")

        # Traceroute (if present)
        if nmap_info.get("traceroute"):
            lines.append("")  # blank
            lines.append("Traceroute (first hops):")
            for hop in nmap_info["traceroute"][:20]:
                lines.append(f"  {hop.get('hop'):2d}  {hop.get('rtt_ms')} ms  {hop.get('address')}")

        # other small pieces
        if nmap_info.get("other_addresses"):
            other = nmap_info.get("other_addresses")
            if other:
                lines.append("")
                lines.append("Other addresses: " + ", ".join(other))
        if nmap_info.get("not_shown_summary"):
            lines.append("")
            lines.append(nmap_info.get("not_shown_summary"))

        lines.append("=" * 60)

    return "\n".join(lines)



# ----------------------------
# Report Printing
# ----------------------------
def print_report(host: str, ip: str, start: int, end: int,
                 results_enriched: List[Dict], nmap_info: Optional[Dict] = None):
    # header
    print("=" * 60)
    print(f"Scan report for {host} ({ip})")
    print(f"Port range: {start}-{end}")
    print(f"Scanned at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"Found {len(results_enriched)} open ports\n")

    # ports discovered by our async scanner + merged nmap entries
    for r in results_enriched:
        svc = r.get('detected_service') or r.get('service_hint') or 'unknown'
        print(f"- Port {r['port']:5d} | Service: {svc:12} | RTT {r.get('rtt_ms', 0.0):.1f} ms")
        if r.get("insecure_note"):
            print(f"    ⚠ {r['insecure_note']}")
        if r.get("banner"):
            snippet = " | ".join([ln.strip() for ln in r["banner"].splitlines() if ln.strip()][:3])
            if snippet:
                print(f"    Banner: {snippet}")

    
    # If nmap info exists, print a full Nmap OS & Network Information block
    if nmap_info:
        lines = []
        print("\n" + "=" * 60)
        print("Nmap OS & Network Information")
        print("=" * 60)
        print("")  # blank line

        # OS Detection (prefer os_text; fallback messaging if absent)
        os_text = nmap_info.get("os_text")
        if os_text:
            print(f"OS Detection: {os_text.strip()}")
        else:
            # if os_guesses exist, we will list them below; otherwise print fallback
            if nmap_info.get("os_guesses"):
                print("OS Detection: (see Aggressive OS Guesses below)")
            else:
                # show host_up status if available
                host_up = nmap_info.get("host_up")
                if host_up is False:
                    print("OS Detection: Host appears down / unreachable")
                else:
                    print("OS Detection: (no specific OS detected)")

        # Aggressive OS guesses (structured)
        if nmap_info.get("os_guesses"):
            print("\nAggressive OS Guesses:")
            for guess, pct in nmap_info.get("os_guesses", []):
                if pct:
                    print(f"  - {guess} ({pct}%)")
                else:
                    print(f"  - {guess}")

        # Network distance & Service info
        if nmap_info.get("network_distance"):
            # Print exactly as your example: "Network Distance: 17 hops"
            nd = nmap_info.get("network_distance")
            # If parse produced whole line, print it; else format
            if isinstance(nd, str) and "Network" in nd:
                print("\n" + nd)
            else:
                print(f"\nNetwork Distance: {nd}")

        if nmap_info.get("service_info"):
            print(f"Service Info: {nmap_info.get('service_info')}")

        # Ports reported by nmap (if any)
        if nmap_info.get("ports"):
            print("\nNmap reported ports:")
            for p in nmap_info["ports"]:
                ver = (" " + p.get("version")) if p.get("version") else ""
                print(f"  - {p.get('port')}: {p.get('state')} {p.get('service')}{ver}")

        # Traceroute (if present)
        if nmap_info.get("traceroute"):
            print("\nTraceroute (first hops):")
            for hop in nmap_info["traceroute"][:20]:
                print(f"  {hop.get('hop'):2d}  {hop.get('rtt_ms')} ms  {hop.get('address')}")

        print("=" * 60)




# ----------------------------
# Nmap Integration (enhanced)
# ----------------------------
def run_nmap_service_scan(target: str, ports: str = "1-1024", aggressive: bool = False) -> Optional[str]:
    """
    Run nmap. If aggressive=True, include -A -sS -O -sC -sV as appropriate.
    Returns stdout string or None.
    """
    nmap_bin = shutil.which("nmap")
    if not nmap_bin:
        logging.warning("nmap not found on PATH. Skipping nmap scan.")
        return None

    # Build command
    cmd = [nmap_bin, "-p", ports]
    if aggressive:
        # -sS (SYN) needs root. -A includes -sV -sC -O -traceroute etc.
        # We also add -Pn to skip host discovery for consistency
        cmd += ["-sS", "-A", "-O", "-Pn"]
    else:
        cmd += ["-sV", "--version-intensity", "0", "-Pn"]
    cmd.append(target)

    logging.info("Running nmap: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        out = proc.stdout or ""
        if proc.returncode != 0:
            out = out + ("\n\n# nmap stderr:\n" + (proc.stderr or ""))
            logging.warning("nmap returned non-zero exit status %s", proc.returncode)
        return out
    except Exception as e:
        logging.error("Error running nmap: %s", e)
        return None

def parse_nmap_aggressive(nmap_output: str) -> Dict[str, Any]:
    """
    Improved parsing for nmap -A textual output (best-effort).
    Returns a dict with:
      - host_up (bool/None)
      - host_latency (float seconds or None)
      - other_addresses (list)
      - not_shown_summary (str/None)
      - os_text (str/None)
      - os_guesses (list of (guess, pct) tuples)
      - network_distance (str/None)
      - service_info (str/None)
      - traceroute (list of {hop, rtt_ms, address})
      - ports (list of {port, state, service, version})
    """
    data: Dict[str, Any] = {
        "host_up": None,
        "host_latency": None,
        "other_addresses": [],
        "not_shown_summary": None,
        "os_text": None,
        "os_guesses": [],
        "network_distance": None,
        "service_info": None,
        "traceroute": [],
        "ports": []
    }
    if not nmap_output:
        return data

    lines = nmap_output.splitlines()
    # helper to normalize
    def clean(s: str) -> str:
        return s.strip()

    # Iterate lines and capture pieces
    for i, raw in enumerate(lines):
        line = raw.strip()

        # Host up + latency
        m_up = re.match(r"Host is up(?: \(([\d\.]+)s latency\))?", line)
        if m_up:
            data["host_up"] = True
            if m_up.group(1):
                try:
                    data["host_latency"] = float(m_up.group(1))
                except Exception:
                    pass
            continue

        # Other addresses
        m_other = re.match(r"Other addresses for .+?:\s*(.*)$", line)
        if m_other:
            rem = m_other.group(1).strip()
            # may be comma separated addresses
            addrs = [a.strip() for a in re.split(r"[,\s]+", rem) if a.strip()]
            data["other_addresses"].extend(addrs)
            continue

        # Not shown summary
        if line.startswith("Not shown:"):
            data["not_shown_summary"] = line
            continue

        # Network Distance
        if line.startswith("Network Distance:") or line.startswith("Network distance:"):
            data["network_distance"] = line
            continue

        # Service Info
        if line.startswith("Service Info:"):
            data["service_info"] = line[len("Service Info:"):].strip()
            continue

        # Aggressive OS guesses line(s)
        if line.startswith("Aggressive OS guesses:") or line.startswith("OS guesses:"):
            # everything after colon may continue on this same line, split by commas
            guesses_part = line.split(":", 1)[1].strip()
            # parse comma separated guesses like "Linux 4.19 - 5.15 (94%), Linux 4.15 (90%)"
            parts = [p.strip() for p in re.split(r",(?=\s*[A-Za-z0-9])", guesses_part) if p.strip()]
            for p in parts:
                m = re.match(r"(.+?)\s*\(?(\d+)%\)?$", p)
                if m:
                    guess = m.group(1).strip()
                    pct = int(m.group(2))
                    data["os_guesses"].append((guess, pct))
                else:
                    data["os_guesses"].append((p, None))
            continue

        # Too many fingerprints / OS detection lines
        if "Too many fingerprints" in line or "OS details" in line or line.startswith("OS:") or line.startswith("OS guesses:"):
            data["os_text"] = (data.get("os_text") or "") + (" " + line if data.get("os_text") else line)
            continue

        # TRACEROUTE block parsing (capture hop lines after TRACEROUTE header)
        if line.startswith("TRACEROUTE"):
            j = i + 1
            while j < len(lines):
                hop_line = lines[j].strip()
                if not hop_line:
                    break
                m_hop = re.match(r"^\s*(\d+)\s+([\d\.]+)\s+ms\s+(.+)$", hop_line)
                if m_hop:
                    try:
                        hop = int(m_hop.group(1))
                        rtt = float(m_hop.group(2))
                        addr = m_hop.group(3).strip()
                        data["traceroute"].append({"hop": hop, "rtt_ms": rtt, "address": addr})
                    except Exception:
                        pass
                j += 1
            continue

        # Ports entries e.g. "22/tcp    open  ssh    OpenSSH 6.6.1p1 Ubuntu-2ubuntu2.13"
        m_port = re.match(r"^(\d+)\/tcp\s+(\S+)\s+(\S+)\s*(.*)$", line)
        if m_port:
            port = int(m_port.group(1))
            state = m_port.group(2)
            service = m_port.group(3)
            version = m_port.group(4).strip() or None
            data["ports"].append({"port": port, "state": state, "service": service, "version": version})
            continue

    return data


# ----------------------------
# CLI
# ----------------------------
def build_argparser():
    p = argparse.ArgumentParser(prog="port_scanner", description="Async Port Scanner with banner grabbing, exports and optional nmap integration")
    p.add_argument("target", help="Hostname or IP to scan")
    p.add_argument("--start", "-s", type=int, default=DEFAULT_START_PORT)
    p.add_argument("--end", "-e", type=int, default=DEFAULT_END_PORT)
    p.add_argument("--concurrency", "-c", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--connect-timeout", type=float, default=CONNECT_TIMEOUT)
    p.add_argument("--read-timeout", type=float, default=READ_TIMEOUT)
    p.add_argument("--rate-delay", type=float, default=DEFAULT_RATE_DELAY)
    p.add_argument("--jitter", type=float, default=DEFAULT_JITTER)
    p.add_argument("--json", type=str, help="Path to write JSON report")
    p.add_argument("--csv", type=str, help="Path to write CSV report")
    p.add_argument("--log", type=str, default=LOG_FILENAME)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--use-nmap", action="store_true", help="Run nmap and include its findings")
    p.add_argument("--nmap-ports", default=None, help="Ports for nmap (e.g. 1-1024)")
    p.add_argument("--no-banner", action="store_true")
    p.add_argument("--nmap-aggressive", action="store_true", help="If using --use-nmap, run aggressive scan (-A). Requires root for full effect.")
    return p

def main():
    # interactive if no args
    if len(sys.argv) == 1:
        try:
            host = input("Target (hostname or IP) [e.g. 127.0.0.1]: ").strip()
            if not host:
                print("No host provided. Exiting.")
                sys.exit(1)
            start = int(input(f"Start port [default {DEFAULT_START_PORT}]: ").strip() or DEFAULT_START_PORT)
            end = int(input(f"End port [default {DEFAULT_END_PORT}]: ").strip() or DEFAULT_END_PORT)
            concurrency = int(input(f"Concurrency [default {DEFAULT_CONCURRENCY}]: ").strip() or DEFAULT_CONCURRENCY)
            setup_logging(level=logging.INFO)
        except (EOFError, KeyboardInterrupt):
            print("\nNo input provided. Exiting.")
            sys.exit(1)
        except ValueError:
            print("Ports and concurrency must be integers. Exiting.")
            sys.exit(1)

        if start < 1 or end > 65535 or start > end:
            print("Invalid port range. Use 1-65535 and ensure start <= end.")
            sys.exit(1)
        ip = resolve_host(host)
        if not ip:
            print(f"Could not resolve host {host}. Exiting.")
            sys.exit(1)

        # run async scan
        try:
            ip_addr, raw_results = asyncio.run(scan_range(host, start, end, concurrency, CONNECT_TIMEOUT, READ_TIMEOUT, DEFAULT_RATE_DELAY, DEFAULT_JITTER))
        except KeyboardInterrupt:
            logging.warning("Scan interrupted by user.")
            sys.exit(1)
        enriched = analyze_results(raw_results)
        print_report(host, ip_addr, start, end, enriched)
        sys.exit(0)

    # CLI mode
    args = build_argparser().parse_args()
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO)

    if args.start < 1 or args.end > 65535 or args.start > args.end:
        sys.exit("Invalid port range.")
    ip = resolve_host(args.target)
    if not ip:
        sys.exit(f"Could not resolve {args.target}")

    nmap_info: Optional[Dict] = None
    if args.use_nmap:
        nmap_ports = args.nmap_ports or f"{args.start}-{args.end}"
        logging.info("Invoking nmap (this may require privileges if you selected aggressive mode)...")
        nmap_out = run_nmap_service_scan(args.target, ports=nmap_ports, aggressive=args.nmap_aggressive)
        if nmap_out:
            nmap_info = parse_nmap_aggressive(nmap_out)
            # print nmap summary early so user sees details
            logging.info("Nmap output captured. Parsed %d ports.", len(nmap_info.get("ports", [])))
            print("\n=== Nmap Output Summary ===")
            if nmap_info.get("os"):
                print("OS:", nmap_info.get("os"))
            if nmap_info.get("service_info"):
                print("Service Info:", nmap_info.get("service_info"))
            if nmap_info.get("ports"):
                for p in nmap_info["ports"]:
                    print(f"- Port {p['port']} {p['state']} {p['service']} {p.get('version') or ''}")
            if nmap_info.get("traceroute"):
                print("\nTraceroute (first hops):")
                for hop in nmap_info["traceroute"][:6]:
                    print(f" {hop['hop']:2d} {hop['rtt_ms']} ms {hop['address']}")
            print("=" * 30)

    # run our async scanner
    try:
        read_timeout = 0.01 if args.no_banner else args.read_timeout
        ip_addr, raw_results = run_scan_sync(args.target, args.start, args.end, args.concurrency,
                                             connect_timeout=args.connect_timeout,
                                             read_timeout=read_timeout,
                                             rate_delay=args.rate_delay,
                                             jitter=args.jitter)
    except KeyboardInterrupt:
        logging.warning("Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        logging.error("Scan failed: %s", e)
        sys.exit(1)

    enriched = analyze_results(raw_results)

    # merge nmap-reported ports into enriched results (without losing banner info)
    if args.use_nmap and nmap_info:
        nm_by_port = {p["port"]: p for p in nmap_info.get("ports", [])}
        # add/merge info
        ports_seen = {r["port"] for r in enriched}
        for port, nm in nm_by_port.items():
            if port not in ports_seen:
                # create a synthetic entry from nmap
                enriched.append({
                    "port": port,
                    "state": nm.get("state", "unknown"),
                    "service_hint": None,
                    "detected_service": nm.get("service"),
                    "version": nm.get("version"),
                    "banner": None,
                    "insecure_note": INSECURE_NOTES.get(nm.get("service")) if nm.get("service") else None,
                    "rtt_ms": 0.0,
                })
        enriched.sort(key=lambda x: x["port"])

    # print final report (includes nmap summary if present)
    print_report(args.target, ip_addr, args.start, args.end, enriched, nmap_info)

    # exports
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
