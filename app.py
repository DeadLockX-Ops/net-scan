# app.py
from flask import Flask, render_template, request, jsonify, Response
from concurrent.futures import ThreadPoolExecutor, Future
import uuid
import time
import logging
import datetime
from typing import Tuple, Dict, Any

# scanner functions (from your uploaded port_scanner.py)
from port_scanner import (
    run_scan_sync,
    analyze_results,
    format_scan_results,        # you defined this in port_scanner.py
    run_nmap_service_scan,      # nmap runner (aggressive flag supported)
    parse_nmap_aggressive       # parser for -A output
)

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# background job store & executor
jobs: Dict[str, Dict[str, Any]] = {}
executor = ThreadPoolExecutor(max_workers=4)

MAX_PORT_RANGE = 2000
MAX_CONCURRENCY = 2000

# ---------------- Helper functions ----------------
def validate_params(target: str, start: int, end: int, concurrency: int):
    if not target:
        raise ValueError("target required")
    if start < 1 or end > 65535 or start > end:
        raise ValueError("invalid port range")
    if (end - start + 1) > MAX_PORT_RANGE:
        raise ValueError(f"port range too large (limit {MAX_PORT_RANGE})")
    if concurrency < 1 or concurrency > MAX_CONCURRENCY:
        raise ValueError("invalid concurrency")


def run_scan_task(target: str, start: int, end: int, concurrency: int,
                  connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float,
                  no_banner: bool, use_nmap: bool = False, aggressive: bool = False) -> dict:
    """
    Run the Python async scanner synchronously via run_scan_sync, then analyze and format.
    Optionally run nmap (parsed) and attach results under '_nmap'.
    """
    try:
        # 1) run async scanner
        ip, raw = run_scan_sync(target, start, end, concurrency,
                                connect_timeout, (0.01 if no_banner else read_timeout),
                                rate_delay, jitter)
        enriched = analyze_results(raw)

        result_obj = {
            "status": "done",
            "target": target,
            "resolved_ip": ip,
            "start": start,
            "end": end,
            "results": enriched,
            "scanned_at": time.time()
        }

        # 2) optionally run nmap and parse it
                # 2) optionally run nmap and parse it
        if use_nmap:
            logging.info("Invoking nmap for job (target=%s ports=%s aggressive=%s)", target, f"{start}-{end}", aggressive)
            nmap_out = run_nmap_service_scan(target, ports=f"{start}-{end}", aggressive=aggressive)
            if nmap_out:
                # parse nmap output first (so nmap_info exists for logging / merging)
                nmap_info = parse_nmap_aggressive(nmap_out)

                # then safe logging (avoid referencing nmap_info before it's defined)
                logging.info("nmap_out (first 200 chars): %s", nmap_out[:200].replace("\n","\\n"))
                logging.info("parsed nmap_info keys: %s", list(nmap_info.keys()))

                result_obj["_nmap"] = nmap_info

                # merge nmap ports into enriched results (without losing banners)
                nm_by_port = {p["port"]: p for p in nmap_info.get("ports", [])}
                ports_seen = {r["port"] for r in enriched}
                for port, nm in nm_by_port.items():
                    if port not in ports_seen:
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
                result_obj["results"] = enriched


        # 3) generate final formatted output AFTER attaching _nmap
        try:
            result_obj["_formatted"] = format_scan_results(result_obj)
        except Exception:
            logging.exception("Failed to format scan results")

        return result_obj
    except Exception as e:
        logging.exception("Scan failed for %s", target)
        return {"status": "error", "error": str(e)}



def create_scan_job(target: str, start: int, end: int, concurrency: int,
                    connect_timeout: float, read_timeout: float, rate_delay: float, jitter: float,
                    no_banner: bool, use_nmap: bool = False, aggressive: bool = False) -> Tuple[str, dict]:
    job_id = str(uuid.uuid4())
    created = time.time()

    def worker():
        return run_scan_task(target, start, end, concurrency,
                             connect_timeout, read_timeout, rate_delay, jitter,
                             no_banner, use_nmap=use_nmap, aggressive=aggressive)

    future = executor.submit(worker)
    jobs[job_id] = {"future": future, "created": created, "params": {"target": target, "start": start, "end": end, "use_nmap": use_nmap, "aggressive": aggressive}}
    return job_id, jobs[job_id]




# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan-blocking", methods=["POST"])
def scan_blocking():
    """
    Blocking endpoint: runs python scanner then (optionally) nmap -A and returns combined report text.
    Accepts JSON or form data fields:
      target, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter, no_banner, use_nmap, aggressive
    """
    data = request.get_json() or request.form
    try:
        target = data.get("target")
        start = int(data.get("start", 1))
        end = int(data.get("end", 1024))
        concurrency = int(data.get("concurrency", 200))
        connect_timeout = float(data.get("connect_timeout", 3.0))
        read_timeout = float(data.get("read_timeout", 2.0))
        rate_delay = float(data.get("rate_delay", 0.0))
        jitter = float(data.get("jitter", 0.02))
        no_banner = bool(data.get("no_banner", False))
        use_nmap = bool(data.get("use_nmap", False))
        aggressive = bool(data.get("aggressive", False))
        job_id, job_meta = create_scan_job(target, start, end, concurrency,
                                   connect_timeout, read_timeout, rate_delay, jitter, no_banner,
                                   use_nmap=use_nmap, aggressive=aggressive)

        validate_params(target, start, end, concurrency)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    try:
        # 1) Run python scanner (banners)
        result_obj = run_scan_task(target, start, end, concurrency, connect_timeout, read_timeout, rate_delay, jitter, no_banner)
        formatted_output = result_obj.get("_formatted") or format_scan_results(result_obj)

        # 2) Optionally run nmap -A (aggressive) or -sV
        if use_nmap:
            nmap_output = run_nmap_service_scan(target, ports=f"{start}-{end}", aggressive=aggressive)
            nmap_data = parse_nmap_aggressive(nmap_output) if nmap_output else None

            if nmap_data:
                # append a separated section for OS / traceroute / service info
                formatted_output += "\n\n" + "=" * 60
                formatted_output += "\nNmap OS & Network Information"
                formatted_output += "\n" + "=" * 60 + "\n"

                if nmap_data.get("host_up") is not None:
                    formatted_output += f"Host up: {nmap_data.get('host_up')}\n"
                if nmap_data.get("os_text"):
                    formatted_output += f"\nOS Detection: {nmap_data['os_text']}\n"
                if nmap_data.get("os_guesses"):
                    formatted_output += "\nAggressive OS Guesses:\n"
                    for guess, pct in nmap_data["os_guesses"]:
                        formatted_output += f"  - {guess} ({pct or '?'}%)\n"
                if nmap_data.get("network_distance"):
                    formatted_output += f"\n{nmap_data['network_distance']}\n"
                if nmap_data.get("service_info"):
                    formatted_output += f"\nService Info: {nmap_data['service_info']}\n"
                if nmap_data.get("traceroute"):
                    formatted_output += "\nTraceroute:\n"
                    for hop in nmap_data["traceroute"]:
                        formatted_output += f"  hop {hop.get('hop')}: {hop.get('rtt_ms')} ms  {hop.get('address')}\n"
                if nmap_data.get("ports"):
                    formatted_output += "\nNmap port table (from -A):\n"
                    for p in nmap_data["ports"]:
                        formatted_output += f"  - {p.get('port')}/tcp {p.get('state')} {p.get('service')} {p.get('version') or ''}\n"

        return Response(formatted_output, mimetype="text/plain")
    except Exception as e:
        logging.exception("Blocking scan failed")
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/scan", methods=["POST"])
def scan():
    """
    Non-blocking endpoint: creates a background job for the python scanner and returns job id.
    The frontend should poll /scan-status/<job_id>?format=txt to get the final formatted text.
    """
    data = request.get_json() or request.form
    try:
        target = data.get("target")
        start = int(data.get("start", 1))
        end = int(data.get("end", 1024))
        concurrency = int(data.get("concurrency", 200))
        connect_timeout = float(data.get("connect_timeout", 3.0))
        read_timeout = float(data.get("read_timeout", 2.0))
        rate_delay = float(data.get("rate_delay", 0.0))
        jitter = float(data.get("jitter", 0.02))
        no_banner = bool(data.get("no_banner", False))

        # <-- IMPORTANT: read these flags from the request so they are defined below -->
        use_nmap = bool(data.get("use_nmap", False))
        aggressive = bool(data.get("aggressive", False))

        validate_params(target, start, end, concurrency)
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 400

    # create the background job and pass nmap flags through
    job_id, job_meta = create_scan_job(target, start, end, concurrency,
                                       connect_timeout, read_timeout, rate_delay, jitter, no_banner,
                                       use_nmap=use_nmap, aggressive=aggressive)
    return jsonify({"status": "submitted", "job_id": job_id, "created": job_meta["created"], "params": job_meta["params"]})


@app.route("/scan-status/<job_id>", methods=["GET"])
def scan_status(job_id):
    meta = jobs.get(job_id)
    if not meta:
        return jsonify({"status": "error", "error": "job not found"}), 404

    future: Future = meta["future"]
    want_text = request.args.get("format", "").lower() in ("txt", "text", "plain")
    if future.done():
        result = future.result()
        if want_text:
            formatted = result.get("_formatted") or format_scan_results(result)
            return Response(formatted, mimetype="text/plain")
        else:
            return jsonify({"status": result.get("status", "done"), "result": result})

    else:
        return jsonify({"status": "running", "created": meta["created"], "params": meta["params"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
