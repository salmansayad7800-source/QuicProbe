import csv
import json
import os
import re
from html import escape
from typing import Dict, List


QUIC_MARKERS = {
    "QUIC": "QUIC",
    "HTTP/3": "HTTP/3",
    "HTTP3": "HTTP3",
    "h3": "ALPN h3",
    "Connection ID": "Connection ID",
    "Version 1": "Version 1",
    "version 1": "version 1",
    "UDP": "UDP",
    "0-RTT": "0-RTT",
    "transport parameter": "Transport Parameters",
    "TLS": "TLS",
    "ALPN": "ALPN",
    "packet": "packet",
}


def _normalize_text(text: str) -> str:
    return text.replace("\r", "\n").strip()


def scan_text(text: str) -> Dict[str, object]:
    cleaned = _normalize_text(text)
    if not cleaned:
        return {
            "is_quic_likely": False,
            "score": 0,
            "markers_found": [],
            "protocols": [],
            "summary": "No input data to analyze.",
        }

    found: List[str] = []
    score = 0

    lowered = cleaned.lower()
    for marker_key, marker_value in QUIC_MARKERS.items():
        if marker_key.lower() in lowered:
            found.append(marker_value)
            score += 1

    is_quic_likely = score >= 2
    summary = (
        "QUIC-like indicators detected."
        if is_quic_likely
        else "Insufficient QUIC indicators were detected."
    )

    return {
        "is_quic_likely": is_quic_likely,
        "score": score,
        "markers_found": found,
        "protocols": _detected_protocols(lowered),
        "summary": summary,
    }


def _detected_protocols(lowered_text: str) -> List[str]:
    protocols = []
    if "quic" in lowered_text:
        protocols.append("QUIC")
    if "http/3" in lowered_text or "http3" in lowered_text or "alpn h3" in lowered_text:
        protocols.append("HTTP/3")
    if "udp" in lowered_text:
        protocols.append("UDP")
    if "tls" in lowered_text:
        protocols.append("TLS")
    return protocols


def _normalize_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))


def classify_risk(
    quic_score: int,
    failed_login_attempts: int,
    suspicious_ips: List[str],
    event_counts: Dict[str, int] = None,
) -> str:
    event_counts = event_counts or {}
    non_login_events = sum(
        event_counts.get(event_name, 0)
        for event_name in ("firewall_drop", "web_attack", "port_scan")
    )
    if suspicious_ips or failed_login_attempts >= 5 or quic_score >= 6 or non_login_events >= 3:
        return "high"
    if quic_score >= 3 or failed_login_attempts >= 2 or non_login_events >= 1:
        return "medium"
    return "low"


def scan_file(path: str) -> Dict[str, object]:
    resolved_path = _normalize_path(path)
    if not os.path.exists(resolved_path):
        raise FileNotFoundError(f"Path not found: {path}")

    with open(resolved_path, "r", encoding="utf-8", errors="replace") as handle:
        content = handle.read()

    return scan_text(content)


def analyze_security_log(text: str) -> Dict[str, object]:
    cleaned = _normalize_text(text)
    if not cleaned:
        return {
            "failed_login_attempts": 0,
            "suspicious_ips": [],
            "event_ips": {
                "failed_login": [],
                "firewall_drop": [],
                "web_attack": [],
                "port_scan": [],
            },
            "event_counts": {
                "failed_login": 0,
                "firewall_drop": 0,
                "web_attack": 0,
                "port_scan": 0,
            },
            "high_risk": False,
            "risk_level": "low",
            "summary": "No log content to analyze.",
        }

    event_patterns = {
        "failed_login": (
            "failed login",
            "failed password",
            "invalid user",
            "authentication failure",
            "authentication failed",
        ),
        "firewall_drop": ("drop", "deny", "blocked", "src="),
        "web_attack": (
            "union select",
            "../",
            "..\\",
            "<script",
            "sqlmap",
            "nikto",
        ),
        "port_scan": ("port scan", "nmap", "connection refused"),
    }
    failed_by_ip = {}
    event_ips = {event_name: set() for event_name in event_patterns}
    event_counts = {event_name: 0 for event_name in event_patterns}
    suspicious_keywords = tuple(
        keyword for keywords in event_patterns.values() for keyword in keywords
    )

    for line in cleaned.splitlines():
        lowered = line.lower()
        if not any(keyword in lowered for keyword in suspicious_keywords):
            continue

        if any(marker in lowered for marker in ("successful login", "accepted", "session opened")):
            continue

        ip = None
        for pattern in (
            r"from\s+(\d+\.\d+\.\d+\.\d+)",
            r"\bSRC\s*=\s*(\d+\.\d+\.\d+\.\d+)",
            r"\bsrc\s*=\s*(\d+\.\d+\.\d+\.\d+)",
            r"^\s*(\d+\.\d+\.\d+\.\d+)\b",
            r"\b(\d+\.\d+\.\d+\.\d+)\b",
        ):
            match = re.search(pattern, line, flags=re.IGNORECASE)
            if match:
                ip = match.group(1)
                break

        if not ip:
            continue

        for event_name, keywords in event_patterns.items():
            if any(keyword in lowered for keyword in keywords):
                event_counts[event_name] += 1
                event_ips[event_name].add(ip)

        if any(keyword in lowered for keyword in event_patterns["failed_login"]):
            failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

    suspicious_ips = [ip for ip, count in failed_by_ip.items() if count >= 2]
    failure_count = sum(failed_by_ip.values())
    risk_level = classify_risk(0, failure_count, suspicious_ips, event_counts)
    high_risk = risk_level == "high"

    return {
        "failed_login_attempts": failure_count,
        "suspicious_ips": suspicious_ips,
        "event_ips": {
            event_name: sorted(ips) for event_name, ips in event_ips.items()
        },
        "event_counts": event_counts,
        "high_risk": high_risk,
        "risk_level": risk_level,
        "summary": (
            "Repeated failed login attempts detected."
            if high_risk
            else "No strong evidence of brute-force activity detected."
        ),
    }


def analyze_path(path: str) -> Dict[str, object]:
    resolved_path = _normalize_path(path)

    if os.path.isdir(resolved_path):
        results = []
        for root, _, files in os.walk(resolved_path):
            for filename in sorted(files):
                full_path = os.path.join(root, filename)
                try:
                    detail = scan_file(full_path)
                    results.append({"file": full_path, **detail})
                except OSError:
                    continue

        aggregate = {
            "path": resolved_path,
            "is_quic_likely": any(item.get("is_quic_likely") for item in results),
            "scan_count": len(results),
            "results": results,
            "risk_level": classify_risk(
                sum(1 for item in results if item.get("is_quic_likely")),
                0,
                [],
            ),
        }
        return aggregate

    result = scan_file(resolved_path)
    result["risk_level"] = classify_risk(result.get("score", 0), 0, [])
    return {
        "path": resolved_path,
        **result,
    }


def analyze_paths(paths: List[str]) -> Dict[str, object]:
    combined_results = []
    suspicious_ips = set()
    overall_quic = False
    files_scanned = 0
    quic_files = 0
    quic_score = 0

    def collect_suspicious_ips_for_path(target_path: str):
        resolved = _normalize_path(target_path)
        found = set()
        if os.path.isdir(resolved):
            for root, _, files in os.walk(resolved):
                for filename in sorted(files):
                    file_path = os.path.join(root, filename)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
                            content = handle.read()
                    except OSError:
                        continue
                    found.update(analyze_security_log(content).get("suspicious_ips", []))
            return found

        try:
            with open(resolved, "r", encoding="utf-8", errors="replace") as handle:
                content = handle.read()
        except OSError:
            return found
        found.update(analyze_security_log(content).get("suspicious_ips", []))
        return found

    for path in paths:
        result = analyze_path(path)
        combined_results.append(result)
        if result.get("is_quic_likely"):
            overall_quic = True

        if isinstance(result.get("results"), list):
            files_scanned += len(result["results"])
            quic_files += sum(1 for item in result["results"] if item.get("is_quic_likely"))
            quic_score += sum(item.get("score", 0) for item in result["results"])
            for item in result["results"]:
                if item.get("is_quic_likely"):
                    overall_quic = True
        elif result.get("path"):
            files_scanned += 1
            quic_score += result.get("score", 0)
            if result.get("is_quic_likely"):
                quic_files += 1

    if combined_results:
        for item in combined_results:
            if isinstance(item.get("suspicious_ips"), list):
                suspicious_ips.update(item["suspicious_ips"])

        for path in paths:
            suspicious_ips.update(collect_suspicious_ips_for_path(path))

    summary = {
        "path_count": len(paths),
        "is_quic_likely": overall_quic,
        "quic_score": quic_score,
        "files_scanned": files_scanned,
        "quic_files": quic_files,
        "risk_level": classify_risk(quic_score, 0, list(suspicious_ips)),
        "suspicious_ips": sorted(suspicious_ips),
        "results": combined_results,
        "summary": (
            "QUIC-like indicators detected in the scanned paths."
            if overall_quic
            else "No strong QUIC indicators detected in the scanned paths."
        ),
    }
    return summary


def export_json_report(data: Dict[str, object], path: str) -> str:
    resolved_path = _normalize_path(path)
    with open(resolved_path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    return resolved_path


def export_csv_report(data: Dict[str, object], path: str) -> str:
    resolved_path = _normalize_path(path)
    with open(resolved_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["key", "value"])
        for key, value in data.items():
            if isinstance(value, list):
                value = "; ".join(str(item) for item in value)
            elif isinstance(value, dict):
                value = json.dumps(value, ensure_ascii=False)
            writer.writerow([key, value])
    return resolved_path


def export_html_report(data: Dict[str, object], path: str) -> str:
    resolved_path = _normalize_path(path)
    risk_level = str(data.get("risk_level", "low")).lower()
    risk_class = risk_level if risk_level in {"low", "medium", "high"} else "low"
    summary = escape(str(data.get("summary", "No summary available.")))
    metric_values = {
        "Risk level": risk_level.upper(),
        "Files scanned": data.get("files_scanned", data.get("scan_count", "-")),
        "QUIC files": data.get("quic_files", "-"),
        "Suspicious IPs": len(data.get("suspicious_ips", [])),
    }
    metrics = "\n".join(
        f'<div class="metric"><span>{escape(label)}</span><strong>{escape(str(value))}</strong></div>'
        for label, value in metric_values.items()
    )
    rows = "\n".join(
        f"<tr><th>{escape(str(key))}</th><td>{escape(str(value))}</td></tr>"
        for key, value in data.items()
        if key != "results"
    )
    html = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>QuicProbe Report</title>
  <style>
        :root {{ color-scheme: dark; font-family: Segoe UI, Arial, sans-serif; }}
        body {{ margin: 0; background: #0b1120; color: #dbeafe; }}
        main {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px; }}
        header {{ border-bottom: 1px solid #263449; padding-bottom: 24px; }}
        h1 {{ margin: 0 0 8px; color: #f8fafc; }}
        .summary {{ color: #a7b5c9; font-size: 1.05rem; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 24px 0; }}
        .metric {{ background: #111c31; border: 1px solid #263449; padding: 16px; }}
        .metric span {{ display: block; color: #8fa3bd; font-size: .8rem; text-transform: uppercase; letter-spacing: .08em; }}
        .metric strong {{ display: block; margin-top: 8px; color: #f8fafc; font-size: 1.35rem; }}
        .metric:first-child strong {{ color: #{"22c55e" if risk_class == "low" else "f59e0b" if risk_class == "medium" else "f87171"}; }}
        section {{ background: #111827; border: 1px solid #263449; padding: 20px; overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border-bottom: 1px solid #263449; padding: 12px; text-align: left; vertical-align: top; }}
        th {{ color: #93c5fd; width: 25%; }}
        td {{ color: #dbeafe; word-break: break-word; }}
        @media (max-width: 600px) {{ main {{ padding: 22px 12px; }} th {{ width: 35%; }} }}
  </style>
</head>
<body>
    <main>
        <header>
    <h1>QuicProbe Security Report</h1>
        <div class=\"summary\">{summary}</div>
        </header>
        <div class=\"metrics\">{metrics}</div>
        <section>
    <table>
      {rows}
    </table>
        </section>
    </main>
</body>
</html>
"""
    with open(resolved_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return resolved_path


if __name__ == "__main__":
    sample = "QUIC Version 1\nHTTP/3\nConnection ID: 123\n"
    print(json.dumps(scan_text(sample), indent=2))
