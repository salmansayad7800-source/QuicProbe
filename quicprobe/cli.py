import argparse
import json
import sys
from . import __version__
from .core.analyzer import (
    analyze_path,
    analyze_paths,
    analyze_security_log,
    classify_risk,
    export_csv_report,
    export_html_report,
    export_json_report,
)
from .core.pcap_analyzer import analyze_pcap
from .core.live_capture import capture_to_pcap, environment_doctor, list_interfaces
from .core.pcap_analyzer import train_ml_model


def _colorize(value: object, color: str, enabled: bool) -> str:
    if not enabled:
        return str(value)
    return f"\033[{color}m{value}\033[0m"


def _color_enabled(no_color: bool) -> bool:
    return not no_color and sys.stdout.isatty()


def _risk_label(risk_level: str, enabled: bool) -> str:
    colors = {"low": "32", "medium": "33", "high": "31"}
    return _colorize(risk_level.upper(), colors.get(risk_level, "37"), enabled)


def _json_default(value):
    """Convert optional NumPy values produced by ML into JSON-safe values."""
    try:
        import numpy as np
    except ImportError:
        np = None

    if np is not None:
        if isinstance(value, np.integer):
            return int(value)
        if isinstance(value, np.floating):
            return float(value)
        if isinstance(value, np.bool_):
            return bool(value)
        if isinstance(value, np.ndarray):
            return value.tolist()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _json_dump(data, **kwargs) -> str:
    return json.dumps(data, default=_json_default, **kwargs)


def _print_pcap_summary(result) -> None:
    print("\nPCAP SECURITY SUMMARY")
    print("=" * 72)
    print(f"{'Metric':<32} {'Value':>12}   Status")
    print("-" * 72)
    rows = [
        ("Packets", result.get("packet_count", 0), "INFO"),
        ("QUIC candidate flows", result.get("quic_candidate_flows", 0), "INFO"),
        ("Handshake flood sources", len(result.get("handshake_flood", {}).get("sources", [])), "ALERT" if result.get("handshake_flood", {}).get("alert") else "OK"),
        ("Padding violations", result.get("padding_compliance", {}).get("violations", 0), "ALERT" if result.get("padding_compliance", {}).get("alert") else "OK"),
        ("Migration/linkability warnings", result.get("migration", {}).get("linkability_warnings", 0), "WARN" if result.get("migration", {}).get("linkability_warnings") else "OK"),
        ("Legacy/draft versions", len(result.get("header_inspection", {}).get("legacy_or_draft_versions", [])), "WARN" if result.get("header_inspection", {}).get("legacy_or_draft_versions") else "OK"),
        ("Amplification warnings", result.get("amplification_warnings", 0), "WARN" if result.get("amplification_warnings") else "OK"),
        ("Risk level", result.get("risk_level", "low").upper(), "ALERT" if result.get("risk_level") == "high" else "OK"),
    ]
    for name, value, status in rows:
        print(f"{name:<32} {str(value):>12}   {status}")


def _exit_code(result) -> int:
    return 2 if str(result.get("risk_level", "low")).lower() in {"medium", "high"} else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quicprobe",
        description="QuicProbe - QUIC/HTTP3 analyzer and security log inspector.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan local files/directories or HTTP(S) website URLs.")
    scan_parser.add_argument("paths", nargs="+", help="Files, directories, or http:// and https:// URLs.")
    scan_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    scan_parser.add_argument("--export", help="Write the result to a JSON, CSV, or HTML file.")

    log_parser = subparsers.add_parser("log", help="Analyze one or more local or external security logs.")
    log_parser.add_argument("paths", nargs="+", help="Log files, including absolute paths such as /var/log/auth.log.")
    log_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    log_parser.add_argument("--export", help="Write the result to a JSON, CSV, or HTML file.")

    pcap_parser = subparsers.add_parser("pcap", help="Analyze PCAP packet metadata and flow behavior.")
    pcap_parser.add_argument("paths", nargs="+", help="PCAP files to analyze.")
    pcap_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    pcap_parser.add_argument("--export", help="Write the result to a JSON, CSV, or HTML file.")
    pcap_parser.add_argument("--keylog", help="TLS key log file; reports availability but does not decrypt QUIC yet.")
    pcap_parser.add_argument("--ml", action="store_true", help="Enable optional IsolationForest anomaly detection.")
    pcap_parser.add_argument("--ml-model", help="Use a saved IsolationForest model.")
    pcap_parser.add_argument("--check-amplification", action="store_true", help="Report response/request ratios at or above 3x.")
    pcap_parser.add_argument("--detect-downgrade", action="store_true", help="Report detectable old or draft QUIC versions.")
    pcap_parser.add_argument("--track-cid", action="store_true", help="Report Connection ID tracking status when visible.")
    pcap_parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed flow findings.")
    pcap_parser.add_argument("--detect-flood", action="store_true", help="Detect rapid unanswered QUIC Initial floods.")
    pcap_parser.add_argument("--check-padding", action="store_true", help="Check client Initial packets for the 1200-byte minimum.")
    pcap_parser.add_argument("--track-migration", action="store_true", help="Track endpoint changes associated with a CID.")
    pcap_parser.add_argument("--inspect-headers", action="store_true", help="Print cleartext QUIC header fields.")

    live_parser = subparsers.add_parser("live", help="Capture live network traffic and analyze it as PCAP.")
    live_parser.add_argument("--duration", type=float, default=10.0, help="Capture duration in seconds (default: 10).")
    live_parser.add_argument("--timeout", type=float, dest="duration", default=argparse.SUPPRESS, help="Alias for --duration.")
    live_parser.add_argument("--interface", help="Interface or local address to capture from.")
    live_parser.add_argument("--iface", dest="interface", default=argparse.SUPPRESS, help="Alias for --interface.")
    live_parser.add_argument("--list-ifaces", action="store_true", help="List available network interfaces and exit.")
    live_parser.add_argument("--max-packets", type=int, default=10000, help="Stop after this many packets.")
    live_parser.add_argument("--count", type=int, dest="max_packets", default=argparse.SUPPRESS, help="Alias for --max-packets.")
    live_parser.add_argument("--output", default="reports\\live_capture.pcap", help="PCAP output path.")
    live_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    live_parser.add_argument("--export", help="Write the analysis result to a JSON, CSV, or HTML file.")
    live_parser.add_argument("--keylog", help="TLS key log file; reports availability but does not decrypt QUIC yet.")
    live_parser.add_argument("--ml", action="store_true", help="Enable optional IsolationForest anomaly detection.")
    live_parser.add_argument("--ml-model", help="Use a saved IsolationForest model.")
    live_parser.add_argument("--check-amplification", action="store_true", help="Report response/request ratios at or above 3x.")
    live_parser.add_argument("--detect-downgrade", action="store_true", help="Report detectable old or draft QUIC versions.")
    live_parser.add_argument("--track-cid", action="store_true", help="Report Connection ID tracking status when visible.")
    live_parser.add_argument("--verbose", "-v", action="store_true", help="Print detailed capture findings.")
    live_parser.add_argument("--detect-flood", action="store_true", help="Detect rapid unanswered QUIC Initial floods.")
    live_parser.add_argument("--check-padding", action="store_true", help="Check client Initial packets for the 1200-byte minimum.")
    live_parser.add_argument("--track-migration", action="store_true", help="Track endpoint changes associated with a CID.")
    live_parser.add_argument("--inspect-headers", action="store_true", help="Print cleartext QUIC header fields.")

    doctor_parser = subparsers.add_parser("doctor", help="Check permissions, interfaces, raw sockets, and ML availability.")
    doctor_parser.add_argument("--json", action="store_true", help="Print JSON output.")

    train_parser = subparsers.add_parser("ml-train", help="Train and save an IsolationForest model from clean PCAP files.")
    train_parser.add_argument("paths", nargs="+", help="Clean PCAP/PCAP-NG files used as training data.")
    train_parser.add_argument("--output", default="reports\\quicprobe_isolation_forest.pkl", help="Model output path.")

    info_parser = subparsers.add_parser("info", help="Show general project information.")
    info_parser.add_argument("--detail", action="store_true", help="Print more detailed info.")

    return parser


def _write_report(data, export_path: str):
    if not export_path:
        return
    extension = export_path.lower().split(".")[-1]
    if extension == "json":
        export_json_report(data, export_path)
    elif extension == "csv":
        export_csv_report(data, export_path)
    elif extension == "html":
        export_html_report(data, export_path)
    else:
        raise ValueError("Unsupported export format. Use .json, .csv, or .html")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    colors_enabled = _color_enabled(args.no_color)

    if args.command == "scan":
        try:
            result = analyze_paths(args.paths)
            if args.export:
                _write_report(result, args.export)
                print(f"Report exported to: {args.export}")
            if args.json or args.export:
                print(_json_dump(result, indent=2, ensure_ascii=False))
            else:
                print(f"Scanning: {', '.join(args.paths)}")
                quic_status = "YES" if result.get("is_quic_likely", False) else "NO"
                quic_color = "31" if quic_status == "YES" else "32"
                print(f"Likely QUIC traffic: {_colorize(quic_status, quic_color, colors_enabled)}")
                print(f"Path count: {result.get('path_count', len(args.paths))}")
                print(f"QUIC score: {result.get('quic_score', 0)}")
                print(f"Risk level: {_risk_label(result.get('risk_level', 'low'), colors_enabled)}")
                print(f"Files scanned: {result.get('files_scanned', 0)}")
                print(f"QUIC files: {result.get('quic_files', 0)}")
                if result.get("external_link_count") is not None:
                    print(f"External links: {result.get('external_link_count', 0)}")
                print(f"Suspicious IPs: {', '.join(result.get('suspicious_ips', [])) or 'none'}")
                print(f"Summary: {result.get('summary', 'No summary available.')}")
            return _exit_code(result)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1

    if args.command == "log":
        try:
            combined = {
                "failed_login_attempts": 0,
                "suspicious_ips": [],
                "event_ips": {},
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

            for path in args.paths:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    content = handle.read()
                result = analyze_security_log(content)
                combined["failed_login_attempts"] += result.get("failed_login_attempts", 0)
                combined["suspicious_ips"].extend(result.get("suspicious_ips", []))
                for event_name, event_count in result.get("event_counts", {}).items():
                    combined["event_counts"][event_name] = combined["event_counts"].get(event_name, 0) + event_count
                for event_name, ips in result.get("event_ips", {}).items():
                    combined["event_ips"].setdefault(event_name, set()).update(ips)
                if result.get("high_risk"):
                    combined["high_risk"] = True

            combined["suspicious_ips"] = sorted(set(combined["suspicious_ips"]))
            combined["event_ips"] = {
                event_name: sorted(ips)
                for event_name, ips in combined["event_ips"].items()
            }
            combined["risk_level"] = classify_risk(
                0,
                combined["failed_login_attempts"],
                combined["suspicious_ips"],
                combined["event_counts"],
            )
            combined["high_risk"] = combined["risk_level"] == "high"
            combined["summary"] = (
                "Repeated failed login attempts detected."
                if combined["high_risk"]
                else "No strong evidence of brute-force activity detected."
            )

            result = combined
            if args.export:
                _write_report(result, args.export)
                print(f"Report exported to: {args.export}")
            if args.json or args.export:
                print(_json_dump(result, indent=2, ensure_ascii=False))
            else:
                print(f"Log files: {', '.join(args.paths)}")
                print(f"Failed login attempts: {result.get('failed_login_attempts', 0)}")
                print(f"Suspicious IPs: {', '.join(result.get('suspicious_ips', [])) or 'none'}")
                print(f"Risk level: {_risk_label(result.get('risk_level', 'low'), colors_enabled)}")
                print(f"Event types: {', '.join(f'{name}={count}' for name, count in result.get('event_counts', {}).items() if count) or 'none'}")
                print(f"Summary: {result.get('summary', 'No summary available.')}")
            return _exit_code(result)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1

    if args.command == "pcap":
        try:
            results = [analyze_pcap(path, keylog_path=args.keylog, enable_ml=args.ml, check_amplification=args.check_amplification, detect_downgrade=args.detect_downgrade, track_cid=args.track_cid, model_path=args.ml_model, detect_flood=args.detect_flood, check_padding=args.check_padding, track_migration=args.track_migration, inspect_headers=args.inspect_headers) for path in args.paths]
            result = results[0] if len(results) == 1 else {
                "source_type": "pcap",
                "path_count": len(results),
                "results": results,
                "risk_level": "high" if any(item["risk_level"] == "high" for item in results) else "medium" if any(item["risk_level"] == "medium" for item in results) else "low",
                "summary": "Multiple PCAP files analyzed with statistical flow heuristics.",
            }
            if args.export:
                _write_report(result, args.export)
                print(f"Report exported to: {args.export}")
            if args.json or args.export:
                print(_json_dump(result, indent=2, ensure_ascii=False))
            else:
                print(f"PCAP files: {', '.join(args.paths)}")
                print(f"Risk level: {_risk_label(result.get('risk_level', 'low'), colors_enabled)}")
                print(f"Summary: {result.get('summary', 'No summary available.')}")
                _print_pcap_summary(result)
            if args.verbose:
                for item in result.get("header_inspection", {}).get("observations", []) or result.get("results", []):
                    print(_json_dump(item, ensure_ascii=False))
            return _exit_code(result)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1

    if args.command == "live":
        try:
            if args.list_ifaces:
                interfaces = list_interfaces()
                print(_json_dump(interfaces, indent=2, ensure_ascii=False) if args.json else "\n".join(f"{item['index']}: {item['name']}" for item in interfaces))
                return 0
            capture = capture_to_pcap(args.output, args.duration, args.interface, args.max_packets, args.verbose)
            result = analyze_pcap(args.output, keylog_path=args.keylog, enable_ml=args.ml, check_amplification=args.check_amplification, detect_downgrade=args.detect_downgrade, track_cid=args.track_cid, model_path=args.ml_model, detect_flood=args.detect_flood, check_padding=args.check_padding, track_migration=args.track_migration, inspect_headers=args.inspect_headers)
            result["capture"] = capture
            if args.export:
                _write_report(result, args.export)
                print(f"Report exported to: {args.export}")
            if args.json or args.export:
                print(_json_dump(result, indent=2, ensure_ascii=False))
            else:
                print(f"Captured packets: {capture['packets_captured']}")
                print(f"PCAP saved to: {capture['path']}")
                print(f"Risk level: {_risk_label(result.get('risk_level', 'low'), colors_enabled)}")
                print(f"Summary: {result.get('summary', 'No summary available.')}")
                _print_pcap_summary(result)
            return _exit_code(result)
        except (FileNotFoundError, OSError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1

    if args.command == "doctor":
        result = environment_doctor()
        print(_json_dump(result, indent=2, ensure_ascii=False) if args.json else "\n".join([
            f"Administrator: {'YES' if result['administrator'] else 'NO'}",
            f"Raw sockets: {'YES' if result['raw_socket_supported'] else 'NO'}",
            f"scikit-learn: {'YES' if result['scikit_learn']['available'] else 'NO'}",
            "Interfaces: " + ", ".join(item["name"] for item in result["interfaces"]),
            f"Ready: {'YES' if result['ready_for_live_capture'] else 'NO'}",
        ]))
        return 0 if result["ready_for_live_capture"] else 2

    if args.command == "ml-train":
        try:
            result = train_ml_model(args.paths, args.output)
            print(_json_dump(result, indent=2, ensure_ascii=False))
            return 0
        except (FileNotFoundError, ValueError, ImportError) as exc:
            print(f"Error: {exc}")
            return 1

    if args.command == "info":
        print("QuicProbe")
        print("QUIC/HTTP3 analyzer and security log inspector")
        print(f"Version: {__version__}")
        if args.detail:
            print("- Uses only standard library modules")
            print("- Supports file, directory, and HTTP(S) URL scanning")
            print("- Extracts external links from scanned web pages")
            print("- Analyzes PCAP flow metadata and statistical behavior")
            print("- Captures live traffic with platform raw sockets")
            print("- Detects suspicious login patterns")
            print("- Exports JSON, CSV, and HTML reports")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
