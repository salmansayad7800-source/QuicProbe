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


def _colorize(value: object, color: str, enabled: bool) -> str:
    if not enabled:
        return str(value)
    return f"\033[{color}m{value}\033[0m"


def _color_enabled(no_color: bool) -> bool:
    return not no_color and sys.stdout.isatty()


def _risk_label(risk_level: str, enabled: bool) -> str:
    colors = {"low": "32", "medium": "33", "high": "31"}
    return _colorize(risk_level.upper(), colors.get(risk_level, "37"), enabled)


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

    scan_parser = subparsers.add_parser("scan", help="Scan one or more local or external file/directory paths.")
    scan_parser.add_argument("paths", nargs="+", help="Files/directories, including absolute paths such as C:\\Logs\\traffic.txt.")
    scan_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    scan_parser.add_argument("--export", help="Write the result to a JSON, CSV, or HTML file.")

    log_parser = subparsers.add_parser("log", help="Analyze one or more local or external security logs.")
    log_parser.add_argument("paths", nargs="+", help="Log files, including absolute paths such as /var/log/auth.log.")
    log_parser.add_argument("--json", action="store_true", help="Print JSON output.")
    log_parser.add_argument("--export", help="Write the result to a JSON, CSV, or HTML file.")

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
                print(json.dumps(result, indent=2, ensure_ascii=False))
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
                print(f"Suspicious IPs: {', '.join(result.get('suspicious_ips', [])) or 'none'}")
                print(f"Summary: {result.get('summary', 'No summary available.')}")
            return 0
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
                print(json.dumps(result, indent=2, ensure_ascii=False))
            else:
                print(f"Log files: {', '.join(args.paths)}")
                print(f"Failed login attempts: {result.get('failed_login_attempts', 0)}")
                print(f"Suspicious IPs: {', '.join(result.get('suspicious_ips', [])) or 'none'}")
                print(f"Risk level: {_risk_label(result.get('risk_level', 'low'), colors_enabled)}")
                print(f"Event types: {', '.join(f'{name}={count}' for name, count in result.get('event_counts', {}).items() if count) or 'none'}")
                print(f"Summary: {result.get('summary', 'No summary available.')}")
            return 0
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}")
            return 1

    if args.command == "info":
        print("QuicProbe")
        print("QUIC/HTTP3 analyzer and security log inspector")
        print(f"Version: {__version__}")
        if args.detail:
            print("- Uses only standard library modules")
            print("- Supports file and directory scanning")
            print("- Detects suspicious login patterns")
            print("- Exports JSON, CSV, and HTML reports")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
