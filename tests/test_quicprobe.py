import os
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from quicprobe.core.analyzer import (
    analyze_paths,
    analyze_security_log,
    classify_risk,
    export_csv_report,
    export_html_report,
    export_json_report,
    scan_text,
    scan_file,
    scan_url,
)
from quicprobe.core.pcap_analyzer import _calculate_risk_level, analyze_pcap
from quicprobe.core.live_capture import capture_to_pcap
from quicprobe.cli import _format_doctor_report, _json_dump


class QuicProbeAnalyzerTests(unittest.TestCase):
    def test_risk_policy_keeps_ml_anomalies_at_medium(self):
        self.assertEqual(_calculate_risk_level(ml_anomalies=4), "medium")
        self.assertEqual(_calculate_risk_level(cid_linkability_warnings=1), "medium")
        self.assertEqual(_calculate_risk_level(ml_anomalies=4, cid_linkability_warnings=1), "medium")

    def test_risk_policy_uses_high_for_active_attacks_and_violations(self):
        self.assertEqual(_calculate_risk_level(padding_violations=1), "high")
        self.assertEqual(_calculate_risk_level(amplification_warnings=1), "high")
        self.assertEqual(_calculate_risk_level(handshake_flood=True), "high")
        self.assertEqual(_calculate_risk_level(c2_flows=1), "high")
        self.assertEqual(_calculate_risk_level(exfiltration_flows=1), "high")

    def test_risk_policy_returns_low_for_compliant_capture(self):
        self.assertEqual(_calculate_risk_level(), "low")
        self.assertEqual(_calculate_risk_level(ml_anomalies=0, cid_linkability_warnings=0), "low")

    @staticmethod
    def _quic_packet(source_ip, source_port, payload):
        ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ipv4 = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0])
        ipv4 += bytes(int(part) for part in source_ip.split(".")) + bytes([10, 0, 0, 9])
        udp = struct.pack("!HHHH", source_port, 443, 8 + len(payload), 0)
        total_length = 20 + len(udp) + len(payload)
        ipv4 = ipv4[:2] + struct.pack("!H", total_length) + ipv4[4:]
        return ethernet + ipv4 + udp + payload

    @staticmethod
    def _quic_header(packet_type=0, version=b"\x00\x00\x00\x01", cid=b"DEST", source_cid=b"SRC1"):
        first_byte = 0xC0 | (packet_type << 4)
        return bytes([first_byte]) + version + bytes([len(cid)]) + cid + bytes([len(source_cid)]) + source_cid

    def test_quic_security_checks_detect_flood_padding_downgrade_and_migration(self):
        initial = self._quic_header() + b"x" * 100
        draft = self._quic_header(version=b"\xff\x00\x00\x1d", cid=b"DRAF") + b"x" * 1200
        migrated = self._quic_header(cid=b"DEST") + b"x" * 40
        handshake = self._quic_header(packet_type=2) + b"x" * 100
        packets = [
            (1, self._quic_packet("10.0.0.1", 50000, initial)),
            (1.1, self._quic_packet("10.0.0.1", 50000, initial)),
            (1.2, self._quic_packet("10.0.0.1", 50000, initial)),
            (2, self._quic_packet("10.0.0.2", 50001, draft)),
            (3, self._quic_packet("10.0.0.3", 50002, migrated)),
            (4, self._quic_packet("10.0.0.1", 50000, handshake)),
        ]
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            handle.write(global_header)
            for timestamp, packet in packets:
                seconds = int(timestamp)
                fraction = int((timestamp - seconds) * 1_000_000)
                handle.write(struct.pack("<IIII", seconds, fraction, len(packet), len(packet)))
                handle.write(packet)
            path = handle.name

        try:
            result = analyze_pcap(
                path,
                detect_flood=True,
                check_padding=True,
                track_migration=True,
                inspect_headers=True,
                flood_threshold=3,
                flood_window=1.0,
            )
        finally:
            os.remove(path)

        self.assertEqual(result["handshake_flood"]["sources"], ["10.0.0.1"])
        self.assertGreaterEqual(result["padding_compliance"]["violations"], 1)
        self.assertGreaterEqual(result["downgrade_warnings"], 1)
        self.assertGreaterEqual(result["migration"]["linkability_warnings"], 1)
        self.assertTrue(result["header_inspection"]["observations"])
        self.assertEqual(result["risk_level"], "high")

    def test_cli_json_dump_handles_numpy_values(self):
        result = _json_dump({
            "count": np.int64(7),
            "score": np.float64(0.75),
            "enabled": np.bool_(True),
            "values": np.array([1, 2, 3]),
        })

        self.assertIn('"count": 7', result)
        self.assertIn('"score": 0.75', result)
        self.assertIn('"enabled": true', result)
        self.assertIn('"values": [1, 2, 3]', result)

    def test_format_doctor_report_uses_ascii_tables_and_grouped_interfaces(self):
        result = {
            "administrator": True,
            "raw_socket_supported": True,
            "scikit_learn": {"available": True, "version": "1.9.1"},
            "interfaces": [
                {"name": "Ethernet0"},
                {"name": "Wi-Fi"},
                {"name": "eth1"},
                {"name": "tun0"},
                {"name": "ppp0"},
                {"name": "lo"},
            ],
            "ready_for_live_capture": True,
        }

        report = _format_doctor_report(result)

        self.assertIn("System Health", report)
        self.assertIn("Administrator", report)
        self.assertIn("Raw Sockets", report)
        self.assertIn("scikit-learn", report)
        self.assertIn("Total Interfaces", report)
        self.assertIn("System Ready", report)
        self.assertIn("Interface Type", report)
        self.assertIn("| Ethernet", report)
        self.assertIn("| Wireless", report)
        self.assertIn("| Tunnel", report)
        self.assertIn("| PPP", report)
        self.assertIn("| Loopback", report)
        self.assertIn("+", report)
        self.assertIn("Total Interfaces", report)
        self.assertIn("6", report)

    def test_analyze_pcap_reads_udp_flow_metadata(self):
        ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ipv4 = bytes([0x45, 0, 0, 36, 0, 0, 0, 0, 64, 17, 0, 0])
        ipv4 += bytes([10, 0, 0, 2, 10, 0, 0, 3])
        udp = struct.pack("!HHHH", 53000, 443, 16, 0)
        packet = ethernet + ipv4 + udp + b"encrypted"
        global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        packet_header = struct.pack("<IIII", 1, 0, len(packet), len(packet))

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
            handle.write(global_header + packet_header + packet)
            path = handle.name

        try:
            result = analyze_pcap(path)
        finally:
            os.remove(path)

        self.assertEqual(result["packet_count"], 1)
        self.assertEqual(result["flow_count"], 1)
        self.assertEqual(result["quic_candidate_flows"], 1)
        self.assertEqual(result["decryption"], "not performed; QUIC/TLS payloads remain encrypted")

    def test_analyze_pcapng_reads_enhanced_packet_block(self):
        ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
        ipv4 = bytes([0x45, 0, 0, 36, 0, 0, 0, 0, 64, 17, 0, 0])
        ipv4 += bytes([10, 0, 0, 2, 10, 0, 0, 3])
        udp = struct.pack("!HHHH", 53000, 443, 16, 0)
        packet = ethernet + ipv4 + udp + b"encrypted"
        section_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
        section = struct.pack("<II", 0x0A0D0D0A, 28) + section_body + struct.pack("<I", 28)
        interface_body = struct.pack("<HHi", 1, 0, 65535)
        interface = struct.pack("<II", 1, 20) + interface_body + struct.pack("<I", 20)
        padded_packet = packet + b"\x00" * ((-len(packet)) % 4)
        enhanced_body = struct.pack("<IIIII", 0, 0, 1_000_000, len(packet), len(packet)) + padded_packet
        enhanced_length = 12 + len(enhanced_body)
        enhanced = struct.pack("<II", 6, enhanced_length) + enhanced_body + struct.pack("<I", enhanced_length)

        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as handle:
            handle.write(section + interface + enhanced)
            path = handle.name

        try:
            result = analyze_pcap(path)
        finally:
            os.remove(path)

        self.assertEqual(result["capture_format"], "pcapng")
        self.assertEqual(result["packet_count"], 1)
        self.assertEqual(result["quic_candidate_flows"], 1)

    def test_live_capture_writes_a_pcap_from_captured_packets(self):
        class FakeSocket:
            def __init__(self):
                self.sent_packet = False

            def settimeout(self, value):
                return None

            def recvfrom(self, size):
                if not self.sent_packet:
                    self.sent_packet = True
                    return b"\x45\x00" + b"\x00" * 38, ("10.0.0.1", 0)
                raise socket.timeout()

            def close(self):
                return None

            def ioctl(self, command, value):
                return None

        with patch("quicprobe.core.live_capture._capture_socket", return_value=(FakeSocket(), True)):
            with tempfile.TemporaryDirectory() as temp_dir:
                output_path = os.path.join(temp_dir, "live.pcap")
                result = capture_to_pcap(output_path, duration=0.01, max_packets=1)

                self.assertEqual(result["packets_captured"], 1)
                self.assertTrue(os.path.exists(output_path))

    def test_scan_text_detects_quic_markers(self):
        sample = """
        QUIC Version 1
        HTTP/3 connection established
        Connection ID: 1234567890
        """
        result = scan_text(sample)

        self.assertTrue(result["is_quic_likely"])
        self.assertIn("QUIC", result["markers_found"])
        self.assertIn("HTTP/3", result["markers_found"])
        self.assertGreater(result["score"], 0)

    def test_scan_file_reads_local_sample(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as handle:
            handle.write("QUIC\nHTTP/3\nConnection ID: 42\n")
            path = handle.name

        try:
            result = scan_file(path)
            self.assertTrue(result["is_quic_likely"])
            self.assertIn("QUIC", result["markers_found"])
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_scan_file_supports_external_absolute_path(self):
        with tempfile.TemporaryDirectory() as external_dir:
            path = os.path.join(external_dir, "external_quic.log")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("QUIC HTTP/3 UDP Connection ID: external\n")

            result = scan_file(path)

            self.assertTrue(result["is_quic_likely"])
            self.assertIn("HTTP/3", result["protocols"])

    def test_scan_url_extracts_external_links_and_page_indicators(self):
        class FakeHeaders:
            def get_content_charset(self):
                return "utf-8"

            def get_all(self, name, default):
                return ['h3=":443"'] if name == "Alt-Svc" else default

        class FakeResponse:
            headers = FakeHeaders()
            version = 11

            def read(self):
                return (
                    b"<html><body>QUIC and HTTP/3"
                    b'<a href="/local">local</a>'
                    b'<a href="https://external.example/report#top">external</a>'
                    b'<a href="https://external.example/report">duplicate</a>'
                    b"</body></html>"
                )

            def geturl(self):
                return "https://example.test/start"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

        with patch("quicprobe.core.analyzer.urlopen", return_value=FakeResponse()):
            result = scan_url("https://example.test/start")

        self.assertTrue(result["is_quic_likely"])
        self.assertTrue(result["http3_advertised"])
        self.assertEqual(result["http_version"], "1.1")
        self.assertEqual(result["transport_protocol"], "QUIC/HTTP3")
        self.assertEqual(result["external_link_count"], 1)
        self.assertEqual(result["external_links"], ["https://external.example/report"])

    def test_scan_url_returns_local_info_when_network_is_unavailable(self):
        with patch(
            "quicprobe.core.analyzer.urlopen",
            side_effect=OSError("network is unavailable"),
        ):
            result = scan_url("https://example.com:8443/path?a=1#section")

        self.assertTrue(result["offline_inspection"])
        self.assertFalse(result["network_available"])
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["port"], 8443)
        self.assertEqual(result["path"], "/path")
        self.assertTrue(result["has_query"])
        self.assertTrue(result["has_fragment"])

    def test_analyze_security_log_detects_failed_logins(self):
        sample = """
        2026-09-16 10:00:00 failed login for admin from 10.0.0.7
        2026-09-16 10:00:02 failed login for admin from 10.0.0.7
        2026-09-16 10:00:04 failed login for admin from 10.0.0.7
        2026-09-16 10:00:05 successful login from 10.0.0.12
        """

        result = analyze_security_log(sample)

        self.assertIn("10.0.0.7", result["suspicious_ips"])
        self.assertTrue(result["high_risk"])
        self.assertGreater(result["failed_login_attempts"], 2)

    def test_classify_risk_levels(self):
        self.assertEqual(classify_risk(9, 6, ["10.0.0.7"]), "high")
        self.assertEqual(classify_risk(1, 1, []), "low")

    def test_report_exports_create_files(self):
        data = {
            "status": "ok",
            "risk_level": "high",
            "summary": "Suspicious activity detected.",
            "markers_found": ["QUIC", "HTTP/3"],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = os.path.join(temp_dir, "report.json")
            csv_path = os.path.join(temp_dir, "report.csv")
            html_path = os.path.join(temp_dir, "report.html")

            export_json_report(data, json_path)
            export_csv_report(data, csv_path)
            export_html_report(data, html_path)

            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(html_path))
            with open(html_path, "r", encoding="utf-8") as handle:
                html = handle.read()
            self.assertIn("QuicProbe Security Report", html)
            self.assertIn("metrics", html)
            self.assertIn("risk level", html.lower())

    def test_analyze_paths_supports_multiple_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dir_a = os.path.join(temp_dir, "a")
            dir_b = os.path.join(temp_dir, "b")
            os.makedirs(dir_a)
            os.makedirs(dir_b)

            with open(os.path.join(dir_a, "one.txt"), "w", encoding="utf-8") as handle:
                handle.write("QUIC Version 1\nHTTP/3\n")

            with open(os.path.join(dir_b, "two.txt"), "w", encoding="utf-8") as handle:
                handle.write("failed login for admin from 10.0.0.9\nfailed login for admin from 10.0.0.9\n")

            result = analyze_paths([dir_a, dir_b])

            self.assertTrue(result["is_quic_likely"])
            self.assertIn("10.0.0.9", result["suspicious_ips"])
            self.assertEqual(result["files_scanned"], 2)
            self.assertEqual(result["quic_files"], 1)
            self.assertEqual(result["quic_score"], 4)

    def test_analyze_security_log_supports_more_formats(self):
        sample = """
        sshd[1234]: Invalid user admin from 10.0.0.8
        sshd[1235]: Failed password for invalid user root from 10.0.0.8
        firewall: DROP IN=eth0 OUT=eth1 SRC=10.0.0.8 DST=10.0.0.1
        """

        result = analyze_security_log(sample)

        self.assertIn("10.0.0.8", result["suspicious_ips"])
        self.assertTrue(result["high_risk"])
        self.assertEqual(result["failed_login_attempts"], 2)

    def test_security_log_classifies_multiple_event_types(self):
        sample = """
        firewall: DROP SRC=10.0.0.10 DST=10.0.0.1
        web: 10.0.0.11 GET /../../etc/passwd 404
        scanner: port scan from 10.0.0.12
        """

        result = analyze_security_log(sample)

        self.assertEqual(result["event_counts"]["firewall_drop"], 1)
        self.assertEqual(result["event_counts"]["web_attack"], 1)
        self.assertEqual(result["event_counts"]["port_scan"], 1)
        self.assertEqual(result["failed_login_attempts"], 0)
        self.assertEqual(result["event_ips"]["web_attack"], ["10.0.0.11"])
        self.assertEqual(result["risk_level"], "high")


if __name__ == "__main__":
    unittest.main()
