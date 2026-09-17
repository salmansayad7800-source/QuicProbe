import os
import tempfile
import unittest

from quicprobe.core.analyzer import (
    analyze_paths,
    analyze_security_log,
    classify_risk,
    export_csv_report,
    export_html_report,
    export_json_report,
    scan_text,
    scan_file,
)


class QuicProbeAnalyzerTests(unittest.TestCase):
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
