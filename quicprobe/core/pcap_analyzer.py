import os
import pickle
import struct
from collections import defaultdict
from statistics import mean, pstdev
from typing import Dict, Iterator, List, Optional, Tuple

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
QUIC_PORTS = {443, 784, 885}
QUIC_VERSIONS = {"00000000", "00000001"}


def _parse_quic_header(payload: bytes) -> Optional[Dict[str, object]]:
    if not payload or not (payload[0] & 0x40):
        return None
    first_byte = payload[0]
    is_long = bool(first_byte & 0x80)
    if not is_long:
        return {
            "header_type": "short",
            "packet_type": "1-RTT/short",
            "version": None,
            "destination_cid": payload[1:9].hex() if len(payload) >= 9 else "",
            "source_cid": "",
        }
    if len(payload) < 6:
        return None
    version = payload[1:5].hex()
    packet_type_number = (first_byte >> 4) & 0x03
    packet_types = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
    destination_length = payload[5]
    cursor = 6
    if len(payload) < cursor + destination_length + 1:
        return None
    destination_cid = payload[cursor:cursor + destination_length].hex()
    cursor += destination_length
    source_length = payload[cursor]
    cursor += 1
    if len(payload) < cursor + source_length:
        return None
    return {
        "header_type": "long",
        "packet_type": packet_types[packet_type_number],
        "version": version,
        "destination_cid": destination_cid,
        "source_cid": payload[cursor:cursor + source_length].hex(),
    }


def _ipv4(value: bytes) -> str:
    return ".".join(str(part) for part in value)


def _flow_key(protocol: str, source: str, source_port: int, destination: str, destination_port: int) -> Tuple[str, str, int, str, int]:
    if (source, source_port) <= (destination, destination_port):
        return protocol, source, source_port, destination, destination_port
    return protocol, destination, destination_port, source, source_port


def _parse_packet(packet: bytes):
    if len(packet) < 14:
        return None
    ether_type = struct.unpack("!H", packet[12:14])[0]
    offset = 14
    if ether_type == 0x8100 and len(packet) >= 18:
        ether_type = struct.unpack("!H", packet[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(packet) < offset + 20:
        return None
    version_ihl = packet[offset]
    if version_ihl >> 4 != 4:
        return None
    header_length = (version_ihl & 0x0F) * 4
    if len(packet) < offset + header_length:
        return None
    protocol_number = packet[offset + 9]
    source = _ipv4(packet[offset + 12:offset + 16])
    destination = _ipv4(packet[offset + 16:offset + 20])
    transport_offset = offset + header_length
    if protocol_number == 17 and len(packet) >= transport_offset + 8:
        source_port, destination_port = struct.unpack("!HH", packet[transport_offset:transport_offset + 4])
        payload_size = max(0, len(packet) - transport_offset - 8)
        return "UDP", source, source_port, destination, destination_port, payload_size, packet[transport_offset + 8:]
    if protocol_number == 6 and len(packet) >= transport_offset + 20:
        source_port, destination_port = struct.unpack("!HH", packet[transport_offset:transport_offset + 4])
        data_offset = (packet[transport_offset + 12] >> 4) * 4
        payload_size = max(0, len(packet) - transport_offset - data_offset)
        return "TCP", source, source_port, destination, destination_port, payload_size, packet[transport_offset + data_offset:]
    return None


def _read_exact(handle, size: int) -> bytes:
    value = handle.read(size)
    if len(value) != size:
        raise ValueError("Truncated capture file.")
    return value


def _iter_pcap(handle, magic: bytes) -> Iterator[Tuple[float, bytes]]:
    endian, nanosecond = PCAP_MAGIC[magic]
    _read_exact(handle, 20)
    while True:
        header = handle.read(16)
        if not header:
            return
        if len(header) != 16:
            raise ValueError("Truncated PCAP packet header.")
        seconds, fraction, included_length, _ = struct.unpack(endian + "IIII", header)
        packet = _read_exact(handle, included_length)
        timestamp = seconds + fraction / (1_000_000_000 if nanosecond else 1_000_000)
        yield timestamp, packet


def _iter_pcapng(handle) -> Iterator[Tuple[float, bytes]]:
    endian = None
    resolutions = {}
    while True:
        header = handle.read(8)
        if not header:
            return
        if len(header) != 8:
            raise ValueError("Truncated PCAP-NG block header.")
        block_type_raw, length_raw = header[:4], header[4:]
        if block_type_raw == PCAPNG_MAGIC:
            length = struct.unpack("<I", length_raw)[0]
            body = _read_exact(handle, length - 12)
            _read_exact(handle, 4)
            if len(body) < 12 or body[:4] not in {b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"}:
                raise ValueError("Invalid PCAP-NG section header.")
            endian = "<" if body[:4] == b"\x4d\x3c\x2b\x1a" else ">"
            continue
        if endian is None:
            raise ValueError("PCAP-NG section header must be first.")
        block_type = struct.unpack(endian + "I", block_type_raw)[0]
        length = struct.unpack(endian + "I", length_raw)[0]
        body = _read_exact(handle, length - 12)
        _read_exact(handle, 4)
        if block_type == 1 and len(body) >= 8:
            interface_id = len(resolutions)
            resolutions[interface_id] = 1_000_000
        elif block_type == 6 and len(body) >= 20:
            interface_id, high, low, captured_length, _ = struct.unpack(endian + "IIIII", body[:20])
            packet = body[20:20 + captured_length]
            timestamp = ((high << 32) | low) / resolutions.get(interface_id, 1_000_000)
            yield timestamp, packet


def _iter_capture(path: str) -> Tuple[str, Iterator[Tuple[float, bytes]]]:
    handle = open(path, "rb")
    magic = handle.read(4)
    handle.seek(0)
    def managed(iterator):
        try:
            yield from iterator
        finally:
            handle.close()

    if magic in PCAP_MAGIC:
        handle.read(4)
        return "pcap", managed(_iter_pcap(handle, magic))
    if magic == PCAPNG_MAGIC:
        return "pcapng", managed(_iter_pcapng(handle))
    handle.close()
    raise ValueError("Unsupported capture format. Use classic PCAP or PCAP-NG.")


def _load_keylog(path: Optional[str]) -> Dict[str, object]:
    if not path:
        return {"provided": False, "entries": 0, "decryption": "not performed; no TLS key log supplied"}
    if not os.path.exists(path):
        raise FileNotFoundError(f"TLS key log not found: {path}")
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        entries = sum(1 for line in handle if line.strip() and not line.lstrip().startswith("#"))
    return {"provided": True, "entries": entries, "decryption": "keys found but QUIC/TLS payload decryption is not implemented"}


def _run_ml(flow_results: List[Dict[str, object]], model_path: Optional[str] = None) -> Dict[str, object]:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return {"available": False, "model": "IsolationForest", "anomalies": 0, "message": "Install scikit-learn to enable ML anomaly detection."}
    if len(flow_results) < 3:
        return {"available": True, "model": "IsolationForest", "anomalies": 0, "message": "At least three flows are required for ML scoring."}
    features = [[item["packets"], item["payload_bytes"], item["directional_byte_ratio"], item["periodicity_variation"] or 0.0] for item in flow_results]
    if model_path:
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"ML model not found: {model_path}")
        with open(model_path, "rb") as handle:
            model = pickle.load(handle)
    else:
        model = IsolationForest(random_state=42, contamination="auto").fit(features)
    predictions = model.predict(features)
    anomalies = 0
    for item, prediction in zip(flow_results, predictions):
        item["ml_anomaly"] = prediction == -1
        anomalies += prediction == -1
    return {"available": True, "model": "IsolationForest", "anomalies": anomalies, "message": "Unsupervised anomaly scores added to flows."}


def train_ml_model(paths: List[str], output_path: str) -> Dict[str, object]:
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:
        raise ImportError("Install scikit-learn first: python -m pip install -e \".[ml]\"") from exc
    features = []
    for path in paths:
        result = analyze_pcap(path)
        for flow in result["results"]:
            features.append([
                flow["packets"],
                flow["payload_bytes"],
                flow["directional_byte_ratio"],
                flow["periodicity_variation"] or 0.0,
            ])
    if len(features) < 3:
        raise ValueError("At least three clean flows are required to train the model.")
    model = IsolationForest(random_state=42, contamination="auto").fit(features)
    resolved_output = os.path.abspath(os.path.expanduser(os.path.expandvars(output_path)))
    os.makedirs(os.path.dirname(resolved_output) or ".", exist_ok=True)
    with open(resolved_output, "wb") as handle:
        pickle.dump(model, handle)
    return {"model": "IsolationForest", "training_flows": len(features), "path": resolved_output}


def _calculate_risk_level(
    *,
    amplification_warnings: int = 0,
    padding_violations: int = 0,
    handshake_flood: bool = False,
    exfiltration_flows: int = 0,
    c2_flows: int = 0,
    ml_anomalies: int = 0,
    cid_linkability_warnings: int = 0,
    downgrade_warnings: int = 0,
) -> str:
    """Apply tiered risk policy; protocol candidates alone are not suspicious."""
    critical_activity = (
        amplification_warnings > 0
        or padding_violations > 0
        or handshake_flood
        or exfiltration_flows > 0
        or c2_flows > 0
    )
    if critical_activity:
        return "high"
    if ml_anomalies > 0 or cid_linkability_warnings > 0 or downgrade_warnings > 0:
        return "medium"
    return "low"


def analyze_pcap(
    path: str,
    keylog_path: Optional[str] = None,
    enable_ml: bool = False,
    check_amplification: bool = False,
    detect_downgrade: bool = False,
    track_cid: bool = False,
    model_path: Optional[str] = None,
    detect_flood: bool = False,
    check_padding: bool = False,
    track_migration: bool = False,
    inspect_headers: bool = False,
    flood_threshold: int = 20,
    flood_window: float = 1.0,
) -> Dict[str, object]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Capture file not found: {path}")
    resolved_path = os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
    capture_format, packets = _iter_capture(resolved_path)
    flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "timestamps": [], "directions": defaultdict(lambda: {"packets": 0, "bytes": 0}), "quic_versions": set(), "connection_ids": set(), "headers": []})
    quic_observations = []
    packet_count = 0
    skipped_packets = 0
    try:
        for timestamp, packet in packets:
            parsed = _parse_packet(packet)
            if parsed is None:
                skipped_packets += 1
                continue
            protocol, source, source_port, destination, destination_port, payload_size, payload = parsed
            key = _flow_key(protocol, source, source_port, destination, destination_port)
            flow = flows[key]
            flow["packets"] += 1
            flow["bytes"] += payload_size
            flow["timestamps"].append(timestamp)
            direction = (source, source_port, destination, destination_port)
            flow["directions"][direction]["packets"] += 1
            flow["directions"][direction]["bytes"] += payload_size
            if protocol == "UDP" and (source_port in {443, 784, 885} or destination_port in {443, 784, 885}) and payload:
                quic_header = _parse_quic_header(payload)
                if quic_header is None:
                    packet_count += 1
                    continue
                header_type = quic_header["header_type"]
                version = quic_header["version"]
                if version:
                    flow["quic_versions"].add(version)
                cid = quic_header["destination_cid"]
                if cid:
                    flow["connection_ids"].add(cid)
                if len(flow["headers"]) < 20:
                    flow["headers"].append(quic_header)
                quic_observations.append({
                    "timestamp": timestamp,
                    "source_ip": source,
                    "source_port": source_port,
                    "destination_ip": destination,
                    "destination_port": destination_port,
                    "payload_size": len(payload),
                    **quic_header,
                })
            packet_count += 1
    finally:
        packets.close()

    flow_results = []
    exfiltration_count = 0
    c2_count = 0
    quic_count = 0
    downgrade_count = 0
    cid_tracking_count = 0
    for key, flow in flows.items():
        protocol, first_host, first_port, second_host, second_port = key
        directions = list(flow["directions"].items())
        largest = max(directions, key=lambda item: item[1]["bytes"], default=(None, {"bytes": 0}))
        smallest_bytes = min((item[1]["bytes"] for item in directions), default=0)
        byte_ratio = largest[1]["bytes"] / max(1, smallest_bytes)
        intervals = [right - left for left, right in zip(flow["timestamps"], flow["timestamps"][1:])]
        interval_mean = mean(intervals) if intervals else 0
        periodicity = pstdev(intervals) / interval_mean if len(intervals) >= 3 and interval_mean else None
        is_quic = protocol == "UDP" and (first_port in QUIC_PORTS or second_port in QUIC_PORTS)
        is_exfiltration = largest[1]["bytes"] >= 100_000 and byte_ratio >= 10
        is_c2 = len(intervals) >= 4 and periodicity is not None and periodicity < 0.35 and flow["packets"] >= 5
        downgrade_warning = bool(detect_downgrade and any(version not in {"00000001", "00000000"} for version in flow["quic_versions"]))
        cid_tracking_warning = bool(track_cid and len(flow["connection_ids"]) > 1)
        quic_count += is_quic
        exfiltration_count += is_exfiltration
        c2_count += is_c2
        downgrade_count += downgrade_warning
        cid_tracking_count += cid_tracking_warning
        flow_results.append({
            "protocol": protocol,
            "endpoint_a": f"{first_host}:{first_port}",
            "endpoint_b": f"{second_host}:{second_port}",
            "packets": flow["packets"],
            "payload_bytes": flow["bytes"],
            "directional_byte_ratio": round(byte_ratio, 2),
            "periodicity_variation": round(periodicity, 3) if periodicity is not None else None,
            "quic_candidate": is_quic,
            "possible_exfiltration": is_exfiltration,
            "possible_c2": is_c2,
            "amplification_ratio": round(byte_ratio, 2) if is_quic else None,
            "amplification_warning": bool(is_quic and byte_ratio >= 3) if check_amplification else False,
            "downgrade_warning": downgrade_warning,
            "cid_tracking_warning": cid_tracking_warning,
            "quic_versions": sorted(flow["quic_versions"]),
            "connection_id_count": len(flow["connection_ids"]),
            "verbose_headers": flow["headers"] if detect_downgrade or track_cid else [],
        })

    ml_result = _run_ml(flow_results, model_path=model_path) if enable_ml else {"available": False, "enabled": False, "anomalies": 0, "message": "ML disabled; pass --ml to enable."}
    keylog_result = _load_keylog(keylog_path)
    initial_observations = [item for item in quic_observations if item["packet_type"] == "Initial"]
    handshake_sources = {item["source_ip"] for item in quic_observations if item["packet_type"] == "Handshake"}
    unanswered_initials = [item for item in initial_observations if item["source_ip"] not in handshake_sources]
    initial_by_source = defaultdict(list)
    for item in initial_observations:
        initial_by_source[item["source_ip"]].append(item)
    flood_sources = []
    for source_ip, items in initial_by_source.items():
        items.sort(key=lambda item: item["timestamp"])
        for start_index, item in enumerate(items):
            end_index = start_index
            while end_index < len(items) and items[end_index]["timestamp"] - item["timestamp"] <= flood_window:
                end_index += 1
            if end_index - start_index >= flood_threshold:
                flood_sources.append(source_ip)
                break
    padding_violations = [item for item in initial_observations if item["source_port"] not in QUIC_PORTS and item["payload_size"] < 1200]
    cid_endpoints = defaultdict(set)
    for item in quic_observations:
        cid = item["destination_cid"]
        if cid:
            cid_endpoints[cid].add((item["source_ip"], item["source_port"]))
    migration_events = {cid: sorted(f"{ip}:{port}" for ip, port in endpoints) for cid, endpoints in cid_endpoints.items() if len(endpoints) > 1}
    downgrade_observations = [item for item in quic_observations if item["version"] and item["version"] not in QUIC_VERSIONS]
    decryption = keylog_result["decryption"] if keylog_path else "not performed; QUIC/TLS payloads remain encrypted"
    amplification_warnings = sum(item["amplification_warning"] for item in flow_results)
    total_downgrade_warnings = downgrade_count + len(downgrade_observations)
    risk_level = _calculate_risk_level(
        amplification_warnings=amplification_warnings,
        padding_violations=len(padding_violations) if check_padding else 0,
        handshake_flood=bool(detect_flood and flood_sources),
        exfiltration_flows=exfiltration_count,
        c2_flows=c2_count,
        ml_anomalies=ml_result.get("anomalies", 0),
        cid_linkability_warnings=len(migration_events) if track_migration else 0,
        downgrade_warnings=total_downgrade_warnings if detect_downgrade else 0,
    )
    return {"path": resolved_path, "source_type": "pcap", "capture_format": capture_format, "packet_count": packet_count, "skipped_packets": skipped_packets, "flow_count": len(flow_results), "quic_candidate_flows": quic_count, "possible_exfiltration_flows": exfiltration_count, "possible_c2_flows": c2_count, "amplification_warnings": amplification_warnings, "downgrade_warnings": total_downgrade_warnings, "cid_tracking_warnings": cid_tracking_count, "checks": {"amplification": check_amplification, "downgrade": detect_downgrade, "connection_id_tracking": track_cid, "flood": detect_flood, "padding": check_padding, "migration": track_migration, "headers": inspect_headers}, "handshake_flood": {"enabled": detect_flood, "threshold": flood_threshold, "window_seconds": flood_window, "sources": sorted(set(flood_sources)), "unanswered_initial_count": len(unanswered_initials), "alert": bool(detect_flood and flood_sources)}, "padding_compliance": {"enabled": check_padding, "minimum_bytes": 1200, "violations": len(padding_violations), "alert": bool(check_padding and padding_violations)}, "migration": {"enabled": track_migration, "cid_endpoints": migration_events, "linkability_warnings": len(migration_events)}, "header_inspection": {"enabled": inspect_headers, "observations": quic_observations if inspect_headers else [], "legacy_or_draft_versions": sorted({item["version"] for item in downgrade_observations})}, "risk_level": risk_level, "decryption": decryption, "keylog": keylog_result, "ml": ml_result, "results": flow_results, "summary": "Capture metadata analyzed with statistical and optional QUIC security heuristics; findings require investigation."}
