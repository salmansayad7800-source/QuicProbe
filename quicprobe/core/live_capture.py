import os
import socket
import struct
import time
from typing import Dict, List, Optional


def list_interfaces() -> List[Dict[str, object]]:
    interfaces = []
    for index, name in socket.if_nameindex():
        interfaces.append({"index": index, "name": name})
    if not interfaces:
        interfaces.append({"index": 0, "name": "default"})
    return interfaces


def environment_doctor() -> Dict[str, object]:
    administrator = False
    if os.name == "nt":
        try:
            import ctypes
            administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            administrator = False
    else:
        administrator = hasattr(os, "geteuid") and os.geteuid() == 0

    try:
        import sklearn
        sklearn_status = {"available": True, "version": sklearn.__version__}
    except ImportError:
        sklearn_status = {"available": False, "version": None}

    return {
        "platform": os.name,
        "administrator": administrator,
        "raw_socket_supported": hasattr(socket, "AF_PACKET") or os.name == "nt",
        "interfaces": list_interfaces(),
        "scikit_learn": sklearn_status,
        "ready_for_live_capture": administrator and (hasattr(socket, "AF_PACKET") or os.name == "nt"),
    }


def _capture_socket(interface: Optional[str]):
    if os.name == "nt":
        local_address = interface or socket.gethostbyname(socket.gethostname())
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw_socket.bind((local_address, 0))
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return raw_socket, True

    if not hasattr(socket, "AF_PACKET"):
        raise OSError("Live capture is supported on Windows and Linux only.")
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    raw_socket.bind((interface or "any", 0))
    return raw_socket, False


def _as_ethernet(packet: bytes, ip_only: bool) -> bytes:
    if not ip_only or not packet or packet[0] >> 4 != 4:
        return packet
    return b"\x00" * 12 + struct.pack("!H", 0x0800) + packet


def capture_to_pcap(
    output_path: str,
    duration: float = 10.0,
    interface: Optional[str] = None,
    max_packets: int = 10_000,
    verbose: bool = False,
) -> Dict[str, object]:
    if duration <= 0:
        raise ValueError("Capture duration must be greater than zero.")
    if max_packets <= 0:
        raise ValueError("Maximum packet count must be greater than zero.")

    resolved_path = os.path.abspath(os.path.expanduser(os.path.expandvars(output_path)))
    os.makedirs(os.path.dirname(resolved_path) or ".", exist_ok=True)
    raw_socket, ip_only = _capture_socket(interface)
    packets: List[tuple] = []
    started = time.time()
    deadline = time.monotonic() + duration
    try:
        raw_socket.settimeout(0.25)
        while time.monotonic() < deadline and len(packets) < max_packets:
            try:
                packet, _ = raw_socket.recvfrom(65535)
            except socket.timeout:
                continue
            captured_packet = _as_ethernet(packet, ip_only)
            packets.append((time.time(), captured_packet))
            if verbose:
                print(f"captured packet={len(packets)} bytes={len(captured_packet)}")
    finally:
        if os.name == "nt":
            try:
                raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        raw_socket.close()

    with open(resolved_path, "wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in packets:
            seconds = int(timestamp)
            fraction = int((timestamp - seconds) * 1_000_000)
            handle.write(struct.pack("<IIII", seconds, fraction, len(packet), len(packet)))
            handle.write(packet)

    return {
        "path": resolved_path,
        "interface": interface or ("local host interface" if os.name == "nt" else "any"),
        "duration_seconds": round(time.time() - started, 3),
        "packets_captured": len(packets),
        "format": "pcap",
    }
