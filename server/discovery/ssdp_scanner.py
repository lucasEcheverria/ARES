"""UPnP/SSDP device discovery via a hand-rolled M-SEARCH multicast (SDD §4.2).

No third-party SSDP library — a raw UDP socket sends the M-SEARCH request to
the standard SSDP multicast group and collects responses for a fixed
timeout. Runs synchronously in a worker thread, same rationale as
`mdns_scanner.scan_mdns`.
"""

import asyncio
import socket
import time

from discovery.models import DiscoveredDevice

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_MSEARCH_REQUEST = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


def _parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.split("\r\n")[1:]:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip().upper()] = value.strip()
    return headers


def _scan_ssdp_sync(timeout_seconds: float) -> list[DiscoveredDevice]:
    devices: dict[str, DiscoveredDevice] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(_MSEARCH_REQUEST, (_SSDP_ADDR, _SSDP_PORT))

        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(65507)
            except TimeoutError:
                break
            ip = addr[0]
            headers = _parse_headers(data.decode("utf-8", errors="ignore"))
            service_type = headers.get("ST", "")
            device = devices.setdefault(
                ip, DiscoveredDevice(ip=ip, mac=None, service_types=[], response_port=_SSDP_PORT)
            )
            if service_type and service_type not in device.service_types:
                device.service_types.append(service_type)
    finally:
        sock.close()
    return list(devices.values())


async def scan_ssdp(timeout_seconds: float = 5.0) -> list[DiscoveredDevice]:
    """Send an M-SEARCH multicast and collect responses for `timeout_seconds`.

    Args:
        timeout_seconds: How long to listen for responses before returning.

    Returns:
        One `DiscoveredDevice` per responding IP, with `service_types`
        accumulated across every distinct `ST` header value it sent back.
    """
    return await asyncio.to_thread(_scan_ssdp_sync, timeout_seconds)
