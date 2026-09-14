"""mDNS/Bonjour device discovery via `zeroconf` (SDD §4.2).

Runs synchronously in a worker thread (`asyncio.to_thread`) rather than
using zeroconf's asyncio-native API — this is plain blocking I/O bounded by
a fixed timeout, offloaded the same way `services/agent_runner.py` offloads
its blocking `subprocess.run` call.
"""

import asyncio
import time

from zeroconf import ServiceBrowser, ServiceListener, Zeroconf

from discovery.models import DiscoveredDevice

_SERVICE_TYPES = [
    "_googlecast._tcp.local.",
    "_airplay._tcp.local.",
    "_ipp._tcp.local.",
    "_http._tcp.local.",
]


class _CollectingListener(ServiceListener):
    """Collects one `DiscoveredDevice` per responding IP across all browsed types."""

    def __init__(self, devices: dict[str, DiscoveredDevice]) -> None:
        self._devices = devices

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        if info is None:
            return
        for ip in info.parsed_addresses():
            device = self._devices.setdefault(
                ip,
                DiscoveredDevice(ip=ip, mac=None, service_types=[], response_port=info.port),
            )
            if type_ not in device.service_types:
                device.service_types.append(type_)

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        self.add_service(zc, type_, name)

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        pass


def _scan_mdns_sync(timeout_seconds: float) -> list[DiscoveredDevice]:
    devices: dict[str, DiscoveredDevice] = {}
    zc = Zeroconf()
    try:
        listener = _CollectingListener(devices)
        browsers = [ServiceBrowser(zc, service_type, listener) for service_type in _SERVICE_TYPES]
        time.sleep(timeout_seconds)
        for browser in browsers:
            browser.cancel()
    finally:
        zc.close()
    return list(devices.values())


async def scan_mdns(timeout_seconds: float = 5.0) -> list[DiscoveredDevice]:
    """Browse the fixed mDNS service types for `timeout_seconds`.

    Args:
        timeout_seconds: How long to listen for responses before returning.

    Returns:
        One `DiscoveredDevice` per responding IP, with `service_types`
        accumulated across every matching service type it announced.
    """
    return await asyncio.to_thread(_scan_mdns_sync, timeout_seconds)
