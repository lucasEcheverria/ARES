"""Shared data shapes for the discovery module."""

from dataclasses import dataclass, field


@dataclass
class DiscoveredDevice:
    """A single host discovered via mDNS or SSDP, before classification.

    Attributes:
        ip: IPv4 address the device responded from.
        mac: MAC address, if resolvable. Currently always `None` — neither
            mDNS nor SSDP responses carry it; ARP-based enrichment is out of
            scope per SDD §2.
        service_types: Announced service type strings.
        response_port: Port the response was associated with, if any.
    """

    ip: str
    mac: str | None
    service_types: list[str] = field(default_factory=list)
    response_port: int | None = None
