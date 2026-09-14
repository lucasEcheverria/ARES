"""Fase 1 completa: descubrimiento de subred (SDD §5.1).

The only entry point invoked by the session-creation flow for `mode="subnet"`.
Runs mDNS then SSDP sequentially, dedups by IP, classifies each unique host,
and persists the macrosession row plus one child `Session` per host. Never
imports from or is imported by `agent/` — discovery is a linear backend
process, not an agent tool.
"""

import uuid

from dao.session_dao import SessionDAO
from discovery.classifier import classify
from discovery.mdns_scanner import scan_mdns
from discovery.models import DiscoveredDevice
from discovery.ssdp_scanner import scan_ssdp
from models.session import HostStatus, Session, SessionStatus


def _merge_by_ip(
    mdns_devices: list[DiscoveredDevice], ssdp_devices: list[DiscoveredDevice]
) -> dict[str, DiscoveredDevice]:
    """Merge mDNS and SSDP results into one entry per IP.

    Args:
        mdns_devices: Devices found via mDNS.
        ssdp_devices: Devices found via SSDP.

    Returns:
        Mapping of IP to a `DiscoveredDevice` whose `service_types` is the
        union of everything announced by that IP across both scanners.
    """
    merged: dict[str, DiscoveredDevice] = {}
    for device in [*mdns_devices, *ssdp_devices]:
        existing = merged.get(device.ip)
        if existing is None:
            merged[device.ip] = device
            continue
        for service_type in device.service_types:
            if service_type not in existing.service_types:
                existing.service_types.append(service_type)
        existing.mac = existing.mac or device.mac
        existing.response_port = existing.response_port or device.response_port
    return merged


async def discover_and_create_macrosession(
    session_dao: SessionDAO, user_id: str, name: str, cidr: str
) -> tuple[Session, list[Session]]:
    """Run phase 1: discover devices and persist the macrosession + children.

    Args:
        session_dao: DAO bound to `ares_sessions`.
        user_id: The owning user's `id`.
        name: User-provided name for the macrosession.
        cidr: Subnet in CIDR notation. `/24`-max validation is the caller's
            responsibility (`SessionService`), not this module's.

    Returns:
        The created macrosession row and its list of created child sessions,
        each with `host_status=PENDING`.
    """
    macrosession = await session_dao.create(
        {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "name": name,
            "target": cidr,
            "status": SessionStatus.RUNNING,
        }
    )

    mdns_devices = await scan_mdns()
    ssdp_devices = await scan_ssdp()
    merged = _merge_by_ip(mdns_devices, ssdp_devices)

    children: list[Session] = []
    for device in merged.values():
        child = await session_dao.create(
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "name": device.ip,
                "target": device.ip,
                "status": SessionStatus.RUNNING,
                "parent_session_id": macrosession.id,
                "host_status": HostStatus.PENDING,
                "device_type": classify(device.service_types),
                "discovery_metadata": {
                    "ip": device.ip,
                    "mac": device.mac,
                    "service_types": device.service_types,
                    "response_port": device.response_port,
                },
            }
        )
        children.append(child)

    return macrosession, children
