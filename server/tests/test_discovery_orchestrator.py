"""Tests for `discovery.orchestrator`, with the network scanners mocked out.

Only the dedup/classification/persistence logic is under test here — the
real `zeroconf`/SSDP scanners are never exercised in this suite. Real
discovery is verified manually against a live network, not in pytest.
"""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from dao.session_dao import SessionDAO
from discovery import orchestrator
from discovery.models import DiscoveredDevice
from models.session import HostStatus, SessionStatus

pytestmark = pytest.mark.asyncio


async def test_discover_and_create_macrosession_dedups_by_ip_and_classifies(
    sessions_db: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_scan_mdns() -> list[DiscoveredDevice]:
        return [
            DiscoveredDevice(
                ip="192.168.1.10", mac=None, service_types=["_googlecast._tcp.local."]
            ),
            DiscoveredDevice(ip="192.168.1.11", mac=None, service_types=["_ipp._tcp.local."]),
        ]

    async def fake_scan_ssdp() -> list[DiscoveredDevice]:
        return [
            # Same IP as the first mDNS result — must merge, not duplicate.
            DiscoveredDevice(
                ip="192.168.1.10",
                mac=None,
                service_types=["urn:schemas-upnp-org:device:MediaRenderer:1"],
                response_port=1900,
            ),
            DiscoveredDevice(ip="192.168.1.1", mac=None, service_types=[], response_port=1900),
        ]

    monkeypatch.setattr(orchestrator, "scan_mdns", fake_scan_mdns)
    monkeypatch.setattr(orchestrator, "scan_ssdp", fake_scan_ssdp)

    dao = SessionDAO(sessions_db)
    macrosession, children = await orchestrator.discover_and_create_macrosession(
        dao, "user-1", "Home subnet", "192.168.1.0/24"
    )

    assert macrosession.target == "192.168.1.0/24"
    assert macrosession.status == SessionStatus.RUNNING
    assert macrosession.parent_session_id is None

    assert {child.target for child in children} == {"192.168.1.10", "192.168.1.11", "192.168.1.1"}
    assert all(child.parent_session_id == macrosession.id for child in children)
    assert all(child.host_status == HostStatus.PENDING for child in children)

    by_ip = {child.target: child for child in children}
    assert by_ip["192.168.1.10"].device_type == "chromecast"  # first-listed service type wins
    metadata = by_ip["192.168.1.10"].discovery_metadata
    assert metadata is not None
    assert set(metadata["service_types"]) == {
        "_googlecast._tcp.local.",
        "urn:schemas-upnp-org:device:MediaRenderer:1",
    }
    assert by_ip["192.168.1.11"].device_type == "printer"
    assert by_ip["192.168.1.1"].device_type == "unknown"

    persisted_children = await dao.get_children(macrosession.id)
    assert len(persisted_children) == 3


async def test_discover_and_create_macrosession_with_no_devices_found(
    sessions_db: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def empty() -> list[DiscoveredDevice]:
        return []

    monkeypatch.setattr(orchestrator, "scan_mdns", empty)
    monkeypatch.setattr(orchestrator, "scan_ssdp", empty)

    dao = SessionDAO(sessions_db)
    macrosession, children = await orchestrator.discover_and_create_macrosession(
        dao, "user-1", "Empty subnet", "10.0.0.0/24"
    )

    assert children == []
    assert await dao.get_children(macrosession.id) == []
