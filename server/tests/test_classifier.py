"""Tests for `discovery.classifier`."""

from discovery.classifier import classify


def test_classify_matches_googlecast() -> None:
    assert classify(["_googlecast._tcp.local."]) == "chromecast"


def test_classify_matches_airplay() -> None:
    assert classify(["_airplay._tcp.local."]) == "apple_tv"


def test_classify_matches_ipp_printer() -> None:
    assert classify(["_ipp._tcp.local."]) == "printer"


def test_classify_matches_media_renderer_urn() -> None:
    assert classify(["urn:schemas-upnp-org:device:MediaRenderer:1"]) == "media_renderer"


def test_classify_matches_router_urn() -> None:
    assert classify(["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]) == "router"


def test_classify_falls_back_to_http_generic_web_device() -> None:
    assert classify(["_http._tcp.local."]) == "generic_web_device"


def test_classify_returns_unknown_for_no_match() -> None:
    assert classify(["_something-else._tcp.local."]) == "unknown"


def test_classify_returns_unknown_for_empty_list() -> None:
    assert classify([]) == "unknown"


def test_classify_returns_first_matching_service_type_in_order() -> None:
    assert classify(["_something-else._tcp.local.", "_googlecast._tcp.local."]) == "chromecast"
