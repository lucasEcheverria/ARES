"""Fixed service-type -> device-type classification (SDD §4.3)."""

SERVICE_TYPE_TO_DEVICE_TYPE: dict[str, str] = {
    "_googlecast._tcp": "chromecast",
    "_airplay._tcp": "apple_tv",
    "_ipp._tcp": "printer",
    "_http._tcp": "generic_web_device",
    "urn:schemas-upnp-org:device:MediaRenderer": "media_renderer",
    "urn:schemas-upnp-org:device:InternetGatewayDevice": "router",
}


def classify(service_types: list[str]) -> str:
    """Classify a device from its announced service types.

    Args:
        service_types: Service type strings announced by the device. mDNS
            service types carry a `.local.` protocol suffix (e.g.
            `_googlecast._tcp.local.`) and SSDP `ST` headers are full URNs —
            both are matched by substring against the fixed mapping above,
            so the mapping's shorter keys still match.

    Returns:
        The device type of the first matching service type, in the order
        given, or `"unknown"` if none match.
    """
    for service_type in service_types:
        for key, device_type in SERVICE_TYPE_TO_DEVICE_TYPE.items():
            if key in service_type:
                return device_type
    return "unknown"
