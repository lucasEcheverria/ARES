# Decision: passive/semi-passive subnet discovery only

**Date:** 2026-09-07
**Status:** Accepted

## Context

The subnet-scan macrosession feature (see `server/SDD-subnet-scan-macrosession.md`)
discovers devices via `server/discovery/`: mDNS/Bonjour (`zeroconf`) and
UPnP/SSDP (a hand-rolled M-SEARCH multicast, no third-party library). Both
are auto-announce protocols — a device only appears if it actively
broadcasts its presence on the network.

## Decision

Device discovery is **passive/semi-passive**: only devices that announce
themselves via mDNS or SSDP are found. No ARP scanning, no ICMP ping sweep,
and no active port scanning is performed during discovery (phase 1). This
is explicit, accepted scope — see `server/SDD-subnet-scan-macrosession.md`
§2 ("fuera de alcance").

## Consequences

- The discovered device list is **not exhaustive**. A live host with no
  mDNS/SSDP responder running (most servers, many IoT devices, anything
  with those services disabled) never appears as a child session.
- An empty or short discovery result is not evidence that a subnet has no
  other reachable hosts — it only means no device announced itself during
  the scan window.
- Exhaustive host discovery (ARP table sweep, ICMP ping sweep) is
  explicitly out of scope for this feature and would need its own design
  decision if pursued later.
