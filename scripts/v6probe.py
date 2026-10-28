#!/usr/bin/env python3
"""IPv6 reachability verdict for the home-side A2 probe (issue #21).

The firewall has IPv6 disabled, so it must not answer an all-nodes ping on the home LAN. Pipe the output of
`ip -6 neigh show dev <iface>` (taken after `ping -6 ff02::1`) on stdin; pass the firewall's WAN MAC as argv[1].
Prints allow (the firewall answered: IPv6 is alive), deny (others answered, the firewall did not) or ERROR
(nothing answered at all: multicast is unusable here, so silence proves nothing).
"""
import re
import sys


def verdict(neigh_text, fw_mac):
    macs = {m.lower() for m in re.findall(r"lladdr ([0-9a-fA-F:]{17})", neigh_text)}
    if not macs:
        return "ERROR"
    return "allow" if fw_mac.lower() in macs else "deny"


if __name__ == "__main__":
    print(verdict(sys.stdin.read(), sys.argv[1]))
