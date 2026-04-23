from scapy.all import *

import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from gateway import NetInfo

class Broadcast:
    def scan(self, subnet: str | None = None, *, quiet: bool = False) -> dict[str, str]:
        try:
            if subnet is None:
                subnet = f"{NetInfo.get('gateway')}/24"

            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            try:
                result = srp(packet, timeout=2, verbose=0)[0]
                hosts: dict[str, str] = {}
                for _, received in result:
                    hosts[received.psrc] = received.hwsrc
                return hosts

            except PermissionError:
                print("Scapy needs raw-socket access. Run with sudo or grant CAP_NET_RAW.")
                return {}

        except OSError as e:
            print(f"ARP scan error: {e}")
            return {}

l2_arp = Broadcast()
arp_scan = l2_arp.scan

