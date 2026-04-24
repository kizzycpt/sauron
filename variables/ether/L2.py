import os
import sys
from pathlib import Path
from scapy.all import ARP, Ether, srp

sys.path.insert(0, os.path.dirname(__file__))
from gateway import NetInfo


class Broadcast:

    def scan(self, subnet: str | None = None, *, quiet: bool = False) -> dict[str, str]:
        try:
            if subnet is None:
                subnet = f"{NetInfo.get('gateway')}/24"

            packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

            try:
                result = srp(packet, timeout=2, verbose=0)[0]
                return {received.psrc: received.hwsrc for _, received in result}
            except PermissionError:
                print("Scapy needs raw-socket access. Run with sudo or grant CAP_NET_RAW.")
                return {}

        except OSError as e:
            print(f"ARP scan error: {e}")
            return {}


l2_arp   = Broadcast()
arp_scan = l2_arp.scan