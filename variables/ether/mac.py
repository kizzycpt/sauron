import sys
from pathlib import Path
from scapy.all import ARP, Ether, srp

import netifaces as n

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gateway import Network, NetInfo


class MAC:

    _BAD_IFACE_PREFIX = ("lo", "docker", "wg", "br-", "veth", "virbr", "zt", "vboxnet")

    gateway_ip = NetInfo.get("gateway")

    @staticmethod
    def get_gateway_mac() -> str | None:
        try:
            gw_ip, gw_iface = n.gateways()['default'][n.AF_INET]
            return n.ifaddresses(gw_iface)[n.AF_LINK][0]['addr']
        except Exception as e:
            print(f"Error resolving gateway MAC: {e}")
            return None

    @staticmethod
    def get_my_mac() -> dict | None:
        try:
            for iface in n.interfaces():
                if iface.startswith(MAC._BAD_IFACE_PREFIX):
                    continue
                addrs    = n.ifaddresses(iface)
                iface_lk = addrs.get(n.AF_LINK, [])
                my_mac   = iface_lk[0].get("addr") if iface_lk else None
                if my_mac and my_mac != "00:00:00:00:00:00":
                    return {"Interface": iface, "MAC": my_mac}
            return None
        except Exception as e:
            print(f"Error resolving MAC: {e}")
            return {}

    @staticmethod
    def get_mac(ip: str) -> str | None:
        packet           = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        answered, _      = srp(packet, timeout=2, verbose=0)
        for _, received in answered:
            return received.hwsrc
        return None


mac         = MAC()
my_mac_info = mac.get_my_mac()
my_mac      = my_mac_info.get("MAC") if my_mac_info else None
target_mac  = mac.get_mac
gateway_mac = mac.get_gateway_mac()