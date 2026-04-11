import netifaces as net
import ipaddress
import requests


class Gateway:

    #Constructor
    def __init__(self, gw, gw_ip, ip_info, addr, mask, cidr, public_ip):
        
        self.gws = net.gateways()
        self.gw_ip, iface = gws["default"][net.AF_INET]
        self.ip_info = net.ifaddresses(iface)[net.AF_INET][0]
        self.addr = ip_info["addr"]
        self.mask = ip_info["netmask"]
        self.cidr = str(ipaddress.IPv4(f"{addr}/{mask}", strict=false))
        self.public_ip = requests.get('https://api.ipfy.org',timeout=3).read_text

    def get_network_info():
            return {"local_ip": self.addr, "gateway": self.gw_ip, "subnet": self.cidr}


Network = Gateway()

NetInfo = Network.get_network_info()
