import netifaces
import ipaddress


class Gateway:

    @staticmethod
    def get_network_info() -> dict:
        gws            = netifaces.gateways()
        gw_ip, iface   = gws["default"][netifaces.AF_INET]
        ip_info        = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        addr           = ip_info["addr"]
        mask           = ip_info["netmask"]
        cidr           = str(ipaddress.IPv4Interface(f"{addr}/{mask}"))
        return {"local_ip": addr, "gateway": gw_ip, "subnet": cidr}


Network = Gateway()
NetInfo = Network.get_network_info()