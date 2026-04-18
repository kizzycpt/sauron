from variables.ether.gateway import Network, NetInfo


import netifaces as n
import subprocess
import re 


class MAC():

#----------------
    bad_iface_prefix = ("lo", "docker", "wg", "br-", "veth", "virbr", "zt", "vboxnet")
#----------------
    gateway_ip = NetInfo.get("gateway")

    @staticmethod
    def get_gateway_mac():
        try:
            route_check = subprocess.check_output(["ip", "route"], text=True)
            route_gateway = None

            for line in route_check.splitlines():
                if line.startswith("default"):
                    route_gateway = line.split()[2]
                    break

            if not route_gateway:
                return None

            if MAC.gateway_ip and MAC.gateway_ip != route_gateway:
                return None

            mac_result = subprocess.check_output(["ip", "neigh"], text=True)

            for line in mac_result.splitlines():
                if route_gateway in line:
                    match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", line)
                    if match:
                        return match.group(1)

            return None

        except Exception as e:
            print(f"error resolving gateway MAC: {e}")
            return None

    @staticmethod
    def get_my_mac():
        try:
            for iface in n.interfaces():
                if iface.startswith(MAC.bad_iface_prefix):
                    continue

                addrs = n.ifaddresses(iface)
                iface_link = addrs.get(n.AF_LINK, [])
                my_mac = iface_link[0].get("addr") if iface_link else None

                if my_mac and my_mac != "00:00:00:00:00:00":
                    return {"Interface": iface, "MAC": my_mac}

            return None

        except Exception as e:
            print(f"error in resolving MAC: {e}")
            return {}


mac = MAC()

my_mac_info = mac.get_my_mac()
my_mac = my_mac_info.get("MAC") if my_mac_info else None

gateway_mac = mac.get_gateway_mac()

 