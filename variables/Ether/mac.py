import netifaces as n


class MAC():

#----------------
    bad_iface_prefix = ("lo", "docker", "wg", "br-", "veth", "virbr", "zt", "vboxnet")
#----------------
    addrs = n.ifaddresses(iface)
    iface_link = addrs.get(n.AF_LINK)
    my_mac = iface_link[0].get("addr")

    @staticmethod
    def get_my_mac():
        try:
            for iface in n.interfaces():
                
                
                if iface.startswith(bad_iface_prefix):
                    continue

                if not iface_link:
                    continue

                if my_mac and my_mac != "00:00:00:00:00:00":
                    return {"Interface:": iface, "MAC": my_mac}
            return None
        
        except Exception as e:
            print(f"error in resolving MAC. {e}.")
            return {}

mac = MAC()

my_mac = mac.get_my_mac.get("MAC")




