from scapy.all import *

class Broadcast:
    
    #Constructor
    def __init__(self, arp, ether, srp):
        self.arp = ARP()
        self.ether = Ether()
        self.gateway = conf.route.route("0.0.0.0")[2]
        self.mask = "/0"


    #ARP Broadcast on entire subnet
    def scan(self, subnet: str, *, quiet: bool = False) -> dict[str, str]:
        
        subnet = str(f"{self.gateway}/{self.mask}")

        self.arp(pdst = subnet)
        self.ether(dst = "ff:ff:ff:ff:ff:ff")
        
        #Packet Craft under layer 2
        packet = self.ether/self.arp



        #Packet transmission and reply
        try:
            result = srp(packet, timeout = 0, verbose = 1)[0]
        except PermissionError:
            print("Scapy needs raw-socket permission for ARP if you're using linux. Please try again")
            print("Run with sudo or grant CAP_NET_RAW/CAP_NET_ADMIN to the terminal")
            return {}


        #Dictionary creation and reply storage
        hosts: dict[str, str] = {}
        for _, received in result:
            if not quiet:
                print(f"Host found: {received.psrc} - MAC: {received.hwsrc} \n")
            hosts[received.psrc] = received.hwsrc
        return hosts



ARP = Broadcast()



