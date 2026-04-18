from scapy.all import *
 
class Broadcast:
    
    #Constructor
    def __init__(self):
        self.gateway = conf.route.route("0.0.0.0")[2]
        self.mask = "0" #adjust


    #ARP Broadcast on entire subnet
    def scan(self, subnet: str | None = None, *, quiet: bool = False) -> dict[str, str]:
        try:
            subnet = str(f"{self.gateway}/{self.mask}")

            arp = ARP(pdst = subnet)
            ether = Ether(dst = "ff:ff:ff:ff:ff:ff")
            
            #Packet Craft under layer 2
            packet = ether/arp



            #Packet transmission and reply
            try:
                result = srp(packet, timeout = 2, verbose = 1)[0]

                
                #Dictionary creation and reply storage
                hosts: dict[str, str] = {}
                for _, received in result:
                    if not quiet:
                        print(f"Host found: {received.psrc} - MAC: {received.hwsrc} \n")
                    hosts[received.psrc] = received.hwsrc
                return hosts


            except PermissionError:
                print("Scapy needs raw-socket permission for ARP if you're using linux. Please try again")
                print("Run with sudo or grant CAP_NET_RAW/CAP_NET_ADMIN to the terminal")
                return {}
           
        
        except Exception as e:
            print(f"ARP scan error: {e}") 
            return {}


#instances
l2_arp = Broadcast()

#---
arp_scan = l2_arp.scan()



 