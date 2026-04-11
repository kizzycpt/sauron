import socket
from Ether.gateway import Network, NetInfo

class Ports:


        DEFAULT_PORTS = (7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88,
                102, 110, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179,
                194, 201, 264, 318, 381, 383, 389, 411, 412, 427, 443, 445, 464, 465,
                497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 546, 547, 560,
                563, 587, 591, 593, 596, 631, 636, 639, 646, 691, 860, 873, 902, 989,
                990, 993, 995 )
         
        PORT_PROTOCOLS = {7: "Echo",
                        19: "CHARGEN",
                        20: "FTP-data",
                        21: "FTP",
                        22: "SSH/SCP/SFTP",
                        23: "Telnet",
                        25: "SMTP",
                        42: "WINS Replication",
                        43: "WHOIS",
                        49: "TACACS",
                        53: "DNS",
                        67: "DHCP/BOOTP",
                        68: "DHCP/BOOTP",
                        69: "TFTP",
                        70: "Gopher",
                        79: "Finger",
                        80: "HTTP",
                        88: "Kerberos",
                        102: "Microsoft Exchange ISO-TSAP",
                        110: "POP3",
                        113: "Ident",
                        119: "NNTP (Usenet)",
                        123: "NTP",
                        135: "Microsoft RPC EPMAP",
                        137: "NetBIOS-ns",
                        138: "NetBIOS-dgm",
                        139: "NetBIOS-ssn",
                        143: "IMAP",
                        161: "SNMP-agents (unencrypted)",
                        162: "SNMP-trap (unencrypted)",
                        177: "XDMCP",
                        179: "BGP",
                        194: "IRC",
                        201: "AppleTalk",
                        264: "BGMP",
                        318: "TSP",
                        381: "HP Openview",
                        383: "HP Openview",
                        389: "LDAP",
                        411: "(Multiple uses)",
                        412: "(Multiple uses)",
                        427: "SLP",
                        443: "HTTPS (HTTP over SSL)",
                        445: "Microsoft DS SMB",
                        464: "Kerberos",
                        465: "SMTP over TLS/SSL, SSM",
                        497: "Dantz Retrospect",
                        500: "IPSec / ISAKMP / IKE",
                        512: "rexec",
                        513: "rlogin",
                        514: "syslog",
                        515: "LPD/LPR",
                        520: "RIP",
                        521: "RIPng (IPv6)",
                        540: "UUCP",
                        546: "DHCPv6",
                        547: "DHCPv6",
                        548: "AFP",
                        554: "RTSP",
                        560: "rmonitor",
                        563: "NNTP over TLS/SSL",
                        587: "SMTP",
                        591: "FileMaker",
                        593: "Microsoft DCOM",
                        596: "SMSD",
                        631: "IPP",
                        636: "LDAP over TLS/SSL",
                        639: "MSDP (PIM)",
                        646: "LDP (MPLS)",
                        691: "Microsoft Exchange",
                        860: "iSCSI",
                        873: "rsync",
                        902: "VMware Server",
                        989: "FTPS",
                        990: "FTPS",
                        993: "IMAP over SSL (IMAPS)",
                        995: "POP3 over SSL (POP3S)"
                        }
        
        
        def __init__(self, ip: str, ports: list[int], net_info: dict):

            self.ip = ip
            self.ports = ports
            self.net_info = net_info


        def address_connect(self):
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.settimeout(1)
            

        def open_ports_for(timeout: float = 1.0) -> list[int]:
            
            
            opens: list[int] = []


            for p in self.ports:
                try:
                    
                    self.address_connect()
                    if self.s.connect_ex((ip, p)) == 0:
                        opens.append(p)
                
                except Exception:
                    pass
                
                finally:
                    try:
                        self.s.close()
                    except Exception:
                        pass

            return sorted(opens)
        

        def port_check(self) -> str:
            # Port scan outputted in text
            ports = self.ports or DEFAULT_PORTS
            

            output = f"Port Scan for {ip}: "
            output += f"- Gateway: {NetInfo.get("gateway", "N/A")}\n"
            output += f"- Subnet: {NetInfo.get("subnet", "N/A")}\n"
            
            for port in ports:
                try:
                    self.address_connect()
                    result = s.connect_ex((ip, port))
                    status = "OPEN" if result == 0 else "CLOSED/FILTERED"
                    protocol = PORT_PROTOCOLS.get(port, "Unknown")
                    output += f"  Port {port}({protocol}): {status}\n"
                except Exception as e:
                    output += f"  Port {port} error: {e}\n"
            return output
        
        
        @classmethod
        def port_scan(cls):
            cls.open_ports_for()
            cls.port_check
        

Port = Ports()

PortScan = Port.port_scan()

