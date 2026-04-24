import socket


class Ports:

    DEFAULT_PORTS = (
        7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88,
        102, 110, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179,
        194, 201, 264, 318, 381, 383, 389, 411, 412, 427, 443, 445, 464, 465,
        497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 546, 547, 560,
        563, 587, 591, 593, 596, 631, 636, 639, 646, 691, 860, 873, 902, 989,
        990, 993, 995,
    )

    PORT_PROTOCOLS = {
        7: "Echo",          19: "CHARGEN",       20: "FTP-data",     21: "FTP",
        22: "SSH/SCP/SFTP", 23: "Telnet",        25: "SMTP",         42: "WINS Replication",
        43: "WHOIS",        49: "TACACS",         53: "DNS",          67: "DHCP/BOOTP",
        68: "DHCP/BOOTP",   69: "TFTP",           70: "Gopher",       79: "Finger",
        80: "HTTP",         88: "Kerberos",       102: "MS Exchange ISO-TSAP",
        110: "POP3",        113: "Ident",         119: "NNTP (Usenet)", 123: "NTP",
        135: "MS RPC EPMAP",137: "NetBIOS-ns",    138: "NetBIOS-dgm", 139: "NetBIOS-ssn",
        143: "IMAP",        161: "SNMP-agents",   162: "SNMP-trap",   177: "XDMCP",
        179: "BGP",         194: "IRC",           201: "AppleTalk",   264: "BGMP",
        318: "TSP",         381: "HP Openview",   383: "HP Openview", 389: "LDAP",
        411: "(Multiple)",  412: "(Multiple)",    427: "SLP",         443: "HTTPS",
        445: "MS DS SMB",   464: "Kerberos",      465: "SMTP/TLS",    497: "Dantz Retrospect",
        500: "IPSec/IKE",   512: "rexec",         513: "rlogin",      514: "syslog",
        515: "LPD/LPR",     520: "RIP",           521: "RIPng",       540: "UUCP",
        546: "DHCPv6",      547: "DHCPv6",        548: "AFP",         554: "RTSP",
        560: "rmonitor",    563: "NNTP/TLS",      587: "SMTP",        591: "FileMaker",
        593: "MS DCOM",     596: "SMSD",          631: "IPP",         636: "LDAP/TLS",
        639: "MSDP (PIM)",  646: "LDP (MPLS)",    691: "MS Exchange", 860: "iSCSI",
        873: "rsync",       902: "VMware Server", 989: "FTPS",        990: "FTPS",
        993: "IMAPS",       995: "POP3S",
    }

    def port_check(self, ip: str, ports=None, stop_flag=None) -> list:
        if ports is None:
            ports = self.DEFAULT_PORTS

        open_ports = []
        for p in ports:
            if stop_flag and stop_flag():
                break
            try:
                with socket.create_connection((ip, p), timeout=0.3):
                    open_ports.append(p)
            except Exception:
                pass
        return open_ports


ports        = Ports()
common_ports = ports.DEFAULT_PORTS