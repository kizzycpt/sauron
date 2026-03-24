from scapy.all import IP, Ether, UDP, Raw, TCP, ICMP, sr1, srp, sendp, sniff 


def ping():
    ping_pkt = IP(dst="127.0.0.1")/ ICMP()

    ping_reply = sr1(ping_pkt, timeout=2, verbose=0)


    if ping_reply:
        ping_reply.show()

def tcp():
    tcp_connect = IP(dst="www.google.com")/TCP(dport=443, flags= "S")
    tcp_ack = sr1(tcp_connect, timeout = 2, verbose = 1)

    if tcp_ack:
        tcp_connect.show()

def sniffr():
    sniff(count = 5, prn=lambda p: p.summary())


if __name__ == "__main__":
    sniffr()

