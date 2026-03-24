from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw

#global variables 
l2_data = Ether(dst = "ff:ff:ff:ff:ff:ff")
l3_data = IP()
frame = srp(l2_data / l3_data)

def sendpkt():
    try:
        menu = input('[1]: send packet \n[2]: Show reply \nSelect your choice:')
        
        if menu == "1":

            for frames in range(10):
                print(frame)
                time.sleep(2)
        elif menu == "2":
            print(frame.show())

        else: 
            print("Error: Unable to parse information. Please try again.")
    except Exeption as e:


if __name__ == "__main__":
    sendpkt()
        