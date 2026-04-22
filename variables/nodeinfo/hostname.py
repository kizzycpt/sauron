import sys
import socket

class Hostnames():
    
    def get_hostname(self, ip: str) -> bool:
        
        try:
            return socket.gethostbyaddr(ip)[0]
        
        except Exception:
            return " "            

    
    

#instances

hostname = Hostnames()

get_hostname = hostname.get_hostname