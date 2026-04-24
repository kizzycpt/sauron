import socket


class Hostnames:

    def get_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return " "


hostname     = Hostnames()
get_hostname = hostname.get_hostname