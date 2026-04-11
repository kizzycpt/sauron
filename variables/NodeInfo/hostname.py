import socket


def hostname_for(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return Nones