import socket
import struct


# Convert IP address from integer to string (with dot-decimal notation)
def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


# Convert IP address from string (with dot-decimal notation) to integer 
def ip2int(addr):
    try:
        return struct.unpack("!I", socket.inet_aton(addr))[0]
    except:
        return float("nan")
