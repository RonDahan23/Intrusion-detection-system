from scapy.all import *

def check_rst(packet):
    if TCP in packet:
        tcp_flags = packet[TCP].flags
        if tcp_flags & TCPFlags.RST:
            print("RST flag is set")
        else:
            print("RST flag is not set")
    else:
        print("Not a TCP packet")

sniff(iface='eth0', filter='tcp', prn=check_rst)
