from scapy.all import TCP, IP, Raw, sendp, Ether, IFACES, UDP, wrpcap
import random

data = "vvvvvhqDvwAxYMeCjmESTpscJebBfMcrA1S5DrA1sfdsfdsfsdfWWWZaCVYlTkhM6VS7aoAArAAAJgAALNBpL(dsda"

#pkt = Ether(src='f4:52:14:3e:dd:60', dst='f4:52:14:88:bf:e0') / IP(src='192.168.1.1', dst='192.168.1.2') / TCP(sport=2568, dport=5656) / Raw(load=data)

#wrpcap('teste.pcap', pkt)

for _ in range(1):
    pkt = Ether(src='f4:52:14:3e:dd:60', dst='f4:52:14:88:bf:e0') / IP(src='192.168.1.1', dst='192.168.1.2') / TCP(sport=2568, dport=5656) / Raw(load=data)
    #wrpcap('1pkt.pcap', pkt, append=True)
    sendp(pkt, iface=IFACES.dev_from_index(3))


