from scapy.all import IP, TCP, send
import time

def sendpack():
    ip = "127.0.0.1"
    port = 80
    syn_packet = IP(dst=ip)/TCP(dport=port, flags='S')

    while True:
        send(syn_packet, count=1) 
        time.sleep(0.01)  # Petit délai pour augmenter la fréquence


sendpack()