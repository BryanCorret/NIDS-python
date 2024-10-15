from scapy.all import *
import datetime


# Envoyer un paquet SYN vers l'adresse IP locale
ip = "127.0.0.1"
port = 80
syn_packet = IP(dst=ip)/TCP(dport=port, flags='FPU')
send(syn_packet)

print(datetime.datetime.today())