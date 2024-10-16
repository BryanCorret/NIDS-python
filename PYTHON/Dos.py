from scapy.all import IP, TCP, ICMP, sniff
import threading
import time
import queue

# Configuration des alertes
alert_queue = queue.Queue()
stop_thread_dos = threading.Event()
syn_cpt,ping_cpt,ip_cpt = {},{},{}
SEUIL = 100  # Seuil pour declancher les alertes
DELAY = 3  

def detect_dos(packet):
    """Détecte les attaques de type DOS"""
    if IP in packet:
        ip_src = packet[IP].src

        # compteur packet syn
        if TCP in packet and packet[TCP].flags == "S":
            syn_cpt[ip_src] = syn_cpt.get(ip_src, 0) + 1

        # compteur packet ping
        elif ICMP in packet:
            ping_cpt[ip_src] = ping_cpt.get(ip_src, 0) + 1
        
        else : 
            # compteur packet
            ip_cpt[ip_src] = ip_cpt.get(ip_src, 0) + 1
        

    # moyenne des packets
    moy_packet = sum(ip_cpt.values()) / DELAY 
    moy_packet_syn = sum(syn_cpt.values()) / DELAY 
    moy_packet_icmp = sum(ping_cpt.values()) / DELAY 

    # si la moyenne packet est supérieur au seuil
    if moy_packet > SEUIL:
        for ip, count in syn_cpt.items():
            if count > SEUIL :
                alerte = f"[ALERTE DoS] Moyenne de {moy_packet:.2f} paquets par seconde détectée sur l'ip {ip}"
                alert_queue.put(alerte)

    # si la moyenne packet SYN est supérieur au seuil 
    if moy_packet_syn > SEUIL:
        for ip, count in syn_cpt.items():
            if count > SEUIL:
                alerte = f"[ALERTE SYN flood] IP : {ip} avec {count} paquets SYN."
                alert_queue.put(alerte)

    # si la moyenne packet est supérieur au seuil
    if moy_packet_icmp > SEUIL:
        for ip, count in ping_cpt.items():
            if count > SEUIL:
                alerte = f"[ALERTE Ping flood] IP : {ip} avec {count} paquets ICMP."
                alert_queue.put(alerte)

def reset():
    """Réinitialise les compteurs toutes les DELAY secondes."""
    while not stop_thread_dos.is_set():
        time.sleep(DELAY)
        ip_cpt.clear()
        syn_cpt.clear()
        ping_cpt.clear()

def run_dos_detection_thread(interface):
    """Lance le thread de détection d'attaques

    Args:
        interface (str): L'interface réseau à surveiller

    Returns:
        thread: Le thread de détection Dos
    """
    stop_thread_dos.clear()
    def detection_task():
        threading.Thread(target=reset).start()
        while not stop_thread_dos.is_set():
            sniff(filter="ip", prn=detect_dos, timeout=1,iface=interface)

    thread = threading.Thread(target=detection_task)
    thread.start()
    return thread

def stop_dos_detection_thread():
    """Arrête le thread """
    stop_thread_dos.set()
