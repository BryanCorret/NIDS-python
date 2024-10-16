from scapy.all import IP, TCP, send, sniff
import threading
import time
import queue

# Configuration des alertes
alert_queue = queue.Queue()
stop_thread_dos = threading.Event()
ip_packet_count = {}
SEUIL = 10  # Seuil pour déclencher une alerte (nombre de paquets par seconde)

def detect_dos(packet):
    """Détecte une attaque DoS en se basant sur le nombre de paquets envoyés."""
    if IP in packet:
        ip_src = packet[IP].src

        # Met à jour le nombre de paquets envoyés par cette IP
        ip_packet_count[ip_src] = ip_packet_count.get(ip_src, 0) + 1

        # Si une IP dépasse le seuil de paquets
        if ip_packet_count[ip_src] > SEUIL:
            alerte = f"[ALERTE DoS] IP suspectée : {ip_src} avec {ip_packet_count[ip_src]} paquets."
            alert_queue.put(alerte)

def reset_packet_count():
    """Réinitialise le compteur de paquets toutes les secondes."""
    while not stop_thread_dos.is_set():
        time.sleep(1)
        ip_packet_count.clear()

def run_dos_detection_thread(interface):
    """Lance le thread de détection d'attaque DoS.

    Args:
        interface (Str): L'interface de 

    Returns:
        thread: Le thread de detection
    """
    stop_thread_dos.clear()
    def detection_task():
        threading.Thread(target=reset_packet_count).start()
        while not stop_thread_dos.is_set():
            sniff(filter="ip", prn=detect_dos, timeout=1,iface=interface)

    thread = threading.Thread(target=detection_task)
    thread.start()
    return thread
    
def stop_dos_detection_thread():
    """Arrête le thread de détection DoS."""
    stop_thread_dos.set()
