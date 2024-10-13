from scapy.all import sniff, IP
import threading
import time
import queue

# File d'alerte pour le partage entre threads
alert_queue = queue.Queue()

# Indicateur pour arrêter le thread de détection DoS
stop_thread_dos = threading.Event()

# Dictionnaire pour suivre le nombre de paquets envoyés par chaque IP
ip_packet_count = {}
THRESHOLD = 100  # Seuil pour déclencher une alerte (nombre de paquets par seconde)

def detect_dos(packet):
    """Fonction pour détecter une attaque DoS en se basant sur le nombre de paquets envoyés."""
    if IP in packet:
        ip_src = packet[IP].src

        # Met à jour le nombre de paquets envoyés par cette IP
        if ip_src in ip_packet_count:
            ip_packet_count[ip_src] += 1
        else:
            ip_packet_count[ip_src] = 1

        # Si une IP dépasse le seuil de paquets
        if ip_packet_count[ip_src] > THRESHOLD:
            alerte = f"[ALERTE DoS] IP suspectée : {ip_src} avec {ip_packet_count[ip_src]} paquets."
            alert_queue.put(alerte)

def reset_packet_count():
    """Réinitialise le compteur de paquets toutes les secondes pour mesurer les paquets par seconde."""
    while not stop_thread_dos.is_set():
        time.sleep(1)  # Attendre 1 seconde
        ip_packet_count.clear()

def run_dos_detection_thread():
    """Démarre la détection DoS dans un thread séparé."""
    def detection_task():
        # Thread pour remettre à zéro les compteurs de paquets toutes les secondes
        threading.Thread(target=reset_packet_count).start()

        while not stop_thread_dos.is_set():
            sniff(filter="ip", prn=detect_dos, timeout=1)  # Timeout pour checker l'indicateur d'arrêt

        print("[INFO] Thread de détection DoS arrêté.")

    thread = threading.Thread(target=detection_task)
    thread.start()
    return thread

def stop_dos_detection_thread():
    """Arrête le thread de détection DoS."""
    stop_thread_dos.set()
