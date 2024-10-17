from scapy.all import IP, TCP, sniff
import threading
import time
import queue

ssh_cpt = {}
SSH_SEUIL = 5  # Seuil alert connexion SSH
DELAY = 10  # temps avant reset du compteurs
alert_queue = queue.Queue()
stop_thread_ssh = threading.Event()

def detect_ssh_bruteforce(packet):
    """Détecte les attaques brute-force SSH"""
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        
        # si le paquet fait est sur le port 22
        if packet[TCP].dport == 22:
            ssh_cpt[ip_src] = ssh_cpt.get(ip_src, 0) + 1
    
    # Détection brute-force SSH
    for ip, count in ssh_cpt.items():
        if count > SSH_SEUIL:
            alerte = f"[ALERTE Brute-force SSH] IP : {ip} avec {count} tentatives sur le port 22."
            alert_queue.put(alerte)
            # print(alerte)

def reset_ssh():
    """Réinitialise les compteurs SSH toutes les DELAY secondes"""
    while not stop_thread_ssh.is_set():
        time.sleep(DELAY)
        ssh_cpt.clear()

def run_ssh_bruteforce_thread(interface):
    """Lance le thread de détection brute-force SSH"""
    stop_thread_ssh.clear()
    
    def detection_task():
        threading.Thread(target=reset_ssh).start()
        while not stop_thread_ssh.is_set():
            sniff(filter="tcp", prn=detect_ssh_bruteforce, timeout=1, iface=interface)

    thread = threading.Thread(target=detection_task)
    thread.start()
    return thread

def stop_ssh_bruteforce_thread():
    """Arrête le thread de détection SSH"""
    stop_thread_ssh.set()
