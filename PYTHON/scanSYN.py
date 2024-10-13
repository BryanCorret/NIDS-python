from scapy.all import sniff, TCP, IP, UDP
import threading
import queue

# File d'alerte pour le partage entre threads
alert_queue = queue.Queue()

# Indicateur pour arrêter le thread de détection
stop_thread = threading.Event()

def detect_scan(packet):
    """Fonction pour détecter les différents types de scans Nmap."""
    if IP in packet : 
        # SYN Scan
        if TCP in packet and packet[TCP].flags == 'S':
            alert_queue.put(f"[SYN Scan] Détecté de {packet[IP].src}")
            print("feur")
        
        # FIN Scan
        elif TCP in packet and packet[TCP].flags == 'F':
            alert_queue.put(f"[FIN Scan] Détecté de {packet[IP].src}")
        
        # Null Scan
        elif TCP in packet and packet[TCP].flags == 0:
            alert_queue.put(f"[Null Scan] Détecté de {packet[IP].src}")
        
        # UDP Scan
        elif UDP in packet:
            alert_queue.put(f"[UDP Scan] Détecté de {packet[IP].src}")

def run_scan_detection_thread():
    """Démarre la détection de scans dans un thread séparé"""
    def detection_task():
        while not stop_thread.is_set():  # Vérifie l'état de l'indicateur
            sniff(filter="tcp", prn=detect_scan, timeout=1)
        print("[INFO] Thread de détection SYN arrêté.")
    
    thread = threading.Thread(target=detection_task)
    thread.start()
    return thread

def stop_scan_detection_thread():
    """Arrête le thread de détection de SYN scans"""
    stop_thread.set()
