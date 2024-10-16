from scapy.all import sniff, TCP, IP, ICMP
import threading
import queue

# File d'alerte pour le partage entre threads
alert_queue = queue.Queue()

# Indicateur pour arrêter le thread de détection
stop_thread = threading.Event()
def detect_scan(packet):
    """Fonction pour détecter les différents types de scans Nmap."""
    if IP in packet:
        print(packet)
        # SYN Scan
        if TCP in packet and packet[TCP].flags == 'S':
            alert_queue.put(f"[SYN Scan] Détecté de {packet[IP].src}")
            print(f"[SYN Scan] Détecté de {packet[IP].src}")

        # Null Scan
        elif TCP in packet and packet[TCP].flags == 0:
            alert_queue.put(f"[Null Scan] Détecté de {packet[IP].src}")
            print(f"[Null Scan] Détecté de {packet[IP].src}")

        # Xmas Scan (FIN, PSH, URG)
        elif TCP in packet and packet[TCP].flags == 0x29:
            alert_queue.put(f"[Xmas Scan] Détecté de {packet[IP].src}")
            print(f"[Xmas Scan] Détecté de {packet[IP].src}")



def run_scan_detection_thread():
    stop_thread.clear()
    """Démarre la détection de scans dans un thread séparé"""
    def detection_task():
        while not stop_thread.is_set():  # Vérifie l'état de l'indicateur

            # Si aucune adresse IP n'est spécifiée, capturer tous les paquets
            """if ip:
                filtre = f"tcp and host {ip}"
                #print(f"ip : {ip}")
            else:
                filtre = None  # Capturer tous les paquets TCP
                print("ca")"""
            
            sniff(filter="tcp", prn=detect_scan, timeout=1,iface='lo')
            

        print("[INFO] Thread de détection SYN arrêté.")
    
    thread = threading.Thread(target=detection_task)
    thread.start()
    return thread

def stop_scan_detection_thread():
    """Arrête le thread de détection de SYN scans"""
    stop_thread.set()
