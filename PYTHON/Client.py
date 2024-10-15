import os
import threading
import queue
import datetime
import ipaddress
from scanSYN import run_scan_detection_thread, stop_scan_detection_thread, alert_queue as syn_alert_queue
from dos import run_dos_detection_thread, stop_dos_detection_thread, alert_queue as dos_alert_queue

VIOLET = '\033[95m'
VERT = '\033[92m'
BLEU = '\033[96m'
WARNING = '\033[93m'
ROUGE = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

Dic_scan = {"syn": False, "dos": False}
scan_syn_thread = None  
scan_dos_thread = None 

def etat(type_scan, dic_scan=Dic_scan):
    """Renvoie l'état d'un scan avec une couleur indiquant s'il est actif ou inactif"""
    if dic_scan.get(type_scan, False):
        return f"{BOLD}{VERT}actif{RESET}"
    else:
        return f"{BOLD}{ROUGE}inactif{RESET}"

def afficher_banniere():
    """Affiche la bannière du tool"""
    print(f"{BOLD}{VIOLET}**************************************************************************{RESET}")
    print(f"{BLEU}       ____  ___  __   __     __  ___ __   __  ______")
    print("      |    ||   ||  \  | |   |  ||   || | | | |    _ |")
    print("      | ___||   ||    \| | __|  ||   || |_| | |  |  _|")
    print("      |____||___||__||___||_____||___||_____| |__|\_|    ")
    print(f"{VIOLET}**************************************************************************{RESET}")

def menu():
    """Affiche le menu des détections"""
    print(f"\nMenu de détections : ")
    print(f"1. Detection SYN : {etat('syn')}")
    print(f"2. Detection Dos : {etat('dos')}")
    print(f"3. Quitter")

def adresseip():
    """Affiche le menu d'une nouvelle adresse IP"""
    print(f"o. Si vous voulez un scan d'une adresse IP spécifique ?")
    print(f"n. Si vous ne souhaitez pas d'adresse IP spécifique")
    bool_ip = input(f"\n{BOLD}Voulez-vous scan une adresse ip spécifique ? option (o, n)")

    ip = None
    if bool_ip == 'o':
        while True:
            ip_input = input(f"\n{BOLD}Entrer l'adresse IP que vous souhaitez ?")
            try:
                ip = str(ipaddress.ip_address(ip_input))  # Valide et retourne une IP valide
                break
            except ValueError:
                print(f"{ROUGE}Adresse IP invalide, veuillez entrer une adresse valide.{RESET}")
    return ip

def choix():
    """Permet à l'utilisateur de choisir et activer/désactiver les détections"""
    global scan_syn_thread, scan_dos_thread
    
    while True:
        menu()
        option = input(f"\n{BOLD}Choisissez une option (1-3) : {RESET}")        

        if option == '1':
            if Dic_scan["syn"]:
                Dic_scan["syn"] = False
                stop_scan_detection_thread()  # Arrêter le thread de détection SYN
                scan_syn_thread.join()  # Attendre que le thread s'arrête
                print(f"\nSYN scan est maintenant {etat('syn', Dic_scan)}")
            else:
                Dic_scan["syn"] = True
                ip = adresseip()
                scan_syn_thread = run_scan_detection_thread(ip)  # Démarrer le thread de détection SYN
                print(f"\nSYN scan est maintenant {etat('syn', Dic_scan)}")
        
        elif option == '2':
            if Dic_scan["dos"]:
                Dic_scan["dos"] = False
                stop_dos_detection_thread()  # Arrêter le thread de détection DoS
                scan_dos_thread.join()  # Attendre que le thread s'arrête
                print(f"\nDétection DoS est maintenant {etat('dos', Dic_scan)}")
            else:
                Dic_scan["dos"] = True
                scan_dos_thread = run_dos_detection_thread()  # Démarrer le thread de détection DoS
                print(f"\nDétection DoS est maintenant {etat('dos', Dic_scan)}")          
        
        elif option == '3':
            print(f"Quitter le programme")
            if Dic_scan["syn"]:
                stop_scan_detection_thread()
                scan_syn_thread.join()
            if Dic_scan["dos"]:
                stop_dos_detection_thread()
                scan_dos_thread.join()
            break
        else:
            print(f"{WARNING}Option invalide, veuillez choisir 1, 2, ou 3.{RESET}")

def log_alert(alert_message):
    """Écrit un message d'alerte dans un fichier de log avec la date et l'heure."""
    log_directory = "./logs"
    
    # Vérifie si le dossier de logs existe, sinon il le crée
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    current_datetime = datetime.datetime.now()
    log_file_name = os.path.join(log_directory, f"LOG_{current_datetime.strftime('%Y-%m-%d')}.txt")

    print(f"Fichier de log : {log_file_name}") 
    log_entry = f"{alert_message} | [{current_datetime.strftime('%d-%m-%Y %H:%M:%S')}]\n"
    with open(log_file_name, "a") as log_file:
        log_file.write(log_entry)

def gestion_alertes():
    """Gère les alertes en temps réel."""
    print("Gestion des alertes activée.")
    while True:
        try:
            alerte_syn = syn_alert_queue.get(timeout=1)  # Récupère les alertes de scan SYN
            print(f"{ROUGE}[ALERTE SYN]{RESET} {alerte_syn}")
            log_alert(alerte_syn)
            syn_alert_queue.task_done()
        except queue.Empty:
            pass

        try:
            alerte_dos = dos_alert_queue.get(timeout=1)  # Récupère les alertes DoS
            print(f"{ROUGE}[ALERTE DOS]{RESET} {alerte_dos}")
            log_alert(alerte_dos)
            dos_alert_queue.task_done()

        except queue.Empty:
            pass

if __name__ == "__main__":
    afficher_banniere()

    # Démarrer un thread pour gérer les alertes en temps réel
    thread_alertes = threading.Thread(target=gestion_alertes)
    thread_alertes.daemon = True  # S'assure que ce thread s'arrête à la fin du programme principal
    thread_alertes.start()

    choix()

    thread_alertes.join()
# arp spoofing
# Injection SQL
# XSS
# Bruit de force serveur ssh