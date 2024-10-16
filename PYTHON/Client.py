import os
import threading
import queue
import datetime
from Scan import run_scan_detection_thread, stop_scan_detection_thread, alert_queue as scan_alert_queue
from Dos import run_dos_detection_thread, stop_dos_detection_thread, alert_queue as dos_alert_queue
from utils import *


scan_syn_thread = None  
scan_dos_thread = None 

def choix_interface():
    """Permet à l'utilisateur de choisir son interface

    Returns:
        String: Le nom de l'interface utilisateur
    """
    interface,interface_input = "",""
    
    while interface_input == "":
            
            interface_input = input(f"\n{BOLD}Entrer le nom de votre interface : {RESET}")
            if interface_input =="":
                print(f"{ROUGE}Votre interface ne peux pas être vide.{RESET}")
            else :
                interface = interface_input
                break

    return interface

def choix():
    """Permet à l'utilisateur de choisir et activer/désactiver les détections"""
    global scan_syn_thread, scan_dos_thread
    
    while True:
        menu()
        print(f"L'interface est choisi est {VIOLET}{interface}{RESET} .")
        option = input(f"\n{BOLD}Choisissez une option (1-3) : {RESET}")        

        if option == '1':
            if Dic_scan["syn"]:
                Dic_scan["syn"] = False
                stop_scan_detection_thread()  # Arrêter le thread de détection SYN
                scan_syn_thread.join()  # Attendre que le thread s'arrête
                print(f"\nSYN scan est maintenant {etat('syn', Dic_scan)}")
            else:
                Dic_scan["syn"] = True
                # ip = adresseip()
                scan_syn_thread = run_scan_detection_thread(interface)  # Démarrer le thread de détection SYN
                print(f"\nSYN scan est maintenant {etat('syn', Dic_scan)}")
        
        elif option == '2':
            if Dic_scan["dos"]:
                Dic_scan["dos"] = False
                stop_dos_detection_thread()  # Arrêter le thread de détection DoS
                scan_dos_thread.join()  # Attendre que le thread s'arrête
                print(f"\nDétection DoS est maintenant {etat('dos', Dic_scan)}")
            else:
                Dic_scan["dos"] = True
                scan_dos_thread = run_dos_detection_thread(interface)  # Démarrer le thread de détection DoS
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
    """"Écrit un message d'alerte dans un fichier de log avec la date et l'heure.

    Args:
        alert_message (String): Un arlerte remonter par les Threads
    """
    log_directory = "./logs"
    #   print(type(alert_message))
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
    while True:
        # Utilise une approche non-bloquante
        try:
            alerte_scan = scan_alert_queue.get_nowait()  # Récupère les alertes de scan sans attendre
            print(f"{ROUGE}[ALERTE]{RESET} {alerte_scan}")
            log_alert(alerte_scan)
            scan_alert_queue.task_done()
        except queue.Empty:
            pass  # Ignore l'exception si la file est vide

        try:
            alerte_dos = dos_alert_queue.get_nowait()  # Récupère les alertes DoS sans attendre
            print(f"{ROUGE}[ALERTE DOS]{RESET} {alerte_dos}")
            log_alert(alerte_dos)
            dos_alert_queue.task_done()
        except queue.Empty:
            pass  # Ignore l'exception si la file est vide

if __name__ == "__main__":
    interface = choix_interface()

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