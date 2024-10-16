import os
import threading
import queue
import datetime
from Scan import run_scan_detection_thread, stop_scan_detection_thread, alert_queue as scan_alert_queue
from Dos import run_dos_detection_thread, stop_dos_detection_thread, alert_queue as dos_alert_queue
from Bruteforce_ssh import run_ssh_bruteforce_thread, stop_ssh_bruteforce_thread, alert_queue as ssh_alert_queue
from utils import *


scan_dos_thread, scan_syn_thread, ssh_thread = None, None, None

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
    """Permet à l'utilisateur de choisir et activer ou de désactiver les détections"""
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
                stop_dos_detection_thread()  # Arrêter le thread de detection DoS
                scan_dos_thread.join()  # Attendre que le thread s'arrete
                print(f"\nDétection DoS est maintenant {etat('dos', Dic_scan)}")
            else:
                Dic_scan["dos"] = True
                scan_dos_thread = run_dos_detection_thread(interface)  # Démarrer le thread de détection DoS
                print(type(scan_dos_thread))
                print(f"\nDétection DoS est maintenant {etat('dos', Dic_scan)}")    
                      
        elif option == '3':
            if Dic_scan["ssh"]:
                Dic_scan["ssh"] = False
                stop_ssh_bruteforce_thread()  # Arrêter le thread de détection SSH
                ssh_thread.join()  # Attendre que le thread s'arrête
                print(f"\nDétection brute-force SSH est maintenant {etat('ssh', Dic_scan)}")
            else:
                Dic_scan["ssh"] = True
                ssh_thread = run_ssh_bruteforce_thread(interface)  # Démarrer le thread de détection SSH
                print(f"\nDétection brute-force SSH est maintenant {etat('ssh', Dic_scan)}")

        elif option == '4':
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

    #  si le dossier existe sinon il le crée
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    current_datetime = datetime.datetime.now()
    log_file_name = os.path.join(log_directory, f"LOG_{current_datetime.strftime('%Y-%m-%d')}.txt")

    print(f"Fichier de log : {log_file_name}") 
    log_entry = f"{alert_message} | [{current_datetime.strftime('%d-%m-%Y %H:%M:%S')}]\n"
    with open(log_file_name, "a") as log_file:
        log_file.write(log_entry)

def gestion_alertes():
    """Gère les alertes"""
    while True:
        try: # accès alert_scan
            alerte_scan = scan_alert_queue.get_nowait()  
            print(f"{ROUGE}[ALERTE]{RESET} {alerte_scan}")
            log_alert(alerte_scan)
            scan_alert_queue.task_done()

            alerte_dos = dos_alert_queue.get_nowait() 
            print(f"{ROUGE}[ALERTE DOS]{RESET} {alerte_dos}")
            log_alert(alerte_dos)
            dos_alert_queue.task_done()

        except queue.Empty: # si vide passer l'erreur
            pass 

        try: # accès alert_scan
            alerte_dos = dos_alert_queue.get_nowait() 
            print(f"{ROUGE}[ALERTE DOS]{RESET} {alerte_dos}")
            log_alert(alerte_dos)
            dos_alert_queue.task_done()

        except queue.Empty: # si vide passer l'erreur
            pass  

        try: # accès alert_scan
            alerte_ssh = ssh_alert_queue.get_nowait()
            print(f"{ROUGE}[ALERTE SSH]{RESET} {alerte_ssh}")  
            log_alert(alerte_ssh)            
            ssh_alert_queue.task_done()       

        except queue.Empty:  # si vide passer l'erreur       
            pass

if __name__ == "__main__":
    interface = choix_interface()

    afficher_banniere()

    # Démarrer un thread pour les alertes
    thread_alertes = threading.Thread(target=gestion_alertes)
    thread_alertes.daemon = True  # le thread s'arrête à la fin du programme principal
    thread_alertes.start()

    choix()

    thread_alertes.join()