import ipaddress

Dic_scan = {"syn": False, "dos": False, "ssh": False}
def etat(type_scan, dic_scan=Dic_scan):
    """Renvoie l'état d'un scan avec une couleur indiquant s'il est actif ou inactif

    Args:
        type_scan (string): Nom de la protection
        dic_scan (Dict): Dictionaire contenant l'état des dictionnaires.

    Returns:
        Bool: True si la protection est active sinon False
    """
    if dic_scan.get(type_scan, False):
        return f"{BOLD}{VERT}actif{RESET}"
    else:
        return f"{BOLD}{ROUGE}inactif{RESET}"
    
BANNER = """_   _ ___________  _____        _____ _____ ___________ _____  ___  
| \\ | |_   _|  _  \\/  ___|      |  _  |_   _|  ___| ___ \\_   _|/ _ \\ 
|  \\| | | | | | | |\\ `--. ______| | | | | | | |__ | |_/ / | | / /_\\ \\
| . ` | | | | | | | `--. \\______| | | | | | |  __||    /  | | |  _  |
| |\\  |_| |_| |/ / /\\__/ /      \\ \\_/ / | | | |___| |\\ \\ _| |_| | | |
\\_| \\_/\\___/|___/  \\____/        \\___/  \\_/ \\____/\\_| \\_|\\___/\\_| |_/"""
VIOLET = '\033[95m'
VERT = '\033[92m'
BLEU = '\033[96m'
WARNING = '\033[93m'
ROUGE = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

def afficher_banniere():
    """Affiche la bannière du tool"""
    print(f"{BOLD}{VIOLET}**********************************************************************{RESET}")
    print(BLEU,BANNER,RESET) 
    print(f"{VIOLET}**********************************************************************{RESET}")

def menu():
    """Affiche le menu des détections"""
    print(f"\nMenu de détections : ")
    print(f"1. Detection SYN : {etat('syn')}")
    print(f"2. Detection Dos : {etat('dos')}")
    print(f"3. Detection Bruteforce SSh : {etat('ssh')}")
    print(f"4. Quitter")

def adresseip():
    """affiche le menu d'une nouvelle adresse IP

    Returns:
        String: Retourne l'ip de l'utilisateur
    """
    print(f"o. Si vous voulez un scan d'une adresse IP spécifique ?")
    print(f"n. Si vous ne souhaitez pas d'adresse IP spécifique")
    bool_ip = input(f"\n{BOLD}Voulez-vous scan une adresse ip spécifique ? option (o, n) : {RESET}")

    ip = None
    if bool_ip == 'o':
        while True:
            ip_input = input(f"\n{BOLD}Entrer l'adresse IP que vous souhaitez : {RESET}")
            try:
                ip = str(ipaddress.ip_address(ip_input))  # Valide et retourne une IP valide
                break
            except ValueError:
                print(f"{ROUGE}Adresse IP invalide, veuillez entrer une adresse valide.{RESET}")
    return ip