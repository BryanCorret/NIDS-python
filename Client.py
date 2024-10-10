# Définition des couleurs pour le terminal
VIOLET = '\033[95m'
VERT = '\033[92m'
BLEU = '\033[96m'
WARNING = '\033[93m'
ROUGE = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Dictionnaire pour stocker l'état des scans
Dic_scan = {"syn": True, "anaPaquet": False}

def etat(type_scan, dic_scan=Dic_scan):
    """Renvoie l'état d'un scan avec une couleur indiquant s'il est actif ou inactif

    Args:
        type_scan (String): Type de scan
        dic_scan (Dict): Dico contenant les scans 

    Returns:
        String: Actif ou incatif
    """
    if dic_scan.get(type_scan, False):  # Si le scan est actif
        return f"{BOLD}{VERT}actif{RESET}"
    else:  # Si le scan est inactif
        return f"{BOLD}{ROUGE}inactif{RESET}"

def afficher_banniere():
    """Affiche la bannière du tool"""
    print(f"{BOLD}{VIOLET}**************************************************************************{RESET}")
    print(f"{BLEU}      __  __ __        __              _______ _______ _____  _______ ")
    print("     |  |/  |__|.----.|__|   ______   |    |  |_     _|     \\|     __| ")
    print("     |     <|  ||   _||  |  |______|  |       |_|   |_|  --  |__     |")
    print("     |__|\\__|__||__|  |__|            |__|____|_______|_____/|_______|")
    print(f"{VIOLET}**************************************************************************{RESET}")

def menu():
    """Affiche le menu des détections"""
    print(f"Menu de détections : ")
    print(f"1. Detection SYN : {etat('syn')}")
    print(f"2. Analyse de Paquets : {etat('anaPaquet')}")

if __name__ == "__main__":
    afficher_banniere()
    menu()
