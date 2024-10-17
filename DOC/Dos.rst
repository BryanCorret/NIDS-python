Module de détection DoS
=======================

Le module `dos.py` permet de détecter les attaques de type Déni de Service (DoS), les floods SYN et ICMP en surveillant le trafic réseau. Il utilise Scapy pour capturer les paquets IP, un compteur pour chaque type de paquet (SYN, ICMP, et général), et des seuils pour déclencher des alertes.

Explication des variables
-------------------------

.. data:: syn_cpt

Dictionnaire contenant les adresses IP sources et le nombre de paquets SYN détectés pour chaque IP.

.. data:: ping_cpt

Dictionnaire contenant les adresses IP sources et le nombre de paquets ICMP détectés pour chaque IP.

.. data:: ip_cpt

Dictionnaire contenant les adresses IP sources et le nombre de paquets IP généraux détectés pour chaque IP.

.. data:: SEUIL

Le seuil à partir duquel une alerte DoS, SYN flood ou ICMP flood est générée. Par défaut, fixé à 10 paquets par seconde.

.. data:: DELAY

Temps en secondes avant la réinitialisation des compteurs pour chaque type de paquet. Par défaut, fixé à 3 secondes.

.. data:: alert_queue

Queue utilisée pour stocker les alertes de détection DoS, SYN flood, et ICMP flood. Chaque alerte est insérée dans la queue lorsqu'une attaque est détectée.

.. data:: stop_thread_dos

Événement threading utilisé pour arrêter le thread de détection DoS de manière propre.

Explication des fonctions
-------------------------

detect_dos
----------

.. autofunction:: detect_dos

Cette fonction est responsable de la détection des attaques DoS en comptant les paquets envoyés par chaque adresse IP source. Si le nombre de paquets envoyés par une IP dépasse un seuil défini, une alerte est générée et placée dans la file d'attente des alertes.

reset
-----

.. autofunction:: reset

Cette fonction réinitialise le compteur de paquets pour chaque IP toutes les `DELAY` secondes, permettant de mesurer le nombre de paquets par IP par seconde.

run_dos_detection_thread
------------------------

.. autofunction:: run_dos_detection_thread

Cette fonction lance un thread qui capture les paquets réseau en temps réel et applique la détection DoS.

Args:
    interface (str): Interface réseau sur laquelle effectuer la capture de paquets (ex : `eth0`).

Returns:
    threading.Thread: Renvoie le thread lancé pour la détection des paquets DoS.

stop_dos_detection_thread
-------------------------

.. autofunction:: stop_dos_detection_thread

Cette fonction arrête proprement le thread de détection DoS en déclenchant l'événement `stop_thread_dos`.