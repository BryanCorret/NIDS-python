SSH Brute-force Detection
=========================
Le module `ssh.py` permet de détecter les attaques brute-force SSH en surveillant les paquets réseau sur le port 22. Il utilise Scapy pour capturer les paquets TCP, un compteur pour chaque adresse IP source, et un seuil pour déclencher une alerte lorsque le nombre de tentatives dépasse la limite définie.

Explication des variables
-------------------------

.. data:: ssh_cpt

Dictionnaire contenant les adresses IP sources et leur nombre de tentatives de connexion SSH.


.. data:: SSH_SEUIL

Le seuil à partir duquel une alerte brute-force SSH est générée. Par défaut, fixé à 5 tentatives.

.. data:: DELAY

Temps en secondes avant la réinitialisation des compteurs d'IP dans `ssh_cpt`. Par défaut, fixé à 10 secondes.

.. data:: alert_queue

Queue utilisée pour stocker les alertes de détection brute-force SSH. Chaque alerte est insérée dans la queue lorsqu'une attaque est détectée.

stop_thread_ssh

.. data:: stop_thread_ssh

Événement threading utilisé pour arrêter le thread de détection SSH de manière propre.

Explication des fonctions
-------------------------

detect_ssh_bruteforce
----------------------

.. autofunction:: detect_ssh_bruteforce

Détecte les tentatives brute-force SSH en comptant les connexions sur le port 22.

Args:
    packet (scapy.packet.Packet): Paquet réseau analysé par Scapy. Si le paquet contient des segments TCP à destination du port 22, l'IP source est enregistrée et son compteur de tentatives est incrémenté.

reset_ssh
---------

.. autofunction:: reset_ssh

Réinitialise les compteurs de tentatives de connexion SSH toutes les `DELAY` secondes pour éviter une accumulation de tentatives à long terme.

run_ssh_bruteforce_thread
--------------------------

.. autofunction:: run_ssh_bruteforce_thread

Lance le thread responsable de la détection des attaques brute-force SSH.

Args:
    interface (str): Interface réseau sur laquelle effectuer la capture de paquets (ex : `eth0`).

Returns:
    threading.Thread: Renvoie le thread lancé pour la détection des paquets SSH.

stop_ssh_bruteforce_thread
---------------------------

.. autofunction:: stop_ssh_bruteforce_thread

Arrête proprement le thread de détection brute-force SSH en déclenchant l'événement `stop_thread_ssh`.
