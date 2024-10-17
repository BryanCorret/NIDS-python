Module de détection Scan
=========================
.. automodule:: Scan

Ce module est utilisé pour détecter divers types de scans réseau, tels que les scans SYN, Null, Xmas, et ICMP. Ces types de scans sont souvent utilisés par les attaquants pour explorer des services ouverts sur des machines cibles.

Explication des variables
-------------------------

.. data:: alert_queue

   Queue utilisée pour stocker les alertes de détection de scans (SYN, Null, Xmas, ICMP). Chaque alerte est insérée dans la queue lorsqu'un scan est détecté.

.. data:: stop_thread

   Événement threading utilisé pour arrêter le thread de détection des scans de manière propre.

Explication des fonctions
-------------------------

detect_scan
-----------

.. autofunction:: detect_scan

   Cette fonction est responsable de la détection de différents types de scans réseau, tels que :

   - **SYN Scan** : Détecte les paquets TCP avec le drapeau SYN uniquement.
   - **Null Scan** : Détecte les paquets TCP sans aucun drapeau activé.
   - **Xmas Scan** : Détecte les paquets TCP avec les drapeaux FIN, PSH, et URG activés.
   - **ICMP Ping** : Détecte les paquets ICMP, souvent utilisés pour découvrir des machines actives sur le réseau.

run_scan_detection_thread
--------------------------

.. autofunction:: run_scan_detection_thread

   Cette fonction lance un thread qui capture le trafic réseau pour détecter les scans SYN et autres. Elle accepte une interface réseau comme paramètre pour capturer les paquets.

   Args:
       interface (str): Interface réseau sur laquelle effectuer la capture de paquets (ex : `eth0`).

   Returns:
       threading.Thread: Renvoie le thread lancé pour la détection des scans.

stop_scan_detection_thread
---------------------------

.. autofunction:: stop_scan_detection_thread

   Cette fonction arrête proprement le thread de détection des scans en déclenchant l'événement `stop_thread`.

