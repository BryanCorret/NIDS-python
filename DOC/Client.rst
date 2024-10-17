Client
======
.. automodule:: Client

Le module `Client` est utilisé pour gérer les différentes détections d'intrusion (scans SYN, DoS, brute-force SSH) et pour traiter les alertes correspondantes. Il propose une interface en ligne de commande permettant d'activer ou de désactiver chaque type de détection, et écrit les alertes dans des fichiers journaux.

Explication des fonctions
-------------------------

choix_interface
---------------

.. autofunction:: choix_interface

Cette fonction permet à l'utilisateur de choisir l'interface réseau à utiliser pour la détection des attaques. Elle retourne le nom de l'interface choisie.

choix
-----

.. autofunction:: choix

Cette fonction présente un menu à l'utilisateur pour activer ou désactiver la détection des attaques (SYN Scan, DoS, brute-force SSH) sur l'interface réseau sélectionnée. Elle gère également l'arrêt propre des threads de détection.

log_alert
---------

.. autofunction:: log_alert

Cette fonction prend un message d'alerte comme argument et l'écrit dans un fichier de log, avec la date et l'heure de l'alerte. Les logs sont stockés dans le répertoire `./logs`.

gestion_alertes
---------------

.. autofunction:: gestion_alertes

Cette fonction fonctionne en arrière-plan (thread) pour surveiller les files d'attente des alertes. Elle récupère les alertes des différentes détections (scans, DoS, SSH brute-force) et les écrit dans les logs.

Alerte d'intrusion
------------------

Les alertes sont gérées via trois files d'attente différentes :

- `scan_alert_queue` : File d'attente pour les alertes de scan réseau (SYN, Null, Xmas).
- `dos_alert_queue` : File d'attente pour les alertes DoS.
- `ssh_alert_queue` : File d'attente pour les alertes brute-force SSH.

Ces alertes sont loguées dans des fichiers avec un horodatage.

Exécution
---------

Le programme principal exécute les étapes suivantes :

1. L'utilisateur choisit une interface réseau via la fonction `choix_interface`.
2. Un thread est démarré pour gérer les alertes en temps réel.
3. L'utilisateur peut activer ou désactiver les différentes détections via la fonction `choix`.
4. Les alertes sont affichées dans la console et sauvegardées dans des fichiers journaux.

.. automodule:: Client
   :members:
   :undoc-members:
