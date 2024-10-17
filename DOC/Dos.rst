=======================
Module de détection DoS
=======================

Ce module est utilisé pour détecter les attaques de type Déni de Service (DoS) en analysant le trafic réseau et en comptant le nombre de paquets envoyés par chaque adresse IP source. Si une IP dépasse un seuil prédéfini de paquets par seconde, une alerte est générée.

Fonctions
=========

.. automodule:: Dos

Explication des fonctions
=========================

detect_dos
----------

.. autofunction:: detect_dos

Cette fonction est responsable de la détection des attaques DoS en comptant les paquets envoyés par chaque adresse IP source. Si le nombre de paquets envoyés par une IP dépasse un seuil défini, une alerte est générée et placée dans la file d'attente des alertes.

reset_packet_count
------------------

.. autofunction:: reset

Cette fonction réinitialise le compteur de paquets pour chaque IP toutes les secondes, permettant de mesurer le nombre de paquets par IP par seconde.

run_dos_detection_thread
------------------------

.. autofunction:: run_dos_detection_thread

Cette fonction lance un thread qui capture les paquets réseau en temps réel et applique la détection DoS.

stop_dos_detection_thread
-------------------------

.. autofunction:: stop_dos_detection_thread

Cette fonction arrête le thread de détection DoS et met fin à la capture de paquets.

Alerte DoS
==========

Une alerte est générée si une adresse IP envoie plus de `Seuil` paquets par seconde. Ces alertes sont stockées dans une file d'attente (`alert_queue`) et peuvent être consultées en temps réel.
