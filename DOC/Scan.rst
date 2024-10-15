========================
Module de détection Scan
========================

Ce module est utilisé pour détecter divers types de scans réseau, tels que les scans SYN, Null, Xmas, et ICMP. Ces types de scans sont souvent utilisés par les attaquants pour explorer des services ouverts sur des machines cibles.

.. currentmodule:: Scan


Explication des fonctions
=========================

detect_scan
-----------

.. autofunction:: detect_scan

Cette fonction est responsable de la détection de différents types de scans réseau, tels que :

- **SYN Scan** : Paquets avec le drapeau TCP SYN uniquement.
- **Null Scan** : Paquets sans aucun drapeau TCP.
- **Xmas Scan** : Paquets avec les drapeaux TCP FIN, PSH, et URG activés.
- **ICMP Ping** : Paquets ICMP, souvent utilisés pour découvrir des machines actives sur le réseau.

run_scan_detection_thread
--------------------------

.. autofunction:: run_scan_detection_thread

Cette fonction lance un thread qui capture le trafic réseau pour détecter les scans SYN et autres. Elle accepte une adresse IP en paramètre pour filtrer les paquets capturés ou analyser tout le trafic si aucune IP spécifique n'est donnée.

stop_scan_detection_thread
---------------------------

.. autofunction:: stop_scan_detection_thread

Cette fonction arrête le thread de détection des scans en mettant fin à la capture de paquets.

Alerte de scan
==============

Les alertes de détection de scans (SYN, Null, Xmas, ICMP) sont placées dans une file d'attente (`alert_queue`) et peuvent être consultées en temps réel ou analysées plus tard.
