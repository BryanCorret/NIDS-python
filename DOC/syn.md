# Scan SYN (Synchronize)

## Introduction

Le **Scan SYN** est une méthode de **reconnaissance passive** utilisée par des attaquants pour déterminer quels ports sont ouverts sur une machine cible. Cette technique tire parti du processus de connexion **TCP** (Transmission Control Protocol), en envoyant des paquets avec le drapeau **SYN** activé. Le Scan SYN est aussi appelé **demi-ouverture** (ou **stealth scan**), car il n’établit jamais de connexion complète.

## Fonctionnement du Protocole TCP

Le protocole TCP utilise un processus en trois étapes appelé **three-way handshake** pour établir une connexion entre deux hôtes :

1. **SYN** : L'initiateur envoie un paquet avec le drapeau SYN activé pour demander une connexion.
2. **SYN-ACK** : Le serveur répond avec un paquet **SYN-ACK** pour accuser réception de la demande.
3. **ACK** : L'initiateur complète la connexion en envoyant un paquet **ACK**.

## Qu'est-ce qu'un Scan SYN ?

Le **Scan SYN** interrompt volontairement ce processus avant l'étape 3. Voici comment fonctionne un Scan SYN :

1. L'attaquant envoie un paquet **SYN** à la cible.
2. Si le port est **ouvert**, la cible répond avec un paquet **SYN-ACK**.
3. Si le port est **fermé**, la cible répond avec un paquet **RST** (reset).
4. Au lieu de répondre avec un **ACK** pour établir une connexion, l'attaquant ignore la réponse ou envoie un paquet **RST** pour couper la connexion.

Cette méthode permet à l'attaquant de rester relativement discret, car une connexion complète n'est jamais établie, ce qui rend plus difficile la détection de son activité.

## Utilité dans les Attaques

Un attaquant utilise un **Scan SYN** pour cartographier les services en cours d'exécution sur une machine sans éveiller trop de soupçons. Voici pourquoi c'est une méthode populaire :
- **Rapidité** : Les scans SYN peuvent être très rapides, permettant à l'attaquant de scanner de nombreux ports en peu de temps.
- **Discrétion** : Puisque la connexion n'est jamais complétée, les serveurs journaux ou pare-feu peuvent être moins susceptibles de détecter le scan comparé à un scan complet TCP.

## Détection d'un Scan SYN dans un NIDS

La détection d'un **Scan SYN** repose sur l'observation de paquets TCP avec le drapeau **SYN** activé, mais sans **ACK**. 
