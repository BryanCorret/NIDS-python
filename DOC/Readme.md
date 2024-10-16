# Projet NIDS en Python (Network Intrusion Detection System)

## Objectif du Projet
Le but de ce projet est de développer un système de détection d'intrusion réseau (NIDS) basique en Python. Cet outil surveille le trafic réseau en temps réel pour détecter des comportements suspects ou des signatures d'attaques connues (comme les scans de ports ou les attaques DoS). 

## Groupe 
* CORRET Bryan
* ARAUJO Alexis
* RGUIG Ryan

## Fonctionnalités du NIDS
1. **Capture des paquets réseau en temps réel** : Utilisation de Scapy pour capturer et analyser le trafic.
2. **Détection de signatures** : Détection de scan SYN (port scan).

## Prérequis
- **Python** : v3.11 
- **Scapy** : v2.6.0

## Installation

1. **Cloner le dépôt** :

   ```bash
   git clone https://github.com/BryanCorret/NIDS.git
   cd nids
   pip install requirment.txt
   ```
## Lancement des scripts
1. **Lancer le projet**
* Il faut lancer Client.py

2. **Lancer l'environnement de test**
* Se trouver dans le répertoire NIDS-python
```bash
python -m unittest discover -s PYTHON/Test
```

3.**Faire la doc sphynx**
   ```bash 
      sphinx-quickstart
      make html
   ```
