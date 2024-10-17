Utils
=====

Le module `utils` contient des fonctions utilitaires pour gérer l'affichage des états de détection, la bannière de l'outil, et le menu des options de protection. Il propose également des constantes pour le formatage en couleur et des messages d'affichage.


BANNER
------

.. data:: BANNER

Contient la bannière ASCII artistique affichée par l'outil.

Explication des fonctions
-------------------------

etat
----

.. autofunction:: etat

Renvoie l'état d'un scan (actif ou inactif) avec une couleur associée.

Args:
    type_scan (string): Nom de la protection à vérifier.
    dic_scan (Dict): Dictionnaire contenant l'état des protections. Par défaut, utilise `Dic_scan`.

Returns:
    str: Renvoie un texte formaté en couleur indiquant si la protection est active ou inactive.

afficher_banniere
-----------------

.. autofunction:: afficher_banniere

Affiche la bannière ASCII de l'outil avec un cadre et des couleurs.

menu
----

.. autofunction:: menu

Affiche le menu des options de détection pour l'utilisateur avec les états des différentes protections (SYN, DoS, SSH brute-force).
