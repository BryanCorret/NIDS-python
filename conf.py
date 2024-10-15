import os
import sys

# Ajouter le chemin vers le répertoire contenant les modules Python
sys.path.insert(0, os.path.abspath('./PYTHON'))  # Répertoire PYTHON à partir de la racine du projet

# Informations sur le projet
project = 'NIDS PYTHON'
copyright = '2024, Bryan CORRET Alexis ARAUJO Rayan RGUIG'
author = 'Bryan CORRET Alexis ARAUJO Rayan RGUIG'
release = 'v1'

# Extensions Sphinx
extensions = ['sphinx.ext.autodoc', 'sphinx.ext.napoleon']

# Chemins des templates
templates_path = ['_templates']

# Langue du projet
language = 'fr'

# Exclure certains fichiers ou répertoires
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# Thème HTML
html_theme = 'alabaster'
html_static_path = ['_static']
