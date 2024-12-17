#!/bin/bash

# Chemin du dépôt GitLab
REPO_URL="https://gitlab.com/your-repo/harvester.git"
LOCAL_DIR="/path/to/harvester"

# Aller dans le répertoire de l'application
cd $LOCAL_DIR

# Récupérer les dernières modifications
git fetch origin
git reset --hard origin/main

# Redémarrer l'application si un service est utilisé
# Remplacer "harvester" par le nom du service
systemctl restart harvester
