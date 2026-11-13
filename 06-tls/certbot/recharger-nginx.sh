#!/bin/sh
# Crochet de déploiement certbot : copié dans /etc/letsencrypt/renewal-hooks/deploy/ (chmod 755).
# Exécuté UNIQUEMENT après un renouvellement réussi : on vérifie la configuration avant de recharger,
# pour qu'un fichier cassé ne coupe jamais le portail.
set -eu
nginx -t -q && systemctl reload nginx
logger -t certbot "Certificat de portail.labo-valmont.fr renouvelé, nginx rechargé"
