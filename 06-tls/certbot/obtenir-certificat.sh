#!/bin/sh
# Première émission du certificat Let's Encrypt (à lancer une fois sur le serveur, en root).
# Défi HTTP-01 par webroot : nginx sert /.well-known/acme-challenge/ depuis /var/www/certbot.
set -eu
mkdir -p /var/www/certbot
certbot certonly \
  --webroot -w /var/www/certbot \
  -d portail.labo-valmont.fr \
  --key-type ecdsa --elliptic-curve secp256r1 \
  --email securite@labo-valmont.fr --agree-tos --no-eff-email \
  --deploy-hook /etc/letsencrypt/renewal-hooks/deploy/recharger-nginx.sh
