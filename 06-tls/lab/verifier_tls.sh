#!/bin/sh
# Vérifie les cinq points de la politique TLS du Laboratoire Valmont, côté serveur (openssl)
# et côté client (curl). Chaque contrôle affiche la commande, le résultat attendu et le résultat obtenu.
#
# Usage : verifier_tls.sh <nom> [fichier_CA]
#   nom        portail.labo-valmont.fr
#   fichier_CA autorité à approuver (lab) ; omis en production (magasin du système)
# Variables facultatives : CONNECT (hôte:port HTTPS réel), CONNECT_HTTP (hôte:port HTTP réel)

# Connexion directe au serveur testé : un proxy HTTP fausserait les résultats.
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy

NOM="${1:-portail.labo-valmont.fr}"
CA="${2:-}"
CONNECT="${CONNECT:-$NOM:443}"
CONNECT_HTTP="${CONNECT_HTTP:-$NOM:80}"
OK=0; KO=0
CAOPT=""; [ -n "$CA" ] && CAOPT="-CAfile $CA"
CURLCA=""; [ -n "$CA" ] && CURLCA="--cacert $CA"
RESOLVE="--connect-to $NOM:443:$CONNECT --connect-to $NOM:80:$CONNECT_HTTP"

ok()  { OK=$((OK+1)); echo "  [OK] $1"; }
ko()  { KO=$((KO+1)); echo "  [ÉCHEC] $1"; }
sc()  { openssl s_client -connect "$CONNECT" -servername "$NOM" "$@" </dev/null 2>&1; }
neg() { sc "$@" | grep -E "^ *(Protocol|Cipher) *:|^New, " | head -1; }

echo "Cible : https://$NOM  (connexion $CONNECT)"
echo

echo "Point 1 — Versions : TLS 1.2 et 1.3 uniquement"
for v in tls1 tls1_1; do
  echo "  \$ openssl s_client -connect $CONNECT -$v -cipher 'DEFAULT:@SECLEVEL=0'    attendu : refus"
  if sc -"$v" -cipher 'DEFAULT:@SECLEVEL=0' | grep -q "Cipher is (NONE)\|alert\|no protocols\|wrong version\|handshake failure\|unsupported protocol"; then
    ok "$v refusé par le serveur"; else ko "$v ACCEPTÉ"; fi
done
for v in tls1_2 tls1_3; do
  echo "  \$ openssl s_client -connect $CONNECT -$v    attendu : poignée de main réussie"
  r=$(sc -"$v" | grep -E "^New, " | head -1)
  case "$r" in *"Cipher is (NONE)"*|"") ko "$v refusé" ;; *) ok "$v accepté — $r" ;; esac
done
echo

echo "Point 2 — Suites AEAD uniquement"
echo "  \$ (essai de chacune des suites TLS 1.2 connues d'OpenSSL, une par une)"
acceptees=""; faibles=""
for c in $(openssl ciphers 'ALL:@SECLEVEL=0' | tr ':' ' '); do
  if sc -tls1_2 -cipher "$c:@SECLEVEL=0" | grep -q "^New, TLSv1.2"; then
    acceptees="$acceptees $c"
    case "$c" in *GCM*|*CHACHA20*|*CCM*) ;; *) faibles="$faibles $c" ;; esac   # AEAD : GCM, ChaCha20-Poly1305, CCM
  fi
done
echo "    suites TLS 1.2 acceptées :$acceptees"
if [ -n "$acceptees" ] && [ -z "$faibles" ]; then ok "TLS 1.2 : uniquement des suites AEAD"; else ko "suites non AEAD acceptées :$faibles"; fi
for s in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
  if sc -tls1_3 -ciphersuites "$s" | grep -q "^New, TLSv1.3"; then echo "    TLS 1.3 : $s acceptée"; fi
done
echo "  \$ openssl s_client -connect $CONNECT -tls1_2 -cipher ECDHE-RSA-AES128-SHA256    attendu : refus (CBC)"
if sc -tls1_2 -cipher 'ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:@SECLEVEL=0' | grep -q "^New, TLSv1.2"; then ko "suite CBC acceptée"; else ok "suite CBC refusée"; fi
echo

echo "Point 3 — En-tête HSTS avec includeSubDomains"
echo "  \$ curl -sI $CURLCA https://$NOM/    attendu : strict-transport-security: max-age=63072000; includeSubDomains"
h=$(curl -sI $CURLCA $RESOLVE "https://$NOM/" | tr -d '\r' | grep -i '^strict-transport-security:')
echo "    $h"
case "$h" in *max-age=63072000*includeSubDomains*) ok "HSTS présent, deux ans, sous-domaines inclus" ;; *) ko "HSTS absent ou incomplet" ;; esac
h404=$(curl -sI $CURLCA $RESOLVE "https://$NOM/page-inexistante" | tr -d '\r' | grep -ci '^strict-transport-security:')
[ "$h404" = "1" ] && ok "HSTS renvoyé aussi sur une réponse 404 (« always »)" || ko "HSTS absent sur les erreurs"
echo

echo "Point 4 — Redirection HTTP → HTTPS"
echo "  \$ curl -sI http://$NOM/resultats?id=42    attendu : 301 vers https://$NOM/resultats?id=42"
r=$(curl -sI $RESOLVE "http://$NOM/resultats?id=42" | tr -d '\r')
code=$(echo "$r" | head -1); loc=$(echo "$r" | grep -i '^location:')
echo "    $code"; echo "    $loc"
case "$code$loc" in *301*"https://$NOM/resultats?id=42"*) ok "redirection permanente vers HTTPS, chemin et paramètres conservés" ;; *) ko "pas de redirection 301 vers HTTPS" ;; esac
r=$(curl -sI -H "Host: site-pirate.example" $RESOLVE "http://$NOM/" | tr -d '\r' | grep -i '^location:')
echo "  \$ curl -sI -H 'Host: site-pirate.example' http://$NOM/    attendu : redirection vers le VRAI nom"
echo "    $r"
case "$r" in *"https://$NOM/"*) ok "en-tête Host forgé ignoré" ;; *) ko "redirection vers un nom fourni par le client" ;; esac
echo

echo "Point 5 — Certificat et chaîne de confiance"
echo "  \$ openssl s_client -connect $CONNECT -servername $NOM -verify_hostname $NOM -verify_return_error $CAOPT"
v=$(sc -verify_hostname "$NOM" -verify_return_error $CAOPT | grep -E "Verify return code|^depth=|subject=|issuer=" )
echo "$v" | sed 's/^/    /'
echo "$v" | grep -q "Verify return code: 0 (ok)" && ok "chaîne valide, nom vérifié" || ko "chaîne invalide"
fin=$(sc | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
echo "  \$ openssl x509 -noout -enddate -checkend 2592000    attendu : expire dans plus de 30 jours"
if sc | openssl x509 -noout -checkend 2592000 >/dev/null 2>&1; then ok "expire le $fin (> 30 jours)"; else ko "expire dans moins de 30 jours ($fin)"; fi
echo "  \$ curl -s -o /dev/null -w '%{http_code} %{ssl_verify_result}' $CURLCA https://$NOM/    attendu : 200 0"
r=$(curl -s -o /dev/null -w '%{http_code} %{ssl_verify_result}' $CURLCA $RESOLVE "https://$NOM/")
echo "    $r"
[ "$r" = "200 0" ] && ok "curl : page servie, certificat vérifié par le client" || ko "curl : échec de vérification ($r)"
if [ -n "$CA" ]; then
  echo "  \$ curl https://$NOM/   (SANS --cacert : magasin de confiance du système)    attendu en labo : refus"
  if curl -s -o /dev/null $RESOLVE "https://$NOM/"; then
    echo "    accepté"; else ok "refusé : l'autorité du laboratoire n'est pas une autorité publique (limite de la simulation)"; fi
fi
echo

echo "Bilan : $OK contrôle(s) réussi(s), $KO échec(s)"
[ "$KO" -eq 0 ]
