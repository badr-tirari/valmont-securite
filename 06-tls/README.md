# Étape 6 — Sécuriser le transit : TLS et certificats

*Chapitres 07 et 08 — portail patient `portail.labo-valmont.fr` (Nginx).*

## Contenu

| Fichier | Rôle |
| --- | --- |
| `nginx/portail-valmont.conf` | **La configuration de production**, commentée point par point |
| `certbot/` | Émission du certificat Let's Encrypt (ECDSA P-256), crochet de rechargement, vérification du renouvellement automatisé |
| `lab/generer_certificats_lab.py` | Mini-PKI de laboratoire : une autorité « Valmont Lab CA » et un certificat serveur de 90 jours |
| `lab/verifier_tls.sh` | Les vérifications : `openssl` côté serveur, `curl` côté client, avec le résultat attendu de chaque commande |
| `docker-compose.yml` | nginx 1.27 qui sert **la configuration de production telle quelle**, plus un conteneur client (openssl + curl) |
| `preuves/06-verification-tls.txt` | Sortie réelle : 14/14 avec la configuration Valmont, **9 échecs** avec la mauvaise configuration du chapitre 07 (contre-épreuve) |
| `preuves/07-execution-poste-badr-nginx-1.27.txt` | Exécution sur le poste de cours, Docker, nginx 1.27 : 14/14 |

## Conformité à la politique interne

| # | Exigence | Directive | Vérification (commande) | Résultat attendu |
| --- | --- | --- | --- | --- |
| 1 | TLS 1.2 et 1.3 uniquement | `ssl_protocols TLSv1.2 TLSv1.3;` | `openssl s_client -connect portail.labo-valmont.fr:443 -tls1_1` | Refus : pas de version commune |
| | | | `openssl s_client -connect portail.labo-valmont.fr:443 -tls1_3` | `New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384` |
| 2 | Suites AEAD uniquement | `ssl_ciphers ECDHE-…-GCM-…:ECDHE-…-CHACHA20-POLY1305` | Essai de **chacune** des suites TLS 1.2 d'OpenSSL ; `openssl s_client … -tls1_2 -cipher ECDHE-RSA-AES128-SHA256` | Seules des suites GCM / ChaCha20 acceptées ; la suite CBC est refusée |
| 3 | HSTS avec `includeSubDomains` | `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;` | `curl -sI https://portail.labo-valmont.fr/` | `strict-transport-security: max-age=63072000; includeSubDomains`, y compris sur une 404 |
| 4 | Redirection HTTP → HTTPS | `return 301 https://portail.labo-valmont.fr$request_uri;` | `curl -sI http://portail.labo-valmont.fr/resultats?id=42` | `301`, `Location: https://portail.labo-valmont.fr/resultats?id=42` |
| 5 | Let's Encrypt, renouvellement automatisé | `ssl_certificate /etc/letsencrypt/live/…` + `certbot.timer` + crochet `deploy` | `openssl s_client … -verify_hostname portail.labo-valmont.fr -verify_return_error` ; sur le serveur, `certbot renew --dry-run` | `Verify return code: 0 (ok)` ; `all simulated renewals succeeded` |

Choix au-delà de la politique : échange de clé ECDHE uniquement (confidentialité
persistante), tickets de session désactivés, nom d'hôte **fixe** dans la redirection
(un en-tête `Host` forgé est ignoré, ce que vérifie le script), `server_tokens off`.

**OCSP stapling volontairement absent.** Le corrigé du chapitre 07 le propose, mais
Let's Encrypt a arrêté son service OCSP le 6 août 2025 et ne met plus d'URL OCSP dans ses
certificats. La révocation passe désormais par les CRL. Activer `ssl_stapling` sur un
certificat Let's Encrypt n'aurait aucun effet.

## Ce que le client vérifie dans la chaîne de confiance

Le client remonte la chaîne du certificat du serveur jusqu'à une **autorité racine
présente dans son magasin de confiance**. À chaque maillon, il vérifie la signature avec
la clé publique de l'émetteur, la période de validité et le rôle autorisé (autorité
d'une part, authentification de serveur d'autre part). Il vérifie enfin que le nom
demandé, `portail.labo-valmont.fr`, figure dans le champ *Subject Alternative Name* du
certificat : sans ce contrôle, un certificat valide pour un autre site serait accepté.

## Exécution (PowerShell, une commande à la fois)

```
cd "C:\Users\tirar\OneDrive\Documents\diginamic cours\La-cryptographie-support-de-cours\valmont-securite\06-tls"
```

Générer la mini-PKI de laboratoire :

```
py lab\generer_certificats_lab.py lab\certs
```

Démarrer nginx avec la configuration de production :

```
docker compose up -d
```

Lancer les vérifications depuis le conteneur client (résultat attendu : `Bilan : 14 contrôle(s) réussi(s), 0 échec(s)`) :

```
docker compose run --rm verif
```

Arrêter :

```
docker compose down
```

## Ce que la simulation ne prouve pas (à reprendre dans le rapport)

- **La confiance publique.** La racine « Valmont Lab CA » n'est dans aucun magasin de
  confiance : le client ne l'accepte que parce qu'on la lui donne avec `--cacert`.
  Sans elle, la connexion est refusée (dernier contrôle du script). Avec Let's Encrypt,
  la racine ISRG fait déjà partie des navigateurs.
- **Le renouvellement.** `certbot`, le défi HTTP-01 et `certbot renew --dry-run` exigent
  un nom de domaine public qui pointe vers le serveur. Ils sont fournis et documentés
  (`certbot/`), mais pas exécutés.
- **HSTS sur les sous-domaines.** `includeSubDomains` engage **tous** les sous-domaines de
  `labo-valmont.fr` pendant deux ans. Il faut vérifier, avant la mise en production, qu'aucun
  ne sert encore du HTTP seul (chapitre 07 : HSTS se déclare après avoir vérifié).
- **Deux exécutions, deux versions.** `preuves/06-verification-tls.txt` a été produit avec
  nginx 1.24 (`listen 443 ssl http2`, sans IPv6), avec en plus la contre-épreuve.
  `preuves/07-execution-poste-badr-nginx-1.27.txt` est l'exécution sur le poste de
  cours, avec nginx 1.27 et le fichier de production **sans aucune modification** :
  14/14.
