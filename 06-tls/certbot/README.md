# Renouvellement automatisé du certificat (point 5 de la politique)

| Élément | Rôle |
| --- | --- |
| `obtenir-certificat.sh` | Première émission : défi HTTP-01 par webroot, clé **ECDSA P-256**, crochet de rechargement enregistré |
| `recharger-nginx.sh` | Crochet `deploy` : `nginx -t` **puis** `reload`, seulement si le renouvellement a réussi |
| `certbot.timer` (fourni par le paquet certbot) | Lance `certbot renew` deux fois par jour ; le certificat est renouvelé quand il lui reste **moins de 30 jours** (certificats de 90 jours, donc tous les 60 jours environ) |

À chaque renouvellement, certbot génère une **nouvelle clé privée** (`reuse_key = False` par
défaut) : la clé K9 de la carte des clés tourne avec le certificat.

## Vérifications sur le serveur

Le minuteur est actif :

```
systemctl list-timers certbot.timer
```

Simulation complète d'un renouvellement, contre l'environnement de test de Let's Encrypt, sans rien modifier :

```
certbot renew --dry-run
```

Résultat attendu : `Congratulations, all simulated renewals succeeded`.

État et échéance du certificat :

```
certbot certificates
```

## Supervision

Une sonde externe vérifie chaque jour que le certificat servi expire dans plus de 21 jours
(`openssl x509 -checkend 1814400`). Si le minuteur tombe en panne, l'alerte arrive trois
semaines avant la coupure, pas le jour même.
