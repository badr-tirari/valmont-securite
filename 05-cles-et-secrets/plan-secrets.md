# Plan de sortie des secrets du code — Laboratoire Valmont

*Étape 5 — chapitre 10. Règle : un secret ne vit ni dans le code, ni dans l'image, ni dans les journaux. Il est injecté au démarrage et conçu pour être remplacé.*

## 1. État des lieux

### Ce que le code du TP fait déjà bien

| Point | Où |
| --- | --- |
| Aucune clé dans le code : `os.environ[...]`, et le script **refuse de démarrer** si la variable manque (aucune valeur de repli codée en dur) | `02-au-repos/cles.py`, `migrer_colonne.py`, `mots_de_passe.py` |
| Mot de passe root MySQL absent du `docker-compose.yml` : il est lu dans l'environnement, et `${VALMONT_DB_PASSWORD:?}` fait échouer le démarrage s'il manque | `02-au-repos/docker-compose.yml` |
| Clés privées chiffrées par une phrase de passe, exclues du dépôt par `.gitignore` | `03-…/partenaire/`, `04-…/cles/` |
| Messages d'erreur sobres, sans trace d'exécution qui révélerait hôte, port ou chemins | `migrer_colonne.py`, `mots_de_passe.py` |

### Fuites constatées pendant le TP lui-même (et corrections)

| # | Constat | Risque | Correction |
| --- | --- | --- | --- |
| F1 | `docker exec … mysql -uroot -p"$env:VALMONT_DB_PASSWORD"` : MySQL lui-même avertit `Using a password on the command line interface can be insecure` | Le mot de passe apparaît dans la liste des processus du conteneur (`ps`) pendant l'exécution | Utiliser `MYSQL_PWD` dans l'environnement du `docker exec`, ou un fichier `--defaults-extra-file` en `600`, ou mieux, le compte `valmont_app` du Coffre |
| F2 | `$env:VALMONT_DB_PASSWORD = "…"` tapé dans PowerShell | PSReadLine enregistre chaque commande dans `ConsoleHost_history.txt` (en clair, dans le profil Windows, synchronisé OneDrive le cas échéant) | Saisir avec `Read-Host -AsSecureString` (voir § 4), ou injecter depuis le Coffre ; purger l'historique après le TP |
| F3 | Le journal d'exécution de l'étape 4 contenait la phrase de passe de démonstration du biologiste | Un secret dans une **preuve** est un secret dans le dépôt | Valeur remplacée par `********` dans `04-signature/preuves/05-execution-poste-badr.txt` ; détecté par `scanner_secrets.py` |
| F4 | Les fichiers `.pem` privés existent sur le poste de cours, dans le dossier du projet | Un `git add .` les embarquerait sans `.gitignore` | `.gitignore` en place **et** garde-fou n° 1, qui bloque même si `.gitignore` est oublié |

## 2. Plan de sortie : où va chaque secret

| Secret (carte des clés) | Aujourd'hui (TP) | Cible |
| --- | --- | --- |
| K1, K2, K3 (clés AES / HMAC) | Variables d'environnement de la session PowerShell | **Coffre** `kv/valmont/prod/…`, injectées au démarrage par l'agent Vault (fichier en mémoire `tmpfs`) ou en variables d'environnement du service systemd |
| S1 root MySQL | Variable d'environnement + `docker-compose` | Coffre, accès « bris de glace » journalisé ; l'application ne l'utilise **jamais** |
| S2 compte applicatif | (n'existe pas : le TP utilise root) | **Secret dynamique** : le Coffre crée `valmont_app_<id>` avec une durée de vie de 24 h et les seuls droits DML |
| S4 MinIO | — | Coffre, clé en écriture seule, verrouillage d'objets sur le bucket de sauvegarde |
| S5 jeton de déploiement | — | **OIDC** : la CI s'authentifie au Coffre / au registre sans aucun secret stocké |
| K7 clé du biologiste | PEM chiffré sur disque | Carte CPS / jeton matériel : la clé ne sort pas du support |

### Ordre de migration

1. **Inventaire** : cette carte, plus un scan de tout l'historique Git avec `gitleaks detect --log-opts="--all"`, pas seulement de la version courante.
2. **Coffre** : créer les chemins `test/` et `prod/`, avec des politiques par identité (application, CI, ADM).
3. **Basculer chaque consommateur** : le code lit toujours `os.environ`, seul l'injecteur change. Aucune modification applicative n'est nécessaire.
4. **Révoquer puis remplacer** tout secret trouvé dans l'historique, **avant** de nettoyer l'historique (un secret retiré du code mais encore valide reste exploitable dans un clone).
5. **Nettoyer** : `git filter-repo`, puis forcer la reprise des clones.
6. **Activer les deux garde-fous** ci-dessous, et seulement ensuite reprendre les déploiements.

## 3. Les deux garde-fous avant le prochain déploiement

### Garde-fou n° 1 — Détection de secrets bloquante, en local ET en CI

Un secret détecté avant le commit coûte une minute ; détecté en production, il coûte un incident.

- **En local** : crochet `pre-commit` avec **gitleaks** (`garde-fous/.pre-commit-config.yaml`). Le commit est refusé si un secret est détecté.
- **En CI** : job `secrets` (`garde-fous/.github/workflows/garde-fous.yml`) qui scanne **tout l'historique** à chaque push et chaque *pull request*. Le job est **requis** : la branche `main` est protégée et rien n'y entre si ce job échoue. Il rattrape ce que le crochet local n'a pas vu (crochet non installé, `--no-verify`).
- **Règles propres à Valmont** (`garde-fous/.gitleaks.toml`), en plus des règles standards : clés `VALMONT_CLE_*` en base64, clés privées PEM (même chiffrées), **NIR** (15 chiffres) : un export de production commité est une fuite de données de santé, même sans secret.

### Garde-fou n° 2 — Les secrets de production hors de portée du code et des journaux

- Les secrets de production ne sont accessibles qu'à un **environnement CI `production` protégé** : seul le job `deploy`, sur `main`, après **approbation manuelle** d'une seconde personne (quatre yeux), peut les obtenir.
- Authentification au Coffre par **OIDC** : jeton fédéré valable quelques minutes, limité à ce dépôt, à cette branche et à cet environnement. Aucun secret longue durée n'est stocké dans la CI.
- **Masquage** des valeurs dans les journaux (`::add-mask::`), interdiction de `set -x` dans les étapes qui manipulent des secrets.
- Les jobs de *pull request* venant de forks n'ont **aucun** accès aux secrets.

## 4. Consignes immédiates pour l'équipe

Saisir un secret dans PowerShell sans le laisser dans l'historique :

```powershell
$env:VALMONT_DB_PASSWORD = [System.Net.NetworkCredential]::new("", (Read-Host "Mot de passe BDD" -AsSecureString)).Password
```

Purger l'historique PowerShell après le TP :

```powershell
Remove-Item (Get-PSReadLineOption).HistorySavePath
```

Vérifier le dossier avant chaque rendu :

```powershell
py scanner_secrets.py ..
```
