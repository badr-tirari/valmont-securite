# Étape 5 — Recenser les clés et les secrets

*Chapitres 06 et 10.*

## Contenu

| Fichier | Rôle |
| --- | --- |
| [`carte-des-cles.md`](carte-des-cles.md) | **La carte des clés** : 12 clés cryptographiques et 9 secrets d'accès, chacun avec son usage, son propriétaire, son emplacement, qui y accède et sa périodicité de rotation ; règles par environnement ; cycle de vie |
| [`plan-secrets.md`](plan-secrets.md) | **Le plan de sortie des secrets du code** : état des lieux (dont 4 fuites constatées pendant le TP lui-même), destination de chaque secret, ordre de migration, **les deux garde-fous**, consignes immédiates |
| `garde-fous/.gitleaks.toml` | Règles gitleaks : règles standards + clés `VALMONT_CLE_*`, clés PEM chiffrées, mots de passe en dur, **NIR** |
| `garde-fous/.pre-commit-config.yaml` | Garde-fou n° 1 côté poste : le commit est refusé si un secret est détecté |
| `garde-fous/.github/workflows/garde-fous.yml` | Garde-fou n° 1 en CI (scan de tout l'historique, contrôle requis) et garde-fou n° 2 (environnement `production` protégé, OIDC, masquage) |
| `scanner_secrets.py` | Détecteur sans dépendance, avec les mêmes règles, pour vérifier le dossier avant le rendu |
| `../.secrets-autorises` | Exceptions : chacune ne lève **qu'une** règle (`nir` pour l'échantillon fictif), et chacune est justifiée |
| `preuves/05-detection-secrets.txt` | Sortie réelle : fuite F3 détectée → corrigée → dossier propre ; dépôt piégé : 6 fuites sur 6 bloquées |

## Les deux garde-fous, en bref

1. **Détection de secrets bloquante, en local et en CI.** gitleaks en crochet `pre-commit`,
   puis en job **requis** qui scanne tout l'historique. Rien n'entre dans `main` si un
   secret, une clé privée ou un NIR est détecté.
2. **Secrets de production hors de portée du code et des journaux.** Ils ne sont
   accessibles qu'au job `deploy`, sur `main`, après **approbation d'une seconde
   personne**, via un jeton OIDC de quelques minutes. Aucun secret longue durée n'est
   stocké dans la CI, et les valeurs sont masquées dans les journaux.

## Vérifier le dossier avant le rendu (PowerShell)

```
cd "C:\Users\tirar\OneDrive\Documents\diginamic cours\La-cryptographie-support-de-cours\valmont-securite\05-cles-et-secrets"
```

```
py scanner_secrets.py ..
```

Résultat attendu : `Bilan : 0 secret(s) détecté(s) hors exceptions`. Les clés privées de
démonstration présentes sur ton poste (partenaire, biologiste) apparaissent en `[info]` :
elles sont exclues du dépôt par `.gitignore`.

## Ce que la démonstration ne prouve pas (à reprendre dans le rapport)

- Le Coffre (Vault), l'OIDC et l'environnement `production` sont **décrits et
  configurés**, pas déployés : le TP n'a ni serveur de production ni dépôt distant avec
  une CI active.
- `scanner_secrets.py` est un filet de vérification pédagogique : en production, c'est
  gitleaks, avec ses règles d'entropie et ses centaines de formats de jetons, qui fait
  foi.
- Un détecteur ne trouve que ce qu'il sait reconnaître : un mot de passe sans mot-clé
  autour (`connect("valmont", "Xy7…")`) lui échappe. La revue de code reste
  indispensable.
