# Étape 7 — Cartographier le trajet de la donnée

*Chapitre 11.*

| Fichier | Rôle |
| --- | --- |
| [`trajet-donnee.md`](trajet-donnee.md) | **Le livrable** : le trajet base → préparation → entrepôt → tableaux de bord, la mesure retenue pour chaque tronçon, ce qui ne doit pas être stocké ni exporté (minimisation RGPD), et chaque choix justifié par un risque |
| `minimiser_pour_entrepot.py` | La minimisation **exécutée** sur l'échantillon : suppression des identifiants directs, NIR → jeton HMAC, date → tranche d'âge, adresse → région ; contrôles de non-fuite et mesure du k-anonymat |
| `sortie/entrepot_resultats.csv` | Ce qui entrerait dans l'entrepôt (8 colonnes au lieu de 12) |
| `sortie/tableau_de_bord.csv` | Ce que verraient les tableaux de bord (cases < 5 masquées) |
| `preuves/07-minimisation.txt` | Sortie réelle |

## Exécution (PowerShell, une commande à la fois)

```
cd "C:\Users\tirar\OneDrive\Documents\diginamic cours\La-cryptographie-support-de-cours\valmont-securite\07-flux"
```

```
$env:VALMONT_CLE_PSEUDO = py ..\02-au-repos\generer_cle.py
```

```
py minimiser_pour_entrepot.py ..\02-au-repos\sql\01-patients.sql sortie
```

Résultat attendu : `[OK] 90 valeurs d'identifiants cherchées, 0 retrouvée(s)`, puis la
mesure du k-anonymat (k = 1, voir la conclusion de `trajet-donnee.md`).

## Ce que la démonstration ne prouve pas

- La chaîne (MinIO, orchestrateur, entrepôt, outil BI) est **décrite**, pas déployée :
  seul le job de minimisation est exécuté, sur le fichier SQL de l'échantillon.
- Le k-anonymat ne mesure qu'un risque parmi d'autres : il ne protège pas contre
  l'inférence d'attribut (si tous les patients d'un groupe ont le même résultat, on
  connaît le résultat de chacun). La l-diversité ou la confidentialité différentielle
  iraient plus loin.
