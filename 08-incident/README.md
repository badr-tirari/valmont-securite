# Étape 8 — Répondre à l'incident : fuite de clé

*Chapitres 06 et 12.*

| Fichier | Rôle |
| --- | --- |
| [`plan-incident.md`](plan-incident.md) | **Le plan** : périmètre exposé, chronologie et responsables, rotation à deux clés et consommateurs couverts, preuve de complétude, repli, coût du chiffrement |
| [`note-communication.md`](note-communication.md) | Note aux équipes (et version partenaire) |
| `trousseau.py` | Clés versionnées : en-tête authentifié qui porte l'identifiant de clé, clé compromise en **lecture seule**, journal d'usage |
| `rotation.py` | `simuler-archive`, `consommateurs`, `inventaire`, `rechiffrer` (par lots, panne simulable), `preuve-completude` |
| `mesure_cout.py` | Temps de lecture avec et sans chiffrement |
| `preuves/08-rotation-incident.txt` | Scénario complet : avant la fuite → isolement → lots → **panne et reprise** → **consommateur oublié détecté** → preuve → retrait |
| `preuves/08-mesure-cout.txt` | Mesures de coût |
| `preuves/09-execution-poste-badr.txt` | Exécution sur le poste de cours (Windows) : phases 0 à 3, retrait et mesure de coût |

## Exécution (PowerShell, une commande à la fois)

```
cd "C:\Users\tirar\OneDrive\Documents\diginamic cours\La-cryptographie-support-de-cours\valmont-securite\08-incident"
```

**Phase 0, avant la fuite :** une seule clé.

```
$v1 = py ..\02-au-repos\generer_cle.py
```

```
$env:VALMONT_TROUSSEAU_K3 = "k3-v1=$v1"
```

```
$env:VALMONT_K3_ACTIVE = "k3-v1"
```

```
py rotation.py simuler-archive archive 30
```

**Phase 1, la fuite :** k3-v1 isolée en lecture seule, k3-v2 devient active.

```
$v2 = py ..\02-au-repos\generer_cle.py
```

```
$env:VALMONT_TROUSSEAU_K3 = "k3-v1=$v1;k3-v2=$v2"
```

```
$env:VALMONT_K3_ACTIVE = "k3-v2"
```

```
$env:VALMONT_K3_LECTURE = "k3-v1"
```

```
py rotation.py consommateurs archive
```

**Phase 2, ré-chiffrement par lots, avec une panne simulée :**

```
py rotation.py rechiffrer archive --lot 10
```

```
py rotation.py rechiffrer archive --lot 10 --panne-apres 3
```

```
py rotation.py inventaire archive
```

```
py rotation.py consommateurs archive
```

```
py rotation.py rechiffrer archive
```

**Phase 3, preuve et retrait :**

```
py rotation.py preuve-completude archive k3-v1
```

```
$env:VALMONT_TROUSSEAU_K3 = "k3-v2=$v2"
```

```
Remove-Item Env:VALMONT_K3_LECTURE
```

```
py rotation.py consommateurs archive
```

**Coût du chiffrement :**

```
py mesure_cout.py
```

> Les clés `$v1` et `$v2` ne vivent que dans la session PowerShell : ne la ferme pas
> avant la fin du scénario.

## Ce que la simulation ne prouve pas

- Le Coffre, MinIO et ses sauvegardes verrouillées sont **décrits**, pas déployés :
  l'archive est un dossier local et le trousseau vient de variables d'environnement.
- Le journal d'usage est écrit par l'application elle-même. En production, c'est le
  **journal d'audit du Coffre** qui fait foi, car un consommateur compromis peut mentir
  sur ce qu'il fait, pas le Coffre.
- La mesure de coût est faite sur un fichier déjà en cache mémoire : c'est le pire cas
  pour le chiffrement en valeur relative. Avec une lecture disque ou réseau, la part du
  déchiffrement est encore plus faible.
