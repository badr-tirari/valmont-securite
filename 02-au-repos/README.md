# Étape 2 — Chiffrer les données au repos

*Chapitres 02 et 09.*

## Contenu

| Fichier | Rôle |
| --- | --- |
| `cles.py` | Module commun : lit une clé de 32 octets (base64) dans une variable d'environnement, refuse de démarrer sans elle |
| `generer_cle.py` | Tire une clé de 32 octets avec un CSPRNG (`secrets`) et l'affiche en base64 |
| `chiffrer_fichier.py` | Chiffre un fichier en AES-256-GCM : `nonce (12) ‖ chiffré ‖ tag (16)` |
| `dechiffrer_fichier.py` | Vérifie le tag **avant** d'écrire : un fichier altéré n'est jamais produit |
| `test_alteration.py` | Preuve automatisée : aller-retour, nonce unique, 1 octet altéré (nonce / chiffré / tag), troncature, mauvaise clé |
| `migrer_colonne.py` | Migration du NIR : `migrer`, `verifier`, `chercher <NIR>` |
| `docker-compose.yml` | Conteneur MySQL 8.4 chargé avec l'échantillon `sql/01-patients.sql` |
| `donnees/export_2026-11-05.csv` | Export nocturne fourni par le sujet |
| `donnees/export_2026-11-05.csv.chiffre` | Le même, chiffré (exemple de format : la clé de la démonstration n'a pas été conservée) |
| `preuves/` | Sorties d'exécution réelles des deux parties |

## Choix techniques

| Point | Choix | Pourquoi |
| --- | --- | --- |
| Algorithme | AES-256-GCM (`cryptography`, `AESGCM`) | AEAD : confidentialité **et** intégrité en une opération |
| Clé | 32 octets, `secrets.token_bytes` | CSPRNG, jamais `random` |
| Nonce | 12 octets `os.urandom` à chaque chiffrement, préfixé | Unicité du nonce : la réutiliser avec la même clé casse GCM |
| AAD fichier | `valmont/export-nocturne/v1` | Un chiffré produit pour un autre usage est refusé |
| AAD colonne | `valmont/patients.nir/<id>` | Le NIR chiffré est **lié à sa ligne** : recopié sur une autre fiche, il est refusé (prouvé dans `preuves/02`) |
| Recherche | Index aveugle `HMAC-SHA-256(clé d'index, NIR)` | Le chiffré GCM est probabiliste, `WHERE nir = ?` est impossible ; un SHA-256 simple serait cassé par énumération des NIR |
| Clés | 3 variables distinctes : `VALMONT_CLE_EXPORT`, `VALMONT_CLE_NIR`, `VALMONT_CLE_INDEX_NIR` | Une clé = un usage ; la fuite de la clé d'index ne permet pas de déchiffrer |
| Migration | Ajout des colonnes → chiffrement dans **une transaction** → relecture de contrôle → suppression du clair | Tout ou rien : en cas d'erreur, rollback et le clair est conservé |
| Suppression | `DROP COLUMN … ALGORITHM=COPY` | Par défaut, MySQL 8.0.29+ fait un DROP « instantané » qui laisse les anciennes valeurs dans les pages du fichier `.ibd` |
| Erreurs | Message sobre, sans distinguer clé fausse et fichier altéré | Ne pas renseigner un attaquant (chapitre 05) |

## Exécution (PowerShell, une commande à la fois)

Se placer dans le dossier :

```
cd "C:\Users\tirar\OneDrive\Documents\diginamic cours\La-cryptographie-support-de-cours\valmont-securite\02-au-repos"
```

Installer les dépendances :

```
pip install -r requirements.txt
```

Choisir le mot de passe root de la base de test :

```
$env:VALMONT_DB_PASSWORD = [System.Net.NetworkCredential]::new("", (Read-Host "Mot de passe root de la base de test" -AsSecureString)).Password
```

Démarrer MySQL (Docker Desktop doit être lancé) :

```
docker compose up -d --wait
```

Générer les trois clés :

```
$env:VALMONT_CLE_EXPORT = python generer_cle.py
```

```
$env:VALMONT_CLE_NIR = python generer_cle.py
```

```
$env:VALMONT_CLE_INDEX_NIR = python generer_cle.py
```

### Partie 1 — Fichier

```
py chiffrer_fichier.py donnees\export_2026-11-05.csv donnees\export_2026-11-05.csv.chiffre
```

```
py dechiffrer_fichier.py donnees\export_2026-11-05.csv.chiffre donnees\export_dechiffre.csv
```

```
py test_alteration.py donnees\export_2026-11-05.csv
```

Résultat attendu : `Bilan : 7/7 contrôles réussis`.

### Partie 2 — Colonne

Voir le NIR en clair avant migration :

```
docker exec valmont-mysql mysql -uroot -p"$env:VALMONT_DB_PASSWORD" valmont -e "SELECT id, nom, nir FROM patients LIMIT 3"
```

```
py migrer_colonne.py migrer
```

```
py migrer_colonne.py verifier
```

```
py migrer_colonne.py chercher 285075921504281
```

Voir ce que montre la base après migration :

```
docker exec valmont-mysql mysql -uroot -p"$env:VALMONT_DB_PASSWORD" valmont -e "SELECT id, nom, HEX(nir_chiffre) FROM patients LIMIT 3"
```

Pour tout recommencer depuis l'état de départ :

```
docker compose down -v
```

> Les clés générées vivent dans la session PowerShell : si tu la fermes après la
> migration, les NIR ne sont plus déchiffrables. C'est voulu pour le TP ; en
> production, elles sont rangées dans un coffre de secrets (étape 5).

## Ce que cette étape ne couvre pas (à reprendre dans le rapport)

- **Traces antérieures** : le NIR en clair subsiste dans tout ce qui a été produit
  avant la migration — journaux binaires (binlog), sauvegardes MinIO déjà copiées,
  dumps de développement. Il faut les purger ou les rechiffrer, sinon la migration ne
  protège que l'avenir.
- **L'index aveugle révèle les égalités** : deux fiches au même NIR ont le même
  `nir_index`. Compromis assumé, documenté au chapitre 09.
- **Les clés en variables d'environnement** sont lisibles par tout processus du même
  utilisateur et peuvent apparaître dans un vidage mémoire ou un journal de CI. C'est
  le minimum demandé ; le coffre de secrets est traité à l'étape 5.
- **Les autres colonnes** (nom, adresse, résultats d'analyse) restent en clair : elles
  relèvent du chiffrement de disque / de tablespace et de la minimisation (étape 7).
- **Environnement de démonstration** : conteneur MySQL local avec un mot de passe root,
  pas de TLS entre le script et la base ; les preuves jointes ont été produites sur
  MariaDB 10.11 (même syntaxe, `ALGORITHM=COPY` compris).
