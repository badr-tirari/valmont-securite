# Carte des clés et des secrets — Laboratoire Valmont

*Étape 5 — chapitres 06 et 10 (complétée à l'étape 7 : K12, S9). Une ligne = une clé ou un secret. Un secret sans propriétaire ni emplacement est un secret qu'on ne saura ni tourner ni révoquer.*

## Rôles

| Rôle | Qui | Responsabilité |
| --- | --- | --- |
| **ADM** | Administrateur système | Coffre de secrets, serveurs, MySQL, MinIO, Nginx, certificats |
| **DEV-L** | Développeur référent | Clés applicatives, chaîne d'intégration continue, scripts |
| **DEV** | Second développeur | Suppléant du DEV-L (principe des quatre yeux sur chaque rotation) |
| **BIO** | Dr A. Kessler, biologiste responsable | Sa clé de signature : il est le seul à l'utiliser |
| **DIR** | Direction du laboratoire / DPO | Valide les rotations exceptionnelles, déclare les incidents à la CNIL |
| **CHU** | RSSI du centre hospitalier partenaire | Clé privée du partenaire (hors du périmètre Valmont) |

Le coffre de secrets est noté **Coffre** : une instance HashiCorp Vault (ou équivalent),
hébergée chez Valmont, avec un journal d'audit activé. Ses chemins sont notés `kv/valmont/<env>/…`.

## 1. Clés cryptographiques

| # | Clé | Usage | Algorithme | Propriétaire | Emplacement | Qui y accède | Rotation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| K1 | `VALMONT_CLE_NIR` | Chiffrement de la colonne `patients.nir_chiffre` | AES-256-GCM | DEV-L | Coffre `kv/valmont/prod/cle-nir`, injectée en variable d'environnement au démarrage | Application, migration | **Annuelle** + sur suspicion ; période à deux clés (étape 8) |
| K2 | `VALMONT_CLE_INDEX_NIR` | Index aveugle `patients.nir_index` | HMAC-SHA-256 | DEV-L | Coffre `kv/valmont/prod/cle-index-nir` | Application | **Sur incident uniquement** : la changer impose de recalculer tout l'index |
| K3 | `VALMONT_CLE_EXPORT` | Export nocturne conservé au repos chez Valmont | AES-256-GCM | DEV-L | Coffre `kv/valmont/prod/cle-export` | Traitement de nuit | **Trimestrielle** + sur suspicion |
| K4 | Clé de session de l'export | Chiffrement de l'export envoyé au CHU | AES-256-GCM | — (éphémère) | Mémoire du traitement de nuit, **jamais écrite** | Traitement de nuit | **À chaque export** |
| K5 | Clé publique du partenaire | Envelopper K4 (RSA-OAEP) | RSA-3072 | CHU | Dépôt de configuration (non secrète) + empreinte confirmée par un appel au RSSI du CHU | Traitement de nuit | **Annuelle**, à l'initiative du CHU |
| K6 | Clé privée du partenaire | Ouvrir l'enveloppe | RSA-3072 | CHU | Chez le CHU uniquement | CHU | Annuelle (côté CHU) |
| K7 | Clé de signature du biologiste | Signer les comptes rendus | Ed25519 | **BIO** | Carte CPS / jeton matériel du biologiste ; en démonstration : PEM PKCS#8 chiffré | BIO seul | **3 ans** (validité du certificat) ; **révocation immédiate** en cas de départ ou de perte |
| K8 | Clé publique du biologiste | Vérification par le CHU | Ed25519 | BIO | Publiée (certificat) | Tous | Avec K7 |
| K9 | Clé privée TLS du portail | Poignée de main HTTPS | ECDSA P-256 | ADM | Serveur Nginx, `/etc/letsencrypt/live/…`, droits `600 root` | Nginx | **Régénérée à chaque renouvellement**, soit tous les 60 jours (certificats de 90 jours) |
| K10 | Clé de chiffrement des sauvegardes | Chiffrement côté serveur des objets MinIO | AES-256-GCM, via MinIO KES | ADM | KMS (KES) adossé au Coffre | MinIO | **Annuelle** ; les anciennes versions restent lisibles le temps de la rétention |
| K11 | Clé SSH de déploiement | La chaîne d'intégration continue se connecte au serveur | Ed25519 | DEV-L | Secret protégé de la CI ; clé publique dans `authorized_keys` avec `restrict,command=` | Job de déploiement | **Annuelle** + départ d'un membre |
| K12 | `VALMONT_CLE_PSEUDO` | Jeton `pseudo_patient` de l'entrepôt (étape 7) | HMAC-SHA-256 | DEV-L, accès validé par DIR / DPO | Coffre `kv/valmont/prod/cle-pseudo`, **jamais dans l'entrepôt** | Job de minimisation uniquement | **Sur incident uniquement** : la changer coupe le suivi longitudinal ; recalcul complet de l'entrepôt |

## 2. Secrets d'accès (mots de passe, jetons, identifiants)

| # | Secret | Usage | Propriétaire | Emplacement | Qui y accède | Rotation |
| --- | --- | --- | --- | --- | --- | --- |
| S1 | Mot de passe `root` MySQL | Administration uniquement, **jamais par l'application** | ADM | Coffre, accès « bris de glace » journalisé | ADM | **Semestrielle** + après chaque usage |
| S2 | Compte MySQL applicatif `valmont_app` | Application du portail : `SELECT/INSERT/UPDATE` sur `valmont`, aucun DDL | DEV-L | **Secret dynamique** du Coffre (moteur *database*) : compte créé à la demande | Application | **Automatique, durée de vie de 24 h** |
| S3 | Compte MySQL `valmont_migration` | Migrations de schéma (étape 2) | DEV-L | Coffre, délivré au moment de la migration | DEV-L, DEV | Désactivé hors migration |
| S9 | Comptes `valmont_extract` (lecture seule, base) et `valmont_load` (écriture seule, entrepôt) | Chaîne data (étape 7) | ADM | Secrets dynamiques du Coffre | Job de minimisation | **Automatique, durée de vie de 1 h** (durée du job) |
| S4 | Clés d'accès MinIO `backup-writer` | Le job de sauvegarde écrit dans le bucket | ADM | Coffre `kv/valmont/prod/minio-backup` | Job de sauvegarde | **90 jours** ; droits en écriture seule, sans suppression (verrouillage d'objets) |
| S5 | Jeton de déploiement CI | Pousser l'image, déclencher le déploiement | DEV-L | **OIDC** : jeton fédéré émis pour chaque job, sans secret stocké | Job `deploy` sur `main` | **À chaque exécution** (validité de quelques minutes) |
| S6 | Phrases de passe des clés PEM (K7 en démonstration) | Déverrouiller la clé privée | BIO | Mémoire du titulaire ou gestionnaire de mots de passe personnel | BIO | Avec la clé |
| S7 | Compte Let's Encrypt (ACME) | Renouvellement automatique des certificats | ADM | Serveur Nginx, `/etc/letsencrypt/accounts` | certbot | Rarement : à la compromission du serveur |
| S8 | Sels PBKDF2 des comptes patients | Hachage des mots de passe (étape 4) | — | Base `comptes_portail.sel`, **non secrets** | Application | Nouveau sel à chaque changement de mot de passe |

## 3. Environnements

| Règle | Application |
| --- | --- |
| Une clé = un environnement | `kv/valmont/test/…` et `kv/valmont/prod/…` sont distincts. Une clé de test ne passe **jamais** en production : on en génère une neuve |
| Données de test | Fictives (comme l'échantillon du TP), jamais une copie de la production |
| Accès développeurs | Les développeurs lisent `test/`, pas `prod/` ; la production n'est lue que par les identités machine (application, CI) |
| Génération | Toujours par un CSPRNG (`secrets`, `os.urandom`, `openssl rand`), dans le Coffre ou sur le serveur cible, jamais sur un poste personnel |

## 4. Cycle de vie (résumé)

| Phase | Règle | Qui |
| --- | --- | --- |
| Création | CSPRNG, directement dans le Coffre ; aucune copie hors Coffre | DEV-L / ADM |
| Distribution | Injection au démarrage (variable d'environnement ou agent Vault) ; jamais par courriel, chat ou ticket | Automatique |
| Usage | Une clé = un usage (K1 ≠ K2 ≠ K3 ≠ K12) ; accès tracé dans le journal d'audit du Coffre | — |
| Rotation | Calendrier ci-dessus + **à chaque suspicion** ; période à deux clés, vérification avant retrait (étape 8) | DEV-L + DEV (quatre yeux) |
| Révocation | Immédiate sur suspicion : révoquer, remplacer, nettoyer, prévenir (chapitre 10) | ADM, DIR informée |
| Destruction | Suppression de la version dans le Coffre **après** ré-chiffrement complet et expiration des sauvegardes qui en dépendent ; trace dans le journal d'audit | ADM, validée par DIR |
