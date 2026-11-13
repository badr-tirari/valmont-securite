# Étape 1 — Recenser les besoins et choisir les primitives

*Chapitres 01 et 05 — Laboratoire Valmont*

## Méthode

Pour chaque élément du système, on part de **ce qu'on veut garantir** (cacher, vérifier,
prouver), puis on remonte à la primitive. Le critère qui départage symétrique et
asymétrique n'est pas « le plus sûr » mais **la manière dont la clé circule** : clé
partagée possible → symétrique ; parties distantes sans secret commun → asymétrique
(en pratique : hybride).

Rappel : la **disponibilité** n'est pas un service de la cryptographie. Elle est traitée
par l'architecture (sauvegardes, redondance), pas par une primitive.

## Tableau des besoins

| # | Élément à protéger | Menace principale | Garanties recherchées | Primitive(s) retenue(s) | Mise en œuvre (étape) |
| --- | --- | --- | --- | --- | --- |
| 1 | **Portail patient** (Nginx) — trafic navigateur ↔ serveur, comptes patients | Interception (Wi-Fi public), faux site, vol de la table des comptes | Confidentialité, intégrité, authentification du serveur ; vérification des mots de passe | **Asymétrique + signature** (poignée de main TLS, certificat) puis **symétrique AEAD** (données) ; **hachage salé lent** (PBKDF2) pour les mots de passe | TLS 1.2/1.3 (6), PBKDF2-HMAC-SHA-256 (4) |
| 2 | **Base `patients`** (MySQL) — identité, NIR, résultats | Dump SQL, accès d'un compte applicatif compromis, disque volé | Confidentialité (NIR, données de santé), intégrité des valeurs stockées | **Symétrique** AES-256-GCM au niveau colonne ; **HMAC** pour l'index aveugle du NIR | Migration de colonne (2) |
| 3 | **Sauvegardes** quotidiennes → MinIO | Accès au bucket, copie hors site, altération d'une sauvegarde | Confidentialité, intégrité (restaurer exactement ce qui a été sauvegardé) | **Symétrique AEAD** (AES-GCM : le tag couvre aussi l'intégrité) ; **hachage** SHA-256 pour contrôler la copie | Chiffrement de fichier (2) |
| 4 | **Export nocturne** CSV → centre hospitalier | Interception en transit, lecture sur le serveur du partenaire avant traitement | Confidentialité de bout en bout, intégrité | **Hybride** : clé de session **symétrique** (AES-GCM) pour les données, chiffrée par la clé **publique** du partenaire (RSA-OAEP) | Chiffrement de fichier (2) + échange de clé (3) |
| 5 | **Comptes rendus** validés par le biologiste | Document modifié, biologiste qui conteste avoir validé | Intégrité, authentification de l'auteur, **non-répudiation** | **Hachage** SHA-256 + **signature numérique** (Ed25519) | Signature / vérification (4) |
| 6 | **Secrets de l'équipe** (clés AES, mots de passe BDD, jetons CI, clé privée TLS) | Secret commité dans Git, journal CI, poste de dev compromis | Confidentialité des secrets, traçabilité, révocation possible | **Symétrique** (chiffrement du coffre de secrets, au repos) ; surtout **gestion de clés** : coffre, variables d'environnement, rotation | Carte des clés (5), incident (8) |

## Justification des combinaisons de primitives

- **Portail (1)** — Le navigateur et le serveur ne partagent aucun secret au départ :
  l'**asymétrique** (échange ECDHE, signature du certificat) établit une clé, puis le
  **symétrique** AEAD chiffre le trafic, car il est des centaines de fois plus rapide.
  Les mots de passe relèvent d'un besoin à part : on doit les **reconnaître**, pas les
  relire, d'où un **hachage salé et lent** et non un chiffrement.
- **Base (2)** — Le chiffrement GCM est **probabiliste** (nonce aléatoire) : deux NIR
  identiques donnent deux chiffrés différents, on ne peut donc plus faire
  `WHERE nir = ?`. On ajoute un **HMAC à clé** du NIR (index aveugle) pour la recherche
  exacte ; un simple SHA-256 serait cassable par énumération (le NIR n'a que 15
  chiffres et une structure connue).
- **Sauvegardes (3)** — L'AEAD apporte déjà confidentialité **et** intégrité (le tag GCM
  échoue au moindre octet modifié). L'empreinte SHA-256 en plus sert à un contrôle
  **opérationnel** : vérifier qu'une copie MinIO est complète sans avoir à la déchiffrer.
- **Export partenaire (4)** — Le symétrique seul échoue car il faudrait livrer la clé
  au partenaire distant ; l'asymétrique seul est trop lent et limité en taille de
  message. L'**hybride** combine les deux : l'asymétrique transporte la clé, le
  symétrique transporte les données.
- **Comptes rendus (5)** — Le hachage seul ne prouve rien (n'importe qui peut
  recalculer une empreinte après modification) ; c'est la **signature de l'empreinte**
  par la clé privée du biologiste qui lie le document à son auteur. Un HMAC ne
  suffirait pas : la clé étant partagée, le partenaire pourrait lui aussi le produire,
  et le biologiste pourrait nier — pas de non-répudiation.
- **Secrets (6)** — Ici, la primitive est secondaire : le coffre chiffre ses données,
  mais le vrai risque est **organisationnel** (secret dans le code, jamais tourné).
  La réponse est la gestion du cycle de vie : inventaire, emplacement, propriétaire,
  rotation.

## Ce que chaque primitive ne fait pas

| Primitive | Ne garantit pas |
| --- | --- |
| Chiffrement (symétrique ou hybride) | Qui a écrit le message (sauf AEAD : intégrité, mais pas l'identité au sens de la non-répudiation) |
| Hachage | Rien n'est caché : l'empreinte d'une donnée devinable se retrouve par force brute |
| HMAC | La non-répudiation : les deux détenteurs de la clé peuvent produire le même code |
| Signature | La confidentialité, ni la **véracité** du contenu (un résultat faux bien signé reste faux) |

## Primitives et paramètres écartés (rappel chapitre 05)

| Écarté | Raison | Retenu à la place |
| --- | --- | --- |
| AES en mode **ECB** | Blocs identiques → chiffrés identiques, motifs visibles | AES-**GCM** (AEAD) |
| AES-CBC sans MAC | Pas d'intégrité, attaques par oracle de remplissage | AES-GCM |
| **MD5**, **SHA-1** | Collisions pratiques | SHA-256 |
| SHA-256 simple pour les mots de passe | Trop rapide, pas de sel → tables arc-en-ciel | PBKDF2-HMAC-SHA-256, 100 000 itérations, sel unique de 16 octets (format imposé par l'existant ; Argon2id serait préférable pour un nouveau système) |
| RSA PKCS#1 v1.5 (chiffrement) | Attaque de Bleichenbacher | RSA-**OAEP** (SHA-256), 3072 bits |
| `random` (Python) | Générateur prévisible | `secrets` / `os.urandom` (CSPRNG) |
| Nonce fixe ou compteur réinitialisé | Réutilisation de nonce GCM = fuite du flux de clé et de la clé d'authentification | Nonce aléatoire de 12 octets par message, préfixé au chiffré |
| TLS 1.0 / 1.1, suites CBC | Obsolètes, attaques connues (BEAST, POODLE, Lucky13) | TLS 1.2 et 1.3, suites AEAD uniquement |
