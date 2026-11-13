# Laboratoire Valmont — Sécuriser un système de bout en bout

*TP intégrateur « La cryptographie » — Badr-Eddine Tirari — 13 novembre 2026*

Chaque étape a été **exécutée**, pas seulement décrite : ses sorties réelles sont dans
le dossier `preuves/` de l'étape. Machines : Linux (MariaDB 10.11, nginx 1.24) et poste
de cours Windows 11 (Python 3.14, Docker : MySQL 8.4, nginx 1.27). Données fictives.

## 1. Sommaire du dossier

| Étape | Livrable | Démontré |
| --- | --- | --- |
| 1 Besoins | `01-besoins.md` | 6 éléments → garantie → primitive ; primitives écartées |
| 2 Au repos | `chiffrer_fichier.py`, `dechiffrer_fichier.py`, `migrer_colonne.py` | AES-256-GCM : 7/7 altérations refusées. NIR chiffré en une transaction + index aveugle HMAC ; 0 NIR lisible |
| 3 Échange de clé | `echanger_cle.py` | Hybride RSA-3072-OAEP + AES-GCM, une clé de session par export ; enveloppe relue par openssl |
| 4 Signature | `signer.py`, `verifier.py`, `mots_de_passe.py` | Ed25519 : 5/5 falsifications rejetées ; PBKDF2 : `marchand.a` accepté, 6 cas refusés |
| 5 Clés et secrets | carte (12 clés, 9 secrets), plan, 2 garde-fous | Détecteur : 6/6 fuites piégées bloquées, 0 alerte sur le dossier |
| 6 TLS | `portail-valmont.conf`, `certbot/`, `verifier_tls.sh` | 14/14 contrôles ; la mauvaise configuration du chapitre 07 échoue sur 9 |
| 7 Flux | `trajet-donnee.md`, `minimiser_pour_entrepot.py` | 0 identifiant direct sur 90 cherchés ; k-anonymat mesuré : **k = 1** |
| 8 Incident | `plan-incident.md`, `rotation.py`, `note-communication.md` | Rotation sans coupure, panne et reprise, **consommateur oublié détecté** |

## 2. Contrôle des erreurs classiques

Trois points relevés en relisant **notre** code ; les deux premiers étaient de vraies
erreurs, corrigées pendant le TP.

**① Message d'erreur trop bavard** : `02-au-repos/migrer_colonne.py:57`,
`04-signature/mots_de_passe.py:58`.

- *Constat :* base injoignable → trace PyMySQL complète, avec hôte, port et chemins internes.
- *Risque :* renseigne un attaquant ; la trace finit dans les journaux de CI.
- *Correction :* `except OperationalError` → message sobre, code 1, plus aucune trace. De
  même, `dechiffrer_fichier.py` ne dit pas si c'est la clé ou le fichier qui est faux.

**② Secret dans le dépôt** : `04-signature/preuves/05-execution-poste-badr.txt:5`.

- *Constat :* la phrase de passe du biologiste, tapée en clair, s'était retrouvée dans un
  journal de preuve. Les README faisaient taper `$env:…_PASSWORD = "…"`, que PowerShell
  garde dans son historique (fichier en clair, synchronisé par OneDrive).
- *Risque :* un secret dans une preuve est un secret dans le dépôt.
- *Correction :* valeur masquée ; saisie `Read-Host -AsSecureString` dans les README ;
  détection automatique (`scanner_secrets.py`, gitleaks en crochet et en CI).

**③ Unicité du nonce GCM** : `chiffrer_fichier.py:25`, `migrer_colonne.py:75`,
`trousseau.py:74` (`os.urandom(12)`).

- *Constat :* un nonce aléatoire de 96 bits sous **une même clé** risque la collision
  au-delà de ≈ 2³² chiffrements.
- *Risque :* une seule collision révèle le XOR des deux clairs et la clé d'authentification GCM.
- *Correction :* rotation **annuelle** de K1 et K3, inscrite dans la carte des clés et
  outillée par l'étape 8 (en-tête versionné) ; au-delà, AES-GCM-SIV ou XChaCha20-Poly1305.

**Conforme par ailleurs :**

- ni ECB, ni CBC sans MAC, ni MD5 ou SHA-1 ;
- comparaisons à temps constant (`hmac.compare_digest`) ;
- identifiant inconnu traité sur une empreinte factice, pour qu'on ne puisse pas
  énumérer les comptes au chronomètre ;
- aléa uniquement par `secrets` et `os.urandom` ;
- aucune clé en dur : les scripts refusent de démarrer si une variable manque.

**Deux contre-épreuves** ont aussi corrigé ma propre logique :

- le vérificateur TLS classait AES-CCM parmi les suites non AEAD ;
- la preuve de complétude comptait des usages de la clé antérieurs à la fuite.

Un contrôle qui ne peut pas échouer ne prouve rien.

## 3. Compromis assumés

| Choix | Concession | Pourquoi c'est acceptable |
| --- | --- | --- |
| Index aveugle HMAC (NIR) | Les égalités entre fiches se voient | Le NIR est unique par patient ; clé d'index ≠ clé de chiffrement |
| PBKDF2, 100 000 itérations | Sous la recommandation OWASP (600 000) | Format imposé par l'existant ; ré-hachage en Argon2id à la prochaine connexion |
| RSA-OAEP vers le CHU | Pas de confidentialité persistante | Clé de session par export, rotation annuelle ; un ECDH éphémère est impossible en dépôt nocturne |
| Clés en variables d'environnement | Lisibles par les processus voisins | Cible : le Coffre, sans changement de code |
| Certificat de labo, sans OCSP | Pas de preuve de confiance publique | Let's Encrypt a arrêté OCSP en août 2025 |
| Entrepôt pseudonymisé | **Ce n'est pas de l'anonymat** (k = 1) | RGPD pleinement appliqué ; seuls les agrégats ≥ 5 sortent |
| Sauvegardes verrouillées en K3-v1 | Ni ré-chiffrables ni destructibles avant l'échéance | Double chiffrement K3 + K10 ; risque documenté |
| Performance | ≈ 1 µs par NIR, quelques µs par export | Négligeable devant un aller-retour réseau ; seul le hachage des mots de passe est lent, et **lent exprès** |

**Non prouvé par les simulations :**

- le Coffre, MinIO, l'entrepôt et la CI sont configurés mais pas déployés ;
- le renouvellement Let's Encrypt réel demande un domaine public ;
- les durées de conservation légales sont à confirmer avec le DPO.
