# Étape 4 — Hacher et signer les comptes rendus

*Chapitre 04 — intégrité, origine et non-répudiation des comptes rendus ; mots de passe du portail.*

## Partie 1 — Comptes rendus signés par le biologiste

Chaque compte rendu sortant devient un document canonique, accompagné de :

| Fichier | Contenu | Ce qu'il prouve | Vérifiable avec |
| --- | --- | --- | --- |
| `CR-2026-xxxx.txt` | Le compte rendu (UTF-8, champs dans un ordre fixe, fins de ligne LF) | — | — |
| `CR-2026-xxxx.txt.sha256` | Empreinte SHA-256, format `sha256sum` | **Intégrité** : le document n'a pas changé depuis le calcul | `sha256sum -c`, `Get-FileHash` |
| `CR-2026-xxxx.txt.sig` | Signature Ed25519 (64 octets) | **Origine et non-répudiation** : seule la clé privée du Dr Kessler a pu la produire | `verifier.py`, `openssl pkeyutl -verify` |

**Pourquoi l'empreinte seule ne suffit pas :** un attaquant qui modifie le document peut
recalculer l'empreinte et la remplacer (scénario C de la preuve). La signature, elle, ne
peut être refaite qu'avec la clé privée du biologiste.

**Pourquoi pas un HMAC :** la clé serait partagée avec le partenaire, qui pourrait
fabriquer un compte rendu « signé », et le biologiste pourrait nier. Avec une signature
asymétrique, le partenaire vérifie sans pouvoir signer.

### Choix techniques

| Point | Choix | Pourquoi |
| --- | --- | --- |
| Algorithme | **Ed25519** | Signature moderne, rapide, 64 octets, déterministe (pas d'aléa qui pourrait fuiter la clé, contrairement à un ECDSA mal implémenté) ; aucun paramètre à mal régler |
| Empreinte publiée | SHA-256 | Contrôle d'intégrité vérifiable sans clé, avec des outils standards |
| Forme canonique | Ordre de champs fixe, LF, UTF-8 | La signature porte sur des **octets** : le même texte en CRLF n'est plus vérifiable (scénario F) |
| Clé privée | PKCS#8 chiffrée, phrase de passe dans `VALMONT_PASSPHRASE_BIOLOGISTE`, **non livrée** | En production : carte CPS ou HSM, la clé ne sort jamais du support |
| Comparaison d'empreintes | `hmac.compare_digest` | Temps constant (chapitre 05) |

### Preuve qu'un document modifié ne passe pas — `test_signature.py`

| Scénario | Empreinte | Signature | Résultat |
| --- | --- | --- | --- |
| A. Document intact | conforme | valide | **accepté** |
| B. Glycémie falsifiée 1.08 → 0.98 | non conforme | invalide | rejeté |
| C. Falsifié + empreinte recalculée par l'attaquant | conforme | invalide | rejeté |
| D. Signature d'un autre compte rendu recopiée | conforme | invalide | rejeté |
| E. Re-signé avec la clé d'un imposteur | conforme | invalide | rejeté |
| F. Même texte converti en CRLF | non conforme | invalide | rejeté |

Sortie complète, avec la vérification croisée par openssl : `preuves/04-signature-et-mots-de-passe.txt`.

## Partie 2 — Mots de passe du portail

| Point | Choix |
| --- | --- |
| Fonction | PBKDF2-HMAC-SHA-256, 100 000 itérations : format imposé par la table `comptes_portail` existante |
| Sel | 16 octets d'un CSPRNG (`secrets`), unique par compte, stocké en hexadécimal |
| **Piège** | Le sel est stocké en hexadécimal mais c'est sa valeur **en octets** (`bytes.fromhex`) qui entre dans PBKDF2. Passer la chaîne telle quelle donne `a39ecb56…` au lieu de `452eacfe…` |
| Comparaison | `hmac.compare_digest`, à temps constant |
| Identifiant inconnu | Calcul sur une empreinte factice, pour une durée de réponse identique : on ne peut pas deviner quels identifiants existent en chronométrant |
| Message d'échec | Unique : « Identifiant ou mot de passe incorrect. » |
| Saisie | `getpass` : le mot de passe ne s'affiche pas et ne finit pas dans l'historique PowerShell |

Preuve (`py mots_de_passe.py preuve`) : `marchand.a` / `valmont-novembre` est **acceptée**.
Sont refusés : une majuscule de différence, un espace en trop, un mot de passe vide, le
même mot de passe sur un autre compte (autre sel) et un identifiant inexistant.

## Exécution (PowerShell, une commande à la fois)

Le conteneur MySQL de l'étape 2 doit tourner, avec `$env:VALMONT_DB_PASSWORD` défini.

```
cd "C:\Users\tirar\OneDrive\Documents\diginamic cours\La-cryptographie-support-de-cours\valmont-securite\04-signature"
```

```
$env:VALMONT_PASSPHRASE_BIOLOGISTE = [System.Net.NetworkCredential]::new("", (Read-Host "Phrase de passe du biologiste" -AsSecureString)).Password
```

```
py signer.py generer-cle cles
```

```
py signer.py signer ..\02-au-repos\donnees\export_2026-11-05.csv cles\biologiste_prive.pem comptes_rendus
```

```
py verifier.py comptes_rendus cles\biologiste_public.pem
```

```
py test_signature.py comptes_rendus cles\biologiste_public.pem
```

```
py mots_de_passe.py initialiser
```

```
py mots_de_passe.py preuve
```

Test manuel (saisir `valmont-novembre`, puis recommencer avec un autre mot de passe) :

```
py mots_de_passe.py connexion marchand.a
```

Vérifications avec des outils standards :

```
Get-FileHash comptes_rendus\CR-2026-1189.txt -Algorithm SHA256
```

```
& "C:\Program Files\Git\usr\bin\openssl.exe" pkeyutl -verify -pubin -inkey cles\biologiste_public.pem -rawin -in comptes_rendus\CR-2026-1189.txt -sigfile comptes_rendus\CR-2026-1189.txt.sig
```

> Les comptes rendus livrés ici ont été signés avec une clé de démonstration. Si tu
> régénères la paire avec `generer-cle`, re-signe avant de vérifier.

## Limites (à reprendre dans le rapport)

- **La clé publique du biologiste doit être authentique.** Sinon, un imposteur diffuse sa
  propre clé et signe à sa place. En pratique : certificat émis par une autorité
  (carte CPS de l'ANS pour les professionnels de santé, chapitre 08).
- **Pas d'horodatage qualifié.** La signature ne prouve pas *quand* le document a été
  signé. Si la clé est révoquée, on ne sait plus distinguer les signatures antérieures
  des postérieures. Un jeton d'horodatage (RFC 3161) réglerait ce point.
- **La signature ne garantit pas la vérité** : un résultat faux, une fois signé, reste
  faux. Elle garantit en revanche qu'il engage le Dr Kessler.
- **Le compte rendu contient le NIR en clair.** Il est protégé en transit par l'étape 3,
  mais le partenaire n'en a peut-être pas besoin (minimisation, étape 7).
- **100 000 itérations PBKDF2, c'est le minimum du cours, mais c'est sous la
  recommandation OWASP actuelle** (600 000 pour PBKDF2-HMAC-SHA-256). Pour aller plus
  loin, il faudrait ajouter une colonne d'algorithme et de paramètres, puis
  ré-hacher en **Argon2id** à la prochaine connexion réussie de chaque patient, sans
  réinitialisation forcée.
