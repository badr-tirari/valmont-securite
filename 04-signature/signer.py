"""Hache et signe chaque compte rendu sortant avec la clé privée du médecin biologiste (Ed25519).

Pour chaque ligne de l'export nocturne, on produit dans le dossier de sortie :
    CR-2026-xxxx.txt         le compte rendu, sous forme canonique (UTF-8, champs dans un ordre fixe, fins de ligne LF)
    CR-2026-xxxx.txt.sha256  son empreinte SHA-256, au format « sha256sum » (vérifiable sans clé)
    CR-2026-xxxx.txt.sig     la signature Ed25519 du document (64 octets bruts, vérifiable avec openssl)

La forme canonique est essentielle : la signature porte sur des OCTETS ; le même contenu
réécrit avec d'autres fins de ligne ou un autre ordre de champs ne serait plus vérifiable.

Commandes :
    python signer.py generer-cle <dossier>
        crée biologiste_prive.pem (chiffrée par VALMONT_PASSPHRASE_BIOLOGISTE) et biologiste_public.pem
    python signer.py signer <export.csv> <biologiste_prive.pem> <dossier_sortie>
"""

import csv
import hashlib
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

CHAMPS = ["compte_rendu", "nir", "nom", "prenom", "analyse", "valeur", "unite", "rendu_le", "biologiste"]


def phrase_de_passe() -> bytes:
    valeur = os.environ.get("VALMONT_PASSPHRASE_BIOLOGISTE")
    if not valeur:
        sys.exit("Erreur : la variable d'environnement VALMONT_PASSPHRASE_BIOLOGISTE n'est pas définie.")
    return valeur.encode()


def document_canonique(ligne: dict) -> bytes:
    """Forme canonique d'un compte rendu : une ligne « champ: valeur » par champ, ordre fixe, LF, UTF-8."""
    lignes = ["LABORATOIRE VALMONT — COMPTE RENDU D'ANALYSE VALIDÉ"]
    lignes += [f"{champ}: {ligne[champ].strip()}" for champ in CHAMPS]
    return ("\n".join(lignes) + "\n").encode("utf-8")


def cmd_generer_cle(dossier: str) -> None:
    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    cle = ed25519.Ed25519PrivateKey.generate()
    (sortie / "biologiste_prive.pem").write_bytes(cle.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(phrase_de_passe()),
    ))
    publique = cle.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (sortie / "biologiste_public.pem").write_bytes(publique)
    print(f"Paire Ed25519 du Dr A. Kessler créée dans {sortie}/")
    print("  biologiste_prive.pem  → reste chez le biologiste (chiffrée par sa phrase de passe)")
    print("  biologiste_public.pem → diffusée au partenaire pour vérifier")


def cmd_signer(export: str, chemin_prive: str, dossier: str) -> None:
    try:
        cle = serialization.load_pem_private_key(Path(chemin_prive).read_bytes(), password=phrase_de_passe())
    except (ValueError, TypeError):
        sys.exit("Échec : clé privée illisible (phrase de passe incorrecte ?).")
    if not isinstance(cle, ed25519.Ed25519PrivateKey):
        sys.exit("Erreur : clé privée Ed25519 attendue.")

    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    with open(export, encoding="utf-8", newline="") as f:
        lignes = list(csv.DictReader(f))

    for ligne in lignes:
        nom = f"{ligne['compte_rendu'].strip()}.txt"
        doc = document_canonique(ligne)
        empreinte = hashlib.sha256(doc).hexdigest()
        signature = cle.sign(doc)                      # Ed25519 : 64 octets, déterministe
        (sortie / nom).write_bytes(doc)
        (sortie / f"{nom}.sha256").write_text(f"{empreinte}  {nom}\n", encoding="ascii", newline="\n")
        (sortie / f"{nom}.sig").write_bytes(signature)
        print(f"  {nom}  SHA-256 {empreinte[:16]}…  signature {signature.hex()[:16]}…")
    print(f"{len(lignes)} compte(s) rendu(s) haché(s) et signé(s) dans {sortie}/")


def main() -> None:
    a = sys.argv[1:]
    if len(a) == 2 and a[0] == "generer-cle":
        cmd_generer_cle(a[1])
    elif len(a) == 4 and a[0] == "signer":
        cmd_signer(*a[1:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
