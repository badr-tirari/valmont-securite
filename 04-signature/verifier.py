"""Côté partenaire : vérifie l'empreinte SHA-256 et la signature Ed25519 de chaque compte rendu reçu.

Deux contrôles indépendants par document :
    1. intégrité  : SHA-256 recalculé == empreinte annoncée (.sha256) — comparaison à temps constant ;
    2. origine    : signature (.sig) valide avec la clé PUBLIQUE du biologiste.
Le contrôle 1 seul ne suffit pas : un attaquant qui modifie le document peut aussi recalculer
l'empreinte. Seul le contrôle 2 lie le document à la clé privée du signataire.

Usage :
    python verifier.py <dossier_comptes_rendus> <biologiste_public.pem>
Code retour 0 si tous les documents sont valides, 1 sinon.
"""

import hashlib
import hmac
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def verifier_document(chemin: Path, cle_publique) -> tuple[bool, bool]:
    doc = chemin.read_bytes()
    try:
        annoncee = chemin.with_name(chemin.name + ".sha256").read_text(encoding="ascii").split()[0]
        signature = chemin.with_name(chemin.name + ".sig").read_bytes()
    except (FileNotFoundError, IndexError):
        return False, False
    integre = hmac.compare_digest(hashlib.sha256(doc).hexdigest(), annoncee.lower())
    try:
        cle_publique.verify(signature, doc)
        authentique = True
    except InvalidSignature:
        authentique = False
    return integre, authentique


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    dossier, chemin_public = Path(sys.argv[1]), sys.argv[2]
    cle_publique = serialization.load_pem_public_key(Path(chemin_public).read_bytes())
    if not isinstance(cle_publique, ed25519.Ed25519PublicKey):
        sys.exit("Erreur : clé publique Ed25519 attendue.")

    documents = sorted(dossier.glob("CR-*.txt"))
    if not documents:
        sys.exit(f"Aucun compte rendu dans {dossier}/")
    valides = 0
    for chemin in documents:
        integre, authentique = verifier_document(chemin, cle_publique)
        ok = integre and authentique
        valides += ok
        print(f"  [{'OK' if ok else 'REJETÉ'}] {chemin.name:<20} "
              f"empreinte {'conforme' if integre else 'NON CONFORME':<13} "
              f"signature {'valide' if authentique else 'INVALIDE'}")
    print(f"{valides}/{len(documents)} compte(s) rendu(s) accepté(s)")
    sys.exit(0 if valides == len(documents) else 1)


if __name__ == "__main__":
    main()
