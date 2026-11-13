"""Preuve qu'un compte rendu modifié ne passe pas la vérification (copie de travail, originaux intacts).

Scénarios sur une copie du dossier signé :
    A. document intact                                   → accepté
    B. résultat falsifié (glycémie 1.08 → 0.98)          → empreinte ET signature refusées
    C. falsifié + empreinte recalculée par l'attaquant   → empreinte conforme, signature refusée
    D. signature d'un autre document recopiée            → refusée
    E. document re-signé avec la clé d'un imposteur      → refusé (clé publique du biologiste)
    F. une fin de ligne LF changée en CRLF (Windows)     → refusée : on signe des octets

Usage :
    python test_signature.py <dossier_comptes_rendus> <biologiste_public.pem>
"""

import hashlib
import shutil
import sys
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from verifier import verifier_document

CIBLE = "CR-2026-1189.txt"  # Alicie Marchand, glycémie à jeun


def etat(integre: bool, authentique: bool) -> str:
    return f"empreinte {'conforme' if integre else 'NON CONFORME'}, signature {'valide' if authentique else 'INVALIDE'}"


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    source, chemin_public = Path(sys.argv[1]), sys.argv[2]
    cle_publique = serialization.load_pem_public_key(Path(chemin_public).read_bytes())
    resultats = []

    with tempfile.TemporaryDirectory() as tmp:
        travail = Path(tmp) / "cr"
        shutil.copytree(source, travail)
        doc = travail / CIBLE
        sha = doc.with_name(CIBLE + ".sha256")
        sig = doc.with_name(CIBLE + ".sig")
        original = doc.read_bytes()

        def controle(libelle, attendu_accepte):
            i, a = verifier_document(doc, cle_publique)
            accepte = i and a
            ok = accepte == attendu_accepte
            print(f"  [{'OK' if ok else 'ÉCHEC'}] {libelle} → {'ACCEPTÉ' if accepte else 'REJETÉ'} ({etat(i, a)})")
            resultats.append(ok)

        print(f"Document testé : {CIBLE}")
        print("A. Document intact")
        controle("original", True)

        print("B. Résultat falsifié")
        falsifie = original.replace(b"valeur: 1.08", b"valeur: 0.98")
        assert falsifie != original
        doc.write_bytes(falsifie)
        controle("glycémie 1.08 → 0.98", False)

        print("C. Falsifié + empreinte recalculée par l'attaquant")
        sha.write_text(f"{hashlib.sha256(falsifie).hexdigest()}  {CIBLE}\n", encoding="ascii")
        controle("empreinte mise à jour, signature d'origine", False)

        print("D. Signature d'un autre compte rendu recopiée")
        doc.write_bytes(original)
        sha.write_text(f"{hashlib.sha256(original).hexdigest()}  {CIBLE}\n", encoding="ascii")
        sig.write_bytes((travail / "CR-2026-1187.txt.sig").read_bytes())
        controle("signature de CR-2026-1187 sur CR-2026-1189", False)

        print("E. Re-signé par un imposteur")
        imposteur = ed25519.Ed25519PrivateKey.generate()
        doc.write_bytes(falsifie)
        sha.write_text(f"{hashlib.sha256(falsifie).hexdigest()}  {CIBLE}\n", encoding="ascii")
        sig.write_bytes(imposteur.sign(falsifie))
        controle("document falsifié signé avec une autre clé privée", False)

        print("F. Fins de ligne converties en CRLF")
        crlf = original.replace(b"\n", b"\r\n")
        doc.write_bytes(crlf)
        sha.write_text(f"{hashlib.sha256(original).hexdigest()}  {CIBLE}\n", encoding="ascii")
        sig.write_bytes((source / (CIBLE + ".sig")).read_bytes())
        controle("même texte, octets différents", False)

    print(f"\nBilan : {sum(resultats)}/{len(resultats)} contrôles réussis")
    sys.exit(0 if all(resultats) else 1)


if __name__ == "__main__":
    main()
