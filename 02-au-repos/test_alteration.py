"""Preuve : chiffrement / déchiffrement de bout en bout, et refus de toute altération.

Scénarios testés sur l'export CSV :
    1. aller-retour : le fichier déchiffré est identique à l'original ;
    2. deux chiffrements du même fichier donnent deux résultats différents (nonce unique) ;
    3. un octet modifié — dans le nonce, au milieu du chiffré, dans le tag — est refusé ;
    4. un fichier tronqué est refusé ;
    5. une autre clé est refusée.

Usage :
    python test_alteration.py donnees/export_2026-11-05.csv
"""

import hashlib
import os
import sys

from chiffrer_fichier import chiffrer
from cles import charger_cle
from dechiffrer_fichier import DechiffrementRefuse, dechiffrer


def doit_refuser(libelle: str, contenu: bytes, cle: bytes) -> bool:
    try:
        dechiffrer(contenu, cle)
    except DechiffrementRefuse:
        print(f"  [OK] {libelle} : refusé")
        return True
    print(f"  [ÉCHEC] {libelle} : ACCEPTÉ — anomalie")
    return False


def main() -> None:
    chemin = sys.argv[1] if len(sys.argv) > 1 else "donnees/export_2026-11-05.csv"
    cle = charger_cle("VALMONT_CLE_EXPORT")
    with open(chemin, "rb") as f:
        clair = f.read()

    resultats = []
    chiffre = chiffrer(clair, cle)

    print("1. Aller-retour")
    ok = dechiffrer(chiffre, cle) == clair
    print(f"  [{'OK' if ok else 'ÉCHEC'}] SHA-256 original   = {hashlib.sha256(clair).hexdigest()}")
    print(f"        SHA-256 déchiffré  = {hashlib.sha256(dechiffrer(chiffre, cle)).hexdigest()}")
    resultats.append(ok)

    print("2. Nonce unique")
    autre = chiffrer(clair, cle)
    ok = autre[:12] != chiffre[:12] and autre != chiffre
    print(f"  [{'OK' if ok else 'ÉCHEC'}] nonce 1 = {chiffre[:12].hex()} / nonce 2 = {autre[:12].hex()}")
    resultats.append(ok)

    print("3. Altération d'un seul octet")
    for libelle, position in [
        ("octet 0 (nonce)", 0),
        (f"octet {len(chiffre) // 2} (milieu du chiffré)", len(chiffre) // 2),
        (f"octet {len(chiffre) - 1} (dernier octet du tag)", len(chiffre) - 1),
    ]:
        altere = bytearray(chiffre)
        altere[position] ^= 0x01  # un seul bit inversé
        resultats.append(doit_refuser(libelle, bytes(altere), cle))

    print("4. Troncature")
    resultats.append(doit_refuser("dernier octet supprimé", chiffre[:-1], cle))

    print("5. Mauvaise clé")
    resultats.append(doit_refuser("clé aléatoire différente", chiffre, os.urandom(32)))

    total = len(resultats)
    print(f"\nBilan : {sum(resultats)}/{total} contrôles réussis")
    sys.exit(0 if all(resultats) else 1)


if __name__ == "__main__":
    main()
