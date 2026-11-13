"""Déchiffre un fichier produit par chiffrer_fichier.py (AES-256-GCM).

Le tag GCM est vérifié AVANT d'écrire quoi que ce soit : un fichier altéré, tronqué
ou déchiffré avec la mauvaise clé est refusé, aucun fichier corrompu n'est produit.

Usage :
    python dechiffrer_fichier.py donnees/export_2026-11-05.csv.chiffre donnees/export_dechiffre.csv
"""

import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cles import charger_cle
from chiffrer_fichier import AAD, TAILLE_NONCE


class DechiffrementRefuse(Exception):
    """Levée quand le contenu n'est pas authentique (altéré, tronqué, mauvaise clé)."""


def dechiffrer(contenu: bytes, cle: bytes) -> bytes:
    if len(contenu) < TAILLE_NONCE + 16:
        raise DechiffrementRefuse()
    nonce, chiffre = contenu[:TAILLE_NONCE], contenu[TAILLE_NONCE:]
    try:
        return AESGCM(cle).decrypt(nonce, chiffre, AAD)
    except InvalidTag:
        raise DechiffrementRefuse() from None


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Usage : python dechiffrer_fichier.py <fichier_chiffre> <fichier_clair>")
    source, cible = sys.argv[1], sys.argv[2]
    cle = charger_cle("VALMONT_CLE_EXPORT")

    with open(source, "rb") as f:
        contenu = f.read()
    try:
        clair = dechiffrer(contenu, cle)
    except DechiffrementRefuse:
        # Message volontairement sobre : on ne dit pas si c'est la clé ou le fichier.
        sys.exit("Échec : déchiffrement refusé (fichier non authentique ou clé incorrecte). Aucun fichier écrit.")

    with open(cible, "wb") as f:
        f.write(clair)
    print(f"Déchiffré et authentifié : {source} -> {cible} ({len(clair)} octets)")


if __name__ == "__main__":
    main()
