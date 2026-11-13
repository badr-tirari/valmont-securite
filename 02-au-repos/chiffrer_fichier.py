"""Chiffre un fichier avec AES-256-GCM.

Format du fichier produit :  nonce (12 octets) || chiffré || tag GCM (16 octets)
    - clé  : 32 octets, lue dans VALMONT_CLE_EXPORT (tirée par un CSPRNG, voir generer_cle.py) ;
    - nonce : 12 octets tirés par os.urandom à CHAQUE chiffrement, jamais réutilisé ;
    - données associées (AAD) : un libellé de format, authentifié mais non chiffré,
      pour qu'un chiffré produit pour un autre usage soit refusé.

Usage :
    python chiffrer_fichier.py donnees/export_2026-11-05.csv donnees/export_2026-11-05.csv.chiffre
"""

import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cles import charger_cle

TAILLE_NONCE = 12
AAD = b"valmont/export-nocturne/v1"


def chiffrer(donnees: bytes, cle: bytes) -> bytes:
    nonce = os.urandom(TAILLE_NONCE)  # CSPRNG, unique par message
    return nonce + AESGCM(cle).encrypt(nonce, donnees, AAD)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit("Usage : python chiffrer_fichier.py <fichier_clair> <fichier_chiffre>")
    source, cible = sys.argv[1], sys.argv[2]
    cle = charger_cle("VALMONT_CLE_EXPORT")

    with open(source, "rb") as f:
        clair = f.read()
    with open(cible, "wb") as f:
        f.write(chiffrer(clair, cle))

    print(f"Chiffré : {source} ({len(clair)} octets) -> {cible} ({len(clair) + TAILLE_NONCE + 16} octets)")


if __name__ == "__main__":
    main()
