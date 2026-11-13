"""Chargement des clés depuis l'environnement — module commun aux scripts de l'étape 2.

Aucune clé n'est écrite dans le code ni dans la base : chaque clé est une variable
d'environnement contenant 32 octets encodés en base64 (voir generer_cle.py).

Variables utilisées :
    VALMONT_CLE_EXPORT     clé AES-256-GCM du fichier d'export nocturne
    VALMONT_CLE_NIR        clé AES-256-GCM de la colonne NIR
    VALMONT_CLE_INDEX_NIR  clé HMAC-SHA-256 de l'index aveugle du NIR (distincte de la précédente)
"""

import base64
import binascii
import os
import sys

TAILLE_CLE = 32  # AES-256 / HMAC-SHA-256


def charger_cle(nom_variable: str) -> bytes:
    """Lit une clé de 32 octets dans l'environnement ; refuse de continuer sans elle."""
    valeur = os.environ.get(nom_variable)
    if not valeur:
        sys.exit(f"Erreur : la variable d'environnement {nom_variable} n'est pas définie.")
    try:
        cle = base64.b64decode(valeur, validate=True)
    except (binascii.Error, ValueError):
        sys.exit(f"Erreur : {nom_variable} n'est pas du base64 valide.")
    if len(cle) != TAILLE_CLE:
        # On ne révèle jamais la valeur, seulement sa taille.
        sys.exit(f"Erreur : {nom_variable} doit contenir {TAILLE_CLE} octets (reçu : {len(cle)}).")
    return cle
