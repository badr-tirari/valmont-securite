"""Génère une clé de 32 octets avec un CSPRNG et l'affiche en base64.

Usage (PowerShell) :
    $env:VALMONT_CLE_EXPORT = python generer_cle.py

La clé n'est jamais écrite sur disque par ce script : c'est à vous de la ranger
dans un coffre de secrets (voir étape 5).
"""

import base64
import secrets

print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
