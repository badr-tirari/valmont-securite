"""Trousseau de clés versionnées pour l'archive des exports nocturnes (clé K3) — étape 8.

Pourquoi un trousseau : pour tourner une clé sans interrompre le service, chaque fichier chiffré
doit dire QUELLE clé l'a produit, et l'ancienne clé doit rester disponible en LECTURE SEULE le temps
de la migration (période à deux clés).

Format v2 d'un fichier chiffré :
    "VLM2" (4) ‖ longueur de l'identifiant (1) ‖ identifiant de clé (ex. "k3-v2") ‖ nonce (12) ‖ chiffré ‖ tag (16)
    AAD = en-tête complet : l'identifiant de clé est authentifié, on ne peut pas le falsifier
    pour forcer l'usage d'une autre clé.
Les fichiers de l'étape 2 (sans en-tête) sont relus comme produits par la clé « k3-v1 ».

Configuration (variables d'environnement) :
    VALMONT_TROUSSEAU_K3   "k3-v1=<base64>;k3-v2=<base64>"   toutes les clés encore utiles
    VALMONT_K3_ACTIVE      "k3-v2"                            la SEULE clé autorisée à chiffrer
    VALMONT_K3_LECTURE     "k3-v1"                            clés autorisées à déchiffrer seulement
                                                              (la clé compromise est isolée ici)
Chaque usage d'une clé est consigné dans journal_cles.log (date, opération, clé, fichier) —
jamais la clé elle-même. C'est ce journal qui prouve, à la fin, que plus rien n'utilise l'ancienne.
"""

import base64
import binascii
import datetime
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"VLM2"
CLE_HISTORIQUE = "k3-v1"                      # fichiers de l'étape 2, sans en-tête
AAD_HISTORIQUE = b"valmont/export-nocturne/v1"
TAILLE_NONCE = 12
JOURNAL = Path(os.environ.get("VALMONT_JOURNAL_CLES", "journal_cles.log"))


class ErreurTrousseau(Exception):
    pass


class Trousseau:
    def __init__(self) -> None:
        brut = os.environ.get("VALMONT_TROUSSEAU_K3", "")
        self.cles: dict[str, bytes] = {}
        for element in filter(None, (e.strip() for e in brut.split(";"))):
            ident, _, valeur = element.partition("=")
            try:
                cle = base64.b64decode(valeur, validate=True)
            except (binascii.Error, ValueError):
                raise ErreurTrousseau(f"clé {ident} : base64 invalide") from None
            if len(cle) != 32:
                raise ErreurTrousseau(f"clé {ident} : 32 octets attendus")
            self.cles[ident.strip()] = cle
        self.active = os.environ.get("VALMONT_K3_ACTIVE", "").strip()
        self.lecture = {c.strip() for c in os.environ.get("VALMONT_K3_LECTURE", "").split(",") if c.strip()}
        if self.active not in self.cles:
            raise ErreurTrousseau("VALMONT_K3_ACTIVE ne désigne aucune clé du trousseau")
        if self.active in self.lecture:
            raise ErreurTrousseau("la clé active ne peut pas être en lecture seule")

    # ------------------------------------------------------------------ journal d'usage
    @staticmethod
    def journaliser(operation: str, ident: str, fichier: str) -> None:
        horodatage = datetime.datetime.now().isoformat(timespec="seconds")
        with open(JOURNAL, "a", encoding="utf-8") as f:
            f.write(f"{horodatage};{operation};{ident};{fichier}\n")

    # ------------------------------------------------------------------ primitives
    def chiffrer(self, donnees: bytes, nom: str = "-") -> bytes:
        ident = self.active.encode()
        entete = MAGIC + bytes([len(ident)]) + ident
        nonce = os.urandom(TAILLE_NONCE)
        self.journaliser("chiffrer", self.active, nom)
        return entete + nonce + AESGCM(self.cles[self.active]).encrypt(nonce, donnees, entete)

    @staticmethod
    def identifiant(contenu: bytes) -> str:
        """Clé qui a produit ce fichier, lue dans l'en-tête (sans rien déchiffrer)."""
        if contenu[:4] == MAGIC:
            n = contenu[4]
            return contenu[5:5 + n].decode()
        return CLE_HISTORIQUE

    def dechiffrer(self, contenu: bytes, nom: str = "-") -> bytes:
        ident = self.identifiant(contenu)
        if ident not in self.cles or (ident != self.active and ident not in self.lecture):
            raise ErreurTrousseau(f"clé {ident} absente ou retirée du trousseau")
        if contenu[:4] == MAGIC:
            fin = 5 + contenu[4]
            entete, nonce, chiffre = contenu[:fin], contenu[fin:fin + TAILLE_NONCE], contenu[fin + TAILLE_NONCE:]
            aad = entete
        else:
            nonce, chiffre, aad = contenu[:TAILLE_NONCE], contenu[TAILLE_NONCE:], AAD_HISTORIQUE
        try:
            clair = AESGCM(self.cles[ident]).decrypt(nonce, chiffre, aad)
        except InvalidTag:
            raise ErreurTrousseau("fichier non authentique") from None
        self.journaliser("dechiffrer", ident, nom)
        return clair


def charger() -> Trousseau:
    try:
        return Trousseau()
    except ErreurTrousseau as exc:
        sys.exit(f"Erreur de trousseau : {exc}")
