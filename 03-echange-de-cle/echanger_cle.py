"""Échange hybride de la clé de session de l'export nocturne — Laboratoire Valmont → partenaire.

Principe :
    1. le partenaire génère sa paire RSA-3072 ; il garde la clé privée, publie la clé publique ;
    2. le labo tire une clé de session AES-256 NEUVE pour chaque export ;
    3. les données sont chiffrées avec la clé de session (AES-256-GCM, symétrique, rapide) ;
    4. la clé de session est chiffrée avec la clé PUBLIQUE du partenaire (RSA-OAEP-SHA-256) :
       c'est l'« enveloppe » ; seule la clé privée du partenaire peut l'ouvrir ;
    5. on envoie l'enveloppe + le fichier chiffré. La clé de session ne circule jamais en clair.

Formats :
    enveloppe  : 384 octets bruts = RSA-OAEP(SHA-256, MGF1-SHA-256)(clé de session)
    chiffré    : nonce (12) ‖ AES-256-GCM(données) ‖ tag (16)
                 AAD = "valmont/export-partenaire/v1" ‖ SHA-256(enveloppe) : le fichier chiffré
                 est lié à SON enveloppe, on ne peut pas les recombiner avec ceux d'un autre jour.

Commandes :
    python echanger_cle.py generer-partenaire <dossier>
        (côté PARTENAIRE) crée partenaire_prive.pem (protégée par VALMONT_PASSPHRASE_PARTENAIRE)
        et partenaire_public.pem
    python echanger_cle.py envelopper <export.csv> <partenaire_public.pem> <dossier_sortie>
        (côté LABO) produit cle_session.enveloppe et export.csv.chiffre
    python echanger_cle.py ouvrir <dossier_livraison> <partenaire_prive.pem> <export_dechiffre.csv>
        (côté PARTENAIRE) ouvre l'enveloppe puis déchiffre l'export
"""

import hashlib
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TAILLE_RSA = 3072          # ≥ 3072 bits recommandé (ANSSI) au-delà de 2030
TAILLE_CLE_SESSION = 32    # AES-256
TAILLE_NONCE = 12
LIBELLE = b"valmont/export-partenaire/v1"
NOM_ENVELOPPE = "cle_session.enveloppe"
NOM_CHIFFRE = "export.csv.chiffre"

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


class OuvertureRefusee(Exception):
    """Enveloppe ou fichier non authentique, ou mauvaise clé privée."""


# --------------------------------------------------------------------------- outils


def phrase_de_passe() -> bytes:
    valeur = os.environ.get("VALMONT_PASSPHRASE_PARTENAIRE")
    if not valeur:
        sys.exit("Erreur : la variable d'environnement VALMONT_PASSPHRASE_PARTENAIRE n'est pas définie.")
    return valeur.encode()


def empreinte_cle_publique(cle_publique) -> str:
    """SHA-256 de la clé publique (format DER) : à comparer avec celle annoncée par le partenaire."""
    der = cle_publique.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    h = hashlib.sha256(der).hexdigest()
    return ":".join(h[i:i + 2] for i in range(0, 16, 2)) + "…" + h[-8:]


def aad(enveloppe: bytes) -> bytes:
    return LIBELLE + hashlib.sha256(enveloppe).digest()


# --------------------------------------------------------------------------- primitives


def envelopper(donnees: bytes, cle_publique) -> tuple[bytes, bytes, bytes]:
    """Retourne (enveloppe, chiffré, clé de session). La clé de session n'est jamais écrite."""
    cle_session = os.urandom(TAILLE_CLE_SESSION)          # neuve à chaque export
    enveloppe = cle_publique.encrypt(cle_session, OAEP)   # asymétrique : transporte la clé
    nonce = os.urandom(TAILLE_NONCE)
    chiffre = nonce + AESGCM(cle_session).encrypt(nonce, donnees, aad(enveloppe))  # symétrique : transporte les données
    return enveloppe, chiffre, cle_session


def ouvrir(enveloppe: bytes, chiffre: bytes, cle_privee) -> tuple[bytes, bytes]:
    """Retourne (données, clé de session) ou lève OuvertureRefusee."""
    try:
        cle_session = cle_privee.decrypt(enveloppe, OAEP)
    except ValueError:
        raise OuvertureRefusee() from None
    if len(cle_session) != TAILLE_CLE_SESSION or len(chiffre) < TAILLE_NONCE + 16:
        raise OuvertureRefusee()
    try:
        donnees = AESGCM(cle_session).decrypt(chiffre[:TAILLE_NONCE], chiffre[TAILLE_NONCE:], aad(enveloppe))
    except InvalidTag:
        raise OuvertureRefusee() from None
    return donnees, cle_session


# --------------------------------------------------------------------------- commandes


def cmd_generer_partenaire(dossier: str) -> None:
    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    cle_privee = rsa.generate_private_key(public_exponent=65537, key_size=TAILLE_RSA)
    (sortie / "partenaire_prive.pem").write_bytes(
        cle_privee.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(phrase_de_passe()),  # jamais stockée en clair
        )
    )
    (sortie / "partenaire_public.pem").write_bytes(
        cle_privee.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    print(f"Paire RSA-{TAILLE_RSA} du partenaire créée dans {sortie}/")
    print("  partenaire_prive.pem  → reste chez le partenaire (chiffrée par sa phrase de passe)")
    print("  partenaire_public.pem → transmise au labo")
    print(f"  empreinte de la clé publique : {empreinte_cle_publique(cle_privee.public_key())}")


def cmd_envelopper(export: str, chemin_public: str, dossier: str) -> None:
    cle_publique = serialization.load_pem_public_key(Path(chemin_public).read_bytes())
    if not isinstance(cle_publique, rsa.RSAPublicKey) or cle_publique.key_size < TAILLE_RSA:
        sys.exit(f"Erreur : clé publique RSA d'au moins {TAILLE_RSA} bits attendue.")
    donnees = Path(export).read_bytes()

    enveloppe, chiffre, cle_session = envelopper(donnees, cle_publique)

    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    (sortie / NOM_ENVELOPPE).write_bytes(enveloppe)
    (sortie / NOM_CHIFFRE).write_bytes(chiffre)
    print(f"Clé publique du partenaire : {empreinte_cle_publique(cle_publique)} "
          "(à comparer avec l'empreinte annoncée par le partenaire)")
    print(f"Clé de session tirée (32 octets) — empreinte SHA-256 : {hashlib.sha256(cle_session).hexdigest()[:16]}…")
    print(f"  {sortie / NOM_ENVELOPPE} : {len(enveloppe)} octets (RSA-OAEP-SHA-256)")
    print(f"  {sortie / NOM_CHIFFRE} : {len(chiffre)} octets (AES-256-GCM)")
    print("La clé de session n'est écrite nulle part en clair.")


def cmd_ouvrir(dossier: str, chemin_prive: str, cible: str) -> None:
    try:
        cle_privee = serialization.load_pem_private_key(Path(chemin_prive).read_bytes(), password=phrase_de_passe())
    except (ValueError, TypeError):
        sys.exit("Échec : clé privée illisible (phrase de passe incorrecte ?).")
    enveloppe = (Path(dossier) / NOM_ENVELOPPE).read_bytes()
    chiffre = (Path(dossier) / NOM_CHIFFRE).read_bytes()
    try:
        donnees, cle_session = ouvrir(enveloppe, chiffre, cle_privee)
    except OuvertureRefusee:
        sys.exit("Échec : ouverture refusée (enveloppe ou fichier non authentique, ou mauvaise clé privée). Aucun fichier écrit.")
    Path(cible).write_bytes(donnees)
    print(f"Enveloppe ouverte — clé de session récupérée, empreinte SHA-256 : {hashlib.sha256(cle_session).hexdigest()[:16]}…")
    print(f"Export déchiffré et authentifié : {cible} ({len(donnees)} octets)")


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == "generer-partenaire":
        cmd_generer_partenaire(args[1])
    elif len(args) == 4 and args[0] == "envelopper":
        cmd_envelopper(*args[1:])
    elif len(args) == 4 and args[0] == "ouvrir":
        cmd_ouvrir(*args[1:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
