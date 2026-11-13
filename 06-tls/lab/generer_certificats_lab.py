"""Certificats de LABORATOIRE pour tester la configuration sans nom de domaine public.

Plutôt qu'un simple certificat auto-signé, on fabrique une mini-PKI à deux niveaux :
    ca.pem         autorité racine « Valmont Lab CA » (le client la déclare explicitement)
    fullchain.pem  certificat du serveur portail.labo-valmont.fr, signé par cette autorité
    privkey.pem    clé privée ECDSA P-256 du serveur
Le client peut ainsi VÉRIFIER une chaîne de confiance complète (signature, nom, dates),
comme il le ferait avec Let's Encrypt. Seule différence : la racine n'est pas dans le
magasin de confiance du système, ce que la vérification montre aussi.

Usage :
    python generer_certificats_lab.py certs
"""

import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOM = "portail.labo-valmont.fr"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sortie = Path(sys.argv[1])
    sortie.mkdir(parents=True, exist_ok=True)
    maintenant = datetime.datetime.now(datetime.timezone.utc)

    # Autorité racine du laboratoire
    cle_ca = ec.generate_private_key(ec.SECP256R1())
    nom_ca = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Laboratoire Valmont (TP)"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Valmont Lab CA"),
    ])
    ca = (
        x509.CertificateBuilder()
        .subject_name(nom_ca).issuer_name(nom_ca)
        .public_key(cle_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(minutes=5))
        .not_valid_after(maintenant + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                     crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(cle_ca.public_key()), critical=False)
        .sign(cle_ca, hashes.SHA256())
    )

    # Certificat du serveur : 90 jours, comme Let's Encrypt
    cle_srv = ec.generate_private_key(ec.SECP256R1())
    srv = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NOM)]))
        .issuer_name(nom_ca)
        .public_key(cle_srv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(maintenant - datetime.timedelta(minutes=5))
        .not_valid_after(maintenant + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(NOM)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(cle_ca.public_key()), critical=False)
        .sign(cle_ca, hashes.SHA256())
    )

    pem = serialization.Encoding.PEM
    (sortie / "ca.pem").write_bytes(ca.public_bytes(pem))
    (sortie / "fullchain.pem").write_bytes(srv.public_bytes(pem) + ca.public_bytes(pem))
    (sortie / "privkey.pem").write_bytes(cle_srv.private_bytes(
        pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))  # nginx doit la lire au démarrage
    print(f"Certificats de laboratoire créés dans {sortie}/ :")
    print(f"  ca.pem         autorité « Valmont Lab CA », valable 365 jours")
    print(f"  fullchain.pem  {NOM}, signé par l'autorité, valable 90 jours (ECDSA P-256)")
    print(f"  privkey.pem    clé privée du serveur (exclue du dépôt par .gitignore)")
    # La clé de l'autorité n'est écrite nulle part : on ne peut plus rien signer avec elle.


if __name__ == "__main__":
    main()
