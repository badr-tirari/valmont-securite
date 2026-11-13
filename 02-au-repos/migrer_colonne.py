"""Chiffrement applicatif de la colonne NIR de la table valmont.patients.

Schéma cible :
    nir_chiffre  VARBINARY(64)  nonce (12) || AES-256-GCM(NIR) || tag (16)
                                AAD = "valmont/patients.nir/<id>" : le chiffré est lié à SA ligne,
                                il ne peut pas être recopié sur la fiche d'un autre patient.
    nir_index    BINARY(32)     HMAC-SHA-256(clé d'index, NIR) — index aveugle pour la recherche exacte.
    (colonne nir et index idx_nir supprimés)

Deux clés distinctes, toutes deux lues dans l'environnement :
    VALMONT_CLE_NIR        chiffrement ;
    VALMONT_CLE_INDEX_NIR  index aveugle. Une fuite de l'une ne livre pas l'autre.

Connexion (variables d'environnement) :
    VALMONT_DB_HOST (127.0.0.1), VALMONT_DB_PORT (3307), VALMONT_DB_USER (root),
    VALMONT_DB_PASSWORD (obligatoire, aucune valeur par défaut).

Commandes :
    python migrer_colonne.py migrer           migre les lignes existantes (idempotent)
    python migrer_colonne.py verifier         prouve qu'aucune colonne ne montre de NIR lisible
    python migrer_colonne.py chercher <NIR>   retrouve une fiche par son NIR via l'index aveugle
"""

import hashlib
import hmac
import os
import re
import sys

import pymysql
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cles import charger_cle

TAILLE_NONCE = 12
MOTIF_NIR = re.compile(rb"(?<!\d)[12]\d{14}(?!\d)")  # 15 chiffres commençant par 1 ou 2


# --------------------------------------------------------------------------- outils


def connexion() -> pymysql.connections.Connection:
    mot_de_passe = os.environ.get("VALMONT_DB_PASSWORD")
    if not mot_de_passe:
        sys.exit("Erreur : la variable d'environnement VALMONT_DB_PASSWORD n'est pas définie.")
    try:
        return pymysql.connect(
            host=os.environ.get("VALMONT_DB_HOST", "127.0.0.1"),
            port=int(os.environ.get("VALMONT_DB_PORT", "3307")),
            user=os.environ.get("VALMONT_DB_USER", "root"),
            password=mot_de_passe,
            database="valmont",
            charset="utf8mb4",
            autocommit=False,
        )
    except pymysql.err.OperationalError:
        # Pas de trace d'exécution : elle dévoilerait hôte, port et chemins internes.
        sys.exit("Erreur : base de données injoignable (le conteneur valmont-mysql est-il démarré ?).")


def normaliser(nir: str) -> str:
    """Même valeur canonique à l'écriture et à la recherche (espaces retirés)."""
    nir = re.sub(r"\s", "", nir)
    if not re.fullmatch(r"[12]\d{14}", nir):
        raise ValueError("NIR invalide : 15 chiffres attendus, commençant par 1 ou 2.")
    return nir


def aad(patient_id: int) -> bytes:
    return f"valmont/patients.nir/{patient_id}".encode()


def chiffrer_nir(nir: str, patient_id: int, cle: bytes) -> bytes:
    nonce = os.urandom(TAILLE_NONCE)
    return nonce + AESGCM(cle).encrypt(nonce, nir.encode(), aad(patient_id))


def dechiffrer_nir(stocke: bytes, patient_id: int, cle: bytes) -> str:
    nonce, chiffre = stocke[:TAILLE_NONCE], stocke[TAILLE_NONCE:]
    return AESGCM(cle).decrypt(nonce, chiffre, aad(patient_id)).decode()


def index_aveugle(nir: str, cle_index: bytes) -> bytes:
    return hmac.new(cle_index, nir.encode(), hashlib.sha256).digest()


def colonnes(cur) -> set:
    cur.execute(
        "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = 'valmont' AND TABLE_NAME = 'patients'"
    )
    return {ligne[0] for ligne in cur.fetchall()}


def masquer(nir: str) -> str:
    return nir[:1] + "*" * 10 + nir[-4:]


# --------------------------------------------------------------------------- commandes


def migrer() -> None:
    cle, cle_index = charger_cle("VALMONT_CLE_NIR"), charger_cle("VALMONT_CLE_INDEX_NIR")
    if cle == cle_index:
        sys.exit("Erreur : VALMONT_CLE_NIR et VALMONT_CLE_INDEX_NIR doivent être deux clés différentes.")

    cnx = connexion()
    with cnx.cursor() as cur:
        presentes = colonnes(cur)
        if "nir" not in presentes:
            print("Rien à faire : la colonne nir en clair n'existe plus (migration déjà effectuée).")
            return

        # 1. Nouvelles colonnes, nullables le temps de la migration (DDL : commit implicite).
        if "nir_chiffre" not in presentes:
            cur.execute("ALTER TABLE patients ADD COLUMN nir_chiffre VARBINARY(64) NULL AFTER nir")
        if "nir_index" not in presentes:
            cur.execute("ALTER TABLE patients ADD COLUMN nir_index BINARY(32) NULL AFTER nir_chiffre")

        # 2. Chiffrement des lignes existantes, dans UNE transaction : tout ou rien.
        cur.execute("SELECT id, nir FROM patients WHERE nir_chiffre IS NULL FOR UPDATE")
        lignes = cur.fetchall()
        try:
            for patient_id, nir in lignes:
                nir = normaliser(nir)
                cur.execute(
                    "UPDATE patients SET nir_chiffre = %s, nir_index = %s WHERE id = %s",
                    (chiffrer_nir(nir, patient_id, cle), index_aveugle(nir, cle_index), patient_id),
                )
            # 3. Contrôle avant de détruire le clair : chaque chiffré se relit et correspond.
            cur.execute("SELECT id, nir, nir_chiffre, nir_index FROM patients")
            for patient_id, nir, chiffre, idx in cur.fetchall():
                if chiffre is None or dechiffrer_nir(chiffre, patient_id, cle) != normaliser(nir) \
                        or not hmac.compare_digest(idx, index_aveugle(normaliser(nir), cle_index)):
                    raise RuntimeError(f"contrôle échoué sur la fiche {patient_id}")
            cnx.commit()
        except Exception as exc:
            cnx.rollback()
            sys.exit(f"Migration annulée (rollback), la colonne en clair est conservée : {exc}")
        print(f"{len(lignes)} fiche(s) chiffrée(s) et contrôlée(s).")

        # 4. Suppression du clair. ALGORITHM=COPY reconstruit la table : avec un DROP COLUMN
        #    « instantané » (défaut MySQL 8.0.29+ / MariaDB), les anciennes valeurs resteraient
        #    physiquement dans les pages du fichier .ibd.
        cur.execute("ALTER TABLE patients DROP INDEX idx_nir")
        cur.execute(
            "ALTER TABLE patients "
            "DROP COLUMN nir, "
            "MODIFY nir_chiffre VARBINARY(64) NOT NULL, "
            "MODIFY nir_index BINARY(32) NOT NULL, "
            "ADD INDEX idx_nir_index (nir_index), "
            "ALGORITHM=COPY"
        )
    cnx.close()
    print("Colonne nir supprimée, table reconstruite, index aveugle idx_nir_index créé.")


def verifier() -> None:
    cnx = connexion()
    anomalies = 0
    with cnx.cursor() as cur:
        presentes = colonnes(cur)
        print(f"Colonnes de patients : {', '.join(sorted(presentes))}")
        if "nir" in presentes:
            print("  [ÉCHEC] la colonne nir en clair existe encore")
            anomalies += 1
        else:
            print("  [OK] plus de colonne nir en clair")

        # Recherche d'un motif de NIR dans TOUTES les valeurs de TOUTES les colonnes.
        cur.execute("SELECT * FROM patients")
        noms = [d[0] for d in cur.description]
        nb, trouves = 0, 0
        for ligne in cur.fetchall():
            nb += 1
            for nom, valeur in zip(noms, ligne):
                brut = valeur if isinstance(valeur, (bytes, bytearray)) else str(valeur).encode()
                if MOTIF_NIR.search(brut):
                    print(f"  [ÉCHEC] NIR lisible : fiche id={ligne[0]}, colonne {nom}")
                    trouves += 1
        if trouves == 0:
            print(f"  [OK] {nb} fiches parcourues : aucun motif de NIR (15 chiffres) dans aucune colonne")
        anomalies += trouves

        cur.execute("SELECT id, HEX(nir_chiffre), HEX(nir_index) FROM patients ORDER BY id LIMIT 3")
        print("Extrait de ce que voit un SELECT direct :")
        for patient_id, chiffre, idx in cur.fetchall():
            print(f"  id={patient_id}  nir_chiffre={chiffre[:32]}…  nir_index={idx[:16]}…")
    cnx.close()
    sys.exit(1 if anomalies else 0)


def chercher(nir_saisi: str) -> None:
    cle, cle_index = charger_cle("VALMONT_CLE_NIR"), charger_cle("VALMONT_CLE_INDEX_NIR")
    nir = normaliser(nir_saisi)
    cnx = connexion()
    with cnx.cursor() as cur:
        # La base compare des empreintes : elle ne voit jamais le NIR recherché.
        cur.execute(
            "SELECT id, nom, prenom, analyse, valeur, unite, nir_chiffre FROM patients WHERE nir_index = %s",
            (index_aveugle(nir, cle_index),),
        )
        lignes = cur.fetchall()
    cnx.close()
    if not lignes:
        print("Aucune fiche pour ce NIR.")
        return
    for patient_id, nom, prenom, analyse, valeur, unite, chiffre in lignes:
        try:
            nir_lu = dechiffrer_nir(chiffre, patient_id, cle)
        except InvalidTag:
            print(f"Fiche {patient_id} : NIR non authentique (altéré ou recopié depuis une autre fiche).")
            continue
        print(f"Fiche {patient_id} : {prenom} {nom} — NIR {masquer(nir_lu)} — {analyse} = {valeur} {unite or ''}")


def main() -> None:
    if len(sys.argv) >= 2 and sys.argv[1] == "migrer":
        migrer()
    elif len(sys.argv) >= 2 and sys.argv[1] == "verifier":
        verifier()
    elif len(sys.argv) == 3 and sys.argv[1] == "chercher":
        try:
            chercher(sys.argv[2])
        except ValueError as exc:
            sys.exit(str(exc))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
