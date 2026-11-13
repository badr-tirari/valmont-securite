"""Mots de passe du portail patient : empreinte salée, fonction lente (PBKDF2-HMAC-SHA-256).

Format imposé par la table comptes_portail existante :
    sel        CHAR(32)  16 octets aléatoires, en hexadécimal, unique par compte
    empreinte  CHAR(64)  PBKDF2-HMAC-SHA-256(mot de passe UTF-8, sel DÉCODÉ en octets, 100 000 itérations)

Attention au piège : le sel est stocké en hexadécimal, mais c'est sa valeur en OCTETS
(bytes.fromhex) qui entre dans PBKDF2. Passer la chaîne hexadécimale telle quelle donne
une autre empreinte, et aucune connexion ne passe.

Connexion à la base : mêmes variables que l'étape 2 (VALMONT_DB_HOST, VALMONT_DB_PORT,
VALMONT_DB_USER, VALMONT_DB_PASSWORD).

Commandes :
    python mots_de_passe.py initialiser                       crée et remplit comptes_portail (sql/02-comptes-portail.sql)
    python mots_de_passe.py connexion <identifiant>           demande le mot de passe (saisie masquée) et répond accepté / refusé
    python mots_de_passe.py preuve                            rejoue les cas de test du sujet
    python mots_de_passe.py creer <identifiant> <patient_id>  crée un compte (mot de passe saisi, sel neuf)
"""

import getpass
import hashlib
import hmac
import os
import secrets
import sys
import time
from pathlib import Path

import pymysql

ITERATIONS = 100_000
TAILLE_SEL = 16
REFUS = "Identifiant ou mot de passe incorrect."  # même message dans tous les cas d'échec


def empreinte(mot_de_passe: str, sel_hex: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", mot_de_passe.encode("utf-8"), bytes.fromhex(sel_hex), ITERATIONS).hex()


# Empreinte factice : calculée quand l'identifiant n'existe pas, pour que la réponse prenne
# le même temps qu'avec un vrai compte (pas d'énumération des identifiants par chronométrage).
_SEL_FACTICE = secrets.token_hex(TAILLE_SEL)
_EMPREINTE_FACTICE = empreinte(secrets.token_urlsafe(16), _SEL_FACTICE)


def connexion_bdd() -> pymysql.connections.Connection:
    mdp = os.environ.get("VALMONT_DB_PASSWORD")
    if not mdp:
        sys.exit("Erreur : la variable d'environnement VALMONT_DB_PASSWORD n'est pas définie.")
    try:
        return pymysql.connect(
            host=os.environ.get("VALMONT_DB_HOST", "127.0.0.1"),
            port=int(os.environ.get("VALMONT_DB_PORT", "3307")),
            user=os.environ.get("VALMONT_DB_USER", "root"),
            password=mdp, database="valmont", charset="utf8mb4", autocommit=True,
        )
    except pymysql.err.OperationalError:
        # Pas de trace d'exécution : elle dévoilerait hôte, port et chemins internes.
        sys.exit("Erreur : base de données injoignable (le conteneur valmont-mysql est-il démarré ?).")


def verifier(identifiant: str, mot_de_passe: str) -> bool:
    with connexion_bdd() as cnx, cnx.cursor() as cur:
        cur.execute("SELECT sel, empreinte FROM comptes_portail WHERE identifiant = %s", (identifiant,))
        ligne = cur.fetchone()
    sel, attendue = ligne if ligne else (_SEL_FACTICE, _EMPREINTE_FACTICE)
    calculee = empreinte(mot_de_passe, sel)
    return ligne is not None and hmac.compare_digest(calculee, attendue)  # comparaison à temps constant


def cmd_initialiser() -> None:
    script = (Path(__file__).parent / "sql" / "02-comptes-portail.sql").read_text(encoding="utf-8")
    instructions = [i.strip() for i in script.split(";\n") if i.strip() and not i.strip().startswith("--")]
    with connexion_bdd() as cnx, cnx.cursor() as cur:
        for instr in instructions:
            lignes = [l for l in instr.splitlines() if not l.strip().startswith("--")]
            if "".join(lignes).strip():
                cur.execute("\n".join(lignes))
        cur.execute("SELECT COUNT(*) FROM comptes_portail")
        print(f"Table comptes_portail chargée : {cur.fetchone()[0]} comptes.")


def cmd_connexion(identifiant: str) -> None:
    mdp = getpass.getpass("Mot de passe : ")
    print("Connexion acceptée." if verifier(identifiant, mdp) else REFUS)


def cmd_preuve() -> None:
    cas = [
        ("marchand.a", "valmont-novembre", True, "bon mot de passe"),
        ("marchand.a", "valmont-Novembre", False, "une majuscule de différence"),
        ("marchand.a", "valmont-novembre ", False, "espace en trop"),
        ("marchand.a", "", False, "mot de passe vide"),
        ("ferrand.b", "valmont-novembre", False, "même mot de passe, autre compte (autre sel)"),
        ("inconnu.x", "valmont-novembre", False, "identifiant inexistant"),
    ]
    r = []
    for ident, mdp, attendu, libelle in cas:
        t0 = time.perf_counter()
        accepte = verifier(ident, mdp)
        ms = (time.perf_counter() - t0) * 1000
        ok = accepte == attendu
        r.append(ok)
        print(f"  [{'OK' if ok else 'ÉCHEC'}] {ident:<11} {libelle:<45} → "
              f"{'acceptée' if accepte else 'refusée':<9} ({ms:.0f} ms)")

    print("\nPiège du sel : le sel hexadécimal doit être décodé en octets")
    with connexion_bdd() as cnx, cnx.cursor() as cur:
        cur.execute("SELECT sel, empreinte FROM comptes_portail WHERE identifiant = 'marchand.a'")
        sel, attendue = cur.fetchone()
    bon = empreinte("valmont-novembre", sel)
    faux = hashlib.pbkdf2_hmac("sha256", b"valmont-novembre", sel.encode(), ITERATIONS).hex()
    print(f"  stockée                     : {attendue}")
    print(f"  sel décodé (bytes.fromhex)  : {bon}  {'= identique' if bon == attendue else '≠'}")
    print(f"  sel pris comme texte        : {faux}  {'= identique' if faux == attendue else '≠ différente'}")
    r.append(bon == attendue and faux != attendue)

    print(f"\nBilan : {sum(r)}/{len(r)} contrôles réussis")
    sys.exit(0 if all(r) else 1)


def cmd_creer(identifiant: str, patient_id: str) -> None:
    mdp = getpass.getpass("Nouveau mot de passe : ")
    if len(mdp) < 12:
        sys.exit("Refusé : 12 caractères minimum.")
    sel = secrets.token_hex(TAILLE_SEL)  # CSPRNG, neuf pour chaque compte
    with connexion_bdd() as cnx, cnx.cursor() as cur:
        cur.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM comptes_portail")
        nouvel_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO comptes_portail (id, patient_id, identifiant, sel, empreinte) VALUES (%s, %s, %s, %s, %s)",
            (nouvel_id, int(patient_id), identifiant, sel, empreinte(mdp, sel)),
        )
    print(f"Compte {identifiant} créé (sel neuf, empreinte PBKDF2 {ITERATIONS} itérations). Le mot de passe n'est stocké nulle part.")


def main() -> None:
    a = sys.argv[1:]
    if a == ["initialiser"]:
        cmd_initialiser()
    elif len(a) == 2 and a[0] == "connexion":
        cmd_connexion(a[1])
    elif a == ["preuve"]:
        cmd_preuve()
    elif len(a) == 3 and a[0] == "creer":
        cmd_creer(a[1], a[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
