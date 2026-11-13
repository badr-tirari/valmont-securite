"""Minimisation des données avant l'entrepôt — Laboratoire Valmont (étape 7).

Lit l'échantillon `patients` (02-au-repos/sql/01-patients.sql, état de départ) et produit :
    entrepot_resultats.csv   ce qui ENTRE dans l'entrepôt : une ligne par résultat, pseudonymisée
    tableau_de_bord.csv      ce que VOIENT les tableaux de bord : des agrégats, petites cases masquées
puis mesure ce qui reste ré-identifiable (k-anonymat sur les quasi-identifiants).

Transformations (chaque colonne de la source a un sort explicite) :
    nom, prenom, email, telephone, adresse   supprimés      aucun traitement statistique n'en a besoin
    nir                                       → pseudo_patient = HMAC-SHA-256(clé de pseudonymisation, NIR), 16 hex
                                                (jeton stable : suivre un patient dans le temps sans le connaître)
    date_naissance                            → tranche_age (10 ans) ; la date exacte est un quasi-identifiant fort
    sexe                                      → déduit du 1er chiffre du NIR ; conservé : les valeurs de référence
                                                biologiques en dépendent (hémoglobine, créatinine, ferritine)
    code postal (dans l'adresse)              → region ; le département rend chaque ligne unique (voir mesure)
    rendu_le                                  → mois_rendu (AAAA-MM)
    analyse, valeur, unite                    conservés : c'est l'objet du traitement

La clé de pseudonymisation (VALMONT_CLE_PSEUDO) est DISTINCTE des clés de la base (K1, K2) et
reste hors de l'entrepôt : sans elle, on ne peut pas recalculer le jeton à partir d'un NIR connu.

Usage :
    python minimiser_pour_entrepot.py ../02-au-repos/sql/01-patients.sql sortie
"""

import base64
import binascii
import csv
import hashlib
import hmac
import os
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path

SEUIL_K = 5          # en dessous de 5 personnes, une case de tableau de bord est masquée
DATE_REFERENCE = date(2026, 11, 5)

# Codes département (2 premiers chiffres du code postal) → région administrative
REGIONS = {
    "59": "Hauts-de-France", "34": "Occitanie", "31": "Occitanie", "75": "Île-de-France",
    "91": "Île-de-France", "92": "Île-de-France", "78": "Île-de-France", "13": "Provence-Alpes-Côte d'Azur",
    "84": "Provence-Alpes-Côte d'Azur", "38": "Auvergne-Rhône-Alpes", "69": "Auvergne-Rhône-Alpes",
    "07": "Auvergne-Rhône-Alpes", "67": "Grand Est", "29": "Bretagne",
}

COLONNES_SOURCE = ["id", "nom", "prenom", "date_naissance", "adresse", "telephone", "email",
                   "nir", "analyse", "valeur", "unite", "rendu_le"]
IDENTIFIANTS_DIRECTS = ["nom", "prenom", "email", "telephone", "adresse", "nir", "date_naissance"]


def cle_pseudo() -> bytes:
    v = os.environ.get("VALMONT_CLE_PSEUDO")
    if not v:
        sys.exit("Erreur : la variable d'environnement VALMONT_CLE_PSEUDO n'est pas définie.")
    try:
        cle = base64.b64decode(v, validate=True)
    except (binascii.Error, ValueError):
        sys.exit("Erreur : VALMONT_CLE_PSEUDO n'est pas du base64 valide.")
    if len(cle) != 32:
        sys.exit("Erreur : VALMONT_CLE_PSEUDO doit contenir 32 octets.")
    return cle


def lire_patients(chemin_sql: str) -> list[dict]:
    """Extrait les lignes de l'INSERT du fichier SQL fourni par le sujet."""
    sql = Path(chemin_sql).read_text(encoding="utf-8")
    bloc = sql[sql.index("VALUES"):]
    lignes = []
    for tuple_txt in re.findall(r"\((\d+,.*?)\)\s*[,;]", bloc):
        valeurs = re.findall(r"'((?:[^']|'')*)'|(\d+)", tuple_txt)
        champs = [a.replace("''", "'") if a else b for a, b in valeurs]
        lignes.append(dict(zip(COLONNES_SOURCE, champs)))
    return lignes


def tranche_age(naissance: str) -> str:
    a, m, j = map(int, naissance.split("-"))
    age = DATE_REFERENCE.year - a - ((DATE_REFERENCE.month, DATE_REFERENCE.day) < (m, j))
    debut = (age // 10) * 10
    return f"{debut}-{debut + 9}"


def minimiser(p: dict, cle: bytes) -> dict:
    cp = re.search(r"\b(\d{5})\b", p["adresse"]).group(1)
    return {
        "pseudo_patient": hmac.new(cle, p["nir"].encode(), hashlib.sha256).hexdigest()[:16],
        "sexe": {"1": "H", "2": "F"}[p["nir"][0]],
        "tranche_age": tranche_age(p["date_naissance"]),
        "region": REGIONS.get(cp[:2], "Autre"),
        "analyse": p["analyse"],
        "valeur": p["valeur"],
        "unite": p["unite"],
        "mois_rendu": p["rendu_le"][:7],
    }


def k_minimum(lignes: list[dict], quasi: list[str]) -> tuple[int, int]:
    """Plus petit groupe partageant les mêmes quasi-identifiants, et nombre de lignes uniques."""
    groupes = Counter(tuple(l[q] for q in quasi) for l in lignes)
    return min(groupes.values()), sum(1 for n in groupes.values() if n == 1)


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sortie = Path(sys.argv[2])
    sortie.mkdir(parents=True, exist_ok=True)
    cle = cle_pseudo()
    source = lire_patients(sys.argv[1])
    entrepot = [minimiser(p, cle) for p in source]

    with open(sortie / "entrepot_resultats.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(entrepot[0]))
        w.writeheader()
        w.writerows(entrepot)

    # Tableau de bord : nombre de résultats par analyse et par tranche d'âge, petites cases masquées
    comptes = Counter((l["analyse"], l["tranche_age"]) for l in entrepot)
    with open(sortie / "tableau_de_bord.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["analyse", "tranche_age", "nombre_resultats"])
        for (analyse, tranche), n in sorted(comptes.items()):
            w.writerow([analyse, tranche, n if n >= SEUIL_K else f"<{SEUIL_K}"])

    print(f"Source : {len(source)} fiches, {len(COLONNES_SOURCE)} colonnes")
    print(f"Entrepôt : {len(entrepot)} lignes, {len(entrepot[0])} colonnes → {sortie / 'entrepot_resultats.csv'}")
    print(f"  supprimées : nom, prenom, email, telephone, adresse, date_naissance, nir, id")
    print(f"  transformées : nir → pseudo_patient (HMAC), date_naissance → tranche_age, "
          f"adresse → region, rendu_le → mois_rendu")

    print("\nContrôle 1 — aucun identifiant direct dans l'entrepôt")
    texte = (sortie / "entrepot_resultats.csv").read_text(encoding="utf-8")
    fuites = []
    for p in source:
        for champ in ["nir", "nom", "email", "telephone", "date_naissance"]:
            if p[champ] and p[champ] in texte:
                fuites.append(f"{champ} de la fiche {p['id']}")
        if re.search(r"\b" + re.escape(p["adresse"].split(",")[0]) + r"\b", texte):
            fuites.append(f"adresse de la fiche {p['id']}")
    print(f"  [{'OK' if not fuites else 'ÉCHEC'}] {len(source) * 6} valeurs d'identifiants cherchées, "
          f"{len(fuites)} retrouvée(s){' : ' + ', '.join(fuites) if fuites else ''}")

    print("\nContrôle 2 — le jeton ne se recalcule pas sans la clé")
    nir = source[0]["nir"]
    sans_cle = hashlib.sha256(nir.encode()).hexdigest()[:16]
    print(f"  jeton dans l'entrepôt       : {entrepot[0]['pseudo_patient']}")
    print(f"  SHA-256(NIR) sans clé       : {sans_cle}  {'≠ (énumération des NIR inutile)' if sans_cle != entrepot[0]['pseudo_patient'] else '= ÉCHEC'}")

    print("\nContrôle 3 — risque de ré-identification (k-anonymat sur les quasi-identifiants)")
    essais = [
        (["sexe", "tranche_age", "departement"], "avec le département (choix écarté)"),
        (["sexe", "tranche_age", "region"], "avec la région (choix retenu, ligne individuelle)"),
        (["tranche_age"], "tableau de bord (tranche d'âge seule)"),
    ]
    for p, l in zip(source, entrepot):
        l["departement"] = re.search(r"\b(\d{5})\b", p["adresse"]).group(1)[:2]
    for quasi, libelle in essais:
        k, uniques = k_minimum(entrepot, quasi)
        print(f"  k = {k:<2} {libelle:<52} — {uniques}/{len(entrepot)} ligne(s) unique(s)")
    for l in entrepot:
        del l["departement"]
    masquees = sum(1 for n in comptes.values() if n < SEUIL_K)
    print(f"\nTableau de bord : {len(comptes)} case(s), {masquees} masquée(s) (< {SEUIL_K} résultats) → {sortie / 'tableau_de_bord.csv'}")
    print("\nConclusion :")
    print("  - pseudonymiser ne suffit pas à anonymiser : même sexe + tranche d'âge + région isole chaque fiche ;")
    print("    l'entrepôt reste une donnée PERSONNELLE de santé (RGPD applicable, accès restreint, durée limitée) ;")
    print(f"  - sur {len(source)} fiches, aucune case n'atteint {SEUIL_K} : RIEN n'est publiable dans un tableau de bord.")
    print("    Au volume réel (des milliers de résultats par mois), les cases fréquentes passent le seuil, les rares restent masquées.")
    sys.exit(0 if not fuites else 1)


if __name__ == "__main__":
    main()
