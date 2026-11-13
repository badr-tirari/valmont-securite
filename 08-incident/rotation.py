"""Rotation de la clé K3 après fuite — période à deux clés, ré-chiffrement progressif, preuve de complétude.

Commandes (le trousseau est lu dans l'environnement, voir trousseau.py) :
    python rotation.py simuler-archive <dossier> <n>
        crée une archive de n exports nocturnes, au format de l'ÉTAPE 2 (clé k3-v1, sans en-tête) :
        c'est l'état réel du laboratoire au moment de la fuite
    python rotation.py consommateurs <dossier>
        fait travailler les consommateurs de la clé : traitement de nuit (écrit un export),
        application du portail (relit le dernier), entrepôt (relit tout le mois) — à lancer
        AVANT, PENDANT et APRÈS la rotation pour prouver qu'il n'y a pas d'interruption
    python rotation.py inventaire <dossier>
        nombre de fichiers par clé, lu dans les en-têtes (sans rien déchiffrer)
    python rotation.py rechiffrer <dossier> [--lot N] [--panne-apres K]
        ré-chiffre avec la clé active les fichiers produits par une autre clé, par lots ;
        chaque fichier : déchiffrer → chiffrer → relire et comparer → remplacement ATOMIQUE.
        --panne-apres K simule un arrêt brutal pendant le fichier K+1 (test du repli)
    python rotation.py preuve-completude <dossier> <cle_retiree>
        prouve que plus rien n'utilise l'ancienne clé avant de la détruire
"""

import csv
import datetime
import hashlib
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import trousseau as tr

JOURNAL_ROTATION = Path(os.environ.get("VALMONT_JOURNAL_ROTATION", "journal_rotation.csv"))
SOURCE = Path(__file__).parent.parent / "02-au-repos" / "donnees" / "export_2026-11-05.csv"


def fichiers(dossier: Path) -> list[Path]:
    return sorted(dossier.glob("export_*.csv.chiffre"))


# --------------------------------------------------------------------------- simuler-archive
def cmd_simuler_archive(dossier: Path, n: int) -> None:
    t = tr.charger()
    if t.active != tr.CLE_HISTORIQUE:
        sys.exit(f"L'archive initiale se crée avec {tr.CLE_HISTORIQUE} active (état avant la fuite).")
    dossier.mkdir(parents=True, exist_ok=True)
    modele = SOURCE.read_text(encoding="utf-8")
    cle = t.cles[tr.CLE_HISTORIQUE]
    debut = datetime.date(2026, 11, 5) - datetime.timedelta(days=n - 1)
    for i in range(n):
        jour = debut + datetime.timedelta(days=i)
        contenu = modele.replace("2026-11-05", jour.isoformat()).encode()
        nonce = os.urandom(tr.TAILLE_NONCE)
        # format de l'étape 2 : nonce ‖ chiffré ‖ tag, sans en-tête
        (dossier / f"export_{jour.isoformat()}.csv.chiffre").write_bytes(
            nonce + AESGCM(cle).encrypt(nonce, contenu, tr.AAD_HISTORIQUE))
    print(f"Archive simulée : {n} exports du {debut} au {jour}, chiffrés par {tr.CLE_HISTORIQUE} (format étape 2)")


# --------------------------------------------------------------------------- consommateurs
def cmd_consommateurs(dossier: Path) -> None:
    t = tr.charger()
    ok = True
    # 1. Traitement de nuit : écrit l'export du jour avec la clé ACTIVE
    tous = fichiers(dossier)
    dernier_jour = datetime.date.fromisoformat(tous[-1].name[7:17])
    jour = dernier_jour + datetime.timedelta(days=1)
    contenu = SOURCE.read_text(encoding="utf-8").replace("2026-11-05", jour.isoformat()).encode()
    nom = f"export_{jour.isoformat()}.csv.chiffre"
    (dossier / nom).write_bytes(t.chiffrer(contenu, nom))
    print(f"  [OK] traitement de nuit : {nom} écrit avec {t.identifiant((dossier / nom).read_bytes())}")
    # 2. Application du portail : relit le dernier export
    try:
        t.dechiffrer((dossier / nom).read_bytes(), nom)
        print(f"  [OK] application       : dernier export relu")
    except tr.ErreurTrousseau as exc:
        ok = False; print(f"  [ÉCHEC] application    : {exc}")
    # 3. Entrepôt : relit tout l'historique
    lus, erreurs, par_cle = 0, 0, {}
    for f in fichiers(dossier):
        try:
            t.dechiffrer(f.read_bytes(), f.name)
            lus += 1
            k = t.identifiant(f.read_bytes()); par_cle[k] = par_cle.get(k, 0) + 1
        except tr.ErreurTrousseau:
            erreurs += 1
    detail = ", ".join(f"{k} : {v}" for k, v in sorted(par_cle.items()))
    if erreurs:
        ok = False; print(f"  [ÉCHEC] entrepôt        : {erreurs} fichier(s) illisible(s)")
    else:
        print(f"  [OK] entrepôt          : {lus} exports relus ({detail})")
    print("  Service : " + ("aucune interruption" if ok else "INTERROMPU"))
    sys.exit(0 if ok else 1)


# --------------------------------------------------------------------------- inventaire
def inventaire(dossier: Path) -> dict[str, int]:
    compte: dict[str, int] = {}
    for f in fichiers(dossier):
        k = tr.Trousseau.identifiant(f.read_bytes())
        compte[k] = compte.get(k, 0) + 1
    return compte


def cmd_inventaire(dossier: Path) -> None:
    compte = inventaire(dossier)
    total = sum(compte.values())
    for k, n in sorted(compte.items()):
        print(f"  {k} : {n:>3} fichier(s)  {'█' * n}")
    restes = sorted(dossier.glob("*.tmp"))
    print(f"  total : {total} fichier(s)" + (f" — {len(restes)} fichier(s) temporaire(s) d'une migration interrompue" if restes else ""))


# --------------------------------------------------------------------------- rechiffrer
def cmd_rechiffrer(dossier: Path, lot: int, panne_apres: int | None) -> None:
    t = tr.charger()
    # Reprise après panne : un .tmp n'a jamais remplacé l'original, il est simplement jeté.
    for tmp in dossier.glob("*.tmp"):
        tmp.unlink()
        print(f"  reprise : {tmp.name} abandonné (l'original est intact)")
    a_migrer = [f for f in fichiers(dossier) if t.identifiant(f.read_bytes()) != t.active][:lot]
    nouveau = not JOURNAL_ROTATION.exists()
    with open(JOURNAL_ROTATION, "a", encoding="utf-8", newline="") as j:
        w = csv.writer(j)
        if nouveau:
            w.writerow(["horodatage", "fichier", "ancienne_cle", "nouvelle_cle", "sha256_clair", "statut"])
        for i, f in enumerate(a_migrer):
            ancien = f.read_bytes()
            ancienne_cle = t.identifiant(ancien)
            clair = t.dechiffrer(ancien, f.name)                 # clé compromise : lecture seule
            nouveau_contenu = t.chiffrer(clair, f.name)           # clé neuve
            if t.dechiffrer(nouveau_contenu, f.name) != clair:    # relecture AVANT remplacement
                w.writerow([datetime.datetime.now().isoformat(timespec="seconds"), f.name, ancienne_cle, t.active, "", "ECHEC_RELECTURE"])
                sys.exit(f"Relecture incorrecte pour {f.name} : arrêt, original conservé.")
            tmp = f.with_name(f.name + ".tmp")
            tmp.write_bytes(nouveau_contenu)
            if panne_apres is not None and i == panne_apres:
                print(f"  ⚡ PANNE SIMULÉE pendant {f.name} : {tmp.name} écrit, original pas encore remplacé")
                sys.exit(2)
            os.replace(tmp, f)                                    # atomique : ancien OU nouveau, jamais un mélange
            w.writerow([datetime.datetime.now().isoformat(timespec="seconds"), f.name, ancienne_cle, t.active,
                        hashlib.sha256(clair).hexdigest(), "OK"])
            print(f"  {f.name} : {ancienne_cle} → {t.active}")
    reste = sum(1 for f in fichiers(dossier) if t.identifiant(f.read_bytes()) != t.active)
    print(f"Lot terminé : {len(a_migrer)} fichier(s) ré-chiffré(s), {reste} restant(s) sur une autre clé")


# --------------------------------------------------------------------------- preuve de complétude
def cmd_preuve_completude(dossier: Path, retiree: str) -> None:
    t = tr.charger()
    verdicts = []

    print(f"1. Inventaire de l'archive (en-têtes) — aucun fichier ne doit encore dépendre de {retiree}")
    compte = inventaire(dossier)
    n = compte.get(retiree, 0)
    print(f"   {dict(sorted(compte.items()))}")
    verdicts.append(n == 0)
    print(f"   [{'OK' if n == 0 else 'ÉCHEC'}] {n} fichier(s) sur {retiree}")

    print(f"2. Journal d'usage des clés — {retiree} n'a-t-elle plus rien chiffré depuis son isolement ?")
    isolement, fautifs = None, []          # fautifs : (horodatage, fichier) chiffrés par la clé compromise
    if tr.JOURNAL.exists():
        for ligne in tr.JOURNAL.read_text(encoding="utf-8").splitlines():
            h, op, k, fichier = ligne.split(";", 3)
            # Isolement = premier chiffrement effectué par une AUTRE clé (bascule de la clé active).
            if op == "chiffrer" and k != retiree and isolement is None:
                isolement = h
            if op == "chiffrer" and k == retiree and isolement is not None:
                fautifs.append((h, fichier))
    migres = {}
    if JOURNAL_ROTATION.exists():
        for l in csv.DictReader(open(JOURNAL_ROTATION, encoding="utf-8")):
            if l["statut"] == "OK" and l["ancienne_cle"] == retiree:
                migres.setdefault(l["fichier"], []).append(l["horodatage"])
    print(f"   isolement (bascule vers la nouvelle clé active) : {isolement or '—'}")
    non_traites = [(h, f) for h, f in fautifs if not any(m >= h for m in migres.get(f, []))]
    for h, f in fautifs:
        etat = "ré-chiffré ensuite" if (h, f) not in non_traites else "NON TRAITÉ"
        print(f"   ⚠ {h} : {f} chiffré par {retiree} APRÈS l'isolement (consommateur mal configuré) → {etat}")
    verdicts.append(not non_traites)
    print(f"   [{'OK' if not non_traites else 'ÉCHEC'}] {len(fautifs)} écriture(s) fautive(s) détectée(s), "
          f"{len(non_traites)} non traitée(s)")

    print(f"3. Test de retrait — tout relire avec un trousseau SANS {retiree}")
    t.cles.pop(retiree, None); t.lecture.discard(retiree)
    illisibles = []
    integrite = {}
    if JOURNAL_ROTATION.exists():
        for l in csv.DictReader(open(JOURNAL_ROTATION, encoding="utf-8")):
            if l["statut"] == "OK":
                integrite[l["fichier"]] = l["sha256_clair"]
    differents = 0
    for f in fichiers(dossier):
        try:
            clair = t.dechiffrer(f.read_bytes(), f.name + " (test de retrait)")
            if f.name in integrite and hashlib.sha256(clair).hexdigest() != integrite[f.name]:
                differents += 1
        except tr.ErreurTrousseau:
            illisibles.append(f.name)
    total = len(fichiers(dossier))
    verdicts.append(not illisibles and differents == 0)
    print(f"   [{'OK' if not illisibles and differents == 0 else 'ÉCHEC'}] {total - len(illisibles)}/{total} fichiers relus sans {retiree} ; "
          f"contenu identique à l'avant-migration (SHA-256) : {len(integrite) - differents}/{len(integrite)}")

    print()
    if all(verdicts):
        print(f"VERDICT : {retiree} n'est plus nécessaire → la retirer du Coffre (destruction de la version), "
              f"puis purger les sauvegardes qui la contiennent.")
    else:
        print(f"VERDICT : {retiree} est ENCORE nécessaire — ne pas la retirer.")
    sys.exit(0 if all(verdicts) else 1)


def main() -> None:
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "simuler-archive":
        cmd_simuler_archive(Path(a[1]), int(a[2]))
    elif len(a) == 2 and a[0] == "consommateurs":
        cmd_consommateurs(Path(a[1]))
    elif len(a) == 2 and a[0] == "inventaire":
        cmd_inventaire(Path(a[1]))
    elif len(a) >= 2 and a[0] == "rechiffrer":
        lot = int(a[a.index("--lot") + 1]) if "--lot" in a else 10**9
        panne = int(a[a.index("--panne-apres") + 1]) if "--panne-apres" in a else None
        cmd_rechiffrer(Path(a[1]), lot, panne)
    elif len(a) == 3 and a[0] == "preuve-completude":
        cmd_preuve_completude(Path(a[1]), a[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
