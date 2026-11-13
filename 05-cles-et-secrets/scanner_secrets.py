"""Détecteur de secrets minimal, sans dépendance, qui reprend les règles de garde-fous/.gitleaks.toml.

Il sert à vérifier le dossier valmont-securite/ avant le rendu, sur une machine où gitleaks
n'est pas installé. En production, c'est gitleaks qui fait foi (garde-fou n° 1).

Règles :
    CRITIQUE  clé privée PEM non chiffrée, clé VALMONT_CLE_* en base64, jeton GitHub, clé AWS
    ÉLEVÉ     clé privée PEM chiffrée, mot de passe ou phrase de passe écrit en dur, NIR (donnée de santé)

Les fichiers exclus par .gitignore (clés privées de démonstration) sont signalés à part,
sans faire échouer le contrôle : ils sont sur le poste, pas dans le dépôt.

Exceptions : le fichier .secrets-autorises, une ligne « <motif de chemin> <règle> » ; chaque
exception ne lève QU'UNE règle (par exemple « nir » pour l'échantillon fictif), jamais toutes.

Usage :
    python scanner_secrets.py <dossier>
Code retour 0 si rien n'est détecté hors exceptions, 1 sinon.
"""

import fnmatch
import re
import sys
from pathlib import Path

REGLES = [
    ("pem", "CRITIQUE", "clé privée PEM non chiffrée", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-{5}")),
    ("pem-chiffree", "ÉLEVÉ", "clé privée PEM chiffrée", re.compile(r"-----BEGIN ENCRYPTED PRIVATE KEY-{5}")),
    ("cle-valmont", "CRITIQUE", "clé Valmont en base64", re.compile(r"VALMONT_CLE_\w+\s*[=:]\s*[\"']?[A-Za-z0-9+/]{43}=")),
    ("github", "CRITIQUE", "jeton GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("aws", "CRITIQUE", "clé d'accès AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("mot-de-passe", "ÉLEVÉ", "mot de passe en dur",
     re.compile(r"(?i)(?:password|passwd|pwd|passphrase|mot_de_passe|secret)\w*\s*[=:]\s*[\"'](?!\*+[\"'])([^\"'\s$<>{}()]{6,})[\"']")),
    ("nir", "ÉLEVÉ", "NIR (numéro de sécurité sociale)", re.compile(r"(?<!\d)[12]\d{14}(?!\d)")),
]

IGNORES = {".git", "__pycache__", ".venv", "node_modules"}
TAILLE_MAX = 2_000_000


def charger_exceptions(racine: Path) -> list[tuple[str, str]]:
    fichier = racine / ".secrets-autorises"
    if not fichier.exists():
        return []
    exceptions = []
    for ligne in fichier.read_text(encoding="utf-8").splitlines():
        ligne = ligne.split("#", 1)[0].strip()
        if ligne:
            motif, _, regle = ligne.partition(" ")
            if not regle.strip():
                sys.exit(f"Exception sans règle refusée : « {ligne} » (format : <motif> <règle>)")
            exceptions.append((motif, regle.strip()))
    return exceptions


def autorise(chemin_relatif: str, regle: str, exceptions: list[tuple[str, str]]) -> bool:
    return any(r == regle and fnmatch.fnmatch(chemin_relatif, m) for m, r in exceptions)


def exclus_par_gitignore(racine: Path) -> set[Path]:
    """Fichiers exclus du dépôt par les .gitignore (motifs simples : fichier, dossier/, joker)."""
    exclus = set()
    for gi in racine.rglob(".gitignore"):
        base = gi.parent
        for motif in gi.read_text(encoding="utf-8").splitlines():
            motif = motif.strip()
            if not motif or motif.startswith("#"):
                continue
            for chemin in base.rglob("*"):
                rel = chemin.relative_to(base).as_posix()
                if fnmatch.fnmatch(rel, motif.rstrip("/")) or fnmatch.fnmatch(chemin.name, motif.rstrip("/")):
                    exclus.add(chemin)
                    if chemin.is_dir():
                        exclus.update(chemin.rglob("*"))
    return exclus


def masquer(texte: str) -> str:
    texte = texte.strip()
    return texte if len(texte) <= 12 else texte[:6] + "…" + texte[-3:]


def scanner(racine: Path) -> tuple[list, list, list]:
    motifs = charger_exceptions(racine)
    ignores_git = exclus_par_gitignore(racine)
    trouves, toleres, hors_depot = [], [], []
    for chemin in sorted(racine.rglob("*")):
        if not chemin.is_file() or any(p in IGNORES for p in chemin.parts) or chemin.stat().st_size > TAILLE_MAX:
            continue
        try:
            contenu = chemin.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue  # fichiers binaires (chiffrés, signatures) : rien de lisible
        rel = chemin.relative_to(racine).as_posix()
        for num, ligne in enumerate(contenu.splitlines(), 1):
            for regle, niveau, libelle, regex in REGLES:
                m = regex.search(ligne)
                if m:
                    entree = (niveau, libelle, rel, num, masquer(m.group(0)))
                    if chemin in ignores_git:
                        hors_depot.append(entree)
                    elif autorise(rel, regle, motifs):
                        toleres.append(entree)
                    else:
                        trouves.append(entree)
    return trouves, toleres, hors_depot


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    racine = Path(sys.argv[1]).resolve()
    trouves, toleres, hors_depot = scanner(racine)
    print(f"Analyse de {racine.name}/")
    for niveau, libelle, rel, num, extrait in trouves:
        print(f"  [{niveau}] {rel}:{num} — {libelle} ({extrait})")
    regroupes = {}
    for niveau, libelle, rel, num, extrait in hors_depot:
        regroupes[(rel, libelle)] = regroupes.get((rel, libelle), 0) + 1
    for (rel, libelle), n in regroupes.items():
        fois = f" ×{n}" if n > 1 else ""
        print(f"  [info] {rel} — {libelle}{fois} : présent sur ce poste, exclu du dépôt par .gitignore")
    if toleres:
        fichiers = sorted({t[2] for t in toleres})
        print(f"  ({len(toleres)} occurrence(s) dans {len(fichiers)} fichier(s) couvert(s) par .secrets-autorises)")
    print(f"Bilan : {len(trouves)} secret(s) détecté(s) hors exceptions")
    sys.exit(1 if trouves else 0)


if __name__ == "__main__":
    main()
