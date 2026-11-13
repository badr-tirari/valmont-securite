"""Coût du chiffrement : temps de lecture avec et sans chiffrement (point 5 de l'étape 8).

Trois mesures, chacune répétée et résumée par sa médiane (moins sensible aux à-coups du système) :
    A. un export nocturne réel (760 octets) : lire le clair vs lire + déchiffrer AES-256-GCM
    B. un export volumineux synthétique (≈ 10 Mo, 100 000 lignes) : idem, débit en Mo/s
    C. la colonne NIR : déchiffrer 10 000 valeurs une par une (coût par ligne d'une requête applicative)
Les fichiers de mesure sont créés dans un dossier temporaire, puis supprimés.

Usage :
    python mesure_cout.py
"""

import os
import statistics
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SOURCE = Path(__file__).parent.parent / "02-au-repos" / "donnees" / "export_2026-11-05.csv"
CLE = AESGCM.generate_key(bit_length=256)
AES = AESGCM(CLE)


def chiffrer(d: bytes) -> bytes:
    n = os.urandom(12)
    return n + AES.encrypt(n, d, None)


def mediane(fonction, repetitions: int) -> float:
    durees = []
    for _ in range(repetitions):
        t0 = time.perf_counter()
        fonction()
        durees.append(time.perf_counter() - t0)
    return statistics.median(durees)


def comparer(libelle: str, clair: Path, chiffre: Path, repetitions: int) -> None:
    lire = lambda: clair.read_bytes()
    lire_dechiffrer = lambda: (lambda c: AES.decrypt(c[:12], c[12:], None))(chiffre.read_bytes())
    lire(); lire_dechiffrer()                                    # préchauffage (cache disque)
    t_clair = mediane(lire, repetitions)
    t_chiffre = mediane(lire_dechiffrer, repetitions)
    taille = clair.stat().st_size
    surcout = t_chiffre - t_clair
    print(f"{libelle} ({taille / 1e6:.3f} Mo, médiane de {repetitions} lectures)")
    print(f"  lecture du clair              : {t_clair * 1e3:9.3f} ms")
    print(f"  lecture + déchiffrement GCM   : {t_chiffre * 1e3:9.3f} ms")
    print(f"  surcoût                       : {surcout * 1e3:9.3f} ms  (×{t_chiffre / t_clair:.1f})")
    if taille > 1e6:
        print(f"  débit de déchiffrement        : {taille / 1e6 / max(surcout, 1e-9):9.0f} Mo/s")


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        # A. export réel
        a_clair, a_chiffre = d / "a.csv", d / "a.chiffre"
        a_clair.write_bytes(SOURCE.read_bytes())
        a_chiffre.write_bytes(chiffrer(a_clair.read_bytes()))
        comparer("A. Export nocturne réel", a_clair, a_chiffre, 2000)
        print()
        # B. export volumineux
        lignes = SOURCE.read_text(encoding="utf-8").splitlines()
        corps = "\n".join([lignes[0]] + [lignes[1 + i % 7] for i in range(100_000)]) + "\n"
        b_clair, b_chiffre = d / "b.csv", d / "b.chiffre"
        b_clair.write_bytes(corps.encode())
        b_chiffre.write_bytes(chiffrer(b_clair.read_bytes()))
        comparer("B. Export volumineux synthétique (100 000 lignes)", b_clair, b_chiffre, 50)
        print()
        # C. colonne NIR
        valeurs = [chiffrer(str(1_850_575 * 10**8 + i).encode()) for i in range(10_000)]   # 15 chiffres, comme un NIR
        t = mediane(lambda: [AES.decrypt(v[:12], v[12:], None) for v in valeurs], 20)
        print("C. Colonne NIR — 10 000 valeurs déchiffrées une à une (médiane de 20 passes)")
        print(f"  total                         : {t * 1e3:9.1f} ms")
        print(f"  par ligne                     : {t / 10_000 * 1e6:9.2f} µs")
    print()
    print("Lecture : le surcoût par fichier ou par ligne se compte en microsecondes ; il est négligeable")
    print("devant un aller-retour réseau vers la base (≈ 0,5 à 1 ms) ou l'affichage d'une page.")
    print("Le vrai coût du chiffrement n'est pas le calcul : c'est la gestion des clés et ce qu'on")
    print("perd côté requêtes (plus de LIKE, de tri ni de jointure sur une colonne chiffrée, étape 2).")


if __name__ == "__main__":
    main()
