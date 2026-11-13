"""Preuve automatisée de l'échange hybride (aucun fichier écrit, tout en mémoire).

Contrôles :
    1. aller-retour : le partenaire retrouve l'export à l'identique ;
    2. la clé de session n'apparaît en clair dans aucun des deux fichiers transmis ;
    3. deux exports successifs → deux clés de session différentes, deux enveloppes différentes ;
    4. enveloppe altérée d'un octet → refusée ;
    5. fichier chiffré altéré d'un octet → refusé ;
    6. un tiers avec SA propre clé privée (interception) → ne peut pas ouvrir ;
    7. enveloppe du jour J recombinée avec le fichier du jour J+1 → refusée.

Usage :
    python test_echange.py ../02-au-repos/donnees/export_2026-11-05.csv
"""

import sys

from cryptography.hazmat.primitives.asymmetric import rsa

from echanger_cle import OuvertureRefusee, envelopper, ouvrir, TAILLE_RSA


def refuse(libelle, enveloppe, chiffre, cle_privee) -> bool:
    try:
        ouvrir(enveloppe, chiffre, cle_privee)
    except OuvertureRefusee:
        print(f"  [OK] {libelle} : refusé")
        return True
    print(f"  [ÉCHEC] {libelle} : accepté")
    return False


def main() -> None:
    chemin = sys.argv[1] if len(sys.argv) > 1 else "../02-au-repos/donnees/export_2026-11-05.csv"
    with open(chemin, "rb") as f:
        donnees = f.read()

    print(f"Génération des paires RSA-{TAILLE_RSA} (partenaire et attaquant)…")
    partenaire = rsa.generate_private_key(public_exponent=65537, key_size=TAILLE_RSA)
    attaquant = rsa.generate_private_key(public_exponent=65537, key_size=TAILLE_RSA)
    r = []

    env, chif, cle = envelopper(donnees, partenaire.public_key())

    print("1. Aller-retour")
    lu, cle_lue = ouvrir(env, chif, partenaire)
    ok = lu == donnees and cle_lue == cle
    print(f"  [{'OK' if ok else 'ÉCHEC'}] export identique ({len(lu)} octets), même clé de session")
    r.append(ok)

    print("2. La clé de session ne voyage pas en clair")
    ok = cle not in env and cle not in chif
    print(f"  [{'OK' if ok else 'ÉCHEC'}] les 32 octets de la clé absents de l'enveloppe et du chiffré")
    r.append(ok)

    print("3. Une clé de session neuve par export")
    env2, chif2, cle2 = envelopper(donnees, partenaire.public_key())
    ok = cle != cle2 and env != env2
    print(f"  [{'OK' if ok else 'ÉCHEC'}] clés et enveloppes différentes d'un export à l'autre")
    r.append(ok)

    print("4. Enveloppe altérée")
    e = bytearray(env); e[100] ^= 1
    r.append(refuse("1 bit inversé dans l'enveloppe", bytes(e), chif, partenaire))

    print("5. Fichier altéré")
    c = bytearray(chif); c[len(c) // 2] ^= 1
    r.append(refuse("1 bit inversé dans l'export chiffré", env, bytes(c), partenaire))

    print("6. Interception")
    r.append(refuse("ouverture avec la clé privée d'un tiers", env, chif, attaquant))

    print("7. Recombinaison")
    r.append(refuse("enveloppe de l'export 1 + fichier de l'export 2", env, chif2, partenaire))

    print(f"\nBilan : {sum(r)}/{len(r)} contrôles réussis")
    sys.exit(0 if all(r) else 1)


if __name__ == "__main__":
    main()
