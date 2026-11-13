# Laboratoire Valmont — sécuriser un système de bout en bout

TP intégrateur du cours **« La cryptographie »** (Diginamic, RNCP40573 — Expert en
informatique et systèmes d'information). Le scénario : un laboratoire d'analyses
médicales **fictif**, avec un portail patient, une base MySQL, des sauvegardes et un
export nocturne vers un hôpital partenaire, à sécuriser de la donnée au repos jusqu'à
la réponse à une fuite de clé.

Chaque étape est **exécutée et prouvée** : les sorties réelles sont dans les dossiers
`preuves/`. La note de synthèse est dans [`RAPPORT.md`](RAPPORT.md).

| Étape | Sujet | Ce qui est démontré |
| --- | --- | --- |
| [01](01-besoins.md) | Besoins → primitives | 6 éléments, garantie recherchée, primitive retenue et primitives écartées |
| [02](02-au-repos/) | Données au repos | AES-256-GCM (7/7 altérations refusées) ; colonne NIR chiffrée + index aveugle HMAC, migration transactionnelle |
| [03](03-echange-de-cle/) | Échange de clé | Chiffrement hybride RSA-3072-OAEP + AES-GCM, vérifié par openssl |
| [04](04-signature/) | Hachage et signature | Ed25519 sur les comptes rendus (5/5 falsifications rejetées) ; mots de passe PBKDF2 |
| [05](05-cles-et-secrets/) | Clés et secrets | Carte de 12 clés et 9 secrets, plan de sortie des secrets du code, gitleaks + CI |
| [06](06-tls/) | TLS | Configuration Nginx (TLS 1.2/1.3, AEAD, HSTS, redirection) : 14/14 contrôles, contre-épreuve à 9 échecs |
| [07](07-flux/) | Flux et RGPD | Minimisation avant l'entrepôt, k-anonymat mesuré (pseudonymiser ≠ anonymiser) |
| [08](08-incident/) | Fuite de clé | Rotation à deux clés sans interruption, panne et reprise, preuve de complétude, coût du chiffrement |

**Stack :** Python 3 (`cryptography`, `PyMySQL`), MySQL 8.4, Nginx 1.27, Docker Compose,
OpenSSL, gitleaks, GitHub Actions.

**Lancer une étape :** chaque dossier a son `README.md`, avec les commandes PowerShell une
par une. Les clés sont toujours générées localement (`02-au-repos/generer_cle.py`) et
lues dans des variables d'environnement : aucune clé privée ni secret n'est versionné.

> Toutes les données (patients, numéros de sécurité sociale, résultats d'analyses) sont
> **fictives** : elles proviennent de l'échantillon fourni par le sujet.

*Badr-Eddine Tirari — novembre 2026*
