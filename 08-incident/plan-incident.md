# Étape 8 — Fuite de la clé de l'export nocturne : plan de réponse

*Chapitres 06 et 12. Scénario : la clé **K3** (`VALMONT_CLE_EXPORT`, carte des clés),
qui chiffre l'archive des exports nocturnes, est retrouvée dans un dépôt public.
À partir de cet instant, on suppose qu'elle est entre de mauvaises mains.*

## 0. Ce que la clé protège, et ce qu'elle ne protège pas

| Élément | Chiffré par K3 ? | Exposé par la fuite ? |
| --- | --- | --- |
| Archive des exports nocturnes chez Valmont (MinIO) et ses sauvegardes | **Oui** | **Oui**, pour qui accède aussi aux fichiers. Les sauvegardes sont en plus chiffrées par K10 (SSE-KMS) : il faut les deux |
| Exports envoyés au CHU (étape 3) | Non : clé de session **neuve à chaque export**, enveloppée par RSA | **Non**. La conception hybride limite l'impact de la fuite |
| Colonne NIR en base (étape 2) | Non : clé K1 | Non (une clé = un usage) |
| Signatures des comptes rendus (étape 4) | Non : clé K7 du biologiste | Non |

## 1. Chronologie et responsables

| Quand | Action | Qui | Ordre du chapitre 12 |
| --- | --- | --- | --- |
| **H+0** | Alerte (garde-fou n° 1, signalement externe…). Ouverture d'un incident, journal de crise | Celui qui détecte → ADM | — |
| **H+0:15** | **Isoler** : K3-v1 passe en **lecture seule** dans le Coffre (elle ne peut plus rien chiffrer) ; tirage de **K3-v2**, qui devient la clé active ; redéploiement de la configuration à **tous** les consommateurs | ADM + DEV-L (quatre yeux) | 1. Révoquer |
| H+0:30 | Rendre le dépôt privé, révoquer les jetons qui y donnaient accès, **puis** nettoyer l'historique (`git filter-repo`) : on nettoie **après** avoir rendu la clé inopérante pour l'avenir | DEV-L | 1. Révoquer |
| **H+1** | **Évaluer l'exposition** : depuis quand la clé était publique (`git log`), forks et clones, accès anonymes au bucket d'archive (journaux MinIO), quelles dates d'export étaient chiffrées par K3-v1 | ADM, DEV-L, DPO | 2. Évaluer |
| H+1 | Information de la direction et du DPO ; ouverture du registre des violations | ADM → DIR, DPO | 4. Notifier (interne) |
| **H+2 → J+1** | **Ré-chiffrer** l'archive par lots, la nuit, hors des heures de pointe (§ 2) | DEV-L | 3. Ré-chiffrer |
| ≤ **H+72** | Si l'évaluation conclut à un risque pour les personnes : **notification à la CNIL** (RGPD, art. 33) ; si le risque est élevé, information des patients concernés (art. 34) | DPO, DIR | 4. Notifier |
| **J+1** | **Preuve de complétude** (§ 3), puis **retrait** de K3-v1 : destruction de la version dans le Coffre, tracée | ADM, validé par DIR | — |
| J+1 → J+30 | Sauvegardes : ré-chiffrer ou détruire celles qui contiennent des fichiers K3-v1, selon leur verrouillage (§ 4) | ADM | — |
| **J+7** | Retour d'expérience : comment la clé est arrivée dans le dépôt, et quel garde-fou a manqué | Toute l'équipe | — |

## 2. Rotation sans interruption : la période à deux clés

```mermaid
gantt
    title Rotation de K3 — les deux clés coexistent, l'ancienne ne fait plus que lire
    dateFormat HH:mm
    axisFormat %H:%M
    section K3-v1 (compromise)
    Chiffre et déchiffre (avant la fuite)        : 00:00, 01:00
    Lecture seule : relit l'archive pendant la migration : crit, 01:00, 06:00
    Retirée après la preuve de complétude          : milestone, 06:00, 0m
    section K3-v2 (neuve)
    Active : chiffre tous les nouveaux exports     : 01:00, 08:00
    section Archive
    Ré-chiffrement par lots (nuit)                 : 01:30, 05:30
    Preuve de complétude                           : 05:30, 06:00
```

| Principe | Mise en œuvre (`trousseau.py`, `rotation.py`) |
| --- | --- |
| Chaque fichier dit quelle clé l'a produit | Format v2 : en-tête `VLM2 ‖ identifiant de clé`, **authentifié** (AAD), ce qui empêche de le falsifier ; les fichiers de l'étape 2, sans en-tête, sont reconnus comme `k3-v1` |
| La clé compromise est isolée | `VALMONT_K3_LECTURE=k3-v1` : elle déchiffre encore, elle ne chiffre **jamais**. Seule `VALMONT_K3_ACTIVE` chiffre |
| Ré-chiffrement progressif | `rechiffrer --lot N` : déchiffrer → chiffrer avec K3-v2 → **relire et comparer** → remplacement **atomique** (`os.replace`). À chaque instant, un fichier est soit l'ancien, soit le nouveau, jamais un mélange |
| Traçabilité | `journal_rotation.csv` (fichier, ancienne et nouvelle clé, SHA-256 du clair) et `journal_cles.log` (chaque usage de chaque clé, sans jamais la valeur) |

**Consommateurs couverts** (prouvé à chaque phase par `rotation.py consommateurs`) :

| Consommateur | Usage de K3 | Pendant la rotation | Action |
| --- | --- | --- | --- |
| **Traitement de nuit** | Chiffre l'export du jour | Chiffre avec K3-v2 dès H+0:15 | Nouvelle configuration injectée par le Coffre ; vérifier **chaque** serveur, y compris celui de secours (§ 3, cas réel) |
| **Application du portail** | Relit un export pour le téléchargement d'un compte rendu | Lit indifféremment v1 ou v2 grâce à l'en-tête | Trousseau à deux clés jusqu'au retrait |
| **Partenaire (CHU)** | **Aucun** : il reçoit une enveloppe RSA par export (étape 3) | Non concerné | **Informé quand même** (§ 5) : il doit savoir que la fuite n'expose pas ses fichiers, et pourquoi |
| **Entrepôt** (job de minimisation) | Relit l'archive du mois | Lit l'archive mixte | Trousseau à deux clés jusqu'au retrait |

## 3. Preuve de complétude : comment savoir que plus rien n'utilise l'ancienne clé

`rotation.py preuve-completude archive k3-v1` exige **trois preuves indépendantes**.
Il suffit qu'une seule manque pour que le verdict soit « ne pas retirer » :

| # | Preuve | Ce qu'elle attrape |
| --- | --- | --- |
| 1 | **Inventaire des en-têtes** : 0 fichier dont l'en-tête désigne `k3-v1` | Un lot oublié, une migration interrompue |
| 2 | **Journal d'usage** : toute écriture par `k3-v1` **après** l'isolement est signalée, et doit avoir été ré-chiffrée ensuite | Un **consommateur mal configuré** qui continue d'écrire avec l'ancienne clé |
| 3 | **Test de retrait** : tout relire avec un trousseau **sans** `k3-v1`, et comparer le SHA-256 du clair à celui noté avant la migration | Un fichier illisible sans l'ancienne clé, ou un contenu altéré par la migration |

**Cas réel joué dans la preuve** (phase 3) : un serveur de secours a gardé l'ancienne
configuration et chiffre l'export du jour avec `k3-v1` **après** l'isolement. La preuve
de complétude échoue sur ses trois critères et désigne le fichier fautif. Une fois le
serveur corrigé et le fichier ré-chiffré, elle passe, et le retrait est autorisé.

## 4. Repli : si la rotation échoue en cours de route

| Situation | Ce qui se passe | Repli |
| --- | --- | --- |
| **Panne brutale** au milieu d'un lot (prouvé, phase 2 bis) | Le fichier en cours existe en `.tmp`, l'original est **intact** (remplacement atomique pas encore fait) | Relancer `rechiffrer` : le `.tmp` est abandonné, la migration reprend où elle s'était arrêtée. Le service n'est pas interrompu, car les deux clés lisent |
| La relecture d'un fichier ré-chiffré ne correspond pas | Arrêt immédiat, statut `ECHEC_RELECTURE` au journal, **original conservé** | Analyse avant toute reprise |
| Un consommateur échoue après la bascule | Les deux clés sont encore dans le trousseau : il suffit de corriger sa configuration | Pas de retour en arrière nécessaire |
| **K3-v2 elle-même** est perdue ou suspecte avant la fin | — | **Ne jamais revenir à K3-v1**, qui est compromise. Tirer **K3-v3** active ; v1 et v2 en lecture ; le même outil migre les deux vers v3 |
| Le Coffre est indisponible | Les consommateurs gardent les clés en mémoire (bail de l'agent Vault) | Rotation suspendue, service maintenu ; reprise au retour du Coffre |
| **Sauvegardes verrouillées** (verrouillage d'objets MinIO) contenant des fichiers K3-v1 | Impossible de les ré-chiffrer ou de les détruire avant l'échéance | Risque résiduel accepté et **documenté** : ces objets sont aussi chiffrés par K10 (SSE-KMS), l'attaquant aurait besoin des deux clés. Destruction à l'échéance, tracée |

Point de non-retour : la **destruction** de K3-v1 dans le Coffre. Elle n'a lieu
qu'après la preuve de complétude **et** la validation de la direction. Un fichier v1
retrouvé ensuite (vieille sauvegarde) est refusé par le trousseau. Il est alors détruit,
ou ré-chiffré depuis une copie de la clé conservée sous scellé (bris de glace), si la
politique en prévoit une.

## 5. Note de communication

Voir [`note-communication.md`](note-communication.md) : message aux équipes, à
envoyer à H+1.

## 6. Coût du chiffrement : le compromis performance / protection

Mesures réelles (`mesure_cout.py`), en médianes, sur deux machines :

| Mesure | Linux (`08-mesure-cout.txt`) sans → avec | Poste de cours Windows / OneDrive (`09-execution-poste-badr.txt`) sans → avec | Surcoût |
| --- | --- | --- | --- |
| Lire un export nocturne réel (760 o) | 0,003 → 0,006 ms | 0,071 → 0,081 ms | **+ 3 à 10 µs** |
| Lire un export de 10 Mo (100 000 lignes) | 0,87 → 3,19 ms | 3,20 → 9,63 ms | **+ 2,3 à 6,4 ms** (1,5 à 4 Go/s) |
| Déchiffrer un NIR en base | 0,79 µs / ligne | 0,77 µs / ligne | 10 000 lignes : ≈ 8 ms |

Sur le poste Windows, la lecture du **clair** est 20 fois plus lente que sous Linux
(dossier OneDrive, antivirus qui inspecte chaque ouverture), alors que le surcoût du
déchiffrement reste du même ordre : sur un vrai système, c'est l'entrée-sortie qui
domine, pas la cryptographie.
| *Pour comparaison : vérifier un mot de passe (PBKDF2, 100 000 itérations, étape 4)* | — | ≈ 25 à 95 ms | *lent **volontairement*** |

**Lecture du compromis.** En valeur relative, le déchiffrement multiplie le temps de
lecture d'un fichier déjà en cache (×2 à ×4). En valeur absolue, il coûte quelques
microsecondes par export et moins d'une microseconde par ligne, soit moins qu'un seul
aller-retour réseau vers la base (0,5 à 1 ms). La rotation de 35 fichiers a pris moins
d'une seconde. Le chiffrement symétrique n'est donc pas ce qui ralentit le portail. Ses
vrais coûts sont ailleurs :
- la gestion des clés, que cette étape illustre ;
- les fonctionnalités perdues sur les colonnes chiffrées : ni `LIKE`, ni tri, ni jointure ;
- la **seule** opération cryptographique lente du système, qui est **lente exprès** : le
  hachage des mots de passe, pour freiner une attaque hors ligne.
