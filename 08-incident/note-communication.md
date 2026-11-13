# Note de communication — à diffuser à H+1

**À :** équipe technique (développeurs, administration système), direction, DPO
**Copie :** RSSI du centre hospitalier partenaire (version partenaire en bas de page)
**Objet :** [INCIDENT SÉCURITÉ] Clé de chiffrement de l'archive des exports exposée : rotation en cours

---

Bonjour à tous,

Ce matin, la clé qui chiffre l'**archive des exports nocturnes** (K3) a été trouvée dans
un dépôt de code public. Nous la considérons comme compromise.

**Ce qui est déjà fait :**
- l'ancienne clé ne peut plus rien chiffrer, et une nouvelle clé l'a remplacée pour tous les nouveaux exports ;
- le dépôt n'est plus public.

**Ce qui est en cours :** le ré-chiffrement de l'archive avec la nouvelle clé, cette
nuit, sans interruption du portail. L'ancienne clé sera détruite demain, une fois
prouvé que plus rien ne l'utilise.

**Ce qui n'est pas touché :** les exports envoyés au CHU (chiffrés avec une clé
différente à chaque envoi), les numéros de sécurité sociale en base, les signatures des
comptes rendus et les mots de passe du portail.

**Ce que nous attendons de vous :**
1. **Ne pas** redémarrer, ni reconfigurer à la main, un serveur ou un traitement qui utilise les exports : la nouvelle configuration est distribuée par le coffre de secrets.
2. Signaler **immédiatement** à l'administrateur système tout serveur, script ou poste qui aurait une copie locale de la clé ou des exports (y compris les serveurs de secours et les environnements de test).
3. Ne rien publier ni commenter à l'extérieur : la communication externe passe par la direction et le DPO.

L'analyse d'exposition (depuis quand la clé était publique, et si l'archive a pu être
lue) sera terminée ce soir. Le DPO décidera alors de la notification à la CNIL, sous
72 heures. Un point d'avancement sera envoyé demain à 9 h, puis un retour d'expérience
dans une semaine.

Contact pendant l'incident : l'administrateur système (astreinte).

---

**Version partenaire (RSSI du CHU) :** une clé interne au laboratoire, servant
uniquement à l'archivage de nos exports, a été exposée et est en cours de remplacement.
Les fichiers que vous recevez sont chiffrés avec une clé de session propre à chaque
envoi et votre clé publique : **ils ne sont pas concernés**, et aucune action n'est
attendue de votre part. Nous vous tiendrons informés de la clôture de l'incident.
