# phplist-adminIMAPauth

Une extension pour permettre l'authentification des administrateurs de phpList via IMAP.
Si le serveur IMAP est injoignable ou que le compte ne fonctionne pas en IMAP, l'authentification est ensuite réalisée sur la base des comptes locaux.

La liste des comptes IMAP autorisés fait partie de l'ensemble des administrateurs.
L'interface classique de gestion des administrateurs suffit.
Le "login name" de l'administrateur est son email.

Pour que les données "loginname" et "modifiedby" puissent être enregistrées, la taille de ces champs (table admin) est portée à 120 caractères.

Avant d'utiliser ce plugin, vous devez disposer d'un compte super-administrateur local.
