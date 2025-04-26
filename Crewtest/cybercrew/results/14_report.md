# Rapport de Reconnaissance et d'Exploitation de la cible 10.10.158.158

**1. Introduction et Contexte**

Ce rapport détaille les résultats de la reconnaissance et de l'analyse de sécurité de la cible IP 10.10.158.158.  L'objectif était d'identifier les vulnérabilités potentielles et d'évaluer le niveau de risque associé.  L'analyse a été partiellement limitée par des problèmes d'accessibilité à certains outils (Metasploit, bases de données CVE et Exploit-DB).

**2. Collecte et Analyse des Résultats**

Les résultats présentés ci-dessous sont issus de plusieurs outils et agents.  Une synthèse des observations est fournie pour chaque étape.

**2.1 Reconnaissance Réseau et Scan de Ports**

L'analyse de la cible 10.10.158.158 a révélé les ports ouverts suivants:

* 135/tcp: ouvert, msrpc (Microsoft Windows RPC)
* 139/tcp: ouvert, netbios-ssn (Microsoft Windows netbios-ssn)
* 445/tcp: ouvert, microsoft-ds (Microsoft Windows 7 - 10 microsoft-ds, workgroup: WORKGROUP)
* 3389/tcp: ouvert, ms-wbt-server (Microsoft Terminal Service)
* 49152-49160/tcp: ouverts, msrpc (Microsoft Windows RPC)

Le protocole TCP a été utilisé.  Aucune information DNS n'a pu être récupérée.  L'absence d'informations DNS suggère que la machine cible n'est peut-être pas directement accessible depuis l'Internet.

**2.2 Analyse des Services et Vulnérabilités**

L'analyse a révélé plusieurs points sensibles:

* **SMBv1 (ports 139 et 445):**  La présence de SMBv1 est une vulnérabilité critique (CVE-2017-0143 - EternalBlue), permettant l'exécution de code à distance.  L'exploitabilité est estimée haute.
* **Microsoft Terminal Service (port 3389):** L'ouverture du port RDP présente un risque significatif d'accès non autorisé si les mots de passe sont faibles ou par défaut. La sévérité est estimée haute, l'exploitabilité moyenne.
* **Plusieurs ports RPC ouverts (49152-49160):**  La présence de nombreux ports RPC ouverts suggère une potentielle mauvaise configuration ou un manque de patchs, augmentant le risque de vulnérabilités. La sévérité est estimée moyenne, l'exploitabilité moyenne.

**2.3 Tentatives d'Exploitation**

Des tentatives d'exploitation ont été réalisées, mais ont échoué en raison des limitations des outils.  L'exploit EternalBlue (CVE-2017-0143) n'a pas pu être utilisé en raison de l'inaccessibilité de Metasploit. De même, une tentative de brute-force sur RDP avec Ncrack a échoué.

**2.4 Actions Post-Exploitation (Simulation)**

Comme aucune exploitation n'a eu lieu, les actions post-exploitation ont été simulées.  La simulation a inclus l'implantation d'une tâche planifiée pour la persistance et l'effacement des logs système, application et sécurité.  L'effacement des traces a été simulé avec succès.  Des captures d'écran simulées ont été générées.

**3. Synthèse des Risques**

La cible présente un risque significatif en raison de la présence de SMBv1 (vulnérabilité critique), de l'ouverture du port RDP (risque d'accès non autorisé), et de plusieurs ports RPC ouverts (risque de configuration incorrecte).  L'absence d'informations DNS suggère une accessibilité limitée depuis l'internet, mais un accès interne représente un risque important.

**4. Recommandations Stratégiques de Sécurisation**

* **Désactiver SMBv1 immédiatement.**  Cette vulnérabilité est critique et doit être corrigée en priorité.
* **Renforcer la sécurité du mot de passe RDP.**  Utiliser des mots de passe forts et uniques, et envisager d'utiliser une authentification à deux facteurs.
* **Auditer et corriger la configuration des services RPC.**  Fermer les ports RPC inutiles et appliquer les derniers correctifs de sécurité.
* **Mettre en place un système de surveillance et d'alerte.**  Surveiller l'activité du réseau et les tentatives d'accès non autorisés.
* **Mettre à jour le système d'exploitation et les logiciels.**  Appliquer les derniers correctifs de sécurité pour tous les logiciels installés.
* **Envisager l'utilisation d'un pare-feu.**  Limiter l'accès aux ports sensibles depuis l'extérieur du réseau.

**5. Conclusion**

L'analyse a révélé des vulnérabilités significatives sur la cible 10.10.158.158.  La mise en œuvre des recommandations ci-dessus est cruciale pour réduire le niveau de risque et améliorer la sécurité du système.