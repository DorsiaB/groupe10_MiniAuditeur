# MiniAuditeur

## Présentation du projet

MiniAuditeur est un outil d'audit de sécurité défensif développé en Python dans le cadre du cours **Python pour la cybersécurité et le pentesting**.

L'objectif du projet est de créer un mini-auditeur en ligne de commande capable d'analyser l'exposition d'une cible autorisée, d'identifier certains éléments de sécurité et de générer un rapport exploitable.

L'outil fonctionne uniquement dans un cadre légal et pédagogique : il réalise des analyses passives et en lecture seule, sans exploitation de vulnérabilités ni modification des systèmes audités.

---

# Fonctionnalités

## Scanner de ports TCP

Le module de scan permet :

* d'analyser une cible sous forme d'adresse IP ou de nom d'hôte ;
* de scanner une plage de ports configurable ;
* d'utiliser plusieurs threads afin d'améliorer les performances ;
* de distinguer les états suivants :

  * OPEN (port ouvert)
  * CLOSED (port fermé)
  * FILTERED (port filtré ou inaccessible)

---

## Analyse des en-têtes HTTP

Le module HTTP récupère plusieurs en-têtes de sécurité importants :

* Strict-Transport-Security (HSTS)
* Content-Security-Policy (CSP)
* X-Frame-Options
* X-Content-Type-Options

Un score de sécurité est ensuite calculé sur 4 points selon la présence des bonnes pratiques.

Niveaux possibles :

* Bon
* Moyen
* Faible

---

## Vérification TLS (fonctionnalité bonus)

Le module TLS permet :

* de vérifier la présence d'un certificat HTTPS ;
* de récupérer sa date d'expiration ;
* de calculer le nombre de jours restants ;
* d'indiquer un état :

  * OK
  * ATTENTION
  * CRITIQUE
  * EXPIRE

---

## Génération de rapport

L'outil génère automatiquement un rapport Markdown contenant :

* la date de l'audit ;
* la cible analysée ;
* un résumé global du risque ;
* les résultats du scan de ports ;
* l'analyse HTTP ;
* l'analyse TLS ;
* les recommandations associées.

Les rapports sont enregistrés dans le dossier :

```text
reports/
```

---

# Architecture du projet

```text
groupe10_MiniAuditeur/

├── main.py
├── requirements.txt
├── README.md
├── .gitignore

├── modules/
│   ├── port_scanner.py
│   ├── http_analyzer.py
│   ├── tls_checker.py
│   ├── report_generator.py
│   └── recommendations.py

├── reports/
│   └── exemple_rapport.md

└── tests/
```

Description des modules :

| Fichier             | Rôle                                              |
| ------------------- | ------------------------------------------------- |
| main.py             | Interface CLI et orchestration des modules        |
| port_scanner.py     | Scan TCP multi-thread                             |
| http_analyzer.py    | Analyse des en-têtes HTTP et calcul du score      |
| tls_checker.py      | Vérification des certificats TLS                  |
| report_generator.py | Création des rapports Markdown                    |
| recommendations.py  | Génération de recommandations selon les résultats |

---

# Installation

## Prérequis

* Python 3.10 ou supérieur
* Git

---

## Création de l'environnement virtuel

Depuis le dossier du projet :

```bash
python -m venv .venv
```

Activation :

### Windows

```powershell
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
```

---

## Installation des dépendances

```bash
pip install -r requirements.txt
```

---

# Utilisation

## Scanner les ports d'une cible

Exemple :

```bash
python main.py scan scanme.nmap.org --start 1 --end 1024
```

---

## Analyser les en-têtes HTTP

Exemple :

```bash
python main.py http https://example.com
```

Résultat :

* récupération des headers de sécurité ;
* calcul du score ;
* affichage du niveau de sécurité.

---

## Vérifier un certificat TLS

Exemple :

```bash
python main.py tls example.com
```

---

## Lancer un audit complet

Exemple :

```bash
python main.py audit scanme.nmap.org --url https://example.com
```

Cette commande exécute :

* un scan de ports ;
* une analyse HTTP ;
* une vérification TLS ;
* une génération de rapport.

---

# Dépendances

Les principales dépendances utilisées sont :

* `* `requests` : récupération des informations HTTP.
* `beautifulsoup4` : dépendance prévue pour de futures évolutions d'analyse web.

Les autres modules utilisés proviennent de la bibliothèque standard Python.
---

# Cibles utilisées pour les tests

Dans le cadre du projet, les tests ont été réalisés uniquement sur des cibles autorisées :

## scanme.nmap.org

Utilisé pour :

* tester le scanner de ports TCP.

Cette cible est fournie par le projet Nmap pour l'entraînement au scan.

## example.com

Utilisé pour :

* tester l'analyse des en-têtes HTTP ;
* tester la vérification TLS.

---

# Cadre légal et éthique

MiniAuditeur est un outil d'audit défensif.

Il ne réalise :

* aucune exploitation ;
* aucune modification de la cible ;
* aucun test offensif ;
* aucune tentative d'accès non autorisé.

L'utilisation doit être limitée aux systèmes :

* appartenant à l'utilisateur ;
* explicitement autorisés ;
* ou fournis pour l'entraînement.

---

# Limites connues

* Les résultats dépendent de la disponibilité réseau de la cible.
* Certains services peuvent bloquer ou ralentir les connexions.
* L'analyse HTTP dépend de la disponibilité du serveur web.
* Le scanner identifie uniquement l'exposition des ports TCP, sans analyse approfondie des services.

---

# Auteur

Projet réalisé dans le cadre du cours :

**Python pour la cybersécurité et le pentesting**
