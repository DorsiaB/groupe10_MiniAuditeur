# Rapport MiniAuditeur

**Date de l'audit :** 2026-07-08_14-30-54

**Cible analysée :** example.com

## Résumé global du risque

- Niveau global du risque : Faible
- Ports ouverts détectés : 5
- Niveau de sécurité HTTP : Faible
- Certificat TLS : valide

## Scan des ports TCP

### Ports ouverts

- Port 80 : OPEN
- Port 110 : OPEN
- Port 119 : OPEN
- Port 143 : OPEN
- Port 443 : OPEN

### Ports filtrés

359 ports filtrés.

## Analyse TLS

- Certificat : Valide
- Expiration : 2026-08-29
- Jours restants : 52
- État : OK

## Analyse des en-têtes HTTP

- Strict-Transport-Security : Absent
- Content-Security-Policy : Absent
- X-Frame-Options : Absent
- X-Content-Type-Options : Absent

Score sécurité : 0/4
Niveau : Faible

## Recommandations

- Activer le header Strict-Transport-Security (HSTS).
- Ajouter une Content-Security-Policy pour limiter les attaques XSS.
- Ajouter X-Frame-Options pour réduire les risques de clickjacking.
- Ajouter X-Content-Type-Options: nosniff.
- Le serveur HTTP est exposé. Vérifier la configuration web et privilégier HTTPS.