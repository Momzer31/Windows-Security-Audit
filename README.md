Audit et Hardening Windows Security

Projet de sécurité avancée des systèmes Windows - M2 T1 Bloc 3

## Objectif
Auditer la configuration d'une machine Windows Server et proposer des pistes de remédiation conformes aux recommandations ANSSI et CIS Benchmarks.

## Résultats
- **Score de sécurité** : 42% (FAIBLE)
- **Problèmes détectés** : 17 issues (0 CRITIQUES, 11 MAJEURS, 6 MINEURS)
- **Vérifications effectuées** : 50+ checks ANSSI/CIS

##  Structure
- `Audit-Windows-Security-Complet.ps1` - Script d'audit automatisé (308 lignes)
- `generate_rapport_anssi_complet.ps1` - Script de génération du rapport (450+ lignes)
- `rapport_audit_anssi_complet.html` - Rapport HTML interactif
- `rapport_audit_anssi_complet.pdf` - Rapport PDF professionnel
- `Audit-*/` - Données brutes des audits (CSV, TXT, XML)

##  Remediations
Chaque trouvaille inclut :
- Description du problème
- Score CVSS
- Commande PowerShell de remédiation
- Explication détaillée

##  Normes utilisées
- ANSSI (Administration sécurisée AD, Journalisation Windows)
- CIS Benchmarks (Windows Server & Desktop)
- Microsoft Security Baseline

##  Utilisation
powershell
# Exécuter l'audit
powershell -ExecutionPolicy Bypass -File "Audit-Windows-Security-Complet.ps1"

# Générer le rapport
powershell -ExecutionPolicy Bypass -File "generate_rapport_anssi_complet.ps1"
