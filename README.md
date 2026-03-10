# PhishAnalyzer - Advanced Email Forensics Tool

🛡️ **PhishAnalyzer** est un outil complet d'analyse forensique d'emails pour la détection de phishing et la sécurité email.

## 🚀 Fonctionnalités

### Analyse Complète
- **Formats supportés** : MSG (Outlook) et EML
- **Extraction métadonnées** : expéditeur, destinataires, sujet, en-têtes complets
- **Analyse de contenu** : IPs, emails, URLs, domaines
- **Détection attachements** : extraction automatique des fichiers joints
- **Analyse X-Headers** : traçabilité des en-têtes personnalisés

### API Web Moderne
- **FastAPI** : serveur RESTful avec documentation Swagger
- **Score de risque** : évaluation automatique LOW/MEDIUM/HIGH/CRITICAL
- **Cache mémoire** : stockage temporaire des analyses
- **CORS** : compatibilité extension navigateur

### Extension Navigateur
- **Intégration Gmail/Outlook** : boutons d'analyse directs
- **Interface moderne** : popup avec résultats en temps réel
- **Multi-navigateurs** : Chrome, Edge, Firefox

## 📦 Installation

### Prérequis
- Python 3.7+
- Navigateur web moderne

### Installation Automatisée
```bash
python setup.py
```

### Installation Manuelle
```bash
pip install -r requirements.txt
python api_server.py
```

## 🔧 Utilisation

### 1. Démarrer le Serveur API
```bash
# Via le script
start_api_server.bat

# Ou directement
python api_server.py
```

Le serveur démarre sur : http://localhost:8000

### 2. Documentation API
- **Swagger UI** : http://localhost:8000/docs
- **ReST API** : endpoints pour analyse email

### 3. Extension Navigateur
1. Ouvrir `chrome://extensions/` (Chrome/Edge) ou `about:debugging` (Firefox)
2. Activer "Developer mode"
3. "Load unpacked" → sélectionner dossier `browser-extension/`
4. Ajouter les icônes dans `browser-extension/icons/`

## 📊 Analyse

### Pipeline d'Analyse

1. **Détection Format** : MSG vs EML
2. **Extraction Métadonnées** :
   - MSG : `extract_msg` library
   - EML : `email` library standard
3. **Parsing Contenu** avec regex :
   - IPs : `\b(?:\d{1,3}\.){3}\d{1,3}\b`
   - Emails : `[\w\.-]+@[\w\.-]+`
   - URLs : `https?://[^\s<>"\'\)]+`
4. **Calcul Score Risque** :
   - URLs suspectes : +20 points
   - IPs publiques : +15 points
   - Attachements dangereux : +30 points
   - En-têtes suspects : +25 points

### Niveaux de Risque
- **LOW** (0-30) : Faible menace
- **MEDIUM** (31-60) : Suspicion modérée
- **HIGH** (61-80) : Forte probabilité de phishing
- **CRITICAL** (81+) : Menace immédiate

## 🛠️ Architecture

```
PhishAnalyzer/
├── PhishAnalyzer.py          # Core analysis engine
├── api_server.py             # FastAPI web server
├── setup.py                  # Installation automation
├── requirements.txt          # Python dependencies
├── start_api_server.bat      # Quick start script
├── browser-extension/        # Chrome/Firefox extension
│   ├── manifest.json
│   ├── popup.html
│   ├── content.js
│   └── icons/
├── Extracted_Attachments/    # Auto-generated
└── extension_install_guide.html
```

## 🔍 API Endpoints

### POST /analyze
Analyse un email pour détection phishing

**Request:**
```json
{
  "subject": "Urgent: Account Verification",
  "sender": "suspicious@fake.com",
  "body": "Click here: http://bit.ly/suspicious",
  "headers": "X-Mailer: Microsoft Outlook Express"
}
```

**Response:**
```json
{
  "success": true,
  "analysis_id": "uuid-string",
  "risk_score": 65,
  "risk_level": "HIGH",
  "findings": {
    "ip_addresses": ["192.168.1.1"],
    "email_addresses": ["victim@company.com"],
    "urls": ["http://bit.ly/suspicious"],
    "attachments": [],
    "header_analysis": {
      "suspicious_headers": ["X-Mailer:.*Microsoft.*Outlook.*Express"],
      "hop_count": 3
    }
  },
  "timestamp": "2024-01-01T12:00:00"
}
```

### GET /results/{analysis_id}
Récupère les résultats d'une analyse

### DELETE /results/{analysis_id}
Supprime les résultats d'analyse

## 🎯 Cas d'Usage

### Sécurité Entreprise
- **SOC/CSIRT** : analyse rapide d'emails suspects
- **Formation** : démonstration techniques phishing
- **Forensique** : investigation incidents email

### Usage Personnel
- **Protection** : vérification emails douteux
- **Éducation** : sensibilisation phishing
- **Recherche** : étude techniques d'attaque

## 🔒 Sécurité

- **Local only** : pas d'envoi de données externes
- **Temporaire** : analyses supprimées automatiquement
- **Privacy** : aucun tracking ou télémétrie

## 📝 Développement

### Dependencies
```txt
fastapi==0.104.1
uvicorn==0.24.0
pydantic==2.5.0
colorama==0.4.6
extract-msg==0.41.1
python-multipart==0.0.6
```

### Contributing
1. Fork le projet
2. Créer branche feature
3. Submit PR

## 📄 Licence

MIT License - Usage libre et open source

## 🆘 Support

- **Documentation** : http://localhost:8000/docs
- **Guide Installation** : `extension_install_guide.html`
- **Issues** : GitHub repository

---

**⚠️ Important** : Toujours garder le serveur API actif lors de l'utilisation de l'extension navigateur !
