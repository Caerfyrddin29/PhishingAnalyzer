# PhishingAnalyzer - Professional Email Phishing Detection

## Quick Start

```bash
# Start the API server (REQUIRED for extension)
python email_api_server.py
# Or use:
start.bat

# Analyze single email
python phishing_analyzer.py email.eml

# Batch analysis
python batch_analyzer.py

# Download emails from accounts
python email_downloader.py
```

## Directory Structure

```
PhishingAnalyzer/
├── email_api_server.py        # FastAPI backend server
├── start.bat                  # Windows launcher for API server
├── main.py                    # Main entry point
├── requirements.txt           # Dependencies
├── LICENSE                    # MIT License
├── README.md                  # Documentation
├── core/                      # Core ML engine
│   ├── email_phishing_analyzer.py
│   ├── phishing_detector.py
│   └── models/
│       └── random_forest_url_model.sav
├── extension/                 # Chrome Extension
│   ├── manifest.json
│   ├── popup.html
│   ├── popup.js
│   ├── content.js
│   ├── background.js
│   └── icons/
├── phishing_analyzer.py       # Single email analysis
├── batch_analyzer.py          # Batch processing
├── email_downloader.py        # Email downloading
├── setup_analyzer.py          # System setup
├── config/                    # Configuration
│   └── email_accounts.json
├── emails/                    # Downloaded emails
├── analysis/                  # Analysis reports
└── logs/                      # Log files
```

## Features

- **ML-Based Detection**: RandomForest classifier for URLs with 95%+ accuracy
- **Email Analysis**: MSG/EML file parsing and threat detection
- **Chrome Extension**: Real-time analysis directly in Gmail interface
- **REST API**: FastAPI backend with endpoints for email/URL analysis
- **Batch Processing**: Analyze multiple emails
- **Email Downloading**: Fetch from Gmail/Outlook accounts
- **Risk Scoring**: 0-100 scale with color-coded threat levels

## Installation

### 1. Backend Setup

```bash
# Automated setup
python setup_analyzer.py

# Or manual
pip install -r requirements.txt
```

### 2. Chrome Extension Setup

1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `extension/` folder from this project
5. Extension icon will appear in Chrome toolbar

### 3. Start the API Server

```bash
# Required for extension to work
python email_api_server.py

# Or on Windows:
start.bat
```

The API server runs on `http://localhost:8000`

## Usage Examples

### Command Line
```bash
# Single email analysis
python phishing_analyzer.py suspicious_email.eml

# Batch processing
python batch_analyzer.py /path/to/emails/

# Download and analyze
python email_downloader.py
```

### Chrome Extension

```bash
# 1. Start the API server first
python email_api_server.py

# 2. Load extension in Chrome:
#    - Go to chrome://extensions/
#    - Enable "Developer mode"
#    - Click "Load unpacked"
#    - Select the extension/ folder

# 3. Use in Gmail:
#    - Open any email in Gmail
#    - Click "🛡️ Analyze Email" button (top-right)
#    - Or click extension icon for popup analysis
```

### API Endpoints

```bash
# Health check
curl http://localhost:8000/health

# Analyze URL
curl -X POST http://localhost:8000/analyze/url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com"}'

# Analyze email file
curl -X POST http://localhost:8000/analyze/email \
  -F "file=@suspicious_email.eml"
```

Visit `http://localhost:8000/docs` for interactive API documentation.

## Configuration

Edit `config/email_accounts.json` with your email credentials:

```json
{
  "accounts": [
    {
      "email": "your.email@gmail.com",
      "password": "your_app_password",
      "imap_server": "imap.gmail.com",
      "imap_port": 993,
      "provider": "gmail"
    }
  ]
}
```

## Risk Scoring

- **LOW (0-30)**: Minimal threat
- **MEDIUM (31-60)**: Suspicious patterns
- **HIGH (61-80)**: Likely phishing
- **CRITICAL (81+)**: Immediate threat

## Security

- Local processing only
- No data transmission to external servers
- Use app passwords for email accounts
- Regularly rotate credentials

---

**PhishingAnalyzer v4.0** - Professional Email Security
