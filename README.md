# PhishingAnalyzer - Professional Email Phishing Detection

## Quick Start

```bash
# Setup the system
python setup_analyzer.py

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
├── main.py                    # Main entry point
├── requirements.txt           # Dependencies
├── LICENSE                    # MIT License
├── README.md                  # Documentation
├── core/                      # Core ML engine
│   ├── email_phishing_analyzer.py
│   ├── phishing_detector.py
│   └── models/
│       └── random_forest_url_model.sav
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

- **ML-Based Detection**: RandomForest classifier for URLs
- **Email Analysis**: MSG/EML file parsing and threat detection
- **Batch Processing**: Analyze multiple emails
- **Email Downloading**: Fetch from Gmail/Outlook accounts
- **REST API**: Integration capabilities

## Installation

```bash
# Automated setup
python setup_analyzer.py

# Or manual
pip install -r requirements.txt
```

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

### Main Entry Point
```bash
# Using main.py
python main.py analyze email.eml
python main.py batch
python main.py download
python main.py setup
```

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
