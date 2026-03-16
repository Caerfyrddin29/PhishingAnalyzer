# PhishAnalyzer v3.0 - Advanced Phishing Detection System

A comprehensive, production-ready phishing detection toolkit with ML and heuristic analysis.

## Features

- URL Analysis: ML + heuristic detection with 13+ features
- Email Analysis: MSG/EML file support with comprehensive analysis
- Risk Scoring: Advanced threat assessment (0-100 scale)
- High Performance: Optimized for scale and batch processing
- REST API: Production-ready FastAPI with comprehensive endpoints
- Modular Design: Clean, maintainable, and extensible architecture

## Quick Start

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Start API Server
```bash
# Windows
start.bat

# Linux/Mac
./start.sh

# Or directly
python api.py
```

### 3. Access Services
- 🌐 API Dashboard: http://localhost:8000
- 📚 Documentation: http://localhost:8000/docs
- 🔍 URL Analysis Form: http://localhost:8000/analyze/url/form

## API Endpoints

### URL Analysis
- `POST /analyze/url` - Analyze single URL
- `POST /analyze/urls` - Batch analyze multiple URLs
- `GET /analyze/url/form` - Web interface for URL analysis

### Email Analysis  
- `POST /analyze/email` - Analyze email content

### System
- `GET /health` - Health check and system status
- `GET /version` - Version and capabilities

## Python Usage

```python
from phishanalyzer_unified import analyze_url, analyze_email

# URL Analysis
result = analyze_url("https://example.com")
print(f"Classification: {result.classification}")
print(f"Risk Score: {result.risk_score}/100")

# Email Analysis
email_result = analyze_email("email.eml")
print(f"Risk Level: {email_result.risk_level}")
```

## Risk Levels

- LOW (0-30): Minimal threat detected
- MEDIUM (31-60): Suspicious patterns found
- HIGH (61-80): Likely phishing attempt
- CRITICAL (81+): Immediate threat detected

## Architecture

```
PhishAnalyzer v3.0/
├── phishanalyzer_unified.py  # Core analysis engine
├── api.py                    # FastAPI REST server
├── requirements.txt           # Dependencies
├── models/                  # ML models
├── logs/                    # Application logs
├── uploads/                 # File uploads
└── temp/                    # Temporary files
```

## Configuration

The system uses `PhishAnalyzerConfig` class for centralized configuration:

- Risk scoring weights
- Suspicious patterns and IPs
- URL analysis thresholds
- Classification levels

## Production Deployment

### Environment Variables
```bash
export PHISHANALYZER_HOST=0.0.0.0
export PHISHANALYZER_PORT=8000
export PHISHANALYZER_LOG_LEVEL=info
```

### Docker Support
```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["python", "api.py"]
```

## Testing

```bash
# Run tests
python -m pytest tests/

# Quick functionality test
python phishanalyzer_unified.py
```

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: http://localhost:8000/docs
- Issues: Create issue on GitHub
- Contact: PhishAnalyzer Team
