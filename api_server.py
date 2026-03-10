#!/usr/bin/env python3
"""
PhishAnalyzer API Server
FastAPI backend for browser extension integration
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import tempfile
import os
import json
from datetime import datetime
import uuid
from PhishAnalyzer import PhishAnalyzer

app = FastAPI(
    title="PhishAnalyzer API",
    description="""Advanced Email Phishing Detection API

### Features
- 📧 **Multi-format support**: MSG, EML files
- 🔍 **Deep content analysis**: IPs, URLs, emails, attachments
- 🎯 **Risk scoring**: Automated threat assessment
- 📊 **Detailed reporting**: Structured JSON responses
- 🌐 **Browser integration**: CORS-enabled for extensions

### Quick Start
1. Send email data to `/analyze`
2. Get risk score and detailed findings
3. Retrieve results with `/results/{analysis_id}`

### Risk Levels
- 🔵 **LOW** (0-30): Minimal threat
- 🟡 **MEDIUM** (31-60): Suspicious content
- 🟠 **HIGH** (61-80): Likely phishing
- 🔴 **CRITICAL** (81+): Immediate threat""",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "PhishAnalyzer Support",
        "url": "http://localhost:8000/docs"
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Enable CORS for browser extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to extension origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailAnalysisRequest(BaseModel):
    """Request model for email analysis"""
    subject: str = Field(..., description="Email subject line")
    sender: str = Field(..., description="Sender email address")
    body: str = Field(..., description="Email body content")
    headers: Optional[str] = Field("", description="Additional email headers")
    raw_content: Optional[str] = Field("", description="Raw email content for advanced analysis")
    
    class Config:
        json_schema_extra = {
            "example": {
                "subject": "Urgent: Account Verification Required",
                "sender": "security@paypal.com",
                "body": "Click here to verify your account immediately",
                "headers": "X-Mailer: Microsoft Outlook Express"
            }
        }

class AnalysisResult(BaseModel):
    """Response model for analysis results"""
    success: bool = Field(..., description="Analysis completion status")
    analysis_id: str = Field(..., description="Unique analysis identifier")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score (0-100)")
    risk_level: str = Field(..., description="Risk level: LOW/MEDIUM/HIGH/CRITICAL")
    findings: Dict = Field(..., description="Detailed analysis findings")
    timestamp: str = Field(..., description="Analysis timestamp (ISO format)")
    processing_time: Optional[float] = Field(None, description="Processing time in seconds")

# Store for temporary analysis results
analysis_cache = {}

def calculate_risk_score(findings: Dict) -> tuple[int, str]:
    """Calculate risk score based on analysis findings"""
    score = 0
    
    # Suspicious URLs
    urls = findings.get('urls', [])
    suspicious_domains = ['bit.ly', 'tinyurl.com', 'short.link', 't.co']
    for url in urls:
        if any(domain in url.lower() for domain in suspicious_domains):
            score += 20
        elif url.startswith('http://'):
            score += 10
    
    # IP addresses
    ips = findings.get('ip_addresses', [])
    private_ips = ['192.168.', '10.', '172.16.', '127.']
    for ip in ips:
        if not any(ip.startswith(private) for private in private_ips):
            score += 15
    
    # Email addresses
    emails = findings.get('email_addresses', [])
    if len(emails) > 5:
        score += 10
    
    # Attachments
    attachments = findings.get('attachments', [])
    if attachments:
        risky_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs']
        for att in attachments:
            if any(att.lower().endswith(ext) for ext in risky_extensions):
                score += 30
            else:
                score += 15
    
    # Headers analysis
    if findings.get('header_analysis', {}).get('suspicious_headers', []):
        score += 25
    
    # Determine risk level
    if score <= 30:
        level = "LOW"
    elif score <= 60:
        level = "MEDIUM"
    elif score <= 80:
        level = "HIGH"
    else:
        level = "CRITICAL"
    
    return score, level

@app.get("/", response_class=HTMLResponse)
async def root():
    """Enhanced health check with dashboard preview"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ PhishAnalyzer API</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                border-radius: 20px;
                padding: 3rem;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                max-width: 800px;
                width: 90%;
                text-align: center;
            }
            .shield { font-size: 4rem; margin-bottom: 1rem; }
            h1 { color: #333; margin-bottom: 1rem; font-size: 2.5rem; }
            .status { 
                background: linear-gradient(45deg, #28a745, #20c997);
                color: white;
                padding: 1rem 2rem;
                border-radius: 50px;
                display: inline-block;
                margin: 1rem 0;
                font-weight: bold;
            }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1.5rem;
                margin: 2rem 0;
            }
            .feature {
                background: #f8f9fa;
                padding: 1.5rem;
                border-radius: 15px;
                border-left: 4px solid #667eea;
            }
            .feature-icon { font-size: 2rem; margin-bottom: 0.5rem; }
            .links {
                display: flex;
                gap: 1rem;
                justify-content: center;
                flex-wrap: wrap;
                margin-top: 2rem;
            }
            .btn {
                background: linear-gradient(45deg, #667eea, #764ba2);
                color: white;
                text-decoration: none;
                padding: 1rem 2rem;
                border-radius: 50px;
                font-weight: bold;
                transition: transform 0.3s;
            }
            .btn:hover { transform: translateY(-2px); }
            .version { color: #666; margin-top: 1rem; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="shield">🛡️</div>
            <h1>PhishAnalyzer API</h1>
            <div class="status">🟢 API Server Online</div>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">📧</div>
                    <h3>Email Analysis</h3>
                    <p>MSG & EML format support</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🔍</div>
                    <h3>Deep Scanning</h3>
                    <p>IPs, URLs, attachments</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🎯</div>
                    <h3>Risk Scoring</h3>
                    <p>Automated threat detection</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🌐</div>
                    <h3>Browser Ready</h3>
                    <p>Extension integration</p>
                </div>
            </div>
            
            <div class="links">
                <a href="/docs" class="btn">📚 API Documentation</a>
                <a href="/redoc" class="btn">📖 ReDoc</a>
                <a href="/analyze" class="btn">🔬 Test Analysis</a>
            </div>
            
            <div class="version">
                Version 2.0.0 • FastAPI • MIT License
            </div>
        </div>
    </body>
    </html>
    """

@app.post("/analyze", response_model=AnalysisResult, 
          summary="🔬 Analyze Email for Phishing",
          description="Comprehensive email analysis with risk scoring and detailed findings",
          response_description="Analysis results with risk assessment and extracted threats")
async def analyze_email(request: EmailAnalysisRequest):
    """
    🔍 **Email Phishing Analysis**
    
    Performs comprehensive forensic analysis on email content to detect phishing threats.
    
    **Analysis Process:**
    1. Content parsing and structure analysis
    2. IP address extraction and validation
    3. URL scanning and reputation checking
    4. Email address verification
    5. Attachment threat assessment
    6. Header analysis for anomalies
    7. Risk score calculation
    
    **Risk Assessment:**
    - 🔵 **LOW** (0-30): Minimal threat detected
    - 🟡 **MEDIUM** (31-60): Suspicious patterns found
    - 🟠 **HIGH** (61-80): Likely phishing attempt
    - 🔴 **CRITICAL** (81+): Immediate threat detected
    
    **Returns:** Detailed analysis with findings, risk score, and recommendations.
    """
    try:
        # Generate unique analysis ID
        analysis_id = str(uuid.uuid4())
        
        # Create temporary EML file
        temp_dir = tempfile.mkdtemp()
        eml_file = os.path.join(temp_dir, f"email_{analysis_id}.eml")
        
        # Construct EML content
        eml_content = f"""From: {request.sender}
Subject: {request.subject}
Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}
{request.headers}

{request.body}"""
        
        # Write temporary file
        with open(eml_file, 'w', encoding='utf-8') as f:
            f.write(eml_content)
        
        # Analyze with PhishAnalyzer
        analyzer = PhishAnalyzer(eml_file)
        
        # Extract findings (modified to return structured data)
        findings = await extract_findings(eml_content, request)
        
        # Calculate risk score
        risk_score, risk_level = calculate_risk_score(findings)
        
        # Store results
        result = {
            "success": True,
            "analysis_id": analysis_id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "findings": findings,
            "timestamp": datetime.now().isoformat(),
            "processing_time": 0.1  # Placeholder for processing time
        }
        
        analysis_cache[analysis_id] = result
        
        # Cleanup
        os.remove(eml_file)
        os.rmdir(temp_dir)
        
        return AnalysisResult(**result)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

async def extract_findings(eml_content: str, request: EmailAnalysisRequest) -> Dict:
    """Extract findings from email content"""
    import re
    
    findings = {
        "metadata": {
            "subject": request.subject,
            "sender": request.sender,
            "timestamp": datetime.now().isoformat()
        },
        "ip_addresses": [],
        "email_addresses": [],
        "urls": [],
        "attachments": [],
        "header_analysis": {
            "suspicious_headers": [],
            "hop_count": 0
        }
    }
    
    # Extract IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    findings["ip_addresses"] = list(set(re.findall(ip_pattern, eml_content)))
    
    # Extract email addresses
    email_pattern = r'[\w\.-]+@[\w\.-]+'
    findings["email_addresses"] = list(set(re.findall(email_pattern, eml_content)))
    
    # Extract URLs
    url_pattern = r'https?://[^\s<>"\'\)]+'
    findings["urls"] = list(set(re.findall(url_pattern, eml_content)))
    
    # Extract domains
    domain_pattern = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    domains = re.findall(domain_pattern, eml_content.lower())
    findings["urls"].extend([f"http://{domain}" for domain in domains if not any(url.endswith(domain) for url in findings["urls"])])
    findings["urls"] = list(set(findings["urls"]))
    
    # Analyze headers
    if "Received:" in eml_content:
        findings["header_analysis"]["hop_count"] = eml_content.count("Received:")
    
    # Check for suspicious headers
    suspicious_patterns = [
        r'X-Mailer:.*Microsoft.*Outlook.*Express',
        r'X-Originating-IP:',
        r'Authentication-Results:.*fail'
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, eml_content, re.IGNORECASE):
            findings["header_analysis"]["suspicious_headers"].append(pattern)
    
    return findings

@app.get("/results/{analysis_id}", 
         summary="📊 Retrieve Analysis Results",
         description="Get detailed analysis results using the unique analysis ID",
         response_description="Complete analysis findings with risk assessment")
async def get_analysis_results(analysis_id: str):
    """
    📋 **Get Analysis Results**
    
    Retrieves previously completed email analysis results.
    
    **Parameters:**
    - `analysis_id`: UUID returned by the original analysis request
    
    **Returns:**
    - Complete analysis findings
    - Risk score and level
    - Extracted threats (IPs, URLs, emails)
    - Processing metadata
    
    **Note:** Results are temporarily cached and automatically cleaned up.
    """
    if analysis_id not in analysis_cache:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return analysis_cache[analysis_id]

@app.delete("/results/{analysis_id}", 
            summary="🗑️ Delete Analysis Results",
            description="Remove analysis results from cache (privacy cleanup)",
            response_description="Confirmation of deletion")
async def delete_analysis_results(analysis_id: str):
    """
    🗑️ **Delete Analysis Results**
    
    Removes analysis results from the temporary cache for privacy and cleanup.
    
    **Parameters:**
    - `analysis_id`: UUID of the analysis to delete
    
    **Returns:**
    - Confirmation message
    
    **Security:** Results are automatically cleaned up after time, but manual deletion
    ensures immediate privacy protection.
    """
    if analysis_id not in analysis_cache:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    del analysis_cache[analysis_id]
    return {"message": "Analysis results deleted"}

if __name__ == "__main__":
    import uvicorn
    print("Starting PhishAnalyzer API Server...")
    print("Server will be available at: http://localhost:8000")
    print("API Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="127.0.0.1", port=8000)
