#!/usr/bin/env python3
"""
PhishAnalyzer API - Production-ready REST API
Fast, scalable, and comprehensive phishing detection API
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Union
import tempfile
import os
import json
import uuid
from datetime import datetime
import asyncio
import time

# Import our unified analyzer
from phishanalyzer_unified import (
    URLAnalyzer, EmailAnalyzer, PhishAnalyzerConfig,
    URLAnalysisResult, EmailAnalysisResult,
    analyze_url, batch_analyze_urls, analyze_email, get_version_info
)
from url_validator import URLValidator

# Initialize FastAPI with production settings
app = FastAPI(
    title="PhishAnalyzer API",
    description="""
    Advanced Phishing Detection API v3.0
    
    ### Features
    - URL Analysis: ML + heuristic detection
    - Email Analysis: MSG/EML file support  
    - Risk Scoring: Advanced threat assessment
    - Batch Processing: Multiple URLs/emails
    - High Performance: Optimized for scale
    - Production Ready: Error handling & validation
    
    ### Risk Levels
    - LOW (0-30): Minimal threat
    - MEDIUM (31-60): Suspicious content
    - HIGH (61-80): Likely phishing
    - CRITICAL (81+): Immediate threat
    """,
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "PhishAnalyzer Support",
        "url": "https://github.com/phishanalyzer"
    }
)

# Production CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Request/Response Models
class URLAnalysisRequest(BaseModel):
    """URL analysis request"""
    url: str = Field(..., description="URL to analyze", example="https://example.com")

class BatchURLAnalysisRequest(BaseModel):
    """Batch URL analysis request"""
    urls: List[str] = Field(..., description="List of URLs to analyze", 
                             example=["https://google.com", "http://192.168.1.1"])

class EmailAnalysisRequest(BaseModel):
    """Email analysis request"""
    subject: str = Field(..., description="Email subject")
    sender: str = Field(..., description="Sender email")
    body: str = Field(..., description="Email body content")
    headers: Optional[str] = Field("", description="Additional headers")

class APIResponse(BaseModel):
    """Standard API response"""
    success: bool = Field(..., description="Request success status")
    message: str = Field(..., description="Response message")
    data: Optional[Dict] = Field(None, description="Response data")
    timestamp: str = Field(..., description="Response timestamp")

# Global instances
url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer(url_analyzer)
config = PhishAnalyzerConfig()

# In-memory cache for results (production: use Redis)
analysis_cache = {}

@app.get("/", response_class=HTMLResponse)
async def root():
    """API dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>PhishAnalyzer API v3.0</title>
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
                max-width: 900px;
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
            <div class="shield">Shield</div>
            <h1>PhishAnalyzer API v3.0</h1>
            <div class="status">Production Ready</div>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">Link</div>
                    <h3>URL Analysis</h3>
                    <p>ML + heuristic detection</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">Email</div>
                    <h3>Email Analysis</h3>
                    <p>MSG & EML support</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">Target</div>
                    <h3>Risk Scoring</h3>
                    <p>Advanced assessment</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">Bolt</div>
                    <h3>High Performance</h3>
                    <p>Optimized for scale</p>
                </div>
            </div>
            
            <div class="links">
                <a href="/docs" class="btn">API Documentation</a>
                <a href="/redoc" class="btn">ReDoc</a>
                <a href="/health" class="btn">Health Check</a>
            </div>
            
            <div class="version">
                Version 3.0.0 • Production • MIT License
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    version_info = get_version_info()
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": version_info["version"],
        "ml_available": version_info["ml_available"],
        "web_analysis_available": version_info["web_analysis_available"],
        "email_processing_available": version_info["email_processing_available"]
    }

@app.post("/analyze/url", response_model=URLAnalysisResult)
async def analyze_single_url(request: URLAnalysisRequest):
    """
    Analyze single URL for phishing
    
    Performs comprehensive URL analysis with ML and heuristic detection.
    
    **Features:**
    - ML-based classification (if model available)
    - Heuristic analysis as fallback
    - 13+ feature extraction
    - Risk scoring 0-100
    - Confidence metrics
    """
    try:
        # Validate URL first
        is_valid, error = URLValidator.is_valid_url(request.url)
        if not is_valid:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {error}")
        
        # Sanitize URL
        sanitized_url = URLValidator.sanitize_url(request.url)
        
        start_time = time.time()
        result = url_analyzer.analyze_url(sanitized_url)
        processing_time = time.time() - start_time
        
        return URLAnalysisResult(
            url=result.url,
            risk_score=result.risk_score,
            classification=result.classification,
            confidence=result.confidence,
            features=result.features,
            timestamp=result.timestamp,
            method=result.method
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL analysis failed: {str(e)}")

@app.post("/analyze/urls", response_model=List[URLAnalysisResult])
async def analyze_multiple_urls(request: BatchURLAnalysisRequest):
    """
    Analyze multiple URLs
    
    Batch analysis for multiple URLs with optimized processing.
    
    **Limits:**
    - Maximum 100 URLs per request
    - URLs validated before processing
    """
    if len(request.urls) > 100:
        raise HTTPException(status_code=400, detail="Maximum 100 URLs allowed per request")
    
    try:
        # Validate and sanitize all URLs
        valid_urls, invalid_urls = URLValidator.validate_batch_urls(request.urls)
        
        if invalid_urls:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid URLs found: {'; '.join(invalid_urls[:3])}"
            )
        
        start_time = time.time()
        results = url_analyzer.batch_analyze(valid_urls)
        processing_time = time.time() - start_time
        
        return results
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@app.post("/analyze/email", response_model=EmailAnalysisResult)
async def analyze_email_content(request: EmailAnalysisRequest):
    """
    Analyze email content
    
    Analyzes email content for phishing threats including URLs, IPs, and patterns.
    
    **Analysis includes:**
    - URL extraction and analysis
    - IP address detection
    - Email address extraction
    - Suspicious pattern matching
    - Overall risk assessment
    """
    try:
        # Create temporary EML content
        eml_content = f"""From: {request.sender}
Subject: {request.subject}
Date: {datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')}
{request.headers}

{request.body}"""
        
        # Analyze content
        findings = email_analyzer._extract_findings_from_content(eml_content)
        risk_score = email_analyzer._calculate_email_risk(findings)
        risk_level = email_analyzer._classify_by_score(risk_score)
        
        metadata = {
            'subject': request.subject,
            'sender': request.sender,
            'timestamp': datetime.now().isoformat(),
            'file_type': 'CONTENT'
        }
        
        return EmailAnalysisResult(
            file_path="content_input",
            metadata=metadata,
            risk_score=risk_score,
            risk_level=risk_level,
            findings=findings,
            timestamp=datetime.now().isoformat(),
            processing_time=0.1
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email analysis failed: {str(e)}")

@app.get("/analyze/url/form", response_class=HTMLResponse)
async def url_analysis_form():
    """URL analysis web form"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>URL Analysis - PhishAnalyzer</title>
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
                padding: 2rem;
            }
            .container {
                background: white;
                border-radius: 20px;
                padding: 3rem;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                max-width: 700px;
                width: 100%;
            }
            .title { 
                text-align: center; 
                margin-bottom: 2rem; 
                color: #333;
                font-size: 2rem;
            }
            .form-group { margin-bottom: 1.5rem; }
            label { 
                display: block; 
                margin-bottom: 0.5rem; 
                font-weight: 600;
                color: #555;
            }
            input[type="url"], textarea { 
                width: 100%; 
                padding: 1rem; 
                border: 2px solid #e1e5e9;
                border-radius: 10px;
                font-size: 1rem;
                transition: border-color 0.3s;
            }
            textarea { min-height: 100px; resize: vertical; }
            input[type="url"]:focus, textarea:focus { 
                outline: none; 
                border-color: #667eea;
            }
            .btn {
                width: 100%;
                background: linear-gradient(45deg, #667eea, #764ba2);
                color: white;
                border: none;
                padding: 1rem 2rem;
                border-radius: 10px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.3s;
            }
            .btn:hover { transform: translateY(-2px); }
            .examples {
                margin-top: 2rem;
                padding: 1rem;
                background: #f8f9fa;
                border-radius: 10px;
            }
            .examples h3 { margin-bottom: 0.5rem; color: #666; }
            .example-url {
                display: block;
                padding: 0.5rem;
                background: white;
                border-radius: 5px;
                margin-bottom: 0.5rem;
                font-family: monospace;
                cursor: pointer;
                transition: background 0.3s;
            }
            .example-url:hover { background: #e9ecef; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="title">URL Analysis</h1>
            <form id="urlForm">
                <div class="form-group">
                    <label for="url">Enter URL to analyze:</label>
                    <input type="url" id="url" name="url" required 
                           placeholder="https://example.com/suspicious-page">
                </div>
                <button type="submit" class="btn">Analyze URL</button>
            </form>
            
            <div class="examples">
                <h3>Test URLs:</h3>
                <div class="example-url" onclick="document.getElementById('url').value='https://google.com'">https://google.com</div>
                <div class="example-url" onclick="document.getElementById('url').value='http://192.168.1.1/login'">http://192.168.1.1/login</div>
                <div class="example-url" onclick="document.getElementById('url').value='https://bit.ly/suspicious'">https://bit.ly/suspicious</div>
            </div>
            
            <div id="result" style="margin-top: 2rem;"></div>
        </div>
        
        <script>
            document.getElementById('urlForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const url = document.getElementById('url').value;
                const resultDiv = document.getElementById('result');
                
                resultDiv.innerHTML = '<div style="text-align: center; padding: 2rem;">Analyzing...</div>';
                
                try {
                    const response = await fetch('/analyze/url', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: url })
                    });
                    
                    const result = await response.json();
                    
                    const riskColor = result.classification === 'PHISHING' ? '#dc3545' : 
                                   result.classification === 'SUSPICIOUS' ? '#ffc107' : '#28a745';
                    
                    resultDiv.innerHTML = `
                        <div style="padding: 2rem; border-radius: 10px; background: #f8f9fa;">
                            <h3>Analysis Results</h3>
                            <p><strong>URL:</strong> ${result.url}</p>
                            <p><strong>Classification:</strong> <span style="color: ${riskColor}">${result.classification}</span></p>
                            <p><strong>Risk Score:</strong> ${result.risk_score}/100</p>
                            <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
                            <p><strong>Method:</strong> ${result.method}</p>
                        </div>
                    `;
                } catch (error) {
                    resultDiv.innerHTML = '<div style="padding: 2rem; color: red;">Analysis failed</div>';
                }
            });
        </script>
    </body>
    </html>
    """

@app.get("/version")
async def get_api_version():
    """Get API version and capabilities"""
    return get_version_info()

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={"success": False, "message": "Endpoint not found"}
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "Internal server error"}
    )

if __name__ == "__main__":
    import uvicorn
    print("Starting PhishAnalyzer API v3.0...")
    print("Server: http://localhost:8000")
    print("Docs: http://localhost:8000/docs")
    print("URL Form: http://localhost:8000/analyze/url/form")
    
    uvicorn.run(
        app, 
        host="127.0.0.1", 
        port=8000,
        log_level="info"
    )
