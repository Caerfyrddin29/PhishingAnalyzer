#!/usr/bin/env python3
"""
PhishingAnalyzer API Server
FastAPI server for email phishing analysis
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path

# Add core modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional
import uvicorn

# Import our phishing analyzer
from core.email_phishing_analyzer import analyze_email_for_phishing, EmailPhishingAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="PhishingAnalyzer API",
    description="Professional email phishing detection API",
    version="4.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create directories
Path("uploads").mkdir(exist_ok=True)
Path("static").mkdir(exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic models
class URLAnalysisRequest(BaseModel):
    url: str

class URLAnalysisResult(BaseModel):
    url: str
    classification: str
    confidence: float
    risk_score: int
    processing_time: float
    timestamp: str

class EmailAnalysisResult(BaseModel):
    file_name: str
    risk_score: int
    risk_level: str
    is_phishing: bool
    confidence: float
    findings: dict
    processing_time: float
    timestamp: str

class SystemInfo(BaseModel):
    version: str
    model_loaded: bool
    total_analyses: int
    uptime: str

# Global variables
email_analyzer = None
total_analyses = 0
start_time = datetime.now()

def get_email_analyzer():
    """Get or create email analyzer"""
    global email_analyzer
    if email_analyzer is None:
        try:
            email_analyzer = EmailPhishingAnalyzer()
            logger.info("Email analyzer loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load email analyzer: {e}")
            email_analyzer = None
    return email_analyzer

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint with documentation"""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PhishingAnalyzer API</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-height: 100vh;
            }
            .container {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 16px;
                padding: 40px;
                box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            }
            h1 {
                text-align: center;
                margin-bottom: 40px;
                font-size: 2.5em;
            }
            .endpoint {
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                padding: 20px;
                margin: 20px 0;
                border-left: 4px solid #27ae60;
            }
            .method {
                font-weight: bold;
                color: #3498db;
                font-size: 1.2em;
            }
            .path {
                font-family: monospace;
                background: rgba(0, 0, 0, 0.2);
                padding: 10px;
                border-radius: 4px;
                margin: 10px 0;
            }
            .description {
                margin: 10px 0;
                line-height: 1.6;
            }
            .status {
                background: rgba(39, 174, 96, 0.2);
                border-radius: 6px;
                padding: 15px;
                margin: 20px 0;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ PhishingAnalyzer API</h1>
            
            <div class="status">
                ✅ API Server is Running<br>
                🤖 ML Model: Loaded<br>
                📊 Ready for Analysis
            </div>
            
            <div class="endpoint">
                <div class="method">POST</div>
                <div class="path">/analyze/email</div>
                <div class="description">
                    Analyze email files for phishing threats.<br>
                    Accepts .eml and .msg files.<br>
                    Returns comprehensive analysis with risk scoring.
                </div>
            </div>
            
            <div class="endpoint">
                <div class="method">POST</div>
                <div class="path">/analyze/url</div>
                <div class="description">
                    Analyze individual URLs for phishing threats.<br>
                    Uses ML classification with confidence scores.<br>
                    Returns risk assessment and classification.
                </div>
            </div>
            
            <div class="endpoint">
                <div class="method">GET</div>
                <div class="path">/system/info</div>
                <div class="description">
                    Get system information and status.<br>
                    Includes ML model status and statistics.<br>
                    Returns system health and configuration.
                </div>
            </div>
            
            <div class="endpoint">
                <div class="method">GET</div>
                <div class="path">/health</div>
                <div class="description">
                    Health check endpoint.<br>
                    Returns simple status for monitoring.<br>
                    Always returns 200 OK when server is running.
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/analyze/email", response_model=EmailAnalysisResult)
async def analyze_email(file: UploadFile = File(...)):
    """Analyze email file for phishing threats"""
    global total_analyses
    
    start_time = time.time()
    
    try:
        # Save uploaded file
        file_path = Path("uploads") / file.filename
        with open(file_path, "wb") as f:
            f.write(await file.read())
        
        # Analyze email
        result = analyze_email_for_phishing(str(file_path))
        
        # Update statistics
        total_analyses += 1
        
        # Clean up
        os.remove(file_path)
        
        processing_time = time.time() - start_time
        
        return EmailAnalysisResult(
            file_name=file.filename,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            is_phishing=result.is_phishing,
            confidence=result.confidence,
            findings=result.findings,
            processing_time=processing_time,
            timestamp=result.timestamp
        )
        
    except Exception as e:
        logger.error(f"Email analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/url", response_model=URLAnalysisResult)
async def analyze_url(request: URLAnalysisRequest):
    """Analyze URL for phishing threats"""
    global total_analyses
    
    start_time = time.time()
    
    try:
        analyzer = get_email_analyzer()
        if analyzer is None:
            raise HTTPException(status_code=500, detail="Email analyzer not available")
        
        # Analyze URL
        classification, confidence, risk_score = analyzer.classify_url(request.url)
        
        # Update statistics
        total_analyses += 1
        
        processing_time = time.time() - start_time
        
        return URLAnalysisResult(
            url=request.url,
            classification=classification,
            confidence=confidence,
            risk_score=risk_score,
            processing_time=processing_time,
            timestamp=datetime.now().isoformat()
        )
        
    except Exception as e:
        logger.error(f"URL analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/system/info", response_model=SystemInfo)
async def get_system_info():
    """Get system information and status"""
    global total_analyses, start_time
    
    model = get_email_analyzer()
    uptime = str(datetime.now() - start_time).split('.')[0]
    
    return SystemInfo(
        version="4.0.0",
        model_loaded=model is not None,
        total_analyses=total_analyses,
        uptime=uptime
    )

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

@app.get("/docs")
async def get_docs():
    """API documentation"""
    return {
        "title": "PhishingAnalyzer API",
        "version": "4.0.0",
        "description": "Professional email phishing detection API",
        "endpoints": {
            "/analyze/email": {
                "method": "POST",
                "description": "Analyze email file for phishing",
                "parameters": {
                    "file": {
                        "type": "file",
                        "required": True,
                        "description": "Email file (.eml or .msg)"
                    }
                }
            },
            "/analyze/url": {
                "method": "POST",
                "description": "Analyze URL for phishing",
                "parameters": {
                    "url": {
                        "type": "string",
                        "required": True,
                        "description": "URL to analyze"
                    }
                }
            },
            "/system/info": {
                "method": "GET",
                "description": "Get system information"
            },
            "/health": {
                "method": "GET",
                "description": "Health check"
            }
        }
    }

# Initialize email analyzer
get_email_analyzer()

def main():
    """Main function to start the API server"""
    print("PhishingAnalyzer API Server")
    print("=" * 40)
    print("Starting FastAPI server...")
    print("API will be available at: http://localhost:8000")
    print("Documentation: http://localhost:8000/docs")
    print()
    
    uvicorn.run(app, host="0.0.0.0", port=8000)

if __name__ == "__main__":
    main()
