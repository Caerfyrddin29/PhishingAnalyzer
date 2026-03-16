#!/usr/bin/env python3
"""PhishAnalyzer - Unified Phishing Detection System
A comprehensive, modular, and production-ready phishing detection toolkit."""

__version__ = "3.0.0"
__author__ = "PhishAnalyzer Team"
__description__ = "Advanced phishing detection with ML and heuristic analysis"

import re
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import socket
from functools import lru_cache

# ML and data processing
try:
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, confusion_matrix
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    pd = None
    np = None
    RandomForestClassifier = None

# Web analysis
try:
    import whois
    from bs4 import BeautifulSoup
    import urllib.request
    from urllib.error import HTTPError
    WEB_ANALYSIS_AVAILABLE = True
except ImportError:
    WEB_ANALYSIS_AVAILABLE = False

import warnings

warnings.filterwarnings('ignore')
try:
    import email
    from email import policy
    import extract_msg
    EMAIL_PROCESSING_AVAILABLE = True
except ImportError:
    EMAIL_PROCESSING_AVAILABLE = False

warnings.filterwarnings('ignore')

@dataclass
class URLAnalysisResult:
    """URL analysis result with comprehensive information"""
    url: str
    risk_score: int
    classification: str
    confidence: float
    features: Dict
    timestamp: str
    method: str = "heuristic"
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class EmailAnalysisResult:
    """Email analysis result with comprehensive information"""
    file_path: str
    metadata: Dict
    risk_score: int
    risk_level: str
    findings: Dict
    timestamp: str
    processing_time: float
    
    def to_dict(self) -> Dict:
        return asdict(self)

class PhishAnalyzerConfig:
    """Centralized configuration for PhishAnalyzer"""
    
    # URL analysis thresholds
    URL_LENGTH_THRESHOLD = {
        "LEGITIMATE": 54,
        "SUSPICIOUS": 75
    }
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        "having_ip": 25,
        "shortening_service": 15,
        "redirection": 15,
        "dns_record_failure": 20,
        "statistical_report": 25,
        "sub_domains": 10,
        "prefix_suffix": 10,
        "domain_registration": 10,
        "age_domain": 10
    }
    
    # Suspicious patterns
    SUSPICIOUS_KEYWORDS = [
        'at.ua', 'usa.cc', 'baltazarpresentes.com.br', 'pe.hu', 'esy.es', 
        'hol.es', 'sweddy.com', 'myjino.ru', '96.lt', 'ow.ly'
    ]
    
    SUSPICIOUS_IPS = [
        '146.112.61.108', '213.174.157.151', '121.50.168.88'
    ]
    
    SHORTENING_SERVICES = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 
        'bitly.com', 'is.gd', 'buff.ly', 'adf.ly'
    ]
    
    # Risk levels
    RISK_LEVELS = {
        (0, 30): "LOW",
        (31, 60): "MEDIUM", 
        (71, 80): "HIGH",
        (81, 100): "CRITICAL"
    }

class URLAnalyzer:
    """Advanced URL analyzer with ML and heuristic methods"""
    
    def __init__(self, config: Optional[PhishAnalyzerConfig] = None):
        self.config = config or PhishAnalyzerConfig()
        self.ml_model = None
        self._load_ml_model()
    
    def _load_ml_model(self):
        """Load ML model if available"""
        if not ML_AVAILABLE:
            return
            
        model_path = "random_forest_url_model.sav"
        if os.path.exists(model_path):
            try:
                import pickle
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
            except Exception:
                self.ml_model = None
    
    def analyze_url(self, url: str) -> URLAnalysisResult:
        """Comprehensive URL analysis"""
        features = self._extract_features(url)
        
        if self.ml_model:
            result = self._ml_predict(url, features)
        else:
            result = self._heuristic_analyze(url, features)
        
        return result
    
    def _extract_features(self, url: str) -> Dict:
        """Extract comprehensive features from URL"""
        try:
            parsed = urlparse(url)
        except:
            parsed = urlparse("http://invalid")
        
        features = {
            'domain': parsed.netloc,
            'path': parsed.path,
            'protocol': parsed.scheme,
            'having_ip': self._check_ip_in_url(url),
            'url_length': self._classify_url_length(url),
            'have_at_symbol': 1 if '@' in url else 0,
            'redirection': 1 if '//' in parsed.path else 0,
            'prefix_suffix_separation': 1 if '-' in parsed.netloc else 0,
            'sub_domains': self._count_subdomains(url),
            'shortening_service': self._check_shortening_service(url),
            'web_traffic': self._check_web_traffic(url) if WEB_ANALYSIS_AVAILABLE else 1,
            'domain_registration_length': self._check_domain_registration(url) if WEB_ANALYSIS_AVAILABLE else 1,
            'age_domain': self._check_domain_age(url) if WEB_ANALYSIS_AVAILABLE else 1,
            'dns_record': self._check_dns_record(url) if WEB_ANALYSIS_AVAILABLE else 1,
            'statistical_report': self._check_statistical_report(url),
            'https_token': self._check_https_token(url)
        }
        
        return features
    
    @lru_cache(maxsize=1000)
    def _check_ip_in_url(self, url: str) -> int:
        """Check if URL contains IP address"""
        pattern = r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
        return 1 if re.search(pattern, url) else 0
    
    def _classify_url_length(self, url: str) -> int:
        """Classify URL length"""
        length = len(url)
        if length < self.config.URL_LENGTH_THRESHOLD["LEGITIMATE"]:
            return 0  # LEGITIMATE
        elif length <= self.config.URL_LENGTH_THRESHOLD["SUSPICIOUS"]:
            return 2  # SUSPICIOUS
        else:
            return 1  # PHISHING
    
    def _count_subdomains(self, url: str) -> int:
        """Count subdomains"""
        dots = url.count(".")
        if dots < 3:
            return 0  # LEGITIMATE
        elif dots == 3:
            return 2  # SUSPICIOUS
        else:
            return 1  # PHISHING
    
    def _check_shortening_service(self, url: str) -> int:
        """Check if URL uses shortening service"""
        pattern = '|'.join(self.config.SHORTENING_SERVICES)
        return 1 if re.search(pattern, url, re.IGNORECASE) else 0
    
    def _check_web_traffic(self, url: str) -> int:
        """Check web traffic (simplified implementation)"""
        return 1  # Default to suspicious since Alexa API is deprecated
    
    def _check_domain_registration(self, url: str) -> int:
        """Check domain registration duration"""
        try:
            domain = urlparse(url).netloc
            domain_info = whois.whois(domain)
            expiration = domain_info.expiration_date
            
            if not expiration:
                return 1  # SUSPICIOUS
            
            today = datetime.now()
            if isinstance(expiration, list):
                expiration = expiration[0]
            
            days_until_expiry = abs((expiration - today).days)
            return 1 if days_until_expiry <= 365 else 0  # LEGITIMATE
        except:
            return 1  # SUSPICIOUS
    
    def _check_domain_age(self, url: str) -> int:
        """Check domain age"""
        try:
            domain = urlparse(url).netloc
            domain_info = whois.whois(domain)
            creation = domain_info.creation_date
            expiration = domain_info.expiration_date
            
            if not creation or not expiration:
                return 1  # SUSPICIOUS
            
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiration, list):
                expiration = expiration[0]
            
            age_days = abs((expiration - creation).days)
            return 1 if age_days < 180 else 0  # LEGITIMATE
        except:
            return 1  # SUSPICIOUS
    
    def _check_dns_record(self, url: str) -> int:
        """Check DNS record existence"""
        try:
            domain = urlparse(url).netloc
            whois.whois(domain)
            return 0  # LEGITIMATE
        except:
            return 1  # SUSPICIOUS
    
    def _check_statistical_report(self, url: str) -> int:
        """Check against known suspicious domains/IPs"""
        hostname = urlparse(url).netloc
        
        try:
            ip_address = socket.gethostbyname(hostname)
            
            # Check suspicious keywords
            for keyword in self.config.SUSPICIOUS_KEYWORDS:
                if keyword in url.lower():
                    return 1  # PHISHING
            
            # Check suspicious IPs
            for suspicious_ip in self.config.SUSPICIOUS_IPS:
                if ip_address == suspicious_ip:
                    return 1  # PHISHING
            
            return 0  # LEGITIMATE
        except:
            return 1  # SUSPICIOUS
    
    def _check_https_token(self, url: str) -> int:
        """Check for HTTPS token abuse"""
        try:
            match = re.search(r'https?://', url)
            if match:
                rest = url[match.end():]
                return 1 if re.search(r'https?', rest) else 0
            return 0
        except:
            return 1
    
    def _heuristic_analyze(self, url: str, features: Dict) -> URLAnalysisResult:
        """Heuristic-based URL analysis"""
        risk_score = 0
        
        # Calculate risk score based on features
        if features['having_ip']:
            risk_score += self.config.RISK_WEIGHTS['having_ip']
        if features['shortening_service']:
            risk_score += self.config.RISK_WEIGHTS['shortening_service']
        if features['redirection']:
            risk_score += self.config.RISK_WEIGHTS['redirection']
        if features['dns_record']:
            risk_score += self.config.RISK_WEIGHTS['dns_record_failure']
        if features['statistical_report']:
            risk_score += self.config.RISK_WEIGHTS['statistical_report']
        if features['sub_domains'] == 1:
            risk_score += self.config.RISK_WEIGHTS['sub_domains']
        if features['prefix_suffix_separation']:
            risk_score += self.config.RISK_WEIGHTS['prefix_suffix']
        if features['domain_registration_length']:
            risk_score += self.config.RISK_WEIGHTS['domain_registration']
        if features['age_domain']:
            risk_score += self.config.RISK_WEIGHTS['age_domain']
        
        risk_score = min(risk_score, 100)
        classification = self._classify_by_score(risk_score)
        
        return URLAnalysisResult(
            url=url,
            risk_score=risk_score,
            classification=classification,
            confidence=0.8,  # Default confidence for heuristic
            features=features,
            timestamp=datetime.now().isoformat(),
            method="heuristic"
        )
    
    def _ml_predict(self, url: str, features: Dict) -> URLAnalysisResult:
        """ML-based URL prediction"""
        if not self.ml_model or not ML_AVAILABLE:
            return self._heuristic_analyze(url, features)
        
        try:
            # Prepare features for ML model
            feature_vector = [
                features['url_length'],
                features['redirection'],
                features['prefix_suffix_separation'],
                features['sub_domains'],
                features['shortening_service'],
                features['web_traffic'],
                features['domain_registration_length'],
                features['dns_record'],
                features['statistical_report'],
                features['age_domain'],
                features['https_token'],
                features['having_ip'],
                features['have_at_symbol']
            ]
            
            prediction = self.ml_model.predict([feature_vector])[0]
            prediction_proba = self.ml_model.predict_proba([feature_vector])[0]
            confidence = max(prediction_proba)
            
            classification = "PHISHING" if prediction == 1 else "LEGITIMATE"
            risk_score = int(confidence * 100) if prediction == 1 else int((1 - confidence) * 100)
            
            return URLAnalysisResult(
                url=url,
                risk_score=risk_score,
                classification=classification,
                confidence=confidence,
                features=features,
                timestamp=datetime.now().isoformat(),
                method="random_forest"
            )
        except Exception as e:
            # Fallback to heuristic
            return self._heuristic_analyze(url, features)
    
    def _classify_by_score(self, score: int) -> str:
        """Classify based on risk score"""
        for (min_score, max_score), level in self.config.RISK_LEVELS.items():
            if min_score <= score <= max_score:
                return level
        return "CRITICAL"
    
    def batch_analyze(self, urls: List[str]) -> List[URLAnalysisResult]:
        """Analyze multiple URLs"""
        return [self.analyze_url(url) for url in urls]

class EmailAnalyzer:
    """Advanced email analyzer for phishing detection"""
    
    def __init__(self, url_analyzer: Optional[URLAnalyzer] = None):
        self.url_analyzer = url_analyzer or URLAnalyzer()
        self.config = PhishAnalyzerConfig()
    
    def analyze_file(self, file_path: str) -> EmailAnalysisResult:
        """Analyze email file (MSG or EML)"""
        start_time = datetime.now()
        
        try:
            if file_path.lower().endswith('.msg'):
                analysis = self._analyze_msg_file(file_path)
            elif file_path.lower().endswith('.eml'):
                analysis = self._analyze_eml_file(file_path)
            else:
                raise ValueError(f"Unsupported file format: {file_path}")
            
            processing_time = (datetime.now() - start_time).total_seconds()
            
            return EmailAnalysisResult(
                file_path=file_path,
                metadata=analysis['metadata'],
                risk_score=analysis['risk_score'],
                risk_level=analysis['risk_level'],
                findings=analysis['findings'],
                timestamp=datetime.now().isoformat(),
                processing_time=processing_time
            )
            
        except Exception as e:
            return EmailAnalysisResult(
                file_path=file_path,
                metadata={},
                risk_score=0,
                risk_level="ERROR",
                findings={"error": str(e)},
                timestamp=datetime.now().isoformat(),
                processing_time=0
            )
    
    def _analyze_msg_file(self, file_path: str) -> Dict:
        """Analyze Outlook MSG file"""
        if not EMAIL_PROCESSING_AVAILABLE:
            return {"error": "Email processing not available"}
        
        try:
            with extract_msg.openMSG(file_path) as msg:
                metadata = {
                    'sender': str(msg.sender),
                    'to': str(msg.to),
                    'subject': str(msg.subject),
                    'received_time': str(msg.receivedTime),
                    'file_type': 'MSG'
                }
                
                body = str(msg.body)
                findings = self._extract_findings_from_content(body)
                
                # Calculate overall risk
                risk_score = self._calculate_email_risk(findings)
                risk_level = self._classify_by_score(risk_score)
                
                return {
                    'metadata': metadata,
                    'findings': findings,
                    'risk_score': risk_score,
                    'risk_level': risk_level
                }
        except Exception as e:
            return {"error": f"MSG analysis failed: {str(e)}"}
    
    def _analyze_eml_file(self, file_path: str) -> Dict:
        """Analyze EML file"""
        if not EMAIL_PROCESSING_AVAILABLE:
            return {"error": "Email processing not available"}
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            msg = email.message_from_string(content, policy=policy.default)
            
            metadata = {
                'from': msg.get('From', 'N/A'),
                'to': msg.get('To', 'N/A'),
                'subject': msg.get('Subject', 'N/A'),
                'date': msg.get('Date', 'N/A'),
                'message_id': msg.get('Message-ID', 'N/A'),
                'file_type': 'EML'
            }
            
            findings = self._extract_findings_from_content(content)
            
            # Calculate overall risk
            risk_score = self._calculate_email_risk(findings)
            risk_level = self._classify_by_score(risk_score)
            
            return {
                'metadata': metadata,
                'findings': findings,
                'risk_score': risk_score,
                'risk_level': risk_level
            }
        except Exception as e:
            return {"error": f"EML analysis failed: {str(e)}"}
    
    def _extract_findings_from_content(self, content: str) -> Dict:
        """Extract findings from email content"""
        findings = {
            'ip_addresses': [],
            'email_addresses': [],
            'urls': [],
            'url_analysis': [],
            'attachments': [],
            'suspicious_patterns': []
        }
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        findings['ip_addresses'] = list(set(re.findall(ip_pattern, content)))
        
        # Extract email addresses
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        findings['email_addresses'] = list(set(re.findall(email_pattern, content)))
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'\)]+'
        urls = re.findall(url_pattern, content)
        
        # Extract domains
        domain_pattern = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
        domains = re.findall(domain_pattern, content.lower())
        urls.extend([f"http://{domain}" for domain in domains])
        
        findings['urls'] = list(set(urls))
        
        # Analyze URLs
        for url in findings['urls']:
            url_result = self.url_analyzer.analyze_url(url)
            findings['url_analysis'].append(url_result.to_dict())
        
        return findings
    
    def _calculate_email_risk(self, findings: Dict) -> int:
        """Calculate overall email risk score"""
        risk_score = 0
        
        # Risk from URLs
        for url_analysis in findings.get('url_analysis', []):
            risk_score += url_analysis.get('risk_score', 0) * 0.3
        
        # Risk from IP addresses
        if findings.get('ip_addresses'):
            risk_score += len(findings['ip_addresses']) * 10
        
        # Risk from suspicious patterns
        if findings.get('suspicious_patterns'):
            risk_score += len(findings['suspicious_patterns']) * 15
        
        return min(int(risk_score), 100)
    
    def _classify_by_score(self, score: int) -> str:
        """Classify based on risk score"""
        for (min_score, max_score), level in self.config.RISK_LEVELS.items():
            if min_score <= score <= max_score:
                return level
        return "CRITICAL"

# Convenience functions
def analyze_url(url: str) -> URLAnalysisResult:
    """Quick URL analysis"""
    analyzer = URLAnalyzer()
    return analyzer.analyze_url(url)

def analyze_email(file_path: str) -> EmailAnalysisResult:
    """Quick email analysis"""
    analyzer = EmailAnalyzer()
    return analyzer.analyze_file(file_path)

def batch_analyze_urls(urls: List[str]) -> List[URLAnalysisResult]:
    """Batch URL analysis"""
    analyzer = URLAnalyzer()
    return analyzer.batch_analyze(urls)

# Version and compatibility info
def get_version_info() -> Dict:
    """Get version and compatibility information"""
    return {
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "ml_available": ML_AVAILABLE,
        "web_analysis_available": WEB_ANALYSIS_AVAILABLE,
        "email_processing_available": EMAIL_PROCESSING_AVAILABLE
    }

if __name__ == "__main__":
    # Demo functionality
    print("🛡️ PhishAnalyzer v3.0.0 - Advanced Phishing Detection System")
    print("=" * 60)
    
    # Test URL analysis
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "https://bit.ly/suspicious"
    ]
    
    print("\n🔗 URL Analysis Demo:")
    url_analyzer = URLAnalyzer()
    for url in test_urls:
        result = url_analyzer.analyze_url(url)
        print(f"  {url}: {result.classification} ({result.risk_score}/100)")
    
    print(f"\n📊 Version Info: {get_version_info()}")
