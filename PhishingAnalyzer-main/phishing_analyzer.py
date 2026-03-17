#!/usr/bin/env python3
"""
PhishingAnalyzer Email Analysis Tool
Professional email parsing and ML-based phishing detection
"""

import os
import sys
import re
import json
import time
import email
import colorama
import extract_msg
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from colorama import Fore, Back, Style
from email import policy
from email.parser import BytesParser

# Add core modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

# Import our phishing analyzer
from core.email_phishing_analyzer import analyze_email_for_phishing

# Initialize colorama
colorama.init(autoreset=True)

# Global variables
count = 0
exportedPath = ""

class PhishingAnalyzerEnhanced:
    """Enhanced email phishing analyzer with ML detection"""
    
    def __init__(self):
        self.phishing_results = []
        self.analysis_summary = {
            "total_emails": 0,
            "phishing_detected": 0,
            "suspicious_ips": [],
            "suspicious_urls": [],
            "suspicious_emails": []
        }
    
    def banner(self):
        """Display PhishingAnalyzer banner"""
        banner = """

    PHISHING ANALYZER EMAIL SECURITY TOOL
    Professional Email Phishing Detection System
    -----------------------------------------
    Usage: python phishing_analyzer.py <email_file>
    -----------------------------------------
    Features:
    - Advanced email parsing and analysis
    - ML-based phishing detection
    - Risk scoring 0-100
    - Professional reporting
    - Threat indicator extraction
    """

        print(Fore.GREEN + banner + "\n")
    
    def setup_paths(self, email_file):
        """Setup file paths"""
        global exportedPath
        
        emailFNameF = "Attachments"
        c_path = os.getcwd()
        exportedPath = os.path.join(c_path, emailFNameF)
        
        try:
            if not os.path.exists(exportedPath):
                os.makedirs(exportedPath)
                print(f"{Fore.CYAN}[+] Created attachments directory: {exportedPath}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error creating directory: {e}")
    
    def file_checker(self, email_file):
        """Check file type and process accordingly"""
        if not os.path.exists(email_file):
            print(f"{Fore.RED}[-] File not found: {email_file}")
            return False
        
        if email_file.endswith('.msg'):
            self.msg_grabber(email_file)
        elif email_file.endswith('.eml'):
            self.base_grabber(email_file)
        else:
            print(f"{Fore.RED}[-] Unsupported file format: {email_file.split('.')[-1]}")
            return False
        
        return True
    
    def msg_grabber(self, file):
        """Process MSG file with enhanced analysis"""
        try:
            print(f"{Fore.CYAN}[+] Processing MSG file: {file}\n")
            
            with extract_msg.openMsg(file) as messageFile:
                # Extract basic info
                print(f"{Fore.GREEN}[+] From: {Fore.RESET}{messageFile.sender}")
                print(f"{Fore.GREEN}[+] To: {Fore.RESET}{messageFile.to}")
                print(f"{Fore.GREEN}[+] Subject: {Fore.RESET}{messageFile.subject}")
                print(f"{Fore.GREEN}[+] CC: {Fore.RESET}{messageFile.cc}")
                print(f"{Fore.GREEN}[+] BCC: {Fore.RESET}{messageFile.bcc}")
                print(f"{Fore.GREEN}[+] Email Time: {Fore.RESET}{messageFile.receivedTime}")
                
                # Handle attachments
                if len(messageFile.attachments) > 0:
                    print(f"{Fore.GREEN}[+] Attachments Found: {len(messageFile.attachments)}")
                    for attachment in messageFile.attachments:
                        attachmentName = attachment.getFilename()
                        print(f"{Fore.CYAN}    - {attachmentName}")
                        try:
                            attachment.save(customPath=exportedPath)
                        except:
                            print(f"{Fore.RED}[-] Failed to save: {attachmentName}")
                else:
                    print(f"{Fore.GREEN}[+] No Attachments Found")
                
                # Extract body
                messageBody = str(messageFile.body)
                truncatedBody = messageBody.replace('\r', ' ')
                
                print(f"{Fore.GREEN}[+] Email Body Preview:\n{Fore.YELLOW}{truncatedBody[:500]}...\n")
                
                # Extract indicators
                self.extract_indicators_from_body(truncatedBody, file)
                
                # ML Analysis
                self.run_ml_analysis(file, messageFile.sender, messageFile.subject)
                
                messageFile.close()
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error processing MSG file: {e}")
    
    def base_grabber(self, file):
        """Process EML file with enhanced analysis"""
        try:
            print(f"{Fore.BLUE}{'-'*50}")
            print(f"{Fore.BLUE}[+] Processing EML file: {file}")
            print(f"{Fore.BLUE}{'-'*50}\n")
            
            # Parse email headers
            with open(file, "r", encoding="utf-8") as sample:
                headers = {}
                for line in sample:
                    if line.strip() and ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip()] = value.strip()
            
            # Display important headers
            important_headers = ['From', 'To', 'Subject', 'Date', 'Message-ID', 'Return-Path']
            for header in important_headers:
                if header in headers:
                    color = Fore.GREEN if header in ['From', 'Subject'] else Fore.YELLOW
                    print(f"{color}[+] {header}: {Fore.RESET}{headers[header]}")
            
            # Count hops
            global count
            count = 0
            with open(file, "r", encoding="utf-8") as sample:
                for line in sample:
                    if line.startswith("Received: "):
                        count += 1
            
            print(f"{Fore.RED}[+] Total HOPS Count: {count}\n")
            
            # Extract full content
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract indicators
            self.extract_indicators_from_body(content, file)
            
            # Handle attachments
            self.extract_attachments(file)
            
            # ML Analysis
            sender = headers.get('From', 'Unknown')
            subject = headers.get('Subject', 'No Subject')
            self.run_ml_analysis(file, sender, subject)
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error processing EML file: {e}")
    
    def extract_indicators_from_body(self, body, filename):
        """Extract IPs, emails, and URLs from email body"""
        print(f"{Fore.BLUE}{'-'*50}")
        print(f"{Fore.BLUE}[+] Extracting Indicators from: {filename}")
        print(f"{Fore.BLUE}{'-'*50}")
        
        # Extract IPs
        self.extract_ips(body)
        
        # Extract emails
        self.extract_emails(body)
        
        # Extract URLs
        self.extract_urls(body)
        
        # Extract X-headers
        self.extract_x_headers(filename)
    
    def extract_ips(self, body):
        """Extract and analyze IP addresses"""
        print(f"\n{Fore.YELLOW}[+] IP Addresses Found:")
        
        IPs = []
        IP_COUNT = 0
        regex = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body)
        
        try:
            if regex:
                for match in regex:
                    if match not in IPs:
                        IPs.append(match)
                        IP_COUNT += 1
                        
                        # Check if it's a suspicious IP
                        is_suspicious = self.check_suspicious_ip(match)
                        color = Fore.RED if is_suspicious else Fore.GREEN
                        
                        print(f"  {IP_COUNT}. {color}{match}")
                        
                        if is_suspicious:
                            self.analysis_summary["suspicious_ips"].append(match)
            else:
                print(f"  {Fore.GREEN}No IP addresses found")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting IPs: {e}")
    
    def extract_emails(self, body):
        """Extract and analyze email addresses"""
        print(f"\n{Fore.YELLOW}[+] Email Addresses Found:")
        
        EMAILS = []
        regex = re.findall(r'[\w\.-]+@[\w\.-]+', body)
        
        try:
            if regex:
                for match in regex:
                    if match not in EMAILS:
                        EMAILS.append(match)
                        
                        # Check if it's a suspicious email
                        is_suspicious = self.check_suspicious_email(match)
                        color = Fore.RED if is_suspicious else Fore.GREEN
                        
                        print(f"  {color}{match}")
                        
                        if is_suspicious:
                            self.analysis_summary["suspicious_emails"].append(match)
            else:
                print(f"  {Fore.GREEN}No email addresses found")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting emails: {e}")
    
    def extract_urls(self, body):
        """Extract and analyze URLs"""
        print(f"\n{Fore.YELLOW}[+] URLs Found:")
        
        URLs = []
        
        # Multiple URL patterns
        patterns = [
            r'https?://[^\s<>"\'\)]+',
            r'www\.[^\s<>"\'\)]+',
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"\'\)]*'
        ]
        
        try:
            for pattern in patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                for match in matches:
                    # Clean up the URL
                    url = match.strip()
                    url = re.sub(r'[<>"\'\)]', '', url)
                    
                    if url and url not in URLs:
                        URLs.append(url)
                        
                        # Check if it's a suspicious URL
                        is_suspicious = self.check_suspicious_url(url)
                        color = Fore.RED if is_suspicious else Fore.GREEN
                        
                        print(f"  {color}{url}")
                        
                        if is_suspicious:
                            self.analysis_summary["suspicious_urls"].append(url)
            
            if not URLs:
                print(f"  {Fore.GREEN}No URLs found")
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting URLs: {e}")
    
    def extract_x_headers(self, filename):
        """Extract X-headers for analysis"""
        print(f"\n{Fore.YELLOW}[+] X-Headers Found:")
        
        try:
            with open(filename, 'r', encoding='utf-8') as sample:
                x_headers_found = False
                for line in sample:
                    if line.startswith("X-"):
                        print(f"  {Fore.CYAN}{line.strip()}")
                        x_headers_found = True
                
                if not x_headers_found:
                    print(f"  {Fore.GREEN}No X-headers found")
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting X-headers: {e}")
    
    def extract_attachments(self, filename):
        """Extract attachments from EML file"""
        print(f"\n{Fore.YELLOW}[+] Processing Attachments:")
        
        try:
            with open(filename, "rb") as f:
                attachFile = email.message_from_bytes(f.read(), policy=policy.default)
                
                attachments_found = False
                for attachment in attachFile.iter_attachments():
                    attName = attachment.get_filename()
                    if attName:
                        print(f"  {Fore.GREEN}[+] Attachment: {Fore.RESET}{attName}")
                        
                        # Save attachment
                        try:
                            save_path = os.path.join(exportedPath, attName)
                            with open(save_path, "wb") as fileWrite:
                                fileWrite.write(attachment.get_payload(decode=True))
                            print(f"    {Fore.CYAN}Saved to: {save_path}")
                            attachments_found = True
                        except Exception as e:
                            print(f"    {Fore.RED}Failed to save: {e}")
                
                if not attachments_found:
                    print(f"  {Fore.GREEN}No attachments found")
                    
        except Exception as e:
            print(f"{Fore.RED}[-] Error processing attachments: {e}")
    
    def check_suspicious_ip(self, ip):
        """Check if IP is suspicious"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            # Check for private IPs
            if (parts[0] in ['10', '127', '192'] or 
                (parts[0] == '172' and 16 <= int(parts[1]) <= 31)):
                return True
            
            # Check for suspicious patterns
            if parts[0] in ['0', '255']:
                return True
                
        except:
            pass
        
        return False
    
    def check_suspicious_email(self, email_addr):
        """Check if email is suspicious"""
        suspicious_domains = [
            'noreply', 'no-reply', 'donotreply', 'security',
            'admin', 'support', 'billing', 'account', 'verification'
        ]
        
        email_lower = email_addr.lower()
        
        for domain in suspicious_domains:
            if domain in email_lower:
                return True
        
        return False
    
    def check_suspicious_url(self, url):
        """Check if URL is suspicious"""
        suspicious_patterns = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
            '192.168.', '10.', '127.', 'click',
            'verify', 'login', 'secure', 'account'
        ]
        
        url_lower = url.lower()
        
        for pattern in suspicious_patterns:
            if pattern in url_lower:
                return True
        
        return False
    
    def run_ml_analysis(self, filename, sender, subject):
        """Run ML-based phishing analysis"""
        print(f"\n{Fore.MAGENTA}{'='*50}")
        print(f"{Fore.MAGENTA}[+] ML PHISHING ANALYSIS")
        print(f"{Fore.MAGENTA}{'='*50}")
        
        try:
            # Analyze with our ML model
            result = analyze_email_for_phishing(filename)
            
            # Update summary
            self.analysis_summary["total_emails"] += 1
            if result.is_phishing:
                self.analysis_summary["phishing_detected"] += 1
            
            # Display results
            risk_color = Fore.RED if result.risk_score > 60 else Fore.YELLOW if result.risk_score > 30 else Fore.GREEN
            
            print(f"{Fore.CYAN}[+] File: {Fore.RESET}{filename}")
            print(f"{Fore.CYAN}[+] Sender: {Fore.RESET}{sender}")
            print(f"{Fore.CYAN}[+] Subject: {Fore.RESET}{subject}")
            print(f"{risk_color}[+] Risk Score: {Fore.RESET}{result.risk_score}/100")
            print(f"{risk_color}[+] Risk Level: {Fore.RESET}{result.risk_level}")
            print(f"{risk_color}[+] Is Phishing: {Fore.RESET}{result.is_phishing}")
            print(f"{risk_color}[+] Confidence: {Fore.RESET}{result.confidence:.2f}")
            print(f"{risk_color}[+] Processing Time: {Fore.RESET}{result.processing_time:.3f}s")
            
            # Display findings
            findings = result.findings
            print(f"\n{Fore.CYAN}[+] Analysis Findings:")
            print(f"  - URLs Found: {findings.get('urls_found', 0)}")
            print(f"  - Phishing URLs: {findings.get('phishing_urls', 0)}")
            
            if findings.get('suspicious_patterns'):
                print(f"  - Suspicious Patterns: {len(findings['suspicious_patterns'])}")
                for pattern in findings['suspicious_patterns'][:3]:
                    print(f"    * {pattern}")
            
            if findings.get('sender_analysis'):
                sender_analysis = findings['sender_analysis']
                if sender_analysis.get('suspicious'):
                    print(f"  - Sender Analysis: {Fore.RED}SUSPICIOUS")
                else:
                    print(f"  - Sender Analysis: {Fore.GREEN}LEGITIMATE")
            
            # Store result
            self.phishing_results.append({
                'file': filename,
                'sender': sender,
                'subject': subject,
                'risk_score': result.risk_score,
                'risk_level': result.risk_level,
                'is_phishing': result.is_phishing,
                'confidence': result.confidence,
                'timestamp': result.timestamp
            })
            
        except Exception as e:
            print(f"{Fore.RED}[-] ML Analysis failed: {e}")
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"{Fore.MAGENTA}[+] COMPREHENSIVE ANALYSIS REPORT")
        print(f"{Fore.MAGENTA}{'='*60}")
        
        summary = self.analysis_summary
        
        print(f"\n{Fore.CYAN}[+] SUMMARY:")
        print(f"  - Total Emails Analyzed: {summary['total_emails']}")
        print(f"  - Phishing Detected: {summary['phishing_detected']}")
        
        if summary['total_emails'] > 0:
            phishing_rate = (summary['phishing_detected'] / summary['total_emails']) * 100
            print(f"  - Phishing Rate: {phishing_rate:.1f}%")
        
        print(f"\n{Fore.CYAN}[+] THREAT INDICATORS:")
        print(f"  - Suspicious IPs: {len(summary['suspicious_ips'])}")
        for ip in summary['suspicious_ips'][:5]:
            print(f"    * {Fore.RED}{ip}")
        
        print(f"  - Suspicious Emails: {len(summary['suspicious_emails'])}")
        for email_addr in summary['suspicious_emails'][:5]:
            print(f"    * {Fore.RED}{email_addr}")
        
        print(f"  - Suspicious URLs: {len(summary['suspicious_urls'])}")
        for url in summary['suspicious_urls'][:5]:
            print(f"    * {Fore.RED}{url}")
        
        # High-risk emails
        high_risk = [r for r in self.phishing_results if r['risk_score'] > 60]
        if high_risk:
            print(f"\n{Fore.RED}[+] HIGH-RISK EMAILS:")
            for result in high_risk[:3]:
                print(f"  - {result['subject'][:50]}... ({result['risk_score']}/100)")
        
        # Save report
        self.save_report()
        
        print(f"\n{Fore.GREEN}[+] Report saved to: analysis/phishing_analyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    def save_report(self):
        """Save analysis report to file"""
        Path("analysis").mkdir(exist_ok=True)
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'summary': self.analysis_summary,
            'results': self.phishing_results
        }
        
        filename = f"analysis/phishing_analyzer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)

def main():
    """Main function"""
    analyzer = PhishingAnalyzerEnhanced()
    
    # Display banner
    analyzer.banner()
    
    # Check arguments
    if len(sys.argv) != 2:
        print(f"{Fore.YELLOW}Usage: python phishing_analyzer.py <email_file>")
        print(f"{Fore.YELLOW}Supported formats: .msg, .eml")
        return
    
    email_file = sys.argv[1]
    
    # Setup paths
    analyzer.setup_paths(email_file)
    
    # Process file
    if analyzer.file_checker(email_file):
        # Generate report
        analyzer.generate_report()
        
        print(f"\n{Fore.GREEN}[+] Analysis complete!")
        print(f"{Fore.GREEN}[+] Check the 'Attachments' folder for extracted files")
        print(f"{Fore.GREEN}[+] Check the 'analysis' folder for detailed reports")
    else:
        print(f"{Fore.RED}[-] Failed to process file: {email_file}")

if __name__ == "__main__":
    main()
