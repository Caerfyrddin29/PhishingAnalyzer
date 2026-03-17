#!/usr/bin/env python3
"""
PhishingAnalyzer Email Downloader and Analyzer
Professional email fetching and local phishing analysis system
"""

import os
import json
import time
import imaplib
import email
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import pickle
import sys

# Email processing
import email
from email.parser import BytesParser
from email.policy import default

# Add core modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

# Import our phishing analyzer
from core.email_phishing_analyzer import analyze_email_for_phishing

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class EmailAccount:
    """Email account configuration"""
    email: str
    password: str
    imap_server: str
    imap_port: int
    provider: str
    
@dataclass
class EmailMessage:
    """Email message structure"""
    subject: str
    from_addr: str
    to_addr: str
    date: str
    message_id: str
    content: str
    attachments: List[str]
    size: int
    folder: str
    
@dataclass
class AnalysisResult:
    """Email phishing analysis result"""
    email_id: str
    subject: str
    from_addr: str
    risk_score: int
    risk_level: str
    is_phishing: bool
    confidence: float
    findings: Dict[str, Any]
    analysis_time: str
    processing_time: float

class PhishingAnalyzerEmailDownloader:
    """Professional email downloader for phishing analysis"""
    
    def __init__(self):
        self.accounts = []
        self.downloaded_emails = []
        self.analysis_results = []
        self.config_file = "email_accounts.json"
        self.emails_file = "downloaded_emails.json"
        self.analysis_file = "analysis_results.json"
        
        # Create directories
        Path("emails").mkdir(exist_ok=True)
        Path("analysis").mkdir(exist_ok=True)
        Path("config").mkdir(exist_ok=True)
        
        # Load configuration
        self.load_accounts()
        
    def load_accounts(self):
        """Load email accounts from configuration"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.accounts = [EmailAccount(**acc) for acc in data.get('accounts', [])]
                logger.info(f"Loaded {len(self.accounts)} email accounts")
            except Exception as e:
                logger.error(f"Failed to load accounts: {e}")
                self.accounts = []
        else:
            logger.info("No accounts file found, creating example configuration")
            self.create_example_config()
    
    def create_example_config(self):
        """Create example configuration file"""
        example_config = {
            "accounts": [
                {
                    "email": "your.email@gmail.com",
                    "password": "your_app_password",
                    "imap_server": "imap.gmail.com",
                    "imap_port": 993,
                    "provider": "gmail"
                },
                {
                    "email": "your.email@outlook.com",
                    "password": "your_app_password",
                    "imap_server": "outlook.office365.com",
                    "imap_port": 993,
                    "provider": "outlook"
                }
            ]
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(example_config, f, indent=2)
        
        logger.info(f"Created example configuration: {self.config_file}")
        logger.info("Please edit this file with your actual email credentials")
    
    def add_account(self, email_addr: str, password: str, provider: str):
        """Add email account"""
        if provider.lower() == "gmail":
            imap_server = "imap.gmail.com"
            imap_port = 993
        elif provider.lower() in ["outlook", "hotmail", "live"]:
            imap_server = "outlook.office365.com"
            imap_port = 993
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        account = EmailAccount(
            email=email_addr,
            password=password,
            imap_server=imap_server,
            imap_port=imap_port,
            provider=provider
        )
        
        self.accounts.append(account)
        self.save_accounts()
        logger.info(f"Added account: {email_addr}")
    
    def save_accounts(self):
        """Save email accounts to configuration"""
        data = {
            "accounts": [asdict(acc) for acc in self.accounts]
        }
        with open(self.config_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def connect_to_imap(self, account: EmailAccount) -> imaplib.IMAP4_SSL:
        """Connect to IMAP server"""
        try:
            mail = imaplib.IMAP4_SSL(account.imap_server, account.imap_port)
            mail.login(account.email, account.password)
            logger.info(f"Connected to {account.provider} for {account.email}")
            return mail
        except Exception as e:
            logger.error(f"Failed to connect to {account.provider}: {e}")
            raise
    
    def get_email_folders(self, mail: imaplib.IMAP4_SSL) -> List[str]:
        """Get available email folders"""
        try:
            _, folders = mail.list()
            folder_list = []
            
            for folder in folders:
                folder_name = folder.decode('utf-8')
                # Extract folder name from IMAP response
                if '"' in folder_name:
                    folder_name = folder_name.split('"')[-2]
                folder_list.append(folder_name)
            
            return folder_list
        except Exception as e:
            logger.error(f"Failed to get folders: {e}")
            return ["INBOX"]  # Default fallback
    
    def download_emails_from_folder(self, account: EmailAccount, folder: str, 
                                   limit: int = 50, days_back: int = 7) -> List[EmailMessage]:
        """Download emails from specific folder"""
        messages = []
        
        try:
            mail = self.connect_to_imap(account)
            
            # Select folder
            status, messages_count = mail.select(f'"{folder}"')
            if status != 'OK':
                logger.error(f"Failed to select folder: {folder}")
                return messages
            
            # Search for recent emails
            date_since = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
            search_criteria = f'(SINCE {date_since})'
            
            status, email_ids = mail.search(None, search_criteria)
            if status != 'OK':
                logger.error(f"Failed to search emails in {folder}")
                return messages
            
            email_id_list = email_ids[0].split()
            
            # Limit number of emails
            if len(email_id_list) > limit:
                email_id_list = email_id_list[-limit:]  # Get most recent
            
            logger.info(f"Found {len(email_id_list)} emails in {folder}")
            
            # Download each email
            for email_id in email_id_list:
                try:
                    # Fetch email
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    if status != 'OK':
                        continue
                    
                    # Parse email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email, policy=default)
                    
                    # Extract email data
                    subject = str(msg.get('Subject', ''))
                    from_addr = str(msg.get('From', ''))
                    to_addr = str(msg.get('To', ''))
                    date = str(msg.get('Date', ''))
                    message_id = str(msg.get('Message-ID', ''))
                    
                    # Extract content
                    content = self.extract_email_content(msg)
                    
                    # Extract attachments
                    attachments = self.extract_attachments(msg)
                    
                    # Create email message
                    email_msg = EmailMessage(
                        subject=subject,
                        from_addr=from_addr,
                        to_addr=to_addr,
                        date=date,
                        message_id=message_id,
                        content=content,
                        attachments=attachments,
                        size=len(raw_email),
                        folder=folder
                    )
                    
                    messages.append(email_msg)
                    
                    # Save email to file
                    self.save_email_to_file(email_msg, account.email)
                    
                except Exception as e:
                    logger.error(f"Failed to process email {email_id}: {e}")
                    continue
            
            mail.logout()
            logger.info(f"Downloaded {len(messages)} emails from {folder}")
            
        except Exception as e:
            logger.error(f"Failed to download from {folder}: {e}")
        
        return messages
    
    def extract_email_content(self, msg) -> str:
        """Extract text content from email"""
        content = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain":
                    try:
                        content += part.get_content() + "\n"
                    except:
                        pass
                elif content_type == "text/html":
                    try:
                        # Extract text from HTML
                        html_content = part.get_content()
                        # Simple HTML tag removal
                        import re
                        content += re.sub(r'<[^>]+>', '', html_content) + "\n"
                    except:
                        pass
        else:
            try:
                content = msg.get_content()
            except:
                content = str(msg.get_payload())
        
        return content
    
    def extract_attachments(self, msg) -> List[str]:
        """Extract attachment names from email"""
        attachments = []
        
        for part in msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
        
        return attachments
    
    def save_email_to_file(self, email_msg: EmailMessage, account_email: str):
        """Save email to file for analysis"""
        # Create safe filename
        safe_subject = "".join(c for c in email_msg.subject if c.isalnum() or c in (' ', '-', '_')).rstrip()
        if not safe_subject:
            safe_subject = "no_subject"
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{safe_subject[:50]}_{account_email[:20]}.eml"
        
        # Create email content
        email_content = f"""From: {email_msg.from_addr}
To: {email_msg.to_addr}
Subject: {email_msg.subject}
Date: {email_msg.date}
Message-ID: {email_msg.message_id}

{email_msg.content}
"""
        
        # Save to emails folder
        filepath = Path("emails") / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(email_content)
        
        logger.info(f"Saved email: {filename}")
    
    def download_all_emails(self, limit_per_folder: int = 50, days_back: int = 7):
        """Download emails from all accounts and folders"""
        all_messages = []
        
        for account in self.accounts:
            try:
                mail = self.connect_to_imap(account)
                folders = self.get_email_folders(mail)
                mail.logout()
                
                # Focus on important folders
                important_folders = ['INBOX', 'Spam', 'Junk', 'Phishing']
                available_folders = [f for f in important_folders if f in folders]
                
                if not available_folders:
                    available_folders = ['INBOX']  # Fallback
                
                logger.info(f"Checking folders for {account.email}: {available_folders}")
                
                for folder in available_folders:
                    try:
                        messages = self.download_emails_from_folder(
                            account, folder, limit_per_folder, days_back
                        )
                        all_messages.extend(messages)
                        
                        # Add delay to avoid rate limiting
                        time.sleep(1)
                        
                    except Exception as e:
                        logger.error(f"Failed to download from {folder}: {e}")
                        continue
                
            except Exception as e:
                logger.error(f"Failed to process account {account.email}: {e}")
                continue
        
        self.downloaded_emails = all_messages
        
        # Save to file
        with open(self.emails_file, 'w') as f:
            json.dump([asdict(msg) for msg in all_messages], f, indent=2)
        
        logger.info(f"Downloaded {len(all_messages)} total emails")
        return all_messages
    
    def analyze_downloaded_emails(self) -> List[AnalysisResult]:
        """Analyze downloaded emails for phishing"""
        results = []
        
        logger.info(f"Analyzing {len(self.downloaded_emails)} emails...")
        
        for i, email_msg in enumerate(self.downloaded_emails):
            try:
                # Create temporary email file
                temp_file = f"temp_email_{i}.eml"
                
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(f"""From: {email_msg.from_addr}
To: {email_msg.to_addr}
Subject: {email_msg.subject}
Date: {email_msg.date}
Message-ID: {email_msg.message_id}

{email_msg.content}
""")
                
                # Analyze with our phishing detector
                analysis = analyze_email_for_phishing(temp_file)
                
                # Create analysis result
                result = AnalysisResult(
                    email_id=email_msg.message_id,
                    subject=email_msg.subject,
                    from_addr=email_msg.from_addr,
                    risk_score=analysis.risk_score,
                    risk_level=analysis.risk_level,
                    is_phishing=analysis.is_phishing,
                    confidence=analysis.confidence,
                    findings=analysis.findings,
                    analysis_time=analysis.timestamp,
                    processing_time=analysis.processing_time
                )
                
                results.append(result)
                
                # Clean up temp file
                os.remove(temp_file)
                
                # Log phishing detection
                if analysis.is_phishing:
                    logger.warning(f"PHISHING DETECTED: {email_msg.subject} from {email_msg.from_addr}")
                else:
                    logger.info(f"Safe: {email_msg.subject} from {email_msg.from_addr}")
                
            except Exception as e:
                logger.error(f"Failed to analyze email {i}: {e}")
                continue
        
        self.analysis_results = results
        
        # Save results
        with open(self.analysis_file, 'w') as f:
            json.dump([asdict(result) for result in results], f, indent=2)
        
        logger.info(f"Analysis complete: {len(results)} emails processed")
        return results
    
    def generate_report(self) -> str:
        """Generate comprehensive analysis report"""
        if not self.analysis_results:
            return "No analysis results available"
        
        total_emails = len(self.analysis_results)
        phishing_emails = sum(1 for r in self.analysis_results if r.is_phishing)
        safe_emails = total_emails - phishing_emails
        
        # Risk distribution
        risk_levels = {}
        for result in self.analysis_results:
            level = result.risk_level
            risk_levels[level] = risk_levels.get(level, 0) + 1
        
        # Average risk score
        avg_risk = sum(r.risk_score for r in self.analysis_results) / total_emails
        
        report = f"""
PHISHING ANALYZER EMAIL ANALYSIS REPORT
{'='*50}

SUMMARY:
- Total Emails Analyzed: {total_emails}
- Phishing Detected: {phishing_emails} ({phishing_emails/total_emails*100:.1f}%)
- Safe Emails: {safe_emails} ({safe_emails/total_emails*100:.1f}%)
- Average Risk Score: {avg_risk:.1f}/100

RISK DISTRIBUTION:
"""
        
        for level, count in risk_levels.items():
            percentage = count / total_emails * 100
            report += f"- {level}: {count} ({percentage:.1f}%)\n"
        
        report += f"\nHIGH-RISK EMAILS:\n"
        
        high_risk = [r for r in self.analysis_results if r.risk_level in ['HIGH', 'CRITICAL']]
        for i, result in enumerate(high_risk[:10]):  # Top 10
            report += f"""
{i+1}. {result.subject[:50]}...
   From: {result.from_addr}
   Risk: {result.risk_score}/100 ({result.risk_level})
   Confidence: {result.confidence:.2f}
   URLs Found: {result.findings.get('urls_found', 0)}
   Phishing URLs: {result.findings.get('phishing_urls', 0)}
"""
        
        report += f"\nANALYSIS COMPLETED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        # Save report
        report_file = f"analysis/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_file, 'w') as f:
            f.write(report)
        
        return report
    
    def run_full_analysis(self, limit_per_folder: int = 50, days_back: int = 7):
        """Run complete email download and analysis"""
        logger.info("Starting PhishingAnalyzer Email Analysis")
        logger.info("="*50)
        
        # Step 1: Download emails
        logger.info("Step 1: Downloading emails...")
        self.download_all_emails(limit_per_folder, days_back)
        
        # Step 2: Analyze emails
        logger.info("Step 2: Analyzing emails for phishing...")
        self.analyze_downloaded_emails()
        
        # Step 3: Generate report
        logger.info("Step 3: Generating analysis report...")
        report = self.generate_report()
        
        print(report)
        logger.info("Analysis complete!")
        
        return self.analysis_results

def main():
    """Main function for PhishingAnalyzer email analyzer"""
    print("PHISHING ANALYZER EMAIL DOWNLOADER")
    print("="*50)
    print("Professional email downloading and phishing detection")
    print()
    
    analyzer = PhishingAnalyzerEmailDownloader()
    
    # Check if accounts configured
    if not analyzer.accounts:
        print("No email accounts configured!")
        print("Please edit 'email_accounts.json' with your credentials")
        print("Example accounts have been created for you")
        return
    
    print(f"Found {len(analyzer.accounts)} configured accounts")
    
    # Run analysis
    try:
        results = analyzer.run_full_analysis(limit_per_folder=25, days_back=3)
        
        if results:
            phishing_count = sum(1 for r in results if r.is_phishing)
            print(f"\nAnalysis Complete: {len(results)} emails analyzed")
            print(f"Phishing detected: {phishing_count} emails")
            print(f"Reports saved in 'analysis/' folder")
        else:
            print("No emails were analyzed")
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
    except Exception as e:
        print(f"Analysis failed: {e}")

if __name__ == "__main__":
    main()
