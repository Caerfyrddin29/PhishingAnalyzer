#!/usr/bin/env python3
"""
PhishAnalyzer - Advanced Email Forensics Tool
A comprehensive email analysis tool for phishing investigation and security research.
"""

import email
from email import policy
import sys
import os
import re
import json
from typing import List, Dict, Optional
import colorama
import extract_msg
from colorama import Fore, Style
colorama.init(autoreset=True)

class PhishAnalyzer:
    """Main class for email forensic analysis"""
    
    def __init__(self, email_file: str):
        self.email_file = email_file
        self.attachments_dir = "Extracted_Attachments"
        self.analysis_results = {}
        self._setup_directories()
    
    def _setup_directories(self):
        """Create necessary directories for analysis"""
        try:
            if not os.path.exists(self.attachments_dir):
                os.makedirs(self.attachments_dir)
                print(f"{Fore.CYAN}[+] Created directory: {self.attachments_dir}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error creating directory: {e}")
    
    def analyze(self) -> Dict:
        """Main analysis pipeline"""
        print(f"{Fore.BLUE}{'='*60}")
        print(f"{Fore.BLUE}PHISHANALYZER - EMAIL FORENSICS TOOL")
        print(f"{Fore.BLUE}{'='*60}\n")
        
        file_ext = os.path.splitext(self.email_file)[1].lower()
        
        if file_ext == '.msg':
            return self._analyze_msg_file()
        elif file_ext == '.eml':
            return self._analyze_eml_file()
        else:
            raise ValueError(f"Unsupported file format: {file_ext}")
    
    def _analyze_msg_file(self) -> Dict:
        """Analyze Outlook MSG files"""
        try:
            print(f"{Fore.CYAN}[+] Analyzing MSG file: {self.email_file}\n")
            
            with extract_msg.openMsg(self.email_file) as msg:
                # Extract metadata
                metadata = {
                    'sender': str(msg.sender),
                    'to': str(msg.to),
                    'cc': str(msg.cc),
                    'bcc': str(msg.bcc),
                    'subject': str(msg.subject),
                    'received_time': str(msg.receivedTime),
                    'file_type': 'MSG'
                }
                
                self._print_metadata(metadata)
                
                # Process body
                body = str(msg.body)
                self._analyze_body_content(body)
                
                # Process attachments
                self._process_msg_attachments(msg.attachments)
                
                return metadata
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error analyzing MSG file: {e}")
            return {}
    
    def _analyze_eml_file(self) -> Dict:
        """Analyze EML files"""
        try:
            print(f"{Fore.CYAN}[+] Analyzing EML file: {self.email_file}\n")
            
            with open(self.email_file, "r", encoding="utf-8") as f:
                email_content = f.read()
            
            # Parse email
            msg = email.message_from_string(email_content, policy=policy.default)
            
            # Extract metadata
            metadata = {
                'from': msg.get('From', 'N/A'),
                'to': msg.get('To', 'N/A'),
                'subject': msg.get('Subject', 'N/A'),
                'date': msg.get('Date', 'N/A'),
                'message_id': msg.get('Message-ID', 'N/A'),
                'return_path': msg.get('Return-Path', 'N/A'),
                'file_type': 'EML'
            }
            
            self._print_metadata(metadata)
            self._count_email_hops(email_content)
            
            # Analyze content
            self._analyze_body_content(email_content)
            self._extract_eml_attachments(msg)
            self._extract_x_headers(email_content)
            
            return metadata
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error analyzing EML file: {e}")
            return {}
    
    def _print_metadata(self, metadata: Dict):
        """Display email metadata"""
        print(f"{Fore.GREEN}{'='*40}")
        print(f"{Fore.GREEN}EMAIL METADATA")
        print(f"{Fore.GREEN}{'='*40}")
        
        for key, value in metadata.items():
            if value and value != 'N/A':
                print(f"{Fore.YELLOW}[+] {key.replace('_', ' ').title()}: {Style.RESET_ALL}{value}")
        print()
    
    def _count_email_hops(self, content: str):
        """Count email server hops from Received headers"""
        hop_count = content.count('Received:')
        print(f"{Fore.MAGENTA}[+] Email Hops (Server Transitions): {hop_count}\n")
    
    def _analyze_body_content(self, content: str):
        """Analyze email body for IPs, emails, and URLs"""
        print(f"{Fore.BLUE}{'='*40}")
        print(f"{Fore.BLUE}CONTENT ANALYSIS")
        print(f"{Fore.BLUE}{'='*40}")
        
        # Extract IP addresses
        self._extract_ip_addresses(content)
        
        # Extract email addresses
        self._extract_email_addresses(content)
        
        # Extract URLs
        self._extract_urls(content)
    
    def _extract_ip_addresses(self, content: str):
        """Extract and display IP addresses"""
        print(f"\n{Fore.CYAN}[+] IP Addresses Found:")
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, content)
        
        unique_ips = list(set(ips))
        for i, ip in enumerate(unique_ips, 1):
            print(f"  {i}. {Fore.GREEN}{ip}")
        
        if not unique_ips:
            print(f"  {Fore.YELLOW}No IP addresses found")
    
    def _extract_email_addresses(self, content: str):
        """Extract and display email addresses"""
        print(f"\n{Fore.CYAN}[+] Email Addresses Found:")
        email_pattern = r'[\w\.-]+@[\w\.-]+'
        emails = re.findall(email_pattern, content)
        
        unique_emails = list(set(emails))
        for i, email_addr in enumerate(unique_emails, 1):
            print(f"  {i}. {Fore.GREEN}{email_addr}")
        
        if not unique_emails:
            print(f"  {Fore.YELLOW}No email addresses found")
    
    def _extract_urls(self, content: str):
        """Extract and display URLs"""
        print(f"\n{Fore.CYAN}[+] URLs Found:")
        
        # HTTP/HTTPS URLs
        url_pattern = r'https?://[^\s<>"\'\)]+'
        urls = re.findall(url_pattern, content)
        
        # Domain names
        domain_pattern = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
        domains = re.findall(domain_pattern, content.lower())
        
        all_urls = list(set(urls + [f"http://{domain}" for domain in domains if not any(url.endswith(domain) for url in urls)]))
        
        for i, url in enumerate(all_urls, 1):
            print(f"  {i}. {Fore.GREEN}{url}")
        
        if not all_urls:
            print(f"  {Fore.YELLOW}No URLs found")
    
    def _process_msg_attachments(self, attachments):
        """Process and save MSG file attachments"""
        if attachments:
            print(f"\n{Fore.MAGENTA}[+] Attachments Found ({len(attachments)}):")
            for i, attachment in enumerate(attachments, 1):
                filename = attachment.getFilename()
                print(f"  {i}. {Fore.YELLOW}{filename}")
                try:
                    attachment.save(customPath=self.attachments_dir)
                    print(f"    {Fore.GREEN}→ Saved to {self.attachments_dir}/")
                except Exception as e:
                    print(f"    {Fore.RED}→ Error saving: {e}")
        else:
            print(f"\n{Fore.YELLOW}[+] No attachments found")
    
    def _extract_eml_attachments(self, msg):
        """Extract and save EML file attachments"""
        attachments = []
        
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
                try:
                    filepath = os.path.join(self.attachments_dir, filename)
                    with open(filepath, "wb") as f:
                        f.write(part.get_payload(decode=True))
                    print(f"{Fore.GREEN}[+] Attachment saved: {filename}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error saving attachment {filename}: {e}")
        
        if not attachments:
            print(f"{Fore.YELLOW}[+] No attachments found")
    
    def _extract_x_headers(self, content: str):
        """Extract and display X-headers"""
        print(f"\n{Fore.BLUE}{'='*40}")
        print(f"{Fore.BLUE}X-HEADERS ANALYSIS")
        print(f"{Fore.BLUE}{'='*40}")
        
        x_headers = []
        for line in content.split('\n'):
            if line.strip().startswith('X-'):
                x_headers.append(line.strip())
        
        if x_headers:
            for header in x_headers:
                print(f"{Fore.CYAN}{header}")
        else:
            print(f"{Fore.YELLOW}No X-headers found")
    
    def generate_report(self) -> str:
        """Generate analysis report"""
        report_file = f"analysis_report_{os.path.basename(self.email_file)}.json"
        
        try:
            with open(report_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=2)
            print(f"\n{Fore.GREEN}[+] Analysis report saved: {report_file}")
            return report_file
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving report: {e}")
            return ""

def display_banner():
    """Display custom banner"""
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    PHISHANALYZER v2.0                        ║
║              Advanced Email Forensics Tool                   ║
║                                                              ║
║  • Analyze MSG and EML email formats                         ║
║  • Extract metadata, attachments, URLs, IPs                  ║
║  • Comprehensive header analysis                             ║
║  • Generate detailed reports                                 ║
║                                                              ║
║  Usage: python PhishAnalyzer.py <email_file>                 ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def main():
    """Main entry point"""
    display_banner()
    
    if len(sys.argv) != 2:
        print(f"{Fore.RED}[-] Usage: python PhishAnalyzer.py <email_file>")
        print(f"{Fore.YELLOW}    Supported formats: .msg, .eml")
        sys.exit(1)
    
    email_file = sys.argv[1]
    
    if not os.path.exists(email_file):
        print(f"{Fore.RED}[-] File not found: {email_file}")
        sys.exit(1)
    
    try:
        analyzer = PhishAnalyzer(email_file)
        results = analyzer.analyze()
        analyzer.generate_report()
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}ANALYSIS COMPLETE")
        print(f"{Fore.GREEN}{'='*60}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
