#!/usr/bin/env python3
"""
PhishingAnalyzer - Simple Entry Point
Professional email phishing detection system
"""

import sys
import os
from pathlib import Path

# Add core modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

def show_banner():
    """Display PhishingAnalyzer banner"""
    print("""
    PHISHING ANALYZER - EMAIL SECURITY
    ================================
    
    Usage:
    - Analyze email: python phishing_analyzer.py <file.eml>
    - Batch analysis: python batch_analyzer.py [directory]
    - Download emails: python email_downloader.py
    - Setup system: python setup_analyzer.py
    """)

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        show_banner()
        return
    
    command = sys.argv[1].lower()
    
    if command == "analyze":
        if len(sys.argv) < 3:
            print("Usage: python main.py analyze <email_file>")
            return
        
        from phishing_analyzer import PhishingAnalyzerEnhanced
        analyzer = PhishingAnalyzerEnhanced()
        analyzer.setup_paths(sys.argv[2])
        analyzer.file_checker(sys.argv[2])
        analyzer.generate_report()
    
    elif command == "batch":
        directory = sys.argv[2] if len(sys.argv) > 2 else "."
        from batch_analyzer import main as batch_main
        sys.argv = ["batch_analyzer.py", directory]
        batch_main()
    
    elif command == "download":
        from email_downloader import main as download_main
        download_main()
    
    elif command == "setup":
        from setup_analyzer import main as setup_main
        setup_main()
    
    else:
        print(f"Unknown command: {command}")
        show_banner()

if __name__ == "__main__":
    main()
