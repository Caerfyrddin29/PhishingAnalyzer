#!/usr/bin/env python3
"""
Batch PhishingAnalyzer - Process multiple emails
"""

import os
import sys
import glob
from pathlib import Path

# Add core modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'core'))

from phishing_analyzer import PhishingAnalyzerEnhanced

def main():
    """Process multiple emails"""
    print("BATCH PHISHING ANALYZER")
    print("=" * 50)
    
    # Check for directory argument or use current directory
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = "."
    
    # Find all email files
    email_files = []
    email_files.extend(glob.glob(os.path.join(directory, "*.eml")))
    email_files.extend(glob.glob(os.path.join(directory, "*.msg")))
    
    if not email_files:
        print(f"No email files found in {directory}")
        return
    
    print(f"Found {len(email_files)} email files")
    
    # Process each file
    analyzer = PhishingAnalyzerEnhanced()
    analyzer.setup_paths("batch")
    
    for i, email_file in enumerate(email_files, 1):
        print(f"\n{'='*60}")
        print(f"Processing {i}/{len(email_files)}: {email_file}")
        print(f"{'='*60}")
        
        try:
            analyzer.file_checker(email_file)
        except Exception as e:
            print(f"Error processing {email_file}: {e}")
    
    # Generate final report
    analyzer.generate_report()
    
    print(f"\nBATCH ANALYSIS COMPLETE!")
    print(f"Processed {len(email_files)} files")
    print(f"Reports saved in 'analysis/' folder")

if __name__ == "__main__":
    main()
