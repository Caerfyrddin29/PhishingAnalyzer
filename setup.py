#!/usr/bin/env python3
"""
PhishAnalyzer Setup Script
Automated installation and configuration
"""

import os
import sys
import subprocess
import webbrowser
import time
from pathlib import Path

def check_python_version():
    """Check if Python 3.7+ is installed"""
    if sys.version_info < (3, 7):
        print("ERROR: Python 3.7+ is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"Python {sys.version.split()[0]} detected")
    return True

def install_dependencies():
    """Install required Python packages"""
    print("\nInstalling Python dependencies...")
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        return False

def create_desktop_shortcut():
    """Create desktop shortcut for the API server"""
    try:
        import winshell
        from win32com.client import Dispatch
        
        desktop = winshell.desktop()
        path = os.path.join(desktop, "PhishAnalyzer API.lnk")
        target = os.path.join(os.getcwd(), "start_api_server.bat")
        wDir = os.getcwd()
        icon = os.path.join(os.getcwd(), "api_server.py")
        
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = wDir
        shortcut.IconLocation = icon
        shortcut.save()
        
        print("Desktop shortcut created")
        return True
    except ImportError:
        print("WARNING: Could not create desktop shortcut (winshell not available)")
        return False
    except Exception as e:
        print(f"WARNING: Could not create desktop shortcut: {e}")
        return False

def create_start_script():
    """Create batch file to start API server"""
    script_content = '''@echo off
title PhishAnalyzer API Server
echo Starting PhishAnalyzer API Server...
echo Server will be available at: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo.
echo Press Ctrl+C to stop the server
echo.

python api_server.py

pause
'''
    
    with open("start_api_server.bat", "w") as f:
        f.write(script_content)
    
    print("Created start_api_server.bat")

def create_extension_install_guide():
    """Create HTML guide for extension installation"""
    guide_content = '''<!DOCTYPE html>
<html>
<head>
    <title>PhishAnalyzer Extension Installation</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .step { margin: 20px 0; padding: 15px; border-left: 4px solid #0078d4; background: #f5f5f5; }
        .code { background: #f0f0f0; padding: 10px; border-radius: 4px; font-family: monospace; }
        .warning { background: #fff3cd; border-color: #ffc107; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .success { background: #d4edda; border-color: #28a745; padding: 15px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>🛡️ PhishAnalyzer Extension Installation</h1>
    
    <div class="warning">
        <strong>⚠️ Important:</strong> Make sure the API server is running before using the extension!
    </div>
    
    <h2>Step 1: Start the API Server</h2>
    <div class="step">
        <p>Double-click on <strong>start_api_server.bat</strong> or run:</p>
        <div class="code">python api_server.py</div>
        <p>You should see "Starting PhishAnalyzer API Server..."</p>
    </div>
    
    <h2>Step 2: Install Browser Extension</h2>
    
    <h3>For Chrome/Edge:</h3>
    <div class="step">
        <ol>
            <li>Open Chrome/Edge and go to <code>chrome://extensions/</code></li>
            <li>Enable "Developer mode" (top right toggle)</li>
            <li>Click "Load unpacked"</li>
            <li>Select the <strong>browser-extension</strong> folder</li>
            <li>The PhishAnalyzer extension should appear in your list</li>
        </ol>
    </div>
    
    <h3>For Firefox:</h3>
    <div class="step">
        <ol>
            <li>Open Firefox and go to <code>about:debugging</code></li>
            <li>Click "This Firefox" on the left</li>
            <li>Click "Load Temporary Add-on"</li>
            <li>Select the <strong>manifest.json</strong> file from the browser-extension folder</li>
            <li>The extension will be loaded temporarily</li>
        </ol>
    </div>
    
    <h2>Step 3: Add Extension Icons</h2>
    <div class="step">
        <p>Add icon files to the <strong>browser-extension/icons/</strong> folder:</p>
        <ul>
            <li>icon16.png (16x16 pixels)</li>
            <li>icon32.png (32x32 pixels)</li>
            <li>icon48.png (48x48 pixels)</li>
            <li>icon128.png (128x128 pixels)</li>
        </ul>
        <p>See the README.md in the icons folder for recommendations.</p>
    </div>
    
    <h2>Step 4: Test the Extension</h2>
    <div class="step">
        <ol>
            <li>Open Gmail or Outlook in your browser</li>
            <li>You should see "🛡️ Analyze" buttons next to emails</li>
            <li>Click the extension icon in your browser toolbar</li>
            <li>The popup should show "API Server: Online"</li>
        </ol>
    </div>
    
    <div class="success">
        <strong>Installation Complete!</strong><br>
        Your PhishAnalyzer extension is now ready to protect you from phishing emails!
    </div>
    
    <h2>Troubleshooting</h2>
    <div class="step">
        <ul>
            <li><strong>API Server Offline:</strong> Make sure the Python server is running</li>
            <li><strong>Extension Not Working:</strong> Reload the email page after installation</li>
            <li><strong>No Buttons in Gmail:</strong> Try refreshing the page or checking extension permissions</li>
            <li><strong>Analysis Failed:</strong> Check the API server console for error messages</li>
        </ul>
    </div>
</body>
</html>'''
    
    with open("extension_install_guide.html", "w") as f:
        f.write(guide_content)
    
    print("Created extension_install_guide.html")

def print_next_steps():
    """Print next steps for the user"""
    print("\n" + "="*60)
    print("PHISHANALYZER SETUP COMPLETE!")
    print("="*60)
    
    print("\nNEXT STEPS:")
    print("1. Start the API server:")
    print("   → Double-click: start_api_server.bat")
    print("   → Or run: python api_server.py")
    
    print("\n2. Install the browser extension:")
    print("   → Open extension_install_guide.html for detailed instructions")
    print("   → Chrome/Edge: chrome://extensions/ → Load unpacked")
    print("   → Firefox: about:debugging → Load Temporary Add-on")
    
    print("\n3. Add icons to browser-extension/icons/ folder")
    
    print("\n4. Test on Gmail or Outlook")
    
    print("\nAPI Documentation: http://localhost:8000/docs")
    print("Extension Guide: extension_install_guide.html")
    
    print("\nIMPORTANT: Always keep the API server running while using the extension!")

def main():
    """Main setup process"""
    print("PHISHANALYZER SETUP")
    print("="*40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Create startup script
    create_start_script()
    
    # Create desktop shortcut (optional)
    create_desktop_shortcut()
    
    # Create extension installation guide
    create_extension_install_guide()
    
    # Print next steps
    print_next_steps()
    
    # Open installation guide in browser
    try:
        webbrowser.open('extension_install_guide.html')
        print("\nInstallation guide opened in your browser")
    except:
        print("\nCould not open installation guide automatically")
        print("   Open extension_install_guide.html manually")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        if success:
            input("\nPress Enter to exit...")
        else:
            input("\nSetup failed. Press Enter to exit...")
    except KeyboardInterrupt:
        print("\n\nSetup cancelled by user")
    except Exception as e:
        print(f"\nSetup error: {e}")
        input("Press Enter to exit...")
