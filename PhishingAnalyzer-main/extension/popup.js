// PhishingAnalyzer Pro - Popup Script
// This script handles the extension popup UI

document.addEventListener('DOMContentLoaded', function() {
    console.log('PhishingAnalyzer popup loaded');
    
    const analyzeBtn = document.getElementById('analyzeBtn');
    const statusDiv = document.getElementById('status');
    const statusContent = document.getElementById('statusContent');
    const loadingDiv = document.getElementById('loading');
    
    // Check if API server is running
    checkApiStatus();
    
    // Get current tab and set up analyze button
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        if (tabs.length === 0) {
            showError('No active tab found');
            return;
        }
        
        const currentTab = tabs[0];
        const url = currentTab.url || '';
        
        console.log('Current tab URL:', url);
        
        // Check if we're on Gmail
        const isGmail = url.includes('mail.google.com') || url.includes('gmail.com');
        
        if (isGmail) {
            analyzeBtn.textContent = '🔍 Analyze Current Email';
            analyzeBtn.onclick = function() {
                console.log('Analyze email clicked');
                analyzeEmail(currentTab);
            };
        } else {
            analyzeBtn.textContent = '🌐 Analyze This Page';
            analyzeBtn.onclick = function() {
                console.log('Analyze page clicked');
                analyzePage(currentTab);
            };
        }
    });
    
    // Function to check API status
    async function checkApiStatus() {
        try {
            const response = await fetch('http://localhost:8000/health', {
                method: 'GET',
                timeout: 3000
            });
            if (response.ok) {
                console.log('API server is running');
            }
        } catch (error) {
            console.warn('API server not detected:', error);
            showWarning('⚠️ API server not running. Start it with: python email_api_server.py');
        }
    }
    
    // Analyze email in Gmail
    function analyzeEmail(tab) {
        showLoading();
        
        // Send message to content script to get email content
        chrome.tabs.sendMessage(tab.id, {action: 'getEmailContent'}, function(response) {
            if (chrome.runtime.lastError) {
                hideLoading();
                showError('Content script not loaded. Refresh the page and try again.');
                return;
            }
            
            if (!response || !response.success) {
                hideLoading();
                showError('Could not extract email content. Make sure you have an email open.');
                return;
            }
            
            // Send to API for analysis
            analyzeEmailViaApi(response.emailData);
        });
    }
    
    // Analyze email via API
    async function analyzeEmailViaApi(emailData) {
        try {
            console.log('Sending email to API for analysis');
            
            // Create FormData with email content
            const formData = new FormData();
            const blob = new Blob([emailData.content || ''], { type: 'text/plain' });
            formData.append('file', blob, 'email.eml');
            
            const response = await fetch('http://localhost:8000/analyze/email', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const result = await response.json();
            console.log('Analysis result:', result);
            
            hideLoading();
            showEmailResult(result, emailData);
            
        } catch (error) {
            console.error('Analysis error:', error);
            hideLoading();
            showError('Analysis failed: ' + error.message);
        }
    }
    
    // Analyze current page URL
    async function analyzePage(tab) {
        showLoading();
        
        try {
            const response = await fetch('http://localhost:8000/analyze/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: tab.url })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const result = await response.json();
            console.log('URL analysis result:', result);
            
            hideLoading();
            showUrlResult(result);
            
        } catch (error) {
            console.error('URL analysis error:', error);
            hideLoading();
            showError('URL analysis failed: ' + error.message);
        }
    }
    
    // Show email analysis result
    function showEmailResult(result, emailData) {
        const riskLevel = result.risk_level || 'UNKNOWN';
        const isPhishing = result.is_phishing || result.risk_score > 60;
        
        // Color scheme
        const colors = {
            'LOW': { bg: '#27ae60', text: 'SAFE ✅', border: '#27ae60' },
            'MEDIUM': { bg: '#f39c12', text: 'CAUTION ⚠️', border: '#f39c12' },
            'HIGH': { bg: '#e74c3c', text: 'DANGER 🚨', border: '#e74c3c' },
            'CRITICAL': { bg: '#8b0000', text: 'PHISHING! 🚨', border: '#8b0000' },
            'ERROR': { bg: '#7f8c8d', text: 'ERROR ⚠️', border: '#7f8c8d' },
            'UNKNOWN': { bg: '#7f8c8d', text: 'UNKNOWN ❓', border: '#7f8c8d' }
        };
        
        const color = colors[riskLevel] || colors['UNKNOWN'];
        const confidence = result.confidence ? (result.confidence * 100).toFixed(1) : 'N/A';
        
        statusContent.innerHTML = `
            <div style="
                background: ${color.bg};
                color: white;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 15px;
                text-align: center;
                font-weight: bold;
            ">
                <div style="font-size: 28px; margin-bottom: 8px;">${isPhishing ? '🚨' : '✅'}</div>
                <div style="font-size: 16px;">${color.text}</div>
                <div style="font-size: 13px; margin-top: 5px; opacity: 0.9;">
                    Risk Score: ${result.risk_score}/100
                </div>
            </div>
            
            ${emailData.subject ? `
            <div style="
                background: rgba(255,255,255,0.1);
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 12px;
                font-size: 13px;
                border-left: 3px solid ${color.border};
            ">
                <strong>Subject:</strong> ${emailData.subject}<br>
                <strong>From:</strong> ${emailData.from || 'Unknown'}
            </div>
            ` : ''}
            
            <div style="
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 10px;
                margin-bottom: 12px;
            ">
                <div style="
                    background: rgba(255,255,255,0.08);
                    padding: 10px;
                    border-radius: 6px;
                    text-align: center;
                ">
                    <div style="font-size: 11px; color: #aaa; margin-bottom: 4px;">Risk Level</div>
                    <div style="font-weight: bold; color: ${color.border}; font-size: 14px;">${riskLevel}</div>
                </div>
                <div style="
                    background: rgba(255,255,255,0.08);
                    padding: 10px;
                    border-radius: 6px;
                    text-align: center;
                ">
                    <div style="font-size: 11px; color: #aaa; margin-bottom: 4px;">Confidence</div>
                    <div style="font-weight: bold; color: #fff; font-size: 14px;">${confidence}%</div>
                </div>
            </div>
            
            ${result.findings && result.findings.urls_found > 0 ? `
            <div style="
                background: rgba(255,255,255,0.05);
                padding: 10px;
                border-radius: 6px;
                font-size: 12px;
                margin-bottom: 12px;
            ">
                <div style="margin-bottom: 5px;"><strong>URLs Found:</strong> ${result.findings.urls_found}</div>
                ${result.findings.phishing_urls > 0 ? `
                <div style="color: #e74c3c; font-weight: bold;">
                    ⚠️ Phishing URLs: ${result.findings.phishing_urls}
                </div>
                ` : '<div style="color: #27ae60;">✓ No phishing URLs detected</div>'}
            </div>
            ` : ''}
            
            <div style="
                background: ${isPhishing ? 'rgba(231, 76, 60, 0.15)' : 'rgba(39, 174, 96, 0.15)'};
                border: 2px solid ${isPhishing ? '#e74c3c' : '#27ae60'};
                padding: 12px;
                border-radius: 8px;
                text-align: center;
                font-weight: 600;
                color: ${isPhishing ? '#e74c3c' : '#27ae60'};
                font-size: 13px;
            ">
                ${isPhishing 
                    ? '⚠️ WARNING: This email shows phishing characteristics!<br><span style="font-size: 11px; font-weight: normal;">Do not click links or download attachments</span>' 
                    : '✓ This email appears to be legitimate'}
            </div>
        `;
        
        statusDiv.style.display = 'block';
        statusDiv.style.borderLeft = `4px solid ${color.border}`;
    }
    
    // Show URL analysis result
    function showUrlResult(result) {
        const riskLevel = result.risk_level || 'UNKNOWN';
        const isPhishing = result.classification === 'PHISHING' || result.risk_score > 60;
        
        const colors = {
            'LOW': { bg: '#27ae60', text: 'SAFE ✅', border: '#27ae60' },
            'MEDIUM': { bg: '#f39c12', text: 'CAUTION ⚠️', border: '#f39c12' },
            'HIGH': { bg: '#e74c3c', text: 'DANGER 🚨', border: '#e74c3c' },
            'CRITICAL': { bg: '#8b0000', text: 'PHISHING! 🚨', border: '#8b0000' },
            'UNKNOWN': { bg: '#7f8c8d', text: 'UNKNOWN ❓', border: '#7f8c8d' }
        };
        
        const color = colors[riskLevel] || colors['UNKNOWN'];
        const confidence = result.confidence ? (result.confidence * 100).toFixed(1) : 'N/A';
        
        statusContent.innerHTML = `
            <div style="
                background: ${color.bg};
                color: white;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 15px;
                text-align: center;
                font-weight: bold;
            ">
                <div style="font-size: 28px; margin-bottom: 8px;">${isPhishing ? '🚨' : '✅'}</div>
                <div style="font-size: 16px;">${color.text}</div>
                <div style="font-size: 13px; margin-top: 5px; opacity: 0.9;">
                    Risk Score: ${result.risk_score}/100
                </div>
            </div>
            
            <div style="
                background: rgba(255,255,255,0.08);
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 12px;
                font-size: 12px;
                word-break: break-all;
                border-left: 3px solid ${color.border};
            ">
                <strong>URL:</strong><br>
                ${result.url}
            </div>
            
            <div style="
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 10px;
                margin-bottom: 12px;
            ">
                <div style="
                    background: rgba(255,255,255,0.08);
                    padding: 10px;
                    border-radius: 6px;
                    text-align: center;
                ">
                    <div style="font-size: 11px; color: #aaa; margin-bottom: 4px;">Classification</div>
                    <div style="font-weight: bold; color: ${isPhishing ? '#e74c3c' : '#27ae60'}; font-size: 14px;">
                        ${result.classification}
                    </div>
                </div>
                <div style="
                    background: rgba(255,255,255,0.08);
                    padding: 10px;
                    border-radius: 6px;
                    text-align: center;
                ">
                    <div style="font-size: 11px; color: #aaa; margin-bottom: 4px;">Confidence</div>
                    <div style="font-weight: bold; color: #fff; font-size: 14px;">${confidence}%</div>
                </div>
            </div>
            
            <div style="
                background: ${isPhishing ? 'rgba(231, 76, 60, 0.15)' : 'rgba(39, 174, 96, 0.15)'};
                border: 2px solid ${isPhishing ? '#e74c3c' : '#27ae60'};
                padding: 12px;
                border-radius: 8px;
                text-align: center;
                font-weight: 600;
                color: ${isPhishing ? '#e74c3c' : '#27ae60'};
                font-size: 13px;
            ">
                ${isPhishing 
                    ? '⚠️ WARNING: This URL is potentially dangerous!' 
                    : '✓ This URL appears to be safe'}
            </div>
        `;
        
        statusDiv.style.display = 'block';
        statusDiv.style.borderLeft = `4px solid ${color.border}`;
    }
    
    // Show loading state
    function showLoading() {
        loadingDiv.style.display = 'block';
        statusDiv.style.display = 'none';
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = '⏳ Analyzing...';
    }
    
    // Hide loading state
    function hideLoading() {
        loadingDiv.style.display = 'none';
        statusDiv.style.display = 'block';
        analyzeBtn.disabled = false;
        
        // Reset button text
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (tabs.length > 0) {
                const url = tabs[0].url || '';
                const isGmail = url.includes('mail.google.com') || url.includes('gmail.com');
                analyzeBtn.textContent = isGmail ? '🔍 Analyze Current Email' : '🌐 Analyze This Page';
            }
        });
    }
    
    // Show error message
    function showError(message) {
        statusContent.innerHTML = `
            <div style="
                background: #e74c3c;
                color: white;
                padding: 15px;
                border-radius: 8px;
                text-align: center;
                font-weight: bold;
            ">
                <div style="font-size: 24px; margin-bottom: 8px;">❌</div>
                <div>Error</div>
                <div style="font-size: 12px; margin-top: 8px; font-weight: normal;">
                    ${message}
                </div>
            </div>
        `;
        statusDiv.style.display = 'block';
        statusDiv.style.borderLeft = '4px solid #e74c3c';
    }
    
    // Show warning message
    function showWarning(message) {
        statusContent.innerHTML = `
            <div style="
                background: #f39c12;
                color: white;
                padding: 12px;
                border-radius: 6px;
                text-align: center;
                font-size: 12px;
                margin-bottom: 10px;
            ">
                ${message}
            </div>
        `;
        statusDiv.style.display = 'block';
        statusDiv.style.borderLeft = '4px solid #f39c12';
    }
});

console.log('PhishingAnalyzer popup script loaded');
