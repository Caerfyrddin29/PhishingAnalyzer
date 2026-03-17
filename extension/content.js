// PhishingAnalyzer Pro - Content Script for Gmail Integration
// This script adds buttons to Gmail interface and handles email analysis

console.log('PhishingAnalyzer content script loaded');

// Global variables
let isAnalyzing = false;
let analysisPanel = null;

// Wait for Gmail to load
function waitForGmail() {
    return new Promise((resolve) => {
        const checkGmail = () => {
            const emailContainer = document.querySelector('div[role="main"]');
            if (emailContainer) {
                console.log('Gmail detected, initializing...');
                resolve();
            } else {
                setTimeout(checkGmail, 1000);
            }
        };
        checkGmail();
    });
}

// Initialize when Gmail loads
waitForGmail().then(() => {
    console.log('Initializing PhishingAnalyzer in Gmail...');
    addPhishingButton();
    
    // Monitor for navigation changes
    const observer = new MutationObserver(() => {
        setTimeout(() => {
            if (!document.getElementById('phishing-analyzer-btn')) {
                addPhishingButton();
            }
        }, 1000);
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});

// Add phishing analysis button to Gmail interface
function addPhishingButton() {
    // Check if button already exists
    if (document.getElementById('phishing-analyzer-btn')) {
        return;
    }
    
    // Check if we're in an email view
    const emailContainer = document.querySelector('div[role="main"]');
    if (!emailContainer) {
        return;
    }
    
    console.log('Adding PhishingAnalyzer buttons to Gmail...');
    
    // Create button container
    const buttonContainer = document.createElement('div');
    buttonContainer.id = 'phishing-analyzer-btn';
    buttonContainer.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 8px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;
    
    // Create analyze button
    const analyzeButton = document.createElement('button');
    analyzeButton.id = 'phishing-analyze-btn';
    analyzeButton.innerHTML = '🛡️ Analyze Email';
    analyzeButton.style.cssText = `
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 12px 20px;
        border-radius: 8px;
        cursor: pointer;
        font-size: 14px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        transition: all 0.3s ease;
        display: flex;
        align-items: center;
        gap: 8px;
    `;
    
    // Add hover effects
    analyzeButton.onmouseenter = () => {
        analyzeButton.style.transform = 'translateY(-2px)';
        analyzeButton.style.boxShadow = '0 6px 20px rgba(102, 126, 234, 0.5)';
    };
    analyzeButton.onmouseleave = () => {
        analyzeButton.style.transform = 'translateY(0)';
        analyzeButton.style.boxShadow = '0 4px 15px rgba(102, 126, 234, 0.4)';
    };
    
    // Add click handler
    analyzeButton.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        console.log('Analyze button clicked');
        analyzeCurrentEmail();
    };
    
    // Create download button
    const downloadButton = document.createElement('button');
    downloadButton.id = 'phishing-download-btn';
    downloadButton.innerHTML = '📥 Download .eml';
    downloadButton.style.cssText = `
        background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
        color: white;
        border: none;
        padding: 10px 16px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 13px;
        font-weight: 500;
        box-shadow: 0 3px 10px rgba(39, 174, 96, 0.3);
        transition: all 0.3s ease;
        display: flex;
        align-items: center;
        gap: 6px;
    `;
    
    downloadButton.onmouseenter = () => {
        downloadButton.style.transform = 'translateY(-2px)';
        downloadButton.style.boxShadow = '0 5px 15px rgba(39, 174, 96, 0.4)';
    };
    downloadButton.onmouseleave = () => {
        downloadButton.style.transform = 'translateY(0)';
        downloadButton.style.boxShadow = '0 3px 10px rgba(39, 174, 96, 0.3)';
    };
    
    downloadButton.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        console.log('Download button clicked');
        downloadCurrentEmail();
    };
    
    // Add buttons to container
    buttonContainer.appendChild(analyzeButton);
    buttonContainer.appendChild(downloadButton);
    
    // Add to page
    document.body.appendChild(buttonContainer);
    console.log('PhishingAnalyzer buttons added successfully');
}

// Get email content from Gmail
function getEmailContent() {
    // Try multiple selectors for Gmail content
    const selectors = [
        'div[role="main"] .a3s',  // Email body
        '.ii.gt',  // Email content
        'div[data-message-id] .a3s',
        '.h7 .a3s'  // Another email body selector
    ];
    
    for (const selector of selectors) {
        const element = document.querySelector(selector);
        if (element && element.textContent.trim()) {
            console.log('Found email content with selector:', selector);
            return element.innerText.trim();
        }
    }
    
    console.warn('Could not find email content with standard selectors');
    return null;
}

// Get email subject
function getEmailSubject() {
    const subjectSelectors = [
        'h2[data-thread-perm-id]',
        '.hP',
        'h1.hP',
        '[data-legacy-thread-id] .hP'
    ];
    
    for (const selector of subjectSelectors) {
        const element = document.querySelector(selector);
        if (element && element.textContent.trim()) {
            return element.textContent.trim();
        }
    }
    
    return 'No Subject';
}

// Get email sender
function getEmailFrom() {
    const fromSelectors = [
        '.gD',  // Sender email
        '.g2',  // Another sender selector
        '[email]'
    ];
    
    for (const selector of fromSelectors) {
        const element = document.querySelector(selector);
        if (element && element.textContent.trim()) {
            return element.textContent.trim();
        }
    }
    
    return 'Unknown Sender';
}

// Analyze current email
async function analyzeCurrentEmail() {
    if (isAnalyzing) {
        console.log('Analysis already in progress');
        return;
    }
    
    console.log('Starting email analysis...');
    isAnalyzing = true;
    
    // Show loading indicator
    showLoadingIndicator();
    
    const emailData = {
        content: getEmailContent(),
        subject: getEmailSubject(),
        from: getEmailFrom()
    };
    
    if (!emailData.content) {
        hideLoadingIndicator();
        showNotification('❌ Could not extract email content', 'error');
        isAnalyzing = false;
        return;
    }
    
    console.log('Email data extracted:', {
        subject: emailData.subject,
        from: emailData.from,
        contentLength: emailData.content.length
    });
    
    try {
        // Send to background script for analysis
        chrome.runtime.sendMessage({
            action: 'analyzeEmail',
            emailData: emailData
        }, function(response) {
            hideLoadingIndicator();
            isAnalyzing = false;
            
            if (chrome.runtime.lastError) {
                console.error('Runtime error:', chrome.runtime.lastError);
                showNotification('❌ Analysis failed: ' + chrome.runtime.lastError.message, 'error');
                return;
            }
            
            if (response && response.success) {
                console.log('Analysis successful:', response.result);
                showAnalysisResult(response.result);
            } else {
                console.error('Analysis failed:', response);
                showNotification('❌ ' + (response?.error || 'Analysis failed'), 'error');
            }
        });
    } catch (error) {
        hideLoadingIndicator();
        isAnalyzing = false;
        console.error('Error sending message:', error);
        showNotification('❌ Error: ' + error.message, 'error');
    }
}

// Download current email
function downloadCurrentEmail() {
    console.log('Starting email download...');
    
    const emailData = {
        content: getEmailContent(),
        subject: getEmailSubject(),
        from: getEmailFrom()
    };
    
    if (!emailData.content) {
        showNotification('❌ Could not extract email content', 'error');
        return;
    }
    
    // Create .eml format
    const date = new Date().toISOString();
    const emlContent = `From: ${emailData.from}
To: recipient@email.com
Subject: ${emailData.subject}
Date: ${date}
Content-Type: text/plain; charset=utf-8

${emailData.content}`;
    
    // Create download
    const blob = new Blob([emlContent], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    
    // Create temporary link
    const link = document.createElement('a');
    link.href = url;
    link.download = `email_${Date.now()}.eml`;
    document.body.appendChild(link);
    
    // Trigger download
    link.click();
    
    // Cleanup
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showNotification('✅ Email downloaded successfully', 'success');
    console.log('Email download completed');
}

// Show loading indicator
function showLoadingIndicator() {
    // Remove existing indicator if any
    hideLoadingIndicator();
    
    const indicator = document.createElement('div');
    indicator.id = 'phishing-loading';
    indicator.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: rgba(0, 0, 0, 0.85);
        color: white;
        padding: 30px 40px;
        border-radius: 12px;
        z-index: 10001;
        text-align: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
    `;
    
    indicator.innerHTML = `
        <div style="width: 50px; height: 50px; border: 4px solid rgba(255,255,255,0.3); border-top: 4px solid #667eea; border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 15px;"></div>
        <div style="font-size: 18px; font-weight: 600; margin-bottom: 8px;">🔍 Analyzing Email...</div>
        <div style="font-size: 14px; opacity: 0.8;">Please wait</div>
    `;
    
    // Add spin animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(indicator);
    console.log('Loading indicator shown');
}

// Hide loading indicator
function hideLoadingIndicator() {
    const indicator = document.getElementById('phishing-loading');
    if (indicator) {
        indicator.remove();
        console.log('Loading indicator hidden');
    }
}

// Show analysis result panel
function showAnalysisResult(result) {
    // Remove existing panel if any
    removeAnalysisPanel();
    
    const riskLevel = (result.risk_level || 'UNKNOWN').toUpperCase();
    const isPhishing = result.is_phishing || result.risk_score > 60;
    const riskScore = result.risk_score || 0;
    
    console.log('Showing analysis result:', { riskLevel, isPhishing, riskScore });
    
    // Color scheme
    const colors = {
        'LOW': { bg: '#27ae60', text: 'SAFE ✅', border: '#27ae60', gradient: 'linear-gradient(135deg, #27ae60 0%, #229954 100%)' },
        'MEDIUM': { bg: '#f39c12', text: 'CAUTION ⚠️', border: '#f39c12', gradient: 'linear-gradient(135deg, #f39c12 0%, #e67e22 100%)' },
        'HIGH': { bg: '#e74c3c', text: 'DANGER 🚨', border: '#e74c3c', gradient: 'linear-gradient(135deg, #e74c3c 0%, #c0392b 100%)' },
        'CRITICAL': { bg: '#8b0000', text: 'PHISHING! 🚨', border: '#8b0000', gradient: 'linear-gradient(135deg, #8b0000 0%, #660000 100%)' },
        'ERROR': { bg: '#7f8c8d', text: 'ERROR ⚠️', border: '#7f8c8d', gradient: 'linear-gradient(135deg, #7f8c8d 0%, #636e72 100%)' },
        'UNKNOWN': { bg: '#7f8c8d', text: 'UNKNOWN ❓', border: '#7f8c8d', gradient: 'linear-gradient(135deg, #7f8c8d 0%, #636e72 100%)' }
    };
    
    const color = colors[riskLevel] || colors['UNKNOWN'];
    const confidence = result.confidence ? (result.confidence * 100).toFixed(1) : 'N/A';
    const urlsFound = result.findings?.urls_found || 0;
    const phishingUrls = result.findings?.phishing_urls || 0;
    
    // Create panel
    const panel = document.createElement('div');
    panel.id = 'phishing-result-panel';
    analysisPanel = panel;
    
    panel.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        width: 380px;
        max-height: 80vh;
        overflow-y: auto;
        background: white;
        border-radius: 16px;
        box-shadow: 0 10px 40px rgba(0,0,0,0.25);
        z-index: 10000;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        animation: slideIn 0.3s ease;
        border: 2px solid ${color.border};
    `;
    
    panel.innerHTML = `
        <!-- Header -->
        <div style="
            background: ${color.gradient};
            color: white;
            padding: 25px 20px;
            text-align: center;
            position: relative;
            border-radius: 14px 14px 0 0;
        ">
            <!-- Close Button X -->
            <button id="phishing-close-btn" style="
                position: absolute;
                top: 10px;
                right: 10px;
                background: rgba(255,255,255,0.2);
                border: 2px solid rgba(255,255,255,0.4);
                color: white;
                width: 32px;
                height: 32px;
                border-radius: 50%;
                cursor: pointer;
                font-size: 20px;
                font-weight: bold;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 0;
                line-height: 1;
                transition: all 0.2s ease;
                z-index: 10;
            " title="Close">×</button>
            
            <div style="font-size: 36px; margin-bottom: 10px;">${isPhishing ? '🚨' : '✅'}</div>
            <div style="font-size: 22px; font-weight: bold; margin-bottom: 5px;">${color.text}</div>
            <div style="font-size: 15px; opacity: 0.95;">
                Risk Score: <strong>${riskScore}/100</strong>
            </div>
        </div>
        
        <!-- Content -->
        <div style="padding: 20px;">
            ${result.subject ? `
            <div style="
                background: #f8f9fa;
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 15px;
                border-left: 4px solid ${color.border};
            ">
                <div style="font-size: 13px; color: #666; margin-bottom: 4px;">Subject:</div>
                <div style="font-weight: 600; color: #333; font-size: 14px;">${result.subject}</div>
                ${result.from ? `<div style="font-size: 12px; color: #888; margin-top: 4px;">From: ${result.from}</div>` : ''}
            </div>
            ` : ''}
            
            <!-- Stats Grid -->
            <div style="
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-bottom: 15px;
            ">
                <div style="
                    background: #f8f9fa;
                    padding: 14px;
                    border-radius: 10px;
                    text-align: center;
                    border: 2px solid ${color.border};
                ">
                    <div style="font-size: 11px; color: #666; margin-bottom: 6px; text-transform: uppercase; font-weight: 600;">Risk Level</div>
                    <div style="font-weight: bold; color: ${color.border}; font-size: 18px;">${riskLevel}</div>
                </div>
                <div style="
                    background: #f8f9fa;
                    padding: 14px;
                    border-radius: 10px;
                    text-align: center;
                    border: 2px solid #e0e0e0;
                ">
                    <div style="font-size: 11px; color: #666; margin-bottom: 6px; text-transform: uppercase; font-weight: 600;">Confidence</div>
                    <div style="font-weight: bold; color: #333; font-size: 18px;">${confidence}%</div>
                </div>
            </div>
            
            <!-- URL Analysis -->
            <div style="
                background: #f8f9fa;
                padding: 14px;
                border-radius: 10px;
                margin-bottom: 15px;
            ">
                <div style="font-size: 13px; color: #666; margin-bottom: 10px; font-weight: 600;">🔗 URL Analysis</div>
                <div style="font-size: 14px; color: #333; margin-bottom: 6px;">
                    <strong>URLs Found:</strong> ${urlsFound}
                </div>
                <div style="font-size: 14px; color: ${phishingUrls > 0 ? '#e74c3c' : '#27ae60'}; font-weight: 600;">
                    ${phishingUrls > 0 
                        ? `⚠️ Phishing URLs: ${phishingUrls}` 
                        : '✓ No phishing URLs detected'}
                </div>
            </div>
            
            <!-- Final Warning/Safe Message -->
            <div style="
                background: ${isPhishing ? '#fee2e2' : '#d1fae5'};
                border: 3px solid ${isPhishing ? '#ef4444' : '#10b981'};
                padding: 18px;
                border-radius: 12px;
                text-align: center;
            ">
                <div style="font-size: 20px; margin-bottom: 8px;">${isPhishing ? '⚠️' : '✓'}</div>
                <div style="font-weight: bold; color: ${isPhishing ? '#dc2626' : '#059669'}; font-size: 15px; margin-bottom: 6px;">
                    ${isPhishing ? 'PHISHING DETECTED!' : 'EMAIL IS SAFE'}
                </div>
                <div style="color: ${isPhishing ? '#dc2626' : '#059669'}; font-size: 13px; line-height: 1.5;">
                    ${isPhishing 
                        ? 'This email shows phishing characteristics.<br>Do NOT click any links or download attachments!' 
                        : 'No phishing indicators detected.<br>This email appears to be legitimate.'}
                </div>
            </div>
        </div>
    `;
    
    // Add close button event listener
    const closeBtn = panel.querySelector('#phishing-close-btn');
    if (closeBtn) {
        closeBtn.onclick = (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('Close button clicked');
            removeAnalysisPanel();
        };
    }
    
    // Add animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(50px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
    `;
    document.head.appendChild(style);
    
    // Add to page
    document.body.appendChild(panel);
    console.log('Analysis result panel shown');
    
    // Auto-remove after 60 seconds
    setTimeout(() => {
        removeAnalysisPanel();
    }, 60000);
}

// Remove analysis panel
function removeAnalysisPanel() {
    const panel = document.getElementById('phishing-result-panel');
    if (panel) {
        panel.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            panel.remove();
            console.log('Analysis panel removed');
        }, 300);
    }
    analysisPanel = null;
    
    // Add slideOut animation if not exists
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideOut {
            from {
                opacity: 1;
                transform: translateX(0);
            }
            to {
                opacity: 0;
                transform: translateX(50px);
            }
        }
    `;
    document.head.appendChild(style);
}

// Show notification
function showNotification(message, type = 'info') {
    const colors = {
        success: '#27ae60',
        error: '#e74c3c',
        warning: '#f39c12',
        info: '#3498db'
    };
    
    const bgColor = colors[type] || colors.info;
    
    // Remove existing notifications
    const existing = document.querySelectorAll('.phishing-notification');
    existing.forEach(n => n.remove());
    
    const notification = document.createElement('div');
    notification.className = 'phishing-notification';
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: ${bgColor};
        color: white;
        padding: 14px 24px;
        border-radius: 8px;
        z-index: 10002;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        font-weight: 500;
        box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        animation: slideDown 0.3s ease;
    `;
    
    notification.textContent = message;
    
    // Add animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateX(-50%) translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(-50%) translateY(0);
            }
        }
    `;
    document.head.appendChild(style);
    
    document.body.appendChild(notification);
    
    // Auto-remove after 4 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideUp 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 4000);
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('Message received in content script:', request);
    
    if (request.action === 'getEmailContent') {
        const emailData = {
            content: getEmailContent(),
            subject: getEmailSubject(),
            from: getEmailFrom()
        };
        
        if (emailData.content) {
            sendResponse({
                success: true,
                emailData: emailData
            });
        } else {
            sendResponse({
                success: false,
                error: 'Could not extract email content'
            });
        }
        return true;
    }
});

console.log('PhishingAnalyzer content script fully loaded and initialized');
