// PhishingAnalyzer Pro - Gmail Content Script
console.log('Gmail content script loaded');

// Gmail-specific email extraction
function extractGmailEmail() {
    const emailData = {
        subject: '',
        from: '',
        to: '',
        date: '',
        content: '',
        urls: []
    };
    
    // Extract subject
    const subjectEl = document.querySelector('h2[data-thread-perm-id]') || 
                     document.querySelector('.hP') || 
                     document.querySelector('h1');
    if (subjectEl) {
        emailData.subject = subjectEl.textContent.trim();
    }
    
    // Extract sender
    const senderEl = document.querySelector('.gD') || 
                     document.querySelector('.g2');
    if (senderEl) {
        emailData.from = senderEl.textContent.trim();
    }
    
    // Extract recipients
    const recipientsEl = document.querySelector('.g2') || 
                        document.querySelector('.g3');
    if (recipientsEl) {
        emailData.to = recipientsEl.textContent.trim();
    }
    
    // Extract date
    const dateEl = document.querySelector('.g3 span') || 
                   document.querySelector('span[title][data-tooltip]');
    if (dateEl) {
        emailData.date = dateEl.getAttribute('title') || dateEl.textContent;
    }
    
    // Extract content
    const contentEl = document.querySelector('.a3s') || 
                      document.querySelector('.ii.gt') ||
                      document.querySelector('div[aria-label*="Message"]');
    if (contentEl) {
        emailData.content = contentEl.textContent.trim();
        
        // Extract URLs from content
        const urlRegex = /https?:\\/\\/[^\\s<>"']+/gi;
        const matches = emailData.content.match(urlRegex);
        if (matches) {
            emailData.urls = [...new Set(matches)]; // Remove duplicates
        }
    }
    
    return emailData;
}

// Add phishing warning overlay
function showPhishingWarning(riskScore, riskLevel) {
    const warning = document.createElement('div');
    warning.id = 'phishing-warning';
    warning.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; background: ' + 
        (riskScore >= 80 ? '#8b0000' : '#e74c3c') + '; color: white; padding: 15px; text-align: center; z-index: 10002; font-family: Arial, sans-serif; font-size: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); border-bottom: 4px solid rgba(255,255,255,0.3);';
    
    warning.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; gap: 15px;"><span style="font-size: 24px;">🚨</span><div><div style="font-weight: bold; font-size: 18px;">PHISHING THREAT DETECTED</div><div style="margin-top: 5px;">Risk Score: ' + riskScore + '/100 - ' + riskLevel + '</div></div><button onclick="this.parentElement.parentElement.remove()" style="background: rgba(255,255,255,0.2); border: 1px solid white; color: white; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-size: 14px;">Dismiss</button></div>';
    
    document.body.appendChild(warning);
    
    // Auto-dismiss after 10 seconds
    setTimeout(() => {
        if (document.getElementById('phishing-warning')) {
            warning.remove();
        }
    }, 10000);
}

// Add URL analysis tooltips
function addURLAnalysis() {
    const links = document.querySelectorAll('a[href^="http"]');
    
    links.forEach(link => {
        const url = link.href;
        
        // Add hover effect for suspicious URLs
        link.addEventListener('mouseenter', async (e) => {
            const isSuspicious = isSuspiciousURL(url);
            
            if (isSuspicious) {
                link.style.backgroundColor = '#fff3cd';
                link.style.border = '1px solid #ffeaa7';
                link.style.borderRadius = '3px';
            }
        });
        
        link.addEventListener('mouseleave', () => {
            link.style.backgroundColor = '';
            link.style.border = '';
        });
    });
}

// Check if URL is suspicious
function isSuspiciousURL(url) {
    const suspiciousPatterns = [
        /192\\.168\\./,
        /10\\./,
        /127\\.0\\.0\\.1/,
        /bit\\.ly/,
        /tinyurl\\.com/,
        /t\\.co/,
        /paypal.*security/i,
        /.*/verify.*account/i,
        /.*/login.*urgent/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(url));
}

// Initialize Gmail-specific features
function initGmailFeatures() {
    // Monitor for new emails
    const observer = new MutationObserver(() => {
        setTimeout(() => {
            addURLAnalysis();
        }, 1000);
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
    
    // Initial URL analysis
    setTimeout(() => {
        addURLAnalysis();
    }, 2000);
}

// Initialize when ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initGmailFeatures);
} else {
    initGmailFeatures();
}

// Export functions for use by other scripts
window.PhishingAnalyzerGmail = {
    extractGmailEmail: extractGmailEmail,
    showPhishingWarning: showPhishingWarning,
    addURLAnalysis: addURLAnalysis
};
