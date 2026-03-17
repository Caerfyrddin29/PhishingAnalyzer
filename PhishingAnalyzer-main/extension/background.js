
// PhishingAnalyzer Pro - Background Service Worker
const API_BASE = 'http://localhost:8000';

// Cache for analysis results
const analysisCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

// Context menu for email analysis
chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: 'analyzeEmail',
        title: 'Analyze Email for Phishing',
        contexts: ['page', 'selection']
    });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === 'analyzeEmail') {
        analyzeCurrentTab(tab);
    }
});

// Analyze current tab
async function analyzeCurrentTab(tab) {
    try {
        const url = tab.url;
        const result = await analyzeUrl(url);
        
        chrome.action.setBadgeText({
            text: result.risk_score.toString(),
            tabId: tab.id
        });
        
        chrome.action.setBadgeBackgroundColor({
            color: getRiskColor(result.risk_score),
            tabId: tab.id
        });
        
        // Show notification for high risk
        if (result.risk_score > 60) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: 'Phishing Threat Detected',
                message: `Risk Score: ${result.risk_score}/100 - ${result.risk_level}`
            });
        }
        
    } catch (error) {
        console.error('Analysis failed:', error);
    }
}

// Analyze URL with caching
async function analyzeUrl(url) {
    const cacheKey = url;
    const cached = analysisCache.get(cacheKey);
    
    if (cached && (Date.now() - cached.timestamp < CACHE_DURATION)) {
        return cached.result;
    }
    
    try {
        const response = await fetch(`${API_BASE}/analyze/url`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        });
        
        const result = await response.json();
        
        // Cache the result
        analysisCache.set(cacheKey, {
            result: result,
            timestamp: Date.now()
        });
        
        return result;
        
    } catch (error) {
        console.error('API call failed:', error);
        return {
            risk_score: 50,
            risk_level: 'ERROR',
            classification: 'ERROR',
            confidence: 0.0
        };
    }
}

// Get color based on risk score
function getRiskColor(score) {
    if (score >= 80) return '#9b0000';      // Critical - Dark Red
    if (score >= 60) return '#e74c3c';      // High - Red
    if (score >= 30) return '#f39c12';      // Medium - Orange
    return '#27ae60';                      // Low - Green
}

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'analyzeEmail') {
        // Analyze email content from content script
        analyzeEmailContent(request.emailData, sender.tab).then(result => {
            sendResponse({ success: true, result: result });
        }).catch(error => {
            console.error('Email analysis failed:', error);
            sendResponse({ success: false, error: error.message });
        });
        return true; // Keep channel open for async response
    } else if (request.action === 'getEmailContent') {
        // Just return success, content script will provide the data
        sendResponse({ success: true });
    } else if (request.action === 'downloadEmail') {
        downloadEmailContent(request.emailContent, request.subject);
        sendResponse({ success: true });
    }
});

// Analyze email content via API
async function analyzeEmailContent(emailData, tab) {
    try {
        // Create a blob from the email content
        const blob = new Blob([emailData.content], { type: 'text/plain' });
        const formData = new FormData();
        formData.append('file', blob, 'email.eml');
        
        const response = await fetch(`${API_BASE}/analyze/email`, {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const result = await response.json();
        
        // Add email metadata to result
        result.subject = emailData.subject;
        result.from = emailData.from;
        
        // Update badge
        chrome.action.setBadgeText({
            text: result.risk_score.toString(),
            tabId: tab.id
        });
        
        chrome.action.setBadgeBackgroundColor({
            color: getRiskColor(result.risk_score),
            tabId: tab.id
        });
        
        // Show notification for high risk
        if (result.risk_score > 60) {
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon48.png',
                title: '🚨 Phishing Threat Detected!',
                message: `Risk Score: ${result.risk_score}/100 - ${result.risk_level}`
            });
        }
        
        return result;
        
    } catch (error) {
        console.error('Email analysis API call failed:', error);
        // Return a default error result
        return {
            risk_score: 50,
            risk_level: 'ERROR',
            classification: 'ERROR',
            confidence: 0.0,
            is_phishing: false,
            subject: emailData.subject,
            from: emailData.from,
            findings: {}
        };
    }
}

// Download email content
function downloadEmailContent(content, subject) {
    const filename = `email_${Date.now()}.eml`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    
    chrome.downloads.download({
        url: url,
        filename: filename,
        saveAs: false
    });
}

console.log('PhishingAnalyzer Pro background script loaded');
