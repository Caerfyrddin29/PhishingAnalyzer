// Background Script - Service Worker
class PhishAnalyzerBackground {
  constructor() {
    this.apiBaseUrl = 'http://localhost:8000';
    this.cache = new Map();
    this.setupContextMenu();
    this.setupMessageHandlers();
  }

  setupContextMenu() {
    chrome.contextMenus.create({
      id: 'analyze-url',
      title: 'Analyze with PhishAnalyzer',
      contexts: ['link', 'page']
    });
  }

  setupMessageHandlers() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'analyze-url') {
        this.analyzeUrl(request.url)
          .then(result => sendResponse({ success: true, result }))
          .catch(error => sendResponse({ success: false, error }));
        return true; // Keep message channel open
      }
    });

    chrome.contextMenus.onClicked.addListener((info, tab) => {
      if (info.menuItemId === 'analyze-url') {
        const url = info.linkUrl || info.pageUrl;
        this.analyzeUrl(url).then(result => {
          chrome.tabs.sendMessage(tab.id, {
            action: 'show-result',
            result: result
          });
        });
      }
    });
  }

  async analyzeUrl(url) {
    // Check cache first
    if (this.cache.has(url)) {
      const cached = this.cache.get(url);
      if (Date.now() - cached.timestamp < 300000) { // 5 minutes cache
        return cached.result;
      }
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

      const response = await fetch(`${this.apiBaseUrl}/analyze/url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: url }),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      
      // Cache the result
      this.cache.set(url, {
        result: result,
        timestamp: Date.now()
      });

      return result;
    } catch (error) {
      console.error('PhishAnalyzer API error:', error);
      return {
        classification: 'ERROR',
        risk_score: 0,
        confidence: 0,
        error: error.name === 'AbortError' ? 'Request timeout' : error.message
      };
    }
  }

  async checkCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      const result = await this.analyzeUrl(tab.url);
      
      // Send result to content script
      chrome.tabs.sendMessage(tab.id, {
        action: 'url-analysis',
        result: result
      });

      // Update badge
      this.updateBadge(tab.id, result);
    }
  }

  updateBadge(tabId, result) {
    let color, text;
    
    if (result.classification === 'PHISHING') {
      color = '#ff4444';
      text = '⚠️';
    } else if (result.classification === 'SUSPICIOUS') {
      color = '#ff8800';
      text = '!';
    } else if (result.classification === 'LEGITIMATE') {
      color = '#44ff44';
      text = '✓';
    } else {
      color = '#888888';
      text = '?';
    }

    chrome.action.setBadgeBackgroundColor({ color, tabId });
    chrome.action.setBadgeText({ text, tabId });
  }
}

// Initialize background service
const phishAnalyzer = new PhishAnalyzerBackground();

// Check current tab when it's updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    phishAnalyzer.checkCurrentTab();
  }
});

// Check when tab is activated
chrome.tabs.onActivated.addListener((activeInfo) => {
  phishAnalyzer.checkCurrentTab();
});
