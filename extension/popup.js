// Popup Script - Extension popup interface
class PhishAnalyzerPopup {
  constructor() {
    this.apiBaseUrl = 'http://localhost:8000';
    this.recentAnalyses = [];
    this.init();
  }

  async init() {
    this.setupEventListeners();
    await this.loadCurrentTab();
    await this.loadRecentAnalyses();
  }

  setupEventListeners() {
    document.getElementById('analyze-btn').addEventListener('click', () => {
      this.analyzeManualUrl();
    });

    document.getElementById('url-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.analyzeManualUrl();
      }
    });
  }

  async loadCurrentTab() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        document.getElementById('current-url').textContent = tab.url;
        await this.analyzeUrl(tab.url, 'current');
      }
    } catch (error) {
      console.error('Error loading current tab:', error);
      this.showError('Could not load current tab');
    }
  }

  async analyzeUrl(url, type = 'manual') {
    this.showLoading(type);
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 second timeout

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
      this.displayResult(result, type);
      
      if (type === 'manual') {
        this.addToRecentAnalyses(url, result);
      }
      
    } catch (error) {
      console.error('Analysis error:', error);
      const errorMessage = error.name === 'AbortError' ? 'Request timeout' : error.message;
      this.showError('Analysis failed: ' + errorMessage, type);
    }
  }

  showLoading(type) {
    const statusElement = document.getElementById('current-status');
    if (type === 'current') {
      statusElement.className = 'status';
      statusElement.innerHTML = `
        <div class="status-icon">🔄</div>
        <div class="status-text">Analyzing...</div>
        <div class="risk-score">-</div>
      `;
    }
    
    const btn = document.getElementById('analyze-btn');
    btn.disabled = true;
    btn.textContent = 'Analyzing...';
  }

  displayResult(result, type) {
    const statusElement = document.getElementById('current-status');
    const statusClass = result.classification.toLowerCase();
    
    const statusIcons = {
      'legitimate': '✅',
      'suspicious': '⚠️',
      'phishing': '🚨',
      'error': '❌'
    };

    const statusTexts = {
      'legitimate': 'Legitimate',
      'suspicious': 'Suspicious',
      'phishing': 'PHISHING DETECTED',
      'error': 'Analysis Error'
    };

    if (type === 'current') {
      statusElement.className = `status ${statusClass}`;
      statusElement.innerHTML = `
        <div class="status-icon">${statusIcons[result.classification.toLowerCase()] || '❓'}</div>
        <div class="status-text">${statusTexts[result.classification.toLowerCase()] || 'Unknown'}</div>
        <div class="risk-score">${result.risk_score}/100</div>
      `;
    }

    const btn = document.getElementById('analyze-btn');
    btn.disabled = false;
    btn.textContent = 'Analyze URL';
  }

  showError(message, type = 'current') {
    if (type === 'current') {
      const statusElement = document.getElementById('current-status');
      statusElement.className = 'status error';
      statusElement.innerHTML = `
        <div class="status-icon">❌</div>
        <div class="status-text">${message}</div>
        <div class="risk-score">-</div>
      `;
    }

    const btn = document.getElementById('analyze-btn');
    btn.disabled = false;
    btn.textContent = 'Analyze URL';
  }

  async analyzeManualUrl() {
    const input = document.getElementById('url-input');
    const url = input.value.trim();
    
    if (!url) {
      this.showError('Please enter a URL', 'manual');
      return;
    }

    await this.analyzeUrl(url, 'manual');
    input.value = '';
  }

  addToRecentAnalyses(url, result) {
    this.recentAnalyses.unshift({
      url: url,
      result: result,
      timestamp: new Date().toISOString()
    });

    // Keep only last 10 analyses
    this.recentAnalyses = this.recentAnalyses.slice(0, 10);
    
    // Save to storage
    chrome.storage.local.set({ recentAnalyses: this.recentAnalyses });
    
    this.displayRecentAnalyses();
  }

  async loadRecentAnalyses() {
    try {
      const data = await chrome.storage.local.get(['recentAnalyses']);
      this.recentAnalyses = data.recentAnalyses || [];
      this.displayRecentAnalyses();
    } catch (error) {
      console.error('Error loading recent analyses:', error);
    }
  }

  displayRecentAnalyses() {
    const resultsContainer = document.getElementById('results');
    const resultsList = document.getElementById('results-list');

    if (this.recentAnalyses.length === 0) {
      resultsContainer.style.display = 'none';
      return;
    }

    resultsContainer.style.display = 'block';
    resultsList.innerHTML = '';

    this.recentAnalyses.forEach(analysis => {
      const resultItem = document.createElement('div');
      resultItem.className = 'result-item';
      
      const riskColor = analysis.result.risk_score > 70 ? '#ff4444' : 
                       analysis.result.risk_score > 40 ? '#ff8800' : '#44ff44';
      
      resultItem.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div style="flex: 1; margin-right: 1rem;">
            <div style="font-weight: bold; margin-bottom: 0.25rem;">
              ${analysis.result.classification}
            </div>
            <div style="font-size: 0.8rem; opacity: 0.8; word-break: break-all;">
              ${analysis.url}
            </div>
          </div>
          <div style="text-align: center;">
            <div style="font-size: 1.2rem; font-weight: bold; color: ${riskColor};">
              ${analysis.result.risk_score}/100
            </div>
            <div style="font-size: 0.7rem; opacity: 0.7;">
              ${(analysis.result.confidence * 100).toFixed(0)}%
            </div>
          </div>
        </div>
      `;
      
      resultsList.appendChild(resultItem);
    });
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PhishAnalyzerPopup();
});
