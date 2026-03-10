// Popup script for PhishAnalyzer extension

class PhishAnalyzerPopup {
  constructor() {
    this.init();
  }

  async init() {
    this.setupEventListeners();
    await this.checkApiStatus();
    await this.loadRecentAnalyses();
  }

  setupEventListeners() {
    document.getElementById('analyzeCurrentBtn').addEventListener('click', () => {
      this.analyzeCurrentEmail();
    });

    document.getElementById('clearResultsBtn').addEventListener('click', () => {
      this.clearResults();
    });

    document.getElementById('settingsBtn').addEventListener('click', () => {
      this.openSettings();
    });
  }

  async checkApiStatus() {
    const statusIndicator = document.getElementById('apiStatus');
    const statusText = document.getElementById('apiStatusText');

    try {
      const response = await fetch('http://127.0.0.1:8000/');
      
      if (response.ok) {
        statusIndicator.className = 'status-indicator online';
        statusText.textContent = 'Online';
      } else {
        throw new Error('API not responding');
      }
    } catch (error) {
      statusIndicator.className = 'status-indicator offline';
      statusText.textContent = 'Offline';
      console.error('API Status check failed:', error);
    }
  }

  async analyzeCurrentEmail() {
    try {
      // Get current active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      // Check if we're on a supported email provider
      if (!tab.url.includes('mail.google.com') && !tab.url.includes('outlook.live.com') && !tab.url.includes('outlook.office.com')) {
        this.showNotification('Please open this extension on Gmail or Outlook', 'error');
        return;
      }

      // Send message to content script to analyze current email
      chrome.tabs.sendMessage(tab.id, {
        action: 'analyzeCurrentEmail'
      });

      // Close popup
      window.close();

    } catch (error) {
      console.error('Failed to analyze current email:', error);
      this.showNotification('Failed to analyze email', 'error');
    }
  }

  async clearResults() {
    try {
      await chrome.runtime.sendMessage({ action: 'clearResults' });
      await this.loadRecentAnalyses();
      this.showNotification('Analysis history cleared', 'success');
    } catch (error) {
      console.error('Failed to clear results:', error);
      this.showNotification('Failed to clear results', 'error');
    }
  }

  async loadRecentAnalyses() {
    const listContainer = document.getElementById('recentAnalysesList');
    
    try {
      // Get recent analyses from storage
      const result = await chrome.storage.local.get(['phishAnalyzer_recentAnalyses']);
      const analyses = result.phishAnalyzer_recentAnalyses || [];

      if (analyses.length === 0) {
        listContainer.innerHTML = '<p style="text-align: center; color: #605e5c; padding: 20px;">No recent analyses</p>';
        return;
      }

      // Sort by timestamp (most recent first)
      analyses.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      // Display last 5 analyses
      const recentAnalyses = analyses.slice(0, 5);
      
      listContainer.innerHTML = recentAnalyses.map(analysis => `
        <div class="analysis-item">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong>${this.truncateText(analysis.findings.metadata.subject, 25)}</strong>
            <span class="analysis-score score-${analysis.risk_level.toLowerCase()}">
              ${analysis.risk_score} - ${analysis.risk_level}
            </span>
          </div>
          <div style="font-size: 12px; color: #605e5c;">
            From: ${this.truncateText(analysis.findings.metadata.sender, 20)}
          </div>
          <div style="font-size: 11px; color: #a19f9d; margin-top: 4px;">
            ${new Date(analysis.timestamp).toLocaleString()}
          </div>
        </div>
      `).join('');

    } catch (error) {
      console.error('Failed to load recent analyses:', error);
      listContainer.innerHTML = '<p style="text-align: center; color: #d13438; padding: 20px;">Failed to load analyses</p>';
    }
  }

  truncateText(text, maxLength) {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  }

  showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 10px;
      right: 10px;
      left: 10px;
      padding: 12px;
      background: ${type === 'error' ? '#d13438' : type === 'success' ? '#107c10' : '#0078d4'};
      color: white;
      border-radius: 4px;
      font-size: 14px;
      z-index: 1000;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.remove();
    }, 3000);
  }

  openSettings() {
    // For now, just show a simple alert
    this.showNotification('Settings coming soon!', 'info');
  }
}

// Listen for storage updates (when new analyses are completed)
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local' && changes.phishAnalyzer_recentAnalyses) {
    // Reload recent analyses when updated
    const popup = new PhishAnalyzerPopup();
    popup.loadRecentAnalyses();
  }
});

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new PhishAnalyzerPopup();
});
