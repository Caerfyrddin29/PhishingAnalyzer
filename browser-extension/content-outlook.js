// Content script for Outlook integration

class OutlookPhishAnalyzer {
  constructor() {
    this.isAnalyzing = false;
    this.analysisOverlay = null;
    this.init();
  }

  init() {
    console.log('PhishAnalyzer loaded for Outlook');
    this.setupObserver();
    this.addAnalysisButtons();
  }

  setupObserver() {
    // Monitor for new emails
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          this.addAnalysisButtons();
        }
      });
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  addAnalysisButtons() {
    // Find email items in Outlook interface
    const emailItems = document.querySelectorAll('[role="option"][aria-label*="From"], div[role="row"]');
    
    emailItems.forEach(item => {
      // Skip if button already added
      if (item.querySelector('.phish-analyzer-btn')) return;
      
      const buttonContainer = item.querySelector('div[role="gridcell"]:last-child, .ms-Button');
      if (!buttonContainer) return;
      
      const analyzeBtn = document.createElement('button');
      analyzeBtn.className = 'phish-analyzer-btn';
      analyzeBtn.innerHTML = '🛡️ Analyze';
      analyzeBtn.style.cssText = `
        margin-left: 8px;
        padding: 4px 8px;
        background: #0078d4;
        color: white;
        border: none;
        border-radius: 4px;
        cursor: pointer;
        font-size: 12px;
        font-family: 'Segoe UI', sans-serif;
        transition: background 0.2s;
      `;
      
      analyzeBtn.addEventListener('mouseenter', () => {
        analyzeBtn.style.background = '#106ebe';
      });
      
      analyzeBtn.addEventListener('mouseleave', () => {
        analyzeBtn.style.background = '#0078d4';
      });
      
      analyzeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        this.analyzeEmailFromItem(item);
      });
      
      buttonContainer.appendChild(analyzeBtn);
    });
  }

  analyzeEmailFromItem(item) {
    // Click to open email
    item.click();
    
    setTimeout(() => {
      this.analyzeCurrentEmail();
    }, 1500);
  }

  analyzeCurrentEmail() {
    if (this.isAnalyzing) return;
    
    this.isAnalyzing = true;
    this.showAnalysisOverlay();
    
    try {
      const emailData = this.extractEmailData();
      
      if (!emailData) {
        this.hideAnalysisOverlay();
        this.showNotification('Could not extract email data', 'error');
        this.isAnalyzing = false;
        return;
      }
      
      // Send to background script for analysis
      chrome.runtime.sendMessage({
        action: 'analyzeEmail',
        data: emailData
      });
      
    } catch (error) {
      console.error('Analysis error:', error);
      this.hideAnalysisOverlay();
      this.showNotification('Analysis failed: ' + error.message, 'error');
      this.isAnalyzing = false;
    }
  }

  extractEmailData() {
    // Extract email data from Outlook interface
    const subjectElement = document.querySelector('[data-testid="subjectLine"], h2[role="heading"]');
    const senderElement = document.querySelector('[data-testid="senderName"], span[title*="@"]');
    const bodyElement = document.querySelector('[role="document"], div[contenteditable="true"]');
    
    if (!subjectElement || !senderElement || !bodyElement) {
      return null;
    }
    
    return {
      subject: subjectElement.textContent.trim(),
      sender: senderElement.textContent.trim(),
      body: bodyElement.textContent.trim(),
      headers: '', // Outlook headers are not easily accessible
      raw_content: document.documentElement.outerHTML
    };
  }

  showAnalysisOverlay() {
    if (this.analysisOverlay) return;
    
    this.analysisOverlay = document.createElement('div');
    this.analysisOverlay.id = 'phish-analyzer-overlay';
    this.analysisOverlay.innerHTML = `
      <div class="phish-analyzer-modal">
        <div class="phish-analyzer-content">
          <h3>🛡️ PhishAnalyzer</h3>
          <div class="analysis-status">
            <div class="spinner"></div>
            <p>Analyzing email for phishing indicators...</p>
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(this.analysisOverlay);
  }

  hideAnalysisOverlay() {
    if (this.analysisOverlay) {
      this.analysisOverlay.remove();
      this.analysisOverlay = null;
    }
    this.isAnalyzing = false;
  }

  showAnalysisResult(result) {
    this.hideAnalysisOverlay();
    
    const { risk_score, risk_level, findings } = result;
    
    // Create result modal
    const resultModal = document.createElement('div');
    resultModal.id = 'phish-analyzer-result';
    resultModal.innerHTML = `
      <div class="phish-analyzer-modal">
        <div class="phish-analyzer-content">
          <h3>🛡️ Analysis Complete</h3>
          <div class="risk-score ${risk_level.toLowerCase()}">
            <div class="score-circle">
              <span class="score-number">${risk_score}</span>
              <span class="risk-label">${risk_level}</span>
            </div>
          </div>
          
          <div class="findings">
            <h4>Findings:</h4>
            <ul>
              <li>Email addresses found: ${findings.email_addresses?.length || 0}</li>
              <li>Suspicious URLs: ${findings.urls?.length || 0}</li>
              <li>IP addresses: ${findings.ip_addresses?.length || 0}</li>
              <li>Email hops: ${findings.header_analysis?.hop_count || 0}</li>
            </ul>
          </div>
          
          <div class="actions">
            <button class="close-btn" onclick="this.closest('#phish-analyzer-result').remove()">Close</button>
            <button class="details-btn" onclick="chrome.runtime.sendMessage({action: 'openDetails', analysisId: '${result.analysis_id}'})">View Details</button>
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(resultModal);
  }

  showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `phish-analyzer-notification ${type}`;
    notification.textContent = message;
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 20px;
      background: ${type === 'error' ? '#d13438' : '#107c10'};
      color: white;
      border-radius: 4px;
      z-index: 10000;
      font-family: 'Segoe UI', sans-serif;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
      notification.remove();
    }, 3000);
  }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analysisComplete') {
    window.outlookAnalyzer.showAnalysisResult(request.data);
  }
  
  if (request.action === 'analysisFailed') {
    window.outlookAnalyzer.hideAnalysisOverlay();
    window.outlookAnalyzer.showNotification('Analysis failed: ' + request.error, 'error');
  }
});

// Initialize when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.outlookAnalyzer = new OutlookPhishAnalyzer();
  });
} else {
  window.outlookAnalyzer = new OutlookPhishAnalyzer();
}
