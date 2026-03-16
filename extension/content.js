// Content Script - Injected into web pages
class PhishAnalyzerContent {
  constructor() {
    this.setupMessageHandlers();
    this.warningOverlay = null;
  }

  setupMessageHandlers() {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'url-analysis') {
        this.handleUrlAnalysis(request.result);
      } else if (request.action === 'show-result') {
        this.showAnalysisResult(request.result);
      }
    });
  }

  handleUrlAnalysis(result) {
    if (result.classification === 'PHISHING' && result.risk_score > 70) {
      this.showPhishingWarning(result);
    }
  }

  showPhishingWarning(result) {
    // Create warning overlay
    if (this.warningOverlay) return; // Already showing

    this.warningOverlay = document.createElement('div');
    this.warningOverlay.id = 'phishanalyzer-warning';
    this.warningOverlay.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(255, 0, 0, 0.95);
      color: white;
      z-index: 999999;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    this.warningOverlay.innerHTML = `
      <div style="text-align: center; max-width: 600px; padding: 2rem;">
        <div style="font-size: 4rem; margin-bottom: 1rem;">⚠️</div>
        <h1 style="margin-bottom: 1rem; font-size: 2rem;">DANGER - PHISHING DETECTED</h1>
        <p style="margin-bottom: 1rem; font-size: 1.2rem;">
          This website has been identified as a phishing threat!
        </p>
        <div style="background: rgba(255,255,255,0.1); padding: 1rem; border-radius: 8px; margin-bottom: 2rem;">
          <p><strong>Risk Score:</strong> ${result.risk_score}/100</p>
          <p><strong>Confidence:</strong> ${(result.confidence * 100).toFixed(1)}%</p>
          <p><strong>URL:</strong> ${window.location.href}</p>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: center;">
          <button id="close-warning" style="
            background: #ff4444;
            color: white;
            border: none;
            padding: 1rem 2rem;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
          ">I understand the risk</button>
          <button id="leave-site" style="
            background: white;
            color: #ff4444;
            border: 2px solid white;
            padding: 1rem 2rem;
            border-radius: 8px;
            font-size: 1rem;
            cursor: pointer;
          ">Leave this site</button>
        </div>
        <p style="margin-top: 2rem; font-size: 0.9rem; opacity: 0.8;">
          Analysis by PhishAnalyzer v3.0
        </p>
      </div>
    `;

    document.body.appendChild(this.warningOverlay);

    // Add event listeners
    document.getElementById('close-warning').addEventListener('click', () => {
      this.removeWarning();
    });

    document.getElementById('leave-site').addEventListener('click', () => {
      window.history.back();
    });
  }

  removeWarning() {
    if (this.warningOverlay) {
      this.warningOverlay.remove();
      this.warningOverlay = null;
    }
  }

  showAnalysisResult(result) {
    // Show a subtle notification
    const notification = document.createElement('div');
    notification.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${result.classification === 'PHISHING' ? '#ff4444' : 
                   result.classification === 'SUSPICIOUS' ? '#ff8800' : '#44ff44'};
      color: white;
      padding: 1rem;
      border-radius: 8px;
      z-index: 999999;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      max-width: 300px;
    `;

    notification.innerHTML = `
      <div style="font-weight: bold; margin-bottom: 0.5rem;">
        ${result.classification}
      </div>
      <div style="font-size: 0.9rem;">
        Risk Score: ${result.risk_score}/100
      </div>
      <div style="font-size: 0.8rem; margin-top: 0.5rem; opacity: 0.8;">
        ${(result.confidence * 100).toFixed(1)}% confidence
      </div>
    `;

    document.body.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove();
      }
    }, 5000);
  }
}

// Initialize content script
const phishAnalyzerContent = new PhishAnalyzerContent();
