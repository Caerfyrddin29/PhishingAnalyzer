// Content script for Gmail integration

class GmailPhishAnalyzer {
  constructor() {
    this.isAnalyzing = false;
    this.analysisOverlay = null;
    this.init();
  }

  init() {
    console.log('PhishAnalyzer loaded for Gmail');
    
    // Add global styles for better button visibility
    this.addGlobalStyles();
    
    this.setupObserver();
    this.addAnalysisButtons();
  }

  addGlobalStyles() {
    // Create and inject global styles
    const styleId = 'phish-analyzer-global-styles';
    if (document.getElementById(styleId)) return;
    
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      .phish-analyzer-btn {
        display: inline-flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        pointer-events: auto !important;
        position: relative !important;
        z-index: 9999 !important;
      }
      
      .phish-analyzer-btn:hover {
        display: inline-flex !important;
        visibility: visible !important;
        opacity: 1 !important;
        pointer-events: auto !important;
      }
      
      /* Ensure button containers don't hide buttons */
      .phish-analyzer-btn-container {
        display: inline-block !important;
        visibility: visible !important;
      }
      
      /* Gmail specific fixes */
      tr.zA .phish-analyzer-btn,
      tr.y6 .phish-analyzer-btn,
      div[role="row"] .phish-analyzer-btn {
        float: none !important;
        position: static !important;
        margin: 2px 4px !important;
      }
      
      /* Prevent Gmail from hiding our buttons */
      .phish-analyzer-btn {
        -webkit-transform: none !important;
        transform: none !important;
        clip: auto !important;
        clip-path: none !important;
      }
    `;
    
    document.head.appendChild(style);
  }

  setupObserver() {
    // Monitor for new emails with more aggressive observation
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
          // Check added nodes for email rows
          mutation.addedNodes.forEach(node => {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Direct check if the node itself is an email row
              if (node.matches && node.matches('tr.zA, tr.y6, div[role="row"]')) {
                this.addAnalysisButtons();
              }
              // Check if node contains email rows
              const emailRows = node.querySelectorAll && node.querySelectorAll('tr.zA, tr.y6, div[role="row"]');
              if (emailRows && emailRows.length > 0) {
                this.addAnalysisButtons();
              }
            }
          });
        }
      });
    });

    // Observe the entire document with more comprehensive settings
    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false
    });
    
    // Also check periodically for any missed emails
    setInterval(() => {
      this.addAnalysisButtons();
    }, 2000);
    
    // Initial scan
    setTimeout(() => {
      this.addAnalysisButtons();
    }, 1000);
  }

  addAnalysisButtons() {
    // Find email rows in Gmail interface with comprehensive selectors
    const emailRows = document.querySelectorAll('tr.zA, tr.y6, div[role="row"][aria-label*="From"]');
    
    emailRows.forEach(row => {
      // Skip if button already added
      if (row.querySelector('.phish-analyzer-btn')) return;
      
      let buttonContainer = null;
      
      // Try multiple container strategies for best placement
      const containerSelectors = [
        '.yW',           // Star column
        '.xY',           // Checkbox column  
        'td.yX',         // Action cell
        'td.yW',         // Star cell
        'div[role="gridcell"]:last-child',  // Last grid cell
        '.buL',          // Button container
        'span.g3'        // Span container
      ];
      
      for (const selector of containerSelectors) {
        buttonContainer = row.querySelector(selector);
        if (buttonContainer) break;
      }
      
      // If no suitable container, create an intelligent one
      if (!buttonContainer) {
        buttonContainer = document.createElement('div');
        buttonContainer.className = 'phish-analyzer-btn-container';
        buttonContainer.style.cssText = `
          display: inline-flex !important;
          align-items: center !important;
          justify-content: flex-end !important;
          margin: 0 !important;
          padding: 0 !important;
          vertical-align: middle !important;
          width: auto !important;
          height: auto !important;
          visibility: visible !important;
          opacity: 1 !important;
          z-index: 9999 !important;
          position: relative !important;
        `;
        
        // Try to append to the best parent location
        const appendTargets = [
          row.querySelector('td:last-child'),  // Last cell
          row.querySelector('td.yX'),          // Action cell
          row.querySelector('div[role="gridcell"]'),  // Any grid cell
          row                                  // Fallback to row itself
        ];
        
        let appended = false;
        for (const target of appendTargets) {
          if (target) {
            target.appendChild(buttonContainer);
            appended = true;
            break;
          }
        }
        
        if (!appended) {
          row.appendChild(buttonContainer);
        }
      }
      
      const analyzeBtn = document.createElement('button');
      analyzeBtn.className = 'phish-analyzer-btn';
      analyzeBtn.innerHTML = '🛡️ Analyze';
      analyzeBtn.setAttribute('title', 'Analyze this email for phishing threats');
      analyzeBtn.style.cssText = `
        display: inline-flex !important;
        align-items: center !important;
        gap: 4px !important;
        margin: 2px 4px !important;
        padding: 6px 12px !important;
        background: linear-gradient(135deg, #4285f4, #357ae8) !important;
        color: white !important;
        border: none !important;
        border-radius: 16px !important;
        cursor: pointer !important;
        font-size: 11px !important;
        font-weight: 500 !important;
        font-family: 'Google Sans', Roboto, Arial, sans-serif !important;
        transition: all 0.2s ease !important;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12) !important;
        z-index: 10000 !important;
        position: relative !important;
        white-space: nowrap !important;
        line-height: 1 !important;
        min-height: 24px !important;
        min-width: 80px !important;
        justify-content: center !important;
        text-decoration: none !important;
        text-align: center !important;
        flex-shrink: 0 !important;
      `;
      
      // Enhanced hover effects
      analyzeBtn.addEventListener('mouseenter', () => {
        analyzeBtn.style.background = 'linear-gradient(135deg, #357ae8, #2a5bc7) !important';
        analyzeBtn.style.transform = 'translateY(-1px) scale(1.02) !important';
        analyzeBtn.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15) !important';
      });
      
      analyzeBtn.addEventListener('mouseleave', () => {
        analyzeBtn.style.background = 'linear-gradient(135deg, #4285f4, #357ae8) !important';
        analyzeBtn.style.transform = 'translateY(0) scale(1) !important';
        analyzeBtn.style.boxShadow = '0 1px 3px rgba(0,0,0,0.12) !important';
      });
      
      // Active/click effects
      analyzeBtn.addEventListener('mousedown', () => {
        analyzeBtn.style.transform = 'translateY(0) scale(0.98) !important';
        analyzeBtn.style.boxShadow = '0 2px 4px rgba(0,0,0,0.2) !important';
      });
      
      analyzeBtn.addEventListener('mouseup', () => {
        analyzeBtn.style.transform = 'translateY(-1px) scale(1.02) !important';
        analyzeBtn.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15) !important';
      });
      
      analyzeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        this.analyzeEmailFromRow(row);
      });
      
      // Ensure button is visible and clickable
      buttonContainer.appendChild(analyzeBtn);
      
      // Force visibility after a short delay
      setTimeout(() => {
        analyzeBtn.style.opacity = '1';
        analyzeBtn.style.pointerEvents = 'auto';
        analyzeBtn.style.visibility = 'visible';
        analyzeBtn.style.display = 'inline-flex';
      }, 100);
    });
  }

  analyzeEmailFromRow(row) {
    const subjectElement = row.querySelector('.bog, .y6');
    const senderElement = row.querySelector('.yW, .go');
    
    if (!subjectElement || !senderElement) {
      this.showNotification('Could not extract email data', 'error');
      return;
    }
    
    const subject = subjectElement.textContent.trim();
    const sender = senderElement.textContent.trim();
    
    // Open email to get full content
    row.click();
    
    setTimeout(() => {
      this.analyzeCurrentEmail();
    }, 1000);
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
    // Extract email data from Gmail interface
    const subjectElement = document.querySelector('h2.hP, h1.hP');
    const senderElement = document.querySelector('.gD, .go');
    const bodyElement = document.querySelector('.a3s, .ii.gt');
    
    if (!subjectElement || !senderElement || !bodyElement) {
      return null;
    }
    
    return {
      subject: subjectElement.textContent.trim(),
      sender: senderElement.textContent.trim(),
      body: bodyElement.textContent.trim(),
      headers: '', // Gmail headers are not easily accessible
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
    
    const { risk_score, risk_level, findings, analysis_id } = result;
    
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
            <button class="close-btn" id="close-analysis-btn">Close</button>
            <button class="details-btn" id="view-details-btn">View Details</button>
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(resultModal);
    
    // Add event listeners with proper event handling
    const closeBtn = document.getElementById('close-analysis-btn');
    const detailsBtn = document.getElementById('view-details-btn');
    
    if (closeBtn) {
      closeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.closeAnalysisModal();
      });
    }
    
    if (detailsBtn) {
      detailsBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.showDetailedResults(result);
      });
    }
    
    // Also close modal when clicking outside
    resultModal.addEventListener('click', (e) => {
      if (e.target === resultModal) {
        this.closeAnalysisModal();
      }
    });
    
    // Close with Escape key
    const escapeHandler = (e) => {
      if (e.key === 'Escape') {
        this.closeAnalysisModal();
        document.removeEventListener('keydown', escapeHandler);
      }
    };
    document.addEventListener('keydown', escapeHandler);
  }

  closeAnalysisModal() {
    const modal = document.getElementById('phish-analyzer-result');
    if (modal) {
      modal.remove();
    }
  }

  showDetailedResults(result) {
    const { findings, risk_score, risk_level, analysis_id } = result;
    
    // Create detailed results modal
    const detailsModal = document.createElement('div');
    detailsModal.id = 'phish-analyzer-details';
    detailsModal.innerHTML = `
      <div class="phish-analyzer-modal details-modal">
        <div class="phish-analyzer-content">
          <h3>🔍 Detailed Analysis Results</h3>
          
          <div class="risk-summary">
            <div class="risk-score ${risk_level.toLowerCase()}">
              <div class="score-circle">
                <span class="score-number">${risk_score}</span>
                <span class="risk-label">${risk_level}</span>
              </div>
            </div>
            <div class="risk-explanation">
              <h4>Risk Assessment</h4>
              <p>${this.getRiskExplanation(risk_level, risk_score)}</p>
            </div>
          </div>
          
          <div class="detailed-findings">
            <h4>📧 Email Metadata</h4>
            <div class="metadata-section">
              <p><strong>Subject:</strong> ${findings.metadata?.subject || 'N/A'}</p>
              <p><strong>Sender:</strong> ${findings.metadata?.sender || 'N/A'}</p>
              <p><strong>Analysis ID:</strong> ${analysis_id}</p>
            </div>
            
            <h4>🔗 Suspicious URLs (${findings.urls?.length || 0})</h4>
            <div class="urls-section">
              ${findings.urls && findings.urls.length > 0 ? 
                findings.urls.map(url => `<div class="url-item">🔗 ${url}</div>`).join('') :
                '<p>No suspicious URLs detected</p>'
              }
            </div>
            
            <h4>📧 Email Addresses (${findings.email_addresses?.length || 0})</h4>
            <div class="emails-section">
              ${findings.email_addresses && findings.email_addresses.length > 0 ?
                findings.email_addresses.map(email => `<div class="email-item">📧 ${email}</div>`).join('') :
                '<p>No additional email addresses detected</p>'
              }
            </div>
            
            <h4>🌐 IP Addresses (${findings.ip_addresses?.length || 0})</h4>
            <div class="ips-section">
              ${findings.ip_addresses && findings.ip_addresses.length > 0 ?
                findings.ip_addresses.map(ip => `<div class="ip-item">🌐 ${ip}</div>`).join('') :
                '<p>No IP addresses detected</p>'
              }
            </div>
            
            <h4>📊 Header Analysis</h4>
            <div class="headers-section">
              <p><strong>Email Hops:</strong> ${findings.header_analysis?.hop_count || 0}</p>
              <p><strong>Suspicious Headers:</strong> ${findings.header_analysis?.suspicious_headers?.length || 0}</p>
              ${findings.header_analysis?.suspicious_headers && findings.header_analysis.suspicious_headers.length > 0 ?
                findings.header_analysis.suspicious_headers.map(header => `<div class="header-item">⚠️ ${header}</div>`).join('') :
                '<p>No suspicious headers detected</p>'
              }
            </div>
          </div>
          
          <div class="actions">
            <button class="back-btn" id="back-to-summary">← Back to Summary</button>
            <button class="export-btn" id="export-results">📥 Export Results</button>
            <button class="close-details-btn" id="close-details-btn">Close</button>
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(detailsModal);
    
    // Hide the summary modal
    this.closeAnalysisModal();
    
    // Add event listeners for details modal
    const backBtn = document.getElementById('back-to-summary');
    const exportBtn = document.getElementById('export-results');
    const closeDetailsBtn = document.getElementById('close-details-btn');
    
    if (backBtn) {
      backBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        detailsModal.remove();
        this.showAnalysisResult(result);
      });
    }
    
    if (exportBtn) {
      exportBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        this.exportResults(result);
      });
    }
    
    if (closeDetailsBtn) {
      closeDetailsBtn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        detailsModal.remove();
      });
    }
    
    // Close modal when clicking outside
    detailsModal.addEventListener('click', (e) => {
      if (e.target === detailsModal) {
        detailsModal.remove();
      }
    });
    
    // Close with Escape key
    const escapeHandler = (e) => {
      if (e.key === 'Escape') {
        detailsModal.remove();
        document.removeEventListener('keydown', escapeHandler);
      }
    };
    document.addEventListener('keydown', escapeHandler);
  }

  getRiskExplanation(level, score) {
    const explanations = {
      'LOW': 'This email appears to be safe with minimal risk indicators. Standard security precautions are recommended.',
      'MEDIUM': 'This email contains some suspicious elements that warrant caution. Verify sender identity before clicking links.',
      'HIGH': 'This email exhibits multiple phishing indicators. Do not click links or download attachments without verification.',
      'CRITICAL': 'This email shows strong signs of being a phishing attempt. Delete immediately and report to security team.'
    };
    
    return explanations[level] || 'Risk assessment could not be determined.';
  }

  exportResults(result) {
    const { findings, risk_score, risk_level, analysis_id } = result;
    
    const exportData = {
      analysis_id: analysis_id,
      timestamp: new Date().toISOString(),
      risk_assessment: {
        score: risk_score,
        level: risk_level,
        explanation: this.getRiskExplanation(risk_level, risk_score)
      },
      findings: findings
    };
    
    const dataStr = JSON.stringify(exportData, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `phishanalyzer_analysis_${analysis_id}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.style.display = 'none';
    
    document.body.appendChild(linkElement);
    linkElement.click();
    document.body.removeChild(linkElement);
    
    this.showNotification('Analysis results exported successfully', 'success');
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
      background: ${type === 'error' ? '#f44336' : '#4CAF50'};
      color: white;
      border-radius: 4px;
      z-index: 10000;
      font-family: Arial, sans-serif;
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
    window.gmailAnalyzer.showAnalysisResult(request.data);
  }
  
  if (request.action === 'analysisFailed') {
    window.gmailAnalyzer.hideAnalysisOverlay();
    window.gmailAnalyzer.showNotification('Analysis failed: ' + request.error, 'error');
  }
});

// Initialize when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.gmailAnalyzer = new GmailPhishAnalyzer();
  });
} else {
  window.gmailAnalyzer = new GmailPhishAnalyzer();
}
