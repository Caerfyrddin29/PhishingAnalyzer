// Background service worker for PhishAnalyzer extension

let analysisResults = new Map();

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'analyzeEmail') {
    analyzeEmail(request.data, sender.tab.id)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'getAnalysisResult') {
    const result = analysisResults.get(request.analysisId);
    sendResponse({ success: true, data: result });
  }
  
  if (request.action === 'clearResults') {
    analysisResults.clear();
    sendResponse({ success: true });
  }
});

// Analyze email via API
async function analyzeEmail(emailData, tabId) {
  try {
    const response = await fetch('http://127.0.0.1:8000/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailData)
    });
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    
    const result = await response.json();
    analysisResults.set(result.analysis_id, result);
    
    // Send result back to content script
    chrome.tabs.sendMessage(tabId, {
      action: 'analysisComplete',
      data: result
    });
    
    return result;
    
  } catch (error) {
    console.error('Analysis failed:', error);
    
    // Notify content script of failure
    chrome.tabs.sendMessage(tabId, {
      action: 'analysisFailed',
      error: error.message
    });
    
    throw error;
  }
}

// Extension installation
chrome.runtime.onInstalled.addListener(() => {
  console.log('PhishAnalyzer extension installed');
  
  // Initialize storage
  chrome.storage.local.set({
    'phishAnalyzer_settings': {
      autoAnalyze: true,
      showNotifications: true,
      apiEndpoint: 'http://127.0.0.1:8000'
    }
  });
});

// Handle extension icon click
chrome.action.onClicked.addListener((tab) => {
  chrome.action.openPopup();
});
