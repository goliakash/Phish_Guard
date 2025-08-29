// DOM elements
const urlDisplay = document.getElementById('url-display');
const statusIndicator = document.getElementById('status');
const resultBox = document.getElementById('result');
const riskDetails = document.getElementById('risk-details');
const scanButton = document.getElementById('scan-btn');
const reportButton = document.getElementById('report-btn');
const whitelistButton = document.getElementById('whitelist-btn');

// Tab elements
const tabButtons = document.querySelectorAll('.tab-btn');
const tabPanes = document.querySelectorAll('.tab-pane');
const detailsTab = document.getElementById('details-tab');
const historyTab = document.getElementById('history-tab');
const settingsTab = document.getElementById('settings-tab');

// Settings elements
const urlAnalysisCheckbox = document.getElementById('enable-url-analysis');
const contentAnalysisCheckbox = document.getElementById('enable-content-analysis');
const brandProtectionCheckbox = document.getElementById('enable-brand-protection');
const realTimeAlertsCheckbox = document.getElementById('enable-realtime-alerts');
const saveSettingsButton = document.getElementById('save-settings');

// Protection status indicators
const protectionIndicator = document.getElementById('protection-indicator');
const urlAnalysisStatus = document.getElementById('url-analysis-status');
const contentAnalysisStatus = document.getElementById('content-analysis-status');
const alertsStatus = document.getElementById('alerts-status');

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  // Get current tab URL
  getCurrentTab().then(tab => {
    const url = new URL(tab.url);
    urlDisplay.textContent = url.hostname;
    
    // Analyze the current URL
    analyzeUrl(tab.url);
    
    // Set up event listeners
    scanButton.addEventListener('click', () => analyzeUrl(tab.url));
    reportButton.addEventListener('click', () => reportSite(tab.url));
    whitelistButton.addEventListener('click', () => addToWhitelist(url.hostname));
    
    // Set up tab switching
    tabButtons.forEach(button => {
      button.addEventListener('click', () => switchTab(button.id));
    });
    
    // Load settings
    loadSettings();
    
    // Load scan history
    loadScanHistory();
    
    // Set up settings save button
    saveSettingsButton.addEventListener('click', saveSettings);
  });
});

// Switch between tabs
function switchTab(tabId) {
  // Remove active class from all tabs
  tabButtons.forEach(btn => btn.classList.remove('active'));
  tabPanes.forEach(pane => pane.classList.remove('active'));
  
  // Add active class to selected tab
  document.getElementById(tabId).classList.add('active');
  
  // Show corresponding content
  if (tabId === 'tab-details') {
    detailsTab.classList.add('active');
  } else if (tabId === 'tab-history') {
    historyTab.classList.add('active');
  } else if (tabId === 'tab-settings') {
    settingsTab.classList.add('active');
  }
}

// Load settings from storage
function loadSettings() {
  chrome.storage.local.get(['enabledFeatures'], (result) => {
    const features = result.enabledFeatures || {
      urlAnalysis: true,
      contentAnalysis: true,
      brandProtection: true,
      realTimeAlerts: true
    };
    
    // Update checkboxes
    urlAnalysisCheckbox.checked = features.urlAnalysis;
    contentAnalysisCheckbox.checked = features.contentAnalysis;
    brandProtectionCheckbox.checked = features.brandProtection;
    realTimeAlertsCheckbox.checked = features.realTimeAlerts;
    
    // Update status indicators
    updateProtectionStatus(features);
  });
}

// Save settings to storage
function saveSettings() {
  const features = {
    urlAnalysis: urlAnalysisCheckbox.checked,
    contentAnalysis: contentAnalysisCheckbox.checked,
    brandProtection: brandProtectionCheckbox.checked,
    realTimeAlerts: realTimeAlertsCheckbox.checked
  };
  
  chrome.storage.local.set({ enabledFeatures: features }, () => {
    // Update status indicators
    updateProtectionStatus(features);
    
    // Show saved message
    const saveBtn = document.getElementById('save-settings');
    const originalText = saveBtn.textContent;
    saveBtn.textContent = 'Saved!';
    setTimeout(() => {
      saveBtn.textContent = originalText;
    }, 1500);
  });
}

// Update protection status indicators
function updateProtectionStatus(features) {
  // Update main indicator
  const isActive = Object.values(features).some(value => value === true);
  protectionIndicator.textContent = isActive ? 'Active' : 'Inactive';
  protectionIndicator.className = isActive ? 'active' : 'inactive';
  
  // Update feature indicators
  urlAnalysisStatus.textContent = features.urlAnalysis ? 'Enabled' : 'Disabled';
  urlAnalysisStatus.className = 'feature-status ' + (features.urlAnalysis ? 'enabled' : 'disabled');
  
  contentAnalysisStatus.textContent = features.contentAnalysis ? 'Enabled' : 'Disabled';
  contentAnalysisStatus.className = 'feature-status ' + (features.contentAnalysis ? 'enabled' : 'disabled');
  
  alertsStatus.textContent = features.realTimeAlerts ? 'Enabled' : 'Disabled';
  alertsStatus.className = 'feature-status ' + (features.realTimeAlerts ? 'enabled' : 'disabled');
}

// Load scan history
function loadScanHistory() {
  chrome.runtime.sendMessage({ action: 'getScanHistory' }, (response) => {
    const historyContainer = document.getElementById('scan-history');
    
    if (response && response.history && response.history.length > 0) {
      // Clear loading message
      historyContainer.innerHTML = '';
      
      // Add history items (limit to 10)
      const recentHistory = response.history.slice(0, 10);
      
      recentHistory.forEach(scan => {
        const historyItem = document.createElement('div');
        historyItem.className = 'history-item';
        
        const domain = document.createElement('div');
        domain.className = 'history-domain';
        domain.textContent = scan.domain;
        
        const risk = document.createElement('div');
        risk.className = `history-risk ${scan.riskLevel}`;
        risk.textContent = scan.riskLevel.charAt(0).toUpperCase() + scan.riskLevel.slice(1);
        
        historyItem.appendChild(domain);
        historyItem.appendChild(risk);
        historyContainer.appendChild(historyItem);
      });
    } else {
      historyContainer.innerHTML = '<p>No scan history available</p>';
    }
  });
}

// Add current domain to whitelist
function addToWhitelist(domain) {
  chrome.runtime.sendMessage({ action: 'addToWhitelist', domain: domain }, (response) => {
    if (response && response.success) {
      // Update button text temporarily
      whitelistButton.textContent = 'Added to Whitelist';
      setTimeout(() => {
        whitelistButton.textContent = 'Add to Whitelist';
      }, 2000);
      
      // Re-analyze URL to update UI
      getCurrentTab().then(tab => {
        analyzeUrl(tab.url);
      });
    }
  });
}

// Get the current active tab
async function getCurrentTab() {
  const queryOptions = { active: true, currentWindow: true };
  const [tab] = await chrome.tabs.query(queryOptions);
  return tab;
}

// Analyze URL for potential fraud
async function analyzeUrl(url) {
  // Reset UI
  statusIndicator.textContent = 'Scanning...';
  resultBox.style.display = 'none';
  riskDetails.innerHTML = '';
  
  try {
    // Show loading state
    statusIndicator.textContent = 'Analyzing...';
    
    // First check if content script has already analyzed the page
    const tab = await getCurrentTab();
    
    // Try to get analysis from content script first
    const contentResponse = await new Promise(resolve => {
      chrome.tabs.sendMessage(tab.id, { action: 'getPageAnalysis' }, response => {
        resolve(response || { complete: false });
      });
    }).catch(() => ({ complete: false }));
    
    let analysis;
    
    // If content script has completed analysis, use that data
    if (contentResponse && contentResponse.complete && contentResponse.analysis) {
      analysis = contentResponse.analysis;
      console.log('Using analysis from content script:', analysis);
    } else {
      // Otherwise, get content and perform our own analysis
      const pageContent = await getPageContent();
      analysis = await performAnalysis(url, pageContent);
      
      // Trigger a reanalysis in the content script to keep data in sync
      chrome.tabs.sendMessage(tab.id, { action: 'reanalyze' });
    }
    
    // Update UI with results
    displayResults(analysis);
    
    // Store this scan in history
    storeInScanHistory(url, analysis);
  } catch (error) {
    console.error('Analysis error:', error);
    statusIndicator.textContent = 'Error scanning site';
  }
}

// Get content from the current page
async function getPageContent() {
  try {
    const tab = await getCurrentTab();
    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      function: () => {
        return {
          title: document.title,
          metaTags: Array.from(document.querySelectorAll('meta')).map(meta => {
            return { name: meta.getAttribute('name'), content: meta.getAttribute('content') };
          }),
          links: Array.from(document.querySelectorAll('a')).map(a => a.href).slice(0, 20),
          forms: document.querySelectorAll('form').length,
          hasPasswordField: document.querySelectorAll('input[type="password"]').length > 0,
          hasLoginForm: document.querySelectorAll('form').length > 0 && 
                        (document.querySelectorAll('input[type="password"]').length > 0 ||
                         document.body.innerText.toLowerCase().includes('login') ||
                         document.body.innerText.toLowerCase().includes('sign in')),
          textContent: document.body.innerText.substring(0, 5000)
        };
      }
    });
    
    return results[0].result;
  } catch (error) {
    console.error('Error getting page content:', error);
    return null;
  }
}

// Perform fraud analysis (simulated AI model)
async function performAnalysis(url, pageContent) {
  // In a real extension, this would call a backend API with ML models
  // For this demo, we'll use a simplified rule-based approach
  
  const urlObj = new URL(url);
  const domain = urlObj.hostname;
  
  // Initialize risk factors and score
  const riskFactors = [];
  let riskScore = 0;
  
  // Check URL characteristics
  if (domain.includes('secure') || domain.includes('login') || domain.includes('account')) {
    riskFactors.push('Domain contains sensitive terms like "secure", "login", or "account"');
    riskScore += 0.1;
  }
  
  if (domain.length > 30) {
    riskFactors.push('Unusually long domain name');
    riskScore += 0.1;
  }
  
  if (domain.split('.').length > 2) {
    riskFactors.push('Multiple subdomains detected');
    riskScore += 0.1;
  }
  
  if (domain.includes('-') && domain.split('-').length > 2) {
    riskFactors.push('Domain contains multiple hyphens');
    riskScore += 0.1;
  }
  
  // Check for common brand names in domain (potential phishing)
  const brandTerms = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 
                     'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard'];
  
  for (const brand of brandTerms) {
    if (domain.includes(brand) && !domain.startsWith(brand + '.com')) {
      riskFactors.push(`Domain contains brand name "${brand}" but is not the official domain`);
      riskScore += 0.3;
      break;
    }
  }
  
  // Check page content if available
  if (pageContent) {
    // Check for login forms with suspicious characteristics
    if (pageContent.hasLoginForm) {
      riskScore += 0.1;
      
      // Higher risk if URL doesn't match content
      if (pageContent.title && brandTerms.some(brand => 
          pageContent.title.toLowerCase().includes(brand) && 
          !domain.includes(brand))) {
        riskFactors.push('Page title contains brand name that doesn\'t match the domain');
        riskScore += 0.3;
      }
    }
    
    // Check for urgency or threatening language in text content
    const urgencyPhrases = ['urgent', 'immediately', 'suspended', 'verify now', 'limited time',
                           'account locked', 'security alert', 'unauthorized access'];
    
    if (pageContent.textContent) {
      const lowerText = pageContent.textContent.toLowerCase();
      const foundPhrases = urgencyPhrases.filter(phrase => lowerText.includes(phrase));
      
      if (foundPhrases.length > 0) {
        riskFactors.push(`Contains urgency language: ${foundPhrases.join(', ')}`);
        riskScore += 0.1 * Math.min(foundPhrases.length, 3);
      }
    }
  }
  
  // Determine risk level
  let riskLevel;
  if (riskScore >= 0.7) {
    riskLevel = 'high';
  } else if (riskScore >= 0.4) {
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }
  
  // Simulate a small delay to make it feel like analysis is happening
  await new Promise(resolve => setTimeout(resolve, 1000));
  
  return {
    url: url,
    domain: domain,
    riskScore: riskScore,
    riskLevel: riskLevel,
    riskFactors: riskFactors
  };
}

// Display analysis results in the popup
function displayResults(analysis) {
  // Update status
  statusIndicator.textContent = `Analysis complete`;
  
  // Show result box with appropriate styling
  resultBox.style.display = 'block';
  resultBox.className = 'result-box';
  
  // Set content based on risk level
  if (analysis.riskLevel === 'high') {
    resultBox.classList.add('result-danger');
    resultBox.innerHTML = `
      <strong>🚨 High Risk Detected!</strong><br>
      This site shows multiple signs of being fraudulent.<br>
      <small>Risk Score: ${analysis.riskScore.toFixed(2)}</small>
    `;
  } else if (analysis.riskLevel === 'medium') {
    resultBox.classList.add('result-warning');
    resultBox.innerHTML = `
      <strong>⚠️ Suspicious Site</strong><br>
      Proceed with caution. This site has some red flags.<br>
      <small>Risk Score: ${analysis.riskScore.toFixed(2)}</small>
    `;
  } else {
    resultBox.classList.add('result-safe');
    resultBox.innerHTML = `
      <strong>✅ Likely Safe</strong><br>
      No major risks detected in this URL.<br>
      <small>Risk Score: ${analysis.riskScore.toFixed(2)}</small>
    `;
  }
  
  // Display risk factors if any
  if (analysis.riskFactors.length > 0) {
    riskDetails.innerHTML = `
      <h2>Risk Factors</h2>
      <ul>
        ${analysis.riskFactors.map(factor => `<li>${factor}</li>`).join('')}
      </ul>
    `;
  }
}

// Store scan in history
function storeInScanHistory(url, analysis) {
  // Send message to background script to store in scan history
  chrome.runtime.sendMessage({
    action: 'addToScanHistory',
    scan: {
      url: url,
      domain: analysis.domain,
      timestamp: new Date().toISOString(),
      riskLevel: analysis.riskLevel,
      riskScore: analysis.riskScore,
      riskFactors: analysis.riskFactors
    }
  });
}

// Report the current site
function reportSite(url) {
  // In a real extension, this would send the report to a backend
  alert(`Thank you for reporting ${url}. Our team will review this site.`);
  
  // Get the current tab
  getCurrentTab().then(tab => {
    // Send report to background script
    chrome.runtime.sendMessage({
      action: 'reportSite',
      url: url,
      tabId: tab.id
    });
  });
}