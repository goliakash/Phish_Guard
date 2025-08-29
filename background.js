// Background script for Spot the Fake extension

// Initialize extension when installed
chrome.runtime.onInstalled.addListener(() => {
  console.log('Spot the Fake extension installed');
  
  // Initialize storage with default settings
  chrome.storage.local.set({
    enabledFeatures: {
      urlAnalysis: true,
      contentAnalysis: true,
      brandProtection: true,
      realTimeAlerts: true
    },
    scanHistory: [],
    whitelist: [],
    knownPhishingPatterns: [
      // Common phishing patterns
      { pattern: 'secure.*login', score: 0.2 },
      { pattern: 'verify.*account', score: 0.2 },
      { pattern: 'confirm.*payment', score: 0.2 },
      { pattern: 'update.*billing', score: 0.2 },
      { pattern: 'suspicious.*activity', score: 0.2 }
    ]
  });
  
  // Set badge text color
  chrome.action.setBadgeTextColor({ color: '#FFFFFF' });
});

// Listen for navigation events to analyze URLs
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Only run when the page is fully loaded
  if (changeInfo.status === 'complete' && tab.url) {
    // Skip browser internal pages and extension pages
    if (!tab.url.startsWith('chrome://') && !tab.url.startsWith('chrome-extension://')) {
      // Check if URL is in whitelist and get enabled features
      chrome.storage.local.get(['whitelist', 'enabledFeatures', 'knownPhishingPatterns'], (data) => {
        const whitelist = data.whitelist || [];
        const enabledFeatures = data.enabledFeatures || {
          urlAnalysis: true,
          contentAnalysis: true,
          brandProtection: true,
          realTimeAlerts: true
        };
        const knownPatterns = data.knownPhishingPatterns || [];
        
        try {
          const url = new URL(tab.url);
          const domain = url.hostname;
          
          // Skip whitelisted domains
          if (!whitelist.includes(domain)) {
            // Only perform URL analysis if the feature is enabled
            if (enabledFeatures.urlAnalysis) {
              // Perform quick URL analysis
              const quickAnalysis = performQuickUrlAnalysis(tab.url, knownPatterns);
              
              // If high risk, show warning
              if (quickAnalysis.riskLevel === 'high') {
                // Set badge to alert user
                chrome.action.setBadgeText({ text: '!', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#dc3545', tabId: tabId });
                
                // Store analysis result
                storeAnalysisResult(tab.url, quickAnalysis);
                
                // Notify content script to show warning if real-time alerts are enabled
                if (enabledFeatures.realTimeAlerts) {
                  chrome.tabs.sendMessage(tabId, {
                    action: 'showWarning',
                    analysis: quickAnalysis
                  }).catch(err => console.log('Content script not ready yet'));
                }
              } else if (quickAnalysis.riskLevel === 'medium') {
                // Set badge for medium risk
                chrome.action.setBadgeText({ text: '!', tabId: tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#ffc107', tabId: tabId });
                
                // Store analysis result
                storeAnalysisResult(tab.url, quickAnalysis);
              } else {
                // Clear badge for low risk
                chrome.action.setBadgeText({ text: '', tabId: tabId });
              }
            }
          } else {
            // Clear badge for whitelisted domains
            chrome.action.setBadgeText({ text: '', tabId: tabId });
          }
        } catch (error) {
          console.error('Error analyzing URL:', error);
        }
      });
    }
  }
});

// Quick URL analysis (simplified version of the full analysis)
async function performQuickUrlAnalysis(url, knownPatterns = []) {
  const urlObj = new URL(url);
  const domain = urlObj.hostname;
  const fullUrl = url.toLowerCase();
  const path = urlObj.pathname.toLowerCase();
  
  // Check if domain is whitelisted
  const whitelisted = await isWhitelisted(domain);
  if (whitelisted) {
    return {
      url: url,
      domain: domain,
      riskScore: 0,
      riskLevel: 'low',
      riskFactors: ['Domain is in whitelist'],
      timestamp: new Date().toISOString(),
      whitelisted: true
    };
  }
  
  // Initialize risk score
  let riskScore = 0;
  const riskFactors = [];
  
  // Check URL characteristics
  if (domain.includes('secure') || domain.includes('login') || domain.includes('account')) {
    riskFactors.push('Sensitive terms in domain');
    riskScore += 0.15;
  }
  
  if (domain.length > 30) {
    riskFactors.push('Unusually long domain name');
    riskScore += 0.15;
  }
  
  if (domain.split('.').length > 2) {
    riskFactors.push('Multiple subdomains detected');
    riskScore += 0.15;
  }
  
  // Check for suspicious TLDs often used in phishing
  const suspiciousTLDs = ['xyz', 'top', 'club', 'online', 'site', 'info', 'work', 'ml', 'ga', 'cf', 'gq', 'buzz'];
  const tld = domain.split('.').pop();
  if (suspiciousTLDs.includes(tld)) {
    riskFactors.push(`Suspicious TLD: .${tld}`);
    riskScore += 0.15;
  }
  
  // Check for common brand names in domain (potential phishing)
  const brandTerms = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 
                     'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard',
                     'coinbase', 'blockchain', 'binance', 'gmail', 'outlook', 'yahoo', 'icloud',
                     'twitter', 'linkedin', 'dropbox', 'steam', 'github'];
  
  for (const brand of brandTerms) {
    if (domain.includes(brand) && !domain.startsWith(brand + '.com')) {
      riskFactors.push(`Brand name "${brand}" in non-official domain`);
      riskScore += 0.4;
      break;
    }
  }
  
  // Check for numbers in domain (common in phishing domains)
  if (/\d/.test(domain)) {
    riskFactors.push('Domain contains numbers');
    riskScore += 0.15;
  }
  
  // Check for hyphens (often used in phishing domains)
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount > 1) {
    riskFactors.push('Domain contains multiple hyphens');
    riskScore += 0.15;
  } else if (hyphenCount === 1 && (domain.includes('-secure') || domain.includes('secure-'))) {
    riskFactors.push('Domain uses suspicious "secure" pattern with hyphen');
    riskScore += 0.2;
  }
  
  // Check for common phishing URL patterns
  for (const pattern of knownPatterns) {
    const regex = new RegExp(pattern.pattern, 'i');
    if (regex.test(fullUrl)) {
      riskFactors.push(`Matches suspicious pattern: ${pattern.pattern}`);
      riskScore += pattern.score;
    }
  }
  
  // Check for suspicious URL paths
  const suspiciousPaths = ['login', 'signin', 'account', 'secure', 'update', 'verify', 'wallet', 'confirm', 
                          'verification', 'authenticate', 'recover', 'billing', 'payment', 'auth', 'session', 
                          'access', 'manage', 'reset', 'password'];
  for (const term of suspiciousPaths) {
    if (path.includes(term)) {
      riskFactors.push(`Suspicious term in URL path: ${term}`);
      riskScore += 0.15;
      break;
    }
  }
  
  // Check for URL redirection parameters
  if (fullUrl.includes('url=') || fullUrl.includes('redirect=') || fullUrl.includes('goto=')) {
    riskFactors.push('URL contains redirection parameters');
    riskScore += 0.2;
  }
  
  // Check for IP address instead of domain name
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain)) {
    riskFactors.push('URL uses IP address instead of domain name');
    riskScore += 0.4;
  }
  
  // Determine risk level with adjusted thresholds
  let riskLevel;
  if (riskScore >= 0.6) { // Increased threshold for high risk
    riskLevel = 'high';
  } else if (riskScore >= 0.35) { // Increased threshold for medium risk
    riskLevel = 'medium';
  } else {
    riskLevel = 'low';
  }
  
  return {
    url: url,
    domain: domain,
    riskScore: riskScore,
    riskLevel: riskLevel,
    riskFactors: riskFactors,
    timestamp: new Date().toISOString(),
    whitelisted: false
  };
}

// Store analysis result in extension storage
function storeAnalysisResult(url, analysis) {
  chrome.storage.local.get(['scanHistory'], (data) => {
    const scanHistory = data.scanHistory || [];
    
    // Add new scan to history (limit to 100 entries)
    scanHistory.unshift({
      url: url,
      domain: analysis.domain,
      riskLevel: analysis.riskLevel,
      riskScore: analysis.riskScore,
      timestamp: analysis.timestamp
    });
    
    // Keep only the most recent 100 scans
    if (scanHistory.length > 100) {
      scanHistory.pop();
    }
    
    // Save updated history
    chrome.storage.local.set({ scanHistory: scanHistory });
  });
}

// Listen for messages from popup or content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'addToWhitelist') {
    addToWhitelist(message.domain).then(result => {
      sendResponse({ success: result });
    });
    return true; // Required for async response
  } else if (message.action === 'removeFromWhitelist') {
    removeFromWhitelist(message.domain);
    sendResponse({ success: true });
  } else if (message.action === 'getScanHistory') {
    getScanHistory(sendResponse);
    return true; // Required for async response
  } else if (message.action === 'openPopup') {
    // Handle request to open the popup
    chrome.action.openPopup();
    sendResponse({ success: true });
  } else if (message.action === 'addToScanHistory') {
    // Add scan to history
    addToScanHistory(message.scan);
    sendResponse({ success: true });
  } else if (message.action === 'reportSite') {
    // Handle site report
    handleSiteReport(message.url, message.tabId);
    sendResponse({ success: true });
  } else if (message.action === 'getWhitelist') {
    // Get whitelist
    chrome.storage.local.get(['whitelist'], (data) => {
      sendResponse({ whitelist: data.whitelist || [] });
    });
    return true; // Required for async response
  } else if (message.action === 'checkWhitelist') {
    // Check if domain is in whitelist
    isWhitelisted(message.domain).then(result => {
      sendResponse({ whitelisted: result });
    });
    return true; // Required for async response
  }
  return true; // Required for async sendResponse
});

// Add scan to history
function addToScanHistory(scan) {
  chrome.storage.local.get(['scanHistory'], (result) => {
    let history = result.scanHistory || [];
    
    // Add new scan at the beginning
    history.unshift(scan);
    
    // Limit history to 100 entries
    if (history.length > 100) {
      history = history.slice(0, 100);
    }
    
    // Save updated history
    chrome.storage.local.set({ scanHistory: history });
  });
}

// Handle site report
function handleSiteReport(url, tabId) {
  // In a real extension, this would send the report to a backend service
  console.log('Site reported:', url);
  
  // For now, just add to scan history with high risk
  const domain = new URL(url).hostname;
  
  const reportScan = {
    url: url,
    domain: domain,
    timestamp: new Date().toISOString(),
    riskLevel: 'high',
    riskScore: 1.0,
    riskFactors: ['User reported as suspicious'],
    reported: true
  };
  
  addToScanHistory(reportScan);
}

// Add domain to whitelist
async function addToWhitelist(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['whitelist'], (data) => {
      const whitelist = data.whitelist || [];
      
      // Add domain if not already in whitelist
      if (!whitelist.includes(domain)) {
        whitelist.push(domain);
        chrome.storage.local.set({ whitelist: whitelist }, () => {
          resolve(true);
        });
      } else {
        resolve(false);
      }
    });
  });
}

// Check if domain is in whitelist
async function isWhitelisted(domain) {
  return new Promise((resolve) => {
    chrome.storage.local.get(['whitelist'], (result) => {
      const whitelist = result.whitelist || [];
      resolve(whitelist.includes(domain));
    });
  });
}

// Remove domain from whitelist
function removeFromWhitelist(domain) {
  chrome.storage.local.get(['whitelist'], (data) => {
    let whitelist = data.whitelist || [];
    
    // Remove domain from whitelist
    whitelist = whitelist.filter(item => item !== domain);
    chrome.storage.local.set({ whitelist: whitelist });
  });
}

// Get scan history
function getScanHistory(sendResponse) {
  chrome.storage.local.get(['scanHistory'], (data) => {
    sendResponse({ scanHistory: data.scanHistory || [] });
  });
}