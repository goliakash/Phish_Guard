// DOM elements
const urlAnalysisCheckbox = document.getElementById('urlAnalysis');
const contentAnalysisCheckbox = document.getElementById('contentAnalysis');
const brandProtectionCheckbox = document.getElementById('brandProtection');
const realTimeAlertsCheckbox = document.getElementById('realTimeAlerts');
const whitelistItems = document.getElementById('whitelist-items');
const whitelistInput = document.getElementById('whitelist-input');
const addWhitelistBtn = document.getElementById('add-whitelist-btn');
const scanHistoryItems = document.getElementById('scan-history-items');
const saveBtn = document.getElementById('save-btn');
const resetBtn = document.getElementById('reset-btn');

// Load settings when options page is opened
document.addEventListener('DOMContentLoaded', loadSettings);

// Load settings from storage
async function loadSettings() {
  chrome.storage.local.get(['enabledFeatures', 'whitelist', 'scanHistory'], (data) => {
    // Set feature checkboxes
    const features = data.enabledFeatures || {
      urlAnalysis: true,
      contentAnalysis: true,
      brandProtection: true,
      realTimeAlerts: true
    };
    
    urlAnalysisCheckbox.checked = features.urlAnalysis;
    contentAnalysisCheckbox.checked = features.contentAnalysis;
    brandProtectionCheckbox.checked = features.brandProtection;
    realTimeAlertsCheckbox.checked = features.realTimeAlerts;
    
    // Load whitelist
    const whitelist = data.whitelist || [];
    renderWhitelist(whitelist);
    
    // Load scan history
    const scanHistory = data.scanHistory || [];
    renderScanHistory(scanHistory);
  });
}

// Render whitelist items
function renderWhitelist(whitelist) {
  whitelistItems.innerHTML = '';
  
  if (whitelist.length === 0) {
    const emptyItem = document.createElement('li');
    emptyItem.textContent = 'No domains in whitelist';
    emptyItem.style.color = '#999';
    whitelistItems.appendChild(emptyItem);
    return;
  }
  
  whitelist.forEach(domain => {
    const item = document.createElement('li');
    
    const domainText = document.createElement('span');
    domainText.textContent = domain;
    
    const removeButton = document.createElement('button');
    removeButton.textContent = 'Remove';
    removeButton.className = 'remove-whitelist';
    removeButton.addEventListener('click', () => removeFromWhitelist(domain));
    
    item.appendChild(domainText);
    item.appendChild(removeButton);
    whitelistItems.appendChild(item);
  });
}

// Render scan history
function renderScanHistory(scanHistory) {
  scanHistoryItems.innerHTML = '';
  
  if (scanHistory.length === 0) {
    const emptyRow = document.createElement('tr');
    const emptyCell = document.createElement('td');
    emptyCell.textContent = 'No scan history';
    emptyCell.colSpan = 3;
    emptyCell.style.textAlign = 'center';
    emptyCell.style.color = '#999';
    emptyRow.appendChild(emptyCell);
    scanHistoryItems.appendChild(emptyRow);
    return;
  }
  
  // Show only the 10 most recent scans
  scanHistory.slice(0, 10).forEach(scan => {
    const row = document.createElement('tr');
    
    const domainCell = document.createElement('td');
    domainCell.textContent = scan.domain;
    
    const riskCell = document.createElement('td');
    riskCell.textContent = capitalizeFirstLetter(scan.riskLevel);
    riskCell.className = `risk-${scan.riskLevel}`;
    
    const dateCell = document.createElement('td');
    dateCell.textContent = formatDate(scan.timestamp);
    
    row.appendChild(domainCell);
    row.appendChild(riskCell);
    row.appendChild(dateCell);
    scanHistoryItems.appendChild(row);
  });
}

// Add domain to whitelist
function addToWhitelist() {
  const domain = whitelistInput.value.trim();
  
  if (!domain) {
    alert('Please enter a valid domain');
    return;
  }
  
  // Simple domain validation
  if (!isValidDomain(domain)) {
    alert('Please enter a valid domain (e.g., example.com)');
    return;
  }
  
  chrome.storage.local.get(['whitelist'], (data) => {
    const whitelist = data.whitelist || [];
    
    // Check if domain is already in whitelist
    if (whitelist.includes(domain)) {
      alert('This domain is already in the whitelist');
      return;
    }
    
    // Add domain to whitelist
    whitelist.push(domain);
    chrome.storage.local.set({ whitelist: whitelist }, () => {
      renderWhitelist(whitelist);
      whitelistInput.value = '';
    });
  });
}

// Remove domain from whitelist
function removeFromWhitelist(domain) {
  chrome.storage.local.get(['whitelist'], (data) => {
    let whitelist = data.whitelist || [];
    
    // Remove domain from whitelist
    whitelist = whitelist.filter(item => item !== domain);
    chrome.storage.local.set({ whitelist: whitelist }, () => {
      renderWhitelist(whitelist);
    });
  });
}

// Save settings
function saveSettings() {
  const enabledFeatures = {
    urlAnalysis: urlAnalysisCheckbox.checked,
    contentAnalysis: contentAnalysisCheckbox.checked,
    brandProtection: brandProtectionCheckbox.checked,
    realTimeAlerts: realTimeAlertsCheckbox.checked
  };
  
  chrome.storage.local.set({ enabledFeatures: enabledFeatures }, () => {
    // Show save confirmation
    const saveBtn = document.getElementById('save-btn');
    const originalText = saveBtn.textContent;
    saveBtn.textContent = 'Settings Saved!';
    saveBtn.disabled = true;
    
    setTimeout(() => {
      saveBtn.textContent = originalText;
      saveBtn.disabled = false;
    }, 2000);
  });
}

// Reset settings to default
function resetSettings() {
  if (confirm('Reset all settings to default?')) {
    const defaultSettings = {
      enabledFeatures: {
        urlAnalysis: true,
        contentAnalysis: true,
        brandProtection: true,
        realTimeAlerts: true
      },
      whitelist: []
    };
    
    chrome.storage.local.set(defaultSettings, () => {
      loadSettings();
      
      // Show reset confirmation
      const resetBtn = document.getElementById('reset-btn');
      const originalText = resetBtn.textContent;
      resetBtn.textContent = 'Settings Reset!';
      resetBtn.disabled = true;
      
      setTimeout(() => {
        resetBtn.textContent = originalText;
        resetBtn.disabled = false;
      }, 2000);
    });
  }
}

// Helper function to validate domain
function isValidDomain(domain) {
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

// Helper function to format date
function formatDate(timestamp) {
  const date = new Date(timestamp);
  return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Helper function to capitalize first letter
function capitalizeFirstLetter(string) {
  return string.charAt(0).toUpperCase() + string.slice(1);
}

// Event listeners
addWhitelistBtn.addEventListener('click', addToWhitelist);
whitelistInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') {
    addToWhitelist();
  }
});
saveBtn.addEventListener('click', saveSettings);
resetBtn.addEventListener('click', resetSettings);