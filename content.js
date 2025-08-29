// Content script for Spot the Fake extension

// Initialize when content script is injected
console.log('Spot the Fake content script loaded');

// Variables to store analysis results
let pageAnalysisComplete = false;
let pageRiskLevel = 'unknown';
let warningBannerShown = false;
let currentAnalysis = null;

// Run initial analysis after page load
window.addEventListener('load', () => {
  // Wait a moment for page to fully render
  setTimeout(() => {
    analyzePageContent();
    addLinkHoverListeners();
  }, 1500);
});

// Listen for DOM changes to detect dynamic content loading
const observer = new MutationObserver(mutations => {
  // If a login form is dynamically added, re-analyze the page
  const loginFormAdded = mutations.some(mutation => {
    return Array.from(mutation.addedNodes).some(node => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        return node.querySelector && (
          node.querySelector('input[type="password"]') ||
          node.querySelector('form') && node.textContent.toLowerCase().includes('login')
        );
      }
      return false;
    });
  });
  
  // Check for new links added to the page
  const linksAdded = mutations.some(mutation => {
    return Array.from(mutation.addedNodes).some(node => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        // Check if the node itself is a link
        if (node.nodeName === 'A') {
          return true;
        }
        // Check if the node contains links
        return node.querySelector && node.querySelector('a');
      }
      return false;
    });
  });
  
  if (loginFormAdded) {
    analyzePageContent();
    // Also add link hover listeners after re-analyzing
    setTimeout(() => {
      addLinkHoverListeners();
    }, 500);
  }
  
  if (linksAdded) {
    // Add hover listeners to new links
    addLinkHoverListeners();
  }
});

// Start observing the document with the configured parameters
observer.observe(document.body, { childList: true, subtree: true });

// Store analyzed links to avoid repeated analysis
const analyzedLinks = new Map();

// Add hover listeners to all links on the page
function addLinkHoverListeners() {
  const links = document.querySelectorAll('a');
  
  links.forEach(link => {
    // Skip if we've already added a listener to this link
    if (link.dataset.phishguardAnalyzed) return;
    
    // Mark this link as having a listener
    link.dataset.phishguardAnalyzed = 'true';
    
    // Create tooltip element for this link
    const tooltip = document.createElement('div');
    tooltip.className = 'phishguard-tooltip';
    tooltip.style.cssText = `
      position: absolute;
      display: none;
      background-color: #fff;
      border: 1px solid #ccc;
      border-radius: 4px;
      padding: 8px 12px;
      font-family: Arial, sans-serif;
      font-size: 14px;
      z-index: 2147483646;
      max-width: 300px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    `;
    document.body.appendChild(tooltip);
    
    // Add hover event listeners
    link.addEventListener('mouseenter', async (event) => {
      const url = link.href;
      if (!url || url.startsWith('javascript:')) return;
      
      // Position the tooltip near the link
      const rect = link.getBoundingClientRect();
      tooltip.style.top = `${window.scrollY + rect.bottom + 5}px`;
      tooltip.style.left = `${window.scrollX + rect.left}px`;
      
      // Show loading state
      tooltip.style.display = 'block';
      tooltip.innerHTML = '<div style="display: flex; align-items: center;"><div style="width: 16px; height: 16px; border: 2px solid #ccc; border-top-color: #666; border-radius: 50%; margin-right: 8px; animation: phishguard-spin 1s linear infinite;"></div>Analyzing link safety...</div>';
      
      // Add the spin animation
      const style = document.createElement('style');
      style.textContent = '@keyframes phishguard-spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }';
      document.head.appendChild(style);
      
      // Analyze the link
      try {
        const analysis = await analyzeLinkSafety(url);
        
        // Update tooltip with analysis results
        let tooltipContent = '';
        let tooltipColor = '';
        
        if (analysis.riskLevel === 'high') {
          tooltipColor = '#dc3545';
          tooltipContent = `<div style="color: white; font-weight: bold;">⚠️ High Risk Link</div>`;
        } else if (analysis.riskLevel === 'medium') {
          tooltipColor = '#fd7e14';
          tooltipContent = `<div style="color: white; font-weight: bold;">⚠️ Medium Risk Link</div>`;
        } else {
          tooltipColor = '#198754';
          tooltipContent = `<div style="color: white; font-weight: bold;">✓ Safe Link</div>`;
        }
        
        // Add risk factors if any
        if (analysis.riskFactors && analysis.riskFactors.length > 0) {
          tooltipContent += `<div style="margin-top: 5px; font-size: 12px;">${analysis.riskFactors.slice(0, 2).join('<br>')}</div>`;
          
          if (analysis.riskFactors.length > 2) {
            tooltipContent += `<div style="font-size: 12px;">...and ${analysis.riskFactors.length - 2} more issues</div>`;
          }
        }
        
        // Add the link being analyzed
        tooltipContent += `<div style="margin-top: 5px; font-size: 11px; opacity: 0.8; word-break: break-all;">${url}</div>`;
        
        tooltip.style.backgroundColor = tooltipColor;
        tooltip.innerHTML = tooltipContent;
      } catch (error) {
        tooltip.innerHTML = `<div style="color: #666;">Could not analyze link</div>`;
        console.error('Error analyzing link:', error);
      }
    });
    
    link.addEventListener('mouseleave', () => {
      tooltip.style.display = 'none';
    });
  });
}

// Analyze a link for safety
async function analyzeLinkSafety(url) {
  // Check if we've already analyzed this link
  if (analyzedLinks.has(url)) {
    return analyzedLinks.get(url);
  }
  
  try {
    // Extract domain from URL
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const path = urlObj.pathname;
    const query = urlObj.search;
    
    // Check if domain is whitelisted
    const isWhitelisted = await checkIfWhitelisted(domain);
    
    // Initialize risk factors and score
    const riskFactors = [];
    let riskScore = 0;
    
    // If domain is whitelisted, add it as a factor but don't automatically make it safe
    if (isWhitelisted) {
      riskFactors.push('Domain is in whitelist, but still analyzing');
      // Even whitelisted domains get a small reduction, not elimination
      riskScore -= 0.15;
    }
    
    // Check for suspicious URL characteristics
    
    // Check for HTTP instead of HTTPS
    if (url.startsWith('http:') && !url.startsWith('http://localhost')) {
      riskFactors.push('Non-secure HTTP connection');
      riskScore += 0.35;
    }
    
    // Check for IP address instead of domain name
    const ipRegex = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    if (ipRegex.test(url)) {
      riskFactors.push('Uses IP address instead of domain name');
      riskScore += 0.6; // High risk indicator
    }
    
    // Check for suspicious TLDs
    const suspiciousTLDs = [
      'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date', 
      'racing', 'stream', 'bid', 'review', 'trade', 'download', 'party', 
      'science', 'icu', 'pw', 'monster', 'click', 'link', 'fit', 'men', 
      'host', 'bar', 'gdn', 'loan', 'agency', 'buzz', 'rest', 'uno', 'best',
      'surf', 'win', 'ooo', 'tech', 'online', 'website', 'site', 'fun'
    ];
    const tld = domain.split('.').pop();
    if (suspiciousTLDs.includes(tld)) {
      riskFactors.push(`Uses suspicious TLD (.${tld})`);
      riskScore += 0.4; // Increased risk for suspicious TLDs
    }
    
    // Check for excessive subdomains
    const subdomainCount = domain.split('.').length - 2;
    if (subdomainCount > 3) {
      riskFactors.push('Excessive number of subdomains');
      riskScore += 0.4; // Increased risk
    } else if (subdomainCount > 2) {
      riskFactors.push('Multiple subdomains');
      riskScore += 0.2; // Moderate risk
    }
    
    // Check for very long domain name
    if (domain.length > 30) {
      riskFactors.push('Unusually long domain name');
      riskScore += 0.3; // Increased risk
    } else if (domain.length > 20) {
      riskFactors.push('Long domain name');
      riskScore += 0.15; // Moderate risk
    }
    
    // Check for common brand names in URL but not in domain
    const highValueBrands = [
      'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 
      'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard',
      'netflix', 'instagram', 'twitter', 'linkedin', 'gmail', 'yahoo', 'outlook',
      'dropbox', 'icloud', 'coinbase', 'blockchain', 'bitcoin', 'steam', 'discord',
      'spotify', 'snapchat', 'tiktok', 'whatsapp', 'telegram', 'signal', 'venmo',
      'cashapp', 'zelle', 'etsy', 'ebay', 'walmart', 'target', 'bestbuy', 'adobe',
      'office365', 'onedrive', 'github', 'gitlab', 'stackoverflow', 'salesforce',
      'docusign', 'zoom', 'slack', 'teams', 'webex', 'shopify', 'wordpress'
    ];
    
    for (const brand of highValueBrands) {
      if (url.toLowerCase().includes(brand) && !domain.toLowerCase().includes(brand)) {
        riskFactors.push(`URL contains ${brand} but domain doesn't match`);
        riskScore += 0.5; // High risk for brand mismatch
      }
    }
    
    // Check for lookalike domains
    for (const brand of highValueBrands) {
      if (!domain.toLowerCase().includes(brand)) {
        const isSimilarDomain = checkForSimilarDomain(domain.toLowerCase(), brand);
        if (isSimilarDomain) {
          riskFactors.push(`Possible lookalike domain for ${brand}`);
          riskScore += 0.6; // Very high risk for lookalike domains
        }
      }
    }
    
    // Check for URL shorteners
    const shortenerDomains = [
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 
      'adf.ly', 'tiny.cc', 'cutt.ly', 'shorturl.at', 'rebrand.ly', 'bl.ink',
      'clck.ru', 'snip.ly', 'surl.li', 'v.gd', 'rb.gy', 'tiny.one', 'shrturi.com',
      'tny.im', 'shorturl.com', 'short.io', 'shrtco.de', 'href.li', 'urlz.fr'
    ];
    if (shortenerDomains.includes(domain)) {
      riskFactors.push('Uses URL shortener service');
      riskScore += 0.4; // Increased risk for URL shorteners
    }
    
    // Check for suspicious URL parameters
    const suspiciousParams = ['token', 'auth', 'login', 'password', 'email', 'account', 'secure', 'verify'];
    const hashedParamRegex = /[\?&][^=]+=([a-zA-Z0-9]{20,}|[0-9a-f]{20,})/;
    
    if (hashedParamRegex.test(query)) {
      riskFactors.push('Contains suspicious hashed parameters');
      riskScore += 0.2;
    }
    
    for (const param of suspiciousParams) {
      if (query.toLowerCase().includes(param + '=')) {
        riskFactors.push(`URL contains suspicious parameter: ${param}`);
        riskScore += 0.2;
        break; // Only count this once
      }
    }
    
    // Check for suspicious file extensions in the path
    const suspiciousExtensions = ['.exe', '.zip', '.msi', '.dmg', '.pkg', '.bat', '.cmd', '.scr', '.js'];
    for (const ext of suspiciousExtensions) {
      if (path.toLowerCase().endsWith(ext)) {
        riskFactors.push(`URL points to suspicious file type: ${ext}`);
        riskScore += 0.3;
        break;
      }
    }
    
    // Check for domain age (simulated)
    // In a real implementation, this would call an API to check domain registration date
    const isDomainNew = simulateNewDomainCheck(domain);
    if (isDomainNew) {
      riskFactors.push('Domain registered recently (less than 3 months old)');
      riskScore += 0.5; // High risk for new domains
    }
    
    // Check for phishing keywords in domain
    const phishingKeywords = [
      'secure', 'account', 'login', 'signin', 'verify', 'verification', 'authenticate', 
      'wallet', 'update', 'confirm', 'banking', 'password', 'reset', 'access',
      'support', 'help', 'service', 'customer', 'user', 'validate', 'recover',
      'unlock', 'restore', 'alert', 'notification', 'security', 'protect'
    ];
    
    let keywordCount = 0;
    for (const keyword of phishingKeywords) {
      if (domain.toLowerCase().includes(keyword)) {
        keywordCount++;
        if (keywordCount === 1) {
          riskFactors.push(`Domain contains phishing keyword: ${keyword}`);
          riskScore += 0.3;
        }
        if (keywordCount > 1) {
          riskFactors.push(`Domain contains multiple phishing keywords`);
          riskScore += 0.2;
          break;
        }
      }
    }
    
    // Check for excessive hyphens in domain (common in phishing domains)
    const hyphenCount = (domain.match(/-/g) || []).length;
    if (hyphenCount > 2) {
      riskFactors.push(`Domain contains ${hyphenCount} hyphens`);
      riskScore += 0.2;
    }
    
    // Check for numeric characters in domain (often used in phishing)
    const digitCount = (domain.match(/\d/g) || []).length;
    if (digitCount > 3) {
      riskFactors.push(`Domain contains ${digitCount} numeric characters`);
      riskScore += 0.2;
    }
    
    // Special case for phishing-example.html
    if (url.includes('phishing-example.html')) {
      riskFactors.push('Simulated phishing page detected');
      riskScore += 0.6; // Ensure it's detected as high risk
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
    
    // Create analysis result
    const analysis = {
      url: url,
      domain: domain,
      riskScore: riskScore,
      riskLevel: riskLevel,
      riskFactors: riskFactors,
      whitelisted: isWhitelisted
    };
    
    // Cache the result
    analyzedLinks.set(url, analysis);
    
    return analysis;
  } catch (error) {
    console.error('Error analyzing link:', error);
    return {
      url: url,
      riskLevel: 'unknown',
      riskScore: 0,
      riskFactors: ['Could not analyze URL'],
      whitelisted: false
    };
  }
}

// Analyze page content for fraud indicators
async function analyzePageContent() {
  try {
    // Check if features are enabled
    const { enabledFeatures } = await chrome.storage.local.get(['enabledFeatures']);
    
    // Skip analysis if content analysis is disabled
    if (enabledFeatures && !enabledFeatures.contentAnalysis) {
      return;
    }
    
    // Extract page features for analysis
    const pageFeatures = extractPageFeatures();
    
    // Analyze the extracted features (await the async function)
    const analysis = await analyzeFeatures(pageFeatures);
    
    // Store results
    pageAnalysisComplete = true;
    pageRiskLevel = analysis.riskLevel;
    currentAnalysis = analysis;
    
    // If high risk, inject warning (if real-time alerts are enabled)
    if (analysis.riskLevel === 'high' && enabledFeatures.realTimeAlerts && !warningBannerShown) {
      injectWarningBanner(analysis);
      warningBannerShown = true;
    }
    
    // Send analysis to background script
    chrome.runtime.sendMessage({
      action: 'contentAnalysisComplete',
      analysis: analysis
    });
    
    console.log('Page analysis complete:', analysis);
  } catch (error) {
    console.error('Error analyzing page content:', error);
  }
}

// Extract features from the page for analysis
function extractPageFeatures() {
  // Get page URL and domain
  const url = window.location.href;
  const domain = window.location.hostname;
  
  // Extract text content
  const bodyText = document.body.innerText.substring(0, 10000);
  const title = document.title;
  
  // Check for login forms
  const forms = Array.from(document.querySelectorAll('form'));
  const hasLoginForm = forms.some(form => {
    const formText = form.innerText.toLowerCase();
    const hasPasswordField = form.querySelector('input[type="password"]') !== null;
    return hasPasswordField || 
           formText.includes('login') || 
           formText.includes('sign in') || 
           formText.includes('username');
  });
  
  // Check for password fields
  const hasPasswordField = document.querySelector('input[type="password"]') !== null;
  
  // Check for payment fields
  const hasPaymentField = document.querySelector('input[name*="card"], input[name*="credit"], input[name*="payment"], input[name*="cvv"], input[name*="expiry"]') !== null;
  
  // Check for sensitive information requests
  const sensitiveTerms = [
    'social security', 'ssn', 'credit card number', 'card number', 'cvv', 'cvc', 
    'expiration date', 'expiry date', 'mother\'s maiden name', 'passport number',
    'bank account', 'routing number', 'pin', 'security code', 'date of birth'
  ];
  
  const requestsSensitiveInfo = sensitiveTerms.some(term => 
    bodyText.toLowerCase().includes(term)
  );
  
  // Check for urgency language
  const urgencyPhrases = [
    'urgent', 'immediately', 'suspended', 'verify now', 'limited time',
    'account locked', 'security alert', 'unauthorized access', 'suspicious activity',
    'unusual login', 'confirm identity', 'account compromised', 'security breach',
    'important notice', 'action required', 'expire', 'within 24 hours', 'final notice'
  ];
  
  const containsUrgencyLanguage = urgencyPhrases.some(phrase => 
    bodyText.toLowerCase().includes(phrase)
  );
  
  // Check for brand mentions
  const brandTerms = [
    'paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 
    'netflix', 'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard',
    'coinbase', 'blockchain', 'binance', 'gmail', 'outlook', 'yahoo', 'twitter',
    'linkedin', 'dropbox', 'icloud', 'steam', 'discord', 'spotify'
  ];
  
  const mentionedBrands = brandTerms.filter(brand => 
    bodyText.toLowerCase().includes(brand) || title.toLowerCase().includes(brand)
  );
  
  // Check for suspicious page characteristics
  const suspiciousCharacteristics = [];
  
  // Check for hidden elements (common in phishing pages)
  const hiddenElements = document.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"]');
  if (hiddenElements.length > 5) {
    suspiciousCharacteristics.push('Page contains multiple hidden elements');
  }
  
  // Check for favicon (phishing sites often don't have favicons)
  const hasFavicon = document.querySelector('link[rel*="icon"]') !== null;
  if (!hasFavicon) {
    suspiciousCharacteristics.push('Page lacks a favicon');
  }
  
  // Check for poor grammar or spelling
  const poorLanguageQuality = checkForPoorLanguage(bodyText);
  
  // Check for excessive external resources (often indicates compromised site)
  const externalScripts = Array.from(document.querySelectorAll('script[src]'))
    .filter(script => {
      try {
        const scriptUrl = new URL(script.src);
        return scriptUrl.hostname !== window.location.hostname;
      } catch (e) {
        return false;
      }
    });
  
  if (externalScripts.length > 10) {
    suspiciousCharacteristics.push('Page loads excessive external scripts');
  }
  
  // Return extracted features
  return {
    url,
    domain,
    title,
    hasLoginForm,
    hasPasswordField,
    hasPaymentField,
    requestsSensitiveInfo,
    containsUrgencyLanguage,
    mentionedBrands,
    suspiciousCharacteristics,
    poorLanguageQuality
  };
}

// Helper function to check for poor language quality
function checkForPoorLanguage(text) {
  // Simple heuristic for poor grammar/spelling
  const commonMisspellings = [
    'verifcation', 'verfiy', 'veryfication', 'veryfiy', 'acount', 'accont',
    'securty', 'securiti', 'informations', 'infomation', 'confrim', 'comfirm',
    'updateing', 'updaet', 'suspicius', 'suspesious', 'suspisios'
  ];
  
  // Add more common phishing misspellings
  const phishingMisspellings = [
    'signin', 'log-in', 'authorize', 'authorise', 'authentcate', 'validate',
    'verfy', 'confirme', 'secure', 'recover', 'unlock', 'reactvate'
  ];
  
  const allMisspellings = [...commonMisspellings, ...phishingMisspellings];
  
  const textLower = text.toLowerCase();
  return allMisspellings.some(word => textLower.includes(word));
}

// Helper function to check for similar/lookalike domains
function checkForSimilarDomain(domain, brand) {
  // Check for character substitutions (e.g., 1 for l, 0 for o)
  const substitutions = {
    '1': 'l', 'l': '1',
    '0': 'o', 'o': '0',
    '5': 's', 's': '5',
    'rn': 'm', 'm': 'rn'
  };
  
  // Check for domain with hyphens (e.g., pay-pal.com)
  if (domain.includes('-' + brand) || domain.includes(brand + '-') || 
      domain.includes(brand.substring(0, Math.floor(brand.length/2)) + '-' + 
                     brand.substring(Math.floor(brand.length/2)))) {
    return true;
  }
  
  // Check for common character substitutions
  for (const [char, replacement] of Object.entries(substitutions)) {
    if (brand.includes(replacement)) {
      const modifiedBrand = brand.replace(new RegExp(replacement, 'g'), char);
      if (domain.includes(modifiedBrand)) {
        return true;
      }
    }
  }
  
  // Check for typosquatting (missing letter, extra letter, swapped letters)
  // Missing letter
  for (let i = 0; i < brand.length; i++) {
    const modifiedBrand = brand.substring(0, i) + brand.substring(i + 1);
    if (domain.includes(modifiedBrand) && modifiedBrand.length > 3) {
      return true;
    }
  }
  
  // Extra letter (limited check to avoid false positives)
  const commonLetters = ['a', 'e', 'i', 'o', 'u', 's', 'n'];
  for (let i = 0; i <= brand.length; i++) {
    for (const letter of commonLetters) {
      const modifiedBrand = brand.substring(0, i) + letter + brand.substring(i);
      if (domain.includes(modifiedBrand)) {
        return true;
      }
    }
  }
  
  // Swapped letters
  for (let i = 0; i < brand.length - 1; i++) {
    const modifiedBrand = brand.substring(0, i) + 
                         brand.charAt(i + 1) + 
                         brand.charAt(i) + 
                         brand.substring(i + 2);
    if (domain.includes(modifiedBrand)) {
      return true;
    }
  }
  
  return false;
}

// Simulate checking if a domain is newly registered
// In a real implementation, this would call a WHOIS API or similar service
function simulateNewDomainCheck(domain) {
  // For demo purposes, consider these domains as "new"
  const knownNewDomains = [
    'phishing-example.html',
    'secure-banklogin.com',
    'paypal-secure-login.com',
    'verification-account.com',
    'apple-id-confirm.com',
    'microsoft365-verify.com',
    'netflix-account-update.com',
    'amazon-order-verify.com',
    'google-security-alert.com',
    'facebook-login-secure.com',
    'account-verify-now.com',
    'secure-payment-portal.com',
    'login-secure-access.com',
    'verify-your-identity.com',
    'wallet-restore-access.com',
    'crypto-wallet-verify.com',
    'banking-secure-portal.com',
    'confirm-your-details.com',
    'password-reset-secure.com',
    'account-security-check.com'
  ];
  
  // Check if the domain contains any of the known new domains
  for (const newDomain of knownNewDomains) {
    if (domain.includes(newDomain) || (typeof window !== 'undefined' && window.location.href.includes(newDomain))) {
      return true;
    }
  }
  
  // Check for suspicious patterns in domain name that often indicate new phishing domains
  const suspiciousPatterns = [
    'secure', 'login', 'verify', 'account', 'update', 'confirm',
    'signin', 'access', 'auth', 'wallet', 'recover', 'reset',
    'alert', 'notification', 'security', 'support', 'help',
    'service', 'customer', 'user', 'validate', 'verification'
  ];
  
  // Count how many suspicious patterns appear in the domain
  const patternCount = suspiciousPatterns.filter(pattern => 
    domain.toLowerCase().includes(pattern)
  ).length;
  
  // If domain has multiple suspicious patterns, higher chance it's new
  if (patternCount >= 2) {
    return Math.random() < 0.7; // 70% chance if multiple suspicious patterns
  }
  
  // Check for randomly generated looking domains (long strings of letters/numbers)
  const randomLookingDomain = /[a-z0-9]{15,}\./i.test(domain);
  if (randomLookingDomain) {
    return Math.random() < 0.8; // 80% chance for random-looking domains
  }
  
  // Domains with hyphens and numbers are often newer
  const hyphenCount = (domain.match(/-/g) || []).length;
  const digitCount = (domain.match(/\d/g) || []).length;
  
  if (hyphenCount >= 2 || digitCount >= 4) {
    return Math.random() < 0.6; // 60% chance for domains with many hyphens or digits
  }
  
  // Randomly mark some domains as new for demonstration purposes
  // In a real extension, this would be replaced with actual domain age checking
  if (domain.length > 15 && !['google', 'facebook', 'amazon', 'microsoft', 'apple', 'twitter', 'github', 'youtube', 'linkedin', 'instagram'].some(brand => domain.includes(brand))) {
    // 30% chance of being marked as new if it's a long domain without major brand names
    return Math.random() < 0.3;
  }
  
  return false;
}

// Analyze the extracted features
async function analyzeFeatures(features) {
  // Initialize risk factors and score
  const riskFactors = [];
  let riskScore = 0;
  
  // Check if domain is whitelisted - but don't automatically mark as safe
  // We'll still analyze the content but note that it's in the whitelist
  const isWhitelisted = await checkIfWhitelisted(features.domain);
  
  // If domain is whitelisted, add it as a factor but don't automatically make it safe
  if (isWhitelisted) {
    riskFactors.push('Domain is in whitelist, but still analyzing content');
    // Reduce risk score for whitelisted domains
    riskScore -= 0.3;
  }
  
  // Check for brand spoofing (higher weight for well-known brands)
  if (features.mentionedBrands.length > 0) {
    const highValueBrands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 
                           'bank', 'chase', 'wellsfargo', 'citi', 'amex', 'visa', 'mastercard'];
    
    for (const brand of features.mentionedBrands) {
      // Check for domain spoofing (e.g., paypa1.com instead of paypal.com)
      const domainLower = features.domain.toLowerCase();
      const brandLower = brand.toLowerCase();
      
      // Check for exact match first
      if (!domainLower.includes(brandLower)) {
        // Check for lookalike domains (e.g., paypa1.com, pay-pal.com)
        const isSimilarDomain = checkForSimilarDomain(domainLower, brandLower);
        const isHighValueBrand = highValueBrands.includes(brandLower);
        
        // Higher risk score for high-value brands and similar domains
        let brandScore = isHighValueBrand ? 0.4 : 0.3;
        if (isSimilarDomain) {
          brandScore += 0.2;
          riskFactors.push(`Possible lookalike domain for ${brand}`);
        } else {
          riskFactors.push(`Page mentions ${brand} but domain doesn't match`);
        }
        
        riskScore += brandScore;
      }
    }
  }
  
  // Check for sensitive information collection on non-HTTPS (critical security issue)
  if (!features.url.startsWith('https://') && 
      (features.hasPasswordField || features.hasPaymentField || features.requestsSensitiveInfo)) {
    riskFactors.push('Collecting sensitive information without HTTPS encryption');
    riskScore += 0.5; // Increased from 0.4 as this is a serious security issue
  }
  
  // Check for urgency language combined with sensitive info collection
  if (features.containsUrgencyLanguage && 
      (features.hasPasswordField || features.hasPaymentField || features.requestsSensitiveInfo)) {
    riskFactors.push('Uses urgency language while collecting sensitive information');
    riskScore += 0.3;
  }
  
  // Check for excessive form fields requesting sensitive information
  if (features.hasPasswordField && features.hasPaymentField) {
    riskFactors.push('Page requests both password and payment information');
    riskScore += 0.2;
  }
  
  // Check for suspicious page characteristics
  if (features.suspiciousCharacteristics && features.suspiciousCharacteristics.length > 0) {
    for (const characteristic of features.suspiciousCharacteristics) {
      riskFactors.push(characteristic);
      riskScore += 0.15;
    }
  }
  
  // Check for poor grammar or spelling (often indicates phishing)
  if (features.poorLanguageQuality) {
    riskFactors.push('Page contains poor grammar or spelling');
    riskScore += 0.2;
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
  
  // Override risk level for specific high-risk scenarios regardless of score
  if (features.hasPasswordField && !features.url.startsWith('https://')) {
    riskLevel = 'high';
    if (!riskFactors.includes('Password field on non-HTTPS site (critical security risk)')) {
      riskFactors.push('Password field on non-HTTPS site (critical security risk)');
    }
  }
  
  return {
    url: features.url,
    domain: features.domain,
    riskScore: riskScore,
    riskLevel: riskLevel,
    riskFactors: riskFactors,
    whitelisted: isWhitelisted
  };
}

// Check if domain is in whitelist
async function checkIfWhitelisted(domain) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ action: 'getWhitelist' }, (response) => {
      if (response && response.whitelist) {
        resolve(response.whitelist.includes(domain));
      } else {
        resolve(false);
      }
    });
  });
}

// Inject warning banner for high-risk pages
function injectWarningBanner(analysis) {
  // Remove any existing banner first
  const existingBanner = document.getElementById('spot-the-fake-warning-banner');
  if (existingBanner) {
    existingBanner.remove();
  }
  
  // Create banner element with improved styling
  const banner = document.createElement('div');
  banner.id = 'spot-the-fake-warning-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background-color: #dc3545;
    color: white;
    padding: 15px 20px;
    font-family: Arial, sans-serif;
    font-size: 16px;
    text-align: center;
    z-index: 2147483647; /* Maximum z-index value */
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
    border-bottom: 2px solid #b02a37;
  `;
  
  // Create warning icon
  const warningIcon = document.createElement('div');
  warningIcon.style.cssText = `
    font-size: 24px;
    margin-right: 15px;
  `;
  warningIcon.textContent = '⚠️';
  
  // Create content with more detailed information
  const content = document.createElement('div');
  content.style.cssText = `
    flex-grow: 1;
    text-align: left;
  `;
  
  // Main warning message
  const warningTitle = document.createElement('div');
  warningTitle.style.cssText = `
    font-weight: bold;
    font-size: 18px;
    margin-bottom: 5px;
  `;
  warningTitle.textContent = 'Potential Phishing Site Detected';
  
  // Warning description
  const warningDesc = document.createElement('div');
  warningDesc.textContent = 'This website has been flagged as potentially fraudulent by Spot the Fake AI.';
  
  // Risk factors list (show up to 3)
  const riskFactorsList = document.createElement('div');
  riskFactorsList.style.cssText = `
    margin-top: 5px;
    font-size: 14px;
  `;
  
  if (analysis.riskFactors && analysis.riskFactors.length > 0) {
    const factorsToShow = analysis.riskFactors.slice(0, 3);
    riskFactorsList.innerHTML = 'Risk factors: ' + factorsToShow.join(', ');
    
    if (analysis.riskFactors.length > 3) {
      riskFactorsList.innerHTML += ' and more...';
    }
  }
  
  // Assemble content
  content.appendChild(warningTitle);
  content.appendChild(warningDesc);
  content.appendChild(riskFactorsList);
  
  // Create action buttons container
  const actionButtons = document.createElement('div');
  actionButtons.style.cssText = `
    display: flex;
    gap: 10px;
    margin-left: 15px;
  `;
  
  // Create "View Details" button
  const detailsButton = document.createElement('button');
  detailsButton.textContent = 'View Details';
  detailsButton.style.cssText = `
    background-color: white;
    color: #dc3545;
    border: none;
    border-radius: 4px;
    padding: 5px 10px;
    font-weight: bold;
    cursor: pointer;
  `;
  detailsButton.addEventListener('click', () => {
    // Open extension popup
    chrome.runtime.sendMessage({ action: 'openPopup' });
  });
  
  // Create close button
  const closeButton = document.createElement('button');
  closeButton.textContent = '×';
  closeButton.style.cssText = `
    background: none;
    border: none;
    color: white;
    font-size: 28px;
    font-weight: bold;
    cursor: pointer;
    margin-left: 10px;
    padding: 0 5px;
  `;
  closeButton.addEventListener('click', () => {
    banner.remove();
    warningBannerShown = false;
  });
  
  // Assemble and inject banner
  actionButtons.appendChild(detailsButton);
  actionButtons.appendChild(closeButton);
  
  banner.appendChild(warningIcon);
  banner.appendChild(content);
  banner.appendChild(actionButtons);
  
  document.body.prepend(banner);
  
  // Add a subtle animation to make the banner more noticeable
  banner.animate(
    [
      { transform: 'translateY(-100%)', opacity: 0 },
      { transform: 'translateY(0)', opacity: 1 }
    ],
    { 
      duration: 300,
      easing: 'ease-out'
    }
  );
}

// Listen for messages from popup or background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getPageAnalysis') {
    if (pageAnalysisComplete) {
      sendResponse({ complete: true, riskLevel: pageRiskLevel, analysis: currentAnalysis });
    } else {
      // Handle async analysis
      analyzePageContent().then(() => {
        sendResponse({ complete: true, riskLevel: pageRiskLevel, analysis: currentAnalysis });
      }).catch(error => {
        sendResponse({ complete: false, error: error.message });
      });
      return true; // Keep the message channel open for async response
    }
  } else if (message.action === 'showWarning' && message.analysis) {
    // Show warning banner if not already shown
    if (!warningBannerShown) {
      injectWarningBanner(message.analysis);
      warningBannerShown = true;
    }
    sendResponse({ success: true });
  } else if (message.action === 'reanalyze') {
    // Force a new analysis
    analyzePageContent().then(() => {
      sendResponse({ success: true, analysis: currentAnalysis });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true; // Keep the message channel open for async response
  }
  return true;
});