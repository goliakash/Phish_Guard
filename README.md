# Phish_Guard
# 🛡️ Spot the Fake: AI Fraud Detector

Spot the Fake is a browser extension that helps protect users against **fraudulent websites, phishing, and scams**.  
It uses AI-powered analysis and real-time webpage inspection to warn users before they fall victim to online fraud.

---

## 🚀 Features
- **AI-Powered Detection** – analyzes web content for phishing or scam indicators.
- **Real-Time Warnings** – alerts users when visiting suspicious websites.
- **Browser Integration** – works directly in Chrome/Edge/Firefox.
- **Popup Dashboard** – quick status checks and information.
- **Options Page** – customize detection preferences.
- **Lightweight** – built with JavaScript, HTML, and CSS.

---

## 📂 Project Structure
├── images/ # Extension icons
│ ├── icon16.png/.svg
│ ├── icon48.png/.svg
│ ├── icon128.png/.svg
├── background.js # Background service worker (event handling)
├── content.js # Content script injected into pages
├── manifest.json # Extension configuration (Manifest v3)
├── options.html/.css/.js # Options page
├── popup.html/.css/.js # Popup UI


---

## 🛠️ How It Works
- **Content Script (`content.js`)**  
  Runs in the context of each webpage. It scans page elements (URLs, forms, text) for suspicious patterns and reports back.

- **Background Script (`background.js`)**  
  Acts as the extension’s brain. It receives signals from content scripts, runs detection logic, and triggers alerts/notifications.

- **Popup (`popup.html`)**  
  Provides a simple interface to view detection results and interact with the extension.

- **Options Page**  
  Lets users configure settings such as sensitivity, whitelist/blacklist, and detection preferences.

---

## 📦 Installation (Developer Mode)
1. Download or clone this repository:
   ```bash
   https://github.com/goliakash/Phish_Guard.git
  
