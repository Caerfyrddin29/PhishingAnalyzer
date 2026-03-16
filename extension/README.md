# PhishAnalyzer Browser Extension

## Installation

### Chrome/Edge
1. Open browser and navigate to `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select the `extension` folder from PhishAnalyzer project
5. Extension will appear in toolbar

### Firefox
1. Open browser and navigate to `about:debugging`
2. Click "This Firefox"
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file from the extension folder

## Features

### 🛡️ Real-time Protection
- **Automatic analysis** of current tab
- **Warning overlays** for dangerous sites
- **Badge indicators** showing site safety
- **Context menu** integration

### 📊 Manual Analysis
- **Popup interface** for manual URL checking
- **Recent analyses** history
- **Detailed risk scoring** 0-100
- **ML confidence** percentages

### 🚨 Smart Warnings
- **Red overlay** for phishing sites (>70% risk)
- **Orange alerts** for suspicious sites (40-70% risk)
- **Green indicators** for legitimate sites (<40% risk)
- **User choice** to proceed or leave

### ⚡ Performance
- **5-minute cache** for analyzed URLs
- **Background service** worker
- **Minimal impact** on browsing speed
- **Offline fallback** protection

## Usage

### Automatic Protection
1. Extension analyzes every website you visit
2. Shows badge icon: ✓ (safe), ! (suspicious), ⚠️ (dangerous)
3. Blocks dangerous sites with warning overlay
4. Right-click any link for "Analyze with PhishAnalyzer"

### Manual Analysis
1. Click extension icon in toolbar
2. See current tab analysis automatically
3. Enter any URL to analyze manually
4. View recent analysis history

### API Integration
- Connects to PhishAnalyzer API at `http://localhost:8000`
- Requires PhishAnalyzer server running
- Falls back gracefully if API unavailable

## Technical Details

### Architecture
```
├── manifest.json          # Extension configuration
├── background.js          # Service worker (background tasks)
├── content.js             # Injected into web pages
├── popup.html             # Extension popup interface
├── popup.js               # Popup logic
└── icons/                 # Extension icons
```

### Permissions
- `activeTab` - Analyze current page
- `storage` - Save analysis history
- `contextMenus` - Right-click menu
- `http://localhost:8000/*` - API access

### Security
- No tracking or data collection
- Local storage only
- HTTPS enforced for API calls
- Minimal permissions requested

## Troubleshooting

### Extension not working
1. Ensure PhishAnalyzer API is running: `python api.py`
2. Check API is accessible: `http://localhost:8000/health`
3. Reload extension in browser
4. Check browser console for errors

### API connection issues
1. Verify server is running on port 8000
2. Check firewall settings
3. Ensure CORS is enabled in API
4. Try refreshing the extension

### Performance issues
1. Clear extension cache: `chrome://extensions/` → Remove → Reinstall
2. Check for conflicting extensions
3. Verify API response times

## Development

### Building icons
Create PNG icons in sizes:
- 16x16px - `icons/icon16.png`
- 48x48px - `icons/icon48.png`
- 128x128px - `icons/icon128.png`

### Testing
1. Load extension in developer mode
2. Test with known phishing URLs
3. Verify API integration
4. Check popup functionality

### Publishing
- Chrome Web Store: Create developer account, upload ZIP
- Firefox Add-ons: Create developer account, submit XPI
- Edge Add-ons: Use Chrome Web Store listing

## Support

For issues with:
- **Extension**: Check browser console, report bugs
- **API**: Verify PhishAnalyzer server status
- **Analysis**: Check ML model and feature extraction
