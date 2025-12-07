# osint-url-scorer
This project intends to add an option to check in-browser URLs against OSINT tools and provide a score to the user. 
A browser extension that provides real-time security scoring for URLs using OSINT (Open Source Intelligence) tools.

## Overview

URL Scorer adds a context menu option to your browser that allows you to quickly check the security reputation of any URL. Right-click on any link and select "Check Security Score" to get an instant assessment of whether the URL is safe, suspicious, or malicious.

## Features

- **Right-click Context Menu Integration** - Check any URL directly from your browser
- **Multi-source OSINT Analysis** - Queries multiple threat intelligence sources
- **Real-time Security Scoring** - Get instant feedback on URL safety (0-100 scale)
- **Detailed Threat Breakdown** - Understand why a URL received its security score

## Architecture

```
┌─────────────────┐
│ Browser Extension│
│   (JavaScript)  │
└────────┬────────┘
         │
         │ HTTPS Request
         │
         ▼
┌─────────────────┐
│  Python Backend │
│   (Flask API)   │
└────────┬────────┘
         │
         │ API Calls
         │
         ▼
┌─────────────────────────────┐
│   OSINT Threat Intel APIs   │
│  • VirusTotal               │
│  • URLhaus                  │
│  • Google Safe Browsing     │
└─────────────────────────────┘
```

## Tech Stack

**Backend:**
- Python 3.8+
- Flask (REST API)
- VirusTotal API
- URLhaus API
- Google Safe Browsing API

**Frontend:**
- Vanilla JavaScript
- Chrome Extension APIs
- HTML/CSS

## Project Status

🚧 **In Development** - Project showcasing cybersecurity automation skills

## Future Enhancements

- Historical URL scanning data
- Bulk URL checking
- Custom threat intelligence source integration
- Machine learning-based scoring improvements
- Export reports functionality

