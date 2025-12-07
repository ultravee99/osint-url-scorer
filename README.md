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

## Snapshots

<img width="1002" height="815" alt="image" src="https://github.com/user-attachments/assets/75fc37df-bb22-487a-a5d0-3e70a55ba96d" />
<img width="527" height="284" alt="image" src="https://github.com/user-attachments/assets/b07ba3a1-5e93-48b8-aaae-41c8218999dd" />
<img width="333" height="241" alt="image" src="https://github.com/user-attachments/assets/22c5c31e-c851-4afa-a654-6fde92e10fec" /> <img width="331" height="236" alt="image" src="https://github.com/user-attachments/assets/0c69b805-3e93-4b4f-982a-e972d6afe385" />



## Future Enhancements

- Historical URL scanning data
- Bulk URL checking
- Custom threat intelligence source integration
- Machine learning-based scoring improvements
- Export reports functionality

