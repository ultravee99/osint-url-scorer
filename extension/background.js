// Add "Check Security Score" to right-click menu
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "checkURL",
    title: "Check Security Score",
    contexts: ["link"]
  });
});

// When user clicks the menu item
chrome.contextMenus.onClicked.addListener((info, tab) => {
  const url = info.linkUrl;
  
  // Call your Flask backend
  fetch('http://127.0.0.1:5000/check-url', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url: url})
  })
  .then(response => response.json())
  .then(data => {
    // Determine status
    let status = "SAFE ✅";
    if (data.score < 30) status = "DANGEROUS ⚠️";
    else if (data.score < 70) status = "SUSPICIOUS ⚠️";
    
    // Build detailed message with all sources
    const message = `URL: ${url}

Status: ${status}
Score: ${data.score}/100

━━━━━━━━━━━━━━━━━━━━
VirusTotal:
  Malicious: ${data.virustotal.malicious}
  Suspicious: ${data.virustotal.suspicious}
  Harmless: ${data.virustotal.harmless}
  Total Scans: ${data.virustotal.total_scans}

URLhaus:
  Found in DB: ${data.urlhaus.found ? 'YES ⚠️' : 'No'}
  Threat: ${data.urlhaus.threat_type}

PhishTank:
  Found in DB: ${data.phishtank.found ? 'YES ⚠️' : 'No'}
  Is Phishing: ${data.phishtank.is_phishing ? 'YES ⚠️' : 'No'}
━━━━━━━━━━━━━━━━━━━━`;
    
    // Inject script into the page to show alert
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (msg) => { alert(msg); },
      args: [message]
    });
  })
  .catch(error => {
    // Show error alert
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => { alert('Error: Could not connect to backend. Is Flask running?'); }
    });
  });
});