from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
import base64
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Get API key from environment
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

def check_virustotal(url):
    """Check URL against VirusTotal API"""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(vt_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)
            
            total = malicious + suspicious + harmless + undetected
            
            if total == 0:
                return {'score': 50, 'status': 'unknown'}
            
            threat_count = malicious + (suspicious * 0.5)
            score = max(0, 100 - (threat_count / total * 100))
            
            return {
                'score': round(score, 1),
                'malicious': malicious,
                'suspicious': suspicious,
                'harmless': harmless,
                'total_scans': total,
                'status': 'success'
            }
        else:
            return {'score': 50, 'status': 'not_found'}
    
    except Exception as e:
        return {'score': 50, 'status': 'error', 'message': str(e)}


def check_urlhaus(url):
    """Check URL against URLhaus malware database"""
    try:
        response = requests.post(
            'https://urlhaus-api.abuse.ch/v1/url/',
            data={'url': url},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data['query_status'] == 'ok':
                # URL found in URLhaus - it's malicious
                threat = data.get('threat', 'malware')
                return {
                    'found': True,
                    'threat_type': threat,
                    'status': 'malicious'
                }
            else:
                # URL not in database - likely safe
                return {
                    'found': False,
                    'status': 'clean'
                }
        
        return {'found': False, 'status': 'error'}
    
    except Exception as e:
        return {'found': False, 'status': 'error', 'message': str(e)}


def check_phishtank(url):
    """Check URL against PhishTank database"""
    try:
        # PhishTank API endpoint
        response = requests.post(
            'https://checkurl.phishtank.com/checkurl/',
            data={
                'url': url,
                'format': 'json',
                'app_key': ''  # PhishTank works without key for basic checks
            },
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if 'results' in data and data['results']['in_database']:
                # URL found in PhishTank
                is_valid = data['results']['valid']
                return {
                    'found': True,
                    'is_phishing': is_valid,
                    'status': 'phishing' if is_valid else 'clean'
                }
            else:
                # Not in database
                return {
                    'found': False,
                    'status': 'clean'
                }
        
        return {'found': False, 'status': 'error'}
    
    except Exception as e:
        return {'found': False, 'status': 'error', 'message': str(e)}


def calculate_combined_score(vt_result, urlhaus_result, phishtank_result):
    """
    Combine results from all sources into a single score
    Score: 0-100 (0 = very dangerous, 100 = very safe)
    """
    
    # Start with VirusTotal score
    base_score = vt_result.get('score', 50)
    
    # Heavy penalty if found in URLhaus (malware database)
    if urlhaus_result.get('found') and urlhaus_result.get('status') == 'malicious':
        base_score = min(base_score, 20)  # Cap at 20 if malware detected
    
    # Heavy penalty if PhishTank confirms it's phishing
    if phishtank_result.get('found') and phishtank_result.get('is_phishing'):
        base_score = min(base_score, 15)  # Cap at 15 if phishing confirmed
    
    return round(base_score, 1)


@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Check all three sources
    vt_result = check_virustotal(url)
    urlhaus_result = check_urlhaus(url)
    phishtank_result = check_phishtank(url)
    
    # Calculate combined score
    final_score = calculate_combined_score(vt_result, urlhaus_result, phishtank_result)
    
    # Build response
    response = {
        'url': url,
        'score': final_score,
        'virustotal': {
            'malicious': vt_result.get('malicious', 0),
            'suspicious': vt_result.get('suspicious', 0),
            'harmless': vt_result.get('harmless', 0),
            'total_scans': vt_result.get('total_scans', 0)
        },
        'urlhaus': {
            'found': urlhaus_result.get('found', False),
            'threat_type': urlhaus_result.get('threat_type', 'N/A')
        },
        'phishtank': {
            'found': phishtank_result.get('found', False),
            'is_phishing': phishtank_result.get('is_phishing', False)
        },
        'status': 'success'
    }
    
    return jsonify(response)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'Backend is running with 3 OSINT sources!'})


if __name__ == '__main__':
    app.run(debug=True, port=5000)