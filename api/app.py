import sys
import os
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import traceback
import pickle
import numpy as np
from urllib.parse import urlparse

API_URL = "https://router.huggingface.co/hf-inference/models/google-bert/bert-base-uncased"

headers = {
    "Authorization": f"Bearer {os.getenv('HF_TOKEN')}"
}

app = Flask(__name__)
CORS(app)  # Enable CORS for React Frontend

# --- 1. WHITELIST CONFIGURATION ---
WHITELIST = [
    "google.com", "www.google.com", 
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com",
    "amazon.com", "www.amazon.com",
    "wikipedia.org", "www.wikipedia.org",
    "instagram.com", "www.instagram.com",
    "linkedin.com", "www.linkedin.com",
    "github.com", "www.github.com",
    "microsoft.com", "www.microsoft.com",
    "netflix.com", "www.netflix.com",
    "whatsapp.com", "www.whatsapp.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
    "reddit.com", "www.reddit.com",
    "apple.com", "www.apple.com",
    "paypal.com", "www.paypal.com",
    # Indian popular sites
    "ixigo.com", "www.ixigo.com",
    "makemytrip.com", "www.makemytrip.com",
    "flipkart.com", "www.flipkart.com",
    "myntra.com", "www.myntra.com",
    "swiggy.com", "www.swiggy.com",
    "zomato.com", "www.zomato.com",
    "paytm.com", "www.paytm.com",
    "phonepe.com", "www.phonepe.com",
    "irctc.co.in", "www.irctc.co.in",
    # Indian State Transport Corporations
    "keralartc.com", "www.keralartc.com",
    "ksrtc.in", "www.ksrtc.in",
    "msrtc.gov.in", "www.msrtc.gov.in",
    "tsrtc.in", "www.tsrtc.in",
    "apsrtc.in", "www.apsrtc.in",
]

# --- TRUSTED TLDs (Government, Education, Official) ---
TRUSTED_TLDS = [
    '.gov', '.gov.in', '.gov.uk', '.gov.au', '.gov.ca',
    '.nic.in',
    '.edu', '.edu.in', '.ac.uk', '.edu.au', '.ac.in',
    '.mil',
    '.int',
]

# --- KNOWN BRAND DOMAINS (for typosquatting detection) ---
BRAND_DOMAINS = {
    'paypal': 'paypal.com',
    'google': 'google.com',
    'amazon': 'amazon.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    'facebook': 'facebook.com',
    'netflix': 'netflix.com',
    'instagram': 'instagram.com',
    'linkedin': 'linkedin.com',
    'twitter': 'twitter.com',
    'github': 'github.com'
}

# --- KNOWN PHISHING DOMAINS ---
KNOWN_PHISHING_PATTERNS = [
    'coincoele.com',
    'pay-pal',
    'paypa-l',
    'paypa1',
    'g00gle',
    'go-ogle',
    'amaz0n',
    'micros0ft',
    'app1e',
    'netf1ix',
    'faceb00k',
    '824555.com',
    'goog1e',
    'googIe',
]

# --- 2. LOAD AI MODELS ---
print("⏳ Loading AI Models... Please wait.")
xgb_model = None
try:
    model_path = os.path.join(os.path.dirname(__file__), 'phishing_detector_phiusiil.pkl')
    with open(model_path, 'rb') as f:
        xgb_model = pickle.load(f)
    print(f"✅ XGBoost Model Loaded from {model_path}")
    print(f"✅ BERT API connection ready")
except Exception as e:
    print(f"❌ CRITICAL ERROR: Could not load models. {str(e)}")
    print(traceback.format_exc())
    xgb_model = None

# --- 3. HELPER FUNCTIONS ---

def is_whitelisted(url):
    try:
        parsed_uri = urlparse(url)
        domain = parsed_uri.netloc
        if not domain: 
            domain = url.split('/')[0]
        
        clean_domain = domain.replace('www.', '').lower()
        
        for safe_site in WHITELIST:
            safe_site_clean = safe_site.replace('www.', '').lower()
            if clean_domain == safe_site_clean:
                return True
        
        for safe_site in WHITELIST:
            safe_site_clean = safe_site.replace('www.', '').lower()
            if clean_domain.endswith('.' + safe_site_clean):
                parts = clean_domain.split('.')
                safe_parts = safe_site_clean.split('.')
                if len(parts) > len(safe_parts):
                    if parts[-len(safe_parts):] == safe_parts:
                        return True
        
        for tld in TRUSTED_TLDS:
            if clean_domain.endswith(tld):
                return True
        
        return False
    except:
        return False

def detect_typosquatting(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or url.split('/')[0]
        domain = domain.replace('www.', '').lower()
        
        for safe_site in WHITELIST:
            safe_site_clean = safe_site.replace('www.', '').lower()
            if domain.endswith('.' + safe_site_clean):
                parts = domain.split('.')
                safe_parts = safe_site_clean.split('.')
                if len(parts) > len(safe_parts) and parts[-len(safe_parts):] == safe_parts:
                    return False, None
        
        for pattern in KNOWN_PHISHING_PATTERNS:
            if pattern in domain:
                return True, f"Domain matches known phishing pattern: {pattern}"
        
        for brand, real_domain in BRAND_DOMAINS.items():
            real_domain_base = real_domain.split('.')[0]
            domain_base = domain.replace('.com', '').replace('.net', '').replace('.org', '').replace('.co.uk', '').replace('.in', '')
            
            if domain.endswith('.' + real_domain):
                continue
            
            if brand in domain_base or real_domain_base in domain_base:
                if domain == real_domain or domain == 'www.' + real_domain:
                    continue
                
                suspicious_patterns = [
                    '-' in domain_base,
                    brand.replace('a', '4') in domain_base,
                    brand.replace('o', '0') in domain_base,
                    brand.replace('l', '1') in domain_base,
                    brand.replace('i', '1') in domain_base,
                    brand.replace('e', '3') in domain_base,
                    real_domain_base.replace('o', '0') in domain_base,
                    real_domain_base.replace('l', '1') in domain_base,
                ]
                
                if any(suspicious_patterns):
                    return True, f"Possible typosquatting of {real_domain}"
                
                domain_no_hyphen = domain_base.replace('-', '')
                if '-' in domain_base and len(domain_no_hyphen) >= len(brand):
                    matches = sum(1 for a, b in zip(domain_no_hyphen[:len(brand)], brand) if a == b)
                    similarity = matches / len(brand)
                    if similarity > 0.8:
                        return True, f"Possible typosquatting of {real_domain} (hyphen insertion)"
                
                if domain_base != real_domain_base and (
                    len(domain_base) - len(real_domain_base) <= 3 and 
                    brand in domain_base
                ):
                    return True, f"Possible typosquatting of {real_domain} (character manipulation)"
        
        return False, None
    except:
        return False, None

def unshorten_url(url):
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        response = requests.head(url, allow_redirects=True, timeout=3)
        return response.url
    except:
        return url

def get_bert_embedding(text):
    payload = {"inputs": text}
    try:
        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            timeout=10
        )
        result = response.json()
        embedding = np.array(result)

        if embedding.ndim == 3:
            embedding = embedding[0][0]
        elif embedding.ndim == 2:
            embedding = embedding[0]

        embedding = embedding.reshape(1, -1)

        if embedding.shape[1] != 768:
            print("⚠️ Unexpected embedding shape:", embedding.shape)
            return np.zeros((1, 768))

        return embedding
    except Exception as e:
        print("❌ BERT API error:", e)
        return np.zeros((1, 768))

def extract_url_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or url.split('/')[0]
        
        features['url_length'] = len(url)
        features['domain_length'] = len(domain)
        features['is_trusted_tld'] = any(domain.lower().endswith(tld) for tld in TRUSTED_TLDS)
        features['has_ip'] = any(c.isdigit() for c in domain.replace('.', ''))
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_at'] = url.count('@')
        features['has_https'] = url.startswith('https://')
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.ru', '.xyz', '.top', '.club', '.work', '.pw', '.cc']
        features['suspicious_tld'] = any(url.lower().endswith(tld) for tld in suspicious_tlds)
        features['has_hyphen_in_domain'] = '-' in domain and not domain.startswith('www.')
        features['excessive_subdomains'] = domain.count('.') > 3
        
        suspicious_keywords = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'signin', 'member', 'admin', 'user']
        features['suspicious_keywords'] = any(keyword in url.lower() for keyword in suspicious_keywords)
        
        domain_without_tld = domain.split('.')[0] if '.' in domain else domain
        features['numeric_domain'] = domain_without_tld.replace('-', '').replace('_', '').isdigit()
        features['mostly_numeric_domain'] = sum(c.isdigit() for c in domain_without_tld) > len(domain_without_tld) * 0.7
        
        try:
            parts = domain.split('.')
            if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                features['is_ip_address'] = True
            else:
                features['is_ip_address'] = False
        except:
            features['is_ip_address'] = False
    except:
        features = {k: 0 for k in features.keys()}
    return features

def calculate_phishing_risk_score(url_features, url):
    risk_score = 0
    if url_features.get('is_trusted_tld'):
        return 0
    
    parsed = urlparse(url)
    domain = (parsed.netloc or url.split('/')[0]).replace('www.', '').lower()
    
    for safe_site in WHITELIST:
        safe_site_clean = safe_site.replace('www.', '').lower()
        if domain.endswith('.' + safe_site_clean):
            parts = domain.split('.')
            safe_parts = safe_site_clean.split('.')
            if len(parts) > len(safe_parts) and parts[-len(safe_parts):] == safe_parts:
                return 0
    
    if url_features.get('numeric_domain') or url_features.get('is_ip_address'):
        risk_score += 50
    if url_features.get('mostly_numeric_domain'):
        risk_score += 35
    if url_features.get('suspicious_tld'):
        risk_score += 30
    
    if url_features.get('has_hyphen_in_domain'):
        common_brands = ['google', 'paypal', 'amazon', 'microsoft', 'apple', 'facebook', 
                        'netflix', 'instagram', 'twitter', 'linkedin', 'github', 'yahoo']
        domain_no_hyphen = domain.replace('-', '')
        for brand in common_brands:
            if brand in domain_no_hyphen or domain_no_hyphen.startswith(brand[:4]):
                risk_score += 40
                break
        else:
            risk_score += 25
    
    if not url_features.get('has_https'):
        risk_score += 20
    if url_features.get('num_at') > 0:
        risk_score += 20
    if url_features.get('url_length', 0) > 100:
        risk_score += 15
    if url_features.get('excessive_subdomains'):
        risk_score += 20
    if url_features.get('suspicious_keywords') and url_features.get('has_hyphen_in_domain'):
        risk_score += 25
    
    url_lower = url.lower()
    suspicious_paths = [
        '/scripts/', '/cgi-bin/', '/temp/', '/tmp/', 
        '?redirect=', '?url=', '?continue=', '?next=',
        '/smiles/', '/default.aspx', '/paginas/',
        '/member/', '/admin/', '/user/', '/app/'
    ]
    if any(pattern in url_lower for pattern in suspicious_paths):
        risk_score += 15
    
    suspicious_params = ['uid=', 'user=', 'id=', 'login=', 'pass=', 'password=', 'token=']
    if any(param in url_lower for param in suspicious_params):
        risk_score += 20
    
    if ('?' in url and url.count('/') > 5):
        risk_score += 15
    if ('/pt-br/' in url_lower or '/en-us/' in url_lower) and '/scripts/' in url_lower:
        risk_score += 20
    if any(ext in url_lower for ext in ['.aspx?', '.php?', '.jsp?']):
        risk_score += 15
    if 'guest' in url_lower or 'test' in url_lower:
        risk_score += 15
    
    return min(risk_score, 100)

# --- 4. API ROUTES ---

@app.route('/api/analyze', methods=['POST'])
@app.route('/analyze', methods=['POST'])
def analyze():
    if not xgb_model:
        return jsonify({
            'error': 'AI models are not loaded. Check server logs.',
            'details': 'Make sure phishing_detector_phiusiil.pkl exists.'
        }), 500
        
    try:
        data = request.get_json()
        raw_url = data.get('url', '').strip()

        if not raw_url:
            return jsonify({'error': 'URL is empty'}), 400

        if is_whitelisted(raw_url):
            return jsonify({
                'status': 'Safe', 
                'score': 100.0, 
                'url': raw_url,
                'method': 'Verified Whitelist',
                'confidence': 'Very High',
                'details': 'This domain is on our trusted whitelist.'
            })
        
        is_typosquat, typosquat_msg = detect_typosquatting(raw_url)
        if is_typosquat:
            return jsonify({
                'status': 'Phishing',
                'score': 95.0,
                'url': raw_url,
                'method': 'Typosquatting Detection',
                'confidence': 'Very High',
                'details': f'⚠️ {typosquat_msg}. This appears to be impersonating a legitimate brand.',
                'warnings': ['Domain impersonation detected', 'Typosquatting attempt']
            })
            
        final_url = unshorten_url(raw_url)
        
        if final_url != raw_url and is_whitelisted(final_url):
            return jsonify({
                'status': 'Safe', 
                'score': 100.0, 
                'url': final_url,
                'original_url': raw_url,
                'method': 'Verified Whitelist (After Unshortening)',
                'confidence': 'Very High',
                'details': 'Shortened URL redirects to a trusted domain.'
            })
        
        url_features = extract_url_features(final_url)
        risk_score = calculate_phishing_risk_score(url_features, final_url)
        
        if risk_score >= 50:
            return jsonify({
                'status': 'Phishing',
                'score': float(risk_score),
                'confidence': 'Very High' if risk_score >= 70 else 'High',
                'url': final_url,
                'original_url': raw_url if final_url != raw_url else None,
                'method': 'URL Pattern Analysis + AI',
                'details': '⚠️ This URL exhibits multiple suspicious characteristics indicating a phishing/malware attempt.'
            })
        
        embedding_vector = get_bert_embedding(final_url)

        if embedding_vector.shape[1] != 768:
            raise ValueError(f"Feature shape mismatch, expected 768 got {embedding_vector.shape[1]}")

        probabilities = xgb_model.predict_proba(embedding_vector)[0]
        prediction = xgb_model.predict(embedding_vector)[0]

        is_phishing = prediction == 1
        ai_confidence = float(probabilities[1 if is_phishing else 0] * 100)
        
        has_https = final_url.startswith('https://')
        parsed = urlparse(final_url)
        domain = (parsed.netloc or final_url.split('/')[0]).replace('www.', '').lower()
        
        looks_legitimate = (
            not url_features.get('numeric_domain') and
            not url_features.get('is_ip_address') and
            not url_features.get('suspicious_tld') and
            has_https and
            not url_features.get('has_hyphen_in_domain')
        )
        
        if not is_phishing and risk_score >= 30:
            if looks_legitimate and ai_confidence > 70:
                is_phishing = False
                final_score = ai_confidence
                method = 'BERT + XGBoost AI (High Confidence)'
            else:
                is_phishing = True
                final_score = max(ai_confidence, risk_score, 70)
                method = 'URL Pattern Analysis (AI Override)'
        elif is_phishing and risk_score >= 50:
            final_score = min(95, (ai_confidence + risk_score) / 2 + 10)
            method = 'Combined Analysis (High Confidence)'
        else:
            final_score = ai_confidence
            method = 'BERT + XGBoost AI (PhiUSIIL Dataset)'
        
        if is_phishing:
            status = 'Phishing'
            score = final_score
            confidence = 'Very High' if score > 95 else 'High' if score > 85 else 'Medium'
            details = '⚠️ This URL shows strong indicators of phishing. Proceed with extreme caution!'
        else:
            status = 'Safe'
            score = final_score
            confidence = 'Very High' if score > 95 else 'High' if score > 85 else 'Medium'
            details = '✅ This URL appears to be legitimate based on our analysis.'
        
        response_data = {
            'status': status,
            'score': round(score, 2),
            'confidence': confidence,
            'url': final_url,
            'method': method,
            'details': details,
            'model_accuracy': '98.27%',
            'model': 'BERT Embedding + XGBoost Classifier',
            'dataset': 'PhiUSIIL Dataset (235K URLs)'
        }
        
        if final_url != raw_url:
            response_data['original_url'] = raw_url
            response_data['note'] = 'URL was unshortened for analysis'

        return jsonify(response_data)

    except Exception as e:
        return jsonify({
            'error': f'Analysis failed: {str(e)}',
            'details': 'Please check if the URL format is valid and try again.'
        }), 500

@app.route('/api/batch-analyze', methods=['POST'])
@app.route('/batch-analyze', methods=['POST'])
def batch_analyze():
    if not xgb_model:
        return jsonify({'error': 'AI models are not loaded'}), 500
    
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({'error': 'Please provide a list of URLs'}), 400
        
        if len(urls) > 50:
            return jsonify({'error': 'Maximum 50 URLs per batch request'}), 400
        
        results = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
                
            try:
                if is_whitelisted(url):
                    results.append({
                        'url': url,
                        'status': 'Safe',
                        'score': 100.0,
                        'method': 'Whitelist'
                    })
                    continue
                
                final_url = unshorten_url(url)
                embedding = get_bert_embedding(final_url)
                probabilities = xgb_model.predict_proba(embedding)[0]
                prediction = xgb_model.predict(embedding)[0]
                
                is_phishing = prediction == 1
                status = 'Phishing' if is_phishing else 'Safe'
                score = float(probabilities[1 if is_phishing else 0] * 100)
                
                results.append({
                    'url': url,
                    'status': status,
                    'score': round(score, 2)
                })
            except Exception as e:
                results.append({
                    'url': url,
                    'status': 'Error',
                    'error': str(e)
                })
        
        return jsonify({'results': results, 'total': len(results)})
        
    except Exception as e:
        return jsonify({'error': f'Batch analysis failed: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
@app.route('/health', methods=['GET'])
def health():
    models_loaded = xgb_model is not None
    return jsonify({
        'status': 'healthy' if models_loaded else 'unhealthy',
        'models_loaded': models_loaded,
        'model_accuracy': '98.27%' if models_loaded else 'N/A',
        'dataset': 'PhiUSIIL (235K URLs)',
        'bert_source': 'HuggingFace API'
    })

@app.route('/api', methods=['GET'])
@app.route('/api/', methods=['GET'])
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'PhishX Phishing Detection API',
        'version': '2.0',
        'model': 'BERT + XGBoost',
        'dataset': 'PhiUSIIL Dataset (235K URLs)'
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
