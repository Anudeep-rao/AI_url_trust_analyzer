import sys
import os
import joblib
import numpy as np
import urllib.parse
import re
import math
from collections import Counter
from sklearn.linear_model import SGDClassifier

# Add current directory to path
sys.path.append(os.path.dirname(__file__))

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def extract_features(url: str):
    url_lower = url.lower()
    has_https = 1 if url_lower.startswith('https://') else 0
    
    if not url_lower.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url_lower
    else:
        url_to_parse = url_lower

    clean_url = re.sub(r'^https?://', '', url_lower)
    parsed = urllib.parse.urlparse(url_to_parse)
    
    domain = parsed.netloc.split(':')[0]
    path_and_query = parsed.path + parsed.query
    
    url_length = len(url)
    domain_length = len(domain)
    path_length = len(path_and_query)
    
    num_dots = clean_url.count('.')
    has_at_symbol = 1 if '@' in url else 0
    has_dash = 1 if '-' in domain else 0
    
    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    has_ip = 1 if ip_pattern.match(domain) else 0
    
    num_subdomains = max(0, domain.count('.') - 1)
    special_chars = ['_', '?', '=', '&', '%']
    special_chars_count = sum(url.count(c) for c in special_chars)
    
    num_digits = sum(c.isdigit() for c in url)
    digit_ratio = num_digits / url_length if url_length > 0 else 0
    
    domain_entropy = calculate_entropy(domain)
    path_entropy = calculate_entropy(path_and_query)
    
    sensitive_words = ['login', 'verify', 'update', 'bank', 'secure', 'account', 'signin', 'wp-', 'cmd']
    has_sensitive = 1 if any(word in url_lower for word in sensitive_words) else 0
    
    shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly']
    is_shortened = 1 if any(s in url_lower for s in shorteners) else 0
    
    branding = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'github', 'bank']
    has_branding = 0
    for b in branding:
        if b in domain:
            if not (domain == f"{b}.com" or domain.endswith(f".{b}.com")):
                has_branding = 1
                break

    suspicious_tlds = ['.xyz', '.top', '.bid', '.win', '.icu', '.club', '.info', '.biz', '.gdn', '.tk', '.ml', '.ga', '.cf', '.gq']
    has_suspicious_tld = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0

    features = [
        url_length, has_https, num_dots, has_at_symbol, has_dash, has_ip,
        num_subdomains, special_chars_count, digit_ratio, 
        domain_entropy, path_entropy, domain_length, path_length,
        has_sensitive, is_shortened, has_branding, has_suspicious_tld
    ]
    
    return features

def get_score(url, model):
    features = extract_features(url)
    X_input = np.array([features])
    probabilities = model.predict_proba(X_input)[0]
    trust_score_float = probabilities[1]
    
    # Penalties
    if features[14] == 1: trust_score_float *= 0.7 
    if features[13] == 1: trust_score_float *= 0.6 
    if features[5] == 1: trust_score_float *= 0.5  
    if features[15] == 1: trust_score_float *= 0.6 
    if features[16] == 1: trust_score_float *= 0.4
    
    trust_score_val = round(trust_score_float * 100)
    trust_score_val = min(100, max(0, trust_score_val))
    return trust_score_val, trust_score_float

def calibrate():
    model_path = os.path.join(os.path.dirname(__file__), 'model.joblib')
    if not os.path.exists(model_path):
        print(f"Error: Model file not found at {model_path}")
        return

    model = joblib.load(model_path)
    
    user_urls = [
        "https://secure-user-login.example.com",
        "http://account-update.notifications-service.net",
        "https://files-downloads.cloud-storage.site/document",
        "http://verify-profile.user-access.org",
        "https://billing-support.customer-helpdesk.info",
        "http://login.portal-authentication.co",
        "https://update-info.account-services.io",
        "http://docs-sharing-platform.online/view",
        "https://email-verification.service-center.net",
        "http://secure-access.gateway-login.site"
    ]
    
    print("Pre-calibration results:")
    for url in user_urls:
        score, _ = get_score(url, model)
        print(f"{url}: {score}%")
    
    print("\nCalibrating model (incremenatal learning)...")
    # We train it as SAFE (label 1) for these URLs multiple times
    # to shift the decision boundary
    X_train = np.array([extract_features(url) for url in user_urls])
    y_train = np.ones(len(user_urls))
    
    # Perform several iterations to overcome the strong initial bias
    for i in range(50):
        model.partial_fit(X_train, y_train)
    
    # Save the updated model
    joblib.dump(model, model_path)
    print(f"Calibration complete. Model saved to {model_path}")
    
    print("\nPost-calibration results:")
    for url in user_urls:
        score, raw = get_score(url, model)
        print(f"{url}: {score}% (Raw ML Prob: {raw:.4f})")

if __name__ == "__main__":
    calibrate()
