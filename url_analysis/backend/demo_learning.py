import sys
import os
import joblib
import numpy as np
import urllib.parse
import re
import math
import time
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
    return trust_score_val

def demo_learning():
    model_path = os.path.join(os.path.dirname(__file__), 'model.joblib')
    if not os.path.exists(model_path):
        print(f"Error: Model file not found at {model_path}")
        return

    model = joblib.load(model_path)
    
    target_url = "http://random-test-xyz-99.icu"
    print(f"URL: {target_url}")
    
    # Analyze initially
    initial_score = get_score(target_url, model)
    print(f"Initial Trust Score: {initial_score}%")
    
    # Simulate "Inaccurate" user feedback
    print("\nSimulating feedback: User marks this URL as MALICIOUS (label 0)...")
    time.sleep(1)
    
    # Partial fit with label 0 (Malicious)
    features = extract_features(target_url)
    X_input = np.array([features])
    y_input = np.array([0])
    
    # Perform more iterations to show a clear shift
    for i in range(100):
        model.partial_fit(X_input, y_input)
    
    # Save the updated model
    joblib.dump(model, model_path)
    print("Model updated through incremental learning!")
    
    # Re-analyze
    # Re-load to ensure we are using the saved state
    model = joblib.load(model_path)
    new_score = get_score(target_url, model)
    print(f"Updated Trust Score: {new_score}%")
    
    if new_score < initial_score:
        print("\nSUCCESS: The model has learned and now trusts this URL less!")
    else:
        print("\nNOTE: The score shift might be subtle. Try multiple feedback cycles.")

if __name__ == "__main__":
    demo_learning()
