from sklearn.linear_model import SGDClassifier
import joblib
import os
import random
import re
import numpy as np

def generate_synthetic_data(n_samples=15000):
    X = []
    y = []
    
    # Common phishing keywords and suspicious TLDs
    suspicious_tlds = ['.xyz', '.top', '.bid', '.win', '.icu', '.club', '.info', '.biz', '.gdn', '.tk', '.ml', '.ga', '.cf', '.gq']
    branding = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'github', 'login', 'bank', 'secure']
    shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly']

    for i in range(n_samples):
        # 50/50 split
        is_safe = random.random() > 0.5
        
        if is_safe:
            # Safe URL Characteristics
            # Include "Long Safe URLs" (like the Opera example with marketing tags)
            is_long_safe = random.random() > 0.4
            
            domain_length = random.randint(8, 20)
            path_length = random.randint(50, 250) if is_long_safe else random.randint(0, 30)
            url_length = domain_length + path_length + 8 # + https://
            
            has_https = 1 if random.random() > 0.02 else 0
            num_dots = random.randint(1, 2)
            has_at_symbol = 0
            has_dash = 1 if random.random() > 0.8 else 0
            has_ip = 0
            num_subdomains = 0 if random.random() > 0.2 else 1
            special_chars_count = random.randint(5, 25) if is_long_safe else random.randint(0, 2)
            digit_ratio = random.uniform(0, 0.1)
            
            domain_entropy = random.uniform(3.0, 3.8)
            # Safe paths/queries can have higher entropy if they are long
            path_entropy = random.uniform(4.0, 5.5) if is_long_safe else random.uniform(0, 4.0)
            
            has_sensitive = 0
            is_shortened = 0
            has_branding = 0 
            has_suspicious_tld = 0
            label = 1
        else:
            # Malicious/Phishing Characteristics
            is_complex = random.random() > 0.3
            
            domain_length = random.randint(25, 60) if is_complex else random.randint(10, 25)
            path_length = random.randint(10, 100)
            url_length = domain_length + path_length + 8
            
            has_https = 1 if random.random() > 0.4 else 0
            num_dots = random.randint(2, 6)
            has_at_symbol = 1 if random.random() > 0.8 else 0
            has_dash = 1 if random.random() > 0.4 else 0
            has_ip = 1 if random.random() > 0.9 else 0
            num_subdomains = random.randint(1, 4)
            special_chars_count = random.randint(2, 10)
            digit_ratio = random.uniform(0.1, 0.4)
            
            domain_entropy = random.uniform(4.2, 5.5)
            path_entropy = random.uniform(3.5, 5.0)
            
            has_sensitive = 1 if random.random() > 0.4 else 0
            is_shortened = 1 if random.random() > 0.8 else 0
            has_branding = 1 if random.random() > 0.6 else 0
            has_suspicious_tld = 1 if random.random() > 0.5 else 0
            label = 0
            
        X.append([
            url_length, has_https, num_dots, has_at_symbol, has_dash, has_ip,
            num_subdomains, special_chars_count, digit_ratio, 
            domain_entropy, path_entropy, domain_length, path_length,
            has_sensitive, is_shortened, has_branding, has_suspicious_tld
        ])
        y.append(label)
        
    return np.array(X), np.array(y)

def train_model():
    n_samples = 20000
    print(f"Generating optimized synthetic dataset ({n_samples} samples)...")
    X, y = generate_synthetic_data(n_samples)
    
    print("Training Adaptive SGD model with 17 features...")
    # Using log_loss for probabilistic outputs (predict_proba)
    model = SGDClassifier(loss='log_loss', max_iter=1000, tol=1e-3, random_state=42)
    model.fit(X, y)
    
    score = model.score(X, y)
    print(f"Model Training Accuracy: {score * 100:.2f}%")
    
    model_path = os.path.join(os.path.dirname(__file__), 'model.joblib')
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    train_model()
