import requests
import random
import string

def gen_url():
    tlds = ['.com', '.net', '.org', '.info', '.biz', '.xyz']
    words = ['secure', 'login', 'update', 'verify', 'account', 'service', 'app', 'portal', 'test', 'demo']
    domain = '-'.join(random.sample(words, 2)) + random.choice(tlds)
    return f"https://{domain}/{random.choice(words)}"

urls_to_test = [gen_url() for _ in range(100)]
found = []

for url in urls_to_test:
    try:
        res = requests.post('http://127.0.0.1:8000/api/analyze', json={'url': url}).json()
        start_score = res.get('trust_score')
        status = res.get('status')
        # Simulate clicking inaccurate
        is_safe = status in ('DANGEROUS', 'SUSPICIOUS')
        feed_res = requests.post('http://127.0.0.1:8000/api/feedback', json={'url': url, 'is_safe': is_safe}).json()
        new_score = feed_res.get('trust_score')
        
        diff = abs(start_score - new_score)
        if 0 < diff <= 25:
            found.append(f'{url} (Changed from {start_score} to {new_score})')
    except Exception:
        pass

with open('utf8_results3.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(found))
