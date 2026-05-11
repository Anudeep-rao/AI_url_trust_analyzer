import requests
import json
test_urls = [
    'http://random-test-domain.xyz/login',
    'https://secure-login-update.verify-account-data.top/cmd',
    'http://192.168.1.1/update',
    'https://short-url.bit.ly/1234',
    'http://very-long-domain-name-that-is-suspicious.com/test',
    'https://paypal-update.example.com/verify',
    'http://microsoft-login.xyz/signin',
    'https://a.b.c.d.e.com/'
]
out = []
for url in test_urls:
    try:
        res = requests.post('http://127.0.0.1:8000/api/analyze', json={'url': url}).json()
        analyze_score = res.get('trust_score')
        is_safe = res.get('status') == 'DANGEROUS' or res.get('status') == 'SUSPICIOUS'
        feed_res = requests.post('http://127.0.0.1:8000/api/feedback', json={'url': url, 'is_safe': is_safe}).json()
        if feed_res.get('score_updated'):
            out.append({'url': url, 'old': analyze_score, 'new': feed_res.get('trust_score')})
    except Exception as e: pass

with open('test_results.json', 'w') as f:
    json.dump(out, f, indent=2)
