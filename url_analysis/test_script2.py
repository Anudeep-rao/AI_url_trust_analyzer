import requests
import json

def test_url(url, is_safe):
    try:
        res = requests.post('http://127.0.0.1:8000/api/analyze', json={'url': url}).json()
        analyze_score = res.get('trust_score')
        feed_res = requests.post('http://127.0.0.1:8000/api/feedback', json={'url': url, 'is_safe': is_safe}).json()
        return {'url': url, 'old': analyze_score, 'new': feed_res.get('trust_score'), 'updated': feed_res.get('score_updated')}
    except Exception as e:
        return {'url': url, 'error': str(e)}

results = [
    test_url('http://suspicious-login-page.xyz/auth', True),
    test_url('https://google.com/test', False),
    test_url('https://unknown-service-provider.net/home', True),
    test_url('http://random-test-domain.xyz/login', True),
    test_url('https://short-url.bit.ly/1234', True),
    test_url('http://very-long-domain-name-that-is-suspicious.com/test', True),
    test_url('https://paypal-update.example.com/verify', True),
    test_url('https://a.b.c.d.e.com/', False)
]

with open('out2.json', 'w') as f:
    json.dump(results, f, indent=2)
