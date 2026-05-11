import requests

urls_to_test = [
    'https://example.com/test1',
    'http://example.org/test2',
    'https://new-website.site/home',
    'http://secure-payment-gateway.info/pay',
    'https://login-verification-portal.net/auth',
    'http://unknown-server.xyz/app',
    'https://portal.my-school-network.edu/login',
    'http://123.45.67.89/admin',
    'https://test-blog-platform.net/article',
    'http://short.ly/1x2y3z',
    'https://brandd-name-login.com/login',
    'http://app-update-center.org/download'
]

with open('utf8_results2.txt', 'w', encoding='utf-8') as f:
    for url in urls_to_test:
        res = requests.post('http://127.0.0.1:8000/api/analyze', json={'url': url}).json()
        start_score = res.get('trust_score')
        status = res.get('status')
        # Simulate clicking inaccurate
        is_safe = status in ('DANGEROUS', 'SUSPICIOUS') 
        feed_res = requests.post('http://127.0.0.1:8000/api/feedback', json={'url': url, 'is_safe': is_safe}).json()
        new_score = feed_res.get('trust_score')
        
        diff = abs(start_score - new_score)
        if 0 < diff <= 30:
            f.write(f'SLIGHT CHANGE: {url} ({start_score} -> {new_score})\n')
        elif diff > 30:
            f.write(f'LARGE CHANGE: {url} ({start_score} -> {new_score})\n')
