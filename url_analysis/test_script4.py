import requests

urls_to_test = [
    'http://not-a-service.info/page',
    'https://new-domain.com/index',
    'http://128.0.0.1/auth',
    'https://random-blog.net/post'
]

with open('utf8_results.txt', 'w', encoding='utf-8') as f:
    for url in urls_to_test:
        f.write(f'Testing: {url}\n')
        res = requests.post('http://127.0.0.1:8000/api/analyze', json={'url': url}).json()
        start_score = res.get('trust_score')
        
        # Force the score to change by repeatedly saying it's the opposite
        is_safe = start_score < 50
        current_score = start_score
        
        updated_once = False
        for i in range(5):
            feed_res = requests.post('http://127.0.0.1:8000/api/feedback', json={'url': url, 'is_safe': is_safe}).json()
            new_score = feed_res.get('trust_score')
            if feed_res.get('score_updated'):
                updated_once = True
                if new_score != current_score:
                    f.write(f'  Changed! {current_score} -> {new_score}\n')
                    current_score = new_score
        
        if start_score != current_score:
            f.write(f'  Final change: {start_score} -> {current_score}\n')
        elif updated_once:
            f.write('  Score updated internally, but rounding/heuristics kept the integer score the same.\n')
        else:
            f.write('  No internal update triggered (disagreement <= 20).\n')
