const BACKEND_URL = 'http://127.0.0.1:8000/api/analyze';
const FRONTEND_URL = 'http://127.0.0.1:8000';

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept main frame navigations (top-level URLs)
    if (details.frameId !== 0) return;
    
    const url = details.url;
    
    // Skip if it's our own analyzer or a chrome internal page
    if (url.startsWith(FRONTEND_URL) || url.startsWith('chrome://') || url.startsWith('about:')) return;

    console.log(`Analyzing: ${url}`);

    try {
        const response = await fetch(BACKEND_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
        });

        if (response.ok) {
            const data = await response.json();
            
            // If the URL is NOT Safe (score < 80)
            if (data.trust_score < 80) {
                console.warn(`Unsafe URL detected (${data.trust_score}%): ${url}`);
                
                // Open our analyzer with the URL as a parameter
                const analyzerUrl = `${FRONTEND_URL}/index.html?url=${encodeURIComponent(url)}`;
                
                chrome.tabs.create({ url: analyzerUrl });
            }
        }
    } catch (error) {
        console.error('Analysis error:', error);
    }
});
