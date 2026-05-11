document.addEventListener('DOMContentLoaded', async () => {
    const scoreTrack = document.getElementById('scoreTrack');
    const speedoNeedleGroup = document.getElementById('speedoNeedleGroup');
    const scoreText = document.getElementById('scoreText');
    const riskBadge = document.getElementById('riskBadge');
    const analyzedUrl = document.getElementById('analyzedUrl');
    const loadingState = document.getElementById('loadingState');
    const resultsArea = document.getElementById('resultsArea');
    const errorArea = document.getElementById('errorArea');
    const retryBtn = document.getElementById('retryBtn');
    const scoreValGroup = document.querySelector('.score-value-group');
    const positiveList = document.getElementById('positiveList');
    const negativeList = document.getElementById('negativeList');
    const feedbackCorrect = document.getElementById('feedbackCorrect');
    const feedbackIncorrect = document.getElementById('feedbackIncorrect');

    const BACKEND_URL = 'http://127.0.0.1:8000/api/analyze';

    async function analyzeCurrentTab() {
        showLoading(true);
        hideError();

        try {
            // Get current active tab
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            
            if (!tab || !tab.url) {
                throw new Error("Unable to identify current URL.");
            }

            let url = tab.url;
            
            // IF we are viewing our own analyzer page, extract the ACTUAL URL being analyzed
            // so the extension matches the result on the page.
            if (url.includes('127.0.0.1:8000') || url.includes('onrender.com')) {
                try {
                    const urlObj = new URL(url);
                    const targetUrl = urlObj.searchParams.get('url');
                    if (targetUrl) {
                        url = targetUrl;
                    }
                } catch (e) {
                    console.log("Not a parameterized analyzer URL");
                }
            }

            analyzedUrl.textContent = url;

            // Only analyze http/https
            if (!url.startsWith('http')) {
                updateUI({
                    trust_score: 100,
                    status: 'SAFE (Internal)',
                    url: url
                });
                return;
            }

            const response = await fetch(BACKEND_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });

            if (!response.ok) throw new Error("Service Unavailable");

            const data = await response.json();
            updateUI(data);

        } catch (error) {
            console.error("Analysis Error:", error);
            showError(error.message);
        } finally {
            showLoading(false);
        }
    }

    function updateUI(data) {
        const score = data.trust_score;
        
        // Arc calculation (Semi-circle length = 471.2)
        const dashLength = (score / 100) * 471.2;
        
        let colorHex = '#ef4444'; // Dangerous
        let statusClass = 'dangerous';
        
        if (score >= 80) {
            colorHex = '#38bdf8'; // Safe
            statusClass = 'safe';
        } else if (score >= 50) {
            colorHex = '#eab308'; // Warning
            statusClass = 'warning';
        } else if (score >= 30) {
            colorHex = '#f97316'; // Suspicious
            statusClass = 'suspicious';
        }

        // Animate elements
        setTimeout(() => {
            scoreTrack.setAttribute('stroke-dasharray', `${dashLength} 471.2`);
            scoreTrack.setAttribute('stroke', colorHex);
            
            const rotation = -90 + (score / 100) * 180;
            speedoNeedleGroup.style.transform = `rotate(${rotation}deg)`;
            
            if (scoreValGroup) scoreValGroup.style.color = colorHex;
        }, 100);

        animateValue(scoreText, 0, score, 1500);
        
        riskBadge.textContent = data.status || 'IDENTIFIED';
        riskBadge.className = `badge ${statusClass}`;
        riskBadge.style.color = colorHex;
        riskBadge.style.borderColor = colorHex;

        // Populate Reasons
        populateList(positiveList, data.features.positive);
        populateList(negativeList, data.features.negative);
    }

    function populateList(listElement, items) {
        if (!listElement) return;
        listElement.innerHTML = '';
        if (!items || items.length === 0 || (items.length === 1 && items[0] === 'None')) {
            listElement.innerHTML = `<li style="opacity:0.5; list-style:none;">None</li>`;
            return;
        }
        items.forEach(item => {
            const li = document.createElement('li');
            li.textContent = item;
            listElement.appendChild(li);
        });
    }

    function animateValue(obj, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start);
            if (progress < 1) window.requestAnimationFrame(step);
        };
        window.requestAnimationFrame(step);
    }

    function showLoading(show) {
        if (show) {
            loadingState.classList.remove('hidden');
            resultsArea.style.opacity = '0.3';
        } else {
            loadingState.classList.add('hidden');
            resultsArea.style.opacity = '1';
        }
    }

    function showError(msg) {
        errorArea.classList.remove('hidden');
        resultsArea.classList.add('hidden');
        document.getElementById('errorMessage').textContent = msg;
    }

    function hideError() {
        errorArea.classList.add('hidden');
        resultsArea.classList.remove('hidden');
    }

    retryBtn.addEventListener('click', analyzeCurrentTab);

    feedbackCorrect.addEventListener('click', () => sendFeedback(true));
    feedbackIncorrect.addEventListener('click', () => sendFeedback(false));

    async function sendFeedback(isSafe) {
        const url = analyzedUrl.textContent;
        feedbackCorrect.disabled = true;
        feedbackIncorrect.disabled = true;

        // Show re-verifying state
        feedbackCorrect.style.opacity = '0.5';
        feedbackIncorrect.style.opacity = '0.5';

        try {
            const response = await fetch(BACKEND_URL.replace('analyze', 'feedback'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, is_safe: isSafe })
            });

            if (response.ok) {
                const data = await response.json();
                // Update the UI with the re-verified result
                updateUI(data);
                // Visual indication of result
                if (data.score_updated) {
                    feedbackIncorrect.style.color = 'var(--danger)';
                    feedbackIncorrect.textContent = '↻ Updated';
                } else {
                    feedbackCorrect.style.color = 'var(--success)';
                    feedbackCorrect.textContent = '✓ Verified';
                }
            }
        } catch (e) {
            console.error(e);
            feedbackCorrect.disabled = false;
            feedbackIncorrect.disabled = false;
            feedbackCorrect.style.opacity = '1';
            feedbackIncorrect.style.opacity = '1';
        }
    }

    // Initial analysis
    analyzeCurrentTab();
});
