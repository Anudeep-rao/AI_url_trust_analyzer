document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loadingState = document.getElementById('loadingState');
    const inputPage = document.getElementById('inputPage');
    const resultsPage = document.getElementById('resultsPage');
    const backBtn = document.getElementById('backBtn');
    const resultsArea = document.getElementById('resultsArea');
    
    // --- UI Enhancements: Mouse Tracking Glow & 3D Tilt ---
    const cursorGlow = document.getElementById('cursorGlow');
    
    document.addEventListener('mousemove', (e) => {
        if (cursorGlow) {
            // Slight delay/smoothness via CSS transition
            cursorGlow.style.left = `${e.clientX}px`;
            cursorGlow.style.top = `${e.clientY}px`;
        }
    });

    document.addEventListener('mousedown', () => cursorGlow?.classList.add('active'));
    document.addEventListener('mouseup', () => cursorGlow?.classList.remove('active'));

    function apply3DTilt(element) {
        if (!element) return;
        element.addEventListener('mousemove', (e) => {
            const rect = element.getBoundingClientRect();
            // Calculate mouse position relative to center of element
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            
            // Limit the tilt angle (max 5 degrees)
            const rotateX = -(y / (rect.height / 2)) * 5;
            const rotateY = (x / (rect.width / 2)) * 5;
            
            element.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
        });

        element.addEventListener('mouseleave', () => {
            element.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg)`;
        });
    }

    // Apply tilt to cards once they are visible
    const scoreCard = document.querySelector('.score-card');
    const detailsCard = document.querySelector('.details-card');
    apply3DTilt(scoreCard);
    apply3DTilt(detailsCard);
    // --- End UI Enhancements ---
    
    // Check for URL parameter (from extension)
    const searchParams = new URLSearchParams(window.location.search);
    const paramUrl = searchParams.get('url');
    if (paramUrl) {
        urlInput.value = decodeURIComponent(paramUrl);
        analyzeUrl();
    }
    
    // UI Elements for Data
    const riskBadge = document.getElementById('riskBadge');
    const scoreTrack = document.getElementById('scoreTrack');
    const speedoNeedleGroup = document.getElementById('speedoNeedleGroup');
    const scoreText = document.getElementById('scoreText');
    const analyzedUrl = document.getElementById('analyzedUrl');
    const positiveList = document.getElementById('positiveList');
    const negativeList = document.getElementById('negativeList');
    
    // Feedback Elements
    const feedbackCorrect = document.getElementById('feedbackCorrect');
    const feedbackIncorrect = document.getElementById('feedbackIncorrect');
    const feedbackThanks = document.getElementById('feedbackThanks');

    // Handle Enter Key
    urlInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            analyzeUrl();
        }
    });

    analyzeBtn.addEventListener('click', analyzeUrl);
    
    backBtn.addEventListener('click', () => {
        // Reset and go back
        resultsPage.classList.add('hidden');
        inputPage.classList.remove('hidden');
        urlInput.value = '';
        urlInput.classList.remove('invalid');
        
        // Reset speedometer needle
        speedoNeedleGroup.style.transform = `rotate(-90deg)`;
        scoreTrack.setAttribute('stroke-dasharray', `0 471.2`);
        scoreTrack.setAttribute('stroke', 'rgba(255,255,255,0.1)');
        scoreText.textContent = '0';
        
        // Reset feedback
        feedbackThanks.classList.add('hidden');
        feedbackCorrect.disabled = false;
        feedbackIncorrect.disabled = false;
    });

    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    async function analyzeUrl() {
        let urlToAnalyze = urlInput.value.trim();
        
        if (!urlToAnalyze) {
            alert('Please enter a URL to analyze.');
            return;
        }

        // Add scheme if missing for more robust validation
        if (!/^https?:\/\//i.test(urlToAnalyze)) {
             urlToAnalyze = 'http://' + urlToAnalyze;
        }

        if (!isValidUrl(urlToAnalyze)) {
            urlInput.classList.add('invalid');
            // Brief animation or red text for invalid format
            const originalPh = urlInput.placeholder;
            urlInput.value = '';
            urlInput.placeholder = 'Invalid URL Format!';
            setTimeout(() => {
                urlInput.placeholder = originalPh;
                urlInput.classList.remove('invalid');
            }, 2000);
            return;
        }
        
        urlInput.classList.remove('invalid');

        // Show Loading
        loadingState.classList.remove('hidden');
        analyzeBtn.disabled = true;

        try {
            // Determine Backend URL based on origin (Works for both Web and Extension)
            let backendHost = 'http://127.0.0.1:8001';
            // Use relative path for web if served from the FastAPI backend directly
            if (window.location.protocol !== 'chrome-extension:' && window.location.port !== '5500') {
                backendHost = ''; 
            }

            // Make Request to FastAPI Backend
            const response = await fetch(`${backendHost}/api/analyze`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ url: urlToAnalyze })
            });

            if (!response.ok) {
                let errorMessage = 'Failed to analyze URL';
                try {
                    const errData = await response.json();
                    errorMessage = errData.detail || errorMessage;
                } catch (e) {
                    errorMessage = `${response.status} ${response.statusText}`;
                }
                throw new Error(errorMessage);
            }

            const data = await response.json();
            
            // Switch view
            inputPage.classList.add('hidden');
            resultsPage.classList.remove('hidden');
            
            updateUI(data);

        } catch (error) {
            console.error("Analysis Error:", error);
            showError(error.message || "An unexpected error occurred. Please check if the backend server is running.");
        } finally {
            loadingState.classList.add('hidden');
            analyzeBtn.disabled = false;
        }
    }

    // Feedback Logic
    feedbackCorrect.addEventListener('click', () => sendFeedback(true));
    feedbackIncorrect.addEventListener('click', () => sendFeedback(false));

    async function sendFeedback(isSafe) {
        const url = analyzedUrl.textContent;
        const backendHost = window.location.protocol !== 'chrome-extension:' && window.location.port !== '5500' ? '' : 'http://127.0.0.1:8000';

        feedbackCorrect.disabled = true;
        feedbackIncorrect.disabled = true;
        feedbackThanks.textContent = 'Re-verifying...';
        feedbackThanks.classList.remove('hidden');

        try {
            const response = await fetch(`${backendHost}/api/feedback`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, is_safe: isSafe })
            });

            if (response.ok) {
                const data = await response.json();
                // Update the UI with the re-verified result
                updateUI(data);
                // Show whether score was changed or confirmed
                feedbackThanks.textContent = data.score_updated
                    ? '✓ Score adjusted after re-verification'
                    : '✓ Score verified as accurate — no change needed';
            } else {
                feedbackThanks.textContent = 'Re-verification failed.';
                feedbackCorrect.disabled = false;
                feedbackIncorrect.disabled = false;
            }
        } catch (error) {
            console.error("Feedback error:", error);
            feedbackThanks.textContent = 'Error during re-verification.';
            feedbackCorrect.disabled = false;
            feedbackIncorrect.disabled = false;
        }
    }

    function updateUI(data) {
        // Update URL Display
        analyzedUrl.textContent = data.url;
        analyzedUrl.title = data.url;

        // Reset Speedometer immediately
        speedoNeedleGroup.style.transform = `rotate(-90deg)`;
        scoreTrack.setAttribute('stroke-dasharray', `0 471.2`);
        
        // Force reflow
        void speedoNeedleGroup.offsetWidth;

        const score = data.trust_score; // 0 to 100
        const scoreValGroup = document.querySelector('.score-value-group');
        
        // Arc calculation for semi-circle (Radius 150)
        // Circumference = 2 * PI * 150 = 942.4
        // Semi-circle length = 471.2
        const dashLength = (score / 100) * 471.2;
        
        // Map Score to Color & Status (User Specified Thresholds)
        let colorHex = '#ef4444'; // Dangerous (<30)
        let statusClass = 'dangerous';
        
        if (score >= 80) {
            colorHex = '#38bdf8'; // Safe (Sky Blue)
            statusClass = 'safe';
        } else if (score >= 50) {
            colorHex = '#eab308'; // Warning (50-80)
            statusClass = 'warning';
        } else if (score >= 30) {
            colorHex = '#f97316'; // Suspicious (30-50)
            statusClass = 'suspicious';
        }
        
        // Trigger Animation
        setTimeout(() => {
            scoreTrack.setAttribute('stroke-dasharray', `${dashLength} 471.2`);
            
            // Needle rotation
            const rotation = -90 + (score / 100) * 180;
            speedoNeedleGroup.style.transform = `rotate(${rotation}deg)`;
            
            // Explicitly set stroke color
            scoreTrack.setAttribute('stroke', colorHex);
            
            // Sync Digital Value Color
            if (scoreValGroup) {
                scoreValGroup.style.color = colorHex;
            }
        }, 100);
        
        // Animate numbers
        animateValue(scoreText, 0, score, 2500);

        // Update Badge
        riskBadge.textContent = data.status;
        riskBadge.className = `badge ${statusClass}`;
        riskBadge.style.color = colorHex;
        riskBadge.style.borderColor = colorHex;
        riskBadge.style.boxShadow = `0 0 15px ${colorHex}44`;

        // Populate Reasons
        populateList(positiveList, data.features.positive, true);
        populateList(negativeList, data.features.negative, false);
    }

    function populateList(listElement, items, isPositive) {
        listElement.innerHTML = ''; // Clear previous

        if (!items || items.length === 0) {
            listElement.innerHTML = `<li><span style="opacity:0.5;">None identified</span></li>`;
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
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }

    function showError(message) {
        // You could implement a more sophisticated toast or modal here
        // For now, let's use a simple alert and log it
        alert(`Error: ${message}`);
        
        // Also show it in the UI if possible
        const urlError = document.getElementById('urlError');
        if (urlError) {
            urlError.textContent = message;
            urlError.classList.remove('hidden');
            setTimeout(() => {
                urlError.classList.add('hidden');
            }, 5000);
        }
    }
});
