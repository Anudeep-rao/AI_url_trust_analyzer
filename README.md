# AI URL Trust Analyzer

## Project Goal
The **AI URL Trust Analyzer** is an intelligent security tool designed to protect users from malicious websites, phishing attempts, and suspicious links. By analyzing the structure, features, and context of a URL, the system assigns a **Trust Score** (0-100) and categorizes the link into severity levels: SAFE, WARNING, SUSPICIOUS, or DANGEROUS. 

With the inclusion of adaptive machine learning, the model actively listens to user feedback ("Accurate" or "Inaccurate") to continually improve its judgments against new or mutating threats.

---

## Architecture & Working Mechanism

The project consists of three main components communicating with each other:
1. **The Machine Learning Model (Scoring Engine)**
2. **The Backend Server (API & Web Interface)**
3. **The Browser Extension (User Interceptor)**

### Flow of Execution
1. **User acts**: A user visits a page or clicks a link.
2. **Extension intercepts**: The Chrome Extension grabs the URL of the active tab.
3. **API Request**: The extension sends an HTTP POST request to the Backend (`/api/analyze`).
4. **Backend Analysis**:
   - Checks against **Google Safe Browsing API**.
   - Extracts 16 unique statistical and linguistic features from the URL (e.g., domain entropy, length, IP usage).
   - Feeds these features into the **SGDClassifier Machine Learning Model**.
   - Applies **Heuristic Calibrations** (rules) to adjust the score based on known service patterns and adds a small **Organic Jitter** to ensure scores feel dynamic and natural.
5. **Response**: The backend returns the final Trust Score, Status, and detailed Reasons (Positive/Negative).
6. **UI Render**: The Extension or Web Dashboard updates the visual speedometer and displays the reasons clearly to the user.
