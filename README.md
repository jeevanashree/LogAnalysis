Project Overview

This project is an AI-assisted Security Operations Center (SOC) Assistant designed to analyze authentication logs, detect malicious activities, and present structured, explainable threat intelligence to security analysts.

The system combines rule-based security detection with machine learning–based anomaly detection to identify both known and unknown attack patterns. It emphasizes clarity, explainability, and human-in-the-loop decision making, mirroring real-world SOC and SOAR platforms.

🎯 Key Objectives

Detect malicious authentication behaviors from logs

Classify and prioritize threats based on severity

Provide structured explanations (Who, What, Why)

Recommend mitigation actions to analysts

Present findings in a clean, analyst-friendly dashboard

🧠 System Architecture


Authentication Logs (CSV)
        ↓
Preprocessing Layer
        ↓
Detection Engine
  ├── Brute Force Detection
  ├── Credential Stuffing Detection
  ├── Privileged Account Targeting
  ├── IP Scanning / Reconnaissance
  └── ML-based Anomaly Detection
        ↓
AI Reasoning Agent
        ↓
Streamlit Analyst Dashboard




🔍 Attack Types Detected
1️⃣ Brute Force Login Attacks

Multiple failed login attempts from the same IP

Detected using ML-assisted outlier detection

2️⃣ Credential Stuffing

Single IP attempting logins across many usernames

Indicates use of leaked credentials

3️⃣ Privileged Account Targeting

Repeated failed attempts on admin or root accounts

High-severity security risk

4️⃣ IP Scanning / Reconnaissance

One IP probing multiple user accounts

Often a precursor to larger attacks

5️⃣ Anomalous Login Behavior (AI)

Uses Isolation Forest (unsupervised ML)

Detects deviations from normal authentication patterns

Identifies unknown or zero-day behaviors

🤖 AI Component Explanation

This project uses a hybrid AI approach:

Symbolic / Rule-Based AI

Deterministic, explainable detection rules

Preferred for security-critical decisions

Machine Learning (Unsupervised)

Isolation Forest for anomaly detection

No labeled data required

Identifies abnormal behavior patterns

AI Reasoning Agent

Assigns severity (LOW → CRITICAL)

Generates human-readable AI summaries

Suggests remediation actions

This mirrors how real SOC platforms balance trust, accuracy, and explainability.

🖥️ Dashboard Features

White, clean, professional UI

Threats grouped by category

Structured sections:

AI Insight

What Happened

Who Was Involved

Evidence

Recommended Actions

Designed to reduce analyst cognitive overload

Installation & Setup
1️⃣ Clone the Repository
git clone <your-repo-link>
cd ai-soc-assistant

2️⃣ Install Dependencies
pip install -r requirements.txt

3️⃣ Run the Application
streamlit run app.py

4️⃣ Upload Logs

Upload data/auth_logs.csv or any compatible authentication log file.
