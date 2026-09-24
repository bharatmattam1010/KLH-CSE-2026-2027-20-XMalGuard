# XMalGuard: Next-Gen AI-Powered Malware Detection & Threat Intelligence Platform

## 1. Project Overview & Objective
**XMalGuard** is an advanced, AI-driven malware analysis platform designed to detect zero-day threats in Windows executables (PE files). Traditional antivirus engines rely on "signature matching" (looking for known patterns of past malware), which fails against newly created or obfuscated malware. XMalGuard solves this by using **Static Analysis** and **Machine Learning** to evaluate the structural and mathematical properties of a file, alongside **Explainable AI (SHAP)** to transparently show cybersecurity analysts *why* a file is deemed malicious.

---

## 2. System Architecture & Tech Stack
The project is built on a modern, decoupled architecture:
*   **Frontend (User Interface):** React.js, Vite, and Recharts. Provides a highly interactive dashboard with drag-and-drop file upload, batch dataset processing, and interactive SHAP visualization charts.
*   **Backend (API Server):** FastAPI (Python). Chosen for its extreme speed and asynchronous capabilities. It handles file parsing, model inference, and external API requests.
*   **Database:** SQLite using SQLAlchemy (ORM). Stores the history of all analyzed files, their risk scores, and Threat Intelligence data.
*   **Machine Learning Pipeline:** Scikit-Learn, XGBoost / Random Forest.
*   **Explainable AI (XAI):** SHAP (SHapley Additive exPlanations) library (`TreeExplainer`).
*   **Static Analysis Engine:** `pefile` (Python library used to parse Portable Executable headers).

---

## 3. How the Project Analyzes a File (The Pipeline)
When a user uploads a `.exe` or `.dll` file (or an EMBER JSON dataset), the following steps occur in milliseconds:

### Step A: Static Feature Extraction
The backend safely parses the file's headers using `pefile` without ever executing the malware. It extracts exactly **35 numerical features**, such as:
*   **Section Entropy:** Measures how "random" the data is. High entropy (>7.0) strongly indicates the malware is packed or encrypted to hide its code.
*   **Suspicious Imports:** Counts how many dangerous Windows API functions the file tries to load (e.g., functions for injecting code or reading keystrokes).
*   **UPX Signature:** Checks if the file is packed with UPX (a common tool used by malware authors to compress their payload).
*   **File Size & Ratios:** Compares the virtual memory size vs. raw disk size.

### Step B: Machine Learning Inference
The 35 extracted features are standardized and fed into the trained **XGBoost / Random Forest Classifier**. The model compares these features against patterns learned from thousands of benign and malicious samples (based on the EMBER dataset structure) and outputs a probability score (e.g., 92% Malicious).

### Step C: Risk Scoring Heuristic
Because Machine Learning isn't perfect, the system applies a **Risk Scorer**. If the ML model is unsure, but the file has critical red flags (like extremely high entropy + suspicious imports), the Risk Scorer artificially boosts the threat level to `HIGH` or `CRITICAL` to keep the user safe.

### Step D: Threat Intelligence (TI)
The backend calculates the SHA-256 hash of the uploaded file and checks it against a Threat Intelligence provider (simulating external services like VirusTotal or AlienVault). If it is a known malware family (like WannaCry or Emotet), it returns the Threat Type.

### Step E: Explainable AI (SHAP)
The AI calculates Shapley values to determine the exact contribution of every feature to the final prediction. This data is sent to the React frontend to render a bar chart, allowing the analyst to see exactly *why* the AI flagged the file.

---
---

## 4. Comprehensive Viva Questions & Answers

### Q1: What is the main objective of your project?
**Answer:** The objective of XMalGuard is to detect unknown, zero-day malware using Machine Learning rather than traditional signature-matching. Additionally, it aims to solve the "black box" problem of AI by using Explainable AI (SHAP) so security analysts can trust and verify the AI's decisions.

### Q2: Why did you choose Static Analysis over Dynamic Analysis?
**Answer:** Dynamic analysis requires running the malware in a sandbox (virtual machine) to observe its behavior, which is very slow and resource-intensive. Static analysis parses the file structure *without* executing it, making it extremely fast, lightweight, and capable of processing massive datasets in seconds.

### Q3: What Machine Learning algorithms did you use and why?
**Answer:** We used tree-based ensemble models (like XGBoost and Random Forest). These models are exceptionally good at handling tabular, non-linear data (like PE header features). They are highly resistant to overfitting, train very quickly, and are perfectly compatible with SHAP TreeExplainer for fast explainability. We avoided Deep Learning (Neural Networks) because they are slower, harder to interpret, and overkill for structured numerical tabular data.

### Q4: Can you explain a few critical features your system extracts from the malware?
**Answer:** 
1. **Entropy (`section_mean_entropy`):** Malware is often encrypted or packed to evade antivirus. Encrypted data looks highly random, resulting in an entropy score close to 8.0.
2. **Suspicious Imports (`suspicious_import_count`):** We count how many sensitive Windows APIs the file uses (e.g., `VirtualAlloc`, `CreateRemoteThread`).
3. **UPX Packing:** We check for UPX section headers, which is a common compression packer used by malware authors.

### Q5: What is SHAP, and why is it important in your project?
**Answer:** SHAP (SHapley Additive exPlanations) is a game-theoretic approach to Explainable AI. In cybersecurity, analysts cannot blindly trust an AI that says "99% Malicious" without knowing why. SHAP breaks down the prediction and tells us exactly how much each feature (like high entropy or string count) contributed to that 99% score, providing transparency and trust.

### Q6: How does your system handle batch processing and large datasets like EMBER?
**Answer:** The system features a specialized pipeline that can accept `.zip` files containing raw `.jsonl` dataset files. Instead of relying heavily on the user's browser, the FastAPI backend streams the files, intelligently maps the raw dataset properties to our 35-feature dimension array, and processes them through the ML model in capped batches to prevent memory crashes.

### Q7: What is the purpose of the Threat Intelligence module?
**Answer:** Machine Learning is predictive, but Threat Intelligence is factual. We integrated a TI module that takes the SHA-256 hash of the uploaded file and checks it against known threat databases. If the file is a famous piece of malware (like ransomware), the TI module instantly tags it with its Malware Family name (e.g., WannaCry), bridging the gap between predictive AI and known cybersecurity intelligence.

### Q8: What were the biggest challenges you faced while building this?
**Answer:**
1. Handling the massive size of cybersecurity datasets (like the 1.5GB EMBER dataset) required writing optimized streaming and parsing logic in the backend so the servers wouldn't crash.
2. Safely extracting features from corrupted or intentionally malformed PE files required robust error handling in the Python `pefile` implementation.
3. Managing the asynchronous integration between the FastAPI backend, the heavy ML/SHAP computations, and the React frontend state.
