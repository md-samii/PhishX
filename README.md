# 🛡️ PhishX — AI-Powered Phishing Website Detector
> **Academic Mini Project** | Computer Science & Engineering

PhishX is a web-based phishing website detector built to identify malicious URLs using machine learning and deep learning. Instead of relying only on traditional blacklists, PhishX uses a hybrid model (**BERT + XGBoost**) to detect zero-day phishing sites in real time.

---

## 🎯 Objectives
- **Accurate Detection:** Detect deceptive and phishing URLs with high accuracy (**98.27%**).
- **Hybrid AI:** Combine **DistilBERT** (for semantic URL analysis) and **XGBoost** (for fast classification).
- **Link Unshortening:** Resolve shortened links (`bit.ly`, `tinyurl`) to inspect the final target domain.
- **Whitelist Protection:** Fast-track known safe websites (Google, Amazon, etc.) to minimize latency.

---

## 🛠️ Tech Stack

| Layer | Technologies Used |
| :--- | :--- |
| **Frontend** | React 19, Vite, Tailwind CSS, Lucide Icons, Framer Motion |
| **Backend** | Python 3, Flask, Flask-CORS |
| **Machine Learning** | XGBoost, DistilBERT (HuggingFace API), Scikit-Learn |
| **Extension** | Manifest V3 Chrome Extension |

---

## 🧠 System Architecture

```
[ User Input URL ]
        │
        ▼
[ 1. Whitelist Check ] ──(If Safe)──► [ Return SAFE (Instant) ]
        │
     (If Not)
        ▼
[ 2. Unshorten URL ] ──► [ 3. Feature Extraction (BERT) ]
                                      │
                                      ▼
                           [ 4. XGBoost Model ]
                                      │
                                      ▼
                        [ 5. Risk Score & Result ]
```

---

## 🚀 Quick Setup & Execution

### Prerequisites
- **Node.js** (v18+)
- **Python** (v3.8+)

### Step 1: Backend Setup
```bash
cd backend
python -m venv venv

# Windows:
venv\Scripts\activate

# Install requirements:
pip install -r requirements.txt

# Start Backend API:
python app.py
```
> Backend runs at: `http://127.0.0.1:5000`

### Step 2: Frontend Setup
```bash
# Open a new terminal in the root folder
npm install
npm run dev
```
> Frontend runs at: `http://localhost:5173`

---

## 📊 Results & Performance

- **Model Accuracy:** `98.27%`
- **Average Response Time:** `< 1 second`
- **Output:** Categorizes URLs into `SAFE` or `PHISHING` with a confidence risk score.

---

## 👤 Project Author

- **Name:** MD Sami
- **GitHub:** [md-samii](https://github.com/md-samii)
- **Course:** B.Tech / BE - Computer Science & Engineering
- **Project Type:** Mini Project
