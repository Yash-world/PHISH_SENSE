# 🛡️ Phishing Detection System

### AI-Powered Multi-Channel Threat Detection — URLs • Emails • SMS

**A machine learning-based cybersecurity system that detects phishing attempts across URLs, emails, and SMS messages — in real time.**

[Features](#-features) • [Architecture](#-architecture) • [Installation](#-installation) • [Dataset](#-dataset) • [Usage](#-usage) • [Tech Stack](#-tech-stack) • [Contributing](#-contributing)

---

## 📖 Overview

Phishing attacks remain one of the most common and dangerous cybersecurity threats — targeting individuals and organizations through deceptive **links, emails, and text messages**. This project combines **machine learning** with **cybersecurity heuristics** to automatically analyze suspicious content and classify it as **legitimate** or **potentially malicious**, helping users identify threats before they cause harm.

Unlike single-purpose detectors, this system is built as a **unified, multi-vector defense platform** — covering the three most common phishing attack surfaces in one dashboard.

---

## ✨ Features

| Module                           | Description                                                                 |
| -------------------------------- | --------------------------------------------------------------------------- |
| 🔗 **URL Analyzer**              | Detects malicious/spoofed URLs using pattern analysis and ML classification |
| 📧 **Email Scanner**             | Flags phishing emails based on content, headers, and linguistic patterns    |
| 📱 **SMS Detector**              | Identifies smishing (SMS phishing) attempts in text messages                |
| 📊 **Interactive Dashboard**     | Centralized view to monitor scans, results, and threat statistics           |
| 🧠 **ML-Powered Classification** | Dedicated trained models for each channel (URL, Email, SMS)                 |
| 🩹 **Recovery Guidance**         | Step-by-step guidance page for users who may have already been compromised  |

---

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                      Web Interface                       │
│   home.html │ dashboard.html │ url.html │ email.html   │
│              │ sms.html │ recovery.html                │
└──────────────────────────┬──────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   app.py    │  ◄── Flask Backend
                    │  (Routing)  │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
┌───────────────┐  ┌────────────────┐  ┌────────────────┐
│url_ml_model.py│  │email_ml_model.py│  │sms_ml_model.py │
│  (URL Model)  │  │  (Email Model) │  │  (SMS Model)   │
└───────────────┘  └────────────────┘  └────────────────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           ▼
                   ┌───────────────┐
                   │  Features.py  │  ◄── Feature Extraction
                   └───────────────┘
```

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Machine Learning:** Scikit-learn (classification models trained per channel)
* **Frontend:** HTML, CSS, JavaScript
* **Feature Engineering:** Custom feature extraction pipeline (`Features.py`)
* **Dataset:** Public phishing datasets hosted on Kaggle

---

## 📂 Project Structure

```text
Phishing-Detection-System/
│
├── app.py                   # Main Flask application & routes
├── Features.py              # Feature extraction utilities for ML models
│
├── url_ml_model.py          # URL phishing classification model
├── email_ml_model.py        # Email phishing classification model
├── sms_ml_model.py          # SMS phishing classification model
│
├── dataset/
│   └── phishing_dataset.csv # Downloaded dataset (not included in GitHub)
│
├── models/
│   ├── url_model.pkl
│   ├── email_model.pkl
│   └── sms_model.pkl
│
├── home.html                # Landing page
├── dashboard.html           # Analytics & results dashboard
├── url.html                 # URL scanner interface
├── email.html               # Email scanner interface
├── sms.html                 # SMS scanner interface
├── recovery.html            # Post-attack recovery guidance
│
├── requirements.txt
└── README.md
```

> **Note:** The dataset is not included directly in this GitHub repository because of its large file size. It is hosted separately on Kaggle.

---

## 📊 Dataset

The dataset used for training the phishing detection models is hosted on **Kaggle** because of its large file size.

### 🔗 Dataset Download

**Kaggle Dataset:**
`[KAGGLE DATASET LINK — ADD HERE]`

### 📥 Dataset Setup

After downloading the dataset from Kaggle:

1. Clone this repository:

```bash
git clone https://github.com/Yash-world/Phishing-Detection-System.git
cd Phishing-Detection-System
```

2. Create a `dataset` folder if it does not already exist:

```text
Phishing-Detection-System/
└── dataset/
```

3. Place the downloaded CSV file inside the `dataset` folder.

Rename the dataset to:

```text
phishing_dataset.csv
```

The final path should be:

```text
Phishing-Detection-System/dataset/phishing_dataset.csv
```

### ⚠️ Important

The dataset is required if you want to **train the machine learning models from scratch**.

The project uses separate models for:

* URL phishing detection
* Email phishing detection
* SMS phishing detection

If pre-trained model files are already included in the repository, you can run the application directly without retraining. Otherwise, download the dataset and run the corresponding training scripts before starting the Flask application.

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/Yash-world/Phishing-Detection-System.git
cd Phishing-Detection-System
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

**Windows:**

```bash
venv\Scripts\activate
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Download the dataset

Download the dataset from the Kaggle link provided in the **Dataset** section above.

https://www.kaggle.com/datasets/yashpratap02/phishing-dectection-system

```text
dataset/phishing_dataset.csv
```

### 5. Train the models

If the repository contains training scripts, run the appropriate training scripts:

```bash
python train_model.py
```

> If the project uses separate training files for URL, Email, and SMS models, run those respective training scripts instead.

The trained model files should be saved inside the `models/` directory.

### 6. Run the application

```bash
python app.py
```

The app will start on:

```text
http://127.0.0.1:5000/
```

Open this address in your browser to access the application.

---

## 🚀 Usage

1. Launch the app and open the **Home** page.
2. Choose a scan type — **URL**, **Email**, or **SMS**.
3. Paste the content you want to analyze.
4. The system extracts features and runs it through the relevant trained ML model.
5. Get instant results and threat statistics on the **Dashboard**: ✅ **Legitimate** or 🚨 **Phishing Detected**.
6. If flagged, refer to the **Recovery** page for suggested next steps.

---

## 🧠 Model Training

The project uses machine learning models trained separately for different phishing attack vectors.

### URL Detection

The URL model analyzes features such as URL structure, suspicious patterns, domain characteristics, and other extracted URL features.

### Email Detection

The email model analyzes email content and linguistic characteristics to identify potential phishing messages.

### SMS Detection

The SMS model analyzes message text and linguistic patterns to identify potential smishing attempts.

Training the models requires the appropriate datasets to be available locally.

---

## 🗺️ Roadmap

* [ ] Add REST API endpoints for programmatic access
* [ ] Browser extension for real-time URL scanning
* [ ] Model performance metrics dashboard (precision/recall/F1)
* [ ] Support for additional languages in SMS/email detection
* [ ] Dockerize the application for easier deployment

---

## 🤝 Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch:

```bash
git checkout -b feature/amazing-feature
```

3. Commit your changes:

```bash
git commit -m "Add amazing feature"
```

4. Push to the branch:

```bash
git push origin feature/amazing-feature
```

5. Open a Pull Request

---

## 👤 Author

**Yash-world**

GitHub: [@Yash-world](https://github.com/Yash-world)
