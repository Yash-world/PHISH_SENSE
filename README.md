# 🛡️ Phishing Detection System

### AI-Powered Multi-Channel Threat Detection — URLs • Emails • SMS

**A machine learning-based cybersecurity system that detects phishing attempts across URLs, emails, and SMS messages.**

[Features](#-features) • [Architecture](#-architecture) • [Installation](#-installation) • [Dataset](#-dataset) • [Usage](#-usage) • [Tech Stack](#-tech-stack) • [Contributing](#-contributing)

---

## 📖 Overview

Phishing attacks remain one of the most common and dangerous cybersecurity threats — targeting individuals and organizations through deceptive **links, emails, and text messages**.

This project combines **machine learning** with **cybersecurity heuristics** to analyze suspicious content and classify it as **legitimate** or **potentially malicious**.

The system provides a unified platform for detecting phishing threats across three common attack surfaces:

* 🔗 URLs
* 📧 Emails
* 📱 SMS

---

## ✨ Features

| Module                           | Description                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------ |
| 🔗 **URL Analyzer**              | Detects potentially malicious URLs using feature analysis and machine learning |
| 📧 **Email Scanner**             | Analyzes email content and linguistic patterns to identify potential phishing  |
| 📱 **SMS Detector**              | Identifies potential smishing attempts in SMS messages                         |
| 📊 **Interactive Dashboard**     | Centralized interface for scan results and threat statistics                   |
| 🧠 **ML-Powered Classification** | Separate machine learning models for URL, Email, and SMS detection             |
| 🩹 **Recovery Guidance**         | Provides suggested security steps after a potential phishing incident          |

---

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                    Web Interface                        │
│  home.html │ dashboard.html │ url.html │ email.html   │
│             │ sms.html │ recovery.html                │
└──────────────────────────┬──────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   app.py    │
                    │ Flask Backend│
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
                   │  Features.py  │
                   │Feature Extraction│
                   └───────────────┘
```

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Machine Learning:** Scikit-learn
* **Frontend:** HTML, CSS, JavaScript
* **Feature Engineering:** Custom feature extraction pipeline (`Features.py`)
* **Datasets:** Public phishing-related datasets hosted on Kaggle

---

## 📂 Project Structure

```text
Phishing-Detection-System/
│
├── app.py
├── Features.py
│
├── url_ml_model.py
├── email_ml_model.py
├── sms_ml_model.py
│
├── dataset/
│   └── .gitkeep
│
├── models/
│   ├── url_model.pkl
│   ├── email_model.pkl
│   └── sms_model.pkl
│
├── home.html
├── dashboard.html
├── url.html
├── email.html
├── sms.html
├── recovery.html
│
├── requirements.txt
└── README.md
```

> **Note:** The actual dataset files are not included in this GitHub repository because of their large file size. The datasets are hosted on Kaggle.

The `.gitkeep` file only keeps the empty `dataset` folder available in the GitHub repository.

---

## 📊 Dataset

This project uses separate datasets for:

* 🔗 URL Phishing Detection
* 📧 Email Phishing Detection
* 📱 SMS Phishing Detection

Because the datasets are large, they are hosted on Kaggle instead of being uploaded directly to GitHub.

### 🔗 Kaggle Dataset

Download the datasets from:

**[Download Phishing Detection Datasets from Kaggle](https://www.kaggle.com/datasets/yashpratap02/phishing-dectection-system)**

---

### 📥 Dataset Setup

After cloning the repository, download the required dataset files from Kaggle.

Create or use the `dataset` folder:

```text
Phishing-Detection-System/
└── dataset/
```

Place the downloaded dataset files inside this folder.

The final structure should look similar to:

```text
Phishing-Detection-System/
│
├── dataset/
│   ├── URL_DATASET.csv
│   ├── CEAS_08.csv
│   └── SMS_DATASET.csv
│
├── app.py
├── Features.py
├── url_ml_model.py
├── email_ml_model.py
└── sms_ml_model.py
```

### 📧 Email Dataset

The Email Detection model uses:

```text
CEAS_08.csv
```

Place the file here:

```text
dataset/CEAS_08.csv
```

The dataset is loaded using a project-relative path:

```python
from pathlib import Path
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
df = pd.read_csv(BASE_DIR / "dataset" / "CEAS_08.csv")
```

This allows the project to work on different computers without using a computer-specific path such as:

```text
C:\Users\yashp\Downloads\CEAS_08.csv
```

> **Important:** Dataset filenames must match the filenames expected by the corresponding Python scripts.

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

### 3. Activate the virtual environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Download the datasets

Download the required datasets from Kaggle:

**[Kaggle Dataset](https://www.kaggle.com/datasets/yashpratap02/phishing-dectection-system)**

Place the downloaded files inside:

```text
dataset/
```

For example:

```text
dataset/
├── Dataset_10191.csv
├── CEAS_08.csv
└── PhiUSIIL_Phishing_URL_Dataset.csv
```

### 6. Train the models

If you want to train the models from scratch, run the corresponding training scripts provided in the project.

For example:

```bash
python url_ml_model.py
python email_ml_model.py
python sms_ml_model.py
```

> **Note:** The exact training command depends on the implementation of each model file. If pre-trained model files are already available, retraining may not be required.

### 7. Run the application

```bash
python app.py
```

The application will start at:

```text
http://127.0.0.1:5000/
```

Open this address in your browser.

---

## 🚀 Usage

1. Launch the Flask application.
2. Open the **Home** page.
3. Select a scan type:

   * URL
   * Email
   * SMS
4. Enter the content you want to analyze.
5. The system extracts the required features.
6. The corresponding machine learning model processes the input.
7. The result is displayed as:

   * ✅ Legitimate
   * 🚨 Phishing Detected
8. If a suspicious result is detected, refer to the **Recovery** page for suggested security steps.

---

## 🧠 Model Training

The system uses separate machine learning models for different phishing channels.

### 🔗 URL Detection

The URL model analyzes URL characteristics and extracted features to identify potentially malicious URLs.

### 📧 Email Detection

The Email model analyzes email content and linguistic characteristics to identify potential phishing emails.

The email dataset used by the project includes:

```text
CEAS_08.csv
```

### 📱 SMS Detection

The SMS model analyzes message content and linguistic patterns to identify potential smishing messages.

---

## ⚠️ Dataset and Model Requirements

If you are only running the application with pre-trained models, you may not need to download the datasets.

If you want to **retrain the models**, you must:

1. Download the required datasets from Kaggle.
2. Place them inside the `dataset/` folder.
3. Make sure the filenames match the paths used in the Python scripts.
4. Run the appropriate model training scripts.
5. Verify that the trained model files are generated correctly.
6. Start the Flask application.

---

## 🗺️ Roadmap

* [ ] Add REST API endpoints for programmatic access
* [ ] Browser extension for URL scanning
* [ ] Model performance metrics dashboard
* [ ] Precision/Recall/F1 reporting
* [ ] Support for additional languages
* [ ] Dockerize the application

---

## 🤝 Contributing

Contributions are welcome!

To contribute:

1. Fork the repository.
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

5. Open a Pull Request.

---

## 👤 Author

**Yash-world**

GitHub: [@Yash-world](https://github.com/Yash-world)
