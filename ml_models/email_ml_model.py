import pandas as pd
import joblib
import scipy.sparse as sp

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report


# ================= LOAD DATA =================

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "CEAS_08.csv"

df = pd.read_csv(DATASET_PATH)

# ================= FEATURE ENGINEERING =================

# combine subject + body
df["text"] = df["subject"].fillna("") + " " + df["body"].fillna("")

X_text = df["text"]
X_urls = df["urls"].fillna(0)

y = df["label"]


# ================= TFIDF =================

tfidf = TfidfVectorizer(max_features=50)

X_tfidf = tfidf.fit_transform(X_text)

# combine urls feature
X_final = sp.hstack((X_tfidf, X_urls.values.reshape(-1,1)))


# ================= TRAIN TEST SPLIT =================

X_train, X_test, y_train, y_test = train_test_split(
    X_final,
    y,
    test_size=0.2,
    random_state=42
)

# ================= MODEL TRAIN =================

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)


# ================= EVALUATION =================

y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))


# ================= SAVE MODEL =================

joblib.dump(model, "email_rf_model.pkl")
joblib.dump(tfidf, "email_tfidf.pkl")

print("✅ Email phishing model saved")
