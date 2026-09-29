import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report

# ================= LOAD DATA =================

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "dataset" / "Dataset_10191.csv"

# sirf required columns
df = df[['LABEL', 'TEXT']]

# ================= CLEAN DATA =================
df.dropna(inplace=True)

# labels clean karo (IMPORTANT 🔥)
df['LABEL'] = df['LABEL'].astype(str).str.lower().str.strip()

# ================= CONVERT TO BINARY =================
df['LABEL'] = df['LABEL'].map({
    'ham': 0,
    'spam': 1,
    'smishing': 2   # phishing category
})

# invalid rows hatao
df.dropna(subset=['LABEL'], inplace=True)

# integer type force karo
df['LABEL'] = df['LABEL'].astype(int)

# ================= DEBUG CHECK =================
print("Unique Labels:", df['LABEL'].unique())
print("Data Type:", df['LABEL'].dtype)

# ================= TF-IDF =================
vectorizer = TfidfVectorizer(
    max_features=3000,
    ngram_range=(1,2),
    stop_words='english'
)

X = vectorizer.fit_transform(df['TEXT'])
y = df['LABEL']

# ================= TRAIN TEST SPLIT =================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ================= MODEL =================
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=25,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# ================= EVALUATION =================
y_pred = model.predict(X_test)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# ================= SAVE =================
joblib.dump(model, "phishing_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\n✅ Model & Vectorizer Saved Successfully")

print("Classes:", model.classes_)
