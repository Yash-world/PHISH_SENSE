
"""Train the email phishing detection model."""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "datasets" / "CEAS_08.csv"
MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(exist_ok=True)


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    data = pd.read_csv(
        DATA_PATH,
        usecols=["subject", "body", "label"]
    ).fillna("")

    text = (
        data["subject"].astype(str)
        + "\n"
        + data["body"].astype(str)
    ).str.strip()

    labels = data["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        text,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                max_features=50000,
                ngram_range=(1, 2),
                min_df=3,
                sublinear_tf=True,
                strip_accents="unicode"
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                C=4.0
            )
        )
    ])

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    phishing_class = list(model.classes_).index(1)
    phishing_scores = probabilities[:, phishing_class]

    print("\nEmail Phishing Model Evaluation")
    print("-" * 35)

    print(
        classification_report(
            y_test,
            predictions,
            target_names=["legitimate", "phishing"],
            digits=4
        )
    )

    print(f"ROC-AUC: {roc_auc_score(y_test, phishing_scores):.4f}")

    model_path = MODEL_DIR / "email_model.pkl"
    joblib.dump(model, model_path)

    print(f"\nModel saved to: {model_path}")
    print(f"Classes: {model.classes_}")


if __name__ == "__main__":
    main()


