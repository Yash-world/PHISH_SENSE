
"""Train the SMS phishing detection model."""

from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "datasets" / "Dataset_10191.csv"
MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(exist_ok=True)


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    data = pd.read_csv(
        DATA_PATH,
        usecols=["LABEL", "TEXT"]
    ).fillna("")

    labels = data["LABEL"].astype(str).str.lower().str.strip()

    label_map = {
        "ham": 0,
        "spam": 1,
        "smishing": 2
    }

    unknown_labels = sorted(set(labels) - set(label_map))

    if unknown_labels:
        raise ValueError(f"Unknown SMS labels: {unknown_labels}")

    y = labels.map(label_map).astype(int).to_numpy()
    text = data["TEXT"].astype(str).to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        text,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    features = FeatureUnion([
        (
            "word",
            TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                min_df=2,
                sublinear_tf=True,
                strip_accents="unicode"
            )
        ),
        (
            "char",
            TfidfVectorizer(
                analyzer="char_wb",
                ngram_range=(3, 5),
                min_df=2,
                sublinear_tf=True,
                max_features=50000
            )
        )
    ])

    model = Pipeline([
        ("features", features),
        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced"
            )
        )
    ])

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)

    classes = list(model.classes_)
    smishing_index = classes.index(2)
    spam_index = classes.index(1)

    smishing_scores = probabilities[:, smishing_index]
    risk_scores = smishing_scores + (0.5 * probabilities[:, spam_index])

    thresholds = np.linspace(0.05, 0.95, 91)
    valid_thresholds = []

    for threshold in thresholds:
        smishing_prediction = smishing_scores >= threshold

        recall = recall_score(
            y_test == 2,
            smishing_prediction,
            zero_division=0
        )

        if recall >= 0.90:
            valid_thresholds.append((threshold, recall))

    default_recall = recall_score(
        y_test == 2,
        smishing_scores >= 0.50,
        zero_division=0
    )

    if valid_thresholds:
        alert_threshold = max(valid_thresholds, key=lambda item: item[0])[0]
    else:
        alert_threshold = 0.50

    ham_messages = y_test == 0

    if ham_messages.any():
        ham_false_positive_rate = float(
            np.mean(risk_scores[ham_messages] >= 0.30)
        )
    else:
        ham_false_positive_rate = 0.0

    print("\nSMS Model Evaluation")
    print("-" * 30)

    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1, 2],
            target_names=["ham", "spam", "smishing"],
            digits=4
        )
    )

    print(
        "Confusion matrix:\n",
        confusion_matrix(
            y_test,
            predictions,
            labels=[0, 1, 2]
        )
    )

    smishing_recall = recall_score(
        y_test,
        predictions,
        labels=[2],
        average="macro",
        zero_division=0
    )

    print(f"Smishing recall: {smishing_recall:.4f}")
    print(
        "Ham false-positive rate at combined risk >= 30%:",
        f"{ham_false_positive_rate:.4f}"
    )
    print(f"Smishing alert threshold: {alert_threshold:.3f}")

    model_path = MODEL_DIR / "sms_model.pkl"
    threshold_path = MODEL_DIR / "sms_threshold.json"

    joblib.dump(model, model_path)

    threshold_path.write_text(
        json.dumps(
            {"smishing_alert_threshold": float(alert_threshold)},
            indent=2
        )
    )

    print(f"\nModel saved to: {model_path}")
    print(f"Threshold saved to: {threshold_path}")
    print(f"Classes: {model.classes_}")


if __name__ == "__main__":
    main()


