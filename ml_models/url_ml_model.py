
"""Train the URL phishing detection model."""

from pathlib import Path
import json
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit

BASE_DIR = Path(__file__).resolve().parent.parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from utils.Features import analyze_url


DATA_PATH = BASE_DIR / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(exist_ok=True)

FEATURE_CACHE = MODEL_DIR / "url_features.npy"
FEATURE_META = MODEL_DIR / "url_features_meta.json"


def get_domain(url):
    try:
        result = analyze_url(url)
        domain = result.get("registered_domain")

        if domain:
            return str(domain).strip().lower()

    except Exception:
        pass

    return str(url).strip().lower()


def extract_features(urls):
    rows = []
    feature_count = None

    for number, url in enumerate(urls, start=1):
        try:
            result = analyze_url(url)
            features = np.asarray(
                result["features"],
                dtype=float
            ).reshape(-1)

            if feature_count is None:
                feature_count = len(features)

            if len(features) != feature_count:
                raise ValueError(
                    f"Expected {feature_count} features, "
                    f"got {len(features)}"
                )

            rows.append(features)

        except Exception as error:
            if feature_count is None:
                feature_count = 36

            rows.append(
                np.zeros(feature_count, dtype=float)
            )

            if number <= 10:
                print(
                    f"Warning: could not extract features "
                    f"for URL {number}: {error}"
                )

        if number % 10000 == 0:
            print(f"Processed {number:,} URLs")

    if not rows:
        raise ValueError("No URLs available for feature extraction.")

    features = np.vstack(rows)

    print(f"Feature matrix shape: {features.shape}")

    return features


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}\n"
            "Place PhiUSIIL_Phishing_URL_Dataset.csv inside datasets/."
        )

    print(f"Dataset: {DATA_PATH}")

    data = pd.read_csv(
        DATA_PATH,
        usecols=["URL", "label"]
    ).dropna(subset=["URL", "label"])

    data["URL"] = data["URL"].astype(str).str.strip()

    data = (
        data[data["URL"] != ""]
        .drop_duplicates("URL")
        .reset_index(drop=True)
    )

    if data.empty:
        raise ValueError("The URL dataset contains no usable rows.")

    raw_labels = pd.to_numeric(
        data["label"],
        errors="coerce"
    )

    if raw_labels.isna().any():
        raise ValueError(
            "The dataset contains invalid values in the label column."
        )

    raw_labels = raw_labels.astype(int)

    if not set(raw_labels.unique()).issubset({0, 1}):
        raise ValueError(
            f"Unexpected labels found: {sorted(raw_labels.unique())}"
        )

    # PhiUSIIL uses 1 for legitimate and 0 for phishing.
    # The project uses 0 for legitimate and 1 for phishing.
    labels = (1 - raw_labels).to_numpy()
    urls = data["URL"].tolist()

    print(f"Usable URLs: {len(urls):,}")
    print(f"Legitimate: {np.sum(labels == 0):,}")
    print(f"Phishing:   {np.sum(labels == 1):,}")

    if FEATURE_CACHE.exists() and FEATURE_META.exists():
        try:
            metadata = json.loads(
                FEATURE_META.read_text(encoding="utf-8")
            )

            cache_matches = (
                metadata.get("row_count") == len(urls)
                and metadata.get("feature_count") == 36
                and metadata.get("source") == DATA_PATH.name
            )

            if cache_matches:
                features = np.load(FEATURE_CACHE)

                if features.shape != (
                    len(urls),
                    int(metadata["feature_count"])
                ):
                    cache_matches = False

            if cache_matches:
                print(f"Using cached features: {FEATURE_CACHE}")

        except Exception:
            cache_matches = False
    else:
        cache_matches = False

    if not cache_matches:
        print("Extracting URL features...")

        features = extract_features(urls)

        if features.ndim != 2:
            raise ValueError(
                f"Expected a 2D feature matrix, got {features.shape}"
            )

        np.save(FEATURE_CACHE, features)

        FEATURE_META.write_text(
            json.dumps(
                {
                    "row_count": len(urls),
                    "feature_count": features.shape[1],
                    "source": DATA_PATH.name,
                },
                indent=2
            ),
            encoding="utf-8"
        )

        print(f"Saved feature cache: {FEATURE_CACHE}")

    # Add normal-looking URLs from legitimate domains.
    # This helps reduce false positives on long paths and query strings.
    legitimate_domains = []
    seen_domains = set()

    for url, label in zip(urls, labels):
        if label != 0:
            continue

        domain = get_domain(url)

        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            legitimate_domains.append(domain)

        if len(legitimate_domains) >= 250:
            break

    hard_negative_urls = []

    for domain in legitimate_domains:
        hard_negative_urls.extend([
            f"https://{domain}/account/settings/profile",
            f"https://{domain}/help/security/login",
            f"https://{domain}/user/profile?id=12345&view=details",
            f"https://{domain}/support/article/2026/update",
        ])

    if hard_negative_urls:
        print(
            f"Generating {len(hard_negative_urls):,} "
            "additional legitimate URLs..."
        )

        hard_features = extract_features(hard_negative_urls)

        if hard_features.shape[1] != features.shape[1]:
            raise ValueError(
                "Feature count does not match between "
                "dataset and additional URLs."
            )

        features = np.vstack([
            features,
            hard_features
        ])

        labels = np.concatenate([
            labels,
            np.zeros(len(hard_negative_urls), dtype=int)
        ])

        groups = (
            [get_domain(url) for url in urls]
            + [get_domain(url) for url in hard_negative_urls]
        )

    else:
        print("No legitimate domains found for additional URLs.")
        groups = [get_domain(url) for url in urls]

    groups = np.asarray(groups)

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42
    )

    train_idx, test_idx = next(
        splitter.split(
            features,
            labels,
            groups=groups
        )
    )

    print(f"Training rows: {len(train_idx):,}")
    print(f"Testing rows:  {len(test_idx):,}")

    if len(np.unique(labels[train_idx])) < 2:
        raise ValueError(
            "Training data contains only one class."
        )

    classifier = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )

    model = CalibratedClassifierCV(
        estimator=classifier,
        method="isotonic",
        cv=3,
        n_jobs=-1
    )

    print("Training URL model...")
    model.fit(features[train_idx], labels[train_idx])

    predictions = model.predict(features[test_idx])

    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            f"Phishing class is missing from model classes: {classes}"
        )

    phishing_index = classes.index(1)

    phishing_scores = model.predict_proba(
        features[test_idx]
    )[:, phishing_index]

    print("\nURL Model Evaluation")
    print("-" * 30)

    print(
        classification_report(
            labels[test_idx],
            predictions,
            labels=[0, 1],
            target_names=["legitimate", "phishing"],
            digits=4,
            zero_division=0
        )
    )

    print(
        f"ROC-AUC: "
        f"{roc_auc_score(labels[test_idx], phishing_scores):.4f}"
    )

    print(
        f"PR-AUC:  "
        f"{average_precision_score(labels[test_idx], phishing_scores):.4f}"
    )

    print(
        "Confusion matrix:\n",
        confusion_matrix(
            labels[test_idx],
            predictions,
            labels=[0, 1]
        )
    )

    model_path = MODEL_DIR / "url_model.pkl"

    joblib.dump(model, model_path)

    print(f"\nModel saved to: {model_path}")
    print(f"Feature cache: {FEATURE_CACHE}")
    print(f"Feature metadata: {FEATURE_META}")
    print(f"Classes: {model.classes_}")


if __name__ == "__main__":
    main()

