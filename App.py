
from __future__ import annotations

import os
import re
from pathlib import Path

import joblib
import pytesseract
from flask import Flask, render_template, request
from PIL import Image, UnidentifiedImageError

from utils.Features import analyze_url, extract_features
from utils.scoring import (
    apply_overrides,
    combine,
    make_reasons,
    risk_label,
    score_from_points,
)
from utils.text_rules import email_rules, extract_urls, sms_rules


BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"

app = Flask(__name__)

# Limit uploaded screenshots to 5 MB.
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}


def _load_model(filename: str):
    """Load a trained model from the models directory."""
    path = MODELS_DIR / filename

    if not path.exists():
        return None

    try:
        return joblib.load(path)
    except Exception:
        return None


url_model = _load_model("url_model.pkl")
email_model = _load_model("email_model.pkl")
sms_model = _load_model("sms_model.pkl")


def _model_error(model_name: str) -> str:
    return (
        f"{model_name} model is missing or could not be loaded. "
        f"Run the corresponding training script in ml_models/ first."
    )


def _image_text(upload) -> str:
    """Extract text from an uploaded screenshot using OCR."""
    if not upload or not upload.filename:
        return ""

    suffix = Path(upload.filename).suffix.lower()

    if suffix not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError(
            "Only PNG, JPG, JPEG and WEBP screenshots are allowed."
        )

    try:
        image = Image.open(upload.stream)
        image.verify()

        upload.stream.seek(0)
        image = Image.open(upload.stream)

        return pytesseract.image_to_string(image)

    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError(
            "The uploaded screenshot is not a valid image."
        ) from exc


def _class_probability(model, text_or_features, class_value) -> float:
    if model is None or not hasattr(model, "predict_proba"):
        return 0.0

    probs = model.predict_proba(text_or_features)[0]
    classes = list(getattr(model, "classes_", []))

    if class_value not in classes:
        return 0.0

    index = classes.index(class_value)
    return float(probs[index] * 100.0)


def _url_rule_score(info: dict) -> tuple[float, list[tuple[str, float]]]:
    signals = info["signals"]
    points = 0.0
    reasons = []

    checks = [
        (
            "@" in info["normalized"],
            18,
            "@ symbol detected",
        ),
        (
            signals["ip_host"],
            35,
            "IP-address host detected",
        ),
        (
            signals["punycode"],
            30,
            "Punycode hostname detected",
        ),
        (
            signals["non_ascii"],
            25,
            "Non-ASCII hostname characters detected",
        ),
        (
            signals["brand_wrong_place"],
            30,
            "Brand name appears outside its legitimate domain",
        ),
        (
            signals["typosquat"],
            28,
            "Possible typosquatting detected",
        ),
        (
            signals["suspicious_tld"],
            15,
            f"Suspicious TLD detected: .{info['tld']}",
        ),
        (
            signals["shortener"],
            12,
            "URL shortener detected",
        ),
        (
            bool(signals["credential_hits"]),
            min(15, len(signals["credential_hits"]) * 5),
            "Credential/security keyword in host or path",
        ),
        (
            len(info["normalized"]) > 75,
            8,
            "Unusually long URL",
        ),
        (
            len(info["host"].split(".")[:-2]),
            8,
            "Deep subdomain structure",
        ),
        (
            signals["nonstandard_port"],
            10,
            "Non-standard port detected",
        ),
        (
            "//" in info["path"],
            8,
            "Double slash in URL path",
        ),
        (
            info["normalized"].count("%") >= 3,
            6,
            "Encoded characters detected",
        ),
        (
            (
                len(
                    [
                        value
                        for value in info["normalized"]
                        .split("?")[-1]
                        .split("&")
                        if value
                    ]
                )
                >= 5
                if "?" in info["normalized"]
                else False
            ),
            6,
            "Many query parameters",
        ),
        (
            signals["dangerous_extension"],
            20,
            "Potentially dangerous file extension",
        ),
    ]

    for condition, weight, reason in checks:
        if condition:
            points += weight
            reasons.append((reason, float(weight)))

    return min(points, 100.0), reasons


def _analyze_url_for_route(raw_url: str):
    info = analyze_url(raw_url)

    rule_pct, reasons = _url_rule_score(info)

    if url_model is None:
        raise RuntimeError(_model_error("URL"))

    ml_pct = _class_probability(
        url_model,
        info["features"].reshape(1, -1),
        1,
    )

    final = combine(rule_pct, ml_pct)
    final = apply_overrides(
        final,
        info["hard_flags"],
        info["trusted"],
    )

    if info["trusted"] and not info["hard_flags"]:
        reasons.append(
            (
                f"Trusted registered domain: {info['registered_domain']}",
                0,
            )
        )

    reasons = make_reasons(reasons)

    return (
        final,
        ml_pct,
        rule_pct,
        risk_label(final),
        reasons,
    )


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/url", methods=["GET", "POST"])
def form():
    if request.method == "GET":
        return render_template("url.html")

    raw_url = request.form.get("url", "").strip()

    if not raw_url:
        return render_template(
            "url.html",
            error="Please enter a URL.",
        )

    try:
        final, ml_pct, rule_pct, label, reasons = _analyze_url_for_route(
            raw_url
        )

        return render_template(
            "dashboard.html",
            result=(
                f"{label} Risk "
                f"{'✅' if label == 'Low' else '⚠' if label == 'Medium' else '🚨'}"
            ),
            risk_percentage=round(final, 2),
            ml_risk=round(ml_pct, 2),
            rule_score=round(rule_pct, 2),
            final_score=round(final, 2),
            reasons=reasons,
            back_url="/url",
            scan_type="URL",
        )

    except (ValueError, RuntimeError) as exc:
        return render_template(
            "url.html",
            error=str(exc),
            url=raw_url,
        )


@app.route("/email", methods=["GET", "POST"])
def email_check():
    if request.method == "GET":
        return render_template("email.html")

    email_text = request.form.get("email", "").strip()
    screenshot = request.files.get("screenshot")

    try:
        extracted = _image_text(screenshot)

        if extracted:
            email_text = f"{email_text}\n{extracted}".strip()

        if not email_text:
            return render_template(
                "email.html",
                error="Please enter email text or upload a screenshot.",
            )

        if email_model is None:
            raise RuntimeError(_model_error("Email"))

        rule_pct, reasons, hard_flags = email_rules(email_text)

        grammar_points = 0.0
        grammar_reason = None

        if os.getenv("GRAMMAR_ENABLED", "0") == "1":
            try:
                import language_tool_python

                tool = language_tool_python.LanguageTool("en-US")
                errors = len(tool.check(email_text))

                grammar_points = min(10.0, errors * 1.5)

                if grammar_points:
                    grammar_reason = (
                        f"Grammar/spelling anomalies detected ({errors})",
                        grammar_points,
                    )

                tool.close()

            except Exception:
                grammar_points = 0.0

        if grammar_reason:
            reasons.append(grammar_reason)
            rule_pct = min(
                100.0,
                rule_pct + grammar_points,
            )

        if extracted:
            reasons.append(
                (
                    "Text read from screenshot (OCR)",
                    0,
                )
            )

        ml_pct = _class_probability(
            email_model,
            [email_text],
            1,
        )

        final = combine(rule_pct, ml_pct)
        final = apply_overrides(
            final,
            hard_flags,
            False,
        )

        reasons = make_reasons(reasons)
        label = risk_label(final)

        return render_template(
            "dashboard.html",
            email_text=email_text,
            result=(
                f"{label} Risk "
                f"{'✅' if label == 'Low' else '⚠' if label == 'Medium' else '🚨'}"
            ),
            risk_percentage=round(final, 2),
            ml_risk=round(ml_pct, 2),
            rule_score=round(rule_pct, 2),
            final_score=round(final, 2),
            reasons=reasons,
            back_url="/email",
            scan_type="Email",
        )

    except (ValueError, RuntimeError) as exc:
        return render_template(
            "email.html",
            error=str(exc),
            email_text=email_text,
        )


@app.route("/sms", methods=["GET", "POST"])
def sms_check():
    if request.method == "GET":
        return render_template("sms.html")

    sms = request.form.get("sms", "").strip()
    sender = request.form.get("sender", "").strip()
    screenshot = request.files.get("screenshot")

    try:
        extracted = _image_text(screenshot)

        if extracted:
            sms = f"{sms}\n{extracted}".strip()

        if not sms:
            return render_template(
                "sms.html",
                error="Please enter SMS text or upload a screenshot.",
            )

        if sms_model is None:
            raise RuntimeError(_model_error("SMS"))

        rule_pct, reasons, hard_flags = sms_rules(
            sms,
            sender,
        )

        urls = extract_urls(sms)
        max_url_risk = 0.0

        for url in urls:
            try:
                url_final, _, _, _, _ = _analyze_url_for_route(url)
                max_url_risk = max(max_url_risk, url_final)
            except (ValueError, RuntimeError):
                continue

        if max_url_risk:
            points = min(25.0, max_url_risk * 0.25)

            rule_pct = min(
                100.0,
                rule_pct + points,
            )

            reasons.append(
                (
                    f"Highest linked URL risk: {max_url_risk:.0f}%",
                    points,
                )
            )

        if extracted:
            reasons.append(
                (
                    "Text read from screenshot (OCR)",
                    0,
                )
            )

        probs = sms_model.predict_proba([sms])[0]
        classes = list(getattr(sms_model, "classes_", []))

        smishing_prob = (
            probs[classes.index(2)] * 100
            if 2 in classes
            else 0.0
        )

        spam_prob = (
            probs[classes.index(1)] * 100
            if 1 in classes
            else 0.0
        )

        ml_pct = min(
            100.0,
            smishing_prob + 0.5 * spam_prob,
        )

        final = combine(rule_pct, ml_pct)
        final = apply_overrides(
            final,
            hard_flags,
            False,
        )

        reasons = make_reasons(reasons)
        label = risk_label(final)

        return render_template(
            "dashboard.html",
            sms=sms,
            result=(
                f"{label} Risk "
                f"{'✅' if label == 'Low' else '⚠' if label == 'Medium' else '🚨'}"
            ),
            risk_percentage=round(final, 2),
            ml_risk=round(ml_pct, 2),
            rule_score=round(rule_pct, 2),
            final_score=round(final, 2),
            reasons=reasons,
            back_url="/sms",
            scan_type="SMS",
        )

    except (ValueError, RuntimeError) as exc:
        return render_template(
            "sms.html",
            error=str(exc),
            sms=sms,
        )


@app.route("/recovery", methods=["GET", "POST"])
def recovery():
    recovery_type = (
        request.form.get("type")
        if request.method == "POST"
        else None
    )

    steps = {
        "password": [
            "Immediately change your password on the real website.",
            "Enable two-factor authentication.",
            "Log out from all devices.",
            "Check login activity and remove unknown sessions.",
        ],
        "bank": [
            "Call your bank using the official number immediately.",
            "Block your debit/credit card if required.",
            "Freeze online banking temporarily if advised by your bank.",
            "Call Cyber Crime Helpline 1930 in India.",
        ],
        "otp": [
            "Immediately contact the relevant bank/service.",
            "Ask them to secure or block the affected account.",
            "Monitor transactions and login activity carefully.",
        ],
        "device": [
            "Disconnect the affected device from the internet if compromise is suspected.",
            "Run a full antivirus/security scan.",
            "Uninstall unknown applications.",
            "Change passwords from another trusted device.",
        ],
    }.get(recovery_type, [])

    return render_template(
        "recovery.html",
        steps=steps,
        recovery_type=recovery_type,
    )


@app.errorhandler(413)
def too_large(_error):
    return (
        render_template(
            "home.html",
            error="Uploaded file is too large. Maximum size is 5 MB.",
        ),
        413,
    )


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0").lower() in {
        "1",
        "true",
        "yes",
    }

    app.run(debug=debug)

