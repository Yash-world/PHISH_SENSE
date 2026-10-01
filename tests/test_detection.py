
import pytest

from utils.Features import analyze_url
from utils.scoring import combine, risk_label
from utils.text_rules import email_rules, sms_rules


def test_url_feature_count_and_normalization():
    info = analyze_url(
        "github.com/user/repo/blob/main/README.md"
    )

    assert info["features"].shape == (36,)
    assert info["registered_domain"] == "github.com"
    assert info["trusted"] is True


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.10/bank/login.php",
        "https://google.com@evil.top/login",
        "http://paypa1.com/verify",
        "https://xn--pypal-4ve.com",
    ],
)
def test_url_hard_flags(url):
    info = analyze_url(url)

    assert info["hard_flags"]


def test_trusted_deep_url_is_trusted():
    info = analyze_url(
        "https://mail.google.com/mail/u/0/"
    )

    assert info["trusted"] is True
    assert not info["hard_flags"]


def test_risk_thresholds():
    assert risk_label(29.99) == "Low"
    assert risk_label(30) == "Medium"
    assert risk_label(59.99) == "Medium"
    assert risk_label(60) == "High"


def test_combined_score():
    assert combine(100, 0) == pytest.approx(40)
    assert combine(0, 100) == pytest.approx(60)


def test_email_rules():
    points, reasons, flags = email_rules(
        "Your account is suspended, verify immediately "
        "http://x.tk/login enter password"
    )

    assert points > 0
    assert reasons
    assert flags


def test_sms_rules_no_free_now_false_positive():
    points, reasons, flags = sms_rules(
        "Hi, are you free tonight?"
    )

    assert points < 30
    assert not any(
        "free" in text.lower()
        for text, _ in reasons
    )


def test_sms_otp_rule():
    points, reasons, flags = sms_rules(
        "Dear customer your SBI KYC expires today, "
        "click http://bit.ly/abc and share OTP"
    )

    assert "otp request" in flags
    assert points >= 30


def test_empty_inputs_rejected():
    with pytest.raises(ValueError):
        analyze_url("")

