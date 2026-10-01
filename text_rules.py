
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlparse

from utils.brands import (
    EMAIL_INFO_REQUESTS,
    EMAIL_SUSPICIOUS_WORDS,
    EMAIL_URGENCY_PHRASES,
    INDIAN_PHISHING_PHRASES,
    SMS_KEYWORDS,
    SMS_URGENCY_PHRASES,
    SUSPICIOUS_EXTENSIONS,
)


URL_RE = re.compile(
    r'''(?i)(?:https?://|www\.)[^\s<>'"]+'''
)

EMAIL_RE = re.compile(
    r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b"
)


def _contains_phrase(text: str, phrase: str) -> bool:
    phrase = phrase.strip()
    escaped = re.escape(phrase)

    if " " in phrase:
        return (
            re.search(
                rf"(?<!\w){escaped}(?!\w)",
                text,
                re.I,
            )
            is not None
        )

    return (
        re.search(
            rf"\b{escaped}\b",
            text,
            re.I,
        )
        is not None
    )


def keyword_hits(text: str, words) -> list[str]:
    return [
        word
        for word in words
        if _contains_phrase(text, word)
    ]


def extract_urls(text: str) -> list[str]:
    urls = []

    for raw_url in URL_RE.findall(text or ""):
        cleaned_url = raw_url.rstrip(
            ".,;:!?)]}"
        )
        urls.append(cleaned_url)

    return urls


def email_rules(
    text: str,
) -> tuple[
    float,
    list[tuple[str, float]],
    list[str],
]:
    text = unescape(text or "")
    lower = text.lower()

    points = 0.0
    reasons: list[tuple[str, float]] = []
    hard_flags: list[str] = []

    # Suspicious email-related keywords.
    hits = keyword_hits(
        lower,
        EMAIL_SUSPICIOUS_WORDS,
    )

    if hits:
        points_to_add = min(
            20.0,
            len(hits) * 4.0,
        )

        points += points_to_add

        reasons.append(
            (
                f"Suspicious email keywords: {', '.join(hits)}",
                points_to_add,
            )
        )

    # Urgency-related language.
    hits = keyword_hits(
        lower,
        EMAIL_URGENCY_PHRASES,
    )

    if hits:
        points_to_add = min(
            15.0,
            len(hits) * 5.0,
        )

        points += points_to_add

        reasons.append(
            (
                f"Urgency language: {', '.join(hits)}",
                points_to_add,
            )
        )

    # Requests for credentials or payment information.
    hits = keyword_hits(
        lower,
        EMAIL_INFO_REQUESTS,
    )

    if hits:
        points_to_add = min(
            25.0,
            len(hits) * 7.0,
        )

        points += points_to_add

        reasons.append(
            (
                f"Credential/payment request: {', '.join(hits)}",
                points_to_add,
            )
        )

        credential_phrases = (
            "send otp",
            "share otp",
            "enter password",
            "cvv",
        )

        if any(
            _contains_phrase(lower, phrase)
            for phrase in credential_phrases
        ):
            hard_flags.append("credential request")

    # Links found in the email.
    urls = extract_urls(text)

    if len(urls) >= 2:
        points += 8
        reasons.append(
            (
                "Multiple links found",
                8,
            )
        )

    if urls:
        reasons.append(
            (
                f"{len(urls)} URL(s) found in email",
                min(8, len(urls) * 2),
            )
        )

    # Suspicious top-level domains.
    if re.search(
        r"(?i)\.(xyz|top|tk|gq|ml|cf|ga|click|zip)\b",
        text,
    ):
        points += 15
        reasons.append(
            (
                "Suspicious link TLD detected",
                15,
            )
        )

    # Potentially dangerous file extensions.
    if any(
        extension in lower
        for extension in SUSPICIOUS_EXTENSIONS
    ):
        points += 18
        reasons.append(
            (
                "Potentially dangerous attachment/file extension mentioned",
                18,
            )
        )

    # Check for displayed links whose destination differs.
    link_pattern = (
        r'''(?i)<a\b[^>]*href\s*=\s*['"]([^'"]+)['"][^>]*>'''
        r"(.*?)"
        r"</a>"
    )

    if re.search(
        link_pattern,
        text,
        re.S,
    ):
        for href, label in re.findall(
            link_pattern,
            text,
            re.S,
        ):
            href_host = urlparse(href).hostname or ""

            visible_text = unescape(
                re.sub(
                    r"<[^>]+>",
                    " ",
                    label,
                )
            )

            label_url = URL_RE.search(visible_text)

            if label_url and href_host:
                shown_host = (
                    urlparse(label_url.group(0)).hostname
                    or ""
                )

                if (
                    shown_host
                    and shown_host.lower()
                    != href_host.lower()
                ):
                    points += 25

                    reasons.append(
                        (
                            "Displayed link differs from destination",
                            25,
                        )
                    )

                    hard_flags.append("link mismatch")
                    break

    # Generic greetings.
    if re.search(
        r"(?i)\bdear\s+(customer|user)\b",
        lower,
    ):
        points += 5
        reasons.append(
            (
                "Generic greeting used",
                5,
            )
        )

    # Threats combined with urgency.
    if (
        re.search(
            r"(?i)(suspended|blocked|legal action)",
            lower,
        )
        and re.search(
            r"(?i)(urgent|immediately|act now|verify)",
            lower,
        )
    ):
        points += 18

        reasons.append(
            (
                "Threat plus urgency combination",
                18,
            )
        )

        hard_flags.append("urgency + threat")

    # Compare From and Reply-To domains.
    sender = re.search(
        r"(?im)^\s*from:\s*[^\n<]*<[^>]*@([^>\s]+)>",
        text,
    )

    reply = re.search(
        r"(?im)^\s*reply-to:\s*[^\n<]*<[^>]*@([^>\s]+)>",
        text,
    )

    if (
        sender
        and reply
        and sender.group(1).lower()
        != reply.group(1).lower()
    ):
        points += 18

        reasons.append(
            (
                "From and Reply-To domains differ",
                18,
            )
        )

        hard_flags.append("reply-to mismatch")

    return (
        min(points, 100.0),
        reasons,
        hard_flags,
    )


def sms_rules(
    text: str,
    sender: str = "",
) -> tuple[
    float,
    list[tuple[str, float]],
    list[str],
]:
    text = text or ""
    lower = text.lower()

    points = 0.0
    reasons: list[tuple[str, float]] = []
    hard_flags: list[str] = []

    # General SMS risk keywords.
    hits = keyword_hits(
        lower,
        SMS_KEYWORDS,
    )

    # "free" by itself is common in normal conversation.
    # Only treat it as suspicious when it appears in a
    # prize, reward, gift, or similar context.
    if "free" in hits and not re.search(
        r"(?i)\b(?:free\s+(?:gift|prize|reward|cash|voucher)"
        r"|(?:gift|prize|reward|cash|voucher)\s+is\s+free)\b",
        lower,
    ):
        hits.remove("free")

    if hits:
        points_to_add = min(
            22.0,
            len(hits) * 3.5,
        )

        points += points_to_add

        reasons.append(
            (
                f"SMS risk keywords: {', '.join(hits)}",
                points_to_add,
            )
        )

    # Urgency-related phrases.
    hits = keyword_hits(
        lower,
        SMS_URGENCY_PHRASES,
    )

    if hits:
        points_to_add = min(
            15.0,
            len(hits) * 5.0,
        )

        points += points_to_add

        reasons.append(
            (
                f"Urgency language: {', '.join(hits)}",
                points_to_add,
            )
        )

    # Indian-context phishing/scam patterns.
    if any(
        _contains_phrase(lower, phrase)
        for phrase in INDIAN_PHISHING_PHRASES
    ):
        points += 15

        reasons.append(
            (
                "Indian-context phishing/scam pattern detected",
                15,
            )
        )

    # OTP requests.
    otp_request = (
        re.search(
            r"(?i)\b(?:share|send|tell|give)\s+"
            r"(?:me\s+)?(?:the\s+)?otp\b",
            lower,
        )
        or re.search(
            r"(?i)\botp\s+(?:is|code)\b.*(?:http|www\.)",
            lower,
        )
    )

    if otp_request:
        points += 30

        reasons.append(
            (
                "OTP-sharing request detected",
                30,
            )
        )

        hard_flags.append("otp request")

    # Potentially dangerous file extensions.
    if any(
        extension in lower
        for extension in SUSPICIOUS_EXTENSIONS
    ):
        points += 18

        reasons.append(
            (
                "Potentially dangerous file extension mentioned",
                18,
            )
        )

    # Electricity-disconnection scam pattern.
    if re.search(
        r"(?i)\b(?:electricity|bill)\b.*\bdisconnect\b",
        lower,
    ):
        points += 12

        reasons.append(
            (
                "Electricity-disconnect scam pattern",
                12,
            )
        )

    # Numeric sender claiming to represent a bank or service.
    if sender:
        sender_clean = sender.strip()

        if re.fullmatch(
            r"\+?\d{10,13}",
            sender_clean,
        ):
            bank_words = (
                "sbi",
                "hdfc",
                "icici",
                "axis",
                "bank",
                "kyc",
            )

            if any(
                _contains_phrase(lower, word)
                for word in bank_words
            ):
                points += 20

                reasons.append(
                    (
                        "Numeric sender claims a bank/service",
                        20,
                    )
                )

                hard_flags.append("sender mimicry")

    return (
        min(points, 100.0),
        reasons,
        hard_flags,
    )


