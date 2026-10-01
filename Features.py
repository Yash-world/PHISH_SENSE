from __future__ import annotations

import ipaddress
import math
import re
from urllib.parse import urlparse

import numpy as np
import tldextract
from rapidfuzz.fuzz import ratio

from utils.brands import (
    BRANDS,
    CREDENTIAL_KEYWORDS,
    SHORTENERS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_TLDS,
    TRUSTED_DOMAINS,
)


_TLD_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=None
)

_URL_SCHEME_RE = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+.-]*://"
)

_TOKEN_RE = re.compile(
    r"[A-Za-z0-9]+"
)


def normalize_url(url: str) -> str:
    """Return a parseable URL without changing host/path semantics."""
    value = (url or "").strip()

    if not value:
        return ""

    if _URL_SCHEME_RE.match(value):
        return value

    return "http://" + value


def _registered_domain(host: str) -> str:
    ext = _TLD_EXTRACT(host or "")

    return (
        getattr(
            ext,
            "top_domain_under_public_suffix",
            "",
        )
        or getattr(
            ext,
            "registered_domain",
            "",
        )
        or (
            f"{ext.domain}.{ext.suffix}"
            if ext.domain and ext.suffix
            else ext.domain
        )
    )


def _is_ip(host: str) -> bool:
    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True

    except ValueError:
        pass

    try:
        if host.lower().startswith("0x"):
            ipaddress.ip_address(int(host, 16))
            return True

        if host.isdigit() and int(host) <= 0xFFFFFFFF:
            ipaddress.ip_address(int(host))
            return True

    except (ValueError, OverflowError):
        pass

    return False


def _host_ip(host: str) -> bool:
    if _is_ip(host):
        return True

    if host and re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        host,
    ):
        return True

    return False


def _entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = [
        value.count(char) / len(value)
        for char in set(value)
    ]

    return -sum(
        probability * math.log2(probability)
        for probability in counts
        if probability > 0
    )


def _domain_label(host: str) -> str:
    ext = _TLD_EXTRACT(host or "")
    return ext.domain or ""


def _host_tokens(host: str) -> list[str]:
    return [
        token
        for token in re.split(
            r"[.\-_]",
            host.lower(),
        )
        if token
    ]


def _brand_wrong_place(host: str, path: str) -> bool:
    registered = _registered_domain(host).lower()
    combined = f"{host.lower()} {path.lower()}"

    for brand, real_domains in BRANDS.items():
        if re.search(
            rf"\b{re.escape(brand)}\b",
            combined,
        ):
            if not any(
                registered == domain
                or registered.endswith("." + domain)
                for domain in real_domains
            ):
                return True

    return False


def _typosquat(host: str) -> bool:
    if not host or _is_ip(host):
        return False

    labels = _host_tokens(host)

    for label in labels:
        if len(label) < 4:
            continue

        normalized = label.translate(
            str.maketrans(
                {
                    "0": "o",
                    "1": "i",
                    "3": "e",
                    "5": "s",
                }
            )
        )

        for brand in BRANDS:
            if (
                ratio(normalized, brand) >= 80
                and normalized != brand
            ):
                return True

            if (
                abs(len(normalized) - len(brand)) <= 2
                and ratio(normalized, brand) >= 70
            ):
                return True

    return False


def _shortener(host: str) -> bool:
    value = host.lower()

    if value.startswith("www."):
        value = value[4:]

    return value in SHORTENERS


def analyze_url(url: str) -> dict:
    raw = (url or "").strip()

    if not raw:
        raise ValueError("URL is empty.")

    normalized = normalize_url(raw)
    parsed = urlparse(normalized)

    host = (
        parsed.hostname or ""
    ).lower().rstrip(".")

    if not host:
        raise ValueError(
            "URL has no valid hostname."
        )

    registered = _registered_domain(host).lower()
    label = _domain_label(host)

    subdomain = (
        _TLD_EXTRACT(host).subdomain or ""
    ).lower()

    tokens = _host_tokens(host)
    path = parsed.path or ""
    query = parsed.query or ""

    tld = (
        _TLD_EXTRACT(host).suffix or ""
    ).lower()

    query_params = [
        parameter
        for parameter in query.split("&")
        if parameter
    ]

    ip_host = _host_ip(host)
    punycode = "xn--" in host
    non_ascii = any(
        ord(char) > 127
        for char in raw
    )

    suspicious_tld = tld in SUSPICIOUS_TLDS
    brand_wrong = _brand_wrong_place(
        host,
        path,
    )

    typo = (
        False
        if registered in TRUSTED_DOMAINS
        else _typosquat(host)
    )

    shortener = _shortener(host)

    credential_hits = [
        keyword
        for keyword in CREDENTIAL_KEYWORDS
        if re.search(
            rf"\b{re.escape(keyword)}\b",
            f"{host} {path}",
            re.I,
        )
    ]

    try:
        port = parsed.port

    except ValueError as exc:
        raise ValueError(
            "URL contains an invalid port."
        ) from exc

    nonstandard_port = (
        port is not None
        and port not in (80, 443)
    )

    dangerous_extension = any(
        re.search(
            rf"{re.escape(extension)}(?:$|[?#])",
            path,
            re.I,
        )
        for extension in SUSPICIOUS_EXTENSIONS
    )

    domain_entropy = _entropy(label)

    vowels = sum(
        char in "aeiou"
        for char in label.lower()
    )

    consonants = sum(
        char.isalpha()
        and char.lower() not in "aeiou"
        for char in label.lower()
    )

    # Feature order is intentionally kept stable because
    # the trained URL model expects exactly these 36 values.
    features = np.array(
        [
            len(raw),  # 1. URL length
            len(host),  # 2. Host length
            len(path),  # 3. Path length
            raw.count("."),  # 4. Dots
            raw.count("-"),  # 5. Hyphens
            raw.count("_"),  # 6. Underscores
            raw.count("@"),  # 7. @ symbols
            raw.count("%"),  # 8. Encoded characters
            raw.count("/"),  # 9. Slashes
            raw.count("?"),  # 10. Query marker
            raw.count("="),  # 11. Equals signs
            len(query_params),  # 12. Query parameters
            sum(char.isdigit() for char in raw),  # 13. Digits
            sum(char.isupper() for char in raw),  # 14. Uppercase
            sum(char.isalpha() for char in raw),  # 15. Letters
            (
                sum(char.isdigit() for char in raw)
                / max(len(raw), 1)
            ),  # 16. Digit ratio
            len(_TOKEN_RE.findall(host)),  # 17. Host tokens
            (
                len(subdomain.split("."))
                if subdomain
                else 0
            ),  # 18. Subdomain count
            len(label),  # 19. Registered label length
            max(
                (
                    len(token)
                    for token in tokens
                ),
                default=0,
            ),  # 20. Longest host token
            sum(
                char == "-"
                for char in host
            ),  # 21. Host hyphens
            sum(
                char.isdigit()
                for char in host
            ),  # 22. Host digits
            int(suspicious_tld),  # 23. Suspicious TLD
            int(brand_wrong),  # 24. Brand in wrong place
            int(typo),  # 25. Typosquat
            int(punycode),  # 26. Punycode
            int(non_ascii),  # 27. Non-ASCII
            int(shortener),  # 28. URL shortener
            len(credential_hits),  # 29. Credential keywords
            int(nonstandard_port),  # 30. Non-standard port
            int(
                parsed.scheme.lower()
                in {"data", "javascript"}
            ),  # 31. Dangerous scheme
            int("//" in path),  # 32. Double slash
            int(dangerous_extension),  # 33. Dangerous extension
            domain_entropy,  # 34. Domain entropy
            (
                vowels
                / max(consonants, 1)
            ),  # 35. Vowel/consonant ratio
            int(len(raw) > 75),  # 36. Long URL
        ],
        dtype=float,
    )

    hard_flags = []

    if "@" in raw:
        hard_flags.append("@ in URL")

    if ip_host:
        hard_flags.append("IP-address host")

    if punycode or non_ascii:
        hard_flags.append(
            "punycode/homoglyph"
        )

    if brand_wrong:
        hard_flags.append(
            "brand in wrong place"
        )

    if typo:
        hard_flags.append(
            "possible typosquatting"
        )

    if credential_hits and suspicious_tld:
        hard_flags.append(
            "credential keyword + suspicious TLD"
        )

    trusted = registered in TRUSTED_DOMAINS

    return {
        "features": features,
        "normalized": normalized,
        "host": host,
        "registered_domain": registered,
        "path": path,
        "tld": tld,
        "trusted": trusted,
        "hard_flags": hard_flags,
        "signals": {
            "ip_host": ip_host,
            "punycode": punycode,
            "non_ascii": non_ascii,
            "brand_wrong_place": brand_wrong,
            "typosquat": typo,
            "shortener": shortener,
            "credential_hits": credential_hits,
            "suspicious_tld": suspicious_tld,
            "nonstandard_port": nonstandard_port,
            "dangerous_extension": dangerous_extension,
        },
    }


def extract_features(url: str) -> np.ndarray:
    return analyze_url(url)["features"]


# Compatibility helpers retained for older imports.
# Email and SMS production models use text pipelines directly
# instead of these hand-crafted feature vectors.


def extract_email_features(
    email_text: str,
) -> list[float]:
    text = email_text or ""
    words = text.split()

    text_length = max(len(text), 1)
    total_words = max(len(words), 1)

    return [
        float(len(text)),
        float(len(words)),
        float(len(set(words))),
        float(
            len(
                re.findall(
                    r"https?://",
                    text,
                    re.I,
                )
            )
        ),
        float(
            sum(
                char.isdigit()
                for char in text
            )
        ),
        float(
            sum(
                char.isupper()
                for char in text
            )
        ),
        float(
            sum(
                1
                for word in (
                    "verify",
                    "login",
                    "password",
                    "bank",
                    "account",
                    "otp",
                )
                if re.search(
                    rf"\b{word}\b",
                    text,
                    re.I,
                )
            )
        ),
        float(len(text)) / total_words,
        float(
            sum(
                char.isdigit()
                for char in text
            )
        ) / text_length,
    ]


def extract_sms_features(
    sms: str,
) -> list[float]:
    text = sms or ""
    words = text.split()

    text_length = max(len(text), 1)
    total_words = max(len(words), 1)

    return [
        float(len(text)),
        float(len(words)),
        float(
            len(
                re.findall(
                    r"https?://",
                    text,
                    re.I,
                )
            )
        ),
        float(
            sum(
                char.isdigit()
                for char in text
            )
        ),
        float(
            sum(
                char.isupper()
                for char in text
            )
        ),
        float(
            sum(
                1
                for word in (
                    "verify",
                    "login",
                    "bank",
                    "otp",
                    "kyc",
                )
                if re.search(
                    rf"\b{word}\b",
                    text,
                    re.I,
                )
            )
        ),
        float(len(text)) / total_words,
        float(
            sum(
                char.isdigit()
                for char in text
            )
        ) / text_length,
    ]


