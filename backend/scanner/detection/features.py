import ipaddress
import math
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from functools import lru_cache
from urllib.parse import parse_qsl, urlsplit

import tldextract

SUSPICIOUS_KEYWORDS = {
    "account", "authenticate", "billing", "confirm", "credential", "login",
    "payment", "password", "secure", "signin", "suspend", "update", "verify",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "ow.ly", "rb.gy"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "work"}
BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon", "facebook", "instagram",
    "netflix", "linkedin", "whatsapp", "sbi", "hdfc", "icici",
}
CHAR_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})
HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "і": "i", "ї": "i", "о": "o", "р": "p",
    "с": "c", "х": "x", "у": "y", "ј": "j", "ӏ": "l", "Α": "a",
    "Β": "b", "Ε": "e", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n",
    "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "μ": "m",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "y", "χ": "x",
    "в": "b", "к": "k", "м": "m", "т": "t", "ѕ": "s",
})
FEATURE_SCHEMA_VERSION = 2
FEATURE_NAMES = [
    "url_length", "domain_length", "dot_count", "hyphen_count", "special_char_count",
    "subdomain_count", "has_ip_address", "uses_https", "digit_count",
    "suspicious_keyword_count", "has_at_symbol", "is_shortened", "suspicious_tld",
    "path_length", "query_parameter_count", "has_fragment", "url_entropy",
    "brand_keyword_count", "brand_lookalike", "host_has_punycode", "has_port",
]
_PUBLIC_SUFFIXES = tldextract.TLDExtract(
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)
_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _entropy(value):
    if not value:
        return 0.0
    counts = Counter(value)
    return round(-sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()), 3)


def _is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_valid_hostname(host):
    if not host:
        return False
    normalized_host = host.lower().rstrip(".")
    try:
        ascii_host = normalized_host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    if len(ascii_host) > 253:
        return False
    if _is_ip(normalized_host):
        return True
    return all(
        _HOST_LABEL_PATTERN.fullmatch(label)
        for label in ascii_host.split(".")
    )


@lru_cache(maxsize=65536)
def _domain_parts(host):
    if not host or _is_ip(host):
        return host, ""
    extracted = _PUBLIC_SUFFIXES(host)
    if extracted.suffix:
        return extracted.domain, extracted.suffix
    labels = host.split(".")
    if len(labels) > 1:
        return labels[-2], labels[-1]
    return host, ""


def registrable_domain(host):
    """Return the public-suffix-aware domain used for hostname grouping."""
    domain, suffix = _domain_parts(host.lower().rstrip("."))
    normalized_host = host.lower().rstrip(".")
    return f"{domain}.{suffix}" if domain and suffix else normalized_host


def _suffix_label_count(host):
    if _is_ip(host):
        return max(1, len(host.split(".")) - 1)
    _, suffix = _domain_parts(host)
    return len(suffix.split(".")) if suffix else 1


def _decoded_host_labels(host):
    labels = []
    for label in host.split("."):
        if label.lower().startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label.lower())
    return labels


def _edit_distance(left, right):
    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            current.append(min(
                current[-1] + 1,
                previous[right_index] + 1,
                previous[right_index - 1] + (left_char != right_char),
            ))
        previous = current
    return previous[-1]


@lru_cache(maxsize=65536)
def _brand_match(host):
    if _is_ip(host):
        return 0.0, ""
    labels = _decoded_host_labels(host)
    registrable_label, suffix = _domain_parts(host)
    suffix_label_count = len(suffix.split(".")) if suffix else 1
    registrable_index = len(labels) - suffix_label_count - 1 if registrable_label else -1
    labels_to_check = [registrable_label, *labels[:max(0, registrable_index)]]
    matches = []
    for brand in BRANDS:
        for label in labels_to_check:
            parts = label.split("-")
            tokens = [label, *parts]
            tokens.extend(
                parts[index] + parts[index + 1]
                for index in range(len(parts) - 1)
            )
            for token in tokens:
                normalized = (unicodedata.normalize("NFKC", token).casefold()
                              .translate(HOMOGLYPH_MAP).translate(CHAR_MAP))
                if normalized == brand and label == registrable_label == brand:
                    continue
                sequence_similarity = SequenceMatcher(None, brand, normalized).ratio()
                edit_similarity = 1 - _edit_distance(brand, normalized) / max(len(brand), len(normalized), 1)
                similarity = max(sequence_similarity, edit_similarity)
                if similarity >= 0.75:
                    matches.append((similarity, brand))
    return max(matches, default=(0.0, ""), key=lambda item: item[0])


def extract_url_features(url):
    """Return JSON-serializable lexical features for an absolute HTTP(S) URL."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError("Enter a non-empty URL of at most 2,048 characters.")
    if url != url.strip() or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("The URL must not contain whitespace or control characters.")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError as error:
        raise ValueError("The URL format is invalid.") from error
    if (parts.scheme.lower() not in {"http", "https"} or not host
            or parts.username is not None or parts.password is not None):
        raise ValueError("Use an absolute HTTP(S) URL without embedded credentials.")
    if not is_valid_hostname(host):
        raise ValueError("The hostname is invalid.")

    labels = [label for label in host.split(".") if label]
    suffix_label_count = _suffix_label_count(host)
    main_domain, _ = _domain_parts(host)
    main_domain = main_domain or host
    keyword_text = f"{host} {parts.path} {parts.query}".lower()
    brand_similarity, suspected_brand = _brand_match(host)
    suffix = labels[-1] if labels else ""
    return {
        "url_length": len(url),
        "domain_length": len(host),
        "dot_count": host.count("."),
        "hyphen_count": url.count("-"),
        "special_char_count": sum(char in "@%_=$&;" for char in url),
        "subdomain_count": max(0, len(labels) - suffix_label_count - 1),
        "has_ip_address": _is_ip(host),
        "uses_https": parts.scheme.lower() == "https",
        "digit_count": sum(char.isdigit() for char in url),
        "suspicious_keyword_count": sum(keyword in keyword_text for keyword in SUSPICIOUS_KEYWORDS),
        "has_at_symbol": "@" in url,
        "is_shortened": host in SHORTENERS,
        "suspicious_tld": suffix in SUSPICIOUS_TLDS,
        "path_length": len(parts.path),
        "query_parameter_count": len(parse_qsl(parts.query, keep_blank_values=True)),
        "has_fragment": bool(parts.fragment),
        "url_entropy": _entropy(url.lower()),
        "brand_keyword_count": sum(brand in keyword_text for brand in BRANDS),
        "brand_lookalike": bool(suspected_brand),
        "suspected_brand": suspected_brand,
        "brand_similarity": round(brand_similarity, 3),
        "host_has_punycode": any(label.lower().startswith("xn--") for label in labels),
        "has_port": port is not None,
        "registrable_label": main_domain,
        "domain_suffix": suffix,
    }


def model_feature_row(features):
    return [int(features[name]) if isinstance(features[name], bool) else features[name]
            for name in FEATURE_NAMES]