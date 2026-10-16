import math
import re
from typing import Dict, Any, List

FEATURE_NAMES = [
    "domain_length",
    "subdomain_length",
    "subdomain_count",
    "shannon_entropy",
    "numeric_ratio",
    "vowel_ratio",
    "consecutive_consonants",
    "special_char_ratio",
    "response_size",
    "ttl"
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not text:
        return 0.0
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    
    length = len(text)
    entropy = 0.0
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)

def calculate_max_consecutive_consonants(text: str) -> int:
    """Finds maximum streak of consecutive consonants in text."""
    consonants_pattern = re.compile(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+')
    matches = consonants_pattern.findall(text)
    if not matches:
        return 0
    return max(len(m) for m in matches)

def extract_features(
    domain: str,
    query_type: str = "A",
    response_size: float = 140.0,
    ttl: float = 300.0
) -> Dict[str, Any]:
    """
    Extracts 10 DNS traffic characteristics for ML classification and UI presentation.
    """
    cleaned_domain = str(domain).strip().lower().rstrip(".")
    if not cleaned_domain:
        cleaned_domain = "unknown"

    parts = cleaned_domain.split(".")
    subdomain_parts = parts[:-2] if len(parts) > 2 else []
    subdomain_str = ".".join(subdomain_parts)

    length = len(cleaned_domain)
    subdomain_len = len(subdomain_str)
    subdomain_cnt = max(len(parts) - 2, 0)

    entropy = calculate_shannon_entropy(cleaned_domain)
    
    numeric_count = len(re.findall(r'[0-9]', cleaned_domain))
    numeric_ratio = round(numeric_count / length if length > 0 else 0.0, 4)

    vowel_count = len(re.findall(r'[aeiou]', cleaned_domain))
    vowel_ratio = round(vowel_count / length if length > 0 else 0.0, 4)

    consecutive_consonants = calculate_max_consecutive_consonants(cleaned_domain)

    special_count = len(re.findall(r'[^a-z0-9.]', cleaned_domain))
    special_ratio = round(special_count / length if length > 0 else 0.0, 4)

    try:
        resp_size = float(response_size)
    except (ValueError, TypeError):
        resp_size = 140.0

    try:
        ttl_val = float(ttl)
    except (ValueError, TypeError):
        ttl_val = 300.0

    feature_dict = {
        "domain_length": length,
        "subdomain_length": subdomain_len,
        "subdomain_count": subdomain_cnt,
        "shannon_entropy": entropy,
        "numeric_ratio": numeric_ratio,
        "vowel_ratio": vowel_ratio,
        "consecutive_consonants": consecutive_consonants,
        "special_char_ratio": special_ratio,
        "response_size": resp_size,
        "ttl": ttl_val
    }

    # Vector in exact training order
    vector = [feature_dict[name] for name in FEATURE_NAMES]

    return {
        "domain": cleaned_domain,
        "query_type": str(query_type).upper(),
        "features": feature_dict,
        "vector": vector,
        # Frontend-friendly characteristic names
        "display_metrics": {
            "queryLength": length,
            "domainLength": length,
            "subdomainCount": subdomain_cnt,
            "entropy": round(entropy, 2),
            "numericRatio": round(numeric_ratio, 2),
            "vowelRatio": round(vowel_ratio, 2),
            "responseSize": resp_size,
            "ttl": ttl_val
        }
    }

def generate_risk_reasons(features: Dict[str, Any]) -> List[str]:
    """Generates human-readable explanations for why a domain is deemed suspicious."""
    reasons = []
    if features.get("shannon_entropy", 0) > 3.5:
        reasons.append(f"High Shannon entropy ({features['shannon_entropy']:.2f}) indicates random/encoded payload.")
    if features.get("domain_length", 0) > 45:
        reasons.append(f"Unusually long domain query ({features['domain_length']} chars) typical of tunneling.")
    if features.get("numeric_ratio", 0) > 0.25:
        reasons.append(f"Elevated numeric ratio ({features['numeric_ratio'] * 100:.1f}%) matches hex/base32 encoding.")
    if features.get("vowel_ratio", 0) < 0.18 and features.get("domain_length", 0) > 20:
        reasons.append(f"Abnormally low vowel ratio ({features['vowel_ratio'] * 100:.1f}%) suggests machine-generated ciphertext.")
    if features.get("consecutive_consonants", 0) >= 8:
        reasons.append(f"Long consonant cluster ({features['consecutive_consonants']} chars) indicates non-lexical string.")
    if features.get("subdomain_count", 0) >= 3:
        reasons.append(f"Excessive subdomain depth ({features['subdomain_count']} levels) used for multi-label exfiltration.")
    if features.get("ttl", 300) <= 60:
        reasons.append(f"Ultra-low TTL ({int(features['ttl'])}s) prevents DNS caching during interactive C2 channels.")
    if features.get("response_size", 140) >= 400:
        reasons.append(f"Large DNS response payload ({int(features['response_size'])} bytes) indicates upstream data transfer.")
    
    if not reasons:
        reasons.append("Model detected subtle multi-variable anomaly pattern across DNS characteristics.")
        
    return reasons
