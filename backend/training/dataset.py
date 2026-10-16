"""
WARNING: SYNTHETIC BENCHMARK DATASET GENERATOR
This module algorithmically generates synthetic demonstration data for offline testing.
It does NOT represent real-world network traffic captures.
For research-grade models, use the verified Yakov Bubnov Mendeley Data v2 pipeline.
"""

import math
import random
import string
from typing import List, Dict, Any

# Representative benign domains and prefixes
BENIGN_BASE_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "github.com", "amazon.com",
    "microsoft.com", "apple.com", "wikipedia.org", "twitter.com", "linkedin.com",
    "cloudflare.com", "netflix.com", "instagram.com", "reddit.com", "yahoo.com",
    "spotify.com", "dropbox.com", "slack.com", "zoom.us", "salesforce.com",
    "adobe.com", "twitch.tv", "medium.com", "quora.com", "stackoverflow.com",
    "cnn.com", "bbc.co.uk", "nytimes.com", "weather.com", "office.com",
    "azure.com", "aliexpress.com", "bing.com", "ebay.com", "wordpress.org"
]

BENIGN_SUBDOMAINS = [
    "www", "api", "cdn", "mail", "auth", "static", "dev", "staging",
    "assets", "img", "portal", "login", "cloud", "app", "blog", "m",
    "support", "docs", "secure", "media", "video", "data", "gateway"
]

TUNNELING_TARGET_DOMAINS = [
    "tunnel-exfil.net", "data-sync.org", "dns-c2.com", "stealth-pipe.info",
    "enc-stream.net", "dns-relay.io", "covert-channel.biz", "tunnel-data.example.com",
    "data-transfer.example.net", "encoded.example.net", "exfil-zone.org"
]

BASE32_CHARS = "abcdefghijklmnopqrstuvwxyz234567"
HEX_CHARS = "0123456789abcdef"
BASE64_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

def generate_benign_record() -> Dict[str, Any]:
    base = random.choice(BENIGN_BASE_DOMAINS)
    r = random.random()
    if r < 0.35:
        # Bare domain or www
        domain = f"www.{base}" if random.random() < 0.5 else base
    elif r < 0.75:
        sub = random.choice(BENIGN_SUBDOMAINS)
        domain = f"{sub}.{base}"
    else:
        sub1 = random.choice(BENIGN_SUBDOMAINS)
        sub2 = random.choice(["us-east", "eu-west", "v1", "v2", "live", "prod", "corp"])
        domain = f"{sub2}.{sub1}.{base}"
        
    query_type = random.choice(["A", "A", "A", "AAAA", "CNAME", "MX"])
    response_size = random.randint(80, 220)
    ttl = random.choice([300, 300, 600, 1800, 3600, 86400])
    
    return {
        "domain": domain,
        "query_type": query_type,
        "response_size": response_size,
        "ttl": ttl,
        "label": 0  # Normal / Benign
    }

def generate_tunneling_record() -> Dict[str, Any]:
    target = random.choice(TUNNELING_TARGET_DOMAINS)
    tunnel_type = random.choice(["hex", "base32", "base64", "chunked"])
    
    if tunnel_type == "hex":
        payload_len = random.randint(18, 48)
        payload = "".join(random.choices(HEX_CHARS, k=payload_len))
        domain = f"{payload}.{target}"
    elif tunnel_type == "base32":
        payload_len = random.randint(20, 52)
        payload = "".join(random.choices(BASE32_CHARS, k=payload_len))
        domain = f"{payload}.{target}"
    elif tunnel_type == "base64":
        payload_len = random.randint(22, 50)
        # DNS safe base64
        payload = "".join(random.choices(BASE64_CHARS.lower(), k=payload_len))
        domain = f"{payload}.{target}"
    else:
        # Multi-label chunked payload (e.g. dnscat2 / iodine style: <seq>.<data>.<target>)
        seq = "".join(random.choices(string.digits, k=4))
        chunk1 = "".join(random.choices(HEX_CHARS, k=random.randint(12, 24)))
        chunk2 = "".join(random.choices(HEX_CHARS, k=random.randint(12, 24)))
        domain = f"{seq}.{chunk1}.{chunk2}.{target}"

    query_type = random.choice(["TXT", "TXT", "A", "A", "CNAME", "NULL"])
    response_size = random.randint(450, 950)
    ttl = random.choice([15, 30, 45, 60, 90])  # Short TTL typical for tunneling channels
    
    return {
        "domain": domain,
        "query_type": query_type,
        "response_size": response_size,
        "ttl": ttl,
        "label": 1  # Tunneling Attack
    }

def generate_dataset(n_samples: int = 4000) -> List[Dict[str, Any]]:
    """Generates a balanced dataset of benign and DNS tunneling samples."""
    random.seed(42)
    dataset = []
    half = n_samples // 2
    for _ in range(half):
        dataset.append(generate_benign_record())
    for _ in range(half):
        dataset.append(generate_tunneling_record())
        
    random.shuffle(dataset)
    return dataset
