import os
import sys
from pathlib import Path
import httpx
import pandas as pd

DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Official Mendeley Data v2 file UUIDs verified from DOI 10.17632/mzn9hvdcxg.2
FILES_TO_DOWNLOAD = {
    "dtqbc-b-train.csv": "5c6d4722-b0d5-44f3-a9e2-b1066553f318",
    "dtqbc-b-val.csv": "44c9b81a-0af9-4f99-9643-650c720c5acf",
    "dtqbc-b-test.csv": "5b6e21d5-180f-4ba4-b57e-1f246fd78326",
}

def download_files():
    client = httpx.Client(follow_redirects=True, timeout=60.0)
    for fname, uuid in FILES_TO_DOWNLOAD.items():
        dest = DATA_DIR / fname
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[EXISTS] {fname} ({dest.stat().st_size:,} bytes)")
            continue

        url = f"https://data.mendeley.com/public-files/datasets/mzn9hvdcxg/files/{uuid}/file_downloaded"
        print(f"[DOWNLOADING] {fname} from {url}...")
        with client.stream("GET", url) as response:
            if response.status_code != 200:
                raise RuntimeError(f"Failed to download {fname}: HTTP {response.status_code}")
            with open(dest, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=128 * 1024):
                    f.write(chunk)
        print(f"[DOWNLOADED] {fname} ({dest.stat().st_size:,} bytes)")

def extract_base_domain(domain: str) -> str:
    """Extracts approximate second-level registrable domain (e.g. sub.example.com -> example.com)."""
    parts = str(domain).strip().lower().rstrip(".").split(".")
    if len(parts) >= 2:
        # Basic two-part suffix check for co.uk, com.au, etc.
        if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "edu", "gov") and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return str(domain).strip().lower()

def validate_dataset():
    print("\n" + "=" * 60)
    print("DATASET VALIDATION & SCHEMA INSPECTION")
    print("=" * 60)

    dfs = {}
    total_raw_rows = 0

    for fname in FILES_TO_DOWNLOAD.keys():
        fpath = DATA_DIR / fname
        print(f"\n--- File: {fname} ---")
        df = pd.read_csv(fpath)
        dfs[fname] = df
        total_raw_rows += len(df)

        print(f"File size: {fpath.stat().st_size:,} bytes")
        print(f"Total rows: {len(df):,}")
        print(f"Columns: {list(df.columns)}")
        print(f"Data types:\n{df.dtypes}")
        print(f"Missing values:\n{df.isnull().sum()}")

        label_col = [c for c in df.columns if c.lower() in ("label", "class", "target")][0]
        domain_col = [c for c in df.columns if c.lower() in ("domain", "query", "qname", "name")][0]

        print(f"Detected Domain Column: '{domain_col}', Label Column: '{label_col}'")
        print(f"Class distribution in {fname}:")
        print(df[label_col].value_counts().to_dict())
        
        # Sample inspection
        print("Sample Benign (0):", df[df[label_col] == 0][domain_col].head(3).tolist())
        print("Sample Tunnel (1):", df[df[label_col] == 1][domain_col].head(3).tolist())

    # Combine all splits for holistic leakage and duplication analysis
    print("\n" + "=" * 60)
    print("UNIFIED LEAKAGE & DUPLICATION AUDIT")
    print("=" * 60)
    
    combined = pd.concat(dfs.values(), ignore_index=True)
    domain_col = [c for c in combined.columns if c.lower() in ("domain", "query", "qname", "name")][0]
    label_col = [c for c in combined.columns if c.lower() in ("label", "class", "target")][0]

    # Clean strings
    combined[domain_col] = combined[domain_col].astype(str).str.strip().str.lower().str.rstrip(".")

    total_combined = len(combined)
    unique_domains = combined[domain_col].nunique()
    duplicate_count = total_combined - unique_domains

    print(f"Total combined rows across all 3 original splits: {total_combined:,}")
    print(f"Unique domain queries: {unique_domains:,}")
    print(f"Duplicate domain queries: {duplicate_count:,} ({duplicate_count / total_combined * 100:.2f}%)")

    # Check conflicting labels (same domain with both label 0 and label 1)
    label_grouped = combined.groupby(domain_col)[label_col].nunique()
    conflicting = label_grouped[label_grouped > 1]
    print(f"Conflicting labels (same domain marked as both 0 and 1): {len(conflicting):,}")
    if len(conflicting) > 0:
        print("Sample conflicting domains:", conflicting.head(5).index.tolist())

    # Deduplicate keeping first
    deduped = combined.drop_duplicates(subset=[domain_col], keep="first")
    print(f"\nDeduplicated dataset size: {len(deduped):,}")
    print(f"Deduplicated Class Distribution: {deduped[label_col].value_counts().to_dict()}")

    # Registrable Base Domain (SLD) Grouping analysis
    deduped["base_domain"] = deduped[domain_col].apply(extract_base_domain)
    unique_base_domains = deduped["base_domain"].nunique()
    print(f"Unique Base Domains (SLDs): {unique_base_domains:,}")

    # Inspect class breakdown by base domain
    base_class_overlap = deduped.groupby("base_domain")[label_col].nunique()
    shared_base_domains = base_class_overlap[base_class_overlap > 1]
    print(f"Base domains containing BOTH benign and tunneling queries: {len(shared_base_domains):,}")
    if len(shared_base_domains) > 0:
        print("Shared base domains:", shared_base_domains.head(5).index.tolist())

    print("\nTop 10 Base Domains by Query Count:")
    print(deduped["base_domain"].value_counts().head(10))

    # Save validated deduplicated dataset for training
    clean_csv = DATA_DIR / "bubnov_deduplicated.csv"
    deduped[[domain_col, label_col, "base_domain"]].to_csv(clean_csv, index=False)
    print(f"\n[SAVED] Clean deduplicated dataset written to: {clean_csv} ({clean_csv.stat().st_size:,} bytes)")

if __name__ == "__main__":
    download_files()
    validate_dataset()
