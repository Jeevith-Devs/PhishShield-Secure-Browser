"""
PhishShield Dataset Curation Script
Downloads and preprocesses public phishing/benign URL datasets.

Sources:
  - PhishTank (phishing): https://www.phishtank.com/developer_info.php
  - URLhaus (malware/phishing): https://urlhaus.abuse.ch/api/
  - OpenPhish (phishing): https://openphish.com/phishing_feeds.html
  - Tranco Top-1M (benign): https://tranco-list.eu/

Usage:
    python -m ml.datasets.curate --output-dir ml/datasets
"""
import argparse
import csv
import os
import sys
import time
from pathlib import Path
from urllib.request import urlretrieve
from typing import List, Tuple

# ─── Source Definitions ───────────────────────────────────────────────────────

BENIGN_SOURCES = [
    # Tranco Top-1M — first 10k as benign baseline
    ("https://tranco-list.eu/top-1m.csv.zip", "tranco_top1m.csv.zip", "tranco"),
]

PHISHING_SOURCES = [
    # OpenPhish free feed (no API key required)
    ("https://openphish.com/feed.txt", "openphish_feed.txt", "openphish"),
]


def download_file(url: str, dest: str) -> bool:
    """Downloads a file with progress indication."""
    try:
        print(f"  Downloading: {url}")
        urlretrieve(url, dest)
        print(f"  Saved to: {dest}")
        return True
    except Exception as e:
        print(f"  [WARN] Failed to download {url}: {e}")
        return False


def parse_openphish(filepath: str) -> List[Tuple[str, int]]:
    """Parses OpenPhish feed — one URL per line."""
    records = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                url = line.strip()
                if url and url.startswith(("http://", "https://")):
                    records.append((url, 1))
    except Exception as e:
        print(f"  [WARN] Could not parse {filepath}: {e}")
    return records


def generate_benign_sample(n: int = 10000) -> List[Tuple[str, int]]:
    """
    Generates benign URL samples from well-known safe domains.
    In Sprint 1, replace with full Tranco top-1M download.
    """
    SAFE_DOMAINS = [
        "google.com", "microsoft.com", "apple.com", "amazon.com",
        "wikipedia.org", "github.com", "stackoverflow.com", "reddit.com",
        "youtube.com", "netflix.com", "linkedin.com", "twitter.com",
        "facebook.com", "instagram.com", "nytimes.com", "bbc.com",
    ]
    PATHS = ["/", "/about", "/help", "/search?q=test", "/products", "/contact", "/login"]
    records = []
    import random
    random.seed(42)
    for _ in range(n):
        domain = random.choice(SAFE_DOMAINS)
        path = random.choice(PATHS)
        scheme = random.choice(["https://", "https://www."])
        records.append((f"{scheme}{domain}{path}", 0))
    return records


def save_dataset(records: List[Tuple[str, int]], filepath: str):
    """Saves labeled URL records as CSV."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(records)
    print(f"  Saved {len(records)} records -> {filepath}")


def curate(output_dir: str):
    """Main dataset curation pipeline."""
    print("\n[PhishShield] Dataset Curation Pipeline")
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    all_phishing: List[Tuple[str, int]] = []
    all_benign: List[Tuple[str, int]] = []

    # Download phishing feeds
    print("\n[1/3] Downloading phishing URL feeds...")
    for url, filename, source in PHISHING_SOURCES:
        dest = output_path / filename
        if download_file(url, str(dest)):
            if source == "openphish":
                records = parse_openphish(str(dest))
                all_phishing.extend(records)
                print(f"  Parsed {len(records)} phishing URLs from OpenPhish")
        time.sleep(1)

    # Generate benign samples
    print("\n[2/3] Generating benign URL baseline...")
    benign_records = generate_benign_sample(n=max(len(all_phishing), 5000))
    all_benign.extend(benign_records)
    print(f"  Generated {len(benign_records)} benign URL samples")

    # Save combined dataset
    print("\n[3/3] Saving labeled datasets...")
    save_dataset(all_phishing, str(output_path / "phishing_urls.csv"))
    save_dataset(all_benign, str(output_path / "benign_urls.csv"))

    combined = all_phishing + all_benign
    import random
    random.shuffle(combined)
    save_dataset(combined, str(output_path / "combined_dataset.csv"))

    print(f"\n[PhishShield] Dataset curation complete.")
    print(f"  Total: {len(combined)} URLs | Phishing: {len(all_phishing)} | Benign: {len(all_benign)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PhishShield Dataset Curation")
    parser.add_argument("--output-dir", default="ml/datasets", help="Output directory for curated datasets")
    args = parser.parse_args()
    curate(args.output_dir)
