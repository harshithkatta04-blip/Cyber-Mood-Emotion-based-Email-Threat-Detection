import csv
import io
import zipfile
from pathlib import Path

import requests


SMS_SPAM_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
PHISHING_URL = "https://archive.ics.uci.edu/static/public/327/phishing+websites.zip"


def _download_bytes(url: str) -> bytes:
    response = requests.get(url, timeout=120)
    response.raise_for_status()
    return response.content


def _save_sms_spam(raw_dir: Path):
    data = _download_bytes(SMS_SPAM_URL)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        member = next((n for n in zf.namelist() if n.lower().endswith("smsspamcollection")), None)
        if not member:
            raise RuntimeError("Could not find SMSSpamCollection in UCI zip.")
        raw = zf.read(member).decode("utf-8", errors="ignore").splitlines()

    out_path = raw_dir / "email_text_phishing.csv"
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "source"])
        writer.writeheader()
        for line in raw:
            if "\t" not in line:
                continue
            label_raw, text = line.split("\t", 1)
            label = "phishing_or_spam" if label_raw.strip().lower() == "spam" else "legitimate"
            writer.writerow({"text": text.strip(), "label": label, "source": "UCI_SMS_Spam_Collection"})
    print(f"Wrote: {out_path}")


def _parse_arff_rows(arff_text: str):
    in_data = False
    rows = []
    for raw_line in arff_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("%"):
            continue
        if not in_data:
            if line.lower() == "@data":
                in_data = True
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        rows.append(parts)
    return rows


def _save_phishing_tabular(raw_dir: Path):
    data = _download_bytes(PHISHING_URL)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        member = next((n for n in zf.namelist() if n.lower().endswith(".arff")), None)
        if not member:
            raise RuntimeError("Could not find ARFF file in UCI phishing zip.")
        arff_text = zf.read(member).decode("utf-8", errors="ignore")

    rows = _parse_arff_rows(arff_text)
    if not rows:
        raise RuntimeError("No rows parsed from phishing ARFF dataset.")

    feature_count = len(rows[0]) - 1
    fieldnames = [f"f{i+1}" for i in range(feature_count)] + ["label", "source"]
    out_path = raw_dir / "url_phishing_tabular.csv"
    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            record = {f"f{i+1}": row[i] for i in range(feature_count)}
            target = row[-1]
            label = "phishing" if target in {"-1", "1"} and target == "-1" else "legitimate"
            record["label"] = label
            record["source"] = "UCI_Phishing_Websites"
            writer.writerow(record)
    print(f"Wrote: {out_path}")


def main():
    raw_dir = Path("ml/data/raw")
    raw_dir.mkdir(parents=True, exist_ok=True)
    _save_sms_spam(raw_dir)
    _save_phishing_tabular(raw_dir)
    print("Seed datasets downloaded and normalized.")
    print("Add additional model-specific datasets (image/audio/stego CSVs) in ml/data/raw/ as needed.")


if __name__ == "__main__":
    main()
