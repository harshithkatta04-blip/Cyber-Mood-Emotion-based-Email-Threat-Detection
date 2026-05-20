# Dataset Catalog (All Model Tracks)

This is the dataset list mapped to each CyberMood model track.

## 1) Email Text Phishing Model

- Primary seed dataset: UCI SMS Spam Collection  
  https://archive.ics.uci.edu/dataset/228/sms+spam+collection
- Auto-download support in project: **Yes** (`ml/scripts/download_uci_seed_datasets.py`)
- Local output file: `ml/data/raw/email_text_phishing.csv`

## 2) URL / Website Phishing Model

- Primary seed dataset: UCI Phishing Websites  
  https://archive.ics.uci.edu/dataset/327/phishing+websites
- Auto-download support in project: **Yes** (`ml/scripts/download_uci_seed_datasets.py`)
- Local output file: `ml/data/raw/url_phishing_tabular.csv`

## 3) Image Spoof / Fake Branding / Logo Model

- FlickrLogos-32 (official university page)  
  https://www.uni-augsburg.de/de/fakultaet/fai/informatik/prof/mmc/research/datensatze/flickrlogos/
- OpenLogo (community benchmark listing)  
  https://paperswithcode.com/dataset/openlogo
- Hugging Face deepfake-vs-real image dataset (used by builder script)  
  https://huggingface.co/datasets/itsLeen/deepfake_vs_real_image_detection
- Auto-download support in project: **Yes** (`ml/scripts/build_real_multimodal_datasets.py`)
- Expected local feature file: `ml/data/raw/image_spoof_features.csv`

## 4) Audio Impersonation / Deepfake Voice Model

- ASVspoof official hub (challenge datasets and protocols)  
  https://www.asvspoof.org/
- Hugging Face deepfake-audio-detection dataset (used by builder script)  
  https://huggingface.co/datasets/garystafford/deepfake-audio-detection
- Auto-download support in project: **Yes** (`ml/scripts/build_real_multimodal_datasets.py`)
- Expected local feature file: `ml/data/raw/audio_impersonation_features.csv`

## 5) Steganography Forensics Model

- ALASKA2 challenge (IEEE page + Kaggle competition)  
  https://signalprocessingsociety.org/publications-resources/data-challenges/alaska-2-steganalysis-challenge
- ALASKA official site  
  https://alaska.utt.fr/
- BOSS/BOWS steganalysis resources  
  https://dde.binghamton.edu/download/stego_algorithms/
- Hugging Face BOWS2 WOW stego classification (used by builder script)  
  https://huggingface.co/datasets/frostymelonade/BOWS2-WOW-stego-classification
- Auto-download support in project: **Yes** (`ml/scripts/build_real_multimodal_datasets.py`)
- Expected local feature file: `ml/data/raw/stego_forensics_features.csv`

## Notes

- This project trains from **CSV feature tables**. For image/audio/stego datasets, first extract features into CSV and then run `train_suite.py`.
- Template headers are provided in `ml/data/templates/`.
