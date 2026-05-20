# CyberMood ML Training Workspace

This folder adds a reproducible training/evaluation pipeline for all CyberMood model tracks:

- Email text phishing model
- URL phishing model
- Image spoof/forensics model
- Audio impersonation/forensics model
- Steganography forensics model

## Target Split

The trainer enforces:

- Train: 70%
- Validation: 10%
- Test: 20%

using stratified splitting per label.

## Accuracy Target

`training_plan.json` sets `target_accuracy=0.97`.

Important: the pipeline can enforce and report the target, but no pipeline can truthfully guarantee 97% on every real-world dataset. The report marks each trained task as `meetsTarget: true/false`.

## Quick Start

1. Install dependencies

```bash
pip install -r requirements.txt
```

2. Download seed public datasets (email + URL)

```bash
python ml/scripts/download_uci_seed_datasets.py
```

3. Build real image/audio/stego feature datasets from public sources

```bash
python ml/scripts/build_real_multimodal_datasets.py
```

4. (Optional) Add your own custom raw datasets in `ml/data/raw/`

- `image_spoof_features.csv`
- `audio_impersonation_features.csv`
- `stego_forensics_features.csv`

Template headers are provided in `ml/data/templates/`.

5. Train all tasks and generate metrics

```bash
python ml/scripts/train_suite.py --config ml/config/training_plan.json --target-accuracy 0.97
```

## Output Artifacts

- Split CSVs: `ml/data/splits/<task>/train.csv`, `validation.csv`, `test.csv`
- Models: `ml/models/<task>.joblib`
- Metrics: `ml/reports/latest_metrics.json`
