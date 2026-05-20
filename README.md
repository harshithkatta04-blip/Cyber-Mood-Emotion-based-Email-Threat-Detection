# CyberMood Emotion Based Email Threat Detector

Flask + SQLite web app for phishing and social-engineering detection using emotion and content-based risk scoring across:

- Email text
- Links
- Attachments
- Embedded media references

## Run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Multipage frontend

- `GET /` -> Dashboard
- `GET /email` -> Email Lab (multimodal email analysis)
- `GET /website` -> Website Lab (URL/page phishing prediction)
- `GET /intel` -> Realtime Intel feed (auto-updating combined activity)

## Features

- NLP-style emotional manipulation detection (fear, urgency, authority, greed, guilt)
- Psychological pressure technique detection
- Social-engineering intent scoring
- URL phishing heuristics
- Attachment/media risk scoring
- OCR extraction from images/video/GIF frames
- QR-code extraction from images/video/GIF frames
- PDF text extraction for embedded phishing cues
- Audio transcription-based social-engineering cue detection (Whisper tiny model)
- JSON output exactly matching requested schema
- SQLite scan history with dashboard view
- Website phishing analysis endpoint: `POST /api/website/analyze`
- Website scan history endpoint: `GET /api/website/history`
- Chrome extension (in `extension/`) for live website verdict popup (`Legitimate / Safe / Unsafe`)
- Website screenshot OCR + QR signal extraction (when extension provides page capture)
- Realtime frontend features: navbar multipage UX, backend health pulse, auto-refresh history/intel, live input signal preview

## Multimodal runtime notes

- OCR uses `pytesseract`; install Tesseract OCR on your system and ensure `tesseract` is in PATH.
- Audio transcription uses `faster-whisper` and loads `tiny.en` model on first audio analysis (automatic download).
- If optional engines are unavailable, the app still runs and reports skipped checks in `multimediaRisks`.

## Chrome extension

See `extension/README.md` for loading and usage instructions.

## ML training workspace

For dataset catalog, 70/10/20 splitting, and multi-model training/evaluation:

- See `ml/README.md`
- Dataset sources: `ml/DATASET_CATALOG.md`
- Train/eval report output: `ml/reports/latest_metrics.json`
