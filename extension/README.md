# CyberMood Chrome Extension

## Load extension

1. Open `chrome://extensions`.
2. Enable `Developer mode`.
3. Click `Load unpacked`.
4. Select the `extension` folder.

## Start backend

Run CyberMood Flask backend first:

```bash
python app.py
```

Default backend endpoint used by extension:

`http://127.0.0.1:5000/api/website/analyze`

You can change this inside extension popup (`Backend API` section).

## Features

- Auto-scan current tab and show `Legitimate / Safe / Unsafe`.
- Manual URL phishing check.
- Protection toggle.
- Stats: URLs checked, threats blocked, warnings shown.
- Indicator details list.
- Captured page screenshot analysis (OCR + QR signal support via backend).
- Backend model first, automatic fallback local model when backend is unavailable.
