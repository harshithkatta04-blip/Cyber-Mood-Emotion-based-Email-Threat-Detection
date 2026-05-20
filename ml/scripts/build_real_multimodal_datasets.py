import csv
import io
import math
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
import requests

try:
    import av  # type: ignore
except Exception:
    av = None

try:
    import cv2  # type: ignore
except Exception:
    cv2 = None

try:
    from PIL import Image  # type: ignore
except Exception:
    Image = None

try:
    import pytesseract  # type: ignore
except Exception:
    pytesseract = None


RAW_DIR = Path("ml/data/raw")
DOWNLOAD_DIR = Path("ml/data/downloads")
DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
RAW_DIR.mkdir(parents=True, exist_ok=True)

IMAGE_PARQUET_URLS = [
    "https://huggingface.co/datasets/itsLeen/deepfake_vs_real_image_detection/resolve/main/data/train-00000-of-00011.parquet",
]

AUDIO_PARQUET_URLS = [
    "https://huggingface.co/datasets/garystafford/deepfake-audio-detection/resolve/main/data/train-00000-of-00002.parquet",
    "https://huggingface.co/datasets/garystafford/deepfake-audio-detection/resolve/main/data/train-00001-of-00002.parquet",
]

STEGO_X_URL = "https://huggingface.co/datasets/frostymelonade/BOWS2-WOW-stego-classification/resolve/main/X_val.npy"
STEGO_Y_URL = "https://huggingface.co/datasets/frostymelonade/BOWS2-WOW-stego-classification/resolve/main/Y_val.npy"

URGENT_WORDS = {"urgent", "immediately", "verify", "suspended", "payment", "security", "alert"}
CEO_WORDS = {"ceo", "finance", "wire transfer", "confidential", "director"}
QR_DETECTOR = cv2.QRCodeDetector() if cv2 is not None else None


def _download(url: str, target: Path):
    if target.exists() and target.stat().st_size > 1024:
        return
    response = requests.get(url, timeout=300)
    response.raise_for_status()
    target.write_bytes(response.content)


def _entropy_binary(p: float) -> float:
    q = 1.0 - p
    if p <= 0.0 or q <= 0.0:
        return 0.0
    return -(p * math.log2(p) + q * math.log2(q))


def _corr_adj(bits: np.ndarray) -> float:
    if bits.size < 3:
        return 0.0
    x = bits[:-1].astype(np.float32)
    y = bits[1:].astype(np.float32)
    if float(np.std(x)) == 0 or float(np.std(y)) == 0:
        return 0.0
    corr = float(np.corrcoef(x, y)[0, 1])
    if math.isnan(corr):
        return 0.0
    return corr


def _decode_audio_waveform(audio_bytes: bytes, target_rate: int = 16000):
    if av is None:
        return None, target_rate
    try:
        container = av.open(io.BytesIO(audio_bytes))
        stream = next((s for s in container.streams if s.type == "audio"), None)
        if stream is None:
            return None, target_rate
        resampler = av.audio.resampler.AudioResampler(format="flt", layout="mono", rate=target_rate)
        chunks = []
        for frame in container.decode(stream):
            out = resampler.resample(frame)
            out_frames = out if isinstance(out, list) else [out]
            for of in out_frames:
                if of is None:
                    continue
                arr = of.to_ndarray().astype("float32")
                if arr.ndim == 2:
                    arr = arr[0]
                chunks.append(arr)
                if sum(c.shape[0] for c in chunks) >= target_rate * 60:
                    break
            if sum(c.shape[0] for c in chunks) >= target_rate * 60:
                break
        if not chunks:
            return None, target_rate
        wav = np.concatenate(chunks).astype("float32")
        max_abs = float(np.max(np.abs(wav))) if wav.size else 0.0
        if max_abs > 1.0:
            wav = wav / max_abs
        return wav, target_rate
    except Exception:
        return None, target_rate


def _estimate_pitch(frame: np.ndarray, sr: int) -> float:
    frame = frame.astype("float32")
    frame = frame - float(np.mean(frame))
    if float(np.sqrt(np.mean(frame * frame))) < 0.01:
        return 0.0
    corr = np.correlate(frame, frame, mode="full")[len(frame) - 1 :]
    min_lag = max(1, int(sr / 350))
    max_lag = min(len(corr) - 1, int(sr / 70))
    if max_lag <= min_lag:
        return 0.0
    window = corr[min_lag : max_lag + 1]
    lag = int(np.argmax(window)) + min_lag
    return float(sr / lag) if lag > 0 else 0.0


def build_image_features(max_rows: int = 560):
    out_path = RAW_DIR / "image_spoof_features.csv"
    rows = []
    for idx, url in enumerate(IMAGE_PARQUET_URLS):
        p = DOWNLOAD_DIR / f"image_{idx:02d}.parquet"
        _download(url, p)
        table = pq.read_table(p)
        for row in table.to_pylist():
            image_blob = (row.get("image") or {}).get("bytes")
            if not image_blob or Image is None:
                continue
            try:
                pil = Image.open(io.BytesIO(image_blob)).convert("RGB")
                arr = np.array(pil, dtype=np.uint8)
                gray = np.array(pil.convert("L"), dtype=np.uint8)
            except Exception:
                continue

            if cv2 is not None:
                edges = cv2.Canny(gray, 80, 160)
                edge_density = float(np.mean(edges > 0))
            else:
                gx = np.abs(np.diff(gray.astype(np.float32), axis=1)).mean()
                gy = np.abs(np.diff(gray.astype(np.float32), axis=0)).mean()
                edge_density = float(min(1.0, (gx + gy) / 255.0))

            has_qr = 0
            ocr_score = 0.0

            bits = (arr & 1).reshape(-1).astype(np.uint8)
            ratio = float(bits.mean()) if bits.size else 0.0
            lsb_entropy = _entropy_binary(ratio)
            lsb_corr = _corr_adj(bits)
            logo_mismatch = max(0.0, min(1.0, (0.08 - abs(lsb_corr)) * 8.0))

            label_val = int(row.get("label", 0))
            label = "phishing_like" if label_val == 1 else "legitimate"
            path_text = ((row.get("image") or {}).get("path") or "").lower()
            rows.append(
                {
                    "brand_score": round(edge_density, 6),
                    "has_qr": int(has_qr),
                    "ocr_urgency_score": round(ocr_score, 6),
                    "logo_mismatch_score": round(logo_mismatch, 6),
                    "lsb_entropy": round(lsb_entropy, 6),
                    "lsb_corr": round(lsb_corr, 6),
                    "path_text": path_text,
                    "label": label,
                    "source": "HF_itsLeen_deepfake_vs_real_image_detection",
                }
            )
            if len(rows) >= max_rows:
                break
        if len(rows) >= max_rows:
            break

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "brand_score",
                "has_qr",
                "ocr_urgency_score",
                "logo_mismatch_score",
                "lsb_entropy",
                "lsb_corr",
                "path_text",
                "label",
                "source",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {out_path}")


def build_audio_features(max_rows: int = 800):
    out_path = RAW_DIR / "audio_impersonation_features.csv"
    rows = []
    for idx, url in enumerate(AUDIO_PARQUET_URLS):
        p = DOWNLOAD_DIR / f"audio_{idx:02d}.parquet"
        _download(url, p)
        table = pq.read_table(p)
        for row in table.to_pylist():
            audio_blob = (row.get("audio") or {}).get("bytes")
            if not audio_blob:
                continue
            wav, sr = _decode_audio_waveform(audio_blob)
            if wav is None or wav.size < int(sr * 0.5):
                continue

            frame_len = int(sr * 0.03)
            hop = int(sr * 0.015)
            pitches = []
            zcr_vals = []
            flat_vals = []
            voiced = 0
            total = 0
            hann = np.hanning(frame_len).astype("float32")
            for start in range(0, max(1, wav.size - frame_len), hop):
                fr = wav[start : start + frame_len]
                if fr.shape[0] != frame_len:
                    continue
                total += 1
                energy = float(np.mean(fr * fr))
                if energy < 0.0002:
                    continue
                voiced += 1
                zcr_vals.append(float(np.mean(fr[:-1] * fr[1:] < 0)))
                spec = np.abs(np.fft.rfft(fr * hann)) + 1e-8
                flat_vals.append(float(np.exp(np.mean(np.log(spec))) / np.mean(spec)))
                pitch = _estimate_pitch(fr, sr)
                if 65 <= pitch <= 380:
                    pitches.append(pitch)
                if total >= 320:
                    break

            if total == 0:
                continue
            pitch_std = float(np.std(pitches)) if pitches else 0.0
            jitter = (
                float(np.mean(np.abs(np.diff(pitches)) / np.maximum(np.array(pitches[:-1]), 1.0)))
                if len(pitches) > 1
                else 0.0
            )
            flat_mean = float(np.mean(flat_vals)) if flat_vals else 0.0
            voiced_ratio = float(voiced / max(total, 1))

            path_text = ((row.get("audio") or {}).get("path") or "").lower()
            text = path_text
            urgency_hits = sum(1 for w in URGENT_WORDS if w in text)
            ceo_hits = sum(1 for w in CEO_WORDS if w in text)
            asr_urgency_score = min(1.0, urgency_hits / 3.0)
            ceo_phrase_score = min(1.0, ceo_hits / 2.0)

            raw_label = str(row.get("label", "")).lower().strip()
            if raw_label in {"1", "fake", "spoof", "deepfake"}:
                label = "impersonated_or_scam"
            else:
                label = "legitimate"

            rows.append(
                {
                    "pitch_std": round(pitch_std, 6),
                    "jitter": round(jitter, 6),
                    "flatness_mean": round(flat_mean, 6),
                    "voiced_ratio": round(voiced_ratio, 6),
                    "asr_urgency_score": round(asr_urgency_score, 6),
                    "ceo_phrase_score": round(ceo_phrase_score, 6),
                    "path_text": path_text,
                    "source_shard": idx,
                    "label": label,
                    "source": "HF_garystafford_deepfake_audio_detection",
                }
            )
            if len(rows) >= max_rows:
                break
        if len(rows) >= max_rows:
            break

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "pitch_std",
                "jitter",
                "flatness_mean",
                "voiced_ratio",
                "asr_urgency_score",
                "ceo_phrase_score",
                "path_text",
                "source_shard",
                "label",
                "source",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {out_path}")


def build_stego_features(max_rows: int = 1500):
    x_path = DOWNLOAD_DIR / "stego_X_val.npy"
    y_path = DOWNLOAD_DIR / "stego_Y_val.npy"
    _download(STEGO_X_URL, x_path)
    _download(STEGO_Y_URL, y_path)

    x = np.load(x_path, allow_pickle=False)
    y = np.load(y_path, allow_pickle=False)
    n = min(int(x.shape[0]), int(y.shape[0]), max_rows)
    out_path = RAW_DIR / "stego_forensics_features.csv"

    rows = []
    for i in range(n):
        sample = np.asarray(x[i])
        if sample.dtype != np.uint8:
            smin = float(sample.min())
            smax = float(sample.max())
            if smax <= 1.0 and smin >= 0.0:
                sample_u8 = np.clip(sample * 255.0, 0, 255).astype(np.uint8)
            else:
                sample_u8 = np.clip(sample, 0, 255).astype(np.uint8)
        else:
            sample_u8 = sample

        bits = (sample_u8.reshape(-1) & 1).astype(np.uint8)
        lsb_ratio = float(bits.mean()) if bits.size else 0.0
        lsb_entropy = _entropy_binary(lsb_ratio)
        zero = int(bits.size - int(bits.sum()))
        one = int(bits.sum())
        expected = bits.size / 2.0 if bits.size else 1.0
        chi = ((zero - expected) ** 2) / max(expected, 1.0) + ((one - expected) ** 2) / max(expected, 1.0)
        adjacent_corr = _corr_adj(bits)
        payload_hint = 1 if (lsb_entropy > 0.995 and abs(adjacent_corr) < 0.02) else 0

        y_val = y[i]
        if isinstance(y_val, np.ndarray):
            y_scalar = int(y_val.item()) if y_val.size == 1 else int(np.argmax(y_val))
        else:
            y_scalar = int(y_val)
        label = "stego_or_payload" if y_scalar == 1 else "clean"

        rows.append(
            {
                "sample_index": i,
                "lsb_ratio": round(lsb_ratio, 6),
                "lsb_entropy": round(lsb_entropy, 6),
                "chi_square": round(float(chi), 6),
                "adjacent_corr": round(float(adjacent_corr), 6),
                "payload_hint": int(payload_hint),
                "label": label,
                "source": "HF_frostymelonade_BOWS2_WOW_stego_classification",
            }
        )

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "sample_index",
                "lsb_ratio",
                "lsb_entropy",
                "chi_square",
                "adjacent_corr",
                "payload_hint",
                "label",
                "source",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows -> {out_path}")


def main():
    build_image_features()
    build_audio_features()
    build_stego_features()
    print("Built real multimodal datasets for image/audio/stego tracks.")


if __name__ == "__main__":
    main()
