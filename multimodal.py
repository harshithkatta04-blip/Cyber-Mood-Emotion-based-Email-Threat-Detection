import math
import re
import shutil
from pathlib import Path


URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>'\"\])]+)")
BRAND_WORDS = {
    "paypal",
    "microsoft",
    "google",
    "amazon",
    "apple",
    "bank",
    "office365",
    "outlook",
    "netflix",
    "dhl",
}
SCAM_CUES = {
    "urgent",
    "verify account",
    "click now",
    "payment due",
    "wire transfer",
    "security alert",
    "suspended",
    "prize",
    "winner",
    "password",
}
VOICE_IMPERSONATION_CUES = {
    "this is your ceo",
    "i am the ceo",
    "finance director",
    "wire transfer now",
    "keep this confidential",
    "do not contact anyone",
}

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None

try:
    import av  # type: ignore
except Exception:  # pragma: no cover
    av = None

try:
    from PIL import Image, ImageSequence  # type: ignore
except Exception:  # pragma: no cover
    Image = None
    ImageSequence = None

try:
    import pytesseract  # type: ignore
except Exception:  # pragma: no cover
    pytesseract = None

try:
    from pypdf import PdfReader  # type: ignore
except Exception:  # pragma: no cover
    PdfReader = None

try:
    from faster_whisper import WhisperModel  # type: ignore
except Exception:  # pragma: no cover
    WhisperModel = None

_qr_detector = cv2.QRCodeDetector() if cv2 is not None else None
_whisper_model = None


def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    return list({u.strip(".,;") for u in URL_RE.findall(text)})


def _ocr_engine_available() -> bool:
    return Image is not None and pytesseract is not None and bool(shutil.which("tesseract"))


def _engine_status() -> dict:
    return {
        "ocr": {
            "available": _ocr_engine_available(),
            "details": "Pillow + pytesseract + tesseract binary",
        },
        "cv": {
            "available": cv2 is not None and np is not None,
            "details": "OpenCV + numpy (QR/video frame analysis)",
        },
        "asr": {
            "available": WhisperModel is not None,
            "details": "faster-whisper transcription",
        },
        "audioForensics": {
            "available": av is not None and np is not None,
            "details": "PyAV + numpy acoustic forensic analysis",
        },
        "stegoForensics": {
            "available": Image is not None and np is not None,
            "details": "LSB/entropy/correlation stego forensics",
        },
        "pdfExtract": {
            "available": PdfReader is not None,
            "details": "pypdf text extraction",
        },
    }


def _ocr_from_pil_image(img) -> str:
    if not _ocr_engine_available():
        return ""
    try:
        return (pytesseract.image_to_string(img) or "").strip()
    except Exception:
        return ""


def _decode_qr_from_frame(frame) -> list[str]:
    if _qr_detector is None:
        return []
    urls = []
    try:
        found, decoded, _, _ = _qr_detector.detectAndDecodeMulti(frame)
        if found and decoded:
            urls.extend([d.strip() for d in decoded if d and d.strip()])
    except Exception:
        pass
    try:
        text, _, _ = _qr_detector.detectAndDecode(frame)
        if text and text.strip():
            urls.append(text.strip())
    except Exception:
        pass
    return list(dict.fromkeys(urls))


def _entropy_binary(p: float) -> float:
    q = 1.0 - p
    if p <= 0.0 or q <= 0.0:
        return 0.0
    return -(p * math.log2(p) + q * math.log2(q))


def _stego_forensics_from_pil(img) -> dict:
    findings = {
        "suspicious": False,
        "score": 0,
        "confidence": 0,
        "observations": [],
    }
    if Image is None or np is None:
        findings["observations"].append("Stego forensics unavailable (Pillow/numpy missing).")
        return findings

    try:
        arr = np.array(img.convert("RGB"), dtype=np.uint8)
    except Exception:
        findings["observations"].append("Stego forensics failed to decode image pixels.")
        return findings

    bits = (arr & 1).reshape(-1).astype(np.uint8)
    if bits.size < 4096:
        findings["observations"].append("Image too small for reliable stego forensics.")
        findings["confidence"] = 25
        return findings

    stride = max(1, bits.size // 800000)
    sample = bits[::stride]
    ones_ratio = float(sample.mean())
    entropy = _entropy_binary(ones_ratio)
    zero_count = int(sample.size - int(sample.sum()))
    one_count = int(sample.sum())
    expected = sample.size / 2.0
    chi = ((zero_count - expected) ** 2) / max(expected, 1.0)
    chi += ((one_count - expected) ** 2) / max(expected, 1.0)

    corr = 0.0
    if sample.size > 2:
        x = sample[:-1].astype(np.float32)
        y = sample[1:].astype(np.float32)
        x_std = float(np.std(x))
        y_std = float(np.std(y))
        if x_std > 0 and y_std > 0:
            corr = float(np.corrcoef(x, y)[0, 1])
            if math.isnan(corr):
                corr = 0.0

    score = 0
    observations = []
    if abs(ones_ratio - 0.5) <= 0.012:
        score += 24
        observations.append("LSB balance is near-perfect (possible payload randomization).")
    if entropy >= 0.995:
        score += 20
        observations.append("LSB entropy is extremely high.")
    if abs(corr) <= 0.02:
        score += 18
        observations.append("Adjacent LSB correlation is abnormally low.")
    if chi <= 1.5:
        score += 16
        observations.append("LSB chi-square is close to idealized random embedding behavior.")
    if sample.size >= 400000:
        score += 6

    confidence = 45 + min(45, int(sample.size / 12000))
    confidence = max(25, min(95, confidence))

    findings["score"] = int(min(100, score))
    findings["confidence"] = int(confidence)
    findings["suspicious"] = findings["score"] >= 55
    findings["observations"] = observations
    return findings


def _decode_audio_waveform(path: str, target_rate: int = 16000, max_seconds: int = 120):
    if av is None or np is None:
        return None, target_rate, "Audio forensic decoder unavailable."
    try:
        container = av.open(path)
        stream = next((s for s in container.streams if s.type == "audio"), None)
        if stream is None:
            return None, target_rate, "No audio stream found."

        resampler = av.audio.resampler.AudioResampler(format="flt", layout="mono", rate=target_rate)
        chunks = []
        total_samples = 0
        max_samples = target_rate * max_seconds

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
                total_samples += int(arr.shape[0])
                if total_samples >= max_samples:
                    break
            if total_samples >= max_samples:
                break

        if not chunks:
            return None, target_rate, "No decodable audio frames."

        audio = np.concatenate(chunks).astype("float32")
        audio = audio[:max_samples]
        max_abs = float(np.max(np.abs(audio))) if audio.size else 0.0
        if max_abs > 1.0:
            audio = audio / max_abs
        return audio, target_rate, ""
    except Exception as exc:
        return None, target_rate, f"Audio decode failed: {exc}"


def _estimate_pitch_autocorr(frame, sr: int) -> float:
    if np is None:
        return 0.0
    frame = frame.astype("float32")
    frame = frame - float(np.mean(frame))
    rms = float(np.sqrt(np.mean(frame * frame)))
    if rms < 0.01:
        return 0.0

    corr = np.correlate(frame, frame, mode="full")[len(frame) - 1 :]
    min_lag = max(1, int(sr / 350))
    max_lag = min(len(corr) - 1, int(sr / 70))
    if max_lag <= min_lag:
        return 0.0

    window = corr[min_lag : max_lag + 1]
    lag = int(np.argmax(window)) + min_lag
    if lag <= 0:
        return 0.0
    return float(sr / lag)


def _voice_impersonation_forensics(path: str, transcript: str) -> dict:
    result = {
        "suspicious": False,
        "score": 0,
        "confidence": 0,
        "observations": [],
        "features": {},
    }
    if av is None or np is None:
        result["observations"].append("Audio forensics unavailable (PyAV/numpy missing).")
        return result

    waveform, sr, err = _decode_audio_waveform(path)
    if waveform is None:
        result["observations"].append(err or "Audio waveform decode failed.")
        return result

    frame_len = int(0.03 * sr)
    hop = int(0.015 * sr)
    if frame_len < 128 or waveform.size < frame_len:
        result["observations"].append("Audio too short for voice forensics.")
        result["confidence"] = 20
        return result

    pitches = []
    zcr_values = []
    flatness_values = []
    voiced_frames = 0
    frame_count = 0
    hann = np.hanning(frame_len).astype("float32")

    for start in range(0, max(1, waveform.size - frame_len), hop):
        frame = waveform[start : start + frame_len]
        if frame.shape[0] != frame_len:
            continue
        frame_count += 1
        energy = float(np.mean(frame * frame))
        if energy < 0.0002:
            continue
        voiced_frames += 1

        zcr = float(np.mean(frame[:-1] * frame[1:] < 0))
        zcr_values.append(zcr)

        spectrum = np.abs(np.fft.rfft(frame * hann)) + 1e-8
        flatness = float(np.exp(np.mean(np.log(spectrum))) / np.mean(spectrum))
        flatness_values.append(flatness)

        pitch = _estimate_pitch_autocorr(frame, sr)
        if 65 <= pitch <= 380:
            pitches.append(pitch)

        if frame_count >= 1200:
            break

    duration = float(waveform.size / max(sr, 1))
    voiced_ratio = float(voiced_frames / max(frame_count, 1))
    pitch_std = float(np.std(pitches)) if pitches else 0.0
    pitch_mean = float(np.mean(pitches)) if pitches else 0.0
    jitter = (
        float(np.mean(np.abs(np.diff(pitches)) / np.maximum(np.array(pitches[:-1]), 1.0)))
        if len(pitches) > 1
        else 0.0
    )
    zcr_std = float(np.std(zcr_values)) if zcr_values else 0.0
    flatness_mean = float(np.mean(flatness_values)) if flatness_values else 0.0
    flatness_std = float(np.std(flatness_values)) if flatness_values else 0.0
    unique_pitch_bins = len({int(round(p / 5.0)) for p in pitches}) if pitches else 0

    score = 0
    observations = []
    if len(pitches) >= 12 and pitch_std < 10:
        score += 24
        observations.append("Pitch variance is unusually narrow.")
    if len(pitches) >= 12 and jitter < 0.012:
        score += 24
        observations.append("Frame-to-frame pitch jitter is abnormally low.")
    if len(pitches) >= 10 and unique_pitch_bins <= 5:
        score += 12
        observations.append("Limited pitch diversity detected.")
    if voiced_ratio >= 0.75 and zcr_std < 0.022:
        score += 14
        observations.append("Voiced segment behavior is highly uniform.")
    if flatness_mean < 0.07 and flatness_std < 0.025:
        score += 10
        observations.append("Spectral flatness profile is unusually consistent.")

    transcript_lower = (transcript or "").lower()
    if any(cue in transcript_lower for cue in VOICE_IMPERSONATION_CUES):
        score += 16
        observations.append("Transcript includes authority-impersonation directives.")

    confidence = 35 + min(35, int(duration * 1.1)) + min(25, int(len(pitches) * 0.5))
    confidence = max(20, min(95, confidence))

    result["score"] = int(min(100, score))
    result["confidence"] = int(confidence)
    result["suspicious"] = result["score"] >= 55
    result["observations"] = observations
    result["features"] = {
        "durationSec": round(duration, 2),
        "voicedRatio": round(voiced_ratio, 3),
        "pitchMeanHz": round(pitch_mean, 2),
        "pitchStdHz": round(pitch_std, 2),
        "jitter": round(jitter, 4),
        "zcrStd": round(zcr_std, 4),
        "flatnessMean": round(flatness_mean, 4),
        "flatnessStd": round(flatness_std, 4),
    }
    return result


def _scan_image(path: str, enterprise_mode: bool = False) -> dict:
    findings = {
        "text": "",
        "qr_urls": [],
        "image_flags": [],
        "forensics": {},
    }
    if Image is None:
        findings["image_flags"].append("Image engine unavailable: Pillow missing.")
        return findings

    try:
        with Image.open(path) as img:
            img_rgb = img.convert("RGB")
            findings["text"] = _ocr_from_pil_image(img_rgb)
            if enterprise_mode:
                findings["forensics"] = _stego_forensics_from_pil(img_rgb)
    except Exception:
        return findings

    if cv2 is not None:
        try:
            frame = cv2.imread(path)
            if frame is not None:
                findings["qr_urls"] = _decode_qr_from_frame(frame)
        except Exception:
            pass
    else:
        findings["image_flags"].append("OpenCV unavailable: QR inspection skipped for image.")

    lower = findings["text"].lower()
    if any(b in lower for b in BRAND_WORDS) and any(c in lower for c in SCAM_CUES):
        findings["image_flags"].append("Image text mixes trusted-brand naming with scam pressure cues.")
    if "invoice" in lower or "payment due" in lower:
        findings["image_flags"].append("Image appears to contain invoice/payment pressure content.")
    if "scan qr" in lower or "qr code" in lower:
        findings["image_flags"].append("Image instructs QR scan; validate destination separately.")

    forensic = findings.get("forensics") or {}
    if forensic.get("suspicious"):
        findings["image_flags"].append(
            f"Forensic steganography anomaly score {forensic.get('score', 0)}/100 "
            f"(confidence {forensic.get('confidence', 0)}%)."
        )
    return findings


def _scan_gif(path: str, enterprise_mode: bool = False) -> dict:
    findings = {"text": "", "qr_urls": [], "flags": [], "forensics": {}}
    if Image is None or ImageSequence is None:
        findings["flags"].append("GIF engine unavailable: Pillow missing.")
        return findings

    all_text = []
    all_qr = []
    stego_scores = []
    stego_conf = []
    try:
        with Image.open(path) as gif:
            frames = [frame.copy().convert("RGB") for frame in ImageSequence.Iterator(gif)]
            if not frames:
                return findings
            step = max(1, len(frames) // 6)
            sampled = frames[::step][:6]
            for frame in sampled:
                text = _ocr_from_pil_image(frame)
                if text:
                    all_text.append(text)
                if cv2 is not None and np is not None:
                    try:
                        frame_arr = cv2.cvtColor(np.array(frame), cv2.COLOR_RGB2BGR)
                        all_qr.extend(_decode_qr_from_frame(frame_arr))
                    except Exception:
                        pass
                if enterprise_mode:
                    out = _stego_forensics_from_pil(frame)
                    if out.get("confidence", 0) >= 30:
                        stego_scores.append(out.get("score", 0))
                        stego_conf.append(out.get("confidence", 0))
    except Exception:
        return findings

    findings["text"] = "\n".join(all_text).strip()
    findings["qr_urls"] = list(dict.fromkeys(all_qr))
    lower = findings["text"].lower()
    if any(c in lower for c in SCAM_CUES):
        findings["flags"].append("GIF frame text contains social-engineering call-to-action cues.")
    if cv2 is None:
        findings["flags"].append("OpenCV unavailable: GIF QR inspection skipped.")

    if stego_scores:
        avg_score = int(round(sum(stego_scores) / len(stego_scores)))
        avg_conf = int(round(sum(stego_conf) / len(stego_conf)))
        findings["forensics"] = {
            "suspicious": avg_score >= 55,
            "score": avg_score,
            "confidence": avg_conf,
            "observations": ["Aggregate GIF-frame stego forensic score."],
        }
        if avg_score >= 55:
            findings["flags"].append(f"GIF forensic steganography anomaly score {avg_score}/100 (confidence {avg_conf}%).")
    return findings


def _scan_video(path: str) -> dict:
    findings = {"text": "", "qr_urls": [], "flags": []}
    if cv2 is None:
        findings["flags"].append("Video analysis unavailable: OpenCV missing.")
        return findings

    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        findings["flags"].append("Video stream could not be opened for analysis.")
        return findings

    fps = cap.get(cv2.CAP_PROP_FPS) or 24
    frame_interval = max(1, int(fps * 2))
    frame_idx = 0
    sampled = 0
    texts = []
    qr_urls = []

    while sampled < 8:
        ok, frame = cap.read()
        if not ok:
            break
        if frame_idx % frame_interval == 0:
            sampled += 1
            qr_urls.extend(_decode_qr_from_frame(frame))
            if _ocr_engine_available() and Image is not None:
                try:
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    pil_img = Image.fromarray(rgb)
                    txt = _ocr_from_pil_image(pil_img)
                    if txt:
                        texts.append(txt)
                except Exception:
                    pass
        frame_idx += 1

    cap.release()
    findings["text"] = "\n".join(texts).strip()
    findings["qr_urls"] = list(dict.fromkeys(qr_urls))
    lower = findings["text"].lower()
    if any(c in lower for c in SCAM_CUES):
        findings["flags"].append("Video frame text contains suspicious urgency/fraud cues.")
    if not _ocr_engine_available():
        findings["flags"].append("OCR unavailable: video text extraction skipped.")
    return findings


def _scan_pdf(path: str) -> dict:
    findings = {"text": "", "flags": []}
    if PdfReader is None:
        findings["flags"].append("PDF analysis unavailable: pypdf missing.")
        return findings
    try:
        reader = PdfReader(path)
        snippets = []
        for page in reader.pages[:5]:
            txt = page.extract_text() or ""
            if txt.strip():
                snippets.append(txt.strip())
        findings["text"] = "\n".join(snippets)
    except Exception:
        findings["flags"].append("PDF text extraction failed.")
    return findings


def _get_whisper_model():
    global _whisper_model
    if WhisperModel is None:
        return None
    if _whisper_model is None:
        try:
            _whisper_model = WhisperModel("tiny.en", device="cpu", compute_type="int8")
        except Exception:
            return None
    return _whisper_model


def _scan_audio(path: str, enterprise_mode: bool = False) -> dict:
    findings = {
        "transcript": "",
        "flags": [],
        "forensics": {},
    }
    model = _get_whisper_model()
    transcript = ""
    if model is None:
        findings["flags"].append("ASR engine unavailable: audio transcription skipped.")
    else:
        try:
            segments, _ = model.transcribe(path, beam_size=1, vad_filter=True)
            parts = []
            asr_conf = []
            for seg in segments:
                text = (seg.text or "").strip()
                if text:
                    parts.append(text)
                no_speech_prob = float(getattr(seg, "no_speech_prob", 0.0))
                avg_logprob = float(getattr(seg, "avg_logprob", -1.0))
                confidence = (1.0 - max(0.0, min(1.0, no_speech_prob))) * 100.0
                confidence += max(0.0, min(30.0, (avg_logprob + 1.5) * 20.0))
                asr_conf.append(max(0.0, min(100.0, confidence)))
            transcript = " ".join(parts).strip()
            findings["transcript"] = transcript
            if asr_conf:
                findings["forensics"]["asrConfidence"] = int(round(sum(asr_conf) / len(asr_conf)))
        except Exception:
            findings["flags"].append("Audio transcription failed.")

    if any(cue in transcript.lower() for cue in SCAM_CUES):
        findings["flags"].append("Audio transcript contains social-engineering urgency cues.")

    if enterprise_mode:
        voice = _voice_impersonation_forensics(path, transcript)
        findings["forensics"]["voiceImpersonation"] = voice
        if voice.get("suspicious"):
            findings["flags"].append(
                f"Voice impersonation forensic score {voice.get('score', 0)}/100 "
                f"(confidence {voice.get('confidence', 0)}%)."
            )
        elif any("unavailable" in obs.lower() or "failed" in obs.lower() for obs in (voice.get("observations") or [])):
            findings["flags"].append((voice.get("observations") or ["Audio forensic analysis unavailable."])[0])
    return findings


def _category_from_attachment(attachment: dict) -> str:
    cat = (attachment.get("category") or "").lower()
    if cat:
        return cat
    ext = Path(attachment.get("filename") or "").suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".svg"}:
        return "image"
    if ext in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
        return "video"
    if ext in {".gif"}:
        return "gif"
    if ext in {".mp3", ".wav", ".m4a", ".aac", ".ogg"}:
        return "audio"
    return "attachment"


def _modality_confidence(present: int, processed: int, missing_engines: int, strict_failures: int) -> int:
    if present <= 0:
        return 100
    score = 45 + min(28, processed * 10)
    score -= missing_engines * 20
    score -= strict_failures * 12
    return int(max(5, min(99, score)))


def inspect_multimedia(
    attachments: list[dict],
    enterprise_mode: bool = False,
    strict_mode: bool = False,
) -> dict:
    results = {
        "derived_links": [],
        "indicators": [],
        "extracted_text": [],
        "multimedia_risks": {"images": [], "videos": [], "audio": [], "attachments": []},
    }

    engine_status = _engine_status()
    modality_presence = {"images": 0, "videos": 0, "audio": 0, "attachments": 0}
    modality_processed = {"images": 0, "videos": 0, "audio": 0, "attachments": 0}
    required_missing = {"images": 0, "videos": 0, "audio": 0, "attachments": 0}
    strict_failures = {"images": 0, "videos": 0, "audio": 0, "attachments": 0}
    operational_flags = []
    forensic_signals = {"steganography": [], "voiceImpersonation": []}

    def add_operational_flag(modality: str, severity: str, code: str, message: str):
        token = f"{modality}:{code}:{message}"
        if token in seen_runtime_flags:
            return
        seen_runtime_flags.add(token)
        operational_flags.append(
            {
                "severity": severity,
                "code": code,
                "modality": modality,
                "message": message,
            }
        )

    seen_runtime_flags = set()

    for item in attachments:
        path = item.get("saved_path")
        name = item.get("filename") or "attachment"
        if not path or not Path(path).exists():
            continue
        category = _category_from_attachment(item)

        if category == "image":
            modality_presence["images"] += 1
            out = _scan_image(path, enterprise_mode=enterprise_mode)
            modality_processed["images"] += 1

            if out["text"]:
                results["extracted_text"].append(out["text"])
                urls = _extract_urls(out["text"])
                if urls:
                    results["indicators"].append(f"Image '{name}' includes visible URL text.")
                    results["derived_links"].extend(urls)
            if out["qr_urls"]:
                results["indicators"].append(f"Image '{name}' contains QR code link(s).")
                results["derived_links"].extend(out["qr_urls"])
                results["multimedia_risks"]["images"].append(f"QR links detected in image '{name}'.")
            results["multimedia_risks"]["images"].extend(out["image_flags"])

            forensics = out.get("forensics") or {}
            if forensics.get("suspicious"):
                forensic_signals["steganography"].append(
                    f"{name}: score={forensics.get('score', 0)} confidence={forensics.get('confidence', 0)}"
                )

        elif category == "video":
            modality_presence["videos"] += 1
            out = _scan_video(path)
            modality_processed["videos"] += 1

            if out["text"]:
                results["extracted_text"].append(out["text"])
                urls = _extract_urls(out["text"])
                if urls:
                    results["indicators"].append(f"Video '{name}' contains rendered URL text.")
                    results["derived_links"].extend(urls)
            if out["qr_urls"]:
                results["indicators"].append(f"Video '{name}' contains QR code link(s).")
                results["derived_links"].extend(out["qr_urls"])
            results["multimedia_risks"]["videos"].extend(out["flags"])

        elif category == "gif":
            modality_presence["videos"] += 1
            out = _scan_gif(path, enterprise_mode=enterprise_mode)
            modality_processed["videos"] += 1

            if out["text"]:
                results["extracted_text"].append(out["text"])
                urls = _extract_urls(out["text"])
                if urls:
                    results["indicators"].append(f"GIF '{name}' contains rendered URL text.")
                    results["derived_links"].extend(urls)
            if out["qr_urls"]:
                results["indicators"].append(f"GIF '{name}' contains QR code link(s).")
                results["derived_links"].extend(out["qr_urls"])
            results["multimedia_risks"]["videos"].extend(out["flags"])

            forensics = out.get("forensics") or {}
            if forensics.get("suspicious"):
                forensic_signals["steganography"].append(
                    f"{name}: score={forensics.get('score', 0)} confidence={forensics.get('confidence', 0)}"
                )

        elif category == "audio":
            modality_presence["audio"] += 1
            out = _scan_audio(path, enterprise_mode=enterprise_mode)
            modality_processed["audio"] += 1
            if out["transcript"]:
                results["extracted_text"].append(out["transcript"])
            results["multimedia_risks"]["audio"].extend(out["flags"])
            if out["transcript"] and _extract_urls(out["transcript"]):
                results["indicators"].append(f"Audio '{name}' transcript contains URL-like text.")
                results["derived_links"].extend(_extract_urls(out["transcript"]))

            voice = (out.get("forensics") or {}).get("voiceImpersonation") or {}
            if voice.get("suspicious"):
                forensic_signals["voiceImpersonation"].append(
                    f"{name}: score={voice.get('score', 0)} confidence={voice.get('confidence', 0)}"
                )
            for flag in out.get("flags") or []:
                lower = flag.lower()
                if "asr engine unavailable" in lower or "transcription failed" in lower:
                    add_operational_flag(
                        "audio",
                        "fail" if strict_mode else "warn",
                        "ENGINE_ASR_RUNTIME_UNAVAILABLE",
                        "ASR unavailable or failed during runtime audio analysis.",
                    )
                if "audio forensic" in lower and ("unavailable" in lower or "failed" in lower):
                    add_operational_flag(
                        "audio",
                        "fail" if strict_mode else "warn",
                        "ENGINE_AUDIO_FORENSICS_RUNTIME_UNAVAILABLE",
                        "Audio forensics unavailable or failed during runtime audio analysis.",
                    )
        else:
            modality_presence["attachments"] += 1
            ext = Path(name).suffix.lower()
            if ext == ".pdf":
                out = _scan_pdf(path)
                modality_processed["attachments"] += 1
                if out["text"]:
                    results["extracted_text"].append(out["text"])
                    urls = _extract_urls(out["text"])
                    if urls:
                        results["indicators"].append(f"PDF '{name}' contains link text.")
                        results["derived_links"].extend(urls)
                results["multimedia_risks"]["attachments"].extend(out["flags"])

    requirements = []
    if modality_presence["images"] > 0:
        requirements.extend([("images", "ocr"), ("images", "cv"), ("images", "stegoForensics")])
    if modality_presence["videos"] > 0:
        requirements.extend([("videos", "ocr"), ("videos", "cv")])
    if modality_presence["audio"] > 0:
        requirements.extend([("audio", "asr"), ("audio", "audioForensics")])
    if modality_presence["attachments"] > 0:
        requirements.append(("attachments", "pdfExtract"))

    seen = set()
    for modality, engine in requirements:
        key = f"{modality}:{engine}"
        if key in seen:
            continue
        seen.add(key)
        if not engine_status.get(engine, {}).get("available", False):
            severity = "fail" if strict_mode else "warn"
            code = f"ENGINE_{engine.upper()}_UNAVAILABLE"
            message = f"{engine} unavailable for {modality} analysis."
            operational_flags.append(
                {
                    "severity": severity,
                    "code": code,
                    "modality": modality,
                    "message": message,
                }
            )
            required_missing[modality] += 1
            if strict_mode:
                strict_failures[modality] += 1

    for key in results["multimedia_risks"]:
        results["multimedia_risks"][key] = list(dict.fromkeys(results["multimedia_risks"][key]))
    results["derived_links"] = list(dict.fromkeys(results["derived_links"]))
    results["indicators"] = list(dict.fromkeys(results["indicators"]))

    if enterprise_mode:
        confidences = {
            "images": _modality_confidence(
                modality_presence["images"],
                modality_processed["images"],
                required_missing["images"],
                strict_failures["images"],
            ),
            "videos": _modality_confidence(
                modality_presence["videos"],
                modality_processed["videos"],
                required_missing["videos"],
                strict_failures["videos"],
            ),
            "audio": _modality_confidence(
                modality_presence["audio"],
                modality_processed["audio"],
                required_missing["audio"],
                strict_failures["audio"],
            ),
            "links": 88 if results["derived_links"] else 78,
            "attachments": _modality_confidence(
                modality_presence["attachments"],
                modality_processed["attachments"],
                required_missing["attachments"],
                strict_failures["attachments"],
            ),
        }
        present_weight = max(1, sum(modality_presence.values()))
        weighted = (
            confidences["images"] * max(1, modality_presence["images"])
            + confidences["videos"] * max(1, modality_presence["videos"])
            + confidences["audio"] * max(1, modality_presence["audio"])
            + confidences["attachments"] * max(1, modality_presence["attachments"])
        ) / float(max(4, present_weight))
        confidences["overall"] = int(max(5, min(99, round(weighted))))

        results["enterprise"] = {
            "mode": "enterprise",
            "strictMode": bool(strict_mode),
            "engineStatus": engine_status,
            "modalityConfidence": confidences,
            "operationalFlags": operational_flags,
            "forensicSignals": forensic_signals,
        }

    return results
