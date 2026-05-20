import ipaddress
import base64
import io
import re
from urllib.parse import urlparse

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None

try:
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover
    Image = None

try:
    import pytesseract  # type: ignore
except Exception:  # pragma: no cover
    pytesseract = None


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "tiny.one",
}

SUSPICIOUS_TLDS = {
    "top",
    "xyz",
    "click",
    "link",
    "gq",
    "work",
    "zip",
    "mov",
    "cam",
    "buzz",
    "shop",
    "rest",
}

PHISHING_URL_TERMS = {
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "update",
    "banking",
    "wallet",
    "password",
    "otp",
    "confirm",
    "sso",
}

EMOTION_KEYWORDS = {
    "Fear": {"suspended", "blocked", "terminate", "fraud", "alert", "warning", "compromised"},
    "Urgency": {"urgent", "immediately", "now", "deadline", "expires", "final notice", "act fast"},
    "Authority": {"ceo", "admin", "security team", "it support", "official", "compliance"},
    "Greed": {"reward", "bonus", "prize", "win", "cashback", "gift"},
    "Guilt": {"your fault", "responsible", "team is waiting", "failed"},
}

PSYCH_TECHNIQUES = {
    "Threats": {"suspend", "terminate", "penalty", "legal action", "locked"},
    "Time pressure": {"within 24 hours", "urgent", "immediately", "deadline", "now"},
    "Impersonation": {"bank", "microsoft", "google", "apple", "amazon", "paypal", "it support"},
    "Trust exploitation": {"verify account", "security check", "confirm identity", "trusted"},
    "Reward or prize promises": {"winner", "prize", "reward", "bonus", "gift"},
}

SENSITIVE_ACTIONS = {
    "login",
    "sign in",
    "verify",
    "confirm password",
    "click",
    "download",
    "wire transfer",
    "pay now",
    "submit otp",
    "enter card",
}

BRAND_TRUSTED_DOMAINS = {
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com"},
    "paypal": {"paypal.com"},
    "bank": {"bankofamerica.com", "chase.com", "wellsfargo.com", "citi.com", "capitalone.com"},
}


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if not re.match(r"(?i)^https?://", value):
        return f"http://{value}"
    return value


def _contains_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_randomish_host(host: str) -> bool:
    compact = host.replace(".", "").replace("-", "")
    if len(compact) < 12:
        return False
    digits = sum(ch.isdigit() for ch in compact)
    return (digits / max(1, len(compact))) > 0.3


def _token_count(text: str, phrase: str) -> int:
    return len(re.findall(rf"\b{re.escape(phrase.lower())}\b", text))


def _join_page_text(page_data: dict) -> str:
    title = page_data.get("title") or ""
    text_sample = page_data.get("textSample") or ""
    form_text = []
    for form in page_data.get("forms") or []:
        form_text.extend(form.get("inputNames") or [])
        form_text.extend(form.get("inputTypes") or [])
    combined = " ".join([title, text_sample, " ".join(form_text)])
    return re.sub(r"\s+", " ", combined).strip().lower()


def _extract_screenshot_signals(page_data: dict) -> dict:
    out = {"text": "", "qr_urls": [], "score": 0, "indicators": [], "media_notes": []}
    data_url = page_data.get("screenshotDataUrl") or ""
    if not isinstance(data_url, str) or not data_url.startswith("data:image"):
        return out

    try:
        encoded = data_url.split(",", 1)[1]
        image_bytes = base64.b64decode(encoded, validate=False)
    except Exception:
        return out

    if Image is not None and pytesseract is not None:
        try:
            img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            text = (pytesseract.image_to_string(img) or "").strip()
            if text:
                out["text"] = text
                lower = text.lower()
                if any(k in lower for k in {"urgent", "verify", "suspended", "password", "pay now"}):
                    out["score"] += 8
                    out["indicators"].append("Screenshot OCR shows phishing-style urgency/credential language.")
                    out["media_notes"].append("Screenshot OCR detected high-risk social-engineering text.")
        except Exception:
            pass

    if cv2 is not None and np is not None:
        try:
            frame = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
            if frame is not None:
                detector = cv2.QRCodeDetector()
                found, decoded, _, _ = detector.detectAndDecodeMulti(frame)
                urls = []
                if found and decoded:
                    urls.extend([v.strip() for v in decoded if v and v.strip()])
                single, _, _ = detector.detectAndDecode(frame)
                if single and single.strip():
                    urls.append(single.strip())
                urls = list(dict.fromkeys(urls))
                if urls:
                    out["qr_urls"] = urls
                    out["score"] += 10
                    out["indicators"].append("Screenshot includes QR code destination(s).")
                    out["media_notes"].append("QR code detected in page screenshot.")
        except Exception:
            pass

    return out


def _analyze_url(url: str) -> tuple[int, list[str], dict]:
    score = 0
    indicators = []
    normalized = _normalize_url(url)
    parsed = urlparse(normalized) if normalized else None
    host = (parsed.hostname or "").lower() if parsed else ""
    path = (parsed.path or "").lower() if parsed else ""
    query = (parsed.query or "").lower() if parsed else ""
    host_parts = host.split(".") if host else []
    tld = host_parts[-1] if len(host_parts) > 1 else ""

    if not host:
        return 40, ["Malformed or missing URL."], {"host": "", "scheme": "", "path": ""}

    if host in SHORTENERS:
        indicators.append("Shortened URL detected.")
        score += 12
    if parsed.scheme != "https":
        indicators.append("Non-HTTPS URL.")
        score += 8
    if _contains_ip(host):
        indicators.append("IP-address based URL host.")
        score += 14
    if "xn--" in host:
        indicators.append("Punycode domain pattern detected.")
        score += 12
    if "@" in parsed.netloc:
        indicators.append("URL includes '@' obfuscation.")
        score += 10
    if tld in SUSPICIOUS_TLDS:
        indicators.append(f"Suspicious top-level domain '.{tld}'.")
        score += 10
    if len(host_parts) >= 5:
        indicators.append("Deep subdomain nesting.")
        score += 8
    if host.count("-") >= 3:
        indicators.append("High hyphen usage in domain.")
        score += 6
    if len(host) > 35:
        indicators.append("Unusually long domain name.")
        score += 5
    if _is_randomish_host(host):
        indicators.append("Domain appears algorithmically/randomly generated.")
        score += 7
    if any(term in f"{host}{path}{query}" for term in PHISHING_URL_TERMS):
        indicators.append("Credential-targeting URL keywords present.")
        score += 8

    for brand, domains in BRAND_TRUSTED_DOMAINS.items():
        if brand in host:
            if not any(host == d or host.endswith(f".{d}") for d in domains):
                indicators.append(f"Potential brand impersonation involving '{brand}'.")
                score += 12

    return min(50, score), indicators, {"host": host, "scheme": parsed.scheme, "path": path}


def _analyze_page_content(page_data: dict, url_host: str) -> tuple[int, dict]:
    screenshot = _extract_screenshot_signals(page_data)
    text = f"{_join_page_text(page_data)} {(screenshot.get('text') or '').lower()}"
    emotions = []
    techniques = []
    indicators = []
    content_score = 0
    multimedia = {"images": [], "videos": [], "audio": [], "links": [], "attachments": []}

    for emotion, cues in EMOTION_KEYWORDS.items():
        if any(_token_count(text, cue) > 0 for cue in cues):
            emotions.append(emotion)
            content_score += 4
    for label, cues in PSYCH_TECHNIQUES.items():
        if any(_token_count(text, cue) > 0 for cue in cues):
            techniques.append(label)
            content_score += 5

    sensitive_hits = [action for action in SENSITIVE_ACTIONS if action in text]
    if sensitive_hits:
        content_score += min(15, len(sensitive_hits) * 3)
        indicators.append("Page calls for sensitive actions (login/payment/verification).")

    forms = page_data.get("forms") or []
    password_forms = 0
    suspicious_form_actions = 0
    for form in forms:
        input_types = [x.lower() for x in (form.get("inputTypes") or [])]
        action = (form.get("action") or "").lower()
        if "password" in input_types:
            password_forms += 1
        if action and url_host and url_host not in action and action.startswith("http"):
            suspicious_form_actions += 1

    if password_forms:
        content_score += 10
        indicators.append("Password-entry form detected.")
    if suspicious_form_actions:
        content_score += min(10, suspicious_form_actions * 5)
        indicators.append("Form submits to external domain.")

    links = page_data.get("links") or []
    off_domain_links = 0
    suspicious_link_terms = 0
    for link in links[:300]:
        href = (link.get("href") or "").strip()
        if not href:
            continue
        normalized = _normalize_url(href)
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        if host and url_host and host != url_host and not host.endswith(f".{url_host}") and not url_host.endswith(f".{host}"):
            off_domain_links += 1
        if any(term in path for term in PHISHING_URL_TERMS):
            suspicious_link_terms += 1

    if off_domain_links >= 10:
        content_score += 6
        indicators.append("High number of off-domain links.")
    if suspicious_link_terms >= 3:
        content_score += 5
        indicators.append("Multiple links with credential-targeting paths.")
    multimedia["links"].append(
        f"{len(links)} links inspected; off-domain={off_domain_links}, credential-style paths={suspicious_link_terms}."
    )

    images = page_data.get("images") or []
    image_flags = 0
    for image in images[:200]:
        signal_text = f"{(image.get('src') or '')} {(image.get('alt') or '')}".lower()
        if "qr" in signal_text:
            image_flags += 1
        if any(b in signal_text for b in BRAND_TRUSTED_DOMAINS) and any(term in text for term in {"login", "verify", "password"}):
            image_flags += 1
    if image_flags:
        content_score += min(8, image_flags * 2)
        multimedia["images"].append("Images include QR/brand-themed phishing cues.")

    videos = page_data.get("videos") or []
    if videos:
        multimedia["videos"].append(f"{len(videos)} video sources present; inspect warning overlays and scam prompts.")
    audios = page_data.get("audios") or []
    if audios:
        multimedia["audio"].append(f"{len(audios)} audio sources present; inspect for impersonation/urgent narration.")

    scripts = page_data.get("scripts") or []
    third_party_scripts = 0
    for script in scripts[:300]:
        src = (script.get("src") or "").strip()
        if not src:
            continue
        parsed = urlparse(_normalize_url(src))
        host = (parsed.hostname or "").lower()
        if host and url_host and host != url_host and not host.endswith(f".{url_host}"):
            third_party_scripts += 1
    if third_party_scripts >= 8:
        content_score += 5
        indicators.append("Large third-party script footprint.")

    meta = page_data.get("meta") or {}
    iframe_count = int(meta.get("iframeCount") or 0)
    hidden_count = int(meta.get("hiddenElementsCount") or 0)
    if iframe_count >= 5:
        content_score += 6
        indicators.append("High iframe count can indicate redirection abuse.")
    if hidden_count >= 20:
        content_score += 4
        indicators.append("Many hidden elements detected.")

    if screenshot["qr_urls"]:
        indicators.append("QR destination embedded on page screenshot.")
        multimedia["images"].append("QR code found in captured page screenshot.")
    if screenshot["media_notes"]:
        multimedia["images"].extend(screenshot["media_notes"])
    if screenshot["indicators"]:
        indicators.extend(screenshot["indicators"])
    content_score += screenshot["score"]
    if screenshot["qr_urls"]:
        multimedia["links"].append(f"Screenshot QR URLs detected: {', '.join(screenshot['qr_urls'][:3])}.")

    return min(50, content_score), {
        "emotions": list(dict.fromkeys(emotions)),
        "techniques": list(dict.fromkeys(techniques)),
        "indicators": list(dict.fromkeys(indicators)),
        "multimedia": multimedia,
        "sensitiveActions": sensitive_hits,
    }


def analyze_website(url: str, page_data: dict | None = None) -> dict:
    page_data = page_data or {}
    url_score, url_indicators, url_info = _analyze_url(url)
    content_score, content = _analyze_page_content(page_data, url_info["host"])

    threat_score = min(100, url_score + content_score)
    if threat_score >= 35:
        risk_level = "Unsafe"
    elif threat_score >= 20:
        risk_level = "Safe"
    else:
        risk_level = "Legitimate"

    indicator_count = len(url_indicators) + len(content["indicators"])
    confidence = min(99, 58 + min(35, abs(threat_score - 35) // 2 + indicator_count * 3))

    multimedia = content["multimedia"]
    links_summary = multimedia["links"][0] if multimedia["links"] else "No link metadata inspected."
    multimedia_risks = {
        "images": "; ".join(multimedia["images"]) if multimedia["images"] else "No high-confidence image risk cues detected.",
        "videos": "; ".join(multimedia["videos"]) if multimedia["videos"] else "No video risk cues detected.",
        "audio": "; ".join(multimedia["audio"]) if multimedia["audio"] else "No audio risk cues detected.",
        "links": links_summary,
        "attachments": "Website mode: attachment analysis not applicable.",
    }

    phishing_indicators = list(dict.fromkeys(url_indicators + content["indicators"]))
    if content["sensitiveActions"]:
        social_intent = (
            "Likely social-engineering intent to trigger credential entry, payment, or urgent account action."
        )
    else:
        social_intent = "No strong social-engineering action cues found in inspected content."

    if risk_level == "Unsafe":
        advice = "Do not enter credentials or payment data. Leave the page and verify the domain through official channels."
    elif risk_level == "Safe":
        advice = "Proceed with caution. Validate domain spelling, SSL, and destination of login/payment actions."
    else:
        advice = "No major phishing signals detected. Continue normal browsing hygiene."

    explanation = (
        f"URL risk score={url_score}, content risk score={content_score}. "
        f"Emotions: {', '.join(content['emotions']) if content['emotions'] else 'none'}. "
        f"Techniques: {', '.join(content['techniques']) if content['techniques'] else 'none'}. "
        f"Indicators: {len(phishing_indicators)}."
    )

    return {
        "url": url,
        "threatScore": int(threat_score),
        "riskLevel": risk_level,
        "confidence": int(confidence),
        "classification": risk_level,
        "emotionsDetected": content["emotions"],
        "psychologicalTechniques": content["techniques"],
        "phishingIndicators": phishing_indicators,
        "multimediaRisks": multimedia_risks,
        "socialEngineeringIntent": social_intent,
        "explanation": explanation,
        "userAdvice": advice,
        "modelVersion": "CyberMood-Web-1.0",
    }
