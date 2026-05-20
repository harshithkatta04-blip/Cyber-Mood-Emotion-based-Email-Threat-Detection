import ipaddress
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from multimodal import inspect_multimedia


EMOTION_KEYWORDS = {
    "fear": {
        "suspended",
        "blocked",
        "terminate",
        "fraud",
        "unauthorized",
        "breach",
        "risk",
        "alert",
        "warning",
        "locked",
        "compromised",
    },
    "urgency": {
        "immediately",
        "urgent",
        "within 24 hours",
        "now",
        "act fast",
        "today",
        "deadline",
        "expires",
        "last chance",
        "final notice",
    },
    "authority": {
        "ceo",
        "cfo",
        "it support",
        "security team",
        "bank",
        "government",
        "compliance",
        "administrator",
        "official",
    },
    "greed": {
        "reward",
        "bonus",
        "prize",
        "jackpot",
        "gift card",
        "free",
        "discount",
        "profit",
        "earn",
    },
    "guilt": {
        "you failed",
        "your fault",
        "disappointed",
        "responsible",
        "blame",
        "duty",
        "team is waiting",
    },
}

TECHNIQUE_RULES = {
    "Threats": {"suspend", "terminate", "legal action", "penalty", "lawsuit", "locked"},
    "Time pressure": {"within", "urgent", "immediately", "expires", "deadline", "now"},
    "Impersonation": {
        "microsoft",
        "paypal",
        "google",
        "amazon",
        "apple",
        "bank",
        "ceo",
        "it support",
        "hr team",
    },
    "Trust exploitation": {"verify account", "confirm identity", "security upgrade", "trusted partner"},
    "Reward or prize promises": {"prize", "bonus", "cashback", "gift", "reward", "lottery"},
}

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
}

REDIRECT_QUERY_KEYS = {
    "url",
    "u",
    "target",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "continue",
    "dest",
    "destination",
    "to",
    "out",
    "r",
}

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".scr",
    ".js",
    ".jar",
    ".ps1",
    ".vbs",
}

HIGH_RISK_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso"}
MACRO_DOCS = {".docm", ".xlsm", ".pptm"}
LIKELY_SENSITIVE_ACTIONS = {
    "click",
    "download",
    "open attachment",
    "login",
    "sign in",
    "verify",
    "confirm password",
    "wire transfer",
    "payment",
    "pay now",
    "send otp",
    "share credentials",
    "bank account",
    "routing number",
    "credit card",
    "ssn",
    "one-time code",
    "security code",
}


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def _extract_urls(text: str) -> list[str]:
    if not text:
        return []
    pattern = r"(?i)\b((?:https?://|www\.)[^\s<>'\"\])]+)"
    return list({u.strip(".,;") for u in re.findall(pattern, text)})


def _token_count(text: str, phrase: str) -> int:
    return len(re.findall(rf"\b{re.escape(phrase.lower())}\b", text))


def _contains_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _analyze_links(urls: list[str]) -> tuple[list[str], str, int]:
    indicators = []
    technical_score = 0
    suspicious_count = 0

    for raw_url in urls:
        normalized = raw_url if raw_url.startswith(("http://", "https://")) else f"http://{raw_url}"
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        host_parts = host.split(".")
        tld = host_parts[-1] if len(host_parts) > 1 else ""

        if not host:
            indicators.append(f"Malformed URL detected: {raw_url}")
            technical_score += 5
            suspicious_count += 1
            continue

        if host in SHORTENERS:
            indicators.append(f"Shortened URL: {raw_url}")
            technical_score += 8
            suspicious_count += 1
        if parsed.scheme != "https":
            indicators.append(f"Non-HTTPS link: {raw_url}")
            technical_score += 4
            suspicious_count += 1
        if _contains_ip(host):
            indicators.append(f"IP-based URL host: {raw_url}")
            technical_score += 8
            suspicious_count += 1
        if "xn--" in host:
            indicators.append(f"Punycode/homograph-style domain: {raw_url}")
            technical_score += 9
            suspicious_count += 1
        if "@" in parsed.netloc:
            indicators.append(f"Credential-obfuscated URL: {raw_url}")
            technical_score += 8
            suspicious_count += 1
        if tld in SUSPICIOUS_TLDS:
            indicators.append(f"Suspicious TLD '.{tld}' in URL: {raw_url}")
            technical_score += 6
            suspicious_count += 1
        if len(host_parts) >= 5:
            indicators.append(f"Excessive subdomain depth in URL: {raw_url}")
            technical_score += 5
            suspicious_count += 1
        if any(token in path for token in {"login", "verify", "secure", "reset", "update-account"}):
            indicators.append(f"Credential-targeting URL path: {raw_url}")
            technical_score += 3
        if any(token in path for token in {"redirect", "out", "away", "bounce"}):
            indicators.append(f"Redirect-themed URL path: {raw_url}")
            technical_score += 4

        query_params = parse_qs(parsed.query, keep_blank_values=True)
        redirect_flag = False
        for key, values in query_params.items():
            key_lower = key.lower()
            decoded_values = [unquote(v or "").strip() for v in values]
            if key_lower in REDIRECT_QUERY_KEYS and any(
                v.startswith(("http://", "https://", "//", "www.")) for v in decoded_values
            ):
                indicators.append(f"Hidden redirect parameter '{key}' in URL: {raw_url}")
                technical_score += 8
                suspicious_count += 1
                redirect_flag = True
                break

        if not redirect_flag:
            decoded_query = unquote(parsed.query).lower()
            if "http://" in decoded_query or "https://" in decoded_query:
                indicators.append(f"Nested URL found in query string: {raw_url}")
                technical_score += 6
                suspicious_count += 1

    if not urls:
        link_summary = "No links detected."
    elif suspicious_count == 0:
        link_summary = f"{len(urls)} links found, no high-confidence technical phishing flags."
    else:
        link_summary = f"{len(urls)} links found, {suspicious_count} suspicious signals detected."

    return indicators, link_summary, min(technical_score, 30)


def _analyze_attachments(attachments: list[dict]) -> tuple[list[str], dict, int]:
    indicators = []
    score = 0

    image_flags = []
    video_flags = []
    audio_flags = []
    attach_flags = []

    for item in attachments:
        name = (item.get("filename") or "").strip()
        category = (item.get("category") or "attachment").lower()
        ext = Path(name).suffix.lower()
        lower_name = name.lower()
        signals = item.get("signals") or {}
        embedded_urls = signals.get("embedded_urls") or []
        macro_markers = signals.get("macro_markers") or []
        script_markers = signals.get("script_markers") or []
        stego_markers = signals.get("stego_markers") or []
        polyglot_hint = bool(signals.get("polyglot_hint"))
        mime_mismatch_hint = bool(signals.get("mime_mismatch_hint"))

        if category == "image":
            if any(token in lower_name for token in {"paypal", "microsoft", "google", "amazon", "bank", "logo"}):
                image_flags.append(f"Image '{name}' filename suggests trusted-brand/logo context; verify authenticity.")
                score += 4
            if any(token in lower_name for token in {"logo", "invoice", "payment", "security", "warning"}):
                image_flags.append(f"Image '{name}' may include impersonated branding or fake invoice content.")
                score += 4
            if "qr" in lower_name:
                image_flags.append(f"Image '{name}' likely includes a QR code; validate destination before scanning.")
                score += 5
            if "screenshot" in lower_name:
                image_flags.append(f"Image '{name}' appears to be a screenshot and may be spoofed evidence.")
                score += 3
            if polyglot_hint:
                image_flags.append(f"Image '{name}' may contain hidden polyglot payload content.")
                score += 8
            if stego_markers:
                image_flags.append(
                    f"Image '{name}' contains steganography-like markers: {', '.join(stego_markers[:4])}"
                )
                score += 7
            if mime_mismatch_hint:
                image_flags.append(f"Image '{name}' file signature does not match its extension.")
                score += 6
        elif category == "video":
            if any(token in lower_name for token in {"alert", "warning", "urgent", "security"}):
                video_flags.append(f"Video '{name}' uses warning/urgent framing that can support social engineering.")
                score += 4
            if mime_mismatch_hint:
                video_flags.append(f"Video '{name}' file signature does not match its extension.")
                score += 5
        elif category == "gif":
            if any(token in lower_name for token in {"urgent", "alert", "verify", "winner"}):
                video_flags.append(f"GIF '{name}' may embed scam-like call-to-action messaging.")
                score += 3
            if mime_mismatch_hint:
                video_flags.append(f"GIF '{name}' file signature does not match its extension.")
                score += 5
        elif category == "audio":
            if any(token in lower_name for token in {"ceo", "urgent", "payment", "wire"}):
                audio_flags.append(f"Audio '{name}' may involve impersonation or urgent payment pressure cues.")
                score += 4
            if mime_mismatch_hint:
                audio_flags.append(f"Audio '{name}' file signature does not match its extension.")
                score += 5
        else:
            if ext in DANGEROUS_EXTENSIONS:
                attach_flags.append(f"Executable/script attachment: {name}")
                score += 15
            elif ext in MACRO_DOCS:
                attach_flags.append(f"Macro-enabled office attachment: {name}")
                score += 12
            elif ext in HIGH_RISK_ARCHIVE_EXTENSIONS:
                attach_flags.append(f"Compressed archive attachment: {name}")
                score += 8
            elif ext in {".pdf", ".doc", ".docx", ".xls", ".xlsx"} and any(
                token in lower_name for token in {"invoice", "payment", "remittance", "statement", "kyc"}
            ):
                attach_flags.append(f"Financial/identity-themed document attachment: {name}")
                score += 5

        if embedded_urls:
            attach_flags.append(f"Attachment '{name}' contains embedded link(s): {', '.join(embedded_urls[:3])}")
            score += 6
        if macro_markers:
            attach_flags.append(
                f"Attachment '{name}' has macro-like markers: {', '.join(macro_markers[:4])}"
            )
            score += 10
        if script_markers:
            attach_flags.append(
                f"Attachment '{name}' has script markers: {', '.join(script_markers[:4])}"
            )
            score += 8
        if signals.get("pdf_js_marker"):
            attach_flags.append(f"Attachment '{name}' includes PDF JavaScript markers.")
            score += 8
        if signals.get("filename_mismatch_hint"):
            attach_flags.append(f"Attachment '{name}' may hide executable content behind a non-exe extension.")
            score += 12
        if polyglot_hint:
            attach_flags.append(f"Attachment '{name}' may include hidden payload content.")
            score += 8
        if stego_markers:
            attach_flags.append(
                f"Attachment '{name}' contains steganography-like markers: {', '.join(stego_markers[:4])}"
            )
            score += 6
        if mime_mismatch_hint:
            attach_flags.append(f"Attachment '{name}' file signature does not match the extension.")
            score += 7
        if signals.get("zip_magic") and ext not in HIGH_RISK_ARCHIVE_EXTENSIONS:
            attach_flags.append(f"Attachment '{name}' appears to contain a compressed payload.")
            score += 5
        archive_entries = signals.get("archive_entries") or []
        if archive_entries:
            risky_inside = [
                f for f in archive_entries if Path(f).suffix.lower() in DANGEROUS_EXTENSIONS | MACRO_DOCS
            ]
            if risky_inside:
                attach_flags.append(
                    f"Archive '{name}' contains potentially dangerous files: {', '.join(risky_inside[:5])}"
                )
                score += 10

    indicators.extend(image_flags)
    indicators.extend(video_flags)
    indicators.extend(audio_flags)
    indicators.extend(attach_flags)

    multimedia_risks = {
        "images": "; ".join(image_flags) if image_flags else "No image-specific red flags detected.",
        "videos": "; ".join(video_flags) if video_flags else "No video/GIF-specific red flags detected.",
        "audio": "; ".join(audio_flags) if audio_flags else "No audio-specific red flags detected.",
        "attachments": "; ".join(attach_flags) if attach_flags else "No high-risk attachment types detected.",
    }
    return indicators, multimedia_risks, min(score, 30)


def analyze_email(
    email_text: str,
    attachments: list[dict] | None = None,
    embedded_links: list[str] | None = None,
    enterprise_mode: bool = False,
    strict_mode: bool = False,
) -> dict:
    attachments = attachments or []
    embedded_links = embedded_links or []

    multimodal = inspect_multimedia(
        attachments,
        enterprise_mode=enterprise_mode,
        strict_mode=strict_mode,
    )
    multimodal_text = "\n".join(multimodal.get("extracted_text") or [])
    normalized_text = _normalize_text(f"{email_text}\n{multimodal_text}")
    text_urls = _extract_urls(email_text)
    file_urls = []
    for item in attachments:
        file_urls.extend((item.get("signals") or {}).get("embedded_urls") or [])
    merged_urls = list({*text_urls, *embedded_links, *file_urls, *(multimodal.get("derived_links") or [])})

    emotions = []
    emotion_score = 0
    for emotion, words in EMOTION_KEYWORDS.items():
        matches = sum(_token_count(normalized_text, w) for w in words)
        if matches > 0:
            emotions.append(emotion.capitalize())
            emotion_score += min(2 + matches, 5)
    emotion_score = min(emotion_score, 25)

    techniques = []
    psych_score = 0
    for label, cues in TECHNIQUE_RULES.items():
        hits = sum(_token_count(normalized_text, cue) for cue in cues)
        if hits > 0:
            techniques.append(label)
            psych_score += min(3 + hits, 6)
    psych_score = min(psych_score, 25)

    intent_hits = [action for action in LIKELY_SENSITIVE_ACTIONS if action in normalized_text]
    deception_score = min(20, 4 * len(intent_hits))
    social_intent = (
        (
            "Likely social-engineering intent to trigger user action "
            f"(click/download/pay/share data). Observed target actions: {', '.join(intent_hits[:5])}."
        )
        if intent_hits
        else "No explicit high-pressure call-to-action detected."
    )

    link_indicators, link_summary, link_score = _analyze_links(merged_urls)
    attachment_indicators, multimedia_risks, media_score = _analyze_attachments(attachments)
    multimodal_indicators = multimodal.get("indicators") or []
    enterprise_data = multimodal.get("enterprise") or {}
    enterprise_flags = enterprise_data.get("operationalFlags") or []
    hard_fail_flags = [flag for flag in enterprise_flags if flag.get("severity") == "fail"]
    warn_flags = [flag for flag in enterprise_flags if flag.get("severity") == "warn"]

    technical_score = min(30, link_score + media_score // 2)
    phishing_indicators = list(dict.fromkeys(link_indicators + attachment_indicators + multimodal_indicators))
    if warn_flags:
        for flag in warn_flags:
            phishing_indicators.append(f"Enterprise warning: {flag.get('message', '')}")
        technical_score = min(30, technical_score + min(6, len(warn_flags)))
    if hard_fail_flags:
        for flag in hard_fail_flags:
            phishing_indicators.append(f"Enterprise hard fail: {flag.get('message', '')}")
        technical_score = min(30, technical_score + min(10, len(hard_fail_flags) * 2))

    total_score = min(100, emotion_score + psych_score + deception_score + technical_score)
    if strict_mode and hard_fail_flags:
        total_score = max(40, total_score)
    if total_score >= 70:
        risk_level = "Dangerous"
    elif total_score >= 35:
        risk_level = "Suspicious"
    else:
        risk_level = "Safe"

    multimedia_risks["links"] = link_summary
    if multimodal.get("multimedia_risks"):
        for key in ("images", "videos", "audio", "attachments"):
            extra = multimodal["multimedia_risks"].get(key) or []
            if extra:
                base = multimedia_risks[key]
                joined_extra = "; ".join(extra)
                if base.startswith("No "):
                    multimedia_risks[key] = joined_extra
                else:
                    multimedia_risks[key] = f"{base}; {joined_extra}"

    explanation = (
        f"Detected emotions: {', '.join(emotions) if emotions else 'none'}. "
        f"Psychological pressure techniques: {', '.join(techniques) if techniques else 'none'}. "
        f"{social_intent} Technical risk flags: {len(phishing_indicators)}."
    )
    if enterprise_mode:
        explanation += (
            f" Enterprise mode confidence: "
            f"{(enterprise_data.get('modalityConfidence') or {}).get('overall', 0)}%."
        )
    if strict_mode and hard_fail_flags:
        explanation += " Strict mode detected unavailable required engines and raised risk floor."

    if risk_level == "Dangerous":
        advice = (
            "Do not click links, open files, or respond. Verify the sender through an independent channel and report the email."
        )
    elif risk_level == "Suspicious":
        advice = (
            "Treat as potentially malicious. Validate sender identity, hover/check URLs, and scan attachments before opening."
        )
    else:
        advice = "No major threats detected, but continue standard email hygiene and verify unexpected requests."

    response = {
        "emotionsDetected": emotions,
        "psychologicalTechniques": techniques,
        "phishingIndicators": phishing_indicators,
        "multimediaRisks": {
            "images": multimedia_risks["images"],
            "videos": multimedia_risks["videos"],
            "audio": multimedia_risks["audio"],
            "links": multimedia_risks["links"],
            "attachments": multimedia_risks["attachments"],
        },
        "threatScore": int(total_score),
        "riskLevel": risk_level,
        "explanation": explanation,
        "userAdvice": advice,
    }
    if enterprise_mode:
        response["enterprise"] = enterprise_data
    return response
