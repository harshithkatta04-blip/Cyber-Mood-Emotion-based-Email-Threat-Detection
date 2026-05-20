import json
import io
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from uuid import uuid4
import zipfile

from flask import Flask, jsonify, render_template, request
from werkzeug.utils import secure_filename

from analyzer import analyze_email
from website_analyzer import analyze_website


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cybermood.db"
UPLOAD_DIR = BASE_DIR / "uploads"
ML_REPORT_PATH = BASE_DIR / "ml" / "reports" / "latest_metrics.json"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAGIC_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "video-or-audio/riff"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"MZ", "application/x-dosexec"),
)

EXT_TO_MIME_HINT = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".zip": "application/zip",
    ".docx": "application/zip",
    ".xlsx": "application/zip",
    ".pptx": "application/zip",
    ".exe": "application/x-dosexec",
}

IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".gif", ".svg"}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS website_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            url TEXT NOT NULL,
            page_data_json TEXT,
            result_json TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            confidence INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            email_text TEXT,
            embedded_links TEXT,
            attachments TEXT,
            result_json TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


def classify_file(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".svg"}:
        return "image"
    if ext in {".mp4", ".mov", ".avi", ".mkv", ".webm"}:
        return "video"
    if ext in {".mp3", ".wav", ".aac", ".m4a", ".ogg"}:
        return "audio"
    if ext in {".gif"}:
        return "gif"
    return "attachment"


def _sniff_magic_type(sample: bytes) -> str:
    for sig, mime in MAGIC_SIGNATURES:
        if sample.startswith(sig):
            return mime
    return ""


def _normalize_links(value) -> list[str]:
    if isinstance(value, str):
        return [line.strip() for line in value.replace(",", "\n").splitlines() if line.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _to_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enterprise", "strict"}
    return False


def extract_file_signals(file_bytes: bytes, filename: str) -> dict:
    sample = file_bytes[: 2 * 1024 * 1024]
    lower_sample = sample.lower()
    ext = Path(filename).suffix.lower()

    url_pattern = rb"(?i)\b(?:https?://|www\.)[^\s<>'\"`]+"
    embedded_urls = [u.decode("utf-8", errors="ignore").strip(".,;") for u in re.findall(url_pattern, sample)]
    embedded_urls = list(dict.fromkeys([u for u in embedded_urls if u]))

    macro_markers = [
        marker
        for marker in (
            b"autoopen",
            b"auto_open",
            b"createobject",
            b"wscript.shell",
            b"cmd.exe",
            b"powershell",
            b"document_open",
            b"workbook_open",
        )
        if marker in lower_sample
    ]

    script_markers = [
        marker
        for marker in (b"<script", b"javascript:", b"eval(", b"fromcharcode", b"base64_decode", b"shell_exec")
        if marker in lower_sample
    ]

    executable_signature = sample.startswith(b"MZ")
    pdf_js_marker = b"/javascript" in lower_sample or b"/js" in lower_sample
    zip_magic = sample.startswith(b"PK\x03\x04")
    magic_mime = _sniff_magic_type(sample)
    expected_mime = EXT_TO_MIME_HINT.get(ext, "")

    stego_markers = [
        marker
        for marker in (b"steghide", b"openstego", b"silenteye", b"outguess", b"steg", b"lsb")
        if marker in lower_sample
    ]

    mz_offset = sample.find(b"MZ", 1)
    zip_offset = sample.find(b"PK\x03\x04", 1)
    polyglot_hint = ext in IMAGE_EXTENSIONS and (mz_offset > 64 or zip_offset > 64)

    archive_entries = []
    if zip_magic:
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                archive_entries = zf.namelist()[:50]
        except Exception:
            archive_entries = []

    return {
        "embedded_urls": embedded_urls[:25],
        "macro_markers": [m.decode("utf-8", errors="ignore") for m in macro_markers],
        "script_markers": [m.decode("utf-8", errors="ignore") for m in script_markers],
        "executable_signature": executable_signature,
        "pdf_js_marker": pdf_js_marker,
        "zip_magic": zip_magic,
        "archive_entries": archive_entries,
        "filename_mismatch_hint": executable_signature and Path(filename).suffix.lower() not in {".exe", ".dll", ".sys"},
        "mime_mismatch_hint": bool(expected_mime and magic_mime and expected_mime != magic_mime),
        "polyglot_hint": polyglot_hint,
        "stego_markers": [m.decode("utf-8", errors="ignore") for m in stego_markers],
    }


def build_attachment_metadata(uploaded_files):
    items = []
    for file in uploaded_files:
        if not file or not file.filename:
            continue

        safe_name = secure_filename(file.filename)
        file_bytes = file.read()
        size = len(file_bytes)
        file.stream.seek(0)
        stored_name = f"{uuid4().hex}_{safe_name}"
        stored_path = UPLOAD_DIR / stored_name
        stored_path.write_bytes(file_bytes)

        items.append(
            {
                "filename": safe_name,
                "stored_name": stored_name,
                "saved_path": str(stored_path),
                "size": size,
                "content_type": file.content_type or "application/octet-stream",
                "category": classify_file(safe_name),
                "signals": extract_file_signals(file_bytes, safe_name),
            }
        )
    return items


def persist_analysis(email_text, embedded_links, attachments, result):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO analyses (
            created_at, email_text, embedded_links, attachments, result_json, threat_score, risk_level
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(timespec="seconds") + "Z",
            email_text,
            json.dumps(embedded_links),
            json.dumps(attachments),
            json.dumps(result),
            int(result["threatScore"]),
            result["riskLevel"],
        ),
    )
    conn.commit()
    conn.close()


def persist_website_analysis(url, page_data, result):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO website_analyses (
            created_at, url, page_data_json, result_json, threat_score, risk_level, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(timespec="seconds") + "Z",
            url,
            json.dumps(page_data),
            json.dumps(result),
            int(result["threatScore"]),
            result["riskLevel"],
            int(result.get("confidence", 0)),
        ),
    )
    conn.commit()
    conn.close()


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.get("/")
def home():
    return render_template("dashboard.html")


@app.get("/email")
def email_page():
    return render_template("email.html")


@app.get("/website")
def website_page():
    return render_template("website.html")


@app.get("/intel")
def intel_page():
    return render_template("intel.html")


@app.post("/api/analyze")
def analyze():
    if request.content_type and "application/json" in request.content_type.lower():
        payload = request.get_json(silent=True) or {}
        email_text = (
            payload.get("emailText")
            or payload.get("EMAIL_TEXT")
            or payload.get("email_text")
            or payload.get("emailContent")
            or ""
        ).strip()
        embedded_links = _normalize_links(payload.get("embeddedLinks"))
        embedded_links.extend(_normalize_links(payload.get("mediaLinks")))
        embedded_links.extend(_normalize_links(payload.get("embeddedMedia")))
        embedded_links.extend(_normalize_links(payload.get("links")))
        embedded_links = list(dict.fromkeys(embedded_links))
        attachments = payload.get("attachments") or payload.get("ATTACHMENTS") or []
        if not isinstance(attachments, list):
            attachments = []
        enterprise_mode = _to_bool(payload.get("enterpriseMode")) or (
            str(payload.get("analysisMode") or "").strip().lower() == "enterprise"
        )
        strict_mode = _to_bool(payload.get("strictMode")) or (
            str(payload.get("analysisPolicy") or "").strip().lower() == "strict"
        )
    else:
        email_text = (request.form.get("emailText") or request.form.get("EMAIL_TEXT") or "").strip()
        embedded_links = _normalize_links(request.form.get("embeddedLinks"))
        embedded_links.extend(_normalize_links(request.form.get("mediaLinks")))
        embedded_links.extend(_normalize_links(request.form.get("embeddedMedia")))
        embedded_links = list(dict.fromkeys(embedded_links))
        attachments = build_attachment_metadata(request.files.getlist("attachments"))
        enterprise_mode = _to_bool(request.form.get("enterpriseMode"))
        strict_mode = _to_bool(request.form.get("strictMode"))

    if strict_mode:
        enterprise_mode = True

    result = analyze_email(
        email_text=email_text,
        attachments=attachments,
        embedded_links=embedded_links,
        enterprise_mode=enterprise_mode,
        strict_mode=strict_mode,
    )
    persist_analysis(email_text, embedded_links, attachments, result)
    return jsonify(result)


@app.get("/api/history")
def history():
    limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, created_at, threat_score, risk_level, result_json
        FROM analyses
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    items = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "createdAt": row["created_at"],
                "threatScore": row["threat_score"],
                "riskLevel": row["risk_level"],
                "result": json.loads(row["result_json"]),
            }
        )
    return jsonify({"items": items})


@app.get("/api/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "service": "CyberMood",
        }
    )


@app.get("/api/ml/metrics")
def ml_metrics():
    if not ML_REPORT_PATH.exists():
        return (
            jsonify(
                {
                    "status": "missing",
                    "message": "No ML metrics report found. Run ml/scripts/train_suite.py first.",
                    "path": str(ML_REPORT_PATH),
                }
            ),
            404,
        )
    try:
        payload = json.loads(ML_REPORT_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        return (
            jsonify(
                {
                    "status": "error",
                    "message": "Failed to read ML metrics report.",
                    "detail": str(exc),
                }
            ),
            500,
        )
    return jsonify(payload)


@app.post("/api/website/analyze")
def analyze_website_endpoint():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()
    page_data = payload.get("pageData") or {}
    if not isinstance(page_data, dict):
        page_data = {}

    result = analyze_website(url=url, page_data=page_data)
    persist_website_analysis(url, page_data, result)
    return jsonify(result)


@app.get("/api/website/history")
def website_history():
    limit = min(max(int(request.args.get("limit", 20)), 1), 100)
    conn = get_db_connection()
    rows = conn.execute(
        """
        SELECT id, created_at, url, threat_score, risk_level, confidence, result_json
        FROM website_analyses
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    items = []
    for row in rows:
        items.append(
            {
                "id": row["id"],
                "createdAt": row["created_at"],
                "url": row["url"],
                "threatScore": row["threat_score"],
                "riskLevel": row["risk_level"],
                "confidence": row["confidence"],
                "result": json.loads(row["result_json"]),
            }
        )
    return jsonify({"items": items})


init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
