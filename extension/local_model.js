const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rb.gy",
  "tiny.one"
]);

const SUSPICIOUS_TLDS = new Set([
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
  "shop"
]);

const URL_TERMS = ["login", "signin", "verify", "secure", "account", "password", "otp", "confirm"];

const EMOTION_WORDS = ["urgent", "immediately", "final notice", "warning", "suspended", "blocked", "reward", "winner"];

function normalizeUrl(input) {
  const value = (input || "").trim();
  if (!value) {
    return "";
  }
  if (value.startsWith("http://") || value.startsWith("https://")) {
    return value;
  }
  return `http://${value}`;
}

function hasIPv4(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host || "");
}

function analyzeUrlSignals(url) {
  let score = 0;
  const indicators = [];
  const normalized = normalizeUrl(url);
  let parsed;

  try {
    parsed = new URL(normalized);
  } catch {
    return { score: 40, indicators: ["Malformed URL."], host: "" };
  }

  const host = (parsed.hostname || "").toLowerCase();
  const hostParts = host.split(".");
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : "";
  const joined = `${host}${parsed.pathname.toLowerCase()}${parsed.search.toLowerCase()}`;

  if (SHORTENERS.has(host)) {
    score += 12;
    indicators.push("Shortened URL.");
  }
  if (parsed.protocol !== "https:") {
    score += 8;
    indicators.push("Non-HTTPS URL.");
  }
  if (hasIPv4(host)) {
    score += 13;
    indicators.push("IP host URL.");
  }
  if (host.includes("xn--")) {
    score += 12;
    indicators.push("Punycode domain.");
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 10;
    indicators.push(`Suspicious TLD .${tld}.`);
  }
  if (hostParts.length >= 5) {
    score += 8;
    indicators.push("Deep subdomain nesting.");
  }
  if ((host.match(/-/g) || []).length >= 3) {
    score += 6;
    indicators.push("High hyphen count in domain.");
  }
  if (joined.includes("@")) {
    score += 8;
    indicators.push("Obfuscated URL pattern.");
  }
  if (URL_TERMS.some((term) => joined.includes(term))) {
    score += 8;
    indicators.push("Credential-targeting URL terms.");
  }

  return { score: Math.min(50, score), indicators, host };
}

function analyzeContent(pageData) {
  const text = `${pageData?.title || ""} ${pageData?.textSample || ""}`.toLowerCase();
  const indicators = [];
  const emotions = [];
  let score = 0;

  if (EMOTION_WORDS.some((w) => text.includes(w))) {
    emotions.push("Urgency/Fear");
    indicators.push("Emotional pressure language detected.");
    score += 8;
  }

  const forms = Array.isArray(pageData?.forms) ? pageData.forms : [];
  const hasPasswordForm = forms.some((form) =>
    (form?.inputTypes || []).map((x) => String(x).toLowerCase()).includes("password")
  );
  if (hasPasswordForm) {
    indicators.push("Password form detected.");
    score += 10;
  }

  const links = Array.isArray(pageData?.links) ? pageData.links : [];
  if (links.length > 20) {
    indicators.push("High link density.");
    score += 4;
  }

  const images = Array.isArray(pageData?.images) ? pageData.images : [];
  if (images.some((img) => /qr|verify|invoice|security/i.test(`${img?.src || ""} ${img?.alt || ""}`))) {
    indicators.push("Suspicious image/QR cue found.");
    score += 5;
  }

  return {
    score: Math.min(50, score),
    indicators,
    emotions,
    multimediaRisks: {
      images: "Fallback model: filename/alt-based image risk checks applied.",
      videos: "Fallback model: no frame OCR available.",
      audio: "Fallback model: no audio transcription available.",
      links: `${links.length} links inspected in fallback mode.`,
      attachments: "Website mode: attachment analysis not applicable."
    }
  };
}

export function analyzeWebsiteLocal(url, pageData = {}) {
  const urlAnalysis = analyzeUrlSignals(url);
  const contentAnalysis = analyzeContent(pageData);
  const threatScore = Math.min(100, urlAnalysis.score + contentAnalysis.score);

  let riskLevel = "Legitimate";
  if (threatScore >= 35) {
    riskLevel = "Unsafe";
  } else if (threatScore >= 20) {
    riskLevel = "Safe";
  }

  const confidence = Math.min(95, 60 + Math.floor((threatScore + urlAnalysis.indicators.length * 3) / 3));
  const phishingIndicators = [...new Set([...urlAnalysis.indicators, ...contentAnalysis.indicators])];

  return {
    url,
    threatScore,
    riskLevel,
    classification: riskLevel,
    confidence,
    emotionsDetected: contentAnalysis.emotions,
    psychologicalTechniques: [],
    phishingIndicators,
    multimediaRisks: contentAnalysis.multimediaRisks,
    socialEngineeringIntent: phishingIndicators.length
      ? "Potential social-engineering signals detected in fallback analysis."
      : "No clear social-engineering cues from fallback analysis.",
    explanation: `Fallback model score=${threatScore}. URL indicators=${urlAnalysis.indicators.length}, content indicators=${contentAnalysis.indicators.length}.`,
    userAdvice:
      riskLevel === "Unsafe"
        ? "Do not log in or submit payment data."
        : riskLevel === "Safe"
          ? "Proceed carefully and verify domain identity."
          : "No major warning from fallback model."
  };
}
