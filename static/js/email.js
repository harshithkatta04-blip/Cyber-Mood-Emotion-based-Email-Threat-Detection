const form = document.getElementById("analyzeForm");
const emailText = document.getElementById("emailText");
const embeddedLinks = document.getElementById("embeddedLinks");
const mediaLinks = document.getElementById("mediaLinks");
const attachments = document.getElementById("attachments");
const enterpriseMode = document.getElementById("enterpriseMode");
const strictMode = document.getElementById("strictMode");
const sampleBtn = document.getElementById("sampleBtn");
const analyzeBtn = document.getElementById("analyzeBtn");
const loading = document.getElementById("loading");
const resultWrap = document.getElementById("resultWrap");
const riskPanel = document.getElementById("riskPanel");
const scoreValue = document.getElementById("scoreValue");
const riskBadge = document.getElementById("riskBadge");
const scoreDial = document.getElementById("scoreDial");
const scoreFill = document.getElementById("scoreFill");
const verdictLine = document.getElementById("verdictLine");
const emotionCount = document.getElementById("emotionCount");
const techniqueCount = document.getElementById("techniqueCount");
const indicatorCount = document.getElementById("indicatorCount");
const fileMeta = document.getElementById("fileMeta");
const livePreview = document.getElementById("livePreview");
const emotions = document.getElementById("emotions");
const techniques = document.getElementById("techniques");
const intentSummary = document.getElementById("intentSummary");
const indicators = document.getElementById("indicators");
const mediaRisks = document.getElementById("mediaRisks");
const explanation = document.getElementById("explanation");
const userAdvice = document.getElementById("userAdvice");
const enterpriseWrap = document.getElementById("enterpriseWrap");
const enterpriseMeta = document.getElementById("enterpriseMeta");
const modalityConfidence = document.getElementById("modalityConfidence");
const engineStatus = document.getElementById("engineStatus");
const operationalFlags = document.getElementById("operationalFlags");
const forensicSignals = document.getElementById("forensicSignals");
const rawJson = document.getElementById("rawJson");
const historyList = document.getElementById("historyList");
const historyCount = document.getElementById("historyCount");
const refreshHistoryBtn = document.getElementById("refreshHistoryBtn");

const LIVE_CUES = [
  { label: "Urgency", words: ["urgent", "immediately", "now", "act fast", "final notice"] },
  { label: "Fear", words: ["suspended", "blocked", "warning", "breach", "fraud"] },
  { label: "Authority", words: ["ceo", "it support", "security team", "official"] },
  { label: "Greed", words: ["prize", "bonus", "winner", "reward", "gift"] },
];

function riskClass(level) {
  if (level === "Dangerous") return "risk-danger";
  if (level === "Suspicious") return "risk-suspicious";
  return "risk-safe";
}

function riskTone(level) {
  if (level === "Dangerous") return "tone-danger";
  if (level === "Suspicious") return "tone-suspicious";
  return "tone-safe";
}

function riskHeadline(level) {
  if (level === "Dangerous") return "High probability of active social-engineering";
  if (level === "Suspicious") return "Potential threat signals detected";
  return "Low-risk pattern currently observed";
}

function setChips(container, items) {
  container.innerHTML = "";
  if (!items || items.length === 0) {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = "None";
    container.appendChild(span);
    return;
  }
  items.forEach((item) => {
    const span = document.createElement("span");
    span.className = "chip";
    span.textContent = item;
    container.appendChild(span);
  });
}

function setList(container, items, fallback = "No indicators detected.") {
  container.innerHTML = "";
  if (!items || items.length === 0) {
    const li = document.createElement("li");
    li.textContent = fallback;
    container.appendChild(li);
    return;
  }
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    container.appendChild(li);
  });
}

function extractIntent(explanationText) {
  const text = explanationText || "";
  if (!text) return "No explicit social-engineering intent evidence detected.";
  const sentences = text.split(".").map((part) => part.trim()).filter(Boolean);
  const hit = sentences.find((line) => line.toLowerCase().includes("social-engineering intent"));
  return hit ? `${hit}.` : "No explicit social-engineering intent evidence detected.";
}

function renderEnterprise(enterprise) {
  if (!enterprise) {
    enterpriseWrap.classList.add("hidden");
    return;
  }
  enterpriseWrap.classList.remove("hidden");
  enterpriseMeta.textContent = `Mode: ${enterprise.mode || "enterprise"} | Strict: ${enterprise.strictMode ? "ON" : "OFF"}`;

  const confidence = enterprise.modalityConfidence || {};
  const confItems = [
    `Images: ${confidence.images ?? "N/A"}%`,
    `Videos/GIFs: ${confidence.videos ?? "N/A"}%`,
    `Audio: ${confidence.audio ?? "N/A"}%`,
    `Links: ${confidence.links ?? "N/A"}%`,
    `Attachments: ${confidence.attachments ?? "N/A"}%`,
    `Overall: ${confidence.overall ?? "N/A"}%`,
  ];
  setList(modalityConfidence, confItems, "No confidence metrics.");

  const engines = enterprise.engineStatus || {};
  const engineItems = Object.entries(engines).map(([name, state]) => {
    const token = state && state.available ? "Available" : "Unavailable";
    const details = state && state.details ? ` - ${state.details}` : "";
    return `${name}: ${token}${details}`;
  });
  setList(engineStatus, engineItems, "No engine status.");

  const flags = (enterprise.operationalFlags || []).map((flag) => {
    const sev = (flag.severity || "warn").toUpperCase();
    const mod = flag.modality || "system";
    const msg = flag.message || "Operational issue";
    return `[${sev}] ${mod}: ${msg}`;
  });
  setList(operationalFlags, flags, "No operational warnings.");

  const forensics = enterprise.forensicSignals || {};
  const forensicItems = [];
  (forensics.steganography || []).forEach((item) => forensicItems.push(`Steganography: ${item}`));
  (forensics.voiceImpersonation || []).forEach((item) => forensicItems.push(`Voice impersonation: ${item}`));
  setList(forensicSignals, forensicItems, "No forensic anomaly signals.");
}

function renderResult(data) {
  const score = Math.max(0, Math.min(100, Number(data.threatScore || 0)));
  const level = data.riskLevel || "Safe";
  const media = data.multimediaRisks || {};

  scoreValue.textContent = String(score);
  riskBadge.textContent = level;
  riskBadge.className = `risk-badge ${riskClass(level)}`;
  scoreFill.style.width = `${score}%`;
  scoreDial.style.setProperty("--score", score);
  verdictLine.textContent = riskHeadline(level);
  riskPanel.classList.remove("tone-safe", "tone-suspicious", "tone-danger");
  riskPanel.classList.add(riskTone(level));

  setChips(emotions, data.emotionsDetected);
  setChips(techniques, data.psychologicalTechniques);
  setList(indicators, data.phishingIndicators);
  intentSummary.textContent = extractIntent(data.explanation);

  emotionCount.textContent = String((data.emotionsDetected || []).length);
  techniqueCount.textContent = String((data.psychologicalTechniques || []).length);
  indicatorCount.textContent = String((data.phishingIndicators || []).length);

  const riskEntries = [
    `Images: ${media.images || "No image-specific red flags detected."}`,
    `Videos/GIFs: ${media.videos || "No video/GIF-specific red flags detected."}`,
    `Audio: ${media.audio || "No audio-specific red flags detected."}`,
    `Links: ${media.links || "No links detected."}`,
    `Attachments: ${media.attachments || "No high-risk attachment types detected."}`,
  ];
  setList(mediaRisks, riskEntries);
  explanation.textContent = data.explanation || "";
  userAdvice.textContent = data.userAdvice || "";
  renderEnterprise(data.enterprise);
  rawJson.textContent = JSON.stringify(data, null, 2);
  resultWrap.classList.remove("hidden");
}

async function analyzeEmail(event) {
  event.preventDefault();
  loading.classList.remove("hidden");
  analyzeBtn.disabled = true;
  verdictLine.textContent = "Running full multimodal analysis...";

  const body = new FormData();
  body.append("emailText", emailText.value || "");
  body.append("embeddedLinks", embeddedLinks.value || "");
  body.append("mediaLinks", mediaLinks.value || "");
  body.append("enterpriseMode", enterpriseMode.checked ? "true" : "false");
  body.append("strictMode", strictMode.checked ? "true" : "false");
  Array.from(attachments.files || []).forEach((file) => body.append("attachments", file));

  try {
    const response = await fetch("/api/analyze", { method: "POST", body });
    if (!response.ok) throw new Error("Threat analysis failed");
    const data = await response.json();
    renderResult(data);
    await loadHistory();
  } catch (error) {
    alert(error.message || "Unable to analyze email.");
    verdictLine.textContent = "Analysis failed.";
  } finally {
    loading.classList.add("hidden");
    analyzeBtn.disabled = false;
  }
}

async function loadHistory() {
  try {
    const response = await fetch("/api/history?limit=12");
    if (!response.ok) throw new Error("History fetch failed");
    const payload = await response.json();
    const items = payload.items || [];

    historyCount.textContent = `${items.length} scans`;
    historyList.innerHTML = "";
    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "history-item";
      li.textContent = "No scans yet.";
      historyList.appendChild(li);
      return;
    }

    items.forEach((item) => {
      const li = document.createElement("li");
      const riskToken = (item.riskLevel || "").toLowerCase();
      li.className = `history-item is-${riskToken}`;
      li.innerHTML = `
        <p><strong>#${item.id}</strong> ${item.createdAt}</p>
        <p>Threat Score: <strong>${item.threatScore}</strong></p>
        <p>Risk Level: <strong>${item.riskLevel}</strong></p>
      `;
      li.addEventListener("click", () => renderResult(item.result));
      historyList.appendChild(li);
    });
  } catch {
    historyCount.textContent = "0 scans";
    historyList.innerHTML = `<li class="history-item">History unavailable.</li>`;
  }
}

function loadSample() {
  emailText.value = `Subject: Immediate Account Verification Required

Dear Employee,
Our IT Security Team noticed unusual login activity in your mailbox. If you do not verify your account immediately, access will be suspended within 24 hours.

Click now: http://bit.ly/urgent-secure-login
Open the attached invoice for compliance proof and confirm your password to avoid legal action.

Regards,
Corporate IT Support`;
  embeddedLinks.value = "http://bit.ly/urgent-secure-login\nhttps://secure-update-account.top/verify";
  mediaLinks.value = "https://media-cdn.example.com/security_alert.gif";
  enterpriseMode.checked = true;
  strictMode.checked = false;
  updateLivePreview();
}

function updateFileMeta() {
  const fileCount = (attachments.files || []).length;
  if (fileCount === 0) {
    fileMeta.textContent = "No files selected.";
    return;
  }
  const names = Array.from(attachments.files).slice(0, 2).map((f) => f.name);
  const suffix = fileCount > 2 ? ` +${fileCount - 2} more` : "";
  fileMeta.textContent = `${fileCount} file(s): ${names.join(", ")}${suffix}`;
}

function updateLivePreview() {
  const text = `${emailText.value}\n${embeddedLinks.value}\n${mediaLinks.value}`.toLowerCase();
  const hits = LIVE_CUES.filter((cue) => cue.words.some((word) => text.includes(word)));
  if (hits.length === 0) {
    livePreview.textContent = "No pressure cues detected yet.";
    return;
  }
  livePreview.textContent = `Detected cues: ${hits.map((h) => h.label).join(", ")}`;
}

form.addEventListener("submit", analyzeEmail);
sampleBtn.addEventListener("click", loadSample);
refreshHistoryBtn.addEventListener("click", loadHistory);
attachments.addEventListener("change", updateFileMeta);
emailText.addEventListener("input", updateLivePreview);
embeddedLinks.addEventListener("input", updateLivePreview);
mediaLinks.addEventListener("input", updateLivePreview);
strictMode.addEventListener("change", () => {
  if (strictMode.checked) enterpriseMode.checked = true;
});
enterpriseMode.addEventListener("change", () => {
  if (!enterpriseMode.checked) strictMode.checked = false;
});

loadHistory();
updateLivePreview();
setInterval(loadHistory, 12000);
