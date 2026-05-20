const protectionToggle = document.getElementById("protectionToggle");
const sourceLabel = document.getElementById("sourceLabel");
const statusPanel = document.querySelector(".status-panel");
const statusTitle = document.getElementById("statusTitle");
const statusSubtitle = document.getElementById("statusSubtitle");
const currentUrl = document.getElementById("currentUrl");
const scoreFill = document.getElementById("scoreFill");
const indicatorsList = document.getElementById("indicatorsList");
const manualUrl = document.getElementById("manualUrl");
const manualCheckBtn = document.getElementById("manualCheckBtn");
const manualResult = document.getElementById("manualResult");
const statChecked = document.getElementById("statChecked");
const statBlocked = document.getElementById("statBlocked");
const statWarnings = document.getElementById("statWarnings");
const clearStatsBtn = document.getElementById("clearStatsBtn");
const rescanBtn = document.getElementById("rescanBtn");
const backendUrl = document.getElementById("backendUrl");
const saveBackendBtn = document.getElementById("saveBackendBtn");
const emotionLine = document.getElementById("emotionLine");
const techniqueLine = document.getElementById("techniqueLine");
const intentLine = document.getElementById("intentLine");
const adviceLine = document.getElementById("adviceLine");

let activeTab = null;

function riskClass(level) {
  if (level === "Unsafe") return "danger";
  if (level === "Safe") return "warn";
  return "safe";
}

function trimUrl(url, max = 70) {
  if (!url) return "-";
  return url.length > max ? `${url.slice(0, max - 3)}...` : url;
}

function renderIndicators(indicators) {
  indicatorsList.innerHTML = "";
  const items = Array.isArray(indicators) ? indicators : [];
  if (items.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No indicators.";
    indicatorsList.appendChild(li);
    return;
  }
  items.slice(0, 40).forEach((entry) => {
    const li = document.createElement("li");
    li.textContent = entry;
    indicatorsList.appendChild(li);
  });
}

function renderResult(result, url) {
  const level = result?.riskLevel || "Legitimate";
  const score = Number(result?.threatScore || 0);
  const confidence = Number(result?.confidence || 0);

  statusPanel.classList.remove("safe", "warn", "danger");
  statusPanel.classList.add(riskClass(level));
  statusTitle.textContent =
    level === "Unsafe" ? "Current site is unsafe" : level === "Safe" ? "Current site needs caution" : "Current site looks legitimate";
  statusSubtitle.textContent = `${level.toUpperCase()} (${confidence}% confidence, score ${score})`;
  currentUrl.textContent = trimUrl(url || activeTab?.url || "");
  scoreFill.style.width = `${Math.max(0, Math.min(100, score))}%`;
  sourceLabel.textContent = result?.source === "fallback-local-model" ? "Fallback model ON" : "Backend model ON";
  renderIndicators(result?.phishingIndicators || []);
  const emotions = Array.isArray(result?.emotionsDetected) && result.emotionsDetected.length
    ? result.emotionsDetected.join(", ")
    : "None";
  const techniques = Array.isArray(result?.psychologicalTechniques) && result.psychologicalTechniques.length
    ? result.psychologicalTechniques.join(", ")
    : "None";
  emotionLine.textContent = `Emotions: ${emotions}`;
  techniqueLine.textContent = `Psych techniques: ${techniques}`;
  intentLine.textContent = `Intent: ${result?.socialEngineeringIntent || "-"}`;
  adviceLine.textContent = `Advice: ${result?.userAdvice || "-"}`;
}

async function sendMessage(payload) {
  return chrome.runtime.sendMessage(payload);
}

async function loadStats() {
  const res = await sendMessage({ type: "GET_STATS" });
  if (!res?.ok) return;
  statChecked.textContent = String(res.stats.urlsChecked || 0);
  statBlocked.textContent = String(res.stats.threatsBlocked || 0);
  statWarnings.textContent = String(res.stats.warningsShown || 0);
}

async function loadSettings() {
  const res = await sendMessage({ type: "GET_SETTINGS" });
  if (!res?.ok) return;
  protectionToggle.checked = Boolean(res.settings.protectionEnabled);
  backendUrl.value = res.settings.backendUrl || "";
}

async function analyzeCurrentTab(force = false) {
  if (!activeTab || !/^https?:\/\//i.test(activeTab.url || "")) {
    statusTitle.textContent = "Current page not scannable";
    statusSubtitle.textContent = "Open an HTTP/HTTPS website tab.";
    currentUrl.textContent = trimUrl(activeTab?.url || "");
    return;
  }
  const res = await sendMessage({
    type: "ANALYZE_CURRENT_TAB",
    tabId: activeTab.id,
    url: activeTab.url,
    force
  });
  if (!res?.ok || !res?.data?.result) {
    statusTitle.textContent = "Scan failed";
    statusSubtitle.textContent = res?.error || "Could not analyze the current tab.";
    return;
  }
  renderResult(res.data.result, activeTab.url);
  await loadStats();
}

async function runManualCheck() {
  const url = manualUrl.value.trim();
  if (!url) return;
  manualCheckBtn.disabled = true;
  manualResult.textContent = "Checking...";
  try {
    const res = await sendMessage({ type: "MANUAL_CHECK", url });
    if (!res?.ok || !res?.data) {
      manualResult.textContent = "Manual check failed.";
      return;
    }
    const result = res.data;
    manualResult.textContent = `${result.riskLevel.toUpperCase()} (${result.confidence}% confidence, score ${result.threatScore})`;
    renderIndicators(result.phishingIndicators || []);
    await loadStats();
  } finally {
    manualCheckBtn.disabled = false;
  }
}

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab || null;
  await loadSettings();
  await loadStats();
  await analyzeCurrentTab(false);
}

protectionToggle.addEventListener("change", async () => {
  await sendMessage({ type: "SET_PROTECTION", enabled: protectionToggle.checked });
  await analyzeCurrentTab(true);
});

manualCheckBtn.addEventListener("click", runManualCheck);
manualUrl.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    runManualCheck();
  }
});

clearStatsBtn.addEventListener("click", async () => {
  await sendMessage({ type: "CLEAR_STATS" });
  await loadStats();
});

rescanBtn.addEventListener("click", async () => {
  await analyzeCurrentTab(true);
});

saveBackendBtn.addEventListener("click", async () => {
  await sendMessage({ type: "SET_BACKEND_URL", backendUrl: backendUrl.value.trim() });
  await analyzeCurrentTab(true);
});

init().catch((error) => {
  statusTitle.textContent = "Extension error";
  statusSubtitle.textContent = String(error);
});
