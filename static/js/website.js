const websiteForm = document.getElementById("websiteForm");
const urlInput = document.getElementById("urlInput");
const pageTitle = document.getElementById("pageTitle");
const pageText = document.getElementById("pageText");
const sampleWebBtn = document.getElementById("sampleWebBtn");
const checkWebBtn = document.getElementById("checkWebBtn");

const webRiskPanel = document.getElementById("webRiskPanel");
const webRiskBadge = document.getElementById("webRiskBadge");
const webThreatScore = document.getElementById("webThreatScore");
const webScoreDial = document.getElementById("webScoreDial");
const webVerdictLine = document.getElementById("webVerdictLine");
const webScoreFill = document.getElementById("webScoreFill");
const webConfidence = document.getElementById("webConfidence");
const webEmotionCount = document.getElementById("webEmotionCount");
const webIndicatorCount = document.getElementById("webIndicatorCount");
const webLoading = document.getElementById("webLoading");
const webResultWrap = document.getElementById("webResultWrap");

const webEmotions = document.getElementById("webEmotions");
const webTechniques = document.getElementById("webTechniques");
const webIndicators = document.getElementById("webIndicators");
const webExplanation = document.getElementById("webExplanation");
const webAdvice = document.getElementById("webAdvice");
const webRawJson = document.getElementById("webRawJson");

const refreshWebHistoryBtn = document.getElementById("refreshWebHistoryBtn");
const webHistoryCount = document.getElementById("webHistoryCount");
const webHistoryList = document.getElementById("webHistoryList");

let autoCheckTimer = null;

function webRiskClass(level) {
  if (level === "Unsafe") return "risk-unsafe";
  if (level === "Safe") return "risk-safe-level";
  return "risk-safe";
}

function webTone(level) {
  if (level === "Unsafe") return "tone-unsafe";
  if (level === "Safe") return "tone-safe-level";
  return "tone-safe";
}

function webHeadline(level) {
  if (level === "Unsafe") return "Unsafe site pattern detected";
  if (level === "Safe") return "Caution advised for this site";
  return "Legitimate signals dominant";
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

function renderWebsiteResult(data) {
  const score = Math.max(0, Math.min(100, Number(data.threatScore || 0)));
  webRiskBadge.textContent = data.riskLevel || "Legitimate";
  webRiskBadge.className = `risk-badge ${webRiskClass(data.riskLevel)}`;
  webThreatScore.textContent = String(score);
  webScoreDial.style.setProperty("--score", score);
  webScoreFill.style.width = `${score}%`;
  webVerdictLine.textContent = webHeadline(data.riskLevel || "Legitimate");
  webRiskPanel.classList.remove("tone-safe", "tone-safe-level", "tone-unsafe");
  webRiskPanel.classList.add(webTone(data.riskLevel || "Legitimate"));

  webConfidence.textContent = `${Number(data.confidence || 0)}%`;
  webEmotionCount.textContent = String((data.emotionsDetected || []).length);
  webIndicatorCount.textContent = String((data.phishingIndicators || []).length);

  setChips(webEmotions, data.emotionsDetected);
  setChips(webTechniques, data.psychologicalTechniques);
  setList(webIndicators, data.phishingIndicators);

  webExplanation.textContent = data.explanation || "";
  webAdvice.textContent = data.userAdvice || "";
  webRawJson.textContent = JSON.stringify(data, null, 2);
  webResultWrap.classList.remove("hidden");
}

async function checkWebsite(event, silent = false) {
  if (event) event.preventDefault();
  const url = (urlInput.value || "").trim();
  if (!url) return;

  if (!silent) {
    webLoading.classList.remove("hidden");
    checkWebBtn.disabled = true;
  }

  const payload = {
    url,
    pageData: {
      title: (pageTitle.value || "").trim(),
      textSample: (pageText.value || "").trim(),
      links: [],
      forms: [],
      images: [],
      videos: [],
      audios: [],
      scripts: [],
      meta: {},
    },
  };

  try {
    const response = await fetch("/api/website/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error("Website analysis failed");
    const data = await response.json();
    renderWebsiteResult(data);
    await loadWebHistory();
  } catch (error) {
    if (!silent) {
      alert(error.message || "Unable to check website.");
    }
  } finally {
    if (!silent) {
      webLoading.classList.add("hidden");
      checkWebBtn.disabled = false;
    }
  }
}

function triggerAutoCheck() {
  clearTimeout(autoCheckTimer);
  autoCheckTimer = setTimeout(() => {
    if (urlInput.value.trim().length >= 8) {
      checkWebsite(null, true);
    }
  }, 800);
}

function loadPhishSample() {
  urlInput.value = "http://verify-account-bank.top/login";
  pageTitle.value = "Urgent Security Verification";
  pageText.value = "Your account will be suspended. Verify immediately and enter password now.";
  checkWebsite();
}

async function loadWebHistory() {
  try {
    const response = await fetch("/api/website/history?limit=12");
    if (!response.ok) throw new Error("history");
    const payload = await response.json();
    const items = payload.items || [];
    webHistoryCount.textContent = `${items.length} scans`;
    webHistoryList.innerHTML = "";

    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "history-item";
      li.textContent = "No website scans yet.";
      webHistoryList.appendChild(li);
      return;
    }

    items.forEach((item) => {
      const li = document.createElement("li");
      li.className = `history-item is-${(item.riskLevel || "").toLowerCase()}`;
      li.innerHTML = `
        <p><strong>#${item.id}</strong> ${item.createdAt}</p>
        <p><code>${item.url || "-"}</code></p>
        <p>Risk: <strong>${item.riskLevel}</strong> • Score: <strong>${item.threatScore}</strong></p>
      `;
      li.addEventListener("click", () => renderWebsiteResult(item.result));
      webHistoryList.appendChild(li);
    });
  } catch {
    webHistoryCount.textContent = "0 scans";
    webHistoryList.innerHTML = `<li class="history-item">History unavailable.</li>`;
  }
}

websiteForm.addEventListener("submit", checkWebsite);
sampleWebBtn.addEventListener("click", loadPhishSample);
refreshWebHistoryBtn.addEventListener("click", loadWebHistory);
urlInput.addEventListener("input", triggerAutoCheck);
pageTitle.addEventListener("input", triggerAutoCheck);
pageText.addEventListener("input", triggerAutoCheck);

loadWebHistory();
setInterval(loadWebHistory, 10000);
