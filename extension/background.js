import { analyzeWebsiteLocal } from "./local_model.js";

const DEFAULT_SETTINGS = {
  protectionEnabled: true,
  backendUrl: "http://127.0.0.1:5000/api/website/analyze"
};

const DEFAULT_STATS = {
  urlsChecked: 0,
  threatsBlocked: 0,
  warningsShown: 0
};

async function getStorage(keys) {
  return chrome.storage.local.get(keys);
}

async function setStorage(values) {
  return chrome.storage.local.set(values);
}

async function getSettings() {
  const stored = await getStorage(["settings"]);
  return { ...DEFAULT_SETTINGS, ...(stored.settings || {}) };
}

async function getStats() {
  const stored = await getStorage(["stats"]);
  return { ...DEFAULT_STATS, ...(stored.stats || {}) };
}

async function setStats(stats) {
  await setStorage({ stats });
}

async function getTabResults() {
  const stored = await getStorage(["tabResults"]);
  return stored.tabResults || {};
}

async function setTabResult(tabId, result) {
  const all = await getTabResults();
  all[String(tabId)] = { ...result, timestamp: Date.now() };
  await setStorage({ tabResults: all });
}

function badgeFromRisk(riskLevel) {
  if (riskLevel === "Unsafe") return { text: "!", color: "#b4232f" };
  if (riskLevel === "Safe") return { text: "~", color: "#c07a10" };
  return { text: "OK", color: "#1f8b4d" };
}

async function setBadge(tabId, riskLevel) {
  const badge = badgeFromRisk(riskLevel);
  await chrome.action.setBadgeText({ tabId, text: badge.text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

async function clearBadge(tabId) {
  await chrome.action.setBadgeText({ tabId, text: "" });
}

function isHttpUrl(url) {
  return /^https?:\/\//i.test(url || "");
}

function collectPageSnapshot() {
  const text = (document.body?.innerText || "").replace(/\s+/g, " ").trim().slice(0, 7000);
  const links = Array.from(document.querySelectorAll("a[href]"))
    .slice(0, 300)
    .map((a) => ({
      href: a.href || "",
      text: (a.innerText || a.textContent || "").trim().slice(0, 120)
    }));
  const forms = Array.from(document.querySelectorAll("form"))
    .slice(0, 50)
    .map((form) => {
      const inputs = Array.from(form.querySelectorAll("input, textarea, select"));
      return {
        action: form.getAttribute("action") || "",
        method: (form.getAttribute("method") || "get").toLowerCase(),
        inputTypes: inputs.map((i) => (i.getAttribute("type") || i.tagName || "").toLowerCase()),
        inputNames: inputs.map((i) => (i.getAttribute("name") || i.getAttribute("id") || "").toLowerCase())
      };
    });

  const images = Array.from(document.querySelectorAll("img[src]"))
    .slice(0, 200)
    .map((img) => ({ src: img.src || "", alt: img.alt || "" }));
  const videos = Array.from(document.querySelectorAll("video source[src], video[src]"))
    .slice(0, 100)
    .map((v) => ({ src: v.src || "" }));
  const audios = Array.from(document.querySelectorAll("audio source[src], audio[src]"))
    .slice(0, 100)
    .map((a) => ({ src: a.src || "" }));
  const scripts = Array.from(document.querySelectorAll("script[src]"))
    .slice(0, 300)
    .map((s) => ({ src: s.src || "" }));

  return {
    title: document.title || "",
    textSample: text,
    links,
    forms,
    images,
    videos,
    audios,
    scripts,
    meta: {
      iframeCount: document.querySelectorAll("iframe").length,
      hiddenElementsCount: document.querySelectorAll(
        "[style*='display:none'], [style*='visibility:hidden'], [hidden], [aria-hidden='true']"
      ).length,
      pageLanguage: document.documentElement?.lang || ""
    }
  };
}

async function capturePageData(tabId) {
  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId },
      func: collectPageSnapshot
    });
    return results?.[0]?.result || {};
  } catch {
    return {};
  }
}

async function captureScreenshot(windowId) {
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: "png", quality: 70 });
    if (typeof dataUrl === "string" && dataUrl.startsWith("data:image")) {
      return dataUrl;
    }
    return "";
  } catch {
    return "";
  }
}

async function analyzeWithBackend(url, pageData) {
  const settings = await getSettings();
  try {
    const response = await fetch(settings.backendUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, pageData })
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const data = await response.json();
    return { ...data, source: "backend" };
  } catch {
    return { ...analyzeWebsiteLocal(url, pageData), source: "fallback-local-model" };
  }
}

async function updateStatsWithResult(result) {
  const stats = await getStats();
  stats.urlsChecked += 1;
  if (result.riskLevel === "Unsafe") {
    stats.threatsBlocked += 1;
    stats.warningsShown += 1;
  }
  await setStats(stats);
  return stats;
}

async function maybeNotifyUnsafe(result, url) {
  if (result.riskLevel !== "Unsafe") return;
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMAASsJTYQAAAAASUVORK5CYII=",
      title: "CyberMood Warning",
      message: `Unsafe website detected: ${url}`
    });
  } catch {
    return;
  }
}

async function scanTab(tabId, url, force = false, windowId = chrome.windows.WINDOW_ID_CURRENT) {
  const settings = await getSettings();
  if (!settings.protectionEnabled && !force) {
    await clearBadge(tabId);
    return { skipped: true, reason: "Protection disabled" };
  }

  const cache = await getTabResults();
  const existing = cache[String(tabId)];
  if (!force && existing && existing.url === url && Date.now() - existing.timestamp < 20000) {
    return existing;
  }

  const pageData = await capturePageData(tabId);
  const screenshotDataUrl = await captureScreenshot(windowId);
  if (screenshotDataUrl) {
    pageData.screenshotDataUrl = screenshotDataUrl;
  }
  const result = await analyzeWithBackend(url, pageData);
  await setBadge(tabId, result.riskLevel);
  await setTabResult(tabId, { url, result });
  await updateStatsWithResult(result);
  await maybeNotifyUnsafe(result, url);
  return { url, result };
}

async function manualCheck(url) {
  const result = await analyzeWithBackend(url, {});
  await updateStatsWithResult(result);
  return result;
}

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await getStorage(["settings", "stats", "tabResults"]);
  if (!stored.settings) await setStorage({ settings: DEFAULT_SETTINGS });
  if (!stored.stats) await setStorage({ stats: DEFAULT_STATS });
  if (!stored.tabResults) await setStorage({ tabResults: {} });
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return;
  if (!isHttpUrl(tab?.url)) {
    await clearBadge(tabId);
    return;
  }
  await scanTab(tabId, tab.url, false, tab.windowId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (message?.type === "GET_SETTINGS") {
      sendResponse({ ok: true, settings: await getSettings() });
      return;
    }

    if (message?.type === "SET_PROTECTION") {
      const settings = await getSettings();
      settings.protectionEnabled = Boolean(message.enabled);
      await setStorage({ settings });
      sendResponse({ ok: true, settings });
      return;
    }

    if (message?.type === "SET_BACKEND_URL") {
      const settings = await getSettings();
      settings.backendUrl = String(message.backendUrl || DEFAULT_SETTINGS.backendUrl).trim();
      await setStorage({ settings });
      sendResponse({ ok: true, settings });
      return;
    }

    if (message?.type === "GET_STATS") {
      sendResponse({ ok: true, stats: await getStats() });
      return;
    }

    if (message?.type === "CLEAR_STATS") {
      await setStats({ ...DEFAULT_STATS });
      sendResponse({ ok: true, stats: await getStats() });
      return;
    }

    if (message?.type === "GET_LAST_RESULT") {
      const all = await getTabResults();
      sendResponse({ ok: true, item: all[String(message.tabId)] || null });
      return;
    }

    if (message?.type === "ANALYZE_CURRENT_TAB") {
      const tab = await chrome.tabs.get(message.tabId);
      const result = await scanTab(message.tabId, message.url, Boolean(message.force), tab.windowId);
      sendResponse({ ok: true, data: result });
      return;
    }

    if (message?.type === "MANUAL_CHECK") {
      const result = await manualCheck(message.url);
      sendResponse({ ok: true, data: result });
      return;
    }

    sendResponse({ ok: false, error: "Unsupported message type" });
  })().catch((err) => {
    sendResponse({ ok: false, error: String(err) });
  });

  return true;
});
