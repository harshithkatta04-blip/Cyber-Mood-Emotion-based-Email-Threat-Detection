const intelTotal = document.getElementById("intelTotal");
const intelCriticalRate = document.getElementById("intelCriticalRate");
const intelSafeRate = document.getElementById("intelSafeRate");
const refreshIntelBtn = document.getElementById("refreshIntelBtn");
const intelFeed = document.getElementById("intelFeed");

function feedCard(item) {
  const li = document.createElement("li");
  li.className = `feed-item is-${item.riskToken}`;
  li.innerHTML = `
    <div class="feed-head">
      <span class="feed-type">${item.kind}</span>
      <span class="feed-time">${item.createdAt}</span>
    </div>
    <p>${item.summary}</p>
    <p>Risk: <strong>${item.riskLevel}</strong> • Score: <strong>${item.threatScore}</strong></p>
  `;
  return li;
}

function toFeedItems(emailItems, webItems) {
  const emailFeed = emailItems.map((x) => ({
    kind: "Email Analysis",
    createdAt: x.createdAt,
    summary: `Entry #${x.id}`,
    riskLevel: x.riskLevel,
    threatScore: x.threatScore,
    riskToken: (x.riskLevel || "").toLowerCase(),
  }));

  const webFeed = webItems.map((x) => ({
    kind: "Website Analysis",
    createdAt: x.createdAt,
    summary: x.url || "Unknown URL",
    riskLevel: x.riskLevel,
    threatScore: x.threatScore,
    riskToken: (x.riskLevel || "").toLowerCase(),
  }));

  return [...emailFeed, ...webFeed].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

function updateStats(items) {
  intelTotal.textContent = String(items.length);
  if (items.length === 0) {
    intelCriticalRate.textContent = "0%";
    intelSafeRate.textContent = "0%";
    return;
  }

  const criticalCount = items.filter((x) => x.riskLevel === "Dangerous" || x.riskLevel === "Unsafe").length;
  const safeCount = items.filter((x) => x.riskLevel === "Safe" || x.riskLevel === "Legitimate").length;

  intelCriticalRate.textContent = `${Math.round((criticalCount / items.length) * 100)}%`;
  intelSafeRate.textContent = `${Math.round((safeCount / items.length) * 100)}%`;
}

async function loadIntelFeed() {
  try {
    const [emailRes, webRes] = await Promise.all([
      fetch("/api/history?limit=30"),
      fetch("/api/website/history?limit=30"),
    ]);
    if (!emailRes.ok || !webRes.ok) throw new Error("Failed");

    const emailPayload = await emailRes.json();
    const webPayload = await webRes.json();
    const items = toFeedItems(emailPayload.items || [], webPayload.items || []);
    updateStats(items);

    intelFeed.innerHTML = "";
    if (items.length === 0) {
      const li = document.createElement("li");
      li.className = "feed-item";
      li.textContent = "No intel yet.";
      intelFeed.appendChild(li);
      return;
    }

    items.slice(0, 40).forEach((item) => intelFeed.appendChild(feedCard(item)));
  } catch {
    intelFeed.innerHTML = "";
    const li = document.createElement("li");
    li.className = "feed-item";
    li.textContent = "Unable to load realtime intel feed.";
    intelFeed.appendChild(li);
  }
}

refreshIntelBtn.addEventListener("click", loadIntelFeed);
loadIntelFeed();
setInterval(loadIntelFeed, 5000);
