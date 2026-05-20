const statEmailTotal = document.getElementById("statEmailTotal");
const statWebTotal = document.getElementById("statWebTotal");
const statDangerous = document.getElementById("statDangerous");
const statSuspicious = document.getElementById("statSuspicious");
const dashboardEmailList = document.getElementById("dashboardEmailList");
const dashboardWebList = document.getElementById("dashboardWebList");
const mlAccuracyMeta = document.getElementById("mlAccuracyMeta");
const mlAccuracyChart = document.getElementById("mlAccuracyChart");

function createSimpleCard(lines, className = "history-item") {
  const li = document.createElement("li");
  li.className = className;
  li.innerHTML = lines.map((line) => `<p>${line}</p>`).join("");
  return li;
}

function fmtPct(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "N/A";
  return `${(n * 100).toFixed(2)}%`;
}

function clampPct(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n * 100));
}

function createAccuracyRow(task, targetAccuracy) {
  const valAcc = Number(task.validationAccuracy);
  const testAcc = Number(task.testAccuracy);
  const target = Number(targetAccuracy || 0.97);
  const meetsTarget = Boolean(task.meetsTarget);

  const article = document.createElement("article");
  article.className = `acc-row ${meetsTarget ? "acc-pass" : "acc-fail"}`;
  article.innerHTML = `
    <div class="acc-head">
      <h3>${task.task}</h3>
      <span class="risk-badge ${meetsTarget ? "risk-safe" : "risk-suspicious"}">
        ${meetsTarget ? ">= Target" : "< Target"}
      </span>
    </div>
    <p class="hint">Target: ${fmtPct(target)}</p>
    <div class="acc-line">
      <span>Validation ${fmtPct(valAcc)}</span>
      <div class="acc-bar"><span style="width:${clampPct(valAcc)}%"></span></div>
    </div>
    <div class="acc-line">
      <span>Test ${fmtPct(testAcc)}</span>
      <div class="acc-bar"><span style="width:${clampPct(testAcc)}%"></span></div>
    </div>
  `;
  return article;
}

async function loadDashboard() {
  try {
    const [emailRes, webRes] = await Promise.all([
      fetch("/api/history?limit=8"),
      fetch("/api/website/history?limit=8"),
    ]);
    if (!emailRes.ok || !webRes.ok) throw new Error("Fetch failed");

    const emailPayload = await emailRes.json();
    const webPayload = await webRes.json();
    const emailItems = emailPayload.items || [];
    const webItems = webPayload.items || [];

    statEmailTotal.textContent = String(emailItems.length);
    statWebTotal.textContent = String(webItems.length);

    const dangerCount =
      emailItems.filter((x) => x.riskLevel === "Dangerous").length +
      webItems.filter((x) => x.riskLevel === "Unsafe").length;
    const suspiciousCount =
      emailItems.filter((x) => x.riskLevel === "Suspicious").length +
      webItems.filter((x) => x.riskLevel === "Safe").length;

    statDangerous.textContent = String(dangerCount);
    statSuspicious.textContent = String(suspiciousCount);

    dashboardEmailList.innerHTML = "";
    if (emailItems.length === 0) {
      dashboardEmailList.appendChild(createSimpleCard(["No email scans yet."]));
    } else {
      emailItems.slice(0, 6).forEach((item) => {
        const cls = `history-item is-${(item.riskLevel || "").toLowerCase()}`;
        dashboardEmailList.appendChild(
          createSimpleCard(
            [
              `<strong>#${item.id}</strong> ${item.createdAt}`,
              `Score: <strong>${item.threatScore}</strong>`,
              `Risk: <strong>${item.riskLevel}</strong>`,
            ],
            cls
          )
        );
      });
    }

    dashboardWebList.innerHTML = "";
    if (webItems.length === 0) {
      dashboardWebList.appendChild(createSimpleCard(["No website scans yet."]));
    } else {
      webItems.slice(0, 6).forEach((item) => {
        const cls = `history-item is-${(item.riskLevel || "").toLowerCase()}`;
        dashboardWebList.appendChild(
          createSimpleCard(
            [
              `<strong>#${item.id}</strong> ${item.createdAt}`,
              `<code>${item.url || "-"}</code>`,
              `Risk: <strong>${item.riskLevel}</strong> • Score: <strong>${item.threatScore}</strong>`,
            ],
            cls
          )
        );
      });
    }
  } catch {
    dashboardEmailList.innerHTML = "";
    dashboardWebList.innerHTML = "";
    dashboardEmailList.appendChild(createSimpleCard(["Unable to load email scans."]));
    dashboardWebList.appendChild(createSimpleCard(["Unable to load website scans."]));
  }
}

async function loadMLAccuracyGraph() {
  mlAccuracyChart.innerHTML = "";
  try {
    const response = await fetch("/api/ml/metrics");
    if (!response.ok) throw new Error("ML metrics unavailable");
    const payload = await response.json();
    const tasks = (payload.tasks || []).filter((task) => task.status === "trained");
    const target = Number(payload.targetAccuracy || 0.97);

    mlAccuracyMeta.textContent = `Target ${fmtPct(target)} • Trained ${tasks.length} • Generated ${payload.generatedAtUtc || "N/A"}`;
    if (tasks.length === 0) {
      const empty = document.createElement("p");
      empty.className = "hint";
      empty.textContent = "No trained models found in metrics report.";
      mlAccuracyChart.appendChild(empty);
      return;
    }

    tasks.forEach((task) => {
      mlAccuracyChart.appendChild(createAccuracyRow(task, target));
    });
  } catch {
    mlAccuracyMeta.textContent = "ML metrics not available";
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "Run ml/scripts/train_suite.py to generate ml/reports/latest_metrics.json.";
    mlAccuracyChart.appendChild(empty);
  }
}

loadDashboard();
loadMLAccuracyGraph();
setInterval(loadDashboard, 12000);
