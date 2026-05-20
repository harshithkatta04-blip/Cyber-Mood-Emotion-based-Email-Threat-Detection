function activateNav() {
  const page = document.body.dataset.page || "dashboard";
  document.querySelectorAll(".nav-link").forEach((link) => {
    if (link.dataset.nav === page) {
      link.classList.add("is-active");
    } else {
      link.classList.remove("is-active");
    }
  });
}

async function checkHealth() {
  const dot = document.getElementById("healthDot");
  const label = document.getElementById("healthText");
  if (!dot || !label) return;

  try {
    const res = await fetch("/api/health", { cache: "no-store" });
    if (!res.ok) throw new Error("bad");
    const data = await res.json();
    dot.classList.remove("bad");
    dot.classList.add("ok");
    label.textContent = `Backend online • ${data.time}`;
  } catch {
    dot.classList.remove("ok");
    dot.classList.add("bad");
    label.textContent = "Backend unreachable";
  }
}

activateNav();
checkHealth();
setInterval(checkHealth, 10000);
