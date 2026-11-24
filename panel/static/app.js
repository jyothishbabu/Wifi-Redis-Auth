// No inline scripts (blocked by the Content-Security-Policy), so behaviour lives here.
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("form[data-confirm]").forEach(f =>
    f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

  document.querySelectorAll("[data-reveal]").forEach(b => b.addEventListener("click", () => {
    const i = b.parentElement.querySelector("input");
    if (i.type === "password") { i.type = "text"; i.value = i.dataset.current; b.textContent = "Hide"; }
    else { i.type = "password"; i.value = ""; b.textContent = "Show current"; }
  }));

  document.querySelectorAll("[data-generate]").forEach(b => b.addEventListener("click", () => {
    const abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const r = crypto.getRandomValues(new Uint32Array(32));
    const i = b.parentElement.querySelector("input");
    i.type = "text"; i.value = Array.from(r, n => abc[n % abc.length]).join("");
  }));

  document.querySelectorAll("[data-autoscroll]").forEach(p => p.scrollTop = p.scrollHeight);

  // While a reload is pending, refresh once the radius container picks it up.
  const st = document.getElementById("status");
  if (st && st.querySelector(".pill.warn")) {
    const t = setInterval(async () => {
      try {
        const s = await (await fetch("/api/status", {credentials: "same-origin"})).json();
        if (!s.reload_pending) { clearInterval(t); location.reload(); }
      } catch (e) { clearInterval(t); }
    }, 2000);
  }
});

document.addEventListener("DOMContentLoaded", () => {
  const r = document.querySelector("[data-redirect]");
  if (r) setTimeout(() => { location.href = r.dataset.redirect; }, Number(r.dataset.delay || 8000));
  document.querySelectorAll("[data-copy]").forEach(b => b.addEventListener("click", async () => {
    await navigator.clipboard.writeText(document.getElementById(b.dataset.copy).textContent);
    b.textContent = "Copied";
  }));
});
