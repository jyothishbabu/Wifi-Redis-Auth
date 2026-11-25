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

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-copy-input]").forEach(b => b.addEventListener("click", async () => {
    const i = document.getElementById(b.dataset.copyInput);
    i.select(); await navigator.clipboard.writeText(i.value); b.textContent = "Copied";
  }));
  // Enrollment page: make the button for this computer's OS the primary one.
  const form = document.getElementById("enroll-form");
  if (form) {
    const ua = navigator.userAgent, mac = /Mac|iPhone|iPad/.test(ua);
    form.querySelectorAll("[data-os]").forEach(b => {
      const mine = (b.dataset.os === "mac") === mac;
      b.classList.toggle("secondary", !mine);
      if (mine) form.prepend(b);
    });
  }
});

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-confirm-click]").forEach(b =>
    b.addEventListener("click", e => { if (!confirm(b.dataset.confirmClick)) e.preventDefault(); }));
});
