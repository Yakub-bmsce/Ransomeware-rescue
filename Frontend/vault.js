"use strict";

// Student Vault frontend-only demonstration: no backend calls and no persistent storage.
const menu = document.querySelector(".menu-toggle");
function closeMenu() {
  document.body.classList.remove("menu-open");
  if (menu) menu.setAttribute("aria-expanded", "false");
}
if (menu) {
  menu.addEventListener("click", () => {
    const expanded = document.body.classList.toggle("menu-open");
    menu.setAttribute("aria-expanded", String(expanded));
  });
  document.addEventListener("keydown", event => { if (event.key === "Escape") { closeMenu(); menu.focus(); } });
  document.addEventListener("click", event => { if (!event.target.closest("#sidebar,.menu-toggle")) closeMenu(); });
}

document.querySelectorAll("[data-password]").forEach(button => {
  button.addEventListener("click", () => {
    const field = document.getElementById(button.dataset.password);
    if (!field) return;
    const show = field.type === "password";
    field.type = show ? "text" : "password";
    button.setAttribute("aria-label", show ? "Hide password" : "Show password");
    button.setAttribute("aria-pressed", String(show));
  });
});

document.querySelectorAll("time[datetime]").forEach(el => {
  const d = new Date(el.dateTime);
  if (!Number.isNaN(d.valueOf())) el.title = el.textContent;
});

function notice(message) {
  let n = document.querySelector(".demo-toast");
  if (!n) { n = document.createElement("div"); n.className = "notice warning demo-toast"; n.setAttribute("role", "status"); document.body.appendChild(n); }
  n.textContent = message;
  n.classList.add("show");
  clearTimeout(notice.timer);
  notice.timer = setTimeout(() => n.classList.remove("show"), 4200);
}

// Auth is a visual entry point only. Continue to the pre-filled demonstration workspace.
document.querySelectorAll(".auth-form form").forEach(form => {
  form.addEventListener("submit", e => {
    e.preventDefault();
    window.location.href = "dashboard.html";
  });
});

// Intercept every other form: nothing is submitted or sent to a server.
document.querySelectorAll("form").forEach(form => {
  if (form.closest(".auth-form")) return;
  form.addEventListener("submit", e => {
    e.preventDefault();
    const label = (e.submitter?.textContent || "").trim().replace(/\s+/g, " ");
    const formText = (form.textContent || "").toLowerCase();
    if (form.classList.contains("filters")) {
      const query = (form.querySelector('input[type="search"]')?.value || "").toLowerCase();
      const selectValues = [...form.querySelectorAll("select")].map(s => s.value ? (s.selectedOptions[0]?.textContent || s.value).toLowerCase() : "").filter(Boolean);
      const table = form.parentElement.querySelector("table");
      if (table) {
        [...table.querySelectorAll("tbody tr")].forEach(row => {
          const t = row.textContent.toLowerCase();
          row.hidden = !!query && !t.includes(query) || selectValues.some(v => !t.includes(v));
        });
      }
      notice("Demo filter applied in this browser only. No data was saved.");
      return;
    }
    if (label.toLowerCase().includes("log out")) { window.location.href = "index.html"; return; }
    if (form.querySelector('input[type="file"]')) { notice("Frontend demo only: the selected file was not uploaded or stored."); return; }
    if (formText.includes("simulated modification") || label.toLowerCase().includes("ransomware")) {
      const banner = document.querySelector(".risk-banner");
      if (banner) banner.innerHTML = '<div class="score"><strong>72</strong><small>/ 100</small></div><div><span class="eyebrow">Five-minute risk score · demo</span><h2>High risk</h2><p>Simulated response shown locally. No files were changed.</p></div>';
      notice("Detection demonstration shown locally. No files or records were changed.");
      return;
    }
    if (label.toLowerCase().includes("verify")) { notice("Demo only: backup verification is represented for display; nothing was processed or saved."); return; }
    if (label.toLowerCase().includes("restore") || label.toLowerCase().includes("scan")) { notice("Demo only: recovery action previewed. No file was restored or stored."); return; }
    if (label.toLowerCase().includes("unlock") || label.toLowerCase().includes("resolve")) { notice("Demo only: administration action previewed. No account or alert was changed."); return; }
    if (label.toLowerCase().includes("save") || label.toLowerCase().includes("setup") || label.toLowerCase().includes("disable")) { notice("Demo only: settings are not saved or sent anywhere."); return; }
    notice("This is a frontend-only demonstration. No data is stored or sent.");
  });
});

document.querySelectorAll('a[href="#demo-action"]').forEach(a => {
  a.addEventListener("click", e => { e.preventDefault(); notice("Demo only: downloads are not connected to stored files."); });
});

// File picker displays the selected filename without reading or uploading its contents.
document.querySelectorAll('input[type="file"]').forEach(input => {
  input.addEventListener("change", () => {
    const file = input.files?.[0];
    const label = input.closest(".file-pick");
    const small = label?.querySelector("small");
    if (file && small) small.textContent = `${file.name} selected · demo only, not uploaded`;
  });
});
