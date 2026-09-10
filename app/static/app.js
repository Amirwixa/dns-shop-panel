/* DNS Shop Panel - Global UI JS (v3.0) */
const $ = (id) => document.getElementById(id);
const faNum = (n) => Number(n || 0).toLocaleString("en-US");
let logOffset = 0;
const LOG_LIMIT = 50;

/* ---------- Theme Management ---------- */
function initTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'light') document.documentElement.setAttribute('data-theme', 'light');
}
function toggleTheme() {
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  document.documentElement.setAttribute('data-theme', isLight ? 'dark' : 'light');
  localStorage.setItem('theme', isLight ? 'dark' : 'light');
}
initTheme();

/* ---------- navigation ---------- */
document.querySelectorAll(".nav button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".nav button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
    const pg = b.dataset.page;
    $("page-" + pg).classList.add("active");
    $("page-title").textContent = b.textContent.trim();
    const sidebar = document.getElementById("sidebar");
    if(sidebar) sidebar.classList.remove("open");
    
    // Load page content
    if (pg === "users") loadUsers(true);
    if (pg === "logs") loadLogs(true);
    if (pg === "dns") { loadSettings(); loadRules(); loadMode(); loadWarp(); loadFirewall(); }
    if (pg === "proxy") { loadProxy(); loadProxyLogs(true); loadDiscover(); }
    if (pg === "block") loadBlock();
  });
});

/* ---------- toast ---------- */
function toast(msg, type = "ok") {
  const t = document.createElement("div");
  t.className = "toast " + type;
  t.innerHTML = `<span>${msg}</span> <button style="background:none;border:none;color:inherit;cursor:pointer;font-size:16px;opacity:0.7" onclick="this.parentElement.remove()">✕</button>`;
  $("toasts").appendChild(t);
  setTimeout(() => { if(t.parentElement) t.remove(); }, 4500);
}

/* ---------- API Handler ---------- */
async function api(url, method = "GET", body = null) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body) opt.body = JSON.stringify(body);
  try {
    const r = await fetch(url, opt);
    if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || "خطای نامشخص از سرور");
    return j;
  } catch (e) {
    if (e.message === "auth") throw e;
    throw new Error(e.message || "خطا در ارتباط با شبکه");
  }
}

/* ---------- clock ---------- */
setInterval(() => {
  const clk = $("clock");
  if(clk) clk.textContent = new Date().toLocaleTimeString("fa-IR", { hour: "2-digit", minute: "2-digit" });
}, 1000);

/* ---------- modals ---------- */
function openModal(id) {
  if (id === "m-user") {
    $("mu-title").textContent = "➕ کاربر جدید";
    $("mu-id").value = ""; $("mu-name").value = ""; $("mu-ip").value = "";
    $("mu-days").value = 30; $("mu-notes").value = "";
    $("mu-days-wrap").style.display = "block"; $("mu-exp-wrap").style.display = "none";
  }
  $(id).classList.add("open");
}
function closeModal(id) { $(id).classList.remove("open"); }
document.querySelectorAll(".modal").forEach((m) =>
  m.addEventListener("click", (e) => { if (e.target === m) m.classList.remove("open"); }));

/* ---------- dashboard ---------- */
function drawBarChart(canvasId, labels, values, color) {
  const c = $(canvasId); if(!c) return;
  const ctx = c.getContext("2d");
  const W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(...values, 1), pad = 30;
  const bw = (W - pad * 2) / Math.max(labels.length, 1);
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  
  ctx.strokeStyle = isLight ? "rgba(0,0,0,0.05)" : "rgba(255,255,255,.08)"; 
  ctx.fillStyle = isLight ? "#64748b" : "#8b949e"; 
  ctx.font = "10px Vazirmatn, Tahoma";
  
  for (let i = 0; i <= 4; i++) {
    const y = 10 + ((H - 40) / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(W - 10, y); ctx.stroke();
    ctx.fillText(faNum(Math.round(max - (max / 4) * i)), 2, y + 3);
  }
  values.forEach((v, i) => {
    const h = ((H - 45) / max) * v;
    const x = pad + bw * i + bw * 0.2, y = H - 25 - h;
    const g = ctx.createLinearGradient(0, y, 0, H - 25);
    g.addColorStop(0, color); g.addColorStop(1, color + "22");
    ctx.fillStyle = g;
    ctx.fillRect(x, y, bw * 0.6, Math.max(h, 2));
    if (labels.length <= 24) { ctx.fillStyle = isLight ? "#64748b" : "#8b949e"; ctx.fillText(labels[i], x, H - 10); }
  });
}

function barRows(el, items, labelKey) {
  if (!items.length) { el.innerHTML = '<div class="empty">داده‌ای نیست</div>'; return; }
  const max = Math.max(...items.map((i) => i.count ?? i.c));
  el.innerHTML = items.map((i) => {
    const n = i.count ?? i.c;
    const lbl = i[labelKey] || i.domain || i.name;
    const pct = Math.round((n / max) * 100);
    return `<div class="bar-row"><span class="lbl" title="${lbl}">${lbl}</span>
      <div class="bar"><div class="fill" style="width:${pct}%"></div></div><span class="num">${faNum(n)}</span></div>`;
  }).join("");
}

function fmtUptime(s) {
  s = Math.floor(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  if (d > 0) return `${d} روز ${h} ساعت`;
  if (h > 0) return `${h} ساعت ${m} دقیقه`;
  return `${m} دقیقه`;
}

async function loadDashboard() {
  try {
    const j = await api("/api/dashboard");
    const d = j.data;
    $("c-total").textContent = faNum(d.users.total);
    $("c-active").textContent = faNum(d.users.active);
    $("c-expiring").textContent = faNum(d.users.expiring) + (d.users.pending ? ` (${faNum(d.users.pending)}⏳)` : "");
    $("c-expired").textContent = faNum(d.users.expired + d.users.disabled);
    $("c-qday").textContent = faNum(d.queries.today);
    $("c-qblock").textContent = faNum(d.queries.blocked_today);
    $("c-pxday").textContent = faNum(d.proxy ? d.proxy.today : 0);
    const modeFa = d.dns.mode === "full" ? "🌐 حالت کامل" : "🧠 حالت هوشمند";
    const modeCls = d.dns.mode === "full" ? "b-purple" : "b-blue";
    $("dns-badge").innerHTML = (d.dns.running
      ? `<span class="badge b-green">● سرویس فعال (پورت ${d.dns.port})</span>`
      : `<span class="badge b-red">● سرویس غیرفعال</span>`)
      + ` <span class="badge ${modeCls}">${modeFa}</span>`;
    $("srv-time").textContent = "🕒 " + d.server_time;
    drawBarChart("ch-hour", d.hourly.map((x) => x.hour), d.hourly.map((x) => x.count), "#3d8bfd");
    drawBarChart("ch-day", d.daily.map((x) => x.date.slice(5)), d.daily.map((x) => x.count), "#2fd07a");
    barRows($("top-domains"), d.top_domains, "domain");
    barRows($("top-users"), d.top_users, "name");
    const s = d.system;
    $("sysbox").innerHTML = `
      <div class="s"><div class="n">${s.cpu}%</div><div class="l">CPU</div></div>
      <div class="s"><div class="n">${s.ram_pct}%</div><div class="l">RAM (${faNum(s.ram_used)}/${faNum(s.ram_total)} MB)</div></div>
      <div class="s"><div class="n">${s.disk_pct}%</div><div class="l">Disk (${s.disk_used_gb}/${s.disk_total_gb} GB)</div></div>
      <div class="s"><div class="n" style="font-size:16px; margin-top:4px;">${fmtUptime(s.uptime_sec)}</div><div class="l">آپتایم پنل</div></div>`;
    $("recent-blocked").innerHTML = d.recent_blocked.length ? d.recent_blocked.map((l) =>
      `<div class="bar-row"><span class="lbl">${l.domain}</span>
       <span class="badge ${l.action === "blocked" ? "b-yellow" : "b-red"}" style="font-size:11px">${actFa(l.action)}</span>
       <code>${l.client_ip}</code></div>`).join("")
      : '<div class="empty">موردی نیست 🎉</div>';
    $("recent-proxy").innerHTML = d.recent_proxy && d.recent_proxy.length ? d.recent_proxy.map((p) =>
      `<div class="bar-row"><span class="lbl">${p.sni || "-"}</span>
       <span class="badge ${pxStatusBadge(p.status)}" style="font-size:11px">${pxStatusFa(p.status)}</span>
       <code>${p.client_ip}</code>
       <small style="color:var(--txt-muted);margin-inline-start:auto;">${p.user_name ? esc(p.user_name) : "ناشناس"}</small></div>`).join("")
      : '<div class="empty">هنوز اتصالی ثبت نشده</div>';
  } catch (e) { if (e.message !== "auth") console.error(e); }
}

function actFa(a) { return { allowed: "✅ مجاز", proxied: "🔀 پروکسی", custom: "⭐ کاستوم", blocked: "🚫 بلاک", refused: "⛔ رد", expired: "⌛ منقضی" }[a] || a; }
function actBadge(a) { return { allowed: "b-green", proxied: "b-purple", custom: "b-blue", blocked: "b-yellow", refused: "b-red", expired: "b-red" }[a] || "b-gray"; }
function pxStatusFa(s) { return { ok: "✅ موفق", refused_ip: "⛔ IP ناشناس", refused_sni: "🚫 خارج از لیست", error: "❌ خطا", dns_fail: "❌ خطای DNS", tcp_timeout: "⏱ تایم‌اوت", tcp_refused: "⛔ رد مقصد", tcp_error: "🔌 خطای اتصال", tls_error: "🔒 خطای TLS" }[s] || s; }
function pxStatusBadge(s) { return { ok: "b-green", refused_ip: "b-red", refused_sni: "b-yellow", error: "b-red", dns_fail: "b-red", tcp_timeout: "b-yellow", tcp_refused: "b-red", tcp_error: "b-red", tls_error: "b-yellow" }[s] || "b-gray"; }
function fmtBytes(n) { n = Number(n || 0); if (n < 1024) return n + " B"; if (n < 1048576) return (n / 1024).toFixed(1) + " KB"; return (n / 1048576).toFixed(1) + " MB"; }

/* ---------- users ---------- */
let usersCache = [];
let _uTimer;
async function loadUsers(instant = false) {
  clearTimeout(_uTimer);
  if (!instant) await new Promise(r => _uTimer = setTimeout(r, 400)); // Debounce
  const tb = $("users-tbody");
  try {
    const j = await api(`/api/users?search=${encodeURIComponent($("u-search").value)}&status=${$("u-status").value}`);
    usersCache = j.data;
    if (!j.data.length) { tb.innerHTML = '<tr><td colspan="9" class="empty">کاربری یافت نشد</td></tr>'; return; }
    tb.innerHTML = j.data.map((u) => {
      const st = u.effective_status;
      const badge = st === "active" ? '<span class="badge b-green">فعال</span>' : st === "pending" ? '<span class="badge b-yellow">⏳ در انتظار IP</span>' : st === "expired" ? '<span class="badge b-red">منقضی</span>' : '<span class="badge b-gray">غیرفعال</span>';
      const left = u.is_expired ? `<span style="color:var(--red)">${u.days_left} روز</span>` : `${u.days_left} روز`;
      return `<tr>
        <td data-label="#">${u.id}</td>
        <td data-label="نام"><b>${esc(u.name)}</b>${u.notes ? `<br><small style="color:var(--txt-muted)">${esc(u.notes)}</small>` : ""}</td>
        <td data-label="IP">${u.ip ? `<code>${u.ip}</code><button class="copy-btn" onclick="copyIp('${u.ip}')">کپی</button>` : '<span style="color:var(--txt-muted)">— ثبت با 🔗</span>'}</td>
        <td data-label="انقضا" class="ltr" style="text-align:end">${u.expiry}</td>
        <td data-label="مانده">${left}</td>
        <td data-label="وضعیت">${badge}</td>
        <td data-label="کوئری">${faNum(u.total_queries)}</td>
        <td data-label="آخرین اتصال"><small>${u.last_seen || "-"}</small></td>
        <td data-label="عملیات" style="white-space:nowrap">
          <button class="btn sm" onclick="editUser(${u.id})">✏️</button>
          <button class="btn sm yellow" onclick="openExtend(${u.id})">⏳</button>
          <button class="btn sm gray" onclick="toggleUser(${u.id})">${u.status === "active" ? "⏸" : "▶"}</button>
          <button class="btn sm gray" title="لینک اختصاصی" onclick="openLinkModal(${u.id})">🔗</button>
          <button class="btn sm red" onclick="delUser(${u.id},'${esc(u.name)}')">🗑</button>
        </td></tr>`;
    }).join("");
  } catch (e) { tb.innerHTML = '<tr><td colspan="9" class="empty">خطا در بارگذاری</td></tr>'; }
}

function esc(s) { return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/'/g, "&#39;"); }
function copyIp(ip) { navigator.clipboard.writeText(ip).then(() => toast("IP کپی شد ✔", "ok")); }

async function saveUser() {
  const id = $("mu-id").value;
  try {
    if (id) {
      await api(`/api/users/${id}`, "PUT", { name: $("mu-name").value, ip: $("mu-ip").value, expiry: $("mu-exp").value || undefined, notes: $("mu-notes").value });
      toast("کاربر بروزرسانی شد ✔", "ok");
    } else {
      const j = await api("/api/users", "POST", { name: $("mu-name").value, ip: $("mu-ip").value, days: $("mu-days").value, notes: $("mu-notes").value });
      toast(`کاربر ساخته شد ✔ (انقضا: ${j.data.expiry})`, "ok");
      closeModal("m-user"); loadUsers(true); loadDashboard();
      showLinkModal(j.data); return;
    }
    closeModal("m-user"); loadUsers(true); loadDashboard();
  } catch (e) { toast(e.message, "err"); }
}
function editUser(id) {
  const u = usersCache.find((x) => x.id === id); if (!u) return;
  $("mu-title").textContent = "✏️ ویرایش کاربر";
  $("mu-id").value = u.id; $("mu-name").value = u.name; $("mu-ip").value = u.ip;
  $("mu-exp").value = u.expiry; $("mu-notes").value = u.notes || "";
  $("mu-days-wrap").style.display = "none"; $("mu-exp-wrap").style.display = "block";
  openModal("m-user");
}
async function delUser(id, name) {
  if (!confirm(`حذف کاربر «${name}»؟`)) return;
  try { await api(`/api/users/${id}`, "DELETE"); toast("حذف شد", "ok"); loadUsers(true); loadDashboard(); } catch (e) { toast(e.message, "err"); }
}
async function toggleUser(id) { try { await api(`/api/users/${id}/toggle`, "POST"); loadUsers(true); } catch (e) { toast(e.message, "err"); } }
function openExtend(id) { $("me-id").value = id; openModal("m-extend"); }
async function doExtend() {
  try {
    const j = await api(`/api/users/${$("me-id").value}/extend`, "POST", { days: $("me-days").value });
    toast(`تمدید شد ✔ (انقضای جدید: ${j.data.expiry})`, "ok"); closeModal("m-extend"); loadUsers(true);
  } catch (e) { toast(e.message, "err"); }
}
function openLinkModal(id) { const u = usersCache.find((x) => x.id === id); if (u) showLinkModal(u); }
function showLinkModal(u) { $("ml-id").value = u.id; $("ml-name").textContent = u.name; $("ml-link").value = u.link || "—"; openModal("m-link"); }
function copyLink() {
  const v = $("ml-link").value;
  if (navigator.clipboard) navigator.clipboard.writeText(v).then(() => toast("لینک کپی شد ✔", "ok"));
  else { $("ml-link").select(); document.execCommand("copy"); toast("لینک کپی شد ✔", "ok"); }
}
async function regenLink() {
  try {
    const j = await api(`/api/users/${$("ml-id").value}/regen-link`, "POST");
    $("ml-link").value = j.data.link;
    const c = usersCache.find((x) => x.id === j.data.id); if (c) { c.token = j.data.token; c.link = j.data.link; }
    toast("لینک جدید ساخته شد ✔", "ok");
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- logs ---------- */
let _lTimer;
async function loadLogs(instant = false) {
  clearTimeout(_lTimer);
  if (!instant) await new Promise(r => _lTimer = setTimeout(r, 400));
  const tb = $("logs-tbody");
  try {
    const j = await api(`/api/logs?domain=${encodeURIComponent($("l-domain").value)}&action=${$("l-action").value}&limit=${LOG_LIMIT}&offset=${logOffset}`);
    $("log-info").textContent = `نمایش ${logOffset + 1} تا ${logOffset + j.logs.length} از ${faNum(j.total)}`;
    tb.innerHTML = j.logs.length ? j.logs.map((l) =>
      `<tr><td data-label="زمان"><small>${l.timestamp}</small></td>
       <td data-label="کاربر">${l.user_name ? esc(l.user_name) : '<span style="color:var(--txt-muted)">ناشناس</span>'}</td>
       <td data-label="IP"><code>${l.client_ip}</code></td>
       <td data-label="دامنه" class="ltr" style="text-align:end">${esc(l.domain)}</td>
       <td data-label="نوع">${l.qtype}</td>
       <td data-label="وضعیت"><span class="badge ${actBadge(l.action)}">${actFa(l.action)}</span>${l.cached ? ' <small title="از کش">⚡</small>' : ""}</td>
       <td data-label="زمان پاسخ">${l.response_ms ? l.response_ms + "ms" : "-"}</td></tr>`).join("")
      : '<tr><td colspan="7" class="empty">لاگی یافت نشد</td></tr>';
  } catch (e) { /* ignore */ }
}
function logPage(d) { logOffset = Math.max(0, logOffset + d * LOG_LIMIT); loadLogs(true); }
async function clearLogs() {
  if (!confirm("همه لاگ‌ها پاک شود؟")) return;
  try { await api("/api/logs", "DELETE"); logOffset = 0; loadLogs(true); toast("لاگ‌ها پاک شد", "ok"); } catch (e) { toast(e.message, "err"); }
}
setInterval(() => { if ($("page-logs").classList.contains("active") && $("l-auto").checked && logOffset === 0) loadLogs(true); }, 5000);

/* ---------- DNS Mode / Settings ---------- */
async function loadMode() {
  try {
    const j = await api("/api/settings"); const m = (j.data && j.data.dns_mode) || "smart";
    document.querySelector(`input[name="dnsmode"][value="${m}"]`).checked = true; modeChanged();
  } catch (e) {}
}
function modeChanged() {
  const m = document.querySelector('input[name="dnsmode"]:checked'); const v = m ? m.value : "smart";
  $("mc-smart").classList.toggle("sel", v === "smart");
  $("mc-full").classList.toggle("sel", v === "full");
  $("full-warn").style.display = v === "full" ? "block" : "none";
}
async function saveMode() {
  const m = document.querySelector('input[name="dnsmode"]:checked');
  try { await api("/api/settings", "POST", { dns_mode: m ? m.value : "smart" }); toast("حالت ذخیره شد ✔", "ok"); loadDashboard(); } catch (e) { toast(e.message, "err"); }
}
async function loadSettings() {
  try {
    const s = (await api("/api/settings")).data;
    $("s-up1").value = s.upstream1 || ""; $("s-up2").value = s.upstream2 || "";
    $("s-timeout").value = s.upstream_timeout || 5; $("s-ttl").value = s.cache_ttl || 300;
    $("s-retention").value = s.log_retention_days || 7; $("s-serverip").value = s.server_ip || "";
    $("s-serveripv6").value = s.server_ipv6 || ""; $("s-cooldown").value = s.link_cooldown_sec || 60;
    $("s-cache").checked = s.cache_enabled === "1"; $("s-log").checked = s.log_enabled === "1";
    $("s-block").checked = s.blocklist_enabled === "1"; $("s-refuse").checked = s.refuse_unlisted === "1";
    $("s-sni").checked = s.sni_enabled !== "0";
  } catch (e) { console.error(e); }
}
async function saveSettings() {
  try {
    await api("/api/settings", "POST", {
      upstream1: $("s-up1").value, upstream2: $("s-up2").value, upstream_timeout: $("s-timeout").value,
      cache_ttl: $("s-ttl").value, log_retention_days: $("s-retention").value, server_ip: $("s-serverip").value,
      server_ipv6: $("s-serveripv6").value, link_cooldown_sec: $("s-cooldown").value,
      cache_enabled: $("s-cache").checked ? "1" : "0", log_enabled: $("s-log").checked ? "1" : "0",
      blocklist_enabled: $("s-block").checked ? "1" : "0", refuse_unlisted: $("s-refuse").checked ? "1" : "0",
      sni_enabled: $("s-sni").checked ? "1" : "0",
    });
    toast("تنظیمات ذخیره شد ✔", "ok");
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- Rules & Blocklist ---------- */
async function loadRules() {
  try {
    const j = await api("/api/rules");
    $("rules-tbody").innerHTML = j.data.length ? j.data.map((r) =>
      `<tr><td data-label="دامنه" class="ltr" style="text-align:end">${esc(r.domain)}</td><td data-label="IP مقصد"><code>${r.target_ip}</code></td>
       <td data-label="وضعیت">${r.enabled ? '<span class="badge b-green">فعال</span>' : '<span class="badge b-gray">غیرفعال</span>'}</td>
       <td data-label="عملیات"><button class="btn sm gray" onclick="toggleRule(${r.id})">${r.enabled ? "⏸" : "▶"}</button>
       <button class="btn sm red" onclick="delRule(${r.id})">🗑</button></td></tr>`).join("") : '<tr><td colspan="4" class="empty">رکوردی ثبت نشده</td></tr>';
  } catch (e) {}
}
async function addRule() { try { await api("/api/rules", "POST", { domain: $("r-domain").value, target_ip: $("r-ip").value }); $("r-domain").value = ""; $("r-ip").value = ""; loadRules(); toast("افزوده شد ✔", "ok"); } catch (e) { toast(e.message, "err"); } }
async function delRule(id) { await api(`/api/rules/${id}`, "DELETE"); loadRules(); }
async function toggleRule(id) { await api(`/api/rules/${id}/toggle`, "POST"); loadRules(); }

async function loadBlock() {
  try {
    const j = await api("/api/blocklist"); $("block-count").textContent = faNum(j.count);
    $("block-tbody").innerHTML = j.data.length ? j.data.map((b, i) =>
      `<tr><td data-label="#">${i + 1}</td><td data-label="دامنه" class="ltr" style="text-align:end">${esc(b.domain)}</td>
       <td data-label="تاریخ"><small>${b.created_at || "-"}</small></td>
       <td data-label="عملیات"><button class="btn sm red" onclick="delBlock(${b.id})">🗑</button></td></tr>`).join("") : '<tr><td colspan="4" class="empty">بلاک‌لیست خالی است</td></tr>';
  } catch (e) {}
}
async function addBlock() { try { await api("/api/blocklist", "POST", { domain: $("b-domain").value }); $("b-domain").value = ""; loadBlock(); toast("افزوده شد ✔", "ok"); } catch (e) { toast(e.message, "err"); } }
async function delBlock(id) { await api(`/api/blocklist/${id}`, "DELETE"); loadBlock(); }
async function clearBlock() { if (!confirm("کل بلاک‌لیست پاک شود؟")) return; await api("/api/blocklist", "DELETE"); loadBlock(); }
async function doBulk() { try { const j = await api("/api/blocklist", "POST", { domains: $("mb-text").value }); toast(`${j.added} دامنه افزوده شد ✔`, "ok"); $("mb-text").value = ""; closeModal("m-bulk"); loadBlock(); } catch (e) { toast(e.message, "err"); } }

/* ---------- Proxy ---------- */
let proxyProfiles = {};
async function ensureProfiles() {
  if (Object.keys(proxyProfiles).length) return;
  try {
    const j = await api("/api/discover"); proxyProfiles = j.profiles || {};
    const opts = Object.entries(proxyProfiles).map(([k, v]) => `<option value="${k}">${v}</option>`).join("");
    $("p-profile").innerHTML = opts; $("p-filter").innerHTML = '<option value="">همه پروفایل‌ها</option>' + opts;
    $("p-seeds").innerHTML = Object.entries(proxyProfiles).filter(([k]) => k !== "general").map(([k, v]) => `<button class="btn gray sm" onclick="seedProfile('${k}')">${v} ➕</button>`).join("");
  } catch (e) {}
}
async function loadProxy() {
  try {
    await ensureProfiles(); const f = $("p-filter").value; const j = await api("/api/proxy");
    const rows = f ? j.data.filter((b) => (b.profile || "general") === f) : j.data;
    $("proxy-count").textContent = faNum(j.count);
    $("proxy-tbody").innerHTML = rows.length ? rows.map((b, i) =>
      `<tr><td data-label="#">${i + 1}</td><td data-label="دامنه" class="ltr" style="text-align:end">${esc(b.domain)}</td>
       <td data-label="پروفایل"><small>${proxyProfiles[b.profile] || esc(b.profile || "general")}</small></td>
       <td data-label="وضعیت">${b.enabled ? '<span class="badge b-green">فعال</span>' : '<span class="badge b-gray">غیرفعال</span>'}</td>
       <td data-label="تاریخ"><small>${b.created_at || "-"}</small></td>
       <td data-label="عملیات" style="white-space:nowrap"><button class="btn sm gray" onclick="toggleProxy(${b.id})">${b.enabled ? "⏸" : "▶"}</button>
       <button class="btn sm red" onclick="delProxy(${b.id})">🗑</button></td></tr>`).join("") : '<tr><td colspan="6" class="empty">لیست خالی است</td></tr>';
  } catch (e) {}
}
async function seedProfile(profile) { try { const j = await api("/api/proxy/seed-profile", "POST", { profile }); loadProxy(); toast(`پروفایل اضافه شد (${j.count}) ✔`, "ok"); } catch (e) { toast(e.message, "err"); } }
async function addProxy() { try { await api("/api/proxy", "POST", { domain: $("p-domain").value, profile: $("p-profile").value }); $("p-domain").value = ""; loadProxy(); toast("افزوده شد ✔", "ok"); } catch (e) { toast(e.message, "err"); } }
async function delProxy(id) { await api(`/api/proxy/${id}`, "DELETE"); loadProxy(); }
async function toggleProxy(id) { await api(`/api/proxy/${id}/toggle`, "POST"); loadProxy(); }
async function clearProxy() { if (!confirm("کل لیست پاک شود؟")) return; await api("/api/proxy", "DELETE"); loadProxy(); }
async function seedProxy() { const j = await api("/api/proxy/seed", "POST"); loadProxy(); toast(`برگردانده شد (${j.count}) ✔`, "ok"); }
async function doProxyBulk() { try { const j = await api("/api/proxy", "POST", { domains: $("mp-text").value }); toast(`${j.added} دامنه افزوده شد ✔`, "ok"); $("mp-text").value = ""; closeModal("m-pbulk"); loadProxy(); } catch (e) { toast(e.message, "err"); } }

let _plTimer;
async function loadProxyLogs(instant = false) {
  clearTimeout(_plTimer);
  if (!instant) await new Promise(r => _plTimer = setTimeout(r, 400));
  try {
    const j = await api(`/api/proxy-logs?sni=${encodeURIComponent($("pl-sni").value)}&limit=50`);
    $("plogs-tbody").innerHTML = j.logs.length ? j.logs.map((l) =>
      `<tr><td data-label="زمان"><small>${l.timestamp}</small></td>
       <td data-label="کاربر">${l.user_name ? esc(l.user_name) : '<span style="color:var(--txt-muted)">ناشناس</span>'}</td>
       <td data-label="IP"><code>${l.client_ip}</code></td><td data-label="SNI" class="ltr" style="text-align:end">${esc(l.sni || "-")}</td>
       <td data-label="مقصد"><code>${l.target_ip || "-"}</code></td>
       <td data-label="تاخیر"><small title="DNS / TCP">🔍${l.dns_ms || 0} 🔌${l.connect_ms || 0}</small></td>
       <td data-label="حجم"><small>⬆${fmtBytes(l.bytes_up)} ⬇${fmtBytes(l.bytes_down)}</small></td>
       <td data-label="وضعیت"><span class="badge ${pxStatusBadge(l.status)}" ${l.err_detail ? `title="${esc(l.err_detail)}"` : ""}>${pxStatusFa(l.status)}</span></td></tr>`).join("") : '<tr><td colspan="8" class="empty">لاگی یافت نشد</td></tr>';
  } catch (e) {}
}
async function clearProxyLogs() { if (!confirm("لاگ پروکسی پاک شود؟")) return; await api("/api/proxy-logs", "DELETE"); loadProxyLogs(true); }

/* ---------- Diagnostics & Other ---------- */
async function loadDiscover() {
  try {
    await ensureProfiles(); const j = await api("/api/discover"); const rows = [];
    (j.refused_sni || []).forEach((r) => rows.push(`<tr><td data-label="دامنه" class="ltr" style="text-align:end"><code>${esc(r.sni)}</code></td><td data-label="منبع"><span class="badge b-red">ردشده 🔥</span></td><td data-label="تعداد">${faNum(r.count)}</td><td data-label="کاربرها">${r.users}</td><td data-label="آخرین"><small>${r.last_seen || "-"}</small></td><td data-label="عملیات"><button class="btn sm green" onclick="discoverAdd('${esc(r.sni)}')">➕</button></td></tr>`));
    (j.top_unlisted || []).forEach((r) => rows.push(`<tr><td data-label="دامنه" class="ltr" style="text-align:end"><code>${esc(r.domain)}</code></td><td data-label="منبع"><span class="badge b-blue">پرتکرار DNS</span></td><td data-label="تعداد">${faNum(r.count)}</td><td data-label="کاربرها">-</td><td data-label="آخرین"><small>${r.last_seen || "-"}</small></td><td data-label="عملیات"><button class="btn sm green" onclick="discoverAdd('${esc(r.domain)}')">➕</button></td></tr>`));
    $("discover-tbody").innerHTML = rows.length ? rows.join("") : '<tr><td colspan="6" class="empty">موردی برای پیشنهاد نیست 🎉</td></tr>';
  } catch (e) {}
}
async function discoverAdd(domain) { try { await api("/api/discover/add", "POST", { domain, profile: $("p-profile") ? $("p-profile").value : "general" }); toast(`${domain} اضافه شد ✔`, "ok"); loadDiscover(); loadProxy(); } catch (e) { toast(e.message, "err"); } }

async function runDiag(fresh) {
  $("diag-tbody").innerHTML = '<tr><td colspan="3" class="empty"><span class="skeleton" style="display:inline-block;width:200px;height:16px;"></span></td></tr>';
  try {
    const j = await api(`/api/diag?fresh=${fresh ? 1 : 0}`);
    $("diag-ts").textContent = (j.cached ? "📦 از کش" : "🆕 تازه") + " — " + new Date(j.ts * 1000).toLocaleTimeString("fa-IR");
    const badge = (s) => s === "up" ? '<span class="badge b-green">🟢 سالم</span>' : s === "degraded" ? '<span class="badge b-yellow">🟡 اختلال</span>' : '<span class="badge b-red">🔴 قطع</span>';
    let html = j.services.map((s) => `<tr><td data-label="سرویس"><b>${s.name}</b></td><td data-label="وضعیت">${badge(s.state)}</td><td data-label="جزئیات"><small>${s.hosts.map((h) => `${h.ok ? "✅" : "❌"} ${h.host} (🔍${h.resolve_ms ?? "-"}ms 🔌${h.connect_ms ?? "-"}ms ${h.http_code ? "HTTP " + h.http_code : esc(h.error || "")})`).join("<br>")}</small></td></tr>`).join("");
    html += `<tr><td data-label="سرویس"><b>آپ‌استریم DNS</b></td><td data-label="وضعیت">${Object.values(j.upstreams).every((u) => u.ok) ? '<span class="badge b-green">🟢 سالم</span>' : '<span class="badge b-yellow">🟡 اختلال</span>'}</td><td data-label="جزئیات"><small>${Object.entries(j.upstreams).map(([k, u]) => `${u.ok ? "✅" : "❌"} ${k} ${u.ok ? u.ms + "ms" : esc(u.error || "")}`).join("<br>")}</small></td></tr>`;
    $("diag-tbody").innerHTML = html;
  } catch (e) { $("diag-tbody").innerHTML = '<tr><td colspan="3" class="empty">خطا در تست</td></tr>'; }
}

async function runFullDiag(fresh) {
  $("fdiag-tbody").innerHTML = '<tr><td colspan="3" class="empty"><span class="skeleton" style="display:inline-block;width:200px;height:16px;"></span></td></tr>';
  try {
    const j = await api(`/api/diag/full?fresh=${fresh ? 1 : 0}`);
    $("fdiag-ts").textContent = (j.cached ? "📦 از کش" : "🆕 تازه") + ` — ${j.up}/${j.total} سالم — ` + new Date(j.ts * 1000).toLocaleTimeString("fa-IR");
    if (!j.total) { $("fdiag-tbody").innerHTML = '<tr><td colspan="3" class="empty">لیست پروکسی خالی است</td></tr>'; return; }
    const sorted = [...j.results].sort((a, b) => (a.ok === b.ok) ? 0 : a.ok ? 1 : -1);
    $("fdiag-tbody").innerHTML = sorted.map((h) => `<tr><td data-label="دامنه" class="ltr" style="text-align:start"><code>${esc(h.host)}</code></td><td data-label="وضعیت">${h.ok ? '<span class="badge b-green">🟢 سالم</span>' : '<span class="badge b-red">🔴 قطع</span>'}</td><td data-label="جزئیات"><small>🔍${h.resolve_ms ?? "-"}ms 🔌${h.connect_ms ?? "-"}ms ${h.http_code ? "HTTP " + h.http_code : esc(h.error || "")}</small></td></tr>`).join("");
  } catch (e) { $("fdiag-tbody").innerHTML = '<tr><td colspan="3" class="empty">خطا در اسکن</td></tr>'; }
}

/* ---------- Firewall & Setup ---------- */
async function loadFirewall() {
  try {
    const j = await api("/api/firewall");
    if (!j.installed) { $("fw-status").textContent = "❌ نصب نیست"; $("fw-tbody").innerHTML = '<tr><td colspan="4" class="empty">فایروال روی سرور نصب نیست</td></tr>'; return; }
    $("fw-status").innerHTML = j.active ? '<span class="badge b-green">🟢 روشن</span>' : '<span class="badge b-red">🔴 خاموش</span>';
    $("fw-note").textContent = ` (SSH: ${j.ssh_port} | پنل: ${j.panel_port}${j.extras ? ` | اضافی: ${j.extras}` : ""})`;
    const allow = (j.rules || []).filter((r) => r.action === "ALLOW" && !r.v6);
    $("fw-tbody").innerHTML = allow.length ? allow.map((r, i) => `<tr><td data-label="#">${i + 1}</td><td data-label="قانون"><code>${r.target}</code></td><td data-label="وضعیت"><span class="badge b-green">ALLOW</span></td><td data-label="عملیات"><button class="btn sm red" onclick="fwDelete('${r.target}')">🗑</button></td></tr>`).join("") : '<tr><td colspan="4" class="empty">قانونی نیست</td></tr>';
  } catch (e) { $("fw-status").textContent = "❌ خطا"; }
}
async function fwSet(action) { if (!confirm("مطمئنی؟")) return; try { await api("/api/firewall", "POST", { action }); toast("انجام شد ✔", "ok"); loadFirewall(); } catch (e) { toast(e.message, "err"); } }
async function fwAllow() { const p = $("fw-port").value.trim(), pr = $("fw-proto").value; if (!p) return toast("پورت؟", "err"); try { await api("/api/firewall/allow", "POST", { port:p, proto:pr }); toast("ثبت شد ✔", "ok"); $("fw-port").value = ""; loadFirewall(); } catch (e) { toast(e.message, "err"); } }
async function fwDelete(t) { const m = String(t).match(/^(\d+)\/(tcp|udp)$/); if (!m) return toast("از SSH مدیریت کن", "err"); if (!confirm(`حذف ${t}؟`)) return; try { await api("/api/firewall/delete", "POST", { port: m[1], proto: m[2] }); toast("حذف شد", "ok"); loadFirewall(); } catch (e) { toast(e.message, "err"); } }
async function detectIPv6() { try { $("s-serveripv6").value = (await api("/api/detect-ipv6")).ipv6; toast("IPv6 پیدا شد ✔", "ok"); } catch (e) { toast(e.message, "err"); } }
async function uploadRestore() { const fi = $("restore-file"); if (!fi.files.length) return toast("فایل انتخاب کن", "err"); if (!confirm("جایگزین شود؟")) return; const fd = new FormData(); fd.append("file", fi.files[0]); try { const r = await fetch("/api/restore", { method: "POST", body: fd }); const j = await r.json(); if (!j.ok) throw new Error(j.error); alert("ریستور شد. با یوزر/پسورد بکاپ وارد شو."); location.href = "/login"; } catch (e) { toast(e.message, "err"); } }
async function applyGaming() { if (!confirm("پیش‌ست گیمینگ؟")) return; try { await api("/api/preset/gaming", "POST"); await loadMode(); loadDashboard(); loadProxy(); toast("اعمال شد ✔", "ok"); } catch (e) { toast(e.message, "err"); } }
async function loadWarp(s) { try { const j = await api("/api/warp/status"); const el = $("warp-status"); if (el) el.textContent = !j.installed ? "❌ نصب نشده" : !j.up ? "⚠️ خاموش" : `✅ فعال (${j.exit_ip})`; if ($("s-warp")) $("s-warp").checked = !!j.enabled; if (s) toast(el?.textContent, j.up ? "ok" : "err"); } catch (e) {} }
async function saveWarp() { try { await api("/api/warp", "POST", { enabled: $("s-warp").checked ? "1" : "0" }); toast("وارپ ذخیره شد ✔", "ok"); loadWarp(); } catch (e) { toast(e.message, "err"); } }
async function changePass() { try { await api("/api/admin/password", "POST", { current: $("p-cur").value, new: $("p-new").value }); $("p-cur").value = $("p-new").value = ""; toast("رمز تغییر کرد ✔", "ok"); } catch (e) { toast(e.message, "err"); } }

/* ---------- init ---------- */
function refreshAll() {
  loadDashboard();
  if ($("page-users").classList.contains("active")) loadUsers(true);
  if ($("page-logs").classList.contains("active")) loadLogs(true);
}
fetch("https://api.ipify.org?format=json").then((r) => r.json()).then((j) => {
  const srv = $("srv-ip"); if(srv) srv.textContent = j.ip;
  document.querySelectorAll(".srv-ip-2").forEach((el) => (el.textContent = j.ip));
}).catch(() => { const srv = $("srv-ip"); if(srv) srv.textContent = "SERVER_IP"; });
loadDashboard();
setInterval(() => { if ($("page-dash").classList.contains("active")) loadDashboard(); }, 15000);
