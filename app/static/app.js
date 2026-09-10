/* DNS Shop Panel - frontend */
const $ = (id) => document.getElementById(id);
const faNum = (n) => Number(n || 0).toLocaleString("en-US");
let logOffset = 0;
const LOG_LIMIT = 50;

/* ---------- navigation ---------- */
document.querySelectorAll(".nav button").forEach((b) => {
  b.addEventListener("click", () => {
    document.querySelectorAll(".nav button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    document.querySelectorAll(".page").forEach((p) => p.classList.remove("active"));
    const pg = b.dataset.page;
    $("page-" + pg).classList.add("active");
    $("page-title").textContent = b.textContent.trim();
    document.getElementById("sidebar").classList.remove("open");
    if (pg === "users") loadUsers();
    if (pg === "logs") loadLogs();
    if (pg === "dns") { loadSettings(); loadRules(); loadMode(); }
    if (pg === "proxy") { loadProxy(); loadProxyLogs(); }
    if (pg === "block") loadBlock();
  });
});

/* ---------- toast ---------- */
function toast(msg, type = "") {
  const t = document.createElement("div");
  t.className = "toast " + type;
  t.textContent = msg;
  $("toasts").appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

async function api(url, method = "GET", body = null) {
  const opt = { method, headers: { "Content-Type": "application/json" } };
  if (body) opt.body = JSON.stringify(body);
  const r = await fetch(url, opt);
  if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
  const j = await r.json();
  if (!j.ok) throw new Error(j.error || "خطا");
  return j;
}

/* ---------- clock ---------- */
setInterval(() => {
  $("clock").textContent = new Date().toLocaleTimeString("fa-IR", { hour: "2-digit", minute: "2-digit" });
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
  const c = $(canvasId), ctx = c.getContext("2d");
  const W = c.width, H = c.height;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(...values, 1), pad = 30;
  const bw = (W - pad * 2) / Math.max(labels.length, 1);
  ctx.strokeStyle = "rgba(255,255,255,.12)"; ctx.fillStyle = "#8b949e"; ctx.font = "10px Tahoma";
  for (let i = 0; i <= 4; i++) {
    const y = 10 + ((H - 40) / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(W - 10, y); ctx.stroke();
    ctx.fillText(faNum(Math.round(max - (max / 4) * i)), 2, y + 3);
  }
  values.forEach((v, i) => {
    const h = ((H - 45) / max) * v;
    const x = pad + bw * i + bw * 0.2, y = H - 25 - h;
    const g = ctx.createLinearGradient(0, y, 0, H - 25);
    g.addColorStop(0, color); g.addColorStop(1, color + "44");
    ctx.fillStyle = g;
    ctx.fillRect(x, y, bw * 0.6, Math.max(h, 2));
    if (labels.length <= 24) { ctx.fillStyle = "#8b949e"; ctx.fillText(labels[i], x, H - 10); }
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
    $("c-expiring").textContent = faNum(d.users.expiring);
    $("c-expired").textContent = faNum(d.users.expired + d.users.disabled);
    $("c-qday").textContent = faNum(d.queries.today);
    $("c-qblock").textContent = faNum(d.queries.blocked_today);
    $("c-pxday").textContent = faNum(d.proxy ? d.proxy.today : 0);
    const modeFa = d.dns.mode === "full" ? "🌐 حالت کامل" : "🧠 حالت هوشمند";
    const modeCls = d.dns.mode === "full" ? "b-purple" : "b-blue";
    $("dns-badge").innerHTML = (d.dns.running
      ? `<span class="badge b-green">● سرویس DNS فعال (پورت ${d.dns.port})</span>`
      : `<span class="badge b-red">● سرویس DNS غیرفعال</span>`)
      + ` <span class="badge ${modeCls}">${modeFa}</span>`;
    $("srv-time").textContent = "🕒 " + d.server_time;
    drawBarChart("ch-hour", d.hourly.map((x) => x.hour), d.hourly.map((x) => x.count), "#2f81f7");
    drawBarChart("ch-day", d.daily.map((x) => x.date.slice(5)), d.daily.map((x) => x.count), "#3fb950");
    barRows($("top-domains"), d.top_domains, "domain");
    barRows($("top-users"), d.top_users, "name");
    const s = d.system;
    $("sysbox").innerHTML = `
      <div class="s"><div class="n">${s.cpu}%</div><div class="l">CPU</div></div>
      <div class="s"><div class="n">${s.ram_pct}%</div><div class="l">RAM (${faNum(s.ram_used)}/${faNum(s.ram_total)} مگ)</div></div>
      <div class="s"><div class="n">${s.disk_pct}%</div><div class="l">Disk (${s.disk_used_gb}/${s.disk_total_gb} گیگ)</div></div>
      <div class="s"><div class="n" style="font-size:15px">${fmtUptime(s.uptime_sec)}</div><div class="l">آپتایم پنل</div></div>`;
    $("recent-blocked").innerHTML = d.recent_blocked.length ? d.recent_blocked.map((l) =>
      `<div class="bar-row"><span class="lbl">${l.domain}</span>
       <span class="badge ${l.action === "blocked" ? "b-yellow" : "b-red"}" style="font-size:11px">${actFa(l.action)}</span>
       <code>${l.client_ip}</code></div>`).join("")
      : '<div class="empty">موردی نیست 🎉</div>';
    $("recent-proxy").innerHTML = d.recent_proxy && d.recent_proxy.length ? d.recent_proxy.map((p) =>
      `<div class="bar-row"><span class="lbl">${p.sni || "-"}</span>
       <span class="badge ${pxStatusBadge(p.status)}" style="font-size:11px">${pxStatusFa(p.status)}</span>
       <code>${p.client_ip}</code>
       <small style="color:var(--muted)">${p.user_name ? esc(p.user_name) : "ناشناس"} · ⬆${fmtBytes(p.bytes_up)} ⬇${fmtBytes(p.bytes_down)}</small></div>`).join("")
      : '<div class="empty">هنوز اتصالی ثبت نشده</div>';
  } catch (e) { if (e.message !== "auth") console.error(e); }
}

function actFa(a) {
  return { allowed: "✅ مجاز", proxied: "🔀 پروکسی", custom: "⭐ کاستوم", blocked: "🚫 بلاک", refused: "⛔ رد", expired: "⌛ منقضی" }[a] || a;
}
function actBadge(a) {
  return { allowed: "b-green", proxied: "b-purple", custom: "b-blue", blocked: "b-yellow", refused: "b-red", expired: "b-red" }[a] || "b-gray";
}
function pxStatusFa(s) {
  return { ok: "✅ موفق", refused_ip: "⛔ IP ناشناس", refused_sni: "🚫 خارج از لیست", error: "❌ خطا" }[s] || s;
}
function pxStatusBadge(s) {
  return { ok: "b-green", refused_ip: "b-red", refused_sni: "b-yellow", error: "b-red" }[s] || "b-gray";
}
function fmtBytes(n) {
  n = Number(n || 0);
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

/* ---------- users ---------- */
let usersCache = [];
async function loadUsers() {
  const tb = $("users-tbody");
  try {
    const j = await api(`/api/users?search=${encodeURIComponent($("u-search").value)}&status=${$("u-status").value}`);
    usersCache = j.data;
    if (!j.data.length) { tb.innerHTML = '<tr><td colspan="9" class="empty">کاربری یافت نشد</td></tr>'; return; }
    tb.innerHTML = j.data.map((u) => {
      const st = u.effective_status;
      const badge = st === "active" ? '<span class="badge b-green">فعال</span>'
        : st === "expired" ? '<span class="badge b-red">منقضی</span>' : '<span class="badge b-gray">غیرفعال</span>';
      const left = u.is_expired ? `<span style="color:#ffa198">${u.days_left} روز</span>` : `${u.days_left} روز`;
      return `<tr><td>${u.id}</td><td><b>${esc(u.name)}</b>${u.notes ? `<br><small style="color:var(--muted)">${esc(u.notes)}</small>` : ""}</td>
        <td><code>${u.ip}</code><button class="copy-btn" onclick="copyIp('${u.ip}')">کپی</button></td>
        <td class="ltr">${u.expiry}</td><td>${left}</td><td>${badge}</td>
        <td>${faNum(u.total_queries)}</td><td><small>${u.last_seen || "-"}</small></td>
        <td style="white-space:nowrap">
          <button class="btn sm" onclick="editUser(${u.id})">✏️</button>
          <button class="btn sm yellow" onclick="openExtend(${u.id})">⏳</button>
          <button class="btn sm gray" onclick="toggleUser(${u.id})">${u.status === "active" ? "⏸" : "▶"}</button>
          <button class="btn sm gray" title="لینک ثبت خودکار IP" onclick="openLinkModal(${u.id})">🔗</button>
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
      await api(`/api/users/${id}`, "PUT", {
        name: $("mu-name").value, ip: $("mu-ip").value,
        expiry: $("mu-exp").value || undefined, notes: $("mu-notes").value,
      });
      toast("کاربر بروزرسانی شد ✔", "ok");
    } else {
      const j = await api("/api/users", "POST", {
        name: $("mu-name").value, ip: $("mu-ip").value,
        days: $("mu-days").value, notes: $("mu-notes").value,
      });
      toast(`کاربر ساخته شد ✔ (انقضا: ${j.data.expiry})`, "ok");
      closeModal("m-user"); loadUsers(); loadDashboard();
      showLinkModal(j.data);
      return;
    }
    closeModal("m-user"); loadUsers(); loadDashboard();
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
  try { await api(`/api/users/${id}`, "DELETE"); toast("حذف شد", "ok"); loadUsers(); loadDashboard(); }
  catch (e) { toast(e.message, "err"); }
}
async function toggleUser(id) {
  try { await api(`/api/users/${id}/toggle`, "POST"); loadUsers(); loadDashboard(); }
  catch (e) { toast(e.message, "err"); }
}
function openExtend(id) { $("me-id").value = id; openModal("m-extend"); }
async function doExtend() {
  try {
    const j = await api(`/api/users/${$("me-id").value}/extend`, "POST", { days: $("me-days").value });
    toast(`تمدید شد ✔ (انقضای جدید: ${j.data.expiry})`, "ok");
    closeModal("m-extend"); loadUsers(); loadDashboard();
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- self-service IP link ---------- */
function openLinkModal(id) {
  const u = usersCache.find((x) => x.id === id);
  if (u) showLinkModal(u);
}
function showLinkModal(u) {
  $("ml-id").value = u.id;
  $("ml-name").textContent = u.name;
  $("ml-link").value = u.link || "—";
  openModal("m-link");
}
function copyLink() {
  const v = $("ml-link").value;
  if (navigator.clipboard) navigator.clipboard.writeText(v).then(() => toast("لینک کپی شد ✔", "ok"));
  else { $("ml-link").select(); document.execCommand("copy"); toast("لینک کپی شد ✔", "ok"); }
}
async function regenLink() {
  try {
    const j = await api(`/api/users/${$("ml-id").value}/regen-link`, "POST");
    $("ml-link").value = j.data.link;
    const c = usersCache.find((x) => x.id === j.data.id);
    if (c) { c.token = j.data.token; c.link = j.data.link; }
    toast("لینک جدید ساخته شد ✔ (قبلی باطل شد)", "ok");
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- logs ---------- */
async function loadLogs() {
  const tb = $("logs-tbody");
  try {
    const j = await api(`/api/logs?domain=${encodeURIComponent($("l-domain").value)}&action=${$("l-action").value}&limit=${LOG_LIMIT}&offset=${logOffset}`);
    $("log-info").textContent = `نمایش ${logOffset + 1} تا ${logOffset + j.logs.length} از ${faNum(j.total)}`;
    tb.innerHTML = j.logs.length ? j.logs.map((l) =>
      `<tr><td><small>${l.timestamp}</small></td><td>${l.user_name ? esc(l.user_name) : '<span style="color:var(--muted)">ناشناس</span>'}</td>
       <td><code>${l.client_ip}</code></td><td class="ltr" style="text-align:right">${esc(l.domain)}</td><td>${l.qtype}</td>
       <td><span class="badge ${actBadge(l.action)}">${actFa(l.action)}</span>${l.cached ? ' <small title="از کش">⚡</small>' : ""}</td>
       <td>${l.response_ms ? l.response_ms + "ms" : "-"}</td></tr>`).join("")
      : '<tr><td colspan="7" class="empty">لاگی یافت نشد</td></tr>';
  } catch (e) { /* ignore */ }
}
function logPage(d) { logOffset = Math.max(0, logOffset + d * LOG_LIMIT); loadLogs(); }
async function clearLogs() {
  if (!confirm("همه لاگ‌ها پاک شود؟")) return;
  try { await api("/api/logs", "DELETE"); logOffset = 0; loadLogs(); toast("لاگ‌ها پاک شد", "ok"); }
  catch (e) { toast(e.message, "err"); }
}
setInterval(() => {
  if ($("page-logs").classList.contains("active") && $("l-auto").checked && logOffset === 0) loadLogs();
}, 5000);

/* ---------- DNS mode ---------- */
async function loadMode() {
  try {
    const j = await api("/api/settings");
    const m = (j.data && j.data.dns_mode) || "smart";
    document.querySelector(`input[name="dnsmode"][value="${m}"]`).checked = true;
    modeChanged();
  } catch (e) { /* */ }
}
function modeChanged() {
  const m = document.querySelector('input[name="dnsmode"]:checked');
  const v = m ? m.value : "smart";
  $("mc-smart").classList.toggle("sel", v === "smart");
  $("mc-full").classList.toggle("sel", v === "full");
  $("full-warn").style.display = v === "full" ? "block" : "none";
}
async function saveMode() {
  const m = document.querySelector('input[name="dnsmode"]:checked');
  try {
    await api("/api/settings", "POST", { dns_mode: m ? m.value : "smart" });
    toast("حالت DNS ذخیره شد ✔ (تا ۳۰ ثانیه اعمال می‌شود)", "ok");
    loadDashboard();
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- DNS settings ---------- */
async function loadSettings() {
  try {
    const j = await api("/api/settings");
    const s = j.data;
    $("s-up1").value = s.upstream1 || ""; $("s-up2").value = s.upstream2 || "";
    $("s-timeout").value = s.upstream_timeout || 5; $("s-ttl").value = s.cache_ttl || 300;
    $("s-retention").value = s.log_retention_days || 7;
    $("s-serverip").value = s.server_ip || "";
    $("s-cooldown").value = s.link_cooldown_sec || 60;
    $("s-cache").checked = s.cache_enabled === "1"; $("s-log").checked = s.log_enabled === "1";
    $("s-block").checked = s.blocklist_enabled === "1"; $("s-refuse").checked = s.refuse_unlisted === "1";
    $("s-sni").checked = s.sni_enabled !== "0";
  } catch (e) { console.error(e); }
}
async function saveSettings() {
  try {
    await api("/api/settings", "POST", {
      upstream1: $("s-up1").value, upstream2: $("s-up2").value,
      upstream_timeout: $("s-timeout").value, cache_ttl: $("s-ttl").value,
      log_retention_days: $("s-retention").value,
      server_ip: $("s-serverip").value,
      link_cooldown_sec: $("s-cooldown").value,
      cache_enabled: $("s-cache").checked ? "1" : "0",
      log_enabled: $("s-log").checked ? "1" : "0",
      blocklist_enabled: $("s-block").checked ? "1" : "0",
      refuse_unlisted: $("s-refuse").checked ? "1" : "0",
      sni_enabled: $("s-sni").checked ? "1" : "0",
    });
    toast("تنظیمات ذخیره شد ✔ (تا ۳۰ ثانیه اعمال می‌شود)", "ok");
  } catch (e) { toast(e.message, "err"); }
}
async function loadRules() {
  try {
    const j = await api("/api/rules");
    $("rules-tbody").innerHTML = j.data.length ? j.data.map((r) =>
      `<tr><td class="ltr" style="text-align:right">${esc(r.domain)}</td><td><code>${r.target_ip}</code></td>
       <td>${r.enabled ? '<span class="badge b-green">فعال</span>' : '<span class="badge b-gray">غیرفعال</span>'}</td>
       <td><button class="btn sm gray" onclick="toggleRule(${r.id})">${r.enabled ? "⏸" : "▶"}</button>
       <button class="btn sm red" onclick="delRule(${r.id})">🗑</button></td></tr>`).join("")
      : '<tr><td colspan="4" class="empty">رکوردی ثبت نشده</td></tr>';
  } catch (e) { /* */ }
}
async function addRule() {
  try {
    await api("/api/rules", "POST", { domain: $("r-domain").value, target_ip: $("r-ip").value });
    $("r-domain").value = ""; $("r-ip").value = ""; loadRules(); toast("افزوده شد ✔", "ok");
  } catch (e) { toast(e.message, "err"); }
}
async function delRule(id) { await api(`/api/rules/${id}`, "DELETE"); loadRules(); }
async function toggleRule(id) { await api(`/api/rules/${id}/toggle`, "POST"); loadRules(); }

/* ---------- blocklist ---------- */
async function loadBlock() {
  try {
    const j = await api("/api/blocklist");
    $("block-count").textContent = faNum(j.count);
    $("block-tbody").innerHTML = j.data.length ? j.data.map((b, i) =>
      `<tr><td>${i + 1}</td><td class="ltr" style="text-align:right">${esc(b.domain)}</td>
       <td><small>${b.created_at || "-"}</small></td>
       <td><button class="btn sm red" onclick="delBlock(${b.id})">🗑</button></td></tr>`).join("")
      : '<tr><td colspan="4" class="empty">بلاک‌لیست خالی است</td></tr>';
  } catch (e) { /* */ }
}
async function addBlock() {
  try {
    await api("/api/blocklist", "POST", { domain: $("b-domain").value });
    $("b-domain").value = ""; loadBlock(); toast("افزوده شد ✔", "ok");
  } catch (e) { toast(e.message, "err"); }
}
async function delBlock(id) { await api(`/api/blocklist/${id}`, "DELETE"); loadBlock(); }
async function clearBlock() {
  if (!confirm("کل بلاک‌لیست پاک شود؟")) return;
  await api("/api/blocklist", "DELETE"); loadBlock();
}
async function doBulk() {
  try {
    const j = await api("/api/blocklist", "POST", { domains: $("mb-text").value });
    toast(`${j.added} دامنه افزوده شد ✔${j.invalid ? ` (${j.invalid} نامعتبر)` : ""}`, "ok");
    $("mb-text").value = ""; closeModal("m-bulk"); loadBlock();
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- proxy domains ---------- */
async function loadProxy() {
  try {
    const j = await api("/api/proxy");
    $("proxy-count").textContent = faNum(j.count);
    $("proxy-tbody").innerHTML = j.data.length ? j.data.map((b, i) =>
      `<tr><td>${i + 1}</td><td class="ltr" style="text-align:right">${esc(b.domain)}</td>
       <td>${b.enabled ? '<span class="badge b-green">فعال</span>' : '<span class="badge b-gray">غیرفعال</span>'}</td>
       <td><small>${b.created_at || "-"}</small></td>
       <td style="white-space:nowrap"><button class="btn sm gray" onclick="toggleProxy(${b.id})">${b.enabled ? "⏸" : "▶"}</button>
       <button class="btn sm red" onclick="delProxy(${b.id})">🗑</button></td></tr>`).join("")
      : '<tr><td colspan="5" class="empty">لیست خالی است — رفع تحریم غیرفعال می‌شود</td></tr>';
  } catch (e) { /* */ }
}
async function addProxy() {
  try {
    await api("/api/proxy", "POST", { domain: $("p-domain").value });
    $("p-domain").value = ""; loadProxy(); toast("افزوده شد ✔", "ok");
  } catch (e) { toast(e.message, "err"); }
}
async function delProxy(id) { await api(`/api/proxy/${id}`, "DELETE"); loadProxy(); }
async function toggleProxy(id) { await api(`/api/proxy/${id}/toggle`, "POST"); loadProxy(); }
async function clearProxy() {
  if (!confirm("کل لیست پروکسی پاک شود؟ (رفع تحریم متوقف می‌شود)")) return;
  await api("/api/proxy", "DELETE"); loadProxy();
}
async function seedProxy() {
  const j = await api("/api/proxy/seed", "POST");
  loadProxy(); toast(`لیست پیش‌فرض برگردانده شد (${j.count} دامنه) ✔`, "ok");
}
async function doProxyBulk() {
  try {
    const j = await api("/api/proxy", "POST", { domains: $("mp-text").value });
    toast(`${j.added} دامنه افزوده شد ✔${j.invalid ? ` (${j.invalid} نامعتبر)` : ""}`, "ok");
    $("mp-text").value = ""; closeModal("m-pbulk"); loadProxy();
  } catch (e) { toast(e.message, "err"); }
}
async function loadProxyLogs() {
  const tb = $("plogs-tbody");
  try {
    const j = await api(`/api/proxy-logs?sni=${encodeURIComponent($("pl-sni").value)}&limit=50`);
    tb.innerHTML = j.logs.length ? j.logs.map((l) =>
      `<tr><td><small>${l.timestamp}</small></td><td>${l.user_name ? esc(l.user_name) : '<span style="color:var(--muted)">ناشناس</span>'}</td>
       <td><code>${l.client_ip}</code></td><td class="ltr" style="text-align:right">${esc(l.sni || "-")}</td>
       <td><code>${l.target_ip || "-"}</code></td>
       <td><small>⬆${fmtBytes(l.bytes_up)} ⬇${fmtBytes(l.bytes_down)}</small></td>
       <td><span class="badge ${pxStatusBadge(l.status)}">${pxStatusFa(l.status)}</span></td></tr>`).join("")
      : '<tr><td colspan="7" class="empty">لاگی یافت نشد</td></tr>';
  } catch (e) { /* */ }
}
async function clearProxyLogs() {
  if (!confirm("لاگ اتصالات پروکسی پاک شود؟")) return;
  await api("/api/proxy-logs", "DELETE"); loadProxyLogs();
}

/* ---------- admin ---------- */
async function changePass() {
  try {
    await api("/api/admin/password", "POST", { current: $("p-cur").value, new: $("p-new").value });
    $("p-cur").value = ""; $("p-new").value = ""; toast("رمز تغییر کرد ✔", "ok");
  } catch (e) { toast(e.message, "err"); }
}

/* ---------- init ---------- */
function refreshAll() {
  loadDashboard();
  if ($("page-users").classList.contains("active")) loadUsers();
  if ($("page-logs").classList.contains("active")) loadLogs();
}
fetch("https://api.ipify.org?format=json").then((r) => r.json()).then((j) => {
  $("srv-ip").textContent = j.ip;
  document.querySelectorAll(".srv-ip-2").forEach((el) => (el.textContent = j.ip));
}).catch(() => { $("srv-ip").textContent = "SERVER_IP"; });
loadDashboard();
setInterval(() => { if ($("page-dash").classList.contains("active")) loadDashboard(); }, 15000);
