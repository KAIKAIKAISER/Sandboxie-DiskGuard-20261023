// DiskGuard UI 逻辑（无框架，原生 JS + Tauri IPC）
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));

const state = {
  apps: [],
  status: null,
  prefs: { theme: "auto", autostart: false, close_to_tray: true },
  editingId: null,
  editRules: [],
  editRoots: [],
  events: [],       // 增量缓存（截断保留）
  eventsSince: 0,
  logSearch: "",
  filterResult: "",
  filterKind: "",
};

function toast(msg, isErr = false) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.toggle("err", isErr);
  t.classList.remove("hidden");
  clearTimeout(toast._h);
  toast._h = setTimeout(() => t.classList.add("hidden"), 3200);
}

function fmtTime(ms) {
  const d = new Date(ms);
  const p = (n, l = 2) => String(n).padStart(l, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

/* ============ 主题 ============ */
const mq = window.matchMedia("(prefers-color-scheme: dark)");
function applyTheme() {
  const t = state.prefs.theme;
  const dark = t === "dark" || (t === "auto" && mq.matches);
  document.body.dataset.theme = dark ? "dark" : "light";
}
mq.addEventListener("change", applyTheme);

/* ============ 状态 ============ */
async function refreshStatus() {
  try {
    state.status = await invoke("get_status");
  } catch (e) {
    state.status = null;
  }
  renderStatus();
}

function renderStatus() {
  const s = state.status;
  const chip = $("status-chip");
  const text = $("status-text");
  const missing = $("sbie-missing");
  if (!s) {
    chip.className = "chip warn";
    text.textContent = "状态未知";
    missing.classList.remove("hidden");
    return;
  }
  if (s.api_ok && s.monitor_active) {
    chip.className = "chip ok";
    text.textContent = "核心运行中 · 监控已启用";
  } else if (s.api_ok) {
    chip.className = "chip ok";
    text.textContent = "核心运行中";
  } else if (s.sbie_found) {
    chip.className = "chip warn";
    text.textContent = s.message || "Sandboxie 异常";
  } else {
    chip.className = "chip bad";
    text.textContent = "未检测到 Sandboxie";
  }
  missing.classList.toggle("hidden", s.sbie_found && s.api_ok);
  $("sbie-missing-msg").textContent = s.message ? `（${s.message}）` : "";
  renderSettingsStatus();
}

function renderSettingsStatus() {
  const s = state.status;
  const el = $("settings-status");
  if (!s) { el.innerHTML = ""; return; }
  const row = (k, v, cls = "") =>
    `<div class="kv-row ${cls}"><span>${esc(k)}</span><span class="val">${esc(v)}</span></div>`;
  const yn = (b, yes = "是", no = "否") => (b ? yes : no);
  el.innerHTML = [
    row("SbieDll", s.sbie_found ? s.home : "未找到", s.sbie_found ? "ok" : "bad"),
    row("SbieSvc 服务", `${yn(s.service_installed, "已安装", "未安装")} · ${yn(s.service_running, "运行中", "未运行")}`, s.service_running ? "ok" : "bad"),
    row("SbieDrv 驱动", `${yn(s.driver_installed, "已安装", "未安装")} · ${yn(s.driver_running, "运行中", "未运行")}`, s.driver_running ? "ok" : "bad"),
    row("驱动 API", yn(s.api_ok, "可用", "不可用"), s.api_ok ? "ok" : "bad"),
    row("资源监视线程", yn(s.monitor_active, "已启用", "未启用"), s.monitor_active ? "ok" : ""),
    row("Sandboxie.ini", s.ini_path || "—"),
  ].join("");
}

/* ============ 软件管理 ============ */
async function refreshApps() {
  try {
    state.apps = await invoke("list_apps");
  } catch (e) {
    return;
  }
  renderApps();
}

function modeLabel(m) {
  return { monitor: "只监控", blacklist: "黑名单", whitelist: "白名单" }[m] || m;
}

function renderApps() {
  const grid = $("apps-grid");
  grid.innerHTML = state.apps.map((a) => {
    const badges = [
      `<span class="badge mode">${modeLabel(a.mode)}</span>`,
      a.enabled
        ? `<span class="badge ${a.applied ? "on" : "warn"}">${a.applied ? "已应用" : "待应用"}</span>`
        : `<span class="badge off">已停用</span>`,
      a.running_pids.length
        ? `<span class="badge on">沙箱内 ${a.running_pids.length} 进程</span>`
        : `<span class="badge">未运行</span>`,
      !a.exe_exists ? `<span class="badge off">程序路径缺失</span>` : "",
    ].join("");
    return `
      <div class="card app-card" data-id="${esc(a.id)}">
        <div class="top">
          <div class="app-icon">${esc((a.name || "?").slice(0, 1).toUpperCase())}</div>
          <div style="min-width:0">
            <div class="name">${esc(a.name)}</div>
            <div class="path">${esc(a.exe || "未设置路径")}</div>
          </div>
        </div>
        <div class="badges">${badges}</div>
      </div>`;
  }).join("");
  grid.querySelectorAll(".app-card").forEach((el) =>
    el.addEventListener("click", () => openDetail(el.dataset.id))
  );
}

/* ---------- 添加 ---------- */
function openAdd() {
  $("add-name").value = "";
  $("add-exe").value = "";
  $("add-dialog").classList.remove("hidden");
}
async function doAdd() {
  const exe = $("add-exe").value.trim();
  if (!exe) return toast("请选择程序路径", true);
  try {
    await invoke("add_app", { input: { name: $("add-name").value.trim(), exe } });
    $("add-dialog").classList.add("hidden");
    toast("已添加（默认只监控 + 启动强制沙箱）");
    await refreshApps();
  } catch (e) {
    toast(String(e), true);
  }
}

/* ---------- 详情 ---------- */
const MODE_DESC = {
  monitor: "只监控：不写入任何拦截规则，全部文件访问照常放行，但每一次打开都会记录到“访问日志”。",
  blacklist: "黑名单：为每个规则目录写入 ClosedFilePath —— 目录及其全部子目录的读/写/枚举打开都会被驱动拒绝（写访问可能表现为“隐藏”而非报错，这是 Sandboxie 的原生行为）。",
  whitelist: "白名单：先写入“默认封闭根”的 ClosedFilePath，再为白名单目录写入 OpenFilePath（读写放行）或 ReadFilePath（只读放行）。盒子启用 UseRuleSpecificity，最具体的规则优先。",
};

function ruleRow(r, listKey) {
  const kindSel =
    state.apps.find((a) => a.id === state.editingId)?.mode === "whitelist" && listKey === "rules"
      ? `<select data-k="kind">
           <option value="rw" ${r.kind === "rw" ? "selected" : ""}>读写放行</option>
           <option value="readonly" ${r.kind === "readonly" ? "selected" : ""}>只读放行</option>
         </select>`
      : "";
  return `
    <div class="rule-row" data-id="${esc(r.id)}">
      <input type="checkbox" data-k="enabled" ${r.enabled ? "checked" : ""} title="启用/停用" />
      <input type="text" data-k="path" value="${esc(r.path)}" placeholder="目录或文件完整路径" />
      <label class="check inline" title="递归覆盖子目录"><input type="checkbox" data-k="recursive" ${r.recursive ? "checked" : ""} /> 递归</label>
      ${kindSel}
      <button class="del" title="删除">✕</button>
    </div>`;
}

function renderRuleLists() {
  const app = state.apps.find((a) => a.id === state.editingId);
  if (!app) return;
  const isWhite = $("input-detail-mode-whitelist").checked;
  $("rules-label").textContent = isWhite ? "白名单目录" : "规则目录";
  $("closed-roots-block").classList.toggle("hidden", !isWhite);
  $("rules-list").innerHTML =
    state.editRules.map((r) => ruleRow(r, "rules")).join("") ||
    `<div class="rule-empty">暂无规则。${isWhite ? "" : "黑名单模式下，这里的目录将被拒绝访问。"}</div>`;
  $("roots-list").innerHTML =
    state.editRoots.map((r) => ruleRow(r, "roots")).join("") ||
    `<div class="rule-empty">暂无封闭根。建议添加用户数据目录（如 文档、下载）。</div>`;

  bindRuleRows("rules-list", state.editRules);
  bindRuleRows("roots-list", state.editRoots);
}

function bindRuleRows(containerId, list) {
  const box = $(containerId);
  box.querySelectorAll(".rule-row").forEach((row) => {
    const id = row.dataset.id;
    const item = list.find((x) => x.id === id);
    row.querySelectorAll("[data-k]").forEach((inp) => {
      const handler = () => {
        if (inp.dataset.k === "kind") item.kind = inp.value;
        else if (inp.type === "checkbox") item[inp.dataset.k] = inp.checked;
        else item[inp.dataset.k] = inp.value;
      };
      inp.addEventListener(inp.tagName === "SELECT" ? "change" : "input", handler);
      inp.addEventListener("change", () => { if (inp.dataset.k === "kind") renderRuleLists(); });
    });
    row.querySelector(".del").addEventListener("click", () => {
      const i = list.findIndex((x) => x.id === id);
      if (i >= 0) list.splice(i, 1);
      renderRuleLists();
    });
  });
}

function currentMode() {
  return document.querySelector('input[name="detail-mode"]:checked')?.value || "monitor";
}

async function openDetail(id) {
  const a = state.apps.find((x) => x.id === id);
  if (!a) return;
  state.editingId = id;
  state.editRules = a.rules.map((r) => ({ ...r }));
  state.editRoots = a.closed_roots.map((r) => ({ ...r }));

  $("detail-title").textContent = `软件详情 · ${a.name}`;
  $("detail-name").value = a.name;
  $("detail-exe").value = a.exe;
  $("detail-box").value = a.box_name;
  $("detail-force").checked = a.force;
  $("detail-force-folder").checked = a.force_folder;
  $("detail-enabled").checked = a.enabled;
  document.querySelectorAll('input[name="detail-mode"]').forEach((r) => {
    r.checked = r.value === a.mode;
  });
  $("mode-desc").textContent = MODE_DESC[a.mode] || "";
  $("detail-msg").textContent = "";

  let running = "未运行";
  try {
    const procs = await invoke("list_box_processes", { id });
    running = procs.length
      ? `沙箱内 ${procs.length} 个进程：` + procs.slice(0, 8).map((p) => `${p.image}(${p.pid})`).join("、")
      : "未运行";
  } catch (e) {
    running = "无法查询（Sandboxie 未就绪）";
  }
  $("detail-running").textContent = running;

  renderRuleLists();
  $("detail-dialog").classList.remove("hidden");
}

async function saveDetail() {
  const id = state.editingId;
  const a = state.apps.find((x) => x.id === id);
  if (!a) return;
  try {
    const out = await invoke("update_app", {
      app: {
        id,
        name: $("detail-name").value,
        exe: $("detail-exe").value,
        mode: currentMode(),
        rules: state.editRules,
        closed_roots: state.editRoots,
        force: $("detail-force").checked,
        force_folder: $("detail-force-folder").checked,
        enabled: $("detail-enabled").checked,
      },
    });
    if (out.applied) {
      $("detail-msg").textContent = "✓ 已保存并应用到 Sandboxie.ini";
      toast("配置已应用");
    } else {
      $("detail-msg").textContent = `⚠ 已保存到本应用，但应用失败：${out.warning || "Sandboxie 未就绪"}`;
      toast("已保存，待 Sandboxie 可用后自动应用", true);
    }
    await refreshApps();
  } catch (e) {
    toast(String(e), true);
  }
}

async function removeCurrent() {
  const id = state.editingId;
  const a = state.apps.find((x) => x.id === id);
  if (!a) return;
  if (!confirm(`确定移除「${a.name}」的保护吗？\n将终止其沙箱内进程并删除盒子规则。`)) return;
  try {
    await invoke("remove_app", { id });
    $("detail-dialog").classList.add("hidden");
    toast("已移除保护");
    await refreshApps();
  } catch (e) {
    toast(String(e), true);
  }
}

/* ============ 访问日志 ============ */
const OP_LABEL = {
  "open-read": "打开·读",
  "open-write": "打开·写",
  "open": "打开",
  "info": "信息",
};
const KIND_LABEL = {
  file: "文件", pipe: "管道", image: "映像",
  registry: "注册表", drive: "磁盘设备", other: "其他",
};

async function pollEvents() {
  try {
    const [events, last] = await invoke("get_events", { since: state.eventsSince, limit: 500 });
    if (events.length) {
      state.events.push(...events);
      if (state.events.length > 5000) state.events.splice(0, state.events.length - 5000);
      state.eventsSince = last;
      renderLog();
    }
  } catch (e) { /* 服务未就绪时静默 */ }
}

function renderLog() {
  const q = state.logSearch.toLowerCase();
  const rows = state.events
    .filter((e) => {
      if (state.filterResult && e.result !== state.filterResult) return false;
      if (state.filterKind && e.kind !== state.filterKind) return false;
      if (q && !(e.path.toLowerCase().includes(q) || e.process.toLowerCase().includes(q) || e.box_name.toLowerCase().includes(q))) return false;
      return true;
    })
    .slice(-500);
  const body = $("log-body");
  body.innerHTML = rows
    .map(
      (e) => `
      <tr class="${e.result === "deny" ? "deny" : ""}">
        <td>${esc(fmtTime(e.ts))}</td>
        <td>${esc(e.process || "?")}</td>
        <td>${e.pid}</td>
        <td>${esc(e.box_name || "—")}</td>
        <td class="path">${esc(e.path)}</td>
        <td><span class="op-tag">${esc(KIND_LABEL[e.kind] || e.kind)}</span> ${esc(OP_LABEL[e.op] || e.op)}${e.access ? ` <span class="muted">0x${esc(e.access)}</span>` : ""}</td>
        <td class="result ${e.result}">${e.result === "deny" ? "拒绝" : "允许"}</td>
      </tr>`
    )
    .join("");
  $("log-empty").classList.toggle("hidden", rows.length > 0);
  $("log-stats").textContent = `显示 ${rows.length} / 缓存 ${state.events.length}`;
  if ($("log-autoscroll").checked) {
    const wrap = document.querySelector(".table-wrap");
    wrap.scrollTop = wrap.scrollHeight;
  }
}

async function exportLog(format) {
  try {
    const dir = await invoke("pick_folder", { title: "选择导出目录" });
    if (!dir) return;
    const name = `diskguard-export-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.${format}`;
    const sep = dir.includes("\\") ? "\\" : "/";
    const count = await invoke("export_events", { path: dir + sep + name, format });
    toast(`已导出 ${count} 条 → ${name}`);
  } catch (e) {
    toast(String(e), true);
  }
}

/* ============ 偏好 ============ */
async function loadPrefs() {
  try {
    state.prefs = await invoke("get_prefs");
  } catch (e) { /* ignore */ }
  applyTheme();
  $("pref-theme").value = state.prefs.theme;
  $("pref-autostart").checked = !!state.prefs.autostart;
  $("pref-close-tray").checked = state.prefs.close_to_tray !== false;
}

async function setPref(key, value) {
  try {
    await invoke("set_pref", { key, value });
    if (key === "theme") {
      state.prefs.theme = value;
      applyTheme();
    }
  } catch (e) {
    toast(String(e), true);
    await loadPrefs();
  }
}

/* ============ 事件绑定 ============ */
function bindNav() {
  document.querySelectorAll(".nav-btn").forEach((btn) =>
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
      btn.classList.add("active");
      $(`view-${btn.dataset.view}`).classList.add("active");
    })
  );
}

function bindDetail() {
  $("btn-add-app").addEventListener("click", openAdd);
  $("add-cancel").addEventListener("click", () => $("add-dialog").classList.add("hidden"));
  $("add-ok").addEventListener("click", doAdd);
  $("btn-browse-exe").addEventListener("click", async () => {
    const p = await invoke("pick_file", { title: "选择程序", exeOnly: true });
    if (p) $("add-exe").value = p;
  });

  $("detail-cancel").addEventListener("click", () => $("detail-dialog").classList.add("hidden"));
  $("detail-save").addEventListener("click", saveDetail);
  $("detail-remove").addEventListener("click", removeCurrent);
  $("detail-browse-exe").addEventListener("click", async () => {
    const p = await invoke("pick_file", { title: "选择程序", exeOnly: true });
    if (p) $("detail-exe").value = p;
  });
  $("detail-launch").addEventListener("click", async () => {
    try {
      await invoke("launch_app", { id: state.editingId });
      toast("已请求在沙箱中启动");
      setTimeout(refreshApps, 1500);
    } catch (e) { toast(String(e), true); }
  });
  $("detail-terminate").addEventListener("click", async () => {
    try {
      await invoke("terminate_app", { id: state.editingId });
      toast("已发送终止命令");
      setTimeout(refreshApps, 1200);
    } catch (e) { toast(String(e), true); }
  });
  $("detail-open-folder").addEventListener("click", async () => {
    try {
      const p = await invoke("get_sandbox_path", { id: state.editingId });
      await invoke("open_in_explorer", { path: p });
    } catch (e) { toast(String(e), true); }
  });

  document.querySelectorAll('input[name="detail-mode"]').forEach((r) =>
    r.addEventListener("change", () => {
      $("mode-desc").textContent = MODE_DESC[currentMode()] || "";
      if (currentMode() === "monitor") toast("只监控模式：规则保留但不生效，切换回其他模式会自动恢复");
      renderRuleLists();
    })
  );
  // 给 mode radio 提供 id 供 renderRuleLists 判断
  document.querySelectorAll('input[name="detail-mode"]').forEach((r) => {
    r.id = `input-detail-mode-${r.value}`;
  });

  const newRule = () => ({ id: "r-" + Math.random().toString(36).slice(2, 10), path: "", recursive: true, enabled: true, kind: "rw" });
  $("btn-add-rule").addEventListener("click", async () => {
    state.editRules.push(newRule());
    renderRuleLists();
  });
  $("btn-add-root").addEventListener("click", async () => {
    state.editRoots.push(newRule());
    renderRuleLists();
  });
}

function bindLogs() {
  $("log-search").addEventListener("input", (e) => { state.logSearch = e.target.value; renderLog(); });
  $("filter-result").addEventListener("change", (e) => { state.filterResult = e.target.value; renderLog(); });
  $("filter-kind").addEventListener("change", (e) => { state.filterKind = e.target.value; renderLog(); });
  $("btn-clear-log").addEventListener("click", async () => {
    await invoke("clear_events");
    state.events = [];
    renderLog();
  });
  $("btn-export-csv").addEventListener("click", () => exportLog("csv"));
  $("btn-export-jsonl").addEventListener("click", () => exportLog("jsonl"));
}

function bindSettings() {
  $("pref-theme").addEventListener("change", (e) => setPref("theme", e.target.value));
  $("pref-autostart").addEventListener("change", (e) => setPref("autostart", e.target.checked));
  $("pref-close-tray").addEventListener("change", (e) => setPref("close_to_tray", e.target.checked));
}

/* ============ 启动 ============ */
(async function init() {
  bindNav();
  bindDetail();
  bindLogs();
  bindSettings();
  await loadPrefs();
  await refreshStatus();
  await refreshApps();
  setInterval(refreshStatus, 5000);
  setInterval(refreshApps, 4000);
  setInterval(pollEvents, 400);
})();
