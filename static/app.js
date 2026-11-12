"use strict";

const SESSION_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_PASSWORD_LENGTH = 20;
const state = {
  mode: "login", entries: [], username: "", csrfToken: "", epoch: 0,
  lastActivity: 0, sessionDeadline: 0, signingOut: false, authPending: false,
};
const $ = (selector) => document.querySelector(selector);
const pendingRequests = new Set();
let lockTimer;

function staleRequestError() {
  const error = new Error("会话已改变，请重新操作");
  error.staleRequest = true;
  return error;
}

function reportError(error) {
  if (!error.staleRequest) toast(error.message || "请求失败，请重试", true);
}

async function api(path, options = {}) {
  const epoch = state.epoch;
  const method = (options.method || "GET").toUpperCase();
  const protectedRequest = !["/api/session", "/api/login", "/api/register"].includes(path);
  if (protectedRequest && !ensureVaultActive()) throw staleRequestError();
  const securityHeaders = {};
  if (method !== "GET" && state.csrfToken) securityHeaders["X-CSRF-Token"] = state.csrfToken;
  const controller = new AbortController();
  pendingRequests.add(controller);
  try {
    const response = await fetch(path, {
      ...options,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...securityHeaders, ...(options.headers || {}) },
    });
    const data = await response.json().catch(() => ({}));
    // An old response must never restore secrets or lock a newer login.
    if (epoch !== state.epoch) throw staleRequestError();
    if (response.status === 401 && protectedRequest) lockVault();
    if (!response.ok) throw new Error(data.error || "请求失败");
    if (protectedRequest) {
      state.sessionDeadline = Date.now() + SESSION_TIMEOUT_MS;
      scheduleLock();
    }
    return data;
  } catch (error) {
    if (epoch !== state.epoch && error.name === "AbortError") throw staleRequestError();
    throw error;
  } finally {
    pendingRequests.delete(controller);
  }
}

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.toggle("error", error);
  node.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => node.classList.remove("show"), 2200);
}

function setAuthMode(mode) {
  state.mode = mode;
  document.querySelectorAll("[data-auth-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.authTab === mode);
  });
  const register = mode === "register";
  $("#auth-title").textContent = register ? "创建保险库" : "欢迎回来";
  $("#auth-subtitle").textContent = register ? "建立你的本地演示账号" : "登录后打开你的密码保险库";
  $("#auth-submit-text").textContent = register ? "创建账号" : "进入保险库";
  $("#auth-password").autocomplete = register ? "new-password" : "current-password";
  $("#auth-hint").textContent = register
    ? "主密码需 12-128 位，并至少包含大写、小写、数字、符号中的三类。"
    : "保险库密钥仅在登录会话内存中使用，服务端数据库只保存密文。";
}

function clearEntryForm() {
  for (const field of ["id", "site", "account", "url", "password", "notes"]) {
    $(`#entry-${field}`).value = "";
  }
  $("#entry-password").type = "password";
  $("#toggle-password").textContent = "显示";
  $("#password-length").value = String(DEFAULT_PASSWORD_LENGTH);
  updateStrength();
}

function lockVault() {
  state.epoch += 1;
  clearTimeout(lockTimer);
  for (const controller of pendingRequests) controller.abort();
  pendingRequests.clear();
  // Drop app-held references; JavaScript cannot guarantee physical memory erasure.
  for (const entry of state.entries) {
    for (const key of Object.keys(entry)) entry[key] = "";
  }
  state.entries = [];
  state.username = "";
  state.csrfToken = "";
  state.lastActivity = 0;
  state.sessionDeadline = 0;
  $("#entries-grid").replaceChildren();
  $("#audit-list").replaceChildren();
  $("#entry-count").textContent = "0";
  $("#visible-count").textContent = "0";
  $("#current-user").textContent = "";
  $("#search-input").value = "";
  $("#auth-username").value = "";
  $("#auth-password").value = "";
  clearEntryForm();
  for (const selector of ["#entry-dialog", "#audit-dialog"]) {
    if ($(selector).open) $(selector).close();
  }
  $("#empty-state").classList.add("hidden");
  $("#auth-view").classList.remove("hidden");
  $("#vault-view").classList.add("hidden");
}

function scheduleLock() {
  clearTimeout(lockTimer);
  if (!state.username) return;
  const remaining = Math.min(state.lastActivity + SESSION_TIMEOUT_MS, state.sessionDeadline) - Date.now();
  lockTimer = setTimeout(() => ensureVaultActive(), Math.max(0, remaining));
}

function ensureVaultActive() {
  if (!state.username || !state.csrfToken) return false;
  if (Date.now() >= Math.min(state.lastActivity + SESSION_TIMEOUT_MS, state.sessionDeadline)) {
    void logout("会话已锁定，请重新登录");
    return false;
  }
  return true;
}

function recordActivity() {
  // Check before renewing: a suspended background tab must lock when resumed.
  if (!ensureVaultActive()) return;
  state.lastActivity = Date.now();
  scheduleLock();
}

async function logout(message = "已退出登录") {
  if (state.signingOut) return;
  const csrfToken = state.csrfToken;
  state.signingOut = true;
  $("#auth-form button[type=submit]").disabled = true;
  lockVault();
  toast(message);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    if (csrfToken) {
      const response = await fetch("/api/logout", {
        method: "POST", body: "{}", signal: controller.signal,
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken },
      });
      if (!response.ok && response.status !== 401) throw new Error("服务端退出失败");
    }
  } catch {
    toast("本页已锁定；服务端退出未确认，请恢复连接后重新登录并退出", true);
  } finally {
    clearTimeout(timeout);
    state.signingOut = false;
    $("#auth-form button[type=submit]").disabled = state.authPending;
  }
}

async function showVault(username) {
  state.username = username;
  state.lastActivity = Date.now();
  state.sessionDeadline = Date.now() + SESSION_TIMEOUT_MS;
  scheduleLock();
  $("#current-user").textContent = username;
  $("#auth-view").classList.add("hidden");
  $("#vault-view").classList.remove("hidden");
  await loadEntries();
}

async function showAudit() {
  if (!ensureVaultActive()) return;
  const epoch = state.epoch;
  try {
    const data = await api("/api/audit");
    if (epoch !== state.epoch || !ensureVaultActive()) return;
    const list = $("#audit-list");
    const labels = {
      register: "账号注册", login: "登录成功", entry_create: "创建条目",
      entry_update: "更新条目", entry_delete: "删除条目", integrity_failure: "完整性异常",
    };
    const nodes = (data.logs || []).map((item) => {
      const row = document.createElement("div");
      row.className = "audit-item";
      const action = document.createElement("b");
      action.textContent = labels[item.action] || item.action;
      const id = document.createElement("span");
      id.textContent = item.entry_id || "-";
      const when = document.createElement("time");
      when.textContent = new Date(item.created_at * 1000).toLocaleString("zh-CN");
      row.append(action, id, when);
      return row;
    });
    if (!nodes.length) {
      const empty = document.createElement("p");
      empty.className = "empty-state";
      empty.textContent = "暂无审计记录";
      nodes.push(empty);
    }
    list.replaceChildren(...nodes);
    $("#audit-dialog").showModal();
  } catch (error) { reportError(error); }
}

async function loadEntries() {
  if (!ensureVaultActive()) return;
  const epoch = state.epoch;
  const data = await api("/api/entries");
  if (epoch !== state.epoch || !ensureVaultActive()) return;
  state.entries = data.entries || [];
  renderEntries();
}

function maskedSecret(value) {
  return "•".repeat(Math.max(10, Math.min(18, value.length || 10)));
}

function createButton(label, className, handler) {
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  if (className) button.className = className;
  button.addEventListener("click", handler);
  return button;
}

function entryCard(entry) {
  const epoch = state.epoch;
  const active = () => epoch === state.epoch && ensureVaultActive();
  const article = document.createElement("article");
  article.className = "entry-card";

  const head = document.createElement("div");
  head.className = "entry-head";
  const icon = document.createElement("span");
  icon.className = "site-icon";
  icon.textContent = (entry.site || "K").trim().slice(0, 1).toUpperCase();
  const title = document.createElement("div");
  title.className = "entry-title";
  const h3 = document.createElement("h3");
  h3.textContent = entry.site;
  const account = document.createElement("p");
  account.textContent = entry.account;
  title.append(h3, account);
  head.append(icon, title);

  const secretRow = document.createElement("div");
  secretRow.className = "secret-row";
  const secret = document.createElement("span");
  secret.className = "secret-text";
  secret.textContent = maskedSecret(entry.password);
  let revealed = false;
  const reveal = createButton("显示", "tiny-action", () => {
    if (!active()) return;
    revealed = !revealed;
    secret.textContent = revealed ? entry.password : maskedSecret(entry.password);
    reveal.textContent = revealed ? "隐藏" : "显示";
  });
  const copy = createButton("复制", "tiny-action", async () => {
    if (!active()) return;
    try {
      await navigator.clipboard.writeText(entry.password);
      if (active()) toast("密码已复制");
    } catch { if (active()) toast("复制失败，请检查浏览器剪贴板权限", true); }
  });
  secretRow.append(secret, reveal, copy);

  const meta = document.createElement("div");
  meta.className = "entry-meta";
  meta.textContent = entry.notes || entry.url || "暂无备注";

  const actions = document.createElement("div");
  actions.className = "entry-actions";
  actions.append(
    createButton("编辑", "", () => { if (active()) openEntryDialog(entry); }),
    createButton("删除", "delete", () => { if (active()) void removeEntry(entry); }),
  );
  article.append(head, secretRow, meta, actions);
  return article;
}

function renderEntries() {
  if (!ensureVaultActive()) return;
  const query = $("#search-input").value.trim().toLowerCase();
  const visible = state.entries.filter((entry) => {
    const haystack = `${entry.site} ${entry.account} ${entry.url} ${entry.notes}`.toLowerCase();
    return haystack.includes(query);
  });
  $("#entry-count").textContent = String(state.entries.length);
  $("#visible-count").textContent = String(visible.length);
  const grid = $("#entries-grid");
  grid.replaceChildren(...visible.map(entryCard));
  $("#empty-state").classList.toggle("hidden", state.entries.length !== 0 || Boolean(query));
  if (!visible.length && state.entries.length && query) {
    const note = document.createElement("p");
    note.className = "empty-state";
    note.textContent = "没有匹配的条目，请尝试其他关键词。";
    grid.replaceChildren(note);
  }
}

function openEntryDialog(entry = null) {
  if (!ensureVaultActive()) return;
  $("#dialog-title").textContent = entry ? "编辑条目" : "新建条目";
  $("#entry-id").value = entry ? String(entry.id) : "";
  $("#entry-site").value = entry?.site || "";
  $("#entry-account").value = entry?.account || "";
  $("#entry-url").value = entry?.url || "";
  $("#entry-password").value = entry?.password || "";
  $("#entry-notes").value = entry?.notes || "";
  $("#entry-password").type = "password";
  $("#toggle-password").textContent = "显示";
  updateStrength();
  $("#entry-dialog").showModal();
  $("#entry-site").focus();
}

async function removeEntry(entry) {
  if (!ensureVaultActive()) return;
  const epoch = state.epoch;
  if (!confirm(`确定删除“${entry.site}”吗？`)) return;
  try {
    await api(`/api/entries/${entry.id}`, { method: "DELETE" });
    if (epoch !== state.epoch) return;
    toast("条目已删除");
    await loadEntries();
  } catch (error) { reportError(error); }
}

function secureRandomInt(maxExclusive) {
  if (!Number.isSafeInteger(maxExclusive) || maxExclusive <= 0) throw new Error("范围无效");
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const values = new Uint32Array(1);
  do { window.crypto.getRandomValues(values); } while (values[0] >= limit);
  return values[0] % maxExclusive;
}

function generatePassword(length = DEFAULT_PASSWORD_LENGTH) {
  if (!Number.isSafeInteger(length) || length < 4 || length > 128) throw new Error("密码长度须为 4-128 位");
  const groups = [
    "ABCDEFGHJKLMNPQRSTUVWXYZ",
    "abcdefghijkmnopqrstuvwxyz",
    "23456789",
    "!@#$%^&*()-_=+",
  ];
  const chars = groups.map((group) => group[secureRandomInt(group.length)]);
  const all = groups.join("");
  while (chars.length < length) chars.push(all[secureRandomInt(all.length)]);
  for (let index = chars.length - 1; index > 0; index -= 1) {
    const target = secureRandomInt(index + 1);
    [chars[index], chars[target]] = [chars[target], chars[index]];
  }
  return chars.join("");
}

function updateStrength() {
  const value = $("#entry-password").value;
  let score = Math.min(2, Math.floor(value.length / 8));
  score += /[a-z]/.test(value) && /[A-Z]/.test(value) ? 1 : 0;
  score += /\d/.test(value) && /[^A-Za-z0-9]/.test(value) ? 1 : 0;
  const labels = ["请设置密码", "较弱", "一般", "良好", "较强"];
  $("#strength-text").textContent = `${labels[Math.min(4, score)]} · 当前 ${value.length} 位`;
}

document.querySelectorAll("[data-auth-tab]").forEach((button) => {
  button.addEventListener("click", () => setAuthMode(button.dataset.authTab));
});

$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (state.signingOut || state.authPending) return;
  const body = { username: $("#auth-username").value.trim(), password: $("#auth-password").value };
  // Invalidate an in-flight startup session check before beginning a new login.
  lockVault();
  const epoch = state.epoch;
  state.authPending = true;
  $("#auth-form button[type=submit]").disabled = true;
  try {
    const data = await api(state.mode === "register" ? "/api/register" : "/api/login", { method: "POST", body: JSON.stringify(body) });
    if (epoch !== state.epoch || state.signingOut) return;
    state.csrfToken = data.csrfToken;
    $("#auth-password").value = "";
    await showVault(data.username);
  } catch (error) {
    if (epoch === state.epoch) lockVault();
    reportError(error);
  } finally {
    body.password = "";
    state.authPending = false;
    $("#auth-form button[type=submit]").disabled = state.signingOut;
  }
});

$("#logout-button").addEventListener("click", () => logout());
$("#audit-button").addEventListener("click", showAudit);
$("#audit-close").addEventListener("click", () => $("#audit-dialog").close());
$("#audit-dialog").addEventListener("close", () => $("#audit-list").replaceChildren());
$("#add-button").addEventListener("click", () => openEntryDialog());
$("#empty-add-button").addEventListener("click", () => openEntryDialog());
$("#refresh-button").addEventListener("click", () => loadEntries().catch(reportError));
$("#search-input").addEventListener("input", renderEntries);
document.querySelectorAll("#entry-dialog .dialog-close, #entry-dialog .dialog-cancel").forEach((button) => button.addEventListener("click", () => $("#entry-dialog").close()));
$("#entry-dialog").addEventListener("close", clearEntryForm);
$("#toggle-password").addEventListener("click", () => {
  if (!ensureVaultActive()) return;
  const input = $("#entry-password");
  input.type = input.type === "password" ? "text" : "password";
  $("#toggle-password").textContent = input.type === "password" ? "显示" : "隐藏";
});
$("#generate-password").addEventListener("click", () => {
  if (!ensureVaultActive()) return;
  const password = generatePassword(Number($("#password-length").value));
  $("#entry-password").value = password;
  updateStrength();
  toast(`已生成 ${password.length} 位随机密码`);
});
$("#entry-password").addEventListener("input", updateStrength);
$("#entry-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!ensureVaultActive()) return;
  const epoch = state.epoch;
  const id = $("#entry-id").value;
  const body = {
    site: $("#entry-site").value.trim(),
    account: $("#entry-account").value.trim(),
    url: $("#entry-url").value.trim(),
    password: $("#entry-password").value,
    notes: $("#entry-notes").value.trim(),
  };
  try {
    await api(id ? `/api/entries/${id}` : "/api/entries", { method: id ? "PUT" : "POST", body: JSON.stringify(body) });
    if (epoch !== state.epoch || !ensureVaultActive()) return;
    $("#entry-dialog").close();
    toast(id ? "条目已更新" : "条目已保存");
    await loadEntries();
  } catch (error) { reportError(error); }
  finally { body.password = ""; }
});

for (const event of ["pointerdown", "keydown"]) document.addEventListener(event, recordActivity, { passive: true });
window.addEventListener("focus", recordActivity);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") ensureVaultActive();
});
window.addEventListener("pagehide", lockVault);
window.addEventListener("pageshow", (event) => {
  if (event.persisted) lockVault();
});

(async () => {
  const epoch = state.epoch;
  try {
    const session = await api("/api/session");
    if (epoch !== state.epoch) return;
    if (session.authenticated) { state.csrfToken = session.csrfToken; await showVault(session.username); }
    else lockVault();
  } catch (error) {
    if (epoch === state.epoch) {
      lockVault();
      reportError(error);
    }
  }
})();
