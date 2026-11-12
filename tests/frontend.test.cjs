"use strict";

// Behavior tests for the shipped browser script, using only Node built-ins.
// This small DOM stub is not a substitute for cross-browser visual testing.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const source = fs.readFileSync(path.join(__dirname, "../static/app.js"), "utf8");
const html = fs.readFileSync(path.join(__dirname, "../static/index.html"), "utf8");
const tick = () => new Promise((resolve) => setImmediate(resolve));
const response = (data = {}, status = 200) => ({
  ok: status >= 200 && status < 300, status, json: async () => data,
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

class Element {
  constructor() {
    this.children = [];
    this.events = new Map();
    this.classes = new Set();
    this.classList = {
      add: (...items) => items.forEach((item) => this.classes.add(item)),
      remove: (...items) => items.forEach((item) => this.classes.delete(item)),
      contains: (item) => this.classes.has(item),
      toggle: (item, force) => {
        const enabled = force === undefined ? !this.classes.has(item) : Boolean(force);
        if (enabled) this.classes.add(item); else this.classes.delete(item);
        return enabled;
      },
    };
    this.value = "";
    this.dataset = {};
    this.open = false;
    this.disabled = false;
    this._text = "";
  }
  get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) { this._text = String(value); this.children = []; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this._text = ""; this.children = children; }
  addEventListener(name, listener) {
    if (!this.events.has(name)) this.events.set(name, []);
    this.events.get(name).push(listener);
  }
  async dispatch(name, event = {}) {
    await Promise.all((this.events.get(name) || []).map((listener) => listener({ preventDefault() {}, ...event })));
  }
  showModal() { this.open = true; }
  close() {
    this.open = false;
    for (const listener of this.events.get("close") || []) listener({});
  }
  focus() {}
}

async function harness({ initialSession } = {}) {
  let now = 100000;
  let timerId = 0;
  const timers = new Map();
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map((match) => [`#${match[1]}`, new Element()]));
  elements.set("#auth-form button[type=submit]", new Element());
  const tabs = ["login", "register"].map((mode) => {
    const element = new Element(); element.dataset.authTab = mode; return element;
  });
  const closeButtons = [new Element(), new Element()];
  const document = new Element();
  document.visibilityState = "visible";
  document.querySelector = (selector) => {
    assert.ok(elements.has(selector), `Known selector: ${selector}`);
    return elements.get(selector);
  };
  document.querySelectorAll = (selector) => {
    if (selector === "[data-auth-tab]") return tabs;
    if (selector === "#entry-dialog .dialog-close, #entry-dialog .dialog-cancel") return closeButtons;
    throw new Error(`Unexpected selector: ${selector}`);
  };
  document.createElement = () => new Element();
  const window = new Element();
  window.crypto = webcrypto;
  const clipboard = [];
  const requests = [];
  let handler = async (url) => {
    if (url === "/api/session") return initialSession ? initialSession.promise : response({ authenticated: false });
    if (url === "/api/entries") return response({ entries: [] });
    return response();
  };
  class ClockDate extends Date { static now() { return now; } }
  const context = vm.createContext({
    document, window, AbortController, Uint32Array, Date: ClockDate,
    confirm: () => true,
    navigator: { clipboard: { writeText: async (text) => clipboard.push(text) } },
    setTimeout: (fn, delay) => { const id = ++timerId; timers.set(id, { fn, due: now + delay }); return id; },
    clearTimeout: (id) => timers.delete(id),
    fetch: (url, options) => { requests.push({ url, options }); return handler(url, options); },
  });
  vm.runInContext(`${source}\n;globalThis.exposed = { state, api, lockVault, loadEntries, showVault, showAudit, openEntryDialog, logout, recordActivity, ensureVaultActive, generatePassword, renderEntries, SESSION_TIMEOUT_MS };`, context);
  await tick();
  const api = context.exposed;
  const get = (id) => document.querySelector(`#${id}`);
  function activate(username = "alice", entries = []) {
    api.state.username = username;
    api.state.csrfToken = `csrf-${username}`;
    api.state.lastActivity = now;
    api.state.sessionDeadline = now + api.SESSION_TIMEOUT_MS;
    api.state.entries = entries;
    get("auth-view").classList.add("hidden");
    get("vault-view").classList.remove("hidden");
    api.renderEntries();
  }
  return {
    ...api, get, activate, document, window, clipboard, requests, closeButtons,
    setHandler: (next) => { handler = next; },
    advance: (amount) => { now += amount; },
    runTimers: () => {
      for (const [id, timer] of [...timers]) {
        if (timer.due <= now) { timers.delete(id); timer.fn(); }
      }
    },
  };
}

const entry = () => ({ id: "entry-1", site: "Example", account: "test@example.invalid", password: "Fictional-Secret-123!", url: "https://example.invalid", notes: "test-only" });
function assertLocked(h) {
  assert.equal(h.state.entries.length, 0);
  assert.equal(h.state.csrfToken, "");
  assert.equal(h.state.username, "");
  assert.equal(h.get("entries-grid").children.length, 0);
  assert.equal(h.get("audit-list").children.length, 0);
  assert.equal(h.get("entry-dialog").open, false);
  assert.equal(h.get("audit-dialog").open, false);
  for (const field of ["id", "site", "account", "url", "password", "notes"]) assert.equal(h.get(`entry-${field}`).value, "");
  assert.equal(h.get("entry-password").type, "password");
  assert.equal(h.get("vault-view").classList.contains("hidden"), true);
  assert.equal(h.get("auth-view").classList.contains("hidden"), false);
}

test("locking clears secrets, forms, audit content, and dialogs", async () => {
  const h = await harness();
  const item = entry();
  h.activate("alice", [item]);
  h.openEntryDialog(item);
  h.get("audit-list").append(new Element());
  h.get("audit-dialog").showModal();
  h.get("auth-password").value = "temporary master password";
  h.get("auth-username").value = "alice";
  h.get("search-input").value = "private query";
  h.lockVault();
  assertLocked(h);
  assert.equal(item.password, "");
  assert.equal(h.get("auth-password").value, "");
  assert.equal(h.get("auth-username").value, "");
  assert.equal(h.get("search-input").value, "");
});

test("detached card callbacks cannot reveal, copy, or edit after lock", async () => {
  const h = await harness();
  h.activate("alice", [entry()]);
  const card = h.get("entries-grid").children[0];
  const [, reveal, copy] = card.children[1].children;
  const edit = card.children[3].children[0];
  h.lockVault();
  await reveal.dispatch("click");
  await copy.dispatch("click");
  await edit.dispatch("click");
  assert.equal(h.clipboard.length, 0);
  assert.equal(h.get("entry-dialog").open, false);
  assert.match(card.children[1].children[0].textContent, /^•+$/);
});

test("protected 401 clears the vault instead of leaving plaintext onscreen", async () => {
  const h = await harness();
  h.activate("alice", [entry()]);
  h.openEntryDialog(h.state.entries[0]);
  h.setHandler(async () => response({ error: "登录已过期" }, 401));
  await h.get("refresh-button").dispatch("click");
  assertLocked(h);
  assert.equal(h.get("toast").textContent, "登录已过期");
});

test("late entry response cannot restore data after locking", async () => {
  const h = await harness();
  h.activate();
  const pending = deferred();
  h.setHandler(() => pending.promise); // Deliberately ignores AbortSignal.
  const result = h.loadEntries().catch((error) => error);
  h.lockVault();
  pending.resolve(response({ entries: [entry()] }));
  assert.equal((await result).staleRequest, true);
  assertLocked(h);
});

test("a late 401 from the previous session cannot lock the next user", async () => {
  const h = await harness();
  h.activate();
  const pending = deferred();
  h.setHandler(() => pending.promise);
  const result = h.loadEntries().catch((error) => error);
  h.lockVault();
  h.activate("bob", [entry()]);
  pending.resolve(response({ error: "old session" }, 401));
  assert.equal((await result).staleRequest, true);
  assert.equal(h.state.username, "bob");
  assert.equal(h.state.entries.length, 1);
});

test("logout locks immediately and blocks re-login until server logout completes", async () => {
  const h = await harness();
  h.activate("alice", [entry()]);
  const pending = deferred();
  h.setHandler(() => pending.promise);
  const result = h.logout();
  assertLocked(h);
  assert.equal(h.state.signingOut, true);
  assert.equal(h.requests.at(-1).options.headers["X-CSRF-Token"], "csrf-alice");
  h.get("auth-username").value = "bob";
  h.get("auth-password").value = "FictionalMaster-123!";
  await h.get("auth-form").dispatch("submit");
  assert.equal(h.requests.filter((request) => request.url === "/api/login").length, 0);
  pending.reject(new TypeError("offline"));
  await result;
  assertLocked(h);
  assert.equal(h.state.signingOut, false);
  assert.match(h.get("toast").textContent, /服务端退出未确认/);
});

test("a delayed audit response cannot reopen its dialog after logout", async () => {
  const h = await harness();
  h.activate();
  const pending = deferred();
  h.setHandler(() => pending.promise);
  const result = h.showAudit();
  h.lockVault();
  pending.resolve(response({ logs: [{ action: "login", entry_id: null, created_at: 1 }] }));
  await result;
  assertLocked(h);
});

test("a late save response cannot close or refresh a new user's editor", async () => {
  const h = await harness();
  h.activate("alice");
  h.openEntryDialog(entry());
  const pending = deferred();
  h.setHandler(() => pending.promise);
  const saving = h.get("entry-form").dispatch("submit");
  h.lockVault();
  h.activate("bob");
  h.openEntryDialog({ ...entry(), password: "Another-Fictional-Secret!" });
  const count = h.requests.length;
  pending.resolve(response({ message: "saved" }));
  await saving;
  assert.equal(h.state.username, "bob");
  assert.equal(h.get("entry-dialog").open, true);
  assert.equal(h.get("entry-password").value, "Another-Fictional-Secret!");
  assert.equal(h.requests.length, count);
});

test("duplicate authentication submissions only send one login request", async () => {
  const h = await harness();
  const pending = deferred();
  h.setHandler(async (url) => url === "/api/login" ? pending.promise : response({ entries: [] }));
  h.get("auth-username").value = "alice";
  h.get("auth-password").value = "FictionalMaster-123!";
  const loggingIn = h.get("auth-form").dispatch("submit");
  await h.get("auth-form").dispatch("submit");
  assert.equal(h.requests.filter((request) => request.url === "/api/login").length, 1);
  pending.resolve(response({ username: "alice", csrfToken: "csrf-alice" }));
  await loggingIn;
  assert.equal(h.state.username, "alice");
  assert.equal(h.state.authPending, false);
});

test("idle deadline locks even if the first event arrives after a suspended timer", async () => {
  const h = await harness();
  h.activate("alice", [entry()]);
  h.advance(h.SESSION_TIMEOUT_MS);
  await h.document.dispatch("keydown");
  await tick();
  assertLocked(h);
  assert.equal(h.requests.at(-1).url, "/api/logout");
});

test("activity cannot extend the server-session deadline without a request", async () => {
  const h = await harness();
  h.activate();
  h.advance(h.SESSION_TIMEOUT_MS - 1);
  h.recordActivity();
  assert.equal(h.state.username, "alice");
  h.advance(1);
  h.runTimers();
  await tick();
  assertLocked(h);
});

test("closing the editor clears its fields and hides any revealed password", async () => {
  const h = await harness();
  h.activate();
  h.openEntryDialog(entry());
  await h.get("toggle-password").dispatch("click");
  assert.equal(h.get("entry-password").type, "text");
  await h.closeButtons[0].dispatch("click");
  assert.equal(h.get("entry-password").value, "");
  assert.equal(h.get("entry-password").type, "password");
  assert.equal(h.get("entry-site").value, "");
});

test("late startup session check does not overwrite a completed login", async () => {
  const startup = deferred();
  const h = await harness({ initialSession: startup });
  h.setHandler(async (url) => url === "/api/login"
    ? response({ username: "bob", csrfToken: "csrf-bob" })
    : response({ entries: [entry()] }));
  h.get("auth-username").value = "bob";
  h.get("auth-password").value = "FictionalMaster-123!";
  await h.get("auth-form").dispatch("submit");
  startup.resolve(response({ authenticated: true, username: "alice", csrfToken: "csrf-old" }));
  await tick();
  assert.equal(h.state.username, "bob");
  assert.equal(h.state.csrfToken, "csrf-bob");
  assert.equal(h.state.entries.length, 1);
  assert.equal(h.get("auth-password").value, "");
});

test("restoring a browser history page leaves the vault locked", async () => {
  const h = await harness();
  h.activate("alice", [entry()]);
  await h.window.dispatch("pagehide");
  assertLocked(h);
  await h.window.dispatch("pageshow", { persisted: true });
  assertLocked(h);
});

test("generated passwords honor length and include all four character groups", async () => {
  const h = await harness();
  const values = new Set();
  for (let index = 0; index < 32; index += 1) {
    const password = h.generatePassword();
    assert.equal(password.length, 20);
    assert.match(password, /[A-Z]/);
    assert.match(password, /[a-z]/);
    assert.match(password, /[0-9]/);
    assert.match(password, /[^A-Za-z0-9]/);
    values.add(password);
  }
  assert.ok(values.size > 1);
  assert.equal(h.generatePassword(4).length, 4);
  for (const length of [0, 3, 129, 4.5, NaN]) assert.throws(() => h.generatePassword(length));
});

test("generate button uses the selected length and closing the dialog restores the default", async () => {
  const h = await harness();
  h.activate();
  h.openEntryDialog();

  const selector = h.get("password-length");
  for (const length of [16, 20, 24, 32]) {
    selector.value = String(length);
    await h.get("generate-password").dispatch("click");
    assert.equal(h.get("entry-password").value.length, length);
    assert.match(h.get("strength-text").textContent, new RegExp(`当前 ${length} 位`));
    assert.equal(h.get("toast").textContent, `已生成 ${length} 位随机密码`);
  }

  h.get("entry-dialog").close();
  assert.equal(selector.value, "20");
});
