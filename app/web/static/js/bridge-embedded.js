/* Keep the unmodified Bridge UI on Team48's authenticated, private upstream. */
(() => {
  "use strict";
  const prefix = "/auth-bridge";
  const channel = "team48-auth-bridge";
  const storagePrefix = "team48.auth-bridge.";
  const origin = window.location.origin;
  document.documentElement.dataset.team48Embedded = "true";
  const NativeRequest = window.Request;
  const nativeFetch = window.fetch.bind(window);
  let initialized = false;
  let autoSave = false;
  let lastWrite = Promise.resolve();
  let resolveReady;
  const ready = new Promise(resolve => { resolveReady = resolve; });

  function upstreamUrl(value) {
    const url = new URL(String(value), window.location.href);
    if (url.origin === origin && (url.pathname === "/api" || url.pathname.startsWith("/api/"))) {
      url.pathname = prefix + url.pathname;
    }
    return url.href;
  }
  function isConfigRequest(value) {
    try { return new URL(String(value), window.location.href).pathname === prefix + "/api/system/config"; }
    catch { return false; }
  }
  function post(type, detail = {}) {
    if (window.parent !== window) window.parent.postMessage({channel, type, ...detail}, origin);
  }
  function currentTool() {
    const selected = document.querySelector('.top-nav [data-format][aria-pressed="true"]');
    if (selected?.dataset.formatGroup === "converter") {
      return document.querySelector('#format-list [data-format][aria-pressed="true"]')?.dataset.format || "sub2api";
    }
    return selected?.dataset.format || "sub2api";
  }
  function markReady() {
    if (initialized || !window.browserWorkspace || !document.querySelector("#session-input")) return;
    initialized = true;
    // The Bridge requests configuration after restoring storage and binding its controls.
    for (const method of ["save", "clear", "clearLoginData"]) {
      const original = window.browserWorkspace[method];
      window.browserWorkspace[method] = function (...args) {
        const pending = original.apply(this, args);
        lastWrite = Promise.resolve(pending);
        lastWrite.catch(() => {});
        return pending;
      };
    }
    resolveReady();
    post("ready", {tool: currentTool()});
  }

  window.Request = class EmbeddedRequest extends NativeRequest {
    constructor(input, init) {
      if (input instanceof NativeRequest) {
        const mapped = upstreamUrl(input.url);
        super(mapped === input.url ? input : new NativeRequest(mapped, input), init);
      } else super(upstreamUrl(input), init);
    }
  };
  window.fetch = function (input, init) {
    const raw = input instanceof NativeRequest ? input.url : String(input);
    const mapped = upstreamUrl(raw);
    const request = input instanceof NativeRequest && mapped !== input.url
      ? new NativeRequest(mapped, input) : input instanceof NativeRequest ? input : mapped;
    if (isConfigRequest(mapped)) queueMicrotask(markReady);
    return nativeFetch(request, init);
  };
  if (window.EventSource) {
    const NativeEventSource = window.EventSource;
    window.EventSource = class EmbeddedEventSource extends NativeEventSource {
      constructor(url, options) { super(upstreamUrl(url), options); }
    };
  }

  // Embedded storage has its own keys, database and cross-tab invalidation channel.
  if (window.indexedDB) {
    for (const method of ["open", "deleteDatabase"]) {
      const original = window.indexedDB[method].bind(window.indexedDB);
      window.indexedDB[method] = function (name, ...args) {
        return original(String(name) === "session-converter-browser" ? storagePrefix + "browser" : name, ...args);
      };
    }
  }
  if (window.BroadcastChannel) {
    const NativeChannel = window.BroadcastChannel;
    window.BroadcastChannel = class EmbeddedChannel extends NativeChannel {
      constructor(name) {
        super(name === "session-converter-workspace" ? storagePrefix + "workspace" : name);
      }
    };
  }
  function scopedStorage(storage) {
    const keys = () => Array.from({length: storage.length}, (_, index) => storage.key(index))
      .filter(key => key?.startsWith(storagePrefix));
    return new Proxy(storage, {
      get(target, property) {
        if (property === "getItem") return key => target.getItem(storagePrefix + key);
        if (property === "setItem") return (key, value) => target.setItem(storagePrefix + key, value);
        if (property === "removeItem") return key => target.removeItem(storagePrefix + key);
        if (property === "clear") return () => keys().forEach(key => target.removeItem(key));
        if (property === "key") return index => keys()[index]?.slice(storagePrefix.length) ?? null;
        if (property === "length") return keys().length;
        if (typeof property === "symbol") return Reflect.get(target, property, target);
        return target.getItem(storagePrefix + property) ?? undefined;
      },
      set(target, key, value) { target.setItem(storagePrefix + key, value); return true; },
      deleteProperty(target, key) { target.removeItem(storagePrefix + key); return true; },
      ownKeys() { return keys().map(key => key.slice(storagePrefix.length)); },
      getOwnPropertyDescriptor() { return {enumerable: true, configurable: true}; },
    });
  }
  for (const name of ["localStorage", "sessionStorage"]) {
    try {
      const storage = scopedStorage(window[name]);
      Object.defineProperty(window, name, {configurable: true, get: () => storage});
    } catch { /* IndexedDB still provides the Bridge's existing encrypted persistence. */ }
  }

  function syncTheme(theme) {
    const value = theme || (window.parent !== window ? window.parent.document.documentElement.dataset.theme : "dark");
    document.documentElement.dataset.theme = value === "light" ? "light" : "dark";
  }
  try {
    syncTheme();
    if (window.parent !== window) new MutationObserver(() => syncTheme())
      .observe(window.parent.document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
  } catch { document.documentElement.dataset.theme = "dark"; }

  const credentialFields = new Set(["email", "name", "id", "type", "version", "platform", "provider",
    "access_token", "accessToken", "refresh_token", "refreshToken", "id_token", "idToken", "session_token", "sessionToken",
    "account_id", "accountId", "workspace_id", "workspaceId", "chatgpt_account_id", "chatgptAccountId",
    "user_id", "chatgpt_user_id", "chatgptUserId", "client_id", "clientId", "expires", "expires_at", "expiresAt",
    "planType", "plan_type", "id_token_synthetic", "token_type"]);
  const credentialContainers = new Set(["user", "account", "credentials", "tokens", "providerSpecificData", "extra", "meta"]);
  function credentialOnly(value) {
    const result = {};
    for (const [key, item] of Object.entries(value || {})) {
      if (credentialFields.has(key) && ["string", "number", "boolean"].includes(typeof item)) result[key] = item;
      if (credentialContainers.has(key) && item && typeof item === "object" && !Array.isArray(item)) result[key] = credentialOnly(item);
    }
    return result;
  }
  function sessionRecords(value) {
    if (Array.isArray(value)) return value.flatMap(sessionRecords);
    if (!value || typeof value !== "object") return [];
    for (const field of ["accounts", "items", "data"]) {
      if (Array.isArray(value[field])) return value[field].flatMap(sessionRecords);
    }
    return [credentialOnly(value)];
  }
  function tokenField(record, names) {
    for (const value of [record, record.credentials, record.tokens, record.providerSpecificData]) {
      for (const name of names) if (typeof value?.[name] === "string" && value[name].trim()) return value[name].trim();
    }
    return "";
  }
  function credentialIdentity(record) {
    try {
      const sources = [record, record.credentials, record.tokens, record.providerSpecificData].filter(Boolean);
      for (const aliases of [["access_token", "accessToken"], ["refresh_token", "refreshToken"],
        ["session_token", "sessionToken"], ["id_token", "idToken"]]) {
        const values = sources.flatMap(source => aliases.map(name => source[name])).filter(value => value != null && value !== "");
        if (values.some(value => typeof value !== "string") || new Set(values.map(value => value.trim())).size > 1) return null;
      }
      const access = tokenField(record, ["access_token", "accessToken"]);
      const encoded = access.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(encoded), char => char.charCodeAt(0))));
      const auth = claims["https://api.openai.com/auth"] || {};
      const email = String(claims["https://api.openai.com/profile"]?.email || claims.email || "").trim().toLowerCase();
      const workspace = auth.chatgpt_account_id || auth.account_id;
      const user = auth.chatgpt_user_id || auth.user_id;
      if (!email || !workspace || !user) return null;
      for (const value of [...sources, record.extra, record.meta, record.account]) {
        if (!value) continue;
        for (const name of ["email", "chatgpt_email"]) if (value[name] && String(value[name]).trim().toLowerCase() !== email) return null;
        for (const name of ["account_id", "accountId", "workspace_id", "workspaceId", "chatgpt_account_id", "chatgptAccountId"]) {
          if (value[name] && String(value[name]) !== workspace) return null;
        }
        for (const name of ["user_id", "chatgpt_user_id", "chatgptUserId"]) if (value[name] && String(value[name]) !== user) return null;
      }
      if (record.user?.email && record.user.email.toLowerCase() !== email ||
          record.user?.id && record.user.id !== user || record.account?.id && record.account.id !== workspace) return null;
      return {key: JSON.stringify([email, workspace, user]), issued: Number(claims.iat || 0)};
    } catch { return null; }
  }
  function mergeSessions(records) {
    const result = [], indexes = new Map();
    for (const record of records) {
      const identity = credentialIdentity(record);
      if (!identity || !indexes.has(identity.key)) {
        if (identity) indexes.set(identity.key, result.length);
        result.push(record);
        continue;
      }
      const index = indexes.get(identity.key), existing = result[index];
      const existingRefresh = tokenField(existing, ["refresh_token", "refreshToken"]);
      const incomingRefresh = tokenField(record, ["refresh_token", "refreshToken"]);
      const preferIncoming = Boolean(incomingRefresh) && !existingRefresh ||
        Boolean(incomingRefresh) === Boolean(existingRefresh) && identity.issued > credentialIdentity(existing).issued;
      const preferred = preferIncoming ? record : existing, secondary = preferIncoming ? existing : record;
      const session = tokenField(preferred, ["session_token", "sessionToken"]) || tokenField(secondary, ["session_token", "sessionToken"]);
      result[index] = {...preferred};
      if (session && !tokenField(preferred, ["session_token", "sessionToken"])) result[index].session_token = session;
    }
    return result;
  }
  function parseDocuments(text) {
    const documents = [];
    let start = -1, depth = 0, quoted = false, escaped = false;
    for (let index = 0; index < text.length; index++) {
      const char = text[index];
      if (start === -1) {
        if (/\s/.test(char)) continue;
        if (char !== "{" && char !== "[") throw new Error("invalid_document");
        start = index;
      }
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') quoted = true;
      else if (char === "{" || char === "[") depth++;
      else if (char === "}" || char === "]") {
        depth--;
        if (!depth) { documents.push(JSON.parse(text.slice(start, index + 1))); start = -1; }
      }
    }
    if (start !== -1 || depth || quoted) throw new Error("invalid_document");
    return documents;
  }
  function backupsFrom(accounts) {
    return accounts.flatMap(account => {
      const pending = account.totp_reset_pending;
      const confirmed = !pending && account.status === "已换绑2FA";
      const secret = confirmed ? account.two_factor_secret : pending?.secret;
      if (typeof account.email !== "string" || typeof secret !== "string" || !/^[A-Z2-7]{16,256}=*$/i.test(secret)) return [];
      const phase = confirmed ? "confirmed" : pending.phase;
      return [{email: account.email, secret, phase,
        verification: confirmed ? "official_confirmed" : phase === "activated" ? "official_activated" : "candidate_unverified"}];
    });
  }
  async function snapshot(expectedInput) {
    await ready;
    // Input changes are saved by the original UI's 250 ms debounce.
    await new Promise(resolve => setTimeout(resolve, 300));
    for (let attempt = 0; attempt < 20; attempt++) {
      await lastWrite;
      if (window.browserWorkspace.signal?.aborted) throw new Error("workspace_unavailable");
      const value = await window.browserWorkspace.read() || {};
      if (expectedInput === undefined || value.state?.conversionInput?.text === expectedInput) return value;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    throw new Error("workspace_save_incomplete");
  }
  async function exchange(message) {
    const id = message.requestId;
    if (typeof id !== "string" || !/^[A-Za-z0-9_.:-]{1,100}$/.test(id)) return;
    try {
      await ready;
      if (message.type === "import-sessions") {
        if (!Array.isArray(message.accounts) || message.accounts.length > 2000) throw new Error("invalid_accounts");
        const input = document.querySelector("#session-input");
        if (document.querySelector("#start-protocol-login")?.disabled ||
            document.querySelector("#reset-login-totp")?.disabled ||
            document.querySelector('[data-evaluation-stop]:not(:disabled)') || window.browserWorkspace.signal?.aborted) {
          throw new Error("workspace_busy");
        }
        const accounts = message.accounts.map(credentialOnly);
        const serialized = accounts.map(account => JSON.stringify(account)).join("\n");
        if (serialized.length > 8 * 1024 * 1024) throw new Error("accounts_too_large");
        input.value = [input.value.trim(), serialized].filter(Boolean).join("\n");
        input.dispatchEvent(new Event("input", {bubbles: true}));
        await snapshot(input.value);
        post("imported", {requestId: id, count: accounts.length});
      } else if (message.type === "export-sessions" || message.type === "export-backups") {
        const saved = await snapshot();
        const browserAccounts = saved.state?.browserAccounts || [];
        const backups = backupsFrom(browserAccounts);
        if (message.type === "export-backups") { post("backups", {requestId: id, backups}); return; }
        const {projectLoginAccounts} = await import("/auth-bridge/account-workspace.js");
        const input = saved.state?.conversionInput?.text || "";
        const accounts = [
          ...parseDocuments(input).flatMap(sessionRecords),
          ...projectLoginAccounts(browserAccounts).map(source => credentialOnly(source.value)),
        ];
        for (const account of browserAccounts) {
          let session;
          try { session = typeof account.session_json === "string" ? JSON.parse(account.session_json) : account.session_json; }
          catch { continue; }
          if (session?.sessionToken && (session.accessToken || account.session_access_token)) {
            accounts.push(credentialOnly({...session, email: account.email, accessToken: session.accessToken || account.session_access_token}));
          }
        }
        post("sessions", {requestId: id, accounts: mergeSessions(accounts), backups});
      }
    } catch {
      post("error", {requestId: id, message: "授权工具暂时无法交换数据，请结束当前操作并核对浏览器保存状态后重试。"});
    }
  }
  window.addEventListener("team48:authorization-complete", async event => {
    if (!autoSave || window.parent === window) return;
    const id = event.detail?.id;
    if (typeof id !== "string" || !id) return;
    try {
      const saved = await snapshot();
      if (!autoSave || window.browserWorkspace.signal?.aborted) return;
      const account = (saved.state?.browserAccounts || []).find(item => String(item.id) === id);
      if (!account) return;
      const {projectLoginAccounts} = await import("/auth-bridge/account-workspace.js");
      const records = projectLoginAccounts([account]).map(source => credentialOnly(source.value));
      let session;
      try { session = typeof account.session_json === "string" ? JSON.parse(account.session_json) : account.session_json; }
      catch { session = null; }
      if (session?.accessToken || account.session_access_token) {
        records.push(credentialOnly({...session, email: account.email, accessToken: session?.accessToken || account.session_access_token}));
      }
      if (records.length) post("authorization-complete", {accounts: mergeSessions(records)});
    } catch {
      post("auto-save-error", {message: "授权已完成，但无法读取本次结果，请使用手动保存。"});
    }
  });
  window.addEventListener("message", event => {
    if (event.source !== window.parent || event.origin !== origin || event.data?.channel !== channel) return;
    const message = event.data;
    if (message.type === "auto-save") { autoSave = message.enabled === true; return; }
    if (message.type === "theme") { syncTheme(message.theme); return; }
    if (message.type === "select-tool") {
      ready.then(() => {
        const button = [...document.querySelectorAll("[data-format]")].find(node => node.dataset.format === message.tool);
        button?.click();
      });
      return;
    }
    void exchange(message);
  });
  document.addEventListener("click", event => {
    if (event.target.closest?.("[data-format], [data-account-destination]")) queueMicrotask(() => post("tool-changed", {tool: currentTool()}));
  });
})();
