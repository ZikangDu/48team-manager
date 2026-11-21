(() => {
  "use strict";
  const frame = document.getElementById("bridge-frame");
  if (!frame) return;
  const byId = id => document.getElementById(id);
  const channel = "team48-auth-bridge";
  const pending = new Map();
  const dialog = byId("bridge-exchange");
  const form = byId("bridge-exchange-form");
  const items = byId("bridge-exchange-items");
  const confirm = byId("bridge-exchange-confirm");
  const submit = byId("bridge-exchange-submit");
  const waiting = byId("bridge-loading");
  const unavailable = byId("bridge-unavailable");
  const autoSave = byId("bridge-auto-save");
  const autoStatus = byId("bridge-auto-save-status");
  const autoRetry = byId("bridge-auto-save-retry");
  let autoQueue = Promise.resolve(), failedAutoSave = [], pageClosed = false, retrying = 0;
  const autoWarnings = new Map(), autoSaved = new Set();
  const followupTimers = new Map(), followupProgress = new Map();
  try { autoSave.checked = localStorage.getItem("team48.bridge.auto-save") !== "false"; } catch (_) {}
  function autoFeedback(text, tone = "") {
    autoStatus.textContent = text; autoStatus.dataset.tone = tone; autoStatus.hidden = !text;
  }
  function showAutoSummary() {
    const pending = failedAutoSave.length;
    autoFeedback([autoSaved.size ? "本页已保存 " + autoSaved.size + " 个账号的授权到 Team48。" : "",
      ...autoWarnings.values(),
      ...followupProgress.values(),
      pending ? "另有 " + pending + " 批授权尚未保存：" + failedAutoSave.at(-1).message + " 授权仍在工作台中，可重试或手动保存。" : "",
      retrying ? "正在重试 " + retrying + " 批授权…" : ""].filter(Boolean).join(" "), pending || autoWarnings.size ? "danger" : "");
    autoRetry.hidden = pending === 0;
    autoRetry.disabled = !autoSave.checked || retrying > 0;
  }
  function watchFollowup(accountId, email, attempt = 0) {
    if (!Number.isInteger(accountId) || pageClosed) return;
    clearTimeout(followupTimers.get(accountId));
    const timer = setTimeout(async () => {
      try {
        const status = await request("/api/bridge-workbench/authorizations/" + accountId + "/status", undefined, "GET");
        if (pageClosed) return;
        followupProgress.set(accountId, email + "：" + status.message + "。");
        showAutoSummary();
        if (!status.done && attempt < 120) watchFollowup(accountId, email, attempt + 1);
        else if (!status.done) {
          followupProgress.set(accountId, email + "：后台仍在处理，可在任务记录查看进度。");
          showAutoSummary();
        }
      } catch (error) {
        if (pageClosed) return;
        followupProgress.set(accountId, email + "：进度暂不可读，后台任务仍会继续。" + error.message);
        showAutoSummary();
        if (attempt < 5) watchFollowup(accountId, email, attempt + 1);
      }
    }, attempt ? 2000 : 300);
    followupTimers.set(accountId, timer);
  }
  function queueAutoSave(accounts, retry = false) {
    autoQueue = autoQueue.then(async () => {
      if (pageClosed || !autoSave.checked) { if (retry) retrying--; return; }
      autoFeedback("正在自动保存本次授权到 Team48…");
      try {
        const result = await request("/api/bridge-workbench/authorizations/auto-save", {accounts});
        if (pageClosed) return;
        const saved = (result.results || []).filter(item => item.status === "saved" || item.status === "unchanged");
        for (const item of result.results || []) {
          const key = item.email || item.code;
          if (item.status === "blocked") autoWarnings.set(key, (item.email ? item.email + "：" : "") + item.message);
          else { autoWarnings.delete(key); autoSaved.add(item.email); }
          if (item.followup?.operation_id && Number.isInteger(item.account_id)) watchFollowup(item.account_id, item.email);
          else if (item.followup?.message) autoWarnings.set(key, item.email + "：" + item.followup.message);
        }
        if (saved.length) window.dispatchEvent(new CustomEvent("team48:accounts-updated"));
      } catch (error) {
        if (!pageClosed) {
          // Retain only in memory for an explicit retry; never write credentials
          // to localStorage, logs, or the parent page's markup.
          failedAutoSave.push({accounts, message: error.message});
        }
      } finally {
        if (retry) retrying--;
        if (!pageClosed) showAutoSummary();
      }
    });
  }
  autoSave.addEventListener("change", () => {
    try { localStorage.setItem("team48.bridge.auto-save", String(autoSave.checked)); } catch (_) {}
    send("auto-save", {enabled: autoSave.checked});
    autoRetry.disabled = !autoSave.checked || retrying > 0;
  });
  autoRetry.addEventListener("click", () => {
    if (!autoSave.checked) return;
    const retry = failedAutoSave; failedAutoSave = []; retrying += retry.length; autoRetry.hidden = true;
    for (const item of retry) queueAutoSave(item.accounts, true);
  });
  let dialogMode = "", draft = null, backups = [], saving = false, ready = false;
  let exchangeGeneration = 0, preparing = false, closing = false;
  let loadTimeout;
  const node = (tag, text, className) => {
    const result = document.createElement(tag);
    if (text != null) result.textContent = text;
    if (className) result.className = className;
    return result;
  };
  function feedback(text, tone = "") {
    const box = byId("bridge-feedback");
    box.textContent = text;
    box.dataset.tone = tone;
    box.hidden = !text;
  }
  function errorText(text) {
    byId("bridge-exchange-error").textContent = text;
    byId("bridge-exchange-error").hidden = !text;
  }
  async function request(url, body, method = "POST") {
    let response;
    try {
      response = await fetch(url, {method, credentials: "same-origin", cache: "no-store",
        headers: {"Content-Type": "application/json"}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
    } catch (_) { throw new Error("连接中断，请先核对保存结果后再重试。"); }
    const data = await response.json().catch(() => ({}));
    if (!response.ok || data.ok === false) throw new Error(response.status === 401 ? "后台登录已过期，请重新登录。" :
      data.detail?.message || data.message || "操作未完成，请核对账号和任务记录。");
    return data;
  }
  function send(type, data = {}) {
    frame.contentWindow?.postMessage({channel, type, ...data}, location.origin);
  }
  function fromFrame(type, data = {}) {
    const requestId = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { pending.delete(requestId); reject(new Error("工作台响应超时，请稍后重试。")); }, 15000);
      pending.set(requestId, {resolve, reject, timer});
      send(type, {...data, requestId});
    });
  }
  const theme = () => send("theme", {theme: document.documentElement.dataset.theme});
  function desiredTool() {
    const tool = new URL(location.href).searchParams.get("tool");
    return ({health: "sub2api", workspaces: "protocol-login"})[tool] || tool || "protocol-login";
  }
  function showConnectionError() {
    clearTimeout(loadTimeout);
    ready = false;
    waiting.hidden = true;
    unavailable.hidden = false;
    byId("bridge-import").disabled = byId("bridge-save").disabled = true;
    byId("bridge-kernel-status").textContent = "授权内核暂不可用";
  }
  window.addEventListener("message", event => {
    if (event.origin !== location.origin || event.source !== frame.contentWindow || event.data?.channel !== channel) return;
    const message = event.data;
    if (message.type === "ready") {
      clearTimeout(loadTimeout);
      ready = true;
      waiting.hidden = unavailable.hidden = true;
      frame.hidden = false;
      byId("bridge-import").disabled = byId("bridge-save").disabled = false;
      byId("bridge-kernel-status").textContent = "内嵌授权内核已连接";
      theme();
      send("auto-save", {enabled: autoSave.checked});
      send("select-tool", {tool: desiredTool()});
    }
    if (message.type === "height" && Number.isFinite(message.height)) frame.style.height = Math.max(400, Math.min(message.height, 50000)) + "px";
    if (message.type === "authorization-complete" && autoSave.checked && Array.isArray(message.accounts)
        && message.accounts.length > 0 && message.accounts.length <= 50) queueAutoSave(message.accounts);
    if (message.type === "auto-save-error") autoFeedback("本次授权无法自动读取，请使用「保存结果到 Team48」。", "danger");
    if (message.type === "tool-changed" && typeof message.tool === "string") {
      const url = new URL(location.href);
      url.searchParams.set("tool", message.tool);
      history.replaceState(null, "", url);
    }
    const receiver = pending.get(message.requestId);
    if (!receiver) return;
    clearTimeout(receiver.timer);
    pending.delete(message.requestId);
    if (message.type === "error") receiver.reject(new Error(message.message || "工作台未能完成交换。"));
    else receiver.resolve(message);
  });
  frame.addEventListener("load", () => {
    try {
      if (!frame.contentDocument?.querySelector("#format-toolbar")) showConnectionError();
    } catch (_) { showConnectionError(); }
  });
  byId("bridge-reconnect").addEventListener("click", () => {
    unavailable.hidden = true;
    waiting.hidden = false;
    frame.src = "/auth-bridge/";
    loadTimeout = setTimeout(showConnectionError, 25000);
  });
  loadTimeout = setTimeout(showConnectionError, 25000);
  new MutationObserver(theme).observe(document.documentElement, {attributes: true, attributeFilter: ["data-theme"]});
  window.addEventListener("popstate", () => { if (ready) send("select-tool", {tool: desiredTool()}); });

  function selection() { return [...items.querySelectorAll("input:checked:not(:disabled)")]; }
  function sync() {
    const count = selection().length;
    byId("bridge-exchange-count").textContent = count ? "已选 " + count + " 项" : "请选择要处理的账号或密钥备份";
    submit.disabled = saving || closing || !confirm.checked || !count;
    byId("bridge-exchange-close").disabled = saving || closing;
    byId("bridge-import").disabled = byId("bridge-save").disabled = !ready || preparing || dialog.open;
  }
  function openDialog(mode, title, note) {
    exchangeGeneration++;
    dialogMode = mode;
    byId("bridge-exchange-title").textContent = title;
    byId("bridge-exchange-note").textContent = note;
    confirm.checked = false;
    errorText("");
    items.replaceChildren();
    submit.textContent = mode === "import" ? "导入到工作台" : "保存所选结果";
    dialog.showModal();
    sync();
  }
  function choice(type, value, email, title, details, enabled = true) {
    const label = node("label"), input = document.createElement("input");
    input.type = type;
    input.value = value;
    input.dataset.email = email;
    input.disabled = !enabled;
    input.dataset.unavailable = String(!enabled);
    const text = node("span", title);
    if (details) text.append(node("small", details));
    label.append(input, text);
    input.addEventListener("change", () => {
      if (dialogMode === "save" && input.checked && input.dataset.kind === "credential") {
        for (const other of items.querySelectorAll('input[data-kind="credential"]')) {
          if (other !== input && other.dataset.email === email) other.checked = false;
        }
      }
      confirm.checked = false;
      sync();
    });
    items.append(label);
    return input;
  }
  async function discardDraft() {
    if (!draft) return;
    const id = draft.draft_id;
    await request("/api/credential-import/preview/" + encodeURIComponent(id), undefined, "DELETE");
    if (draft?.draft_id === id) draft = null;
  }
  async function closeDialog() {
    if (saving || closing) return;
    closing = true;
    sync();
    try { await discardDraft(); }
    catch (_) { draft = null; feedback("窗口已关闭，未提交的预览会在 15 分钟后过期。"); }
    backups = [];
    exchangeGeneration++;
    dialog.close();
    items.replaceChildren();
    closing = false;
    sync();
  }
  byId("bridge-exchange-close").addEventListener("click", closeDialog);
  dialog.addEventListener("cancel", event => { event.preventDefault(); void closeDialog(); });
  confirm.addEventListener("change", sync);
  byId("bridge-import").addEventListener("click", async () => {
    if (!ready || dialog.open) return;
    openDialog("import", "选择 Team48 账号", "所选授权将复制到此浏览器的加密工作台中，可用于测活、评测和格式转换。");
    const generation = exchangeGeneration;
    try {
      const data = await request("/api/bridge-workbench/accounts", undefined, "GET");
      if (!dialog.open || exchangeGeneration !== generation) return;
      if (!data.accounts.length) items.append(node("p", "尚未登记账号。可在账号页导入授权，或直接在下方协议登录。", "hint"));
      for (const account of data.accounts) {
        const input = choice("checkbox", account.id, account.email, account.email,
          account.has_access_token ? account.plan : "此账号缺少已保存的授权", account.has_access_token);
        input.dataset.kind = "account";
      }
      sync();
    } catch (error) { if (dialog.open && exchangeGeneration === generation) errorText(error.message); }
  });
  byId("bridge-save").addEventListener("click", async () => {
    if (!ready || dialog.open || preparing) return;
    preparing = true;
    sync();
    feedback("正在读取工作台结果…");
    try {
      const message = await fromFrame("export-sessions");
      openDialog("save", "保存工作台结果", "每个邮箱选择一组授权保存到 Team48；其余空间授权继续保存在工作台。已确认的 2FA 可另选加密备份。");
      const generation = exchangeGeneration;
      backups = (message.backups || []).filter(item => item.phase === "confirmed" && item.email && item.secret);
      if (message.accounts?.length) {
        const preview = await request("/api/credential-import/preview", {content: {accounts: message.accounts}});
        message.accounts = null;
        if (!dialog.open || exchangeGeneration !== generation) {
          if (preview.draft_id) await request("/api/credential-import/preview/" + encodeURIComponent(preview.draft_id), undefined, "DELETE");
          return;
        }
        draft = preview;
        const groups = new Map();
        for (const candidate of draft.candidates || []) {
          const input = choice("checkbox", candidate.id, candidate.email, candidate.email,
            [candidate.workspace_name || candidate.plan || "工作区授权", candidate.workspace_id,
              candidate.error?.message, ...(candidate.warnings || []).map(warning => warning.message || String(warning))]
              .filter(Boolean).join(" · "), candidate.allowed === true);
          input.dataset.kind = "credential";
          if (!groups.has(candidate.email)) groups.set(candidate.email, []);
          if (candidate.allowed) groups.get(candidate.email).push(input);
        }
        for (const group of groups.values()) if (group.length === 1) group[0].checked = true;
        for (const error of draft.errors || []) items.append(node("p", error.message || "有一项授权无法解析，请核对邮箱和工作区。", "hint"));
        if (!draft.draft_id) draft = null;
      }
      for (const [index, backup] of backups.entries()) {
        const input = choice("checkbox", index, backup.email, backup.email + " · 新 2FA 密钥",
          "将工作台已确认的密钥保存为用户核对备份");
        input.dataset.kind = "backup";
      }
      const pendingKeys = (message.backups || []).filter(item => item.phase !== "confirmed").length;
      message.backups = null;
      if (pendingKeys) items.append(node("p", "另有 " + pendingKeys + " 项换绑待核对，请在协议登录中的恢复入口继续，保留候选密钥备份。", "hint"));
      if (!items.childElementCount) items.append(node("p", "工作台暂无可保存的授权或已确认密钥。", "hint"));
      sync();
      feedback("");
    } catch (error) { if (dialog.open) errorText(error.message); else feedback(error.message, "danger"); }
    finally { preparing = false; sync(); }
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (submit.disabled || saving) return;
    const selected = selection();
    saving = true;
    form.querySelectorAll("input").forEach(input => { input.disabled = true; });
    sync();
    errorText("");
    try {
      if (dialogMode === "import") {
        const data = await request("/api/bridge-workbench/accounts/export", {account_ids: selected.map(input => Number(input.value)), confirm: true});
        await fromFrame("import-sessions", {accounts: data.accounts});
        data.accounts = null;
        feedback("已将所选账号的授权导入工作台。");
      } else {
        const credentials = selected.filter(input => input.dataset.kind === "credential");
        if (credentials.length && !draft) throw new Error("授权预览已结束，请重新打开保存窗口。");
        if (credentials.length && draft) {
          const result = await request("/api/credential-import/commit", {draft_id: draft.draft_id,
            selected_ids: credentials.map(input => input.value), verify_quota: false});
          draft = null;
          for (const input of items.querySelectorAll('input[data-kind="credential"]')) input.dataset.unavailable = "true";
          for (const input of credentials) {
            input.checked = false; input.dataset.saved = "true";
            input.closest("label").append(node("small", "已保存"));
          }
          feedback("已保存 " + (result.imported?.length ?? credentials.length) + " 个账号的授权。");
          for (const item of result.imported || []) {
            if ((result.followups || []).some(task => task.account_id === item.account_id && task.operation_id)) watchFollowup(item.account_id, item.email);
          }
        }
        for (const input of selected.filter(input => input.dataset.kind === "backup")) {
          const backup = backups[Number(input.value)];
          await request("/api/assisted-login/totp-backup", {email: backup.email, secret: backup.secret, confirmed: true});
          backup.secret = "";
          input.checked = false;
          input.dataset.saved = "true";
          input.closest("label").append(node("small", "密钥已加密备份"));
        }
        if (!credentials.length) feedback("所选密钥已加密备份到 Team48。");
      }
      await discardDraft();
      backups = [];
      dialog.close();
      items.replaceChildren();
    } catch (error) { errorText(error.message); }
    finally {
      saving = false;
      form.querySelectorAll("input").forEach(input => { input.disabled = input.dataset.saved === "true" || input.dataset.unavailable === "true"; });
      confirm.checked = false;
      sync();
    }
  });
  window.addEventListener("pagehide", () => {
    pageClosed = true; failedAutoSave = [];
    for (const timer of followupTimers.values()) clearTimeout(timer);
    followupTimers.clear();
    exchangeGeneration++;
    backups = [];
    dialog.close();
    items.replaceChildren();
    if (draft?.draft_id) {
      void fetch("/api/credential-import/preview/" + encodeURIComponent(draft.draft_id),
        {method: "DELETE", credentials: "same-origin", keepalive: true, cache: "no-store"}).catch(() => {});
      draft = null;
    }
    for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error("页面已关闭。")); }
    pending.clear();
  });
})();
