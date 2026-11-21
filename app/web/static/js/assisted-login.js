(() => {
  "use strict";
  const sheet = document.getElementById("assisted-login-sheet");
  if (!sheet) return;
  const body = document.getElementById("assisted-login-body");
  const opener = document.getElementById("assisted-login-open");
  const errorBox = document.getElementById("assisted-login-error");
  const tabs = document.getElementById("assisted-login-tabs");
  const TERMINAL = new Set(["success", "partial", "failed", "cancelled", "manual_required", "resolved"]);
  const ORDER = ["oauth", "reset_totp", "security", "logout_all"];
  const ACTIONS = {
    oauth: {name: "授权登录", hint: "登录后把 OAuth 授权保存到 Team48", submit: "打开浏览器并授权"},
    reset_totp: {name: "重设 2FA", hint: "自动换绑：停用旧验证器，生成并激活新密钥，加密保存到本机", submit: "登录并重设 2FA"},
    security: {name: "官方安全设置", hint: "登录后打开官方安全设置，由你手动操作", submit: "登录并打开安全设置"},
    logout_all: {name: "退出全部会话", hint: "登录后打开官方安全设置，由你确认退出", submit: "登录并打开安全设置"},
  };
  // The real order of work; a task view marks where it is.
  const LOGIN = [["open", "打开官方窗口"], ["login", "登录账号"]];
  const FLOWS = {
    oauth: [...LOGIN, ["callback", "核对授权回调"], ["saved", "保存授权"]],
    reset_totp: [...LOGIN, ["session", "读取账号会话"], ["status", "读取 2FA 状态"], ["disable", "停用旧 2FA"],
      ["enroll", "生成新密钥"], ["activate", "激活新密钥"], ["confirm", "核对生效"]],
    security: [...LOGIN, ["handoff", "在官方安全设置中操作"]],
    logout_all: [...LOGIN, ["handoff", "在官方页面退出会话"]],
  };
  const STEP_OF = {
    starting: "open", queued: "open", browser_open: "open",
    email: "login", password: "login", totp: "login", challenge: "login", email_verification: "login",
    phone_verification: "login", account_change: "login", consent: "login", untrusted_origin: "login",
    ambiguous_otp: "login", manual_required: "login", rate_limited: "login", account_unavailable: "login",
    credentials_rejected: "login", exchanging: "callback", callback: "callback", awaiting_user: "handoff", authenticated_reset: "session",
    mfa_session: "session", mfa_status: "status", mfa_disable: "disable", mfa_enroll: "enroll",
    mfa_activate: "activate", mfa_confirm: "confirm",
  };
  // Stages that wait for the person at the Chrome window.
  const NEEDS_YOU = new Set(["challenge", "email_verification", "phone_verification", "account_change", "consent",
    "untrusted_origin", "ambiguous_otp", "manual_required", "awaiting_user", "rate_limited", "account_unavailable",
    "credentials_rejected"]);
  const STAGES = {
    challenge: "官方要求人机验证，请在 Chrome 窗口亲自完成", email_verification: "官方要求邮箱验证码，请在 Chrome 窗口输入",
    phone_verification: "官方要求手机验证，请在 Chrome 窗口完成", account_change: "页面进入注册或账号恢复，已停止自动填写",
    consent: "请在 Chrome 窗口核对并确认授权", untrusted_origin: "页面离开了官方来源，已停止自动填写",
    ambiguous_otp: "验证码类型不明确，请在 Chrome 窗口核对", rate_limited: "官方提示操作频繁，已停止自动提交",
    account_unavailable: "官方提示账号不可用，请在官方页面核对", credentials_rejected: "官方没有接受登录资料，请在 Chrome 窗口核对",
    manual_required: "需要你在 Chrome 窗口继续", awaiting_user: "请在 Chrome 窗口完成操作（安全设置未自动打开时请手动打开）",
    starting: "正在打开 Chrome 窗口", queued: "正在打开 Chrome 窗口", browser_open: "正在打开官方登录页",
    email: "正在填写邮箱", password: "正在填写密码", totp: "正在填写验证码", exchanging: "正在核对授权回调并保存",
    callback: "正在核对授权回调并保存", authenticated: "已登录官方页面", authenticated_reset: "已登录，准备换绑 2FA", mfa_session: "已登录，正在读取账号会话",
    mfa_status: "正在读取官方 2FA 状态", mfa_disable: "正在停用旧 2FA", mfa_enroll: "正在生成新密钥",
    mfa_activate: "新密钥已加密保存，正在激活", mfa_confirm: "正在核对新 2FA 是否生效",
  };
  const ERRORS = {
    browser_input_invalid: "浏览器参数或固定代理不受支持，请核对后重试。",
    browser_failed: "浏览器没能完成操作，请确认本机 Chrome 和网络可用。",
    browser_timeout: "等待超时，窗口已关闭。请重新发起。",
    browser_closed: "Chrome 窗口被关闭，任务结束。",
    browser_login_incomplete: "没有登录到官方页面，请核对后重新发起。",
    credentials_rejected: "官方没有接受密码或验证码。",
    rate_limited: "官方提示操作频繁，请稍后再试。",
    account_unavailable: "官方提示账号不可用，请人工核对。",
    authorization_not_saved: "授权没有保存，请核对身份、工作区和任务记录。",
    official_review_required: "请在官方安全页面核对结果；本机没有确认远端变更。",
    logout_scope_unverified: "窗口已回到登录页；其他设备是否退出请在官方页面核对。",
    interrupted: "服务重启或任务中断，没有自动重放登录。请重新发起。",
    cancelled: "已停止本次任务。", timeout: "等待超时，请重新发起。",
    invalid_input: "请检查邮箱、密码和 2FA 密钥的格式。", email_invalid: "请输入有效邮箱。",
    totp_invalid: "2FA 密钥格式不对：要填验证器的完整密钥，不是六位验证码。",
    invalid_totp: "2FA 密钥格式不对：要填验证器的完整密钥，不是六位验证码。",
    password_invalid: "请输入有效密码。", password_required: "请输入账号密码；本机没有保存这个账号的密码。",
    action_invalid: "不支持这个操作。", proxy_invalid: "账号的代理配置无效，请先核对。",
    browser_busy: "已有浏览器任务在进行，请先完成或停止。", account_busy: "这个账号有未完成的任务或授权。",
    oauth_busy: "这个账号有未结束的授权，请先完成或取消。", account_disabled: "账号已停用或归档，请先核对。",
    remote_refresh_owned: "这个账号的刷新由远端托管，请先完成刷新权交接。",
    runner_unavailable: "后台任务服务还没就绪，请稍后重试。", start_failed: "任务没能启动，请刷新后重试。",
    origin_mismatch: "请从当前后台页面提交。", not_found: "任务不存在，请查看任务记录。",
    oauth_exchange_failed: "官方授权换票没有完成，请重新发起。",
    confirmation_required: "请先勾选确认。", reset_confirmation_required: "请先勾选确认要更换此账号的 2FA。",
    backup_not_found: "这个邮箱没有保存密钥。", backup_failed: "密钥没有保存成功，请保留密钥后重试。",
    backup_unreadable: "已保存的密钥无法读取，请核对本机加密配置。",
    reset_pending: "这个邮箱有未完成的换绑记录，请先完成核对或放弃该记录。",
    reset_unreadable: "换绑记录无法读取，没有做任何更改；请核对本机加密配置。",
    reset_not_open: "没有待处理的换绑记录，请重新查询。",
    export_required: "激活结果未知时候选密钥可能已经生效，请先导出候选密钥再放弃记录。",
    candidate_not_found: "这个邮箱没有待核对的候选密钥。", candidate_export_failed: "候选密钥没能导出，请重新查询后再试。",
    bridge_disabled: "授权桥已停用，请检查 Team48 设置。", bridge_starting: "授权桥正在启动，请稍后重新检查。",
    bridge_unavailable: "当前无法连接内嵌授权桥，请检查 Team48 服务状态。", bridge_incompatible: "授权桥版本不兼容，请检查 Team48 服务状态。",
    bridge_busy: "授权桥繁忙，请稍后再试。", bridge_timeout: "授权桥响应超时，请先核对任务记录。",
    bridge_credentials_rejected: "登录资料未通过验证，请核对密码和 2FA。", bridge_email_verification: "需要邮箱验证，请在浏览器中人工完成。",
    bridge_account_unavailable: "账号不可用，请人工核对。", bridge_validation_failed: "官方验证未完成，请在浏览器中核对。",
    bridge_identity_mismatch: "账号身份不符，授权未保存。", bridge_login_failed: "未取得可用授权。",
    totp_required: "请输入此账号的现有 2FA 密钥。", input_empty: "请至少输入一个账号。", too_many: "每次最多可提交 50 个账号。",
    line_duplicate: "输入中有重复账号，请每个邮箱只保留一行。", line_invalid: "账号行格式有误，请检查邮箱、分隔符和 2FA 密钥。",
    reset_save_failed: "记录没能关闭，请重新查询。",
  };
  const VERIFICATION = {
    user_reported: "用户确认，未经官方验证", official_activated: "官方已激活，状态待核对",
    official_confirmed: "官方已激活并核对生效", candidate_unverified: "候选密钥，尚未确认生效",
  };
  const PHASES = {
    none: "没有换绑记录", preparing: "已开始，尚未取得新密钥", prepared: "新密钥待激活", activating: "激活结果未知",
    activated: "已激活，待核对", confirmed: "最近一次换绑已核对生效", abandoned: "最近一次换绑记录已放弃",
  };
  const OPEN_PHASES = new Set(["preparing", "prepared", "activating", "activated"]);
  const KEY_BUSY = new Set(["backup", "download", "copy", "lookup", "export", "abandon"]);
  let registered = false, mode = "login", busy = "", emailHint = "", actionHint = "oauth", operation = null;
  let pollTimer = null, pollBusy = false, returnFocus = null, lastRendered = "", hintTimer = 0, hintSeq = 0;
  const api = () => window.Team48;
  const visible = () => !sheet.hidden;
  const active = () => operation && !TERMINAL.has(operation.state || operation.status);
  const node = (tag, className, text) => {
    const value = document.createElement(tag);
    if (className) value.className = className;
    if (text != null) value.textContent = String(text);
    return value;
  };
  const button = (label, action, className = "button") => {
    const value = node("button", className, label); value.type = "button"; value.addEventListener("click", action); return value;
  };
  const tone = (target, name, text) => {
    if (name) target.dataset.tone = name; else target.removeAttribute("data-tone");
    if (text != null) target.textContent = text;
  };
  function clearError() { errorBox.textContent = ""; errorBox.hidden = true; }
  function showError(message) { errorBox.textContent = message; errorBox.hidden = false; }
  function clearSecrets() { body.querySelectorAll('input[type="password"], textarea[name="protocol_accounts"]').forEach(input => { input.value = ""; }); }
  function when(value) {
    const date = new Date(value);
    if (!value || Number.isNaN(date.getTime())) return "";
    const pad = number => String(number).padStart(2, "0");
    return date.getFullYear() + "-" + pad(date.getMonth() + 1) + "-" + pad(date.getDate()) + " " + pad(date.getHours()) + ":" + pad(date.getMinutes());
  }
  async function request(path, options = {}) {
    let response;
    try { response = await fetch(path, {credentials: "same-origin", cache: "no-store", ...options,
      headers: {Accept: "application/json", ...(options.body ? {"Content-Type": "application/json"} : {})}}); }
    catch (_) { throw new Error("连接中断，结果未确认。请先查看任务记录，再决定是否重试。"); }
    let result;
    try { result = await response.json(); } catch (_) { result = {}; }
    if (!result || typeof result !== "object" || Array.isArray(result)) result = {};
    if (!response.ok || result.ok === false) {
      const code = result.error_code || result.detail?.error_code || result.code;
      const error = new Error(response.status === 401 ? "后台登录已过期，请重新登录。" : ERRORS[code] || "操作没有完成，请核对输入和任务记录。");
      error.code = code; throw error;
    }
    return result;
  }
  const post = (path, payload) => request(path, {method: "POST", body: JSON.stringify(payload)});
  async function copyText(text) {
    if (navigator.clipboard?.writeText && window.isSecureContext !== false) { await navigator.clipboard.writeText(text); return; }
    const area = document.createElement("textarea");
    area.value = text; area.setAttribute("readonly", ""); area.style.position = "fixed"; area.style.opacity = "0";
    document.body.append(area); area.select();
    try { if (!document.execCommand("copy")) throw new Error("浏览器拒绝了复制，请改用下载。"); } finally { area.value = ""; area.remove(); }
  }
  // Starts the clipboard write inside the click (Safari keeps the gesture), then falls back.
  async function copyFetched(fetcher) {
    const pending = fetcher();
    if (window.ClipboardItem && navigator.clipboard?.write) {
      try {
        await navigator.clipboard.write([new ClipboardItem({"text/plain": pending.then(data => new Blob([data.secret], {type: "text/plain"}))})]);
        return;
      } catch (_) { /* fall back below */ }
    }
    const data = await pending;
    try { await copyText(data.secret); } catch (_) { throw new Error("浏览器拒绝了复制，请改用「下载备份」。"); }
  }
  function downloadJson(filename, value) {
    const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], {type: "application/json"}));
    const link = document.createElement("a"); link.href = url; link.download = filename; document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  const validKey = value => typeof value === "string" && value.length >= 16 && value.length <= 256;
  // A saved key leaves the server only for one copy or one download; it is never put into the page.
  async function fetchKey(email) {
    const data = await post("/api/assisted-login/totp-backup/reveal", {email});
    if (!validKey(data.secret)) throw new Error("已保存的密钥格式无效，没有取出。");
    return {email: data.email || email, secret: data.secret, saved_at: data.saved_at || null,
      verification: VERIFICATION[data.verification] ? data.verification : "user_reported"};
  }
  // "email----password----2FA" (also "email|password|2FA", and without the last part), as account lists are usually kept.
  // Same boundary rule as gpt-auth-bridge: the shorter dash run is the separator, extra dashes belong to the password.
  function splitAccountLine(line) {
    const value = String(line || "").trim();
    if (!value || value.length > 4700 || /[\r\n]/.test(value)) return null;
    const host = "@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+?[a-z0-9]+";
    const three = value.match(new RegExp("^(.+?" + host + ")\\s*(-{2,})(.*?)(-{2,})((?:[^-\\r\\n]|-(?!-))*)$", "i"));
    if (three && three[3]) {
      const [, email, left, middle, right, key] = three;
      const width = Math.min(4, left.length, right.length);
      return [email.trim(), (left.slice(width) + middle + right.slice(width)).trim(), key.trim()];
    }
    const two = value.match(new RegExp("^(.+?" + host + ")\\s*-{2,4}(.+)$", "i"));
    if (two) return [two[1].trim(), two[2].trim(), ""];
    const pipe = value.match(/^([^|\s]+@[^|\s]+)\|(.+?)(?:\|([^|]*))?$/);
    return pipe ? [pipe[1].trim(), pipe[2].trim(), (pipe[3] || "").trim()] : null;
  }
  function stopPolling() { if (pollTimer) clearTimeout(pollTimer); pollTimer = null; }
  function schedulePoll() {
    stopPolling();
    if (visible() && active()) pollTimer = setTimeout(() => void poll(), 1500);
  }
  async function poll() {
    if (!operation?.operation_id || pollBusy) return;
    const id = operation.operation_id; pollBusy = true;
    try {
      const result = await request("/api/assisted-login/" + encodeURIComponent(id));
      if (operation?.operation_id !== id) return;
      operation = {...operation, ...result, operation_id: id};
      opener.textContent = active() ? "登录任务" : "登录与安全";
      if (visible() && mode === "login") renderTask();
    } catch (error) {
      if (visible()) showError(error.message);
    } finally { pollBusy = false; schedulePoll(); }
  }
  function ensureRegistered() {
    if (registered) return;
    api().registerOverlay("assisted-login", sheet); registered = true;
    new MutationObserver(() => {
      if (sheet.hidden) { clearSecrets(); stopPolling(); detachProtocolView(); }
    }).observe(sheet, {attributes: true, attributeFilter: ["hidden"]});
  }
  function open(trigger, hint = "", action = "") {
    if (!api()) return;
    ensureRegistered(); returnFocus = trigger || opener;
    if (typeof hint === "string" && hint && hint.length <= 255) emailHint = hint.trim().toLowerCase();
    if (ACTIONS[action]) actionHint = action;
    if (hint && !active()) { operation = null; mode = "login"; }
    clearError();
    const show = api().getActiveOverlay() && api().getActiveOverlay() !== "assisted-login" ? api().replaceOverlay : api().openOverlay;
    show("assisted-login", {returnFocus, context: {kind: "assisted-login"}, initialFocus: "#assisted-login-close"});
    render();
    if (operation) void poll();
  }
  function close() {
    if (KEY_BUSY.has(busy)) { showError("正在处理密钥，请等结果出来再关闭。"); return; }
    clearSecrets(); stopPolling();
    if (api()?.getActiveOverlay() === "assisted-login") {
      if (api().overlayState.previousContext) api().restoreOverlayContext(); else api().closeOverlay();
    } else sheet.hidden = true;
    if (returnFocus?.isConnected && !returnFocus.closest("[hidden]")) returnFocus.focus();
  }
  function render() {
    detachProtocolView(); clearSecrets(); clearTimeout(hintTimer); body.replaceChildren(); lastRendered = "";
    sheet.querySelector(".assisted-header p").textContent = mode === "login" ? "用本机 Chrome 在官方页面登录，再执行所选操作。"
      : mode === "backup" ? "查询本机保存的 2FA 密钥和换绑记录。" : "通过 Team48 内嵌授权桥登录，授权保存在本机。";
    tabs.querySelectorAll("[data-assist-mode]").forEach(tab => {
      const selected = tab.dataset.assistMode === mode;
      tab.classList.toggle("is-active", selected);
      tab.setAttribute("aria-selected", String(selected)); tab.tabIndex = selected ? 0 : -1;
    });
    body.setAttribute("aria-labelledby", "assisted-" + mode + "-tab");
    if (mode === "backup") renderVault(); else if (mode === "protocol") renderProtocol(); else if (operation) renderTask(); else renderForm();
  }
  function field(label, name, type, value = "", required = true) {
    const wrap = node("label", "", label), input = document.createElement("input");
    input.name = name; input.type = type; input.required = required; input.value = value;
    input.autocomplete = type === "password" ? "off" : "username"; input.spellcheck = false;
    input.maxLength = type === "email" ? 255 : name === "password" ? 4096 : 256;
    wrap.append(input); return {wrap, input};
  }
  function group(title, tag = "div") {
    const value = node(tag, "assisted-group");
    value.append(node(tag === "fieldset" ? "legend" : "h3", "", title));
    return value;
  }
  function startAction(email, action) {
    mode = "login";
    if (active()) { clearError(); render(); showError("当前任务还在进行，请等它结束再发起新的操作。"); return; }
    operation = null;
    if (ACTIONS[action]) actionHint = action;
    if (typeof email === "string" && email) emailHint = email;
    clearError(); render();
  }
  function renderForm() {
    const form = node("form", "assisted-form"); form.autocomplete = "off";
    const account = group("账号", "fieldset");
    const email = field("邮箱", "email", "email", emailHint);
    const password = field("密码", "password", "password", "", false);
    const totp = field("2FA 密钥", "totp_secret", "password", "", false);
    const pair = node("div", "assisted-pair"); pair.append(password.wrap, totp.wrap);
    const hints = node("p", "assisted-hints"); hints.setAttribute("role", "status");
    account.append(email.wrap, pair, hints);
    const paintHints = data => {
      password.input.placeholder = data?.has_password ? "留空使用已保存的密码" : "";
      totp.input.placeholder = data?.has_totp ? "留空使用已保存的密钥" : "可留空";
      if (data && OPEN_PHASES.has(data.reset_phase)) tone(hints, "warning", "这个邮箱有未完成的换绑（" + PHASES[data.reset_phase] + "）。选「重设 2FA」会接着核对，不会重新生成密钥。");
      else if (data?.reset_phase === "unreadable") tone(hints, "warning", "这个邮箱的换绑记录无法读取，暂时不能重设 2FA；其他操作不受影响。");
      else if (data && (data.has_password || data.has_totp)) tone(hints, "success", "本机已保存这个账号的" + [data.has_password && "密码", data.has_totp && "2FA 密钥"].filter(Boolean).join("和") + "，可以留空。");
      else tone(hints, "", "可以直接粘贴「邮箱----密码----2FA 密钥」整行，自动拆分。");
    };
    const loadHints = async () => {
      const target = email.input.value.trim().toLowerCase(), sequence = ++hintSeq;
      if (!target || !email.input.validity.valid) { paintHints(null); return; }
      let data = null;
      try { data = await post("/api/assisted-login/hints", {email: target}); } catch (_) { data = null; }
      if (sequence === hintSeq && form.isConnected) paintHints(data);
    };
    const applyLine = text => {
      const parts = splitAccountLine(text);
      if (!parts) return false;
      [email.input.value, password.input.value, totp.input.value] = parts;
      void loadHints();
      return true;
    };
    const combined = text => /-{3,}|\|/.test(String(text || ""));
    email.input.addEventListener("paste", event => {
      const text = event.clipboardData?.getData("text") || "";
      if (combined(text) && applyLine(text)) event.preventDefault();
    });
    email.input.addEventListener("change", () => { if (combined(email.input.value)) applyLine(email.input.value); });
    email.input.addEventListener("input", () => { clearTimeout(hintTimer); hintTimer = setTimeout(() => void loadHints(), 350); });

    const operations = group("操作", "fieldset");
    const choices = node("div", "assisted-choices");
    const radios = ORDER.map(id => {
      const row = node("label", "assisted-choice"), radio = document.createElement("input");
      radio.type = "radio"; radio.name = "action"; radio.value = id; radio.checked = id === actionHint;
      const copy = node("span", "assisted-choice-copy"); copy.append(node("strong", "", ACTIONS[id].name), node("small", "", ACTIONS[id].hint));
      row.append(radio, copy); choices.append(row);
      return radio;
    });
    if (!radios.some(radio => radio.checked)) radios[0].checked = true;
    operations.append(choices);
    const confirmLabel = node("label", "assisted-confirm");
    const confirm = document.createElement("input"); confirm.type = "checkbox"; confirm.name = "confirm_reset";
    confirmLabel.append(confirm, document.createTextNode("我确认更换这个账号的 2FA，旧验证器会立即失效。"));
    operations.append(confirmLabel);
    const actions = node("div", "assisted-actions");
    const submit = node("button", "button primary", ""); submit.type = "submit";
    const tasks = node("a", "assisted-link", "任务记录"); tasks.href = "/operations";
    actions.append(submit, tasks);
    const chosen = () => radios.find(radio => radio.checked)?.value || "oauth";
    const sync = () => {
      const action = chosen(), reset = action === "reset_totp";
      actionHint = action;
      radios.forEach(radio => radio.closest(".assisted-choice").classList.toggle("is-selected", radio.checked));
      submit.textContent = ACTIONS[action].submit;
      confirmLabel.hidden = !reset;
      if (!reset) confirm.checked = false;
      submit.disabled = reset && !confirm.checked;
    };
    radios.forEach(radio => radio.addEventListener("change", sync)); confirm.addEventListener("change", sync);
    form.append(account, operations, actions, node("p", "assisted-foot", "在本机独立的 Chrome 窗口里执行，关掉这个抽屉不会停止任务。验证码和人机验证要你在那个窗口里完成。"));
    form.addEventListener("submit", async event => {
      event.preventDefault(); if (busy || active()) return;
      const action = chosen();
      if (action === "reset_totp" && !confirm.checked) return;
      if (!email.input.reportValidity()) return;
      clearError(); busy = "start"; form.setAttribute("aria-busy", "true");
      form.querySelectorAll("input,button").forEach(control => { control.disabled = true; });
      emailHint = email.input.value.trim().toLowerCase();
      let payload = {email: emailHint, password: password.input.value, totp_secret: totp.input.value.trim(), action};
      if (action === "reset_totp") payload.confirm_reset = true;
      clearSecrets();
      try {
        const result = await post("/api/assisted-login/start", payload);
        payload = null;
        if (!/^[A-Za-z0-9_-]{1,100}$/.test(result.operation_id || "")) throw new Error("服务没有返回任务编号。请先查看任务记录，避免重复启动。");
        operation = {operation_id: result.operation_id, email: emailHint, action, state: result.state || result.status || "running", stage: "starting", ...result};
        opener.textContent = "登录任务"; busy = "";
        if (visible()) render();
        schedulePoll();
      } catch (error) {
        if (visible()) showError(error.message); else api()?.toast(error.message, "warning");
      } finally {
        payload = null; busy = ""; clearSecrets();
        if (form.isConnected) { form.removeAttribute("aria-busy"); form.querySelectorAll("input,button").forEach(control => { control.disabled = false; }); sync(); }
      }
    });
    body.append(form); sync(); paintHints(null);
    if (email.input.value) void loadHints();
  }
  function stepOf(stage, action) {
    if (stage === "authenticated") return action === "reset_totp" ? "session" : action === "oauth" ? "login" : "handoff";
    return STEP_OF[stage] || "";
  }
  function stepRows() {
    const flow = FLOWS[operation.action] || FLOWS.oauth, state = operation.state || operation.status;
    const seen = new Set();
    for (const stage of Array.isArray(operation.stages) ? operation.stages : []) {
      const id = stepOf(stage, operation.action); if (id) seen.add(id);
    }
    const live = active() ? stepOf(operation.stage, operation.action) : "";
    if (live) seen.add(live);
    let last = -1;
    flow.forEach(([id], index) => { if (seen.has(id)) last = index; });
    if (last < 0 && active()) last = 0;
    return flow.map(([id, label], index) => {
      let mark = "pending";
      if (state === "success") mark = seen.has(id) || operation.action === "oauth" || id === "confirm" ? "done" : "skipped";
      else if (index < last) mark = seen.has(id) ? "done" : "skipped";
      else if (index === last) mark = active() ? "current" : state === "failed" ? "failed" : state === "cancelled" ? "visited" : "attention";
      return {label, mark};
    });
  }
  const STEP_WORDS = {done: "已完成", skipped: "未执行", visited: "已停止", current: "进行中", failed: "未完成", attention: "需要处理", pending: ""};
  function stepList() {
    const list = node("ol", "task-steps assisted-steps"); list.setAttribute("aria-label", "任务步骤");
    stepRows().forEach(row => {
      const item = node("li", "task-step is-" + row.mark);
      item.setAttribute("aria-label", row.label + (STEP_WORDS[row.mark] ? "：" + STEP_WORDS[row.mark] : ""));
      if (row.mark === "current") item.setAttribute("aria-current", "step");
      const mark = node("span", "task-step-mark", row.mark === "failed" || row.mark === "attention" ? "!" : ""); mark.setAttribute("aria-hidden", "true");
      const copy = node("span", "task-step-copy"); copy.append(node("strong", "", row.label));
      if (STEP_WORDS[row.mark]) copy.append(node("small", "", STEP_WORDS[row.mark]));
      item.append(mark, copy); list.append(item);
    });
    return list;
  }
  function outcome() {
    const state = operation.state || operation.status, result = operation.result || {}, action = operation.action;
    if (!TERMINAL.has(state)) {
      const stage = operation.stage || operation.current_step;
      return {tone: NEEDS_YOU.has(stage) ? "warning" : "accent", text: STAGES[stage] || "正在处理，请留意打开的 Chrome 窗口"};
    }
    const kind = state === "success" ? "success" : state === "failed" ? "danger" : state === "cancelled" ? "" : "warning";
    // Reset outcomes are fixed sentences written by the server; they never carry page text or keys.
    if (action === "reset_totp" && typeof result.message === "string" && result.message && result.message.length <= 200) return {tone: kind, text: result.message};
    if (state === "success" && action === "oauth") return {tone: kind, text: "授权已保存到本机账号库；没有自动检查额度或推送远端。"};
    if (state === "cancelled") return {tone: kind, text: action === "reset_totp" ? "已停止。已经发出的官方请求不会撤销，请在「2FA 密钥」查询换绑状态。" : "已停止本次任务。已在官方页面完成的操作不会撤销。"};
    if (action !== "oauth" && action !== "reset_totp" && state !== "failed") return {tone: kind, text: "请在官方安全页面核对结果。本机没有确认退出会话或更换 2FA。"};
    return {tone: kind, text: ERRORS[result.error_code || operation.error_code] || (state === "failed" ? "任务没有完成，请核对后重新发起。" : "需要人工继续，请查看官方页面和任务记录。")};
  }
  function keyButtons(target, email, rerender, primary) {
    const take = (label, kind, deliver, className) => {
      const control = button(label, async () => {
        if (busy) return; busy = kind; clearError(); rerender();
        let data = null;
        try { data = await fetchKey(email); await deliver(data); }
        catch (error) { showError(error.message); }
        finally { data = null; busy = ""; rerender(); }
      }, className);
      control.disabled = Boolean(busy);
      return control;
    };
    const copy = button("复制新密钥", async () => {
      if (busy) return; busy = "copy"; clearError(); rerender();
      try { await copyFetched(() => fetchKey(email)); api()?.toast("新 2FA 密钥已复制", "success"); }
      catch (error) { showError(error.message); }
      finally { busy = ""; rerender(); }
    }, primary ? "button primary" : "button");
    copy.disabled = Boolean(busy);
    target.append(copy,
      take("下载备份", "download", data => downloadJson("team48-2fa-backup.json", data), "button"));
  }
  function renderTask() {
    if (!operation || mode !== "login") return;
    const signature = JSON.stringify([operation.operation_id, operation.state, operation.status, operation.stage, operation.stages, operation.result, busy]);
    if (signature === lastRendered) return; lastRendered = signature;
    clearSecrets(); body.replaceChildren();
    const action = operation.action, reset = action === "reset_totp", result = operation.result || {};
    const state = operation.state || operation.status, email = operation.email || emailHint;
    const section = node("section", "assisted-task");
    const head = node("div", "assisted-task-head");
    head.append(node("h3", "", (ACTIONS[action]?.name || "账号任务") + (operation.mode === "resume" ? "（继续）" : "")), node("p", "", email + " · 任务 " + operation.operation_id));
    const view = outcome(), status = node("p", "assisted-result"); tone(status, view.tone, view.text);
    status.setAttribute("role", "status"); status.setAttribute("aria-live", "polite");
    section.append(head, status, stepList());
    const actions = node("div", "assisted-actions");
    const rerender = () => { lastRendered = ""; renderTask(); };
    if (active()) {
      if (reset) section.append(node("p", "assisted-note", "换绑一旦开始，会执行到可恢复的节点；停止任务不会打断已经发出的官方请求。"));
      const cancel = button(busy === "cancel" ? "正在停止…" : "停止任务", async () => {
        if (busy) return; busy = "cancel"; cancel.disabled = true; clearError();
        try { await request("/api/assisted-login/" + encodeURIComponent(operation.operation_id) + "/cancel", {method: "POST"}); await poll(); }
        catch (error) { showError(error.message); }
        finally { busy = ""; rerender(); }
      });
      cancel.disabled = Boolean(busy); actions.append(cancel);
    } else {
      let primary = true;
      const lead = () => { const name = primary ? "button primary" : "button"; primary = false; return name; };
      if (reset) {
        const details = [];
        if (Number(result.owner_synced) > 0) details.push("已同步 " + Number(result.owner_synced) + " 个团队的母号 2FA。");
        if (Number(result.extra_factors) > 0) details.push("官方还列出另外 " + Number(result.extra_factors) + " 个验证器，请在官方安全设置里核对。");
        if (Number.isInteger(result.remote_status) && result.remote_status > 0) details.push("官方返回 HTTP " + result.remote_status + (/^[A-Za-z0-9_]{1,80}$/.test(result.remote_code || "") ? "（" + result.remote_code + "）" : "") + "。");
        if (details.length) section.append(node("p", "assisted-note", details.join(" ")));
        if (result.backup_saved === true) keyButtons(actions, email, rerender, primary && !(primary = false));
        if (OPEN_PHASES.has(result.phase)) {
          actions.append(button(result.phase === "activated" ? "重新核对" : "继续换绑", () => startAction(email, "reset_totp"), lead()));
          actions.append(button("查看换绑记录", () => { mode = "backup"; emailHint = email; clearError(); render(); }));
        }
      }
      if (action === "oauth" && state === "success") actions.append(button("刷新账号列表", async () => {
        try { await api()?.bootPage(); api()?.toast("账号列表已刷新", "success"); } catch (_) { showError("账号列表刷新失败，请手动刷新页面。"); }
      }, lead()));
      if (action === "security") actions.append(button("备份手动换绑的密钥", () => { mode = "backup"; emailHint = email; clearError(); render(); }, lead()));
      actions.append(button(state === "success" ? "再做一个操作" : "重新发起", () => startAction(email, action), lead()));
    }
    const tasks = node("a", "assisted-link", "任务记录"); tasks.href = "/operations"; actions.append(tasks);
    section.append(actions); body.append(section);
  }
  let protocolTask = null, protocolView = null, protocolSubmitting = "", protocolError = "";

  function detachProtocolView() {
    if (protocolView) clearTimeout(protocolView.timer);
    protocolView = null;
  }
  function protocolActive() {
    return protocolTask && !TERMINAL.has(protocolTask.state || protocolTask.status);
  }

  const IMPORT_LABELS = {
    imported: "已导入", skipped_remote_owned: "已跳过导入，刷新权在远端", conflict: "导入信息冲突",
    no_credential: "缺少可导入的授权", failed: "导入失败", workspace_selection_required: "请在完整工作台选择工作区",
  };
  function protocolRow(row) {
    if (row.login !== "ok") return [row.code === "bridge_email_verification" ? "warning" : "danger", row.message || ERRORS[row.code] || "登录失败，请核对代理与凭据"];
    if (row.import === "imported") return ["success", "已登录，已导入"];
    const label = IMPORT_LABELS[row.import] || "未确认导入";
    return [row.import === "failed" ? "danger" : "warning", "已登录，" + label];
  }
  function protocolOutcome(data) {
    const state = data.state || data.status;
    const result = data.result || {};
    const reset = data.op_type === "protocol_reset";
    if (!TERMINAL.has(state)) {
      if (data.cancel_requested) return ["warning", "正在等待任务停止"];
      if (state === "pending" || data.stage === "queued") return ["accent", "任务已受理，等待执行"];
      const resetStage = reset && data.stage?.startsWith("mfa_") && STAGES[data.stage];
      return ["accent", resetStage || (data.stage === "import" ? "正在导入授权" :
        reset ? "正在登录账号" : "正在登录账号，等待授权桥返回结果。")];
    }
    const labels = {failed: "任务失败", manual_required: "需要人工核对", partial: "部分完成", cancelled: "任务已停止", resolved: "任务已处理"};
    if (state !== "success" || reset) {
      const detail = result.message || ERRORS[result.error_code] || result.error;
      return [state === "success" ? "success" : state === "failed" ? "danger" : "warning",
        [labels[state] || "2FA 已重设", detail].filter(Boolean).join(" · ")];
    }
    const rows = result.results || [];
    const total = data.count ?? result.total ?? rows.length;
    const logged = rows.filter(row => row.login === "ok").length;
    const imported = rows.filter(row => row.login === "ok" && row.import === "imported").length;
    if (!rows.length) return ["warning", "任务已结束，未返回账号结果。请查看任务记录。"];
    const counts = "登录成功 " + logged + "/" + total + "，已导入 " + imported + "/" + total;
    if (logged === 0 && rows.length === total) return ["danger", "全部登录失败 · " + counts];
    if (imported === total && rows.length === total) return ["success", "已完成 · " + counts];
    return ["warning", (logged === total && imported === 0 ? "授权未导入" : "部分完成") + " · " + counts];
  }

  function batchStageResults(data) {
    const result = data.result || {};
    const rows = result.results || [];
    if (!rows.length) {
      if (data.confirmedPhase >= 2) return [["done", "已收到登录结果"], ["warning", "导入待核对"]];
      if (result.error_code?.startsWith("bridge_")) return [["danger", "未完成"], ["skipped", "未执行"]];
      return [["pending", "未确认"], ["pending", "未确认"]];
    }
    const total = data.count ?? result.total ?? rows.length;
    const logged = rows.filter(row => row.login === "ok");
    const saved = logged.filter(row => row.import === "imported").length;
    const login = [logged.length === total ? "done" : logged.length ? "warning" : "danger", "成功 " + logged.length + "/" + total];
    let imported = ["skipped", "未执行"];
    if (saved) imported = [saved === total ? "done" : "warning", "已导入 " + saved + "/" + total];
    else if (logged.some(row => ["conflict", "failed"].includes(row.import))) imported = ["danger", "导入失败"];
    else if (logged.some(row => row.import === "skipped_remote_owned")) imported = ["skipped", "已跳过"];
    else if (logged.some(row => row.import && row.import !== "no_credential") || rows.length !== total) imported = ["pending", "未确认"];
    return [login, imported];
  }

  function protocolProgress() {
    const panel = node("section", "protocol-progress");
    const title = node("h3");
    title.tabIndex = -1;
    const summary = node("p", "assisted-result");
    summary.setAttribute("role", "status");
    summary.setAttribute("aria-atomic", "true");
    const rail = node("ol", "protocol-rail");
    rail.setAttribute("aria-label", "任务阶段");
    const rows = node("ul", "protocol-account-list");
    rows.setAttribute("aria-label", "逐账号结果");
    const actions = node("div", "assisted-actions");
    const record = node("a", "assisted-link", "任务记录");
    record.href = "/operations";
    const copy = button("复制新 2FA 密钥", async () => {
      const email = protocolTask?.email;
      if (!email) return;
      try { await copyFetched(() => fetchKey(email)); api()?.toast("新 2FA 密钥已复制", "success"); }
      catch (error) { if (panel.isConnected && visible()) showError(error.message); }
    });
    actions.append(copy, record);
    panel.append(title, summary, rail, rows, actions);
    panel.hidden = true;
    let currentId = "", markers = [], rowsRendered = false;
    function update(data) {
      panel.hidden = false;
      const reset = data.op_type === "protocol_reset";
      const state = data.state || data.status, finished = TERMINAL.has(state);
      if (currentId !== data.operation_id) {
        title.textContent = reset ? "2FA 换绑进度" : "批量登录进度";
        currentId = data.operation_id;
        markers = ["受理任务", "协议登录", reset ? "重设 2FA" : "导入授权", "返回结果"].map(label => {
          const item = node("li"), caption = node("small");
          item.append(node("span", "", label), caption);
          return {item, label, caption};
        });
        rail.replaceChildren(...markers.map(marker => marker.item));
        rows.replaceChildren();
        rowsRendered = false;
      }
      const [kind, message] = protocolOutcome(data);
      if (summary.textContent !== message) tone(summary, kind, message);
      const last = markers.length - 1;
      const current = finished ? last : data.confirmedPhase;
      const accountStages = finished && !reset ? batchStageResults(data) : null;
      markers.forEach(({item, label, caption}, index) => {
        // A terminal response may arrive between polls. Mark only the work we can confirm.
        const confirmed = index === 0 || index < data.confirmedPhase || (finished && kind === "success");
        let stageState = confirmed ? "done" : "pending";
        if (index === current) stageState = finished ? kind : "current";
        let word = {done: "已完成", current: "进行中", pending: finished ? "未确认" : "待处理",
          success: "已完成", warning: "请核对", danger: "失败"}[stageState];
        if (!reset && !finished && index === 1 && data.confirmedPhase === 2) word = "已收到结果";
        if (accountStages && (index === 1 || index === 2)) [stageState, word] = accountStages[index - 1];
        item.dataset.state = stageState;
        if (index === current && !finished) item.setAttribute("aria-current", "step"); else item.removeAttribute("aria-current");
        if (caption.textContent !== word) caption.textContent = word;
        item.setAttribute("aria-label", label + "，" + word);
      });
      if (finished && !rowsRendered) {
        for (const row of data.result?.results || []) {
          const [rowTone, label] = protocolRow(row), item = node("li"), status = node("span", "assisted-result");
          tone(status, rowTone, label);
          item.append(node("span", "assisted-mono", row.email), status);
          rows.append(item);
        }
        rowsRendered = true;
      }
      rows.hidden = !rows.childElementCount;
      copy.hidden = !(reset && data.result?.backup_saved === true && data.email);
    }
    return {panel, title, update};
  }

  function renderProtocol() {
    const section = node("section", "assisted-vault protocol-pane");
    const fullWorkbench = node("a", "button", "完整协议工作台 · 代理、并发 2FA 与工作区");
    fullWorkbench.href = "/tools/auth-bridge?tool=protocol-login";
    section.append(fullWorkbench);
    const connection = node("div", "protocol-connection");
    const status = node("p", "assisted-result");
    const check = button("重新检查", () => void checkConnection());
    connection.append(status, check);
    const progress = protocolProgress();
    const batch = node("form", "assisted-group"); batch.autocomplete = "off";
    const inputLabel = node("label", "protocol-label", "批量登录并导入授权");
    const lines = document.createElement("textarea");
    lines.name = "protocol_accounts"; lines.rows = 4; lines.spellcheck = false; lines.required = true;
    inputLabel.append(lines);
    const hint = node("p", "assisted-note", "每行一个账号，填写 邮箱----密码----2FA密钥。2FA 可省略，也可用 —— 或 | 分隔。");
    hint.id = "protocol-format"; lines.setAttribute("aria-describedby", hint.id);
    const batchBtn = node("button", "button primary", "开始批量登录"); batchBtn.type = "submit";
    const network = node("div", "assisted-pair");
    const proxyLabel = node("label", "assisted-field", "登录代理");
    const proxyMode = document.createElement("select"); proxyMode.name = "protocol_proxy_mode";
    for (const [value, text] of [["auto", "自动：账号绑定 → 母号代理 → 系统默认"], ["inherit", "继承指定母号代理"],
      ["profile", "选择代理档案"], ["custom", "自定义代理"], ["default", "系统默认出口"], ["direct", "服务器直连"]]) {
      const option = document.createElement("option"); option.value = value; option.textContent = text; proxyMode.append(option);
    }
    proxyLabel.append(proxyMode);
    const concurrencyLabel = node("label", "assisted-field", "同出口并发数");
    const concurrency = document.createElement("input"); concurrency.type = "number"; concurrency.min = "1"; concurrency.max = "10";
    concurrency.value = "5"; concurrency.name = "protocol_concurrency"; concurrencyLabel.append(concurrency);
    concurrency.required = true;
    network.append(proxyLabel, concurrencyLabel);
    const teamLabel = node("label", "assisted-field", "母号团队（可选）");
    const team = document.createElement("select"); team.name = "protocol_workspace_id";
    const automatic = document.createElement("option"); automatic.value = ""; automatic.textContent = "按邮箱匹配已同步的团队"; team.append(automatic); teamLabel.append(team);
    const profileLabel = node("label", "assisted-field", "代理档案");
    const profile = document.createElement("select"); profile.name = "protocol_proxy_profile_id"; profileLabel.append(profile);
    const custom = field("代理地址", "protocol_proxy_url", "password", "", false);
    custom.input.placeholder = "http://用户名:密码@主机:端口 或 socks5://主机:端口";
    const networkNote = node("p", "assisted-note", "优先保留账号固定出口。登录后自动保存、识别母号或子号并刷新额度；确认母号后自动登记团队和同步成员。");
    const optionsState = node("p", "assisted-note", "正在读取团队和代理档案…"); optionsState.setAttribute("role", "status");
    const retryOptions = button("重新读取代理选项", () => void loadOptions()); retryOptions.hidden = true;
    function syncNetwork() {
      profileLabel.hidden = proxyMode.value !== "profile";
      custom.wrap.hidden = proxyMode.value !== "custom";
      profile.required = proxyMode.value === "profile";
      custom.input.required = proxyMode.value === "custom";
    }
    proxyMode.addEventListener("change", syncNetwork);
    batch.append(inputLabel, hint, network, teamLabel, profileLabel, custom.wrap, networkNote, optionsState, retryOptions, batchBtn);
    syncNetwork();

    const disclosure = node("details", "assisted-manual");
    const reset = node("form", "assisted-group"); reset.autocomplete = "off";
    disclosure.append(node("summary", "", "重设单个账号的 2FA"), reset);
    const email = field("邮箱", "p_email", "email", emailHint);
    const pw = field("密码（留空使用已存密码）", "p_password", "password", "", false);
    const totp = field("现有 2FA 密钥（留空使用已存密钥）", "p_totp", "password", "", false);
    const ok = node("label", "assisted-confirm"); const ck = document.createElement("input");
    ck.type = "checkbox"; ck.required = true;
    ok.append(ck, document.createTextNode("我确认更换这个账号的 2FA，旧验证器会失效。"));
    const resetBtn = node("button", "button", "重设 2FA"); resetBtn.type = "submit";
    reset.append(email.wrap, pw.wrap, totp.wrap, ok, resetBtn);
    const refresh = button("刷新任务状态", () => void pollStatus());
    refresh.hidden = true;
    progress.panel.append(refresh);
    section.append(connection, progress.panel, batch, disclosure); body.append(section);
    let available = false, reading = false;
    const view = {timer: null, sync};
    protocolView = view;
    const attached = () => protocolView === view && visible() && mode === "protocol";
    function sync() {
      const locked = Boolean(protocolSubmitting || protocolActive() || !available);
      batchBtn.disabled = resetBtn.disabled = locked;
      lines.readOnly = protocolSubmitting === "protocol_login";
      for (const control of [proxyMode, team, profile, custom.input, concurrency]) control.disabled = locked;
      batchBtn.textContent = protocolSubmitting === "protocol_login" ? "正在提交…" : "开始批量登录";
      resetBtn.textContent = protocolSubmitting === "protocol_reset" ? "正在提交…" : "重设 2FA";
      if (protocolTask) progress.update(protocolTask);
      if (protocolError) showError(protocolError);
    }
    async function checkConnection() {
      check.hidden = true;
      tone(status, "", "正在检查授权桥…");
      try {
        const cap = await request("/api/protocol-auth/capabilities");
        if (!attached()) return;
        available = cap.available === true;
        tone(status, available ? "success" : "warning", available ? "内嵌授权桥已连接" :
          ERRORS[cap.error_code] || "内嵌授权桥暂不可用。");
      } catch (error) { if (attached()) tone(status, "warning", error.message); }
      if (attached()) { check.hidden = available; sync(); }
    }
    async function loadOptions() {
      retryOptions.hidden = true;
      try {
        const options = await request("/api/protocol-auth/options");
        if (!attached()) return;
        team.replaceChildren(automatic);
        for (const item of options.workspaces || []) {
          const option = document.createElement("option"); option.value = item.id;
          option.textContent = item.name + " · " + item.owner_email; team.append(option);
        }
        profile.replaceChildren();
        for (const item of options.proxies || []) {
          const option = document.createElement("option"); option.value = item.id; option.textContent = item.name; profile.append(option);
        }
        optionsState.textContent = options.default_has_proxy ? "系统默认：已配置代理。" : "系统默认未配置代理；无法匹配账号或团队时将使用服务器直连。";
        if (!(options.proxies || []).length) optionsState.textContent += " 暂无可用代理档案，可选择自定义代理。";
      } catch (_) {
        if (attached()) { optionsState.textContent = "团队和代理选项读取失败，可重试或使用自定义代理。"; retryOptions.hidden = false; }
      }
    }
    async function pollStatus() {
      const id = protocolTask?.operation_id;
      if (!id || !attached() || reading || !protocolActive()) return;
      clearTimeout(view.timer); reading = true; refresh.disabled = true;
      try {
        const data = await request("/api/protocol-auth/" + encodeURIComponent(id));
        if (!attached() || id !== protocolTask?.operation_id) return;
        const phase = data.stage?.startsWith("mfa_") || data.stage === "import" ? 2 : data.stage === "protocol_login" ? 1 : 0;
        protocolTask = {...protocolTask, ...data, confirmedPhase: Math.max(protocolTask.confirmedPhase, phase)};
        if (protocolError) { protocolError = ""; clearError(); }
        refresh.hidden = true;
        sync();
        if (!protocolActive() && data.result?.imported > 0) await api()?.bootPage();
        if (protocolActive()) view.timer = setTimeout(pollStatus, 2000);
      } catch (error) {
        if (!attached() || id !== protocolTask?.operation_id) return;
        protocolError = error.message; showError(protocolError); refresh.hidden = false;
        if (error.code === "not_found") {
          protocolTask = {...protocolTask, state: "manual_required", result: {message: "任务记录未找到。"}};
          refresh.hidden = true; sync();
        }
      } finally { reading = false; refresh.disabled = false; }
    }
    view.poll = pollStatus;
    async function start(type, path, payload) {
      if (!available || protocolSubmitting || protocolActive()) return;
      protocolSubmitting = type; protocolError = ""; clearError(); sync();
      try {
        const result = await post(path, payload);
        if (!/^[A-Za-z0-9_-]{1,100}$/.test(result.operation_id || "")) throw new Error("任务编号未确认，请查看任务记录。");
        protocolTask = {...result, op_type: type, confirmedPhase: 0};
        if (type === "protocol_login") lines.value = ""; else ck.checked = false;
      } catch (error) { protocolError = error.message; }
      finally { payload = null; protocolSubmitting = ""; }
      if (!protocolView || !visible()) return;
      protocolView.sync();
      if (protocolTask && !protocolError) {
        if (attached()) progress.title.focus();
        void protocolView.poll();
      }
    }
    batch.addEventListener("submit", event => {
      event.preventDefault();
      if (batchBtn.disabled || !batch.reportValidity()) return;
      const payload = {text: lines.value, proxy_mode: proxyMode.value, concurrency: Number(concurrency.value),
        workspace_id: team.value ? Number(team.value) : null,
        proxy_profile_id: proxyMode.value === "profile" && profile.value ? Number(profile.value) : null};
      if (proxyMode.value === "custom") payload.proxy = custom.input.value.trim();
      void start("protocol_login", "/api/protocol-auth/batch-login", payload);
    });
    reset.addEventListener("submit", event => {
      event.preventDefault();
      if (resetBtn.disabled || !reset.reportValidity()) return;
      const payload = {email: email.input.value.trim().toLowerCase(), password: pw.input.value, totp_secret: totp.input.value.trim(), confirm_reset: true};
      pw.input.value = ""; totp.input.value = "";
      void start("protocol_reset", "/api/protocol-auth/reset", payload);
    });
    sync(); void checkConnection(); void loadOptions(); void pollStatus();
  }
  function renderVault() {
    const section = node("section", "assisted-vault");
    const lookup = node("form", "assisted-lookup"); lookup.autocomplete = "off";
    const email = field("邮箱", "vault_email", "email", emailHint);
    const find = node("button", "button primary", "查询"); find.type = "submit";
    lookup.append(email.wrap, find);
    const keys = group("已保存的密钥"), keyState = node("p", "assisted-result"), keyMeta = node("p", "assisted-meta"), keyActions = node("div", "assisted-actions");
    keys.append(keyState, keyMeta, keyActions);
    const record = group("自动换绑记录"), recordState = node("p", "assisted-result"), recordNote = node("p", "assisted-note"), recordActions = node("div", "assisted-actions");
    record.append(recordState, recordNote, recordActions);
    [keyState, recordState].forEach(target => target.setAttribute("role", "status"));
    const manual = node("details", "assisted-manual");
    manual.append(node("summary", "", "备份在官方页面手动换绑的密钥"));
    const manualBox = node("form", "assisted-group"); manualBox.autocomplete = "off";
    const secret = field("手动换绑后的新 2FA 密钥", "new_totp_secret", "password");
    const confirmLabel = node("label", "assisted-confirm");
    const confirm = document.createElement("input"); confirm.type = "checkbox";
    confirmLabel.append(confirm, document.createTextNode("我已在官方页面完成换绑，这把密钥属于上面的邮箱。"));
    const save = node("button", "button", "加密保存"); save.type = "submit"; save.disabled = true;
    const saveRow = node("div", "assisted-actions"); saveRow.append(save);
    manualBox.append(node("p", "assisted-foot", "只保存，不改动官方 2FA；记录标为“用户确认，未经官方验证”。「重设 2FA」生成的密钥会自动保存，不用在这里填。"), secret.wrap, confirmLabel, saveRow);
    manual.append(manualBox);
    keys.hidden = record.hidden = true;
    const target = () => email.input.value.trim().toLowerCase();
    let abandonTimer = 0;
    const lock = (name, value) => {
      busy = value ? name : "";
      section.querySelectorAll("input,button").forEach(control => { control.disabled = value; });
      if (!value) save.disabled = !confirm.checked;
    };
    const take = (label, kind, deliver, className) => button(label, async () => {
      if (busy) return; clearError(); lock(kind, true);
      let data = null;
      try { data = await fetchKey(target()); await deliver(data); }
      catch (error) { showError(error.message); }
      finally { data = null; lock(kind, false); }
    }, className);
    const paint = (address, backup, reset) => {
      keys.hidden = record.hidden = false; clearTimeout(abandonTimer); abandonTimer = 0;
      keyActions.replaceChildren(); recordActions.replaceChildren(); keyMeta.textContent = ""; recordNote.textContent = "";
      if (backup.failed) tone(keyState, "danger", backup.failed);
      else if (!backup.exists) tone(keyState, "", "没有保存这个邮箱的密钥");
      else {
        const stale = reset && reset.open === true && reset.phase !== "activated";
        if (stale) tone(keyState, "warning", "换绑进行中：这是换绑前保存的密钥，旧 2FA 可能已停用");
        else tone(keyState, backup.verification === "official_confirmed" ? "success" : backup.verification === "official_activated" ? "warning" : "", VERIFICATION[backup.verification] || "已保存");
        keyMeta.textContent = when(backup.saved_at) ? "保存于 " + when(backup.saved_at) : "";
        const copyKey = button("复制密钥", async () => {
          if (busy) return; clearError(); lock("copy", true);
          try { await copyFetched(() => fetchKey(target())); api()?.toast("2FA 密钥已复制", "success"); }
          catch (error) { showError(error.message); }
          finally { lock("copy", false); }
        });
        keyActions.append(copyKey,
          take("下载备份", "download", data => downloadJson("team48-2fa-backup.json", data), "button"));
      }
      keyMeta.hidden = !keyMeta.textContent; keyActions.hidden = !keyActions.childElementCount;
      if (reset.failed) tone(recordState, "danger", reset.failed);
      else {
        const open = reset.open === true;
        tone(recordState, open ? "warning" : reset.phase === "confirmed" ? "success" : "", PHASES[reset.phase] || "状态未知");
        if (open && typeof reset.message === "string") recordNote.textContent = reset.message;
        if (open && !active()) recordActions.append(button(reset.phase === "activated" ? "重新核对" : "继续换绑", () => { if (!busy) startAction(address, "reset_totp"); }, "button"));
        if (reset.has_candidate === true) recordActions.append(button("导出候选密钥", async () => {
          if (busy) return; clearError(); lock("export", true);
          let data = null;
          try {
            data = await post("/api/assisted-login/totp-reset/reveal", {email: address});
            if (!validKey(data.secret)) throw new Error("候选密钥格式无效，没有下载。");
            downloadJson("team48-2fa-candidate.json", {email: data.email || address, secret: data.secret, phase: data.phase || null,
              saved_at: data.saved_at || null, verification: VERIFICATION[data.verification] ? data.verification : "candidate_unverified"});
            recordNote.textContent = "已导出候选密钥。核对生效前，它不代表账号当前的 2FA。";
          } catch (error) { showError(error.message); }
          finally { data = null; lock("export", false); }
        }));
        if (open && !active()) {
          const abandon = button("放弃记录", async () => {
            if (busy) return;
            if (!abandonTimer) {
              // Two presses within five seconds, like the other irreversible local actions.
              abandon.textContent = "确认放弃？"; abandon.classList.add("is-armed");
              abandonTimer = setTimeout(() => { abandonTimer = 0; abandon.textContent = "放弃记录"; abandon.classList.remove("is-armed"); }, 5000);
              return;
            }
            clearTimeout(abandonTimer); abandonTimer = 0; clearError(); lock("abandon", true);
            let closed = null;
            try { closed = await post("/api/assisted-login/totp-reset/abandon", {email: address, confirmed: true}); api()?.toast(closed.archived ? "本地换绑记录已放弃，含密钥的记录已归档" : "本地换绑记录已放弃", "success"); }
            catch (error) { showError(error.message); abandon.textContent = "放弃记录"; abandon.classList.remove("is-armed"); }
            finally { lock("abandon", false); }
            if (closed) void query();
          });
          recordActions.append(abandon);
        }
      }
      recordNote.hidden = !recordNote.textContent; recordActions.hidden = !recordActions.childElementCount;
    };
    const settle = async (path, address) => {
      try { return await post(path, {email: address}); } catch (error) { return {failed: error.message}; }
    };
    async function query() {
      if (busy || !email.input.reportValidity()) return;
      const address = target(); clearError(); lock("lookup", true);
      let backup, reset;
      try {
        [backup, reset] = await Promise.all([settle("/api/assisted-login/totp-backup/status", address), settle("/api/assisted-login/totp-reset/status", address)]);
        emailHint = address;
      } finally { lock("lookup", false); }
      if (address === target()) paint(address, backup, reset);
    }
    lookup.addEventListener("submit", event => { event.preventDefault(); void query(); });
    email.input.addEventListener("input", () => { keys.hidden = record.hidden = true; confirm.checked = false; save.disabled = true; });
    confirm.addEventListener("change", () => { save.disabled = !confirm.checked || Boolean(busy); });
    secret.input.addEventListener("input", () => { confirm.checked = false; save.disabled = true; });
    manualBox.addEventListener("submit", async event => {
      event.preventDefault(); if (busy || !confirm.checked) return;
      if (!email.input.reportValidity() || !secret.input.reportValidity()) return;
      clearError(); lock("backup", true);
      let payload = {email: target(), secret: secret.input.value.trim(), confirmed: true}, done = false;
      secret.input.value = "";
      try { await post("/api/assisted-login/totp-backup", payload); done = true; api()?.toast("密钥已加密保存在本机", "success"); }
      catch (error) { showError(error.message); }
      finally { payload = null; secret.input.value = ""; confirm.checked = false; lock("backup", false); save.disabled = true; }
      if (done) { manual.open = false; void query(); }
    });
    section.append(lookup, keys, record, manual); body.append(section);
    if (email.input.value && email.input.validity.valid) void query();
  }
  tabs.querySelectorAll("[data-assist-mode]").forEach(tab => tab.addEventListener("click", () => {
    if (busy) return; clearSecrets(); clearError(); mode = tab.dataset.assistMode; render();
  }));
  tabs.addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key) || busy) return;
    event.preventDefault(); const options = Array.from(tabs.querySelectorAll("[data-assist-mode]"));
    const current = options.findIndex(tab => tab.dataset.assistMode === mode);
    const index = event.key === "Home" ? 0 : event.key === "End" ? options.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + options.length) % options.length;
    options[index].click(); options[index].focus();
  });
  opener.addEventListener("click", event => void open(event.currentTarget));
  document.getElementById("assisted-login-close").addEventListener("click", close);
  sheet.addEventListener("click", event => { if (event.target === sheet) close(); });
  window.addEventListener("keydown", event => {
    if (event.key === "Escape" && visible() && api()?.getActiveOverlay() === "assisted-login") { event.preventDefault(); event.stopImmediatePropagation(); close(); }
  }, true);
  window.addEventListener("pagehide", () => { clearSecrets(); stopPolling(); detachProtocolView(); });
  window.addEventListener("pageshow", event => { if (event.persisted && visible() && mode === "protocol") render(); });
  if (new URLSearchParams(location.search).get("assist") === "protocol") {
    const openProtocol = () => { mode = "protocol"; open(opener); };
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", openProtocol, {once: true});
    else openProtocol();
  }
  function openProtocol(trigger) { mode = "protocol"; open(trigger || opener); }
  document.getElementById("register-protocol-import")?.addEventListener("click", event => openProtocol(event.currentTarget));
  window.Team48AssistedLogin = {open, openProtocol, splitAccountLine};
})();
