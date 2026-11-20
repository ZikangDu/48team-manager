(() => {
  "use strict";
  const sheet = document.getElementById("credential-import-sheet");
  if (!sheet) return;
  const body = document.getElementById("credential-import-body");
  const title = document.getElementById("credential-import-title");
  const subtitle = document.getElementById("credential-import-subtitle");
  const errorBox = document.getElementById("credential-import-error");
  const opener = document.getElementById("credential-import-open");
  const MAX_BYTES = 5 * 1024 * 1024;
  let registered = false;
  let phase = "input";
  let draft = null;
  let selected = new Set();
  let busy = "";
  let requestVersion = 0;
  let returnFocus = null;

  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text != null) element.textContent = String(text);
    return element;
  };
  const button = (text, action, className = "button") => {
    const element = node("button", className, text);
    element.type = "button";
    element.addEventListener("click", action);
    return element;
  };
  const visible = () => !sheet.hidden;
  const api = () => window.Team48;
  function messageOf(value, fallback = "操作未完成，请重试") {
    if (typeof value === "string") return value.slice(0, 800);
    const detail = value?.detail;
    if (typeof detail === "string") return detail.slice(0, 800);
    const message = detail?.message || detail?.error || value?.message || value?.error;
    return typeof message === "string" ? message.slice(0, 800) : fallback;
  }
  function showError(value, fallback) {
    errorBox.textContent = messageOf(value, fallback);
    errorBox.hidden = false;
  }
  function clearError() { errorBox.textContent = ""; errorBox.hidden = true; }
  const ERROR_MESSAGES = {
    invalid_input: "输入格式不正确，请检查 JSON 内容。", invalid_json: "JSON 格式无效或存在重复字段，请检查导出文件。",
    content_too_large: "内容超过 5 MB，请分批导入。", input_too_large: "内容超过 5 MB，请分批导入。",
    too_many_candidates: "单次最多 50 组工作区凭据，请分批导入。", structure_too_complex: "结构过深或记录过多，请拆分文件。",
    format_unsupported: "未识别到支持的授权格式。", access_token_missing: "记录中没有可导入的访问凭据。",
    access_token_expired: "访问凭据已过期，请重新取得授权后导入。", identity_missing: "凭据缺少必要身份信息。",
    email_mismatch: "邮箱与凭据身份不一致。", workspace_mismatch: "工作区与凭据身份不一致。", user_mismatch: "用户与凭据身份不一致。",
    client_mismatch: "客户端身份不一致。", id_token_mismatch: "身份令牌与访问凭据不一致。", refresh_client_unsupported: "不支持这组刷新凭据的客户端。",
    account_changed: "预览后账号或绑定已变化，请返回重新解析。", workspace_conflict: "工作区与本地账号关联冲突，请先核对。",
    user_conflict: "凭据用户与本地账号冲突。", binding_conflict: "远端绑定存在冲突，请先核对。",
    account_disabled: "账号已归档或停用，请先在原管理入口处理。", account_busy: "账号有未完成的任务或授权会话，请完成后重新解析。",
    remote_refresh_owned: "刷新权已由远端服务托管，不能覆盖本地凭据。", bridge_security_pending: "账号有待核对的安全操作，请先处理。",
    preview_expired: "预览已过期或关闭，请返回输入并重新解析。", preview_consumed: "预览已经提交，请先核对账号列表。",
    preview_busy: "预览正在提交，请稍后核对。", preview_context_mismatch: "预览不属于当前数据库，请重新解析。",
    preview_capacity: "当前预览较多，请稍后重试。", preview_invalid: "预览无效，请返回重新解析。",
    selection_invalid: "所选记录无效，请重新解析。", selection_duplicate: "同一记录不能重复选择。", candidate_blocked: "所选记录包含无法导入的凭据。",
    workspace_selection_required: "每个邮箱只能选择一组工作区授权。", duplicate_workspace: "存在重复工作区记录，请先整理文件。",
    import_failed: "保存未完成，请先核对账号列表，再重新解析。", origin_mismatch: "请从当前后台页面提交。"
  };
  function apiErrorMessage(value, fallback = "操作未完成，请检查输入或稍后重试。") {
    const code = value?.detail?.error_code || value?.error_code || value?.code;
    return ERROR_MESSAGES[code] || fallback;
  }
  async function request(path, options = {}) {
    let response;
    try { response = await fetch(path, {
      credentials: "same-origin", cache: "no-store", ...options,
      headers: {Accept: "application/json", ...(options.body ? {"Content-Type": "application/json"} : {}), ...options.headers},
    }); } catch (_) { throw new Error("连接中断，请先核对账号列表再重试。"); }
    let result;
    try { result = await response.json(); } catch (_) { result = {}; }
    if (!result || typeof result !== "object" || Array.isArray(result)) result = {};
    if (!response.ok || result.ok !== true) {
      const error = new Error(apiErrorMessage(result, response.status === 401 ? "登录已过期，请重新登录后台。" : "请求未完成，请重试。"));
      error.code = result.error_code || result.code || result.detail?.error_code || result.detail?.code;
      error.status = response.status;
      throw error;
    }
    return result;
  }
  function clearSensitiveFields() {
    body.querySelectorAll('textarea, input[type="file"]').forEach(input => { input.value = ""; });
  }
  function setInputsBusy(form, value) {
    form.querySelectorAll("input, textarea, button").forEach(input => { input.disabled = value; });
    form.setAttribute("aria-busy", String(value));
  }
  function setHeading(heading, description) {
    title.textContent = heading;
    subtitle.textContent = description;
  }
  async function discardDraft() {
    const id = draft?.draft_id;
    if (!id) return;
    try { await request(`/api/credential-import/preview/${encodeURIComponent(id)}`, {method: "DELETE"}); }
    catch (error) {
      if (error.code === "preview_busy" || error.status === 409) throw error;
      api()?.toast("暂时无法确认草稿清除；未提交的草稿会在 15 分钟内失效。", "warning");
    }
    if (draft?.draft_id === id) { draft = null; selected.clear(); }
  }
  function cleanupHidden() {
    clearSensitiveFields();
  }
  async function close() {
    if (busy === "commit" || busy === "discard") { showError("正在保存或处理授权，请等待结果后再关闭。"); return; }
    const wasPreview = phase === "preview";
    const returnToDetails = phase !== "result";
    if (wasPreview) {
      busy = "discard";
      setInputsBusy(body, true);
      try { await discardDraft(); }
      catch (error) { busy = ""; renderPreview(); showError(error); return; }
      busy = "";
    }
    requestVersion++;
    busy = "";
    cleanupHidden();
    if (wasPreview) {
      phase = "input";
    }
    const manager = api();
    if (manager?.getActiveOverlay() === "credential-import") {
      if (returnToDetails && manager.overlayState.previousContext) manager.restoreOverlayContext();
      else manager.closeOverlay();
    } else sheet.hidden = true;
    body.replaceChildren();
    if (returnFocus?.isConnected && !returnFocus.closest("[hidden]")) returnFocus.focus();
  }
  function ensureRegistered() {
    if (registered) return;
    api().registerOverlay("credential-import", sheet);
    registered = true;
    new MutationObserver(() => { if (sheet.hidden) cleanupHidden(); }).observe(sheet, {attributes: true, attributeFilter: ["hidden"]});
  }
  async function open(trigger) {
    const manager = api();
    if (!manager || busy) return;
    ensureRegistered();
    returnFocus = trigger || opener;
    clearError();
    if (draft) phase = "preview";
    else phase = "input";
    const show = manager.getActiveOverlay() && manager.getActiveOverlay() !== "credential-import" ? manager.replaceOverlay : manager.openOverlay;
    show("credential-import", {returnFocus, context: {kind: "auth-tools"}, initialFocus: "#credential-import-close"});
    render();
  }
  function render() {
    cleanupHidden(); body.replaceChildren();
    if (phase === "preview") renderPreview(); else renderImport();
  }
  function renderImport() {
    setHeading("导入授权凭据", "先核对邮箱与工作区，再保存到本机账号库。");
    const form = node("form", "auth-tools-form");
    const fileLabel = node("label", "", "选择 JSON / TXT 文件");
    const files = document.createElement("input"); files.type = "file"; files.accept = ".json,.txt,application/json,text/plain"; files.multiple = true;
    fileLabel.append(files);
    const fileSummary = node("p", "auth-tools-files"); fileSummary.hidden = true;
    const pasteLabel = node("label", "", "或粘贴授权 JSON");
    const text = document.createElement("textarea"); text.name = "credential_json"; text.spellcheck = false; text.autocomplete = "off"; text.maxLength = MAX_BYTES;
    text.placeholder = "粘贴 Bridge 导出、CPA、Sub2API 或 Session JSON";
    pasteLabel.append(text);
    const submit = node("button", "button primary", "预览授权"); submit.type = "submit";
    const actions = node("div", "auth-tools-actions"); actions.append(submit);
    form.append(fileLabel, fileSummary, pasteLabel, node("p", "hint", "支持单个对象或 JSON 数组；总大小不超过 5 MB，最多 50 组候选。仅粘贴邮箱、密码或 2FA 密钥无法导入授权。"), actions);
    files.addEventListener("change", () => {
      clearError();
      if (files.files.length) text.value = "";
      fileSummary.hidden = !files.files.length;
      fileSummary.textContent = "已选择 " + files.files.length + " 个文件";
    });
    text.addEventListener("input", () => { if (text.value.trim()) { files.value = ""; fileSummary.hidden = true; } });
    form.addEventListener("submit", async event => {
      event.preventDefault(); if (busy) return;
      clearError();
      busy = "preview"; setInputsBusy(form, true); submit.textContent = "正在解析…";
      const version = ++requestVersion;
      let content;
      try {
        if (files.files.length) {
          const chosen = Array.from(files.files);
          if (chosen.length > 50) throw new Error("最多选择 50 个文件，请分批导入。");
          if (chosen.reduce((sum, file) => sum + file.size, 0) > MAX_BYTES) throw new Error("文件总大小超过 5 MB，请分批导入。");
          const documents = [];
          for (const file of chosen) {
            const raw = (await file.text()).replace(/^\uFEFF/, "");
            try { JSON.parse(raw); documents.push(raw); }
            catch (_) { throw new Error("有文件不是有效 JSON，请检查导出内容。"); }
          }
          content = documents.length === 1 ? documents[0] : "[" + documents.join(",") + "]";
        } else {
          content = text.value.trim();
          if (!content) throw new Error("请选择文件或粘贴授权 JSON。");
          if (new Blob([content]).size > MAX_BYTES) throw new Error("内容超过 5 MB，请分批导入。");
        }
        if (new Blob([JSON.stringify({content})]).size > MAX_BYTES) throw new Error("提交内容超过 5 MB，请分批导入。");
      } catch (error) {
        content = null;
        if (version === requestVersion) { busy = ""; setInputsBusy(form, false); submit.textContent = "预览授权"; showError(error); }
        return;
      }
      if (version !== requestVersion || !visible()) { content = null; return; }
      try {
        clearSensitiveFields();
        const result = await request("/api/credential-import/preview", {method: "POST", body: JSON.stringify({content})});
        content = null; form.querySelectorAll('textarea,input[type="file"]').forEach(input => { input.value = ""; });
        if (version !== requestVersion || !visible()) {
          if (result.draft_id) void request(`/api/credential-import/preview/${encodeURIComponent(result.draft_id)}`, {method: "DELETE"}).catch(() => {});
          return;
        }
        if (!result.draft_id || !Array.isArray(result.candidates)) {
          const failures = (Array.isArray(result.errors) ? result.errors : []).slice(0, 4).map(item => apiErrorMessage(item, "有一条凭据无法识别"));
          throw new Error(failures.join("；") || apiErrorMessage(result, "未找到可识别的授权凭据。"));
        }
        draft = result; selected.clear(); phase = "preview"; busy = ""; render();
      } catch (error) {
        if (version === requestVersion && visible()) {
          showError(error); setInputsBusy(form, false); submit.textContent = "预览授权";
        }
      } finally {
        content = null;
        form.querySelectorAll('textarea,input[type="file"]').forEach(input => { input.value = ""; });
        if (version === requestVersion) { busy = ""; fileSummary.hidden = true; }
      }
    });
    body.append(form);
  }
  function renderPreview() {
    if (!draft) { phase = "input"; render(); return; }
    body.replaceChildren();
    body.removeAttribute("aria-busy");
    setHeading("选择工作区授权", "每个邮箱只能保留一组授权；请选择要在 Team48 管理的工作区。");
    const candidates = Array.isArray(draft.candidates) ? draft.candidates : [];
    const head = node("div", "auth-tools-preview-head");
    const expires = draft.expires_at ? new Date(draft.expires_at) : null;
    head.append(node("p", "auth-tools-note", "保存会替换所选账号的一整组授权，不改变团队成员、母号用途、代理或远端托管关系。账号是否有效需另行检查。"));
    if (expires && Number.isFinite(expires.getTime())) head.append(node("p", "hint", `此预览有效至 ${expires.toLocaleTimeString("zh-CN", {hour: "2-digit", minute: "2-digit"})}；关闭窗口会丢弃未保存的预览。`));
    const errors = Array.isArray(draft.errors) ? draft.errors : [];
    if (errors.length) {
      const list = node("ul", "auth-tools-preview-errors");
      errors.forEach(error => list.append(node("li", "", apiErrorMessage(error, "有一条凭据无法识别"))));
      head.append(list);
    }
    const groups = new Map();
    candidates.forEach(candidate => {
      const email = String(candidate.email || "未知邮箱");
      if (!groups.has(email)) groups.set(email, []);
      groups.get(email).push(candidate);
    });
    const unique = button("选择可唯一确定的账号", () => {
      selected.clear();
      groups.forEach(items => { const allowed = items.filter(item => item.allowed === true); if (allowed.length === 1) selected.add(String(allowed[0].id)); });
      list.querySelectorAll("input[data-credential-email]").forEach(input => { input.checked = selected.has(input.value); });
      confirmed.checked = false; syncSelection();
    });
    unique.disabled = !candidates.some(item => item.allowed === true);
    head.append(unique);
    const list = node("div", "auth-tools-candidates");
    if (!candidates.length) list.append(node("p", "muted", "没有可导入的授权。请检查文件格式，或重新获取授权。"));
    groups.forEach((items, email) => {
      const group = node("fieldset", "auth-tools-candidate-group"); group.append(node("legend", "", email));
      if (items.length > 1) group.append(node("p", "hint", `发现 ${items.length} 组授权，请选择其中一组。`));
      items.forEach(candidate => {
        const id = String(candidate.id);
        const label = node("label", `auth-tools-candidate${candidate.allowed === true ? "" : " is-blocked"}`);
        const input = document.createElement("input"); input.type = "checkbox"; input.value = id; input.checked = selected.has(id); input.disabled = candidate.allowed !== true;
        input.dataset.credentialEmail = email;
        const detail = node("span");
        const workspaceName = candidate.workspace_name || (candidate.workspace_id ? "工作区授权" : "个人授权");
        detail.append(node("strong", "", workspaceName));
        if (candidate.workspace_id) detail.append(node("small", "auth-tools-workspace-id", candidate.workspace_id));
        detail.append(node("small", "", `${candidate.action === "update" || candidate.account_id ? "更新现有账号" : "新建本地待命账号"}${candidate.format ? ` · ${candidate.format}` : ""}`));
        detail.append(node("small", candidate.has_refresh_token ? "" : "auth-tools-warning", candidate.has_refresh_token ? "包含刷新凭据" : "仅访问凭据，过期后需要重新授权"));
        const expiry = candidate.expires_at ? new Date(candidate.expires_at) : null;
        if (expiry && Number.isFinite(expiry.getTime())) detail.append(node("small", "", `访问凭据到期：${expiry.toLocaleString("zh-CN")}`));
        (candidate.warnings || []).forEach(warning => detail.append(node("small", "auth-tools-warning", messageOf(warning, "请核对这组授权"))));
        if (candidate.allowed !== true) detail.append(node("small", "auth-tools-blocker", apiErrorMessage(candidate.error, "此项暂不可导入，请核对本地账号及导出文件。")));
        input.addEventListener("change", () => {
          if (input.checked) {
            items.forEach(item => selected.delete(String(item.id))); selected.add(id);
            list.querySelectorAll("input[data-credential-email]").forEach(other => { if (other.dataset.credentialEmail === email && other !== input) other.checked = false; });
          } else selected.delete(id);
          confirmed.checked = false; syncSelection();
        });
        label.append(input, detail); group.append(label);
      });
      list.append(group);
    });
    const footer = node("div", "auth-tools-import-footer");
    const verifyLabel = node("label", "check auth-tools-confirm");
    const confirmed = document.createElement("input"); confirmed.type = "checkbox";
    verifyLabel.append(confirmed, document.createTextNode("我已核对邮箱和工作区，确认替换所选账号的本地授权。"));
    confirmed.addEventListener("change", syncSelection);
    const count = node("p", "hint"); count.setAttribute("role", "status");
    const actions = node("div", "auth-tools-actions");
    const commit = button("确认导入", () => { if (confirmed.checked) void commitSelection(); }, "button primary"); commit.id = "credential-import-commit";
    const back = button("返回输入", async () => {
      if (busy) return;
      busy = "discard"; setInputsBusy(body, true);
      try { await discardDraft(); }
      catch (error) { busy = ""; renderPreview(); showError(error); return; }
      busy = ""; phase = "input"; clearError(); render();
    });
    actions.append(commit, back); footer.append(count, verifyLabel, node("p", "hint", "导入过程不检查官方额度，保存后可手动检查。"), actions);
    body.append(head, list, footer);
    function syncSelection() {
      const valid = new Set(candidates.filter(item => item.allowed === true).map(item => String(item.id)));
      selected = new Set([...selected].filter(id => valid.has(id)));
      count.textContent = `已选择 ${selected.size} 个账号。导入不会接受邀请、创建母号或自动推送。`;
      commit.textContent = selected.size ? `确认导入 ${selected.size} 个账号` : "确认导入";
      commit.disabled = selected.size === 0 || !confirmed.checked || Boolean(busy);
    }
    syncSelection();
  }
  async function commitSelection() {
    if (busy || !draft || !selected.size) return;
    clearError(); busy = "commit";
    body.querySelectorAll("input,button").forEach(input => { input.disabled = true; });
    body.setAttribute("aria-busy", "true");
    const commit = document.getElementById("credential-import-commit"); if (commit) commit.textContent = "正在保存…";
    try {
      const result = await request("/api/credential-import/commit", {method: "POST", body: JSON.stringify({draft_id: draft.draft_id, selected_ids: [...selected], verify_quota: false})});
      const count = Array.isArray(result.imported) ? result.imported.length : Number(result.imported_count) || selected.size;
      draft = null; selected.clear(); busy = ""; phase = "result"; 
      body.removeAttribute("aria-busy"); body.replaceChildren();
      setHeading("授权已导入", `已保存 ${count} 个账号的授权。`);
      const section = node("section", "auth-tools-result");
      const verificationNote = "凭据已导入，尚未完成有效性验证。可在账号列表手动检查额度。";
      section.append(node("p", "auth-tools-note", verificationNote));
      section.append(node("p", "hint", "新账号保存在“未分配”。已有待接受邀请保持原状态，正式入组后再同步团队。"));
      const actions = node("div", "auth-tools-actions");
      actions.append(button("返回账号列表", () => void close(), "button primary"));
      actions.append(button("继续导入", () => { phase = "input"; render(); }));
      section.append(actions); body.append(section);
      api()?.toast(`已导入 ${count} 个账号的授权`, "success");
      try { await api()?.bootPage(); }
      catch (_) { api()?.toast("授权已保存，账号列表刷新失败，请手动刷新页面。", "warning"); }
    } catch (error) {
      busy = ""; body.removeAttribute("aria-busy"); renderPreview();
      showError(error, "保存结果未确认，请先查看账号状态，再决定是否重试。");
    }
  }

  opener.addEventListener("click", event => void open(event.currentTarget));
  document.getElementById("credential-import-close").addEventListener("click", close);
  sheet.addEventListener("click", event => { if (event.target === sheet) close(); });
  window.addEventListener("keydown", event => {
    if (event.key === "Escape" && visible() && api()?.getActiveOverlay() === "credential-import") {
      event.preventDefault(); event.stopImmediatePropagation(); close();
    }
  }, true);
  window.addEventListener("pagehide", clearSensitiveFields);
  window.Team48CredentialImport = {open};
})();
