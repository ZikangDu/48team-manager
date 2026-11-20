import {readEvaluationEvents} from "/tools/auth-bridge/modules/evaluation-stream.js";
import {evaluationPreviewDocument} from "/tools/auth-bridge/modules/evaluation-preview.js";

const byId = id => document.getElementById(id);
const picker = byId("bridge-account");
const form = byId("evaluation-form");
const source = byId("evaluation-source");
const preview = byId("evaluation-preview");
const previewToggle = byId("evaluation-preview-toggle");
const liveRequests = new Map();
const accounts = new Map();
const tabs = [...document.querySelectorAll(".bridge-tabs a")];
let tool = "health";
let previewSource = "";
let workspacesLoaded = false;

function say(id, message = "", tone = "") {
  const target = byId(id);
  if (target.textContent !== message) target.textContent = message;
  target.dataset.tone = tone;
}
function resetPreview() {
  preview.removeAttribute("srcdoc");
  preview.hidden = true;
  previewToggle.textContent = "预览动画";
  previewToggle.setAttribute("aria-expanded", "false");
}
function resetEvaluation() {
  resetPreview();
  previewSource = "";
  previewToggle.hidden = true;
  byId("evaluation-result").hidden = true;
  byId("evaluation-output").textContent = "";
  byId("evaluation-meta").textContent = "";
  say("evaluation-status");
}
function syncControls() {
  const account = accounts.get(picker.value);
  const apiMode = tool === "model-evaluation" && source.value === "api";
  const ready = account?.has_access_token && account.proxy_compatible;
  const testing = liveRequests.has("evaluation");
  byId("evaluation-source-label").hidden = tool !== "model-evaluation";
  source.disabled = testing;
  byId("bridge-account-label").hidden = apiMode;
  byId("bridge-account-note").hidden = apiMode;
  byId("bridge-account-detail").hidden = apiMode || !account || account.has_access_token && account.proxy_compatible;
  if (account) byId("bridge-account-detail").href = "/accounts?account=" + encodeURIComponent(account.id);
  byId("evaluation-api").hidden = !apiMode;
  byId("evaluation-api").disabled = !apiMode || testing;
  byId("bridge-check").disabled = !ready || liveRequests.has("health");
  byId("evaluation-start").disabled = testing || (!apiMode && (!ready || account?.plan?.toLowerCase() === "free"));
  form.querySelectorAll("input,select").forEach(el => { el.disabled = testing; });
  byId("evaluation-stop").hidden = !testing;
  byId("workspace-refresh").disabled = !account || liveRequests.has("workspaces");
  const ultra = form.elements.reasoning_effort.querySelector('[value="ultra"]');
  ultra.disabled = source.value !== "api";
  if (ultra.disabled && ultra.selected) form.elements.reasoning_effort.value = "medium";
  if (!account) return;
  const plan = account.plan && account.plan !== "unknown" ? account.plan : "套餐待确认";
  let note = plan;
  if (tool !== "workspaces") {
    if (!account.has_access_token) note += " · 请先在账号页完成授权";
    else if (!account.proxy_compatible) note += " · 无法核对固定代理出口";
    else if (tool === "model-evaluation" && account.plan?.toLowerCase() === "free") note += " · Free 账号不支持模型评测";
  }
  say("bridge-account-note", note);
}
async function fetchChecked(url, options = {}) {
  const response = await fetch(url, {credentials: "same-origin", cache: "no-store", ...options});
  if (response.ok) return response;
  const error = await response.json().catch(() => null);
  throw new Error(response.status === 401 ? "后台登录已过期，请重新登录。" :
    (error?.detail?.message || error?.message || "请求未完成，请稍后再试。"));
}
function cancelRequests() {
  for (const request of liveRequests.values()) request.abort();
  liveRequests.clear();
}
async function runAction(action, callback, usesAccount = true) {
  if ((usesAccount && !accounts.has(picker.value)) || liveRequests.has(action)) return;
  const controller = new AbortController();
  liveRequests.set(action, controller);
  syncControls();
  const id = encodeURIComponent(picker.value);
  try {
    const url = usesAccount ? "/api/bridge-workbench/accounts/" + id + "/" + action : null;
    await callback(url, controller.signal);
  } catch (error) {
    if (!controller.signal.aborted) {
      const statusIds = {workspaces: "workspace-status", health: "health-status", evaluation: "evaluation-status"};
      say(statusIds[action], error instanceof TypeError ? "连接中断，请检查本机服务后重试。" : error.message, "danger");
    }
  } finally {
    if (liveRequests.get(action) === controller) {
      liveRequests.delete(action);
      syncControls();
    }
  }
}
const post = (url, payload, signal) => fetchChecked(url, {method: "POST", signal,
  headers: {"Content-Type": "application/json"}, body: JSON.stringify(payload)});

async function listAccounts() {
  picker.disabled = true;
  byId("bridge-reload").hidden = true;
  try {
    const response = await fetchChecked("/api/bridge-workbench/accounts");
    const data = await response.json();
    accounts.clear();
    picker.replaceChildren(new Option(data.accounts.length ? "选择账号…" : "暂无可用账号", ""));
    for (const item of data.accounts) {
      accounts.set(String(item.id), item);
      picker.add(new Option(item.email, String(item.id)));
    }
    picker.disabled = !accounts.size;
    say("bridge-account-note", accounts.size ? "" : "可以从账号页登记团队或导入授权。");
    byId("bridge-reload").hidden = Boolean(accounts.size);
  } catch (error) {
    picker.replaceChildren(new Option("账号列表暂不可用", ""));
    say("bridge-account-note", error instanceof TypeError ? "无法连接 Team48。" : error.message, "danger");
    byId("bridge-reload").hidden = false;
  }
  syncControls();
}
function selectTool() {
  const requested = new URL(location.href).searchParams.get("tool");
  tool = tabs.some(el => el.dataset.tool === requested) ? requested : "health";
  for (const tab of tabs) {
    if (tab.dataset.tool === tool) tab.setAttribute("aria-current", "page");
    else tab.removeAttribute("aria-current");
  }
  for (const panel of document.querySelectorAll("[data-panel]")) panel.hidden = panel.dataset.panel !== tool;
  if (!preview.hidden && tool !== "model-evaluation") resetPreview();
  if (tool !== "model-evaluation") form.elements.key.value = "";
  syncControls();
  if (tool === "workspaces" && !workspacesLoaded) loadWorkspaces();
}
for (const tab of tabs) {
  tab.addEventListener("click", event => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    if (tool === tab.dataset.tool) return;
    history.pushState(null, "", tab.href);
    selectTool();
  });
}
picker.addEventListener("change", () => {
  cancelRequests();
  resetEvaluation();
  say("health-status");
  say("workspace-status");
  say("bridge-account-note");
  byId("health-details").hidden = true;
  byId("health-timing").hidden = true;
  byId("workspace-list").replaceChildren();
  workspacesLoaded = false;
  syncControls();
  if (tool === "workspaces") loadWorkspaces();
});
source.addEventListener("change", () => {
  resetEvaluation();
  form.elements.key.value = "";
  syncControls();
});
byId("bridge-reload").addEventListener("click", listAccounts);
byId("bridge-check").addEventListener("click", () => runAction("health", async (url, signal) => {
  say("health-status", "正在检查会话…");
  byId("health-details").hidden = true;
  byId("health-timing").hidden = true;
  const data = await (await post(url, {}, signal)).json();
  if (signal.aborted) return;
  say("health-status", data.message, data.healthy ? "success" : "warning");
  const percent = number => Number.isFinite(number) ? number + "%" : "—";
  byId("health-code").textContent = data.status ?? "未收到响应";
  byId("health-five").textContent = percent(data.quota?.five_hour_used_percent);
  byId("health-week").textContent = percent(data.quota?.seven_day_used_percent);
  byId("health-devices").textContent = data.device_count ?? "—";
  const timings = [["检测于", data.checked_at], ["五小时额度重置于", data.quota?.five_hour_resets_at],
    ["七天额度重置于", data.quota?.seven_day_resets_at]];
  byId("health-timing").textContent = timings.filter(([, date]) => date && Number.isFinite(Date.parse(date)))
    .map(([label, date]) => label + " " + new Date(date).toLocaleString("zh-CN")).join(" · ");
  byId("health-timing").hidden = !byId("health-timing").textContent;
  byId("health-details").hidden = false;
}));

const roleNames = {owner: "所有者", member: "成员", admin: "管理员", "workspace-owner": "所有者"};
const seatStates = {active: "在席", joined: "在席", invited: "待接受邀请", pending: "待确认", removed: "已移除",
  unknown: "状态待确认", archived: "已归档", disabled: "已停用", conflicted: "待核对"};
function loadWorkspaces() {
  return runAction("workspaces", async (url, signal) => {
    say("workspace-status", "正在读取工作区…");
    const data = await (await fetchChecked(url, {signal})).json();
    if (signal.aborted) return;
    const list = byId("workspace-list");
    const rows = data.workspaces.map(item => {
      const li = document.createElement("li");
      const link = document.createElement("a");
      link.href = "/accounts?view=teams&workspace=" + encodeURIComponent(item.id);
      link.textContent = item.name || "工作区 #" + item.id;
      const meta = document.createElement("span");
      meta.className = "hint";
      meta.textContent = [roleNames[item.role] || item.role, seatStates[item.state] || item.state].filter(Boolean).join(" · ");
      li.append(link, meta);
      return li;
    });
    list.replaceChildren(...rows);
    say("workspace-status", rows.length ? "共 " + rows.length + " 个工作区" : "这个账号还没有本地工作区记录。");
    workspacesLoaded = true;
  });
}
byId("workspace-refresh").addEventListener("click", loadWorkspaces);

const phases = {queued: "评测已排队", connecting: "正在连接模型…", waiting: "已发送题目，等待模型回答…"};
const grades = {passed: "答案正确", wrong_answer: "答案有误", invalid_format: "输出格式不符", manual_review: "动画已生成，请预览核对"};
form.addEventListener("submit", event => {
  event.preventDefault();
  if (byId("evaluation-start").disabled) return;
  const apiMode = source.value === "api";
  const payload = Object.fromEntries(new FormData(form));
  form.elements.key.value = "";
  resetEvaluation();
  runAction("evaluation", async (url, signal) => {
    say("evaluation-status", "正在提交评测…");
    const output = byId("evaluation-output");
    output.dataset.source = payload.question === "pelican" ? "svg" : "text";
    const answer = document.createTextNode("");
    output.replaceChildren(answer);
    let finished = false;
    const showEvent = packet => {
      if (signal.aborted || finished) return;
      if (packet.type === "phase" && phases[packet.phase]) say("evaluation-status", phases[packet.phase]);
      if (packet.type === "error") {
        finished = true;
        say("evaluation-status", packet.error || "评测中断，未取得完整结果。", "danger");
      }
      if (packet.type === "delta" && typeof packet.delta === "string") {
        say("evaluation-status", "正在接收模型回答…");
        answer.appendData(packet.delta);
        byId("evaluation-result").hidden = false;
      }
      if (packet.type === "complete") {
        finished = true;
        answer.data = packet.output ?? answer.data;
        say("evaluation-status", grades[packet.status] || "评测结束", packet.status === "passed" ? "success" : "warning");
        const sec = n => (n / 1000).toFixed(1) + " 秒";
        byId("evaluation-meta").textContent = [
          Number.isFinite(packet.firstTokenMs) && "首个词元 " + sec(packet.firstTokenMs),
          Number.isFinite(packet.durationMs) && "总耗时 " + sec(packet.durationMs),
          Number.isFinite(packet.outputTokens) && packet.outputTokens + " 个输出词元"
        ].filter(Boolean).join(" · ");
        byId("evaluation-result").hidden = false;
        if (payload.question === "pelican" && packet.status === "manual_review") {
          previewSource = packet.html || answer.data;
          previewToggle.hidden = !previewSource;
        }
      }
    };
    if (apiMode) {
      const {runApiEvaluation} = await import("./bridge-api-evaluation.js");
      try { await runApiEvaluation(payload, signal, showEvent); }
      finally { delete payload.key; }
    } else {
      const response = await post(url, payload, signal);
      await readEvaluationEvents(response.body, showEvent);
    }
    if (!finished && !signal.aborted) throw new Error("连接已结束，未收到完整的评测结果。");
  }, !apiMode);
});
byId("evaluation-stop").addEventListener("click", () => {
  liveRequests.get("evaluation")?.abort();
  say("evaluation-status", "评测已停止。");
});
previewToggle.addEventListener("click", () => {
  if (!preview.hidden) { resetPreview(); return; }
  preview.srcdoc = evaluationPreviewDocument(previewSource);
  preview.hidden = false;
  previewToggle.textContent = "关闭动画";
  previewToggle.setAttribute("aria-expanded", "true");
});
window.addEventListener("pagehide", () => {
  form.elements.key.value = "";
  if (liveRequests.has("evaluation")) say("evaluation-status", "评测已停止。");
  if (liveRequests.has("health")) say("health-status", "检查已中断，请重新检查。");
  if (liveRequests.has("workspaces")) say("workspace-status", "读取已中断，可刷新工作区。");
  cancelRequests();
  syncControls();
});
window.addEventListener("popstate", selectTool);
selectTool();
listAccounts();
