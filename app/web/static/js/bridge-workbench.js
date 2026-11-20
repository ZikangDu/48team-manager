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
let evaluationRun = 0;
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
  evaluationRun++;
  resetPreview();
  previewSource = "";
  previewToggle.hidden = true;
  byId("evaluation-result").hidden = true;
  for (const question of ["candy", "pelican"]) {
    byId("evaluation-result-" + question).hidden = true;
    byId("evaluation-output-" + question).replaceChildren();
    byId("evaluation-output-" + question).hidden = true;
    byId("evaluation-meta-" + question).hidden = true;
    byId("evaluation-stop-" + question).hidden = true;
    say("evaluation-status-" + question);
  }
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
  const selected = form.querySelectorAll('[name="question"]:checked').length;
  byId("evaluation-selection").textContent = selected ? "已选 " + selected + " 题 · " + selected + " 次模型请求" : "请选择至少一道题";
  byId("evaluation-start").disabled = testing || !selected || (!apiMode && (!ready || account?.plan?.toLowerCase() === "free"));
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
async function evaluateQuestion(question, {run, url, options, signal, multiple}) {
  const controller = new AbortController();
  const jobSignal = AbortSignal.any([signal, controller.signal]);
  const statusId = "evaluation-status-" + question;
  const output = byId("evaluation-output-" + question);
  const answer = document.createTextNode("");
  output.replaceChildren(answer);
  byId("evaluation-result-" + question).hidden = false;
  const stop = byId("evaluation-stop-" + question);
  stop.hidden = !multiple;
  stop.onclick = () => controller.abort();
  let outcome = "";
  say(statusId, "评测已排队");
  function receive(packet) {
    if (jobSignal.aborted || evaluationRun !== run || outcome) return;
    if (packet.type === "phase" && phases[packet.phase]) say(statusId, phases[packet.phase]);
    if (packet.type === "error") throw new Error(packet.error || "评测中断，未取得完整结果。");
    if (packet.type === "delta" && typeof packet.delta === "string") {
      say(statusId, "正在接收模型回答…");
      answer.appendData(packet.delta);
      output.hidden = false;
    }
    if (packet.type !== "complete") return;
    if (!Object.hasOwn(grades, packet.status)) throw new Error("模型返回了无法识别的评测结果。");
    outcome = "complete";
    stop.hidden = true;
    answer.data = packet.output ?? answer.data;
    output.hidden = !answer.length;
    say(statusId, grades[packet.status], packet.status === "passed" ? "success" : "warning");
    const sec = n => (n / 1000).toFixed(1) + " 秒";
    const meta = byId("evaluation-meta-" + question);
    meta.textContent = [Number.isFinite(packet.firstTokenMs) && "首个词元 " + sec(packet.firstTokenMs),
      Number.isFinite(packet.durationMs) && "总耗时 " + sec(packet.durationMs),
      Number.isFinite(packet.outputTokens) && packet.outputTokens + " 个输出词元"].filter(Boolean).join(" · ");
    meta.hidden = !meta.textContent;
    if (question === "pelican" && packet.status === "manual_review") {
      previewSource = packet.html || answer.data;
      previewToggle.hidden = !previewSource;
    }
  }
  try {
    if (url) {
      const response = await post(url, {...options, question}, jobSignal);
      await readEvaluationEvents(response.body, receive);
    } else {
      const {runApiEvaluation} = await import("./bridge-api-evaluation.js");
      await runApiEvaluation({...options, question}, jobSignal, receive);
    }
    if (!outcome) throw new Error("连接已结束，未收到完整的评测结果。");
  } catch (error) {
    if (!outcome) {
      outcome = jobSignal.aborted ? "cancelled" : "failed";
      if (evaluationRun === run) say(statusId, jobSignal.aborted ? "此题已停止。" :
        error instanceof TypeError ? "连接中断，请检查服务后重试。" : error.message,
        jobSignal.aborted ? "warning" : "danger");
    }
  } finally {
    if (evaluationRun === run) { stop.hidden = true; stop.onclick = null; }
  }
  return outcome;
}

form.addEventListener("change", event => { if (event.target.name === "question") syncControls(); });
form.addEventListener("submit", event => {
  event.preventDefault();
  if (byId("evaluation-start").disabled) return;
  const apiMode = source.value === "api";
  const fields = new FormData(form);
  const questions = fields.getAll("question");
  const options = {model: fields.get("model"), reasoning_effort: fields.get("reasoning_effort")};
  if (apiMode) Object.assign(options, {baseUrl: fields.get("baseUrl"), protocol: fields.get("protocol"), key: fields.get("key")});
  form.elements.key.value = "";
  resetEvaluation();
  const run = evaluationRun;
  runAction("evaluation", async (url, signal) => {
    byId("evaluation-result").hidden = false;
    const results = [];
    const total = questions.length;
    say("evaluation-status", "正在评测 " + total + " 题…");
    try {
      await Promise.all(questions.map(async question => {
        results.push(await evaluateQuestion(question, {run, url, options, signal, multiple: total > 1}));
        if (run !== evaluationRun) return;
        const count = value => results.filter(result => result === value).length;
        const summary = ["已返回结果 " + count("complete") + "/" + total + " 题"];
        if (count("failed")) summary.push(count("failed") + " 题请求失败");
        if (count("cancelled")) summary.push(count("cancelled") + " 题已停止");
        if (results.length < total) summary.push((total - results.length) + " 题进行中");
        say("evaluation-status", summary.join(" · "), count("failed") || count("cancelled") ? "warning" : "");
      }));
    } finally { delete options.key; }
  }, !apiMode);
});
byId("evaluation-stop").addEventListener("click", () => liveRequests.get("evaluation")?.abort());
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
