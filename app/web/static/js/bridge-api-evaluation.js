import {evaluationApi, evaluationParameters, requestEvaluation} from "/tools/auth-bridge/modules/evaluation-core.js";

// The browser sends the request directly to the provider chosen in the form.
async function fetchProvider(url, options) {
  try {
    return await fetch(url, {...options, mode: "cors", credentials: "omit", redirect: "error",
      cache: "no-store", referrerPolicy: "no-referrer"});
  } catch (error) {
    if (options.signal.aborted) throw error;
    throw new Error("浏览器无法连接模型 API。请检查地址和网络，并确认服务允许当前站点跨域请求（CORS），且地址不会重定向。");
  }
}

export async function runApiEvaluation({baseUrl, key, protocol, question, model, reasoning_effort}, signal, onEvent = () => {}) {
  const settings = evaluationParameters({question, model, reasoningEffort: reasoning_effort, protocol});
  const api = evaluationApi({baseUrl, key, protocol});
  const url = new URL(api.endpoint);
  const loopback = url.hostname === "localhost" || url.hostname === "[::1]" || /^127\.(?:\d+\.){2}\d+$/.test(url.hostname);
  if (url.protocol !== "https:" && !loopback) throw new Error("请填写 HTTPS API 地址。本机回环地址也支持 HTTP。");
  signal?.throwIfAborted();
  onEvent({type: "phase", phase: "queued"});
  try {
    const result = await requestEvaluation({...settings, ...api}, {fetchImpl: fetchProvider, signal, onEvent});
    onEvent({type: "complete", ...result});
    return result;
  } catch (error) {
    signal?.throwIfAborted();
    // Parsing errors can include a preview of a provider's raw response.
    if (error instanceof SyntaxError || error instanceof TypeError) throw new Error("模型 API 返回了无法读取的响应，请核对接口类型。");
    throw error;
  }
}
