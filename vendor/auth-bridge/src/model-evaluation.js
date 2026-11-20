import { createProxiedFetch, resolveSessionProxy } from '../login-service/lib/proxy-config.js';
import { runAccountTask } from '../login-service/lib/task-concurrency.js';
import { evaluationParameters, evaluationApi, requestEvaluation, evaluationTimeoutMs } from '../docs/evaluation-core.js';

export { EVALUATION_QUESTIONS, gradeEvaluation, parseEvaluationResponse } from '../docs/evaluation-core.js';

export function validateEvaluation(body = {}) {
  const { account, api, question, model, reasoningEffort } = body || {};
  const params = evaluationParameters({ question, model, reasoningEffort, protocol: api?.protocol });
  if (api) return { ...params, ...evaluationApi(api) };
  if (params.reasoningEffort === 'ultra') {
    throw Object.assign(new Error('账号模式的 ultra 需要 Codex 客户端执行任务委派。单次模型测试请另选思考程度。'), { statusCode: 400 });
  }
  if (typeof account?.accessToken !== 'string' || !account.accessToken.trim() || account.accessToken.length > 32768 || /[\r\n]/.test(account.accessToken)
    || (account.accountId != null && (typeof account.accountId !== 'string' || account.accountId.length > 200 || /[\r\n]/.test(account.accountId)))) {
    throw Object.assign(new Error('请提供有效账号、模型和测试题'), { statusCode: 400 });
  }
  if (String(account.planType || account.plan_type || '').trim().toLowerCase() === 'free') {
    throw Object.assign(new Error('free 账号不参与模型测试'), { statusCode: 400 });
  }
  return { ...params, account, endpoint: 'https://chatgpt.com/backend-api/codex/responses', key: account.accessToken.trim(), protocol: 'responses' };
}

export async function evaluateModel(body, { signal, fetchImpl, onEvent = () => {} } = {}) {
  const settings = validateEvaluation(body);
  const started = Date.now();
  onEvent({ type: 'phase', phase: 'queued' });
  const run = transport => requestEvaluation(settings, { fetchImpl: transport, signal, onEvent, started });
  if (fetchImpl) return run(fetchImpl);
  const upstreamTimeoutMs = evaluationTimeoutMs(settings.reasoningEffort);
  return runAccountTask(async () => {
    const transport = createProxiedFetch(resolveSessionProxy().proxyUrl, { upstreamTimeoutMs });
    try { return await run(transport); }
    finally { await transport.dispose(); }
  }, { signal });
}
