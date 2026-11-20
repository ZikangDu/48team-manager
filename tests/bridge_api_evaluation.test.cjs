const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {registerHooks} = require('node:module');

const core = pathToFileURL(path.join(__dirname, '../vendor/auth-bridge/docs/evaluation-core.js')).href;
const hooks = registerHooks({
  resolve(specifier, context, next) {
    return next(specifier === '/tools/auth-bridge/modules/evaluation-core.js' ? core : specifier, context);
  },
});
const client = import('../app/web/static/js/bridge-api-evaluation.js');
test.after(() => hooks.deregister());
const settings = {baseUrl: 'https://models.example.test', key: 'fixture-model-key', protocol: 'responses',
  model: 'fixture-model', question: 'candy', reasoning_effort: 'high'};

test('browser sends one credentialed request to the chosen provider and streams the shared grade', async t => {
  const {runApiEvaluation} = await client;
  const events = [];
  const upstream = [
    {type: 'response.output_text.delta', delta: '答案：21'},
    {type: 'response.completed', response: {status: 'completed', usage: {output_tokens: 5}}},
  ];
  const transport = t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, 'https://models.example.test/v1/responses');
    assert.equal(init.headers.Authorization, 'Bearer fixture-model-key');
    assert.equal(init.credentials, 'omit');
    assert.equal(init.redirect, 'error');
    assert.equal(init.referrerPolicy, 'no-referrer');
    assert.equal(init.mode, 'cors');
    assert.equal(JSON.parse(init.body).reasoning.effort, 'high');
    return new Response(upstream.map(item => 'data: ' + JSON.stringify(item) + '\n\n').join(''));
  });
  const result = await runApiEvaluation(settings, undefined, event => events.push(event));
  assert.equal(transport.mock.callCount(), 1);
  assert.deepEqual(events.map(e => e.phase || e.type), ['queued', 'connecting', 'waiting', 'delta', 'complete']);
  assert.equal(result.status, 'passed');
  assert.equal(result.outputTokens, 5);
  assert.ok(!JSON.stringify(events).includes(settings.key));
});

test('loopback Chat JSON shares the HTML review grade', async t => {
  const {runApiEvaluation} = await client;
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, 'http://[::1]:9123/v1/chat/completions');
    assert.equal(JSON.parse(init.body).reasoning_effort, 'high');
    return Response.json({choices: [{finish_reason: 'stop', message: {content: '<html><svg></svg></html>'}}]});
  });
  const result = await runApiEvaluation({...settings, baseUrl: 'http://[::1]:9123/v1', protocol: 'chat', question: 'pelican'});
  assert.equal(result.status, 'manual_review');
});

test('rejects unsafe destinations before sending the key and reports browser connection failure', async t => {
  const {runApiEvaluation} = await client;
  const transport = t.mock.method(globalThis, 'fetch', async () => { throw new TypeError('opaque browser failure'); });
  for (const baseUrl of ['http://models.example.test', 'https://user:pw@models.example.test', '/relative']) {
    await assert.rejects(runApiEvaluation({...settings, baseUrl}), /API 地址/);
  }
  await assert.rejects(runApiEvaluation(settings, AbortSignal.abort()), {name: 'AbortError'});
  assert.equal(transport.mock.callCount(), 0);
  await assert.rejects(runApiEvaluation(settings), /CORS/);
  assert.equal(transport.mock.callCount(), 1);
});

test('provider errors and malformed responses never echo their raw text or emit a passing result', async t => {
  const {runApiEvaluation} = await client;
  const transport = t.mock.method(globalThis, 'fetch');
  for (const response of [
    new Response(settings.key, {status: 401}),
    new Response('data: ' + settings.key + '\n\n'),
    new Response('data: {"type":"response.output_text.delta","delta":"答案：21"}\n\n'),
  ]) {
    transport.mock.mockImplementationOnce(async () => response);
    const events = [];
    await assert.rejects(runApiEvaluation(settings, undefined, e => events.push(e)), error => !error.message.includes(settings.key));
    assert.ok(events.every(event => event.type !== 'complete'));
  }
});
