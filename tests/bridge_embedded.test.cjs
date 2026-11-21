const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {registerHooks} = require('node:module');
const {pathToFileURL} = require('node:url');

const hooks = registerHooks({resolve(specifier, context, next) {
  return next(specifier === '/auth-bridge/account-workspace.js'
    ? pathToFileURL(path.join(__dirname, '../vendor/auth-bridge/docs/account-workspace.js')).href : specifier, context);
}});
test.after(() => hooks.deregister());

const script = fs.readFileSync(path.join(__dirname, '../app/web/static/js/bridge-embedded.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

function browser(snapshot = {}) {
  let stored = snapshot;
  const calls = [], messages = [], databases = [], channels = [];
  const listeners = new Map();
  const root = {dataset: {theme: 'dark'}};
  const input = {value: '', disabled: false, dispatchEvent(event) {
    this.event = event.type;
    setTimeout(() => scope.browserWorkspace.save({state: {...stored.state, conversionInput: {text: this.value}}}), 20);
  }};
  class MemoryStorage {
    constructor() { this.data = new Map(); }
    get length() { return this.data.size; }
    key(index) { return [...this.data.keys()][index] ?? null; }
    getItem(key) { return this.data.get(String(key)) ?? null; }
    setItem(key, value) { this.data.set(String(key), String(value)); }
    removeItem(key) { this.data.delete(String(key)); }
    clear() { this.data.clear(); }
  }
  const local = new MemoryStorage();
  const parent = {document: {documentElement: root}, postMessage(data, target) { messages.push({data, target}); }};
  const document = {
    documentElement: {dataset: {}},
    querySelector(selector) {
      if (selector === '#session-input') return input;
      if (selector.includes('.top-nav')) return {dataset: {format: 'sub2api', formatGroup: 'converter'}};
      if (selector.includes('#format-list')) return {dataset: {format: 'sub2api'}};
      return null;
    },
    querySelectorAll() { return []; },
    addEventListener() {},
  };
  const scope = {
    URL, Request, Response, Event, AbortController, TextDecoder, atob, setTimeout, queueMicrotask, Promise,
    location: {origin: 'http://team48.test', href: 'http://team48.test/auth-bridge/'},
    document, parent,
    fetch: async (input, init) => { calls.push({input, init}); return new Response('{}'); },
    indexedDB: {
      open(name, version) { databases.push({method: 'open', name, version}); },
      deleteDatabase(name) { databases.push({method: 'deleteDatabase', name}); },
    },
    BroadcastChannel: class { constructor(name) { channels.push(name); } },
    EventSource: class { constructor(url, options) { this.url = url; this.options = options; } },
    localStorage: local, sessionStorage: new MemoryStorage(),
    MutationObserver: class { observe() {} },
    addEventListener(name, handler) { listeners.set(name, handler); },
    browserWorkspace: {signal: new AbortController().signal, read: async () => stored,
      save: async value => { stored = value; }, clear: async () => {}, clearLoginData: async () => {}},
  };
  scope.window = scope;
  vm.runInNewContext(script, scope, {filename: 'bridge-embedded.js',
    importModuleDynamically: vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER});
  const message = (type, detail = {}, event = {}) => listeners.get('message')({source: parent,
    origin: scope.location.origin, data: {channel: 'team48-auth-bridge', type, ...detail}, ...event});
  const ready = async () => { await scope.fetch('/api/system/config'); await tick(); };
  const authorization = id => listeners.get('team48:authorization-complete')({detail: {id}});
  return {scope, calls, messages, databases, channels, local, input, message, ready, authorization};
}

test('routes only same-origin native API requests to the embedded gateway', async () => {
  const b = browser();
  await b.scope.fetch('/api/v2/accounts/export-sessions?ids=1');
  await b.scope.fetch('/auth-bridge/api/health');
  await b.scope.fetch('https://models.example/api/responses');
  await b.scope.fetch('/api/bridge-workbench/accounts');
  assert.equal(b.calls[0].input, 'http://team48.test/auth-bridge/api/v2/accounts/export-sessions?ids=1');
  assert.equal(b.calls[1].input, 'http://team48.test/auth-bridge/api/health');
  assert.equal(b.calls[2].input, 'https://models.example/api/responses');
  assert.equal(b.calls[3].input, 'http://team48.test/auth-bridge/api/bridge-workbench/accounts');
  const source = new b.scope.EventSource('/api/events', {withCredentials: true});
  assert.equal(source.url, 'http://team48.test/auth-bridge/api/events');
  assert.equal(source.options.withCredentials, true);
});

test('Request routing preserves a POST body, custom headers and cancellation', async () => {
  const b = browser();
  const controller = new AbortController();
  const original = new Request('http://team48.test/api/model-evaluation', {method: 'POST', body: '{"question":"candy"}',
    headers: {'x-operation-id': 'fixture'}, signal: controller.signal});
  const request = new b.scope.Request(original);
  assert.equal(request.url, 'http://team48.test/auth-bridge/api/model-evaluation');
  assert.equal(request.headers.get('x-operation-id'), 'fixture');
  assert.equal(await request.text(), '{"question":"candy"}');
  controller.abort();
  assert.equal(request.signal.aborted, true);
});

test('isolates browser keys, IndexedDB and cross-tab notifications', () => {
  const b = browser();
  b.local.setItem('session-converter-secret', 'standalone');
  b.local.setItem('team48-theme', 'light');
  b.scope.localStorage.setItem('session-converter-secret', 'embedded');
  assert.equal(b.scope.localStorage.getItem('session-converter-secret'), 'embedded');
  assert.equal(b.scope.localStorage.length, 1);
  assert.equal(b.scope.localStorage.key(0), 'session-converter-secret');
  b.scope.localStorage.clear();
  assert.equal(b.local.getItem('session-converter-secret'), 'standalone');
  assert.equal(b.local.getItem('team48-theme'), 'light');
  b.scope.indexedDB.open('session-converter-browser', 1);
  b.scope.indexedDB.deleteDatabase('session-converter-browser');
  new b.scope.BroadcastChannel('session-converter-workspace');
  assert.equal(b.databases[0].name, 'team48.auth-bridge.browser');
  assert.equal(b.databases[1].name, 'team48.auth-bridge.browser');
  assert.deepEqual(b.channels, ['team48.auth-bridge.workspace']);
});

test('announces readiness after native initialization and accepts only its parent', async () => {
  const b = browser();
  assert.equal(b.messages.length, 0);
  await b.ready();
  assert.equal(b.messages[0].data.type, 'ready');
  assert.equal(b.messages[0].target, 'http://team48.test');
  b.message('import-sessions', {requestId: 'ignored', accounts: [{accessToken: 'x'}]}, {origin: 'https://other.test'});
  b.message('import-sessions', {requestId: 'ignored', accounts: [{accessToken: 'x'}]}, {source: {}});
  await tick();
  assert.equal(b.input.value, '');
  b.message('import-sessions', {requestId: 'import-1', accounts: [{accessToken: 'fixture-token',
    password: 'never-forward-password', two_factor_secret: 'never-forward-totp', user: {email: 'demo@example.test'}}]});
  await new Promise(resolve => setTimeout(resolve, 330));
  assert.equal(b.input.event, 'input');
  assert.deepEqual(JSON.parse(b.input.value), {accessToken: 'fixture-token', user: {email: 'demo@example.test'}});
  assert.equal(b.messages.at(-1).data.type, 'imported');
  assert.equal((await b.scope.browserWorkspace.read()).state.conversionInput.text, b.input.value);
});

test('export merges an OAuth credential with its matching Session and preserves conflicts for review', async () => {
  const jwt = (email, workspace, user) => {
    const value = {email, iat: 100, 'https://api.openai.com/auth': {chatgpt_account_id: workspace, chatgpt_user_id: user}};
    return 'eyJhbGciOiJSUzI1NiJ9.' + Buffer.from(JSON.stringify(value)).toString('base64url') + '.fixture';
  };
  const access = jwt('demo@example.test', 'workspace-1', 'user-1');
  const wrong = jwt('other@example.test', 'workspace-1', 'user-other');
  const b = browser({state: {conversionInput: {text: ''}, browserAccounts: [
    {id: 'one', email: 'demo@example.test', openai_access_token: access, openai_rt: 'fixture-refresh',
      session_json: JSON.stringify({user: {email: 'demo@example.test'}, accessToken: access, sessionToken: 'fixture-session'})},
    {id: 'wrong', email: 'demo@example.test', session_json: JSON.stringify({user: {email: 'other@example.test'},
      accessToken: wrong, sessionToken: 'mismatched-session'})},
  ]}});
  await b.ready();
  b.message('export-sessions', {requestId: 'merged'});
  await new Promise(resolve => setTimeout(resolve, 360));
  const result = b.messages.at(-1).data;
  assert.equal(result.type, 'sessions');
  const match = result.accounts.find(record => record.refresh_token === 'fixture-refresh');
  assert.equal(match.session_token, 'fixture-session');
  assert.equal(result.accounts.filter(record => record.access_token === access || record.accessToken === access).length, 1);
  assert.equal(JSON.stringify(match).includes('mismatched-session'), false);
  assert.equal(result.accounts.some(record => record.sessionToken === 'mismatched-session'), true);
});

test('explicit session export combines stored input and workspace projections without login secrets', async () => {
  const b = browser({state: {conversionInput: {text: JSON.stringify({accounts: [{email: 'manual@example.test',
    credentials: {access_token: 'manual-token', refresh_token: 'manual-refresh', password: 'discard-me'}}]})},
    browserAccounts: [{id: 'bridge-1', email: 'login@example.test', openai_access_token: 'personal-token',
      openai_rt: 'personal-refresh', openai_account_id: 'personal', openai_password: 'never-export-password',
      two_factor_secret: 'JBSWY3DPEHPK3PXP', business_workspace_credentials: [
        {workspaceId: 'team', accessToken: 'team-token', refreshToken: 'team-refresh'},
        {workspaceId: 'left', accessToken: 'left-token', status: 'left'},
      ]}]}});
  await b.ready();
  b.message('export-sessions', {requestId: 'sessions-1'});
  await new Promise(resolve => setTimeout(resolve, 360));
  const response = b.messages.at(-1).data;
  assert.equal(response.type, 'sessions');
  assert.equal(response.accounts.length, 3);
  assert.equal(response.accounts[0].credentials.refresh_token, 'manual-refresh');
  assert.equal(response.accounts[1].access_token, 'personal-token');
  assert.equal(response.accounts[2].access_token, 'team-token');
  assert.equal(JSON.stringify(response).includes('never-export-password'), false);
  assert.equal(JSON.stringify(response).includes('discard-me'), false);
  assert.equal(JSON.stringify(response).includes('left-token'), false);
  assert.equal(response.backups.length, 0);
});

test('explicit backup export distinguishes confirmed keys from pending candidates', async () => {
  const b = browser({state: {browserAccounts: [
    {email: 'confirmed@example.test', status: '已换绑2FA', two_factor_secret: 'JBSWY3DPEHPK3PXP', openai_password: 'private-password'},
    {email: 'pending@example.test', status: '已换绑2FA', two_factor_secret: 'OLDKEYVALUEABCDE',
      totp_reset_pending: {secret: 'QJNCOSXD4XN3GUCXT7RWVORI6QDYHR2D', phase: 'activated'}},
    {email: 'normal@example.test', two_factor_secret: 'JBSWY3DPEHPK3PXP'},
  ]}});
  await b.ready();
  b.message('export-backups', {requestId: 'backup-1'});
  await new Promise(resolve => setTimeout(resolve, 330));
  const result = b.messages.at(-1).data;
  assert.equal(result.type, 'backups');
  assert.equal(result.backups.length, 2);
  assert.equal(result.backups[0].phase, 'confirmed');
  assert.equal(result.backups[0].verification, 'official_confirmed');
  assert.equal(result.backups[1].phase, 'activated');
  assert.equal(result.backups[1].verification, 'official_activated');
  assert.equal(JSON.stringify(result).includes('private-password'), false);
  assert.equal(JSON.stringify(result).includes('OLDKEYVALUEABCDE'), false);
});

test('automatic save exports only a newly completed account after parent opt-in, without login secrets', async () => {
  const b = browser({state: {browserAccounts: [
    {id: 'fresh', email: 'fresh@example.test', openai_access_token: 'fresh-at', openai_rt: 'fresh-rt',
      openai_password: 'never-auto-export-password', two_factor_secret: 'NEVEREXPORT2FA'},
    {id: 'old', email: 'old@example.test', openai_access_token: 'old-at', openai_rt: 'old-rt'},
  ]}});
  await b.ready();
  await b.authorization('fresh');
  assert.equal(b.messages.filter(item => item.data.type === 'authorization-complete').length, 0);
  b.message('auto-save', {enabled: true});
  await b.authorization('fresh');
  const saved = b.messages.find(item => item.data.type === 'authorization-complete').data;
  assert.equal(saved.accounts.length, 1);
  assert.equal(saved.accounts[0].email, 'fresh@example.test');
  assert.equal(saved.accounts[0].refresh_token, 'fresh-rt');
  assert.equal(JSON.stringify(saved).includes('never-auto-export-password'), false);
  assert.equal(JSON.stringify(saved).includes('NEVEREXPORT2FA'), false);
  assert.equal(JSON.stringify(saved).includes('old-rt'), false);
  b.message('auto-save', {enabled: false});
  await b.authorization('fresh');
  assert.equal(b.messages.filter(item => item.data.type === 'authorization-complete').length, 1);
});
