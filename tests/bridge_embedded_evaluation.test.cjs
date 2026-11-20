const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const implementation = import('../vendor/auth-bridge/docs/model-evaluation.js');

class Element {
  constructor() {
    this.children = [];
    this.listeners = new Map();
    this.attributes = new Map();
    this.dataset = {};
    this.style = {setProperty() {}};
    this.classList = {add() {}, remove() {}, toggle() {}};
    this.parentElement = {clientWidth: 1024, clientHeight: 768};
    this.contentWindow = {postMessage() {}};
    this.textContent = '';
    this.value = '';
    this.checked = false;
    this.hidden = false;
    this.disabled = false;
    this.selectedOptions = [{textContent: '中等'}];
    this.clientHeight = this.scrollHeight = this.scrollTop = 0;
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  setAttribute(name, value) { this.attributes.set(name, value); }
  removeAttribute(name) { this.attributes.delete(name); }
  querySelector() { return new Element(); }
  querySelectorAll() { return []; }
  getBoundingClientRect() { return {height: 70}; }
}

function fixture({candy = true, pelican = false, legacy = false} = {}) {
  const nodes = new Map();
  const find = name => {
    if (name === 'include-candy' && legacy) return null;
    if (!nodes.has(name)) nodes.set(name, new Element());
    return nodes.get(name);
  };
  const panel = new Element();
  panel.querySelector = selector => {
    if (selector.startsWith('#evaluation-')) return find(selector.slice('#evaluation-'.length));
    if (selector === '[data-evaluation-start]') return find('start');
    if (selector === '[data-evaluation-stop]') return find('stop');
    if (selector === '[data-evaluation-results]') return find('results');
    if (selector === 'input[name="evaluation-source"]:checked') return {value: 'accounts'};
    throw new Error('Unsupported selector in fixture: ' + selector);
  };
  global.document = {
    querySelector: selector => selector === '#model-evaluation' ? panel : new Element(),
    createElement: () => new Element(),
  };
  global.window = {markdownit: () => ({disable() {}, render: value => value})};
  global.ResizeObserver = class { observe() {} };
  find('model').value = 'fixture-model';
  find('reasoning-effort').value = 'medium';
  find('include-pelican').checked = pelican;
  if (!legacy) find('include-candy').checked = candy;
  return {find};
}

for (const scenario of [
  {name: 'default candy', candy: true, pelican: false, expected: ['candy'], title: '糖果题'},
  {name: 'pelican only', candy: false, pelican: true, expected: ['pelican'], title: '鹈鹕骑自行车'},
  {name: 'both questions', candy: true, pelican: true, expected: ['candy', 'pelican'], title: '鹈鹕骑自行车'},
  {name: 'legacy markup default', legacy: true, pelican: false, expected: ['candy'], title: '糖果题'},
]) {
  test('embedded evaluation runs ' + scenario.name + ' through the existing queue', async () => {
    const {initializeModelEvaluation} = await implementation;
    const {find} = fixture(scenario);
    const requested = [];
    initializeModelEvaluation({
      getEligibility: () => ({accounts: [{email: 'fixture@example.org'}], total: 1}),
      getConcurrency: () => 2,
      getHeaders: headers => headers,
      isWorkspaceCurrent: () => () => true,
      request: async (url, options) => {
        assert.equal(url, '/api/model-evaluation');
        const payload = JSON.parse(options.body);
        requested.push(payload.question);
        const result = {type: 'complete', status: payload.question === 'candy' ? 'passed' : 'manual_review',
          output: 'fixture output', durationMs: 10};
        return new Response('data: ' + JSON.stringify(result) + '\n\n', {headers: {'Content-Type': 'text/event-stream'}});
      },
    });
    assert.equal(find('start').disabled, false);
    await find('form').listeners.get('submit')({preventDefault() {}});
    assert.deepEqual(requested, scenario.expected);
    assert.equal(find('case-title').textContent, scenario.title);
    assert.equal(find('progress-count').textContent, scenario.expected.length + ' / ' + scenario.expected.length);
    assert.equal(find('queue-count').textContent, scenario.expected.length + ' 项');
    assert.equal(find('start').disabled, false);
  });
}

test('zero selected questions disables start and guards form submission', async () => {
  const {initializeModelEvaluation} = await implementation;
  const {find} = fixture({candy: false, pelican: false});
  let calls = 0;
  initializeModelEvaluation({
    getEligibility: () => ({accounts: [{email: 'fixture@example.org'}], total: 1}),
    getConcurrency: () => 2,
    getHeaders: headers => headers,
    isWorkspaceCurrent: () => () => true,
    request: async () => { calls++; throw new Error('must not submit'); },
  });
  assert.equal(find('start').disabled, true);
  await find('form').listeners.get('submit')({preventDefault() {}});
  assert.equal(calls, 0);
  assert.equal(find('status').textContent, '请至少选择一道测试题。');
  find('include-pelican').checked = true;
  find('include-pelican').listeners.get('change')();
  assert.equal(find('start').disabled, false);
});

test('native markup keeps candy selected and both questions independently selectable', () => {
  const html = fs.readFileSync(path.join(__dirname, '../vendor/auth-bridge/docs/index.html'), 'utf8');
  assert.match(html, /id="evaluation-include-candy"[^>]*\bchecked/);
  assert.doesNotMatch(html, /id="evaluation-include-pelican"[^>]*\bchecked/);
  assert.doesNotMatch(html, /默认必测/);
});
