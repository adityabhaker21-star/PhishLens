/* Run with Node 20+: node tests/extension_regressions.cjs */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const root = path.resolve(__dirname, '..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const event = () => ({ listeners: [], addListener(fn) { this.listeners.push(fn); } });
const tick = () => new Promise(resolve => setImmediate(resolve));

function worker(fetcher) {
  let messages = [], badges = [], storage = {};
  const area = {
    async get(keys) {
      if (keys == null) return structuredClone(storage);
      return Object.fromEntries((Array.isArray(keys) ? keys : [keys])
        .filter(k => k in storage).map(k => [k, structuredClone(storage[k])]));
    },
    async set(values) { Object.assign(storage, structuredClone(values)); },
    async remove(keys) { for (const key of Array.isArray(keys) ? keys : [keys]) delete storage[key]; }
  };
  const chrome = {
    storage: { session: area, local: area },
    runtime: { onMessage: event(), getURL: p => 'chrome-extension://test/' + p },
    tabs: { onCreated: event(), onRemoved: event(),
      sendMessage: async (...args) => messages.push(args),
      update: async () => {}, get: async () => ({ url: 'https://page.test' }) },
    webNavigation: { onBeforeNavigate: event() },
    action: { setBadgeText: x => badges.push(x), setBadgeBackgroundColor: () => {} }
  };
  const context = vm.createContext({
    chrome, fetch: fetcher, URL, TextEncoder, crypto: webcrypto, AbortController,
    AbortSignal, setTimeout, clearTimeout, console: { log() {}, debug() {}, warn() {} }
  });
  vm.runInContext(read('extension/background.js'), context);
  function message(payload, frameId = 0, pageUrl = 'https://page.test') {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('message response timeout')), 3000);
      chrome.runtime.onMessage.listeners[0](payload,
        { tab: { id: 1, url: pageUrl }, frameId },
        response => { clearTimeout(timer); resolve(response); });
    });
  }
  return { context, message, messages, badges, storage, chrome };
}
const response = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });
const safe = id => ({ scan_id: id, score: 0, verdict: 'safe', signals: [] });
const payload = action => ({ url: 'https://page.test', forms: [{ action, has_password: true }] });
const tests = [];
const test = (name, run) => tests.push([name, run]);

test('outage is unknown and is not cached as safe', async () => {
  const w = worker(async () => { throw new Error('offline'); });
  const r = await w.message({ action: 'ANALYZE_PAGE', payload: payload('/login') });
  assert.equal(r.data.verdict, 'unknown');
  assert.equal(r.data.score, null);
  assert.equal(Object.keys(w.storage).filter(k => k.startsWith('cache_')).length, 0);
});

test('invalid backend response is unknown', async () => {
  const w = worker(async () => response({ score: 0, verdict: 'safe' }));
  const r = await w.message({ action: 'ANALYZE_PAGE', payload: payload('/login') });
  assert.equal(r.data.verdict, 'unknown');
});

test('cache distinguishes form destination and manual re-scan bypasses it', async () => {
  let count = 0;
  const w = worker(async url => response(url.endsWith('/analyze') ? safe('s' + ++count) : {}));
  const message = { action: 'ANALYZE_PAGE', payload: payload('/login') };
  await w.message(message);
  await w.message(message);
  assert.equal(count, 1);
  await w.message({ ...message, payload: payload('https://collector.test') });
  assert.equal(count, 2);
  await w.message({ ...message, force: true });
  assert.equal(count, 3);
});

test('changed page text invalidates the cache', async () => {
  let count = 0;
  const w = worker(async url => response(url.endsWith('/analyze') ? safe('s' + ++count) : {}));
  for (const text_snippet of ['Welcome', 'Urgent verify now']) {
    await w.message({ action: 'ANALYZE_PAGE', payload: { ...payload('/login'), text_snippet } });
  }
  assert.equal(count, 2);
});

test('late response cannot overwrite a newer scan', async () => {
  let release, started;
  const firstStarted = new Promise(r => { started = r; });
  let count = 0;
  const w = worker(async url => {
    if (!url.endsWith('/analyze')) return response({});
    if (++count === 1) { started(); return new Promise(r => { release = r; }); }
    return response(safe('new'));
  });
  const old = w.message({ action: 'ANALYZE_PAGE', payload: payload('/old') });
  await firstStarted;
  await w.message({ action: 'ANALYZE_PAGE', payload: payload('/new') });
  release(response(safe('old')));
  assert.equal((await old).success, false);
  const r = await w.message({ action: 'GET_TAB_SCAN', tabId: 1, url: 'https://page.test' });
  assert.equal(r.scan.data.scan_id, 'new');
});

test('popup does not reuse scan from a previous navigation', async () => {
  const w = worker(async () => response(safe('old')));
  await w.message({ action: 'ANALYZE_PAGE', payload: payload('/login') });
  const r = await w.message({ action: 'GET_TAB_SCAN', tabId: 1, url: 'https://different.test' });
  assert.equal(r.scan, null);
});

test('safe child frame does not hide danger in parent', async () => {
  const w = worker(async url => response(url.includes('/explain/') ? {
    advice: 'Leave page', reasons: ['Known threat']
  } : { scan_id: 'danger', score: 100, verdict: 'danger', signals: [] }));
  await w.message({ action: 'ANALYZE_PAGE', payload: payload('/login') });
  await tick();
  await w.chrome.storage.session.set({
    tab_1_2: { pageUrl: 'https://page.test', data: safe('child'), url: 'https://child.test' }
  });
  const r = await w.message({ action: 'GET_TAB_SCAN', tabId: 1, url: 'https://page.test' });
  assert.equal(r.scan.data.verdict, 'danger');
});

test('explanations are sent only to the originating frame', async () => {
  const w = worker(async url => response(url.includes('/explain/') ? {
    advice: 'Leave page', reasons: ['Known threat']
  } : { scan_id: 'danger', score: 100, verdict: 'danger', signals: [] }));
  await w.message({ action: 'ANALYZE_PAGE', payload: payload('/login') }, 7);
  for (let i = 0; i < 10 && w.messages.length === 0; i++) await tick();
  assert.equal(w.messages[0][2].frameId, 7);
});

test('HTTP report failure is reported as failure', async () => {
  const w = worker(async url => response({}, url.endsWith('/report') ? 500 : 200));
  const r = await w.message({ action: 'REPORT_PHISHING', url: 'https://page.test' });
  assert.equal(r.success, false);
});

test('successful report invalidates cached counts', async () => {
  const w = worker(async () => response({ reports_count: 3 }));
  w.storage.cache_old = { data: { reports_count: 1 } };
  const r = await w.message({ action: 'REPORT_PHISHING', url: 'https://page.test' });
  assert.equal(r.data.reports_count, 3);
  assert.equal(w.storage.cache_old, undefined);
});

test('co.uk suffix is not treated as a shared trusted domain', async () => {
  const w = worker(async () => response({}));
  const r = vm.runInContext("evaluateUrlForRogueRedirect('https://casino.co.uk', 'https://example.co.uk')", w.context);
  assert.equal(r.isRogue, true);
});

test('discussing an ad network in a query does not block a clean host', async () => {
  const w = worker(async () => response({}));
  const r = vm.runInContext("evaluateUrlForRogueRedirect('https://research.example/search?q=propellerads', '')", w.context);
  assert.equal(r.isRogue, false);
});

test('offline explanation uses actual evidence instead of Nova Bank fixtures', async () => {
  const w = worker(async () => response({}));
  const r = vm.runInContext("fallbackExplanation({verdict:'danger',signals:[{detail:'Real evidence'}]})", w.context);
  assert.equal(r.reasons[0], 'Real evidence');
  assert.ok(!JSON.stringify(r).includes('Nova Bank'));
});

test('main shield permits a TLD or affiliate parameter alone', async () => {
  const opened = [];
  const document = { readyState: 'loading', addEventListener() {} };
  const window = { location: { href: 'https://example.test', hostname: 'example.test' },
    open: url => { opened.push(url); return null; }, postMessage() {} };
  function HTMLAnchorElement() {}
  HTMLAnchorElement.prototype.click = () => {};
  const context = vm.createContext({ window, document, HTMLAnchorElement, URL,
    setInterval() {}, console: { log() {}, warn() {} } });
  vm.runInContext(read('extension/shield_main.js'), context);
  window.open('https://example.live');
  window.open('https://shop.example?aff_id=123');
  window.open('https://example.top?clickid=123');
  assert.equal(opened.length, 2);
});

test('both dashboards escape untrusted event text', async () => {
  for (const file of ['index.html', 'demo/dashboard.html']) {
    const source = read(file);
    const start = source.indexOf('    function escapeHtml');
    const end = source.indexOf('    function updateDashboard', start);
    const context = vm.createContext({});
    vm.runInContext(source.slice(start, end), context);
    assert.equal(vm.runInContext("escapeHtml('<img src=x onerror=alert(1)>')", context),
      '&lt;img src=x onerror=alert(1)&gt;');
    for (const value of ['ev.url || "N/A"', 'topSignal', 'r', 's.detail', 'adviceText']) {
      assert.ok(source.includes('${escapeHtml(' + value + ')}'), file + ': unescaped ' + value);
    }
  }
});

async function run() {
  const results = [];
  for (const [name, fn] of tests) {
    try { await fn(); results.push('PASS ' + name); }
    catch (error) { results.push('FAIL ' + name + '\n' + error.stack); }
  }
  return { passed: results.filter(x => x.startsWith('PASS')).length, total: tests.length, results };
}
module.exports = { run };
if (require.main === module) run().then(result => {
  console.log(result.results.join('\n'));
  console.log(result.passed + '/' + result.total + ' passed');
  process.exitCode = result.passed === result.total ? 0 : 1;
});
