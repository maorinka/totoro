// UI smoke test for the Wisp console (Playwright, Chromium).
//
//   WISP_URL=http://127.0.0.1:8080 WISP_ADMIN_TOKEN=... WISP_VIEWER_TOKEN=... \
//     node bench/ui_smoke.js
//
// Needs a running console with data (bench/demo_fleet.py). Signs in, renders
// every page in light and dark, exercises triage, filters, keyboard nav, a
// staged rollout (preview must equal the server's cohort), viewer read-only
// mode and a 390px phone layout, and fails on any browser console error.
// Screenshots go to $WISP_SHOTS (default ./ui-shots).
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs = require('fs');
const BASE = process.env.WISP_URL || 'http://127.0.0.1:8080';
const admin = process.env.WISP_ADMIN_TOKEN, viewer = process.env.WISP_VIEWER_TOKEN;
if (!admin || !viewer) { console.error('set WISP_ADMIN_TOKEN and WISP_VIEWER_TOKEN'); process.exit(2); }
const shots = process.env.WISP_SHOTS || 'ui-shots'; fs.mkdirSync(shots, { recursive: true });
const problems = [];
const report = (m) => { problems.push(m); console.log('PROBLEM:', m); };
const ok = (m) => console.log('ok:', m);

async function ctx(browser, opts = {}) {
  const c = await browser.newContext({ viewport: opts.viewport || { width: 1440, height: 900 }, colorScheme: opts.dark ? 'dark' : 'light', deviceScaleFactor: 1 });
  const p = await c.newPage();
  p.on('console', (m) => { if (m.type() === 'error' && !(opts.allow401 && m.text().includes('401'))) report(`console error [${opts.tag || ''}]: ${m.text()}`); });
  p.on('pageerror', (e) => report(`page error [${opts.tag || ''}]: ${e.message}`));
  return { c, p };
}
async function signIn(p, tok) {
  await p.goto(BASE + '/');
  await p.waitForSelector('#signin:not([hidden])');
  await p.fill('#token', tok);
  await p.click('#signin-form button[type=submit]');
  await p.waitForSelector('#app:not([hidden])');
}
async function settle(p) {
  await p.waitForFunction(() => !document.querySelector('#main .loading'), null, { timeout: 8000 });
  await p.waitForTimeout(250);
}
const ROUTES = ['/', '/incidents', '/suggestions', '/analysis', '/alerts', '/hosts', '/investigate?host=web-01', '/vulnerabilities', '/posture', '/rollouts', '/settings'];

(async () => {
  const browser = await chromium.launch();

  // --- sign-in flow -------------------------------------------------------
  {
    const { c, p } = await ctx(browser, { tag: 'signin', allow401: true });
    await p.goto(BASE + '/');
    await p.waitForSelector('#signin:not([hidden])');
    await p.screenshot({ path: `${shots}/signin.png` });
    await p.fill('#token', 'wisp_not-a-real-token-123456');
    await p.click('#signin-form button[type=submit]');
    await p.waitForSelector('#signin-err:not([hidden])');
    const err = await p.textContent('#signin-err');
    err.includes('not accepted') ? ok('bad token rejected with message') : report('bad token message: ' + err);
    await c.close();
  }

  // --- every page, light + dark, desktop ----------------------------------
  for (const dark of [false, true]) {
    const { c, p } = await ctx(browser, { dark, tag: dark ? 'dark' : 'light' });
    await signIn(p, admin);
    for (const r of ROUTES) {
      await p.goto(BASE + r);
      await p.waitForSelector('#app:not([hidden])');
      await settle(p);
      const name = (r === '/' ? 'overview' : r.slice(1).split('?')[0]) + (dark ? '-dark' : '');
      await p.screenshot({ path: `${shots}/${name}.png`, fullPage: true });
      const empty = await p.$$eval('#main .empty b', (els) => els.map((e) => e.textContent));
      const bad = await p.$$eval('#main .empty b', (els) => els.filter((e) => e.textContent.startsWith('Could not load')).length);
      if (bad) report(`${r}: error state shown`);
      ok(`${r} ${dark ? 'dark' : 'light'} rendered${empty.length ? ' (empty states: ' + empty.join('; ') + ')' : ''}`);
    }
    await c.close();
  }

  // --- interactions as admin ----------------------------------------------
  {
    const { c, p } = await ctx(browser, { tag: 'interact' });
    await signIn(p, admin);
    // keyboard nav
    await p.keyboard.press('g'); await p.keyboard.press('a');
    await p.waitForURL('**/alerts'); await settle(p);
    ok('keyboard g a -> alerts');
    // filter by severity via URL-synced control
    await p.selectOption('#alert-sev', 'critical'); await p.waitForTimeout(600);
    const sevs = await p.$$eval('#main tbody tr .sev', (els) => [...new Set(els.map((e) => e.textContent))]);
    (sevs.length && sevs.every((s) => s === 'Critical')) ? ok('severity filter: only Critical rows') : report('severity filter rows: ' + sevs);
    p.url().includes('severity=critical') ? ok('filter synced to URL') : report('filter not in URL: ' + p.url());
    // open first alert, acknowledge it
    await p.click('#main tbody tr.clickable >> nth=0');
    await p.waitForSelector('#drawer:not([hidden])');
    await p.waitForSelector('#drawer-body textarea');
    await p.fill('#triage-note', 'Investigated: expected red-team exercise');
    const id = await p.$eval('#drawer-body dl.kv', (dl) => [...dl.querySelectorAll('dt')].find((d) => d.textContent === 'Alert ID').nextElementSibling.textContent);
    await p.click('#drawer-body button:has-text("Acknowledge")');
    await p.waitForSelector('#toast:not([hidden])');
    const st = await p.evaluate(async ([id, tok]) => { const r = await fetch('/api/alerts?status=all&limit=5000', { headers: { Authorization: 'Bearer ' + tok } }); return (await r.json()).find((a) => a.id === id); }, [id, admin]);
    (st && st.status === 'acknowledged' && st.note.includes('red-team') && st.triaged_by === 'Ada Lovelace') ? ok(`triage persisted (${id} acknowledged by ${st.triaged_by})`) : report('triage: ' + JSON.stringify(st));
    await p.screenshot({ path: `${shots}/alert-drawer.png` });
    await p.keyboard.press('Escape');
    (await p.isHidden('#drawer')) ? ok('Esc closes drawer') : report('drawer still open after Esc');
    // host drawer
    await p.goto(BASE + '/hosts'); await settle(p);
    await p.click('#main tbody tr.clickable >> nth=0');
    await p.waitForSelector('#drawer-body h3'); await p.waitForTimeout(300);
    await p.screenshot({ path: `${shots}/host-drawer.png` });
    await p.keyboard.press('Escape');
    // rollout: preview must equal the server's cohort
    await p.goto(BASE + '/rollouts'); await settle(p);
    await p.selectOption('#ro-group', 'prod-web');
    await p.click('button:has-text("25%")');
    const previewN = Number((await p.textContent('.preview b')).split(' ')[0]);
    await p.click('button:has-text("Start rollout")');
    await p.waitForSelector('#confirm:not([hidden])');
    await p.screenshot({ path: `${shots}/rollout-confirm.png` });
    await p.click('#confirm-yes');
    await p.waitForSelector('#toast:not([hidden])');
    const ro = await p.evaluate(async (tok) => (await (await fetch('/api/policy/rollout', { headers: { Authorization: 'Bearer ' + tok } })).json())[0], admin);
    (ro && ro.cohort.length === previewN && ro.percent === 25 && ro.group === 'prod-web') ? ok(`rollout preview (${previewN}) matched server cohort (${ro.cohort.length}); delivered ${ro.delivered.length}`) : report(`rollout preview ${previewN} vs server ${JSON.stringify(ro)}`);
    await settle(p);
    await p.screenshot({ path: `${shots}/rollouts-after.png`, fullPage: true });
    // incidents: the drawer explains the priority
    await p.goto(BASE + '/incidents'); await settle(p);
    await p.click('#main tbody tr.clickable >> nth=0');
    await p.waitForSelector('#drawer-body .reasons li');
    ok(`incident drawer shows ${await p.locator('#drawer-body .reasons li').count()} priority reasons`);
    const ai = await p.evaluate(async (tok) => (await (await fetch('/api/ai/status', { headers: { Authorization: 'Bearer ' + tok } })).json()), admin);
    if (ai.enabled) {
      const before = await p.locator('#drawer-body .ai-card time').getAttribute('datetime').catch(() => null);
      await p.click('#drawer-body button:has(use[href="#i-spark"])');
      await p.waitForFunction((b) => { const t = document.querySelector('#drawer-body .ai-card time'); return t && t.getAttribute('datetime') !== b; }, before, { timeout: 60000 });
      ok('AI triage rendered in the incident drawer');
    }
    await p.screenshot({ path: `${shots}/incident-drawer.png` });
    await p.keyboard.press('Escape');
    // suggestions: approving one is carried out and recorded
    await p.goto(BASE + '/suggestions'); await settle(p);
    const first = p.locator('.sugg').first();
    if (await first.count()) {
      const title = await first.locator('b.grow').textContent();
      await first.locator('button.primary').click();
      await p.waitForSelector('#confirm:not([hidden])');
      await p.click('#confirm-yes');
      await p.waitForSelector('#toast:not([hidden])');
      const done = await p.evaluate(async ([tok, t]) => (await (await fetch('/api/suggestions?status=all', { headers: { Authorization: 'Bearer ' + tok } })).json()).find((x) => x.title === t), [admin, title]);
      (done && ['applied', 'accepted', 'failed'].includes(done.status) && done.decided_by === 'Ada Lovelace') ? ok(`suggestion "${title}" ${done.status} by ${done.decided_by}`) : report('suggestion approval: ' + JSON.stringify(done));
    } else ok('no suggestions waiting (nothing to approve)');
    await c.close();
  }

  // --- viewer role: no write controls -------------------------------------
  {
    const { c, p } = await ctx(browser, { tag: 'viewer' });
    await signIn(p, viewer);
    await p.goto(BASE + '/rollouts'); await settle(p);
    (await p.$('button:has-text("Start rollout")')) ? report('viewer sees Start rollout') : ok('viewer: rollout planner hidden');
    await p.goto(BASE + '/alerts?status=all'); await settle(p);
    await p.click('#main tbody tr.clickable >> nth=0'); await p.waitForSelector('#drawer-body h3');
    (await p.$('#drawer-body button:has-text("Resolve")')) ? report('viewer sees triage buttons') : ok('viewer: triage read-only');
    await p.keyboard.press('Escape');
    await p.goto(BASE + '/suggestions'); await settle(p);
    (await p.$('.sugg button.primary:not([disabled])')) ? report('viewer can approve suggestions') : ok('viewer: suggestions read-only');
    await c.close();
  }

  // --- phone width: no horizontal page scroll, nav drawer works ------------
  {
    const { c, p } = await ctx(browser, { viewport: { width: 390, height: 844 }, tag: 'mobile' });
    await signIn(p, admin);
    for (const r of ['/', '/incidents', '/suggestions', '/analysis', '/alerts', '/hosts', '/rollouts']) {
      await p.goto(BASE + r); await settle(p);
      const over = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      over > 1 ? report(`${r} at 390px scrolls horizontally by ${over}px`) : ok(`${r} fits 390px`);
      await p.screenshot({ path: `${shots}/mobile-${r === '/' ? 'overview' : r.slice(1)}.png`, fullPage: true });
    }
    await p.click('#menu'); await p.waitForTimeout(300);
    (await p.$eval('#side', (s) => s.classList.contains('open'))) ? ok('mobile nav opens') : report('mobile nav did not open');
    await c.close();
  }
  await browser.close();
  console.log(`\n${problems.length} problem(s)`);
  process.exit(problems.length ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
