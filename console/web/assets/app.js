/* Wisp Console -- single-page app, no dependencies.
 *
 * Every element is built with the h() helper, which sets text via
 * textContent: data from sensors (command lines, hostnames, titles) can never
 * become markup. No inline scripts, styles or handlers, so the page runs
 * under a strict Content-Security-Policy.
 */
'use strict';
(() => {
  // ---- DOM helpers ---------------------------------------------------------
  const $ = (s, r = document) => r.querySelector(s);
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'style') Object.assign(el.style, v); // CSSOM: allowed under CSP
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (v === true) el.setAttribute(k, '');
      else el.setAttribute(k, v);
    }
    append(el, kids);
    return el;
  }
  function append(el, kids) {
    for (const k of kids.flat(Infinity)) {
      if (k == null || k === false) continue;
      el.append(k instanceof Node ? k : document.createTextNode(String(k)));
    }
    return el;
  }
  const SVGNS = 'http://www.w3.org/2000/svg';
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null) continue;
      if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const k of kids.flat()) if (k) el.append(k);
    return el;
  }
  function icon(id, cls = 'ic') {
    const svg = document.createElementNS(SVGNS, 'svg');
    svg.setAttribute('class', cls);
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVGNS, 'use');
    use.setAttribute('href', '#' + id);
    svg.append(use);
    return svg;
  }
  const clear = (el) => { el.replaceChildren(); return el; };

  // ---- formatting ----------------------------------------------------------
  const nf = new Intl.NumberFormat();
  const fmtNum = (n) => (n == null ? '–' : nf.format(n));
  const fmtPct = (n, d = 3) => (n == null ? '–' : `${Number(n).toFixed(d)}%`);
  const toDate = (ts) => (ts ? new Date(ts) : null);
  function rel(ts) {
    const d = toDate(ts);
    if (!d || isNaN(d) || d.getFullYear() < 2000) return '–';
    const s = Math.round((Date.now() - d) / 1000);
    if (s < 45) return 'just now';
    const m = Math.round(s / 60);
    if (m < 60) return `${m}m ago`;
    const hr = Math.round(m / 60);
    if (hr < 48) return `${hr}h ago`;
    return `${Math.round(hr / 24)}d ago`;
  }
  const abs = (ts) => { const d = toDate(ts); return d && !isNaN(d) && d.getFullYear() >= 2000 ? d.toLocaleString() : ''; };
  const timeEl = (ts) => h('time', { datetime: ts || '', title: abs(ts), text: rel(ts) });
  const cap = (x) => (x ? x[0].toUpperCase() + x.slice(1) : '');

  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const sevChip = (sev) => {
    const v = SEV.includes(sev) ? sev : 'info';
    return h('span', { class: `sev ${v}` }, icon(`i-sev-${v}`), cap(v));
  };
  const TIER_ICON = { exploited: 'critical', reachable: 'high', dormant: 'medium', theoretical: 'info' };
  const tierChip = (t) => h('span', { class: `tier ${t}` }, icon(`i-sev-${TIER_ICON[t] || 'info'}`), cap(t));
  const stateBadge = (st) => h('span', { class: `badge ${st}` }, h('span', { class: 'dot' }), cap(st));
  const modeBadge = (m) => (m ? h('span', { class: `badge ${m}` }, cap(m)) : h('span', { class: 'muted', text: '–' }));
  const actorBadge = (a, src) => a ? h('span', { class: `badge ${a === 'ai' ? 'ai' : ''}`, title: src || '' }, a === 'ai' ? 'AI agent' : cap(a), src ? h('span', { class: 'muted', text: `· ${src}` }) : null) : h('span', { class: 'muted', text: '–' });
  const gradeEl = (g) => h('span', { class: `grade ${g}`, 'aria-label': `Grade ${g}`, text: g });
  const TRUST = { tpm: 'TPM-backed', dmi: 'Platform (DMI)', 'machine-id': 'Machine ID', generated: 'Generated' };

  // ---- auth + API ----------------------------------------------------------
  const store = {
    get token() { return sessionStorage.getItem('wisp.token') || localStorage.getItem('wisp.token') || ''; },
    setToken(t, remember) { (remember ? localStorage : sessionStorage).setItem('wisp.token', t); },
    clearToken() { sessionStorage.removeItem('wisp.token'); localStorage.removeItem('wisp.token'); },
    pref(k, d) { try { return localStorage.getItem('wisp.' + k) ?? d; } catch { return d; } },
    setPref(k, v) { try { localStorage.setItem('wisp.' + k, v); } catch { /* private mode */ } },
  };
  class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
  async function api(path, opts = {}) {
    const headers = { Accept: 'application/json' };
    if (store.token) headers.Authorization = 'Bearer ' + store.token;
    let body = opts.body;
    if (body && typeof body !== 'string') { body = JSON.stringify(body); headers['Content-Type'] = 'application/json'; }
    let r;
    try {
      r = await fetch(path, { method: opts.method || 'GET', headers, body, cache: 'no-store' });
    } catch {
      setConn(false);
      throw new ApiError('Cannot reach the console. Check that wisp-console is running.', 0);
    }
    setConn(true);
    if (r.status === 401) { showSignin('Your session is no longer valid. Sign in again.'); throw new ApiError('Not signed in', 401); }
    let data = null;
    try { data = await r.json(); } catch { /* empty */ }
    if (!r.ok) throw new ApiError((data && data.error) || `Request failed (${r.status})`, r.status);
    return data;
  }
  const qs = (o) => { const p = new URLSearchParams(); for (const [k, v] of Object.entries(o)) if (v !== '' && v != null) p.set(k, v); const s = p.toString(); return s ? '?' + s : ''; };

  // ---- session state -------------------------------------------------------
  const RANK = { viewer: 1, deployer: 2, operator: 3, admin: 4 };
  let me = { role: '', name: '' };
  const can = (role) => (RANK[me.role] || 0) >= RANK[role];

  // ---- chrome: theme, live indicator, toast, banner ------------------------
  function applyTheme() {
    const t = store.pref('theme', 'system');
    if (t === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    const dark = t === 'dark' || (t === 'system' && matchMedia('(prefers-color-scheme: dark)').matches);
    const btn = $('#theme');
    clear(btn).append(icon(dark ? 'i-sun' : 'i-moon'));
    btn.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
  }
  let lastOk = 0, connDown = false;
  function setConn(ok) {
    connDown = !ok;
    if (ok) lastOk = Date.now();
    const b = $('#banner');
    if (!ok) { b.textContent = 'The console is unreachable. Data shown may be out of date; retrying automatically.'; b.hidden = false; }
    else b.hidden = true;
    paintLive();
  }
  function paintLive() {
    const el = $('#live');
    el.className = 'live' + (paused ? ' paused' : connDown ? ' down' : '');
    clear(el).append(h('span', { text: paused ? 'Paused' : connDown ? 'Offline' : lastOk ? `Updated ${rel(new Date(lastOk).toISOString())}` : 'Live' }));
  }
  let toastTimer;
  function toast(msg, err) {
    const t = $('#toast');
    t.textContent = msg; t.className = 'toast' + (err ? ' err' : ''); t.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 4200);
  }

  // ---- tooltip (charts) ----------------------------------------------------
  const tip = { show(ev, nodes) { const t = $('#tip'); clear(t).append(...nodes); t.hidden = false; this.move(ev); },
    move(ev) { const t = $('#tip'); const x = Math.min(ev.clientX + 14, innerWidth - t.offsetWidth - 8); t.style.left = x + 'px'; t.style.top = (ev.clientY + 14) + 'px'; },
    hide() { $('#tip').hidden = true; } };

  // ---- drawer + confirm (focus-managed dialogs) ----------------------------
  let drawerReturn = null;
  function openDrawer(title, build) {
    drawerReturn = document.activeElement;
    $('#drawer-title').textContent = title;
    const body = clear($('#drawer-body'));
    $('#drawer').hidden = false;
    body.append(h('div', { class: 'loading', text: 'Loading…' }));
    Promise.resolve(build(body)).catch((e) => { clear(body).append(errorBox(e)); });
    $('#drawer-close').focus();
  }
  function closeDrawer() {
    $('#drawer').hidden = true;
    if (drawerReturn && drawerReturn.focus) drawerReturn.focus();
  }
  function trapFocus(container, ev) {
    if (ev.key !== 'Tab') return;
    const f = [...container.querySelectorAll('a[href],button:not([disabled]),input,select,textarea,[tabindex]:not([tabindex="-1"])')].filter((x) => x.offsetParent !== null);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (ev.shiftKey && document.activeElement === first) { last.focus(); ev.preventDefault(); }
    else if (!ev.shiftKey && document.activeElement === last) { first.focus(); ev.preventDefault(); }
  }
  function confirmDialog(title, bodyNodes, yesLabel = 'Confirm', danger = false) {
    return new Promise((resolve) => {
      const m = $('#confirm'), prev = document.activeElement;
      $('#confirm-title').textContent = title;
      clear($('#confirm-body')).append(...[].concat(bodyNodes));
      const yes = $('#confirm-yes'), no = $('#confirm-no');
      yes.textContent = yesLabel; yes.className = 'btn ' + (danger ? 'danger' : 'primary');
      m.hidden = false; no.focus();
      const done = (v) => { m.hidden = true; yes.onclick = no.onclick = m.onkeydown = null; if (prev && prev.focus) prev.focus(); resolve(v); };
      yes.onclick = () => done(true); no.onclick = () => done(false);
      m.onkeydown = (e) => { if (e.key === 'Escape') done(false); trapFocus(m, e); };
    });
  }

  // ---- generic building blocks ---------------------------------------------
  function errorBox(e) {
    return h('div', { class: 'empty' }, h('b', { text: 'Could not load this view' }), e.message || String(e));
  }
  function empty(title, text) { return h('div', { class: 'empty' }, h('b', { text: title }), text || ''); }
  function table(cols, rows, { onRow, rowLabel, emptyNode, page = 0 } = {}) {
    if (!rows.length) return h('div', { class: 'tablewrap' }, emptyNode || empty('Nothing to show'));
    if (page && rows.length > page) {
      // Render a page at a time so long lists stay fast and scannable.
      const wrap = h('div', {});
      let shown = page;
      const draw = () => {
        const more = rows.length - shown;
        clear(wrap).append(table(cols, rows.slice(0, shown), { onRow, rowLabel, emptyNode }),
          more > 0 ? h('div', { class: 'row', style: { justifyContent: 'center', marginTop: '12px' } },
            h('button', { class: 'btn', type: 'button', onclick: () => { shown += page; draw(); } }, `Show ${Math.min(page, more)} more`),
            h('span', { class: 'muted', text: `${fmtNum(shown)} of ${fmtNum(rows.length)}` })) : null);
      };
      draw();
      return wrap;
    }
    const thead = h('thead', {}, h('tr', {}, cols.map((c) => h('th', { scope: 'col', class: c.num ? 'num' : '' }, c.label))));
    const tbody = h('tbody', {}, rows.map((r) => {
      const tr = h('tr', onRow ? { class: 'clickable', tabindex: '0', 'aria-label': rowLabel ? rowLabel(r) : null } : {},
        cols.map((c) => h('td', { class: c.num ? 'num' : c.cls || '' }, c.cell(r))));
      if (onRow) {
        tr.addEventListener('click', () => onRow(r, tr));
        tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onRow(r, tr); } });
      }
      return tr;
    }));
    return h('div', { class: 'tablewrap' }, h('table', {}, thead, tbody));
  }
  function seg(options, value, onChange, label) {
    const g = h('div', { class: 'seg', role: 'group', 'aria-label': label });
    for (const [v, text] of options) {
      g.append(h('button', { type: 'button', 'aria-pressed': String(v === value), onclick: () => {
        g.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', 'false'));
        g.querySelector(`[data-v="${CSS.escape(v)}"]`).setAttribute('aria-pressed', 'true');
        onChange(v);
      }, dataset: { v } }, text));
    }
    return g;
  }
  function select(id, options, value, onChange) {
    const el = h('select', { id, onchange: () => onChange(el.value) }, options.map(([v, t]) => h('option', { value: v, text: t })));
    el.value = value;
    return el;
  }
  const debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  // Column chart: one series, columns <= 24px with a 4px rounded data end and
  // a square baseline, hairline grid, a hover tooltip per column, and a table
  // view for screen readers / exact values.
  function columnChart(data, { height = 160, label = '', unit = '' } = {}) {
    const W = 640, H = height, padL = 30, padB = 22, padT = 10;
    const max = Math.max(1, ...data.map((d) => d.value));
    const step = niceStep(max);
    const top = Math.ceil(max / step) * step;
    const y = (v) => padT + (H - padT - padB) * (1 - v / top);
    const band = (W - padL) / data.length;
    const bw = Math.min(24, band - 2);
    const svg = s('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': label });
    for (let v = 0; v <= top; v += step) {
      svg.append(s('line', { class: v === 0 ? 'baseline' : 'grid-line', x1: padL, x2: W, y1: y(v), y2: y(v) }));
      svg.append(s('text', { class: 'tick', x: padL - 6, y: y(v) + 4, 'text-anchor': 'end', text: fmtNum(v) }));
    }
    data.forEach((d, i) => {
      const x = padL + i * band + (band - bw) / 2;
      const yy = y(d.value), hgt = H - padB - yy;
      const r = Math.min(4, hgt);
      const path = hgt <= 0 ? null : s('path', { class: 'bar', d: `M${x},${H - padB}V${yy + r}Q${x},${yy} ${x + r},${yy}H${x + bw - r}Q${x + bw},${yy} ${x + bw},${yy + r}V${H - padB}Z` });
      const hit = s('rect', { class: 'bar-hit', x: padL + i * band, y: padT, width: band, height: H - padT - padB, tabindex: '-1' });
      hit.addEventListener('mouseenter', (ev) => { path && path.classList.add('hot'); tip.show(ev, [h('b', { text: `${fmtNum(d.value)}${unit}` }), h('div', { class: 'muted', text: d.tip || d.label })]); });
      hit.addEventListener('mousemove', (ev) => tip.move(ev));
      hit.addEventListener('mouseleave', () => { path && path.classList.remove('hot'); tip.hide(); });
      svg.append(hit);
      if (path) svg.append(path);
      if (d.tick) svg.append(s('text', { class: 'tick', x: padL + i * band + band / 2, y: H - 6, 'text-anchor': 'middle', text: d.tick }));
    });
    const tv = h('details', { class: 'table-view' }, h('summary', { text: 'Show as table' }),
      table([{ label: 'Period', cell: (d) => d.tip || d.label }, { label: 'Count', num: true, cell: (d) => fmtNum(d.value) }], data));
    return h('div', { class: 'chart' }, svg, tv);
  }
  function niceStep(max) {
    const raw = max / 4, p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 5, 10]) if (raw <= m * p) return Math.max(1, m * p);
    return Math.max(1, 10 * p);
  }
  function gauge(score) {
    const r = 46, cx = 60, cy = 60, a0 = Math.PI, frac = Math.max(0, Math.min(1, score / 100));
    const pt = (f) => [cx + r * Math.cos(a0 + Math.PI * f), cy + r * Math.sin(a0 + Math.PI * f)];
    const [x0, y0] = pt(0), [x1, y1] = pt(1), [xf, yf] = pt(frac);
    const svg = s('svg', { viewBox: '0 0 120 66', 'aria-hidden': 'true' },
      s('path', { class: 'track', d: `M${x0},${y0}A${r},${r} 0 0 1 ${x1},${y1}`, fill: 'none', 'stroke-width': 10, 'stroke-linecap': 'round' }),
      frac > 0 ? s('path', { class: 'fill' + (score < 60 ? ' crit' : score < 75 ? ' warn' : ''), d: `M${x0},${y0}A${r},${r} 0 0 1 ${xf},${yf}`, fill: 'none', 'stroke-width': 10, 'stroke-linecap': 'round' }) : null);
    return svg;
  }
  function meter(value, max, { inline = false, label } = {}) {
    const f = Math.max(0, Math.min(1, value / max));
    const m = h('div', { class: `meter${inline ? ' inline' : ''}${f >= 1 ? ' crit' : f >= 0.8 ? ' warn' : ''}`, role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': String(max), 'aria-valuenow': String(value), 'aria-label': label || '' },
      h('span', { style: { width: `${Math.max(2, f * 100)}%` } }));
    return m;
  }

  // ---- shared drawers ------------------------------------------------------
  function alertDrawer(a, onChange) {
    openDrawer(a.title || a.rule, (body) => {
      clear(body);
      body.append(h('div', { class: 'row' }, sevChip(a.severity), h('span', { class: 'badge' }, cap(a.status || 'open')),
        a.actor ? actorBadge(a.actor, a.actor_src) : null));
      const kv = h('dl', { class: 'kv' });
      const add = (k, v) => { if (v !== '' && v != null && v !== 0) kv.append(h('dt', { text: k }), h('dd', {}, v)); };
      add('Detection', h('span', {}, h('b', { text: a.rule }), a.mitre ? [' · ', h('a', { href: `https://attack.mitre.org/techniques/${a.mitre.replace('.', '/')}/`, target: '_blank', rel: 'noopener noreferrer' }, a.mitre, ' ', icon('i-ext', 'ic small'))] : null));
      add('Host', h('a', { href: '#', onclick: (e) => { e.preventDefault(); hostDrawer(a.host); } }, a.host));
      add('Time', `${abs(a.ts)} (${rel(a.ts)})`);
      add('Response', a.action);
      add('Process', a.comm ? `${a.comm}  (pid ${a.pid || '–'}, parent ${a.ppid || '–'}, uid ${a.uid ?? '–'})` : '');
      add('Executable', a.exe ? h('code', { text: a.exe }) : '');
      add('Destination', a.dest ? h('code', { text: `${a.dest}:${a.dport}` }) : '');
      add('Alert ID', h('code', { text: a.id }));
      body.append(kv);
      if (a.cmd) body.append(h('div', {}, h('h3', { text: 'Command line' }), h('pre', { class: 'block', text: a.cmd })));

      const tri = h('div', {}, h('h3', { text: 'Triage' }));
      if (a.triaged_by) tri.append(h('p', { class: 'muted' }, `${cap(a.status)} by ${a.triaged_by} ${rel(a.triaged_at)}`, a.note ? [':', h('br'), h('span', { text: a.note })] : ''));
      if (can('operator')) {
        const note = h('textarea', { id: 'triage-note', 'aria-label': 'Triage note', placeholder: 'What did you find? (optional)' });
        note.value = a.note || '';
        const act = (status, label) => h('button', { class: 'btn small' + (status === 'resolved' ? ' primary' : ''), type: 'button', disabled: a.status === status, onclick: async () => {
          try {
            const upd = await api('/api/alerts/triage', { method: 'POST', body: { id: a.id, status, note: note.value } });
            toast({ acknowledged: 'Alert acknowledged', resolved: 'Alert resolved', open: 'Alert reopened' }[status]); Object.assign(a, upd); onChange && onChange(); alertDrawer(a, onChange);
          } catch (e) { toast(e.message, true); }
        } }, label);
        tri.append(note, h('div', { class: 'row', style: { marginTop: '8px' } }, act('acknowledged', 'Acknowledge'), act('resolved', 'Resolve'), act('open', 'Reopen')));
      } else {
        tri.append(h('p', { class: 'muted', text: 'Triage requires the operator role.' }));
      }
      body.append(tri);
      const inv = h('div', {}, h('h3', { text: 'Investigate' }),
        h('div', { class: 'row' },
          h('a', { class: 'btn small', href: `/investigate${qs({ host: a.host, pid: a.pid || '' })}` }, 'Events for this process'),
          h('a', { class: 'btn small', href: `/alerts${qs({ host: a.host, status: 'all' })}` }, 'All alerts on host')),
        a.pid ? h('p', { class: 'hint' }, 'Full process tree, including every exec and network flow, from the host itself: ', h('code', { text: `sudo wispd --search tree=${a.pid}` })) : null);
      body.append(inv);
    });
  }

  async function hostDrawer(name) {
    openDrawer(name, async (body) => {
      const d = await api('/api/hosts/detail' + qs({ name }));
      const hst = d.host;
      clear(body);
      body.append(h('div', { class: 'row' }, stateBadge(hst.state), modeBadge(hst.mode), hst.ephemeral ? h('span', { class: 'badge', text: 'Ephemeral' }) : null,
        h('span', { class: 'badge' }, h('span', { class: 'dot' + (hst.connected ? ' on' : '') }), hst.connected ? 'Connected' : 'Not connected')));
      if (d.posture) {
        body.append(h('div', { class: 'card' }, h('div', { class: 'row' }, gradeEl(d.posture.grade), h('b', { text: `Posture ${d.posture.score}/100` })),
          d.posture.findings.length ? h('ul', { class: 'findings' }, d.posture.findings.map((f) => h('li', { text: f }))) : h('p', { class: 'muted', text: 'No findings.' })));
      }
      body.append(h('dl', { class: 'kv' },
        h('dt', { text: 'Group' }), h('dd', { text: hst.group || '–' }),
        h('dt', { text: 'Identity' }), h('dd', {}, TRUST[hst.trust] || hst.trust || '–', hst.host_id ? h('div', { class: 'muted mono', text: hst.host_id }) : null),
        h('dt', { text: 'Sensor' }), h('dd', { text: `wispd ${hst.version || '–'}` }),
        h('dt', { text: 'Sensor CPU' }), h('dd', {}, `${fmtPct(hst.cpu_pct)} now · ${fmtPct(hst.peak_cpu)} peak`, meter(hst.cpu_pct, 0.05, { inline: true, label: 'CPU against the 0.05% budget' })),
        h('dt', { text: 'Memory' }), h('dd', { text: hst.rss_kb ? `${(hst.rss_kb / 1024).toFixed(1)} MiB` : '–' }),
        h('dt', { text: 'Runtimes seen' }), h('dd', { text: (hst.runtimes || []).join(', ') || '–' }),
        h('dt', { text: 'First seen' }), h('dd', { text: abs(hst.first_seen) || '–' }),
        h('dt', { text: 'Last seen' }), h('dd', { text: `${abs(hst.last_seen)} (${rel(hst.last_seen)})` }),
        hst.decommissioned ? [h('dt', { text: 'Decommissioned' }), h('dd', { text: `${hst.decommissioned}, ${abs(hst.decommissioned_at)}` })] : null));
      if (can('operator') && hst.state !== 'decommissioned') {
        const push = (action, label, msg) => h('button', { class: 'btn small', type: 'button', disabled: !hst.connected, onclick: async () => {
          if (!(await confirmDialog(`${label} on ${name}?`, h('p', { text: msg }), label))) return;
          try {
            const r = await api('/api/policy/push' + qs({ host: name, action }), { method: 'POST' });
            toast(r.delivered ? `${label}: sent to ${name}` : `${name} is not connected; nothing sent`, !r.delivered);
          } catch (e) { toast(e.message, true); }
        } }, label);
        body.append(h('div', {}, h('h3', { text: 'Policy' }), h('div', { class: 'row' },
          push('reload', 'Reload policy', 'The sensor re-reads its rules and catalog from disk.'),
          push('enforce', 'Switch to enforce', 'Policy violations will be blocked: matching processes are killed. Make sure the rules are tuned in monitor mode first.'),
          push('monitor', 'Switch to monitor', 'Violations will be reported but not blocked.')),
          !hst.connected ? h('p', { class: 'muted', text: 'Actions need a live sensor connection.' }) : null));
      }
      body.append(h('div', {}, h('h3', { text: `Recent alerts (${d.alerts.length})` }),
        table([{ label: 'Severity', cell: (a) => sevChip(a.severity) }, { label: 'Detection', cell: (a) => a.title || a.rule }, { label: 'When', cell: (a) => timeEl(a.ts) }],
          d.alerts.slice(0, 15), { onRow: (a) => alertDrawer(a), emptyNode: empty('No alerts from this host') })));
      body.append(h('div', {}, h('h3', { text: `Software inventory (${d.inventory.length})` }),
        table([{ label: 'Kind', cell: (e) => e.kind }, { label: 'Name', cell: (e) => h('code', { text: e.name }) }, { label: 'Version', cell: (e) => e.version || '–' }],
          d.inventory, { emptyNode: empty('No inventory reported yet') })));
    });
  }

  // ---- analysis: incidents, suggestions, AI ---------------------------------
  const PRIO = { P1: 'critical', P2: 'high', P3: 'medium', P4: 'info' };
  const prioChip = (p) => h('span', { class: `sev ${PRIO[p] || 'info'}`, title: 'Priority' }, icon(`i-sev-${PRIO[p] || 'info'}`), p || '–');
  const VERDICT = { malicious: 'critical', suspicious: 'medium', benign: 'info' };
  const verdictChip = (v) => h('span', { class: `sev ${VERDICT[v] || 'info'}` }, icon(`i-sev-${VERDICT[v] || 'info'}`), cap(v || 'unknown'));
  const aiBadge = () => h('span', { class: 'badge ai', title: 'Proposed by the AI assistant' }, icon('i-spark', 'ic small'), 'AI');
  const KIND = { contain: 'Contain', rollout: 'Gradual enforcement', tune_rule: 'Rule tuning', enforce_rule: 'Rule hardening', close_stale: 'Housekeeping',
    patch: 'Patch', ai_push: 'Policy push', ai_rollout: 'Rollout', ai_triage: 'Triage', ai_manual: 'Manual step', ai_rule: 'Rule change' };

  let aiStatus = null;
  async function getAiStatus() {
    try { aiStatus = await api('/api/ai/status'); } catch { aiStatus = { enabled: false, reason: 'unavailable' }; }
    return aiStatus;
  }
  // Start an AI job and wait for it (the console runs it in the background).
  async function runAiJob(kind, body, onProgress) {
    let job = await api(`/api/ai/${kind}`, { method: 'POST', body });
    const t0 = Date.now();
    while (job.status === 'queued' || job.status === 'running') {
      onProgress && onProgress(job, Math.round((Date.now() - t0) / 1000));
      await new Promise((r) => setTimeout(r, 1000));
      job = await api('/api/ai/jobs' + qs({ id: job.id }));
    }
    if (job.status === 'failed') throw new ApiError(job.error || 'The AI request failed', 0);
    return job;
  }
  function aiButton(label, kind, body, after) {
    if (!can('operator')) return h('p', { class: 'muted', text: 'Asking the AI assistant requires the operator role.' });
    if (aiStatus && !aiStatus.enabled) return h('p', { class: 'muted' }, 'The AI assistant is off. ', aiStatus.reason || '');
    const status = h('span', { class: 'muted', role: 'status', 'aria-live': 'polite' });
    const btn = h('button', { class: 'btn small', type: 'button', onclick: async () => {
      btn.disabled = true;
      try {
        const job = await runAiJob(kind, body, (j, secs) => { status.textContent = `${j.status === 'queued' ? 'Queued' : 'Thinking'}… ${secs}s`; });
        status.textContent = '';
        toast('AI analysis ready');
        after(job);
      } catch (e) { status.textContent = ''; toast(e.message, true); btn.disabled = false; }
    } }, icon('i-spark'), label);
    return h('div', { class: 'row' }, btn, status);
  }

  function describeAction(a) {
    if (!a) return '';
    if (a.type === 'push') return `Send “${actionLabel(a.control)}” to ${a.host}`;
    if (a.type === 'rollout') return `${actionLabel(a.control)} for ${a.percent}% of ${a.group || 'all groups'}`;
    if (a.type === 'triage') return `Mark ${a.alerts.length} alert${a.alerts.length === 1 ? '' : 's'} ${a.status}`;
    return 'Manual step (the console records your decision; you make the change)';
  }

  async function decide(sg, approve, onDone) {
    const note = h('textarea', { 'aria-label': 'Note', placeholder: approve ? 'Note for the audit trail (optional)' : 'Why not? (optional, kept in the audit trail)' });
    const body = [h('p', { text: describeAction(sg.action) })];
    if (sg.action.type === 'manual') body.push(h('pre', { class: 'block', text: sg.action.instructions }));
    else if (approve) body.push(h('p', { class: 'muted', text: 'The console carries this out now and records it with your name.' }));
    body.push(note);
    const ok = await confirmDialog(approve ? (sg.action.type === 'manual' ? 'Accept this suggestion?' : 'Approve and apply?') : 'Reject this suggestion?', body,
      approve ? (sg.action.type === 'manual' ? 'Accept' : 'Approve') : 'Reject', approve && sg.action.type !== 'manual' && sg.action.control === 'enforce');
    if (!ok) return;
    try {
      const r = await api('/api/suggestions/decide', { method: 'POST', body: { id: sg.id, decision: approve ? 'approve' : 'reject', note: note.value } });
      toast(r.status === 'failed' ? `Could not apply: ${r.result}` : `${cap(r.status)}: ${r.result}`, r.status === 'failed');
      onDone && onDone();
    } catch (e) { toast(e.message, true); }
  }

  function suggestionCard(sg, onDone) {
    const allowed = can(sg.required_role);
    const ev = (sg.evidence || []).map((x) => x.startsWith('INC-')
      ? h('a', { href: '#', onclick: (e) => { e.preventDefault(); incidentDrawer(x, onDone); } }, 'incident')
      : x.startsWith('rule:') ? h('a', { href: '/analysis' }, x.slice(5)) : h('code', { text: x }));
    return h('li', { class: 'sugg' },
      h('div', { class: 'row' }, sevChip(sg.severity), h('b', { class: 'grow', text: sg.title }), sg.source === 'ai' ? aiBadge() : null,
        h('span', { class: 'badge', text: KIND[sg.kind] || sg.kind })),
      h('p', { class: 'muted', text: sg.rationale }),
      h('div', { class: 'row' }, h('span', { class: 'action-desc', text: describeAction(sg.action) }),
        ev.length ? h('span', { class: 'muted' }, 'Evidence: ', ...ev.flatMap((x, i) => (i ? [', ', x] : [x]))) : null,
        h('span', { class: 'muted' }, '· ', timeEl(sg.ts))),
      sg.action.type === 'manual' ? h('pre', { class: 'block', text: sg.action.instructions }) : null,
      sg.status === 'proposed'
        ? h('div', { class: 'row', style: { marginTop: '8px' } },
          h('button', { class: 'btn small primary', type: 'button', disabled: !allowed, onclick: () => decide(sg, true, onDone) }, sg.action.type === 'manual' ? 'Accept' : 'Approve'),
          h('button', { class: 'btn small', type: 'button', disabled: !allowed, onclick: () => decide(sg, false, onDone) }, 'Reject'),
          !allowed ? h('span', { class: 'muted', text: `Needs the ${sg.required_role} role.` }) : null)
        : h('p', { class: 'muted' }, `${cap(sg.status)} by ${sg.decided_by || '–'} `, timeEl(sg.decided_at), sg.result ? [': ', h('span', { text: sg.result })] : ''));
  }

  function aiTriageView(ai) {
    const r = ai.result || {};
    return h('div', { class: 'card ai-card' },
      h('div', { class: 'row' }, aiBadge(), verdictChip(r.verdict), h('span', { class: 'muted', text: `${cap(r.confidence)} confidence` }),
        h('span', { class: 'muted grow', style: { textAlign: 'right' } }, `${ai.model || ''} · `, timeEl(ai.ts))),
      h('p', { text: r.summary || '' }),
      (r.reasoning || []).length ? h('ul', { class: 'findings' }, r.reasoning.map((x) => h('li', { text: x }))) : null,
      (r.dropped || []).length ? h('p', { class: 'hint' }, `${r.dropped.length} recommendation${r.dropped.length === 1 ? ' was' : 's were'} discarded by the console's checks: `,
        r.dropped.map((d) => `${d.title || d.rule_line} (${d.reason})`).join('; ')) : null);
  }

  function incidentDrawer(id, onChange) {
    openDrawer('Incident', async (body) => {
      const [inc] = await Promise.all([api('/api/incidents/detail' + qs({ id })), aiStatus ? null : getAiStatus()]);
      $('#drawer-title').textContent = `${inc.priority} · ${inc.host}`;
      const redraw = () => { onChange && onChange(); incidentDrawer(id, onChange); };
      clear(body);
      body.append(h('div', { class: 'row' }, prioChip(inc.priority), h('span', { class: 'badge', text: `Score ${inc.score}` }), sevChip(inc.severity),
        h('span', { class: 'badge', text: cap(inc.status) }), inc.contained ? h('span', { class: 'badge enforce', text: 'Contained' }) : null));
      body.append(h('p', { class: 'lead', text: inc.summary }));
      body.append(h('div', {}, h('h3', { text: 'Why this priority' }), h('ul', { class: 'reasons' }, inc.reasons.map((r) => {
        const m = /^([+-]\d+) (.*)$/.exec(r) || [null, '', r];
        return h('li', {}, h('span', { class: 'pts' + (m[1].startsWith('-') ? ' neg' : ''), text: m[1] }), h('span', { text: m[2] }));
      }))));
      if (inc.campaign_hosts.length) body.append(h('div', {}, h('h3', { text: 'Also seen on' }), h('div', { class: 'chips' }, inc.campaign_hosts.map((x) => h('a', { class: 'chip', href: '#', onclick: (e) => { e.preventDefault(); hostDrawer(x); } }, x)))));

      const aiBox = h('div', {}, h('h3', { text: 'AI triage' }));
      if (inc.ai) aiBox.append(aiTriageView(inc.ai));
      aiBox.append(aiButton(inc.ai ? 'Triage again' : 'Ask AI to triage', 'triage', { incident: inc.id }, redraw));
      body.append(aiBox);

      if (inc.suggestions.length) body.append(h('div', {}, h('h3', { text: 'Suggested actions' }), h('ul', { class: 'list suggs' }, inc.suggestions.map((sg) => suggestionCard(sg, redraw)))));

      const tri = h('div', {}, h('h3', { text: 'Triage the incident' }));
      if (can('operator')) {
        const note = h('textarea', { 'aria-label': 'Triage note', placeholder: 'What did you find? Notes containing “benign” or “false positive” teach the rule review.' });
        const act = (status, label) => h('button', { class: 'btn small' + (status === 'resolved' ? ' primary' : ''), type: 'button', disabled: inc.status === status, onclick: async () => {
          try {
            const r = await api('/api/incidents/triage', { method: 'POST', body: { id: inc.id, status, note: note.value } });
            toast(`${r.updated} alert${r.updated === 1 ? '' : 's'} marked ${status}`); redraw();
          } catch (e) { toast(e.message, true); }
        } }, label);
        tri.append(note, h('div', { class: 'row', style: { marginTop: '8px' } }, act('acknowledged', 'Acknowledge all'), act('resolved', 'Resolve all'), act('open', 'Reopen')));
      } else tri.append(h('p', { class: 'muted', text: 'Triage requires the operator role.' }));
      body.append(tri);

      body.append(h('div', {}, h('h3', { text: `Timeline (${inc.alerts.length} alert${inc.alerts.length === 1 ? '' : 's'})` }),
        table([{ label: 'When', cell: (a) => timeEl(a.ts) }, { label: 'Severity', cell: (a) => sevChip(a.severity) },
          { label: 'Detection', cls: 'title-cell', cell: (a) => [h('b', { text: a.rule }), h('div', { class: 'muted', text: a.title })] },
          { label: 'Actor', cell: (a) => actorBadge(a.actor, a.actor_src) }, { label: 'Command', cell: (a) => h('div', { class: 'cmd', title: a.cmd || '', text: a.cmd || '–' }) }],
        inc.alerts, { onRow: (a) => alertDrawer(a, redraw) }),
        h('div', { class: 'row', style: { marginTop: '8px' } }, h('a', { class: 'btn small', href: '#', onclick: (e) => { e.preventDefault(); hostDrawer(inc.host); } }, 'Host details'),
          h('a', { class: 'btn small', href: `/investigate${qs({ host: inc.host, since: inc.first_ts })}` }, 'Events from this point'))));
    });
  }

  // ---- pages ---------------------------------------------------------------
  const pages = {};

  pages.overview = {
    title: 'Overview',
    mount(main) { this.el = main; main.append(h('div', { class: 'loading', text: 'Loading fleet overview…' })); },
    async load() {
      const [sm, crit, incs, sugg, hl] = await Promise.all([api('/api/summary'), api('/api/alerts' + qs({ status: 'open', severity: 'high', limit: 8 })),
        api('/api/incidents' + qs({ status: 'open', limit: 500 })), api('/api/suggestions'), api('/api/analysis/health')]);
      const p12 = incs.filter((i) => i.priority === 'P1' || i.priority === 'P2');
      const main = clear(this.el);
      if (!sm.hosts.live && !sm.hosts.decommissioned) main.append(onboarding());
      const vulnHot = (sm.vulns_by_tier.exploited || 0) + (sm.vulns_by_tier.reachable || 0);
      const kpi = (label, value, href, ...sub) => h('div', { class: 'card stat' }, h('div', { class: 'label', text: label }),
        href ? h('a', { class: 'value', href }, value) : h('div', { class: 'value' }, value),
        h('div', { class: 'sub' }, ...sub.filter((x) => x != null).map((x) => (x instanceof Node ? x : h('span', { text: x })))));
      main.append(h('div', { class: 'grid kpis' },
        kpi('Open incidents', fmtNum(incs.length), '/incidents', h('span', {}, prioChip('P1'), ` ${incs.filter((i) => i.priority === 'P1').length}`), h('span', {}, prioChip('P2'), ` ${incs.filter((i) => i.priority === 'P2').length}`)),
        kpi('Hosts', fmtNum(sm.hosts.live), '/hosts', `${sm.hosts.active} active`, `${sm.hosts.stale} stale`, sm.hosts.ephemeral ? `${sm.hosts.ephemeral} ephemeral` : null),
        kpi('Open alerts', fmtNum(sm.alerts.open_total), '/alerts', h('span', {}, sevChip('critical'), ` ${sm.alerts.open_by_severity.critical || 0}`), h('span', {}, sevChip('high'), ` ${sm.alerts.open_by_severity.high || 0}`)),
        kpi('Fleet posture', h('span', { class: 'row' }, gradeEl(sm.posture.grade), `${sm.posture.score}`), '/posture', 'Score out of 100'),
        h('div', { class: 'card stat' }, h('div', { class: 'label', text: 'Sensor CPU (peak host)' }), h('div', { class: 'value', text: fmtPct(sm.sensor_cpu.max_pct) }),
          meter(sm.sensor_cpu.max_pct, sm.sensor_cpu.budget_pct, { label: 'Peak sensor CPU against the budget' }),
          h('div', { class: 'sub' }, `Budget ${fmtPct(sm.sensor_cpu.budget_pct, 2)} · avg ${fmtPct(sm.sensor_cpu.avg_pct)}`, sm.sensor_cpu.hosts_over_budget ? `${sm.sensor_cpu.hosts_over_budget} over` : null)),
        kpi('Exploitable vulnerabilities', fmtNum(vulnHot), '/vulnerabilities', h('span', {}, tierChip('exploited'), ` ${sm.vulns_by_tier.exploited || 0}`), h('span', {}, tierChip('reachable'), ` ${sm.vulns_by_tier.reachable || 0}`))));
      main.append(h('div', { class: 'spacer' }));
      const HL = { ok: 'Healthy', attention: 'Needs attention', critical: 'Action needed' };
      main.append(h('div', { class: 'grid two' },
        h('div', { class: 'card' }, h('h2', {}, 'Top incidents', h('a', { href: '/incidents', text: 'All incidents' })),
          table([{ label: 'Priority', cell: (i) => prioChip(i.priority) }, { label: 'Incident', cls: 'title-cell', cell: (i) => [h('b', { text: i.host }), h('div', { class: 'muted', text: i.summary })] },
            { label: 'Last activity', cell: (i) => timeEl(i.last_ts) }],
          incs.slice(0, 5), { onRow: (i) => incidentDrawer(i.id, () => this.load()), rowLabel: (i) => `${i.priority} incident on ${i.host}`, emptyNode: empty('No open incidents') }),
          p12.length > 5 ? h('p', { class: 'hint', text: `${p12.length} open P1/P2 incidents in total.` }) : null),
        h('div', { class: 'card' }, h('h2', {}, 'Suggested next steps', h('a', { href: '/suggestions', text: `${sugg.length} waiting` })),
          h('div', { class: 'row', style: { marginBottom: '6px' } }, h('span', { class: 'muted', text: 'Fleet health:' }), h('a', { href: '/analysis', text: HL[hl.status] || hl.status }),
            hl.findings.length ? h('span', { class: 'muted', text: `· ${hl.findings.length} finding${hl.findings.length === 1 ? '' : 's'}` }) : null),
          sugg.length ? h('ul', { class: 'list' }, sugg.slice(0, 5).map((sg) => h('li', {}, sevChip(sg.severity), h('div', { class: 'grow' }, h('b', { text: sg.title }), h('div', { class: 'muted', text: describeAction(sg.action) })), sg.source === 'ai' ? aiBadge() : null)))
            : empty('Nothing waiting for approval'))));
      main.append(h('div', { class: 'spacer' }));

      const now = new Date();
      const hourly = sm.alerts.hourly_24h.map((v, i) => {
        const t = new Date(now - (23 - i) * 3600e3);
        const hh = t.getHours();
        return { value: v, label: `${hh}:00`, tick: i % 4 === 3 ? `${hh}:00` : '', tip: `${t.toLocaleDateString(undefined, { weekday: 'short' })} ${hh}:00–${hh}:59` };
      });
      const top = sm.alerts.top_rules_24h;
      const maxTop = Math.max(1, ...top.map((r) => r.count));
      main.append(h('div', { class: 'grid two' },
        h('div', { class: 'card' }, h('h2', {}, 'Alerts per hour', h('span', { class: 'muted', text: `· ${fmtNum(sm.alerts.last_24h)} in the last 24 hours` })),
          columnChart(hourly, { label: 'Alerts per hour over the last 24 hours' })),
        h('div', { class: 'card' }, h('h2', {}, 'Top detections', h('span', { class: 'muted', text: '· 24 hours' })),
          top.length ? h('ul', { class: 'list' }, top.map((r) => h('li', {}, h('div', { class: 'grow' }, h('b', { text: r.rule }), h('div', { class: 'muted', text: r.title })),
            h('span', { class: 'barcell', 'aria-hidden': 'true' }, h('span', { style: { width: `${(r.count / maxTop) * 100}%` } })), h('span', { class: 'n', text: fmtNum(r.count) })))) : empty('No detections in the last 24 hours', 'Quiet is good.'))));
      main.append(h('div', { class: 'spacer' }));
      main.append(h('div', { class: 'grid two' },
        h('div', { class: 'card' }, h('h2', {}, 'Open high-severity alerts', h('a', { href: '/alerts?severity=high&status=open', text: 'View all' })),
          table([{ label: 'Severity', cell: (a) => sevChip(a.severity) }, { label: 'Detection', cls: 'title-cell', cell: (a) => [h('b', { text: a.rule }), ' ', h('span', { class: 'muted', text: a.title })] },
            { label: 'Host', cell: (a) => a.host }, { label: 'When', cell: (a) => timeEl(a.ts) }],
          crit, { onRow: (a) => alertDrawer(a, () => this.load()), rowLabel: (a) => `${a.severity} ${a.rule} on ${a.host}`, emptyNode: empty('No open high or critical alerts') })),
        h('div', { class: 'card' }, h('h2', {}, 'Recent rollouts', h('a', { href: '/rollouts', text: 'Rollouts' })),
          sm.recent_rollouts.length ? h('ul', { class: 'list' }, sm.recent_rollouts.map((r) => h('li', {}, h('div', { class: 'grow' }, h('b', { text: `${cap(r.action)} · ${r.group || 'all groups'} · ${r.percent}%` }),
            h('div', { class: 'muted' }, `${r.delivered.length}/${r.cohort.length} delivered · by ${r.by || '–'} · `, timeEl(r.ts)))))) : empty('No rollouts yet'))));
    },
  };

  function onboarding() {
    return h('div', { class: 'card' }, h('h2', { text: 'Connect your first sensor' }),
      h('p', { class: 'muted', text: 'No sensors have reported to this console yet. Install wispd on a host and point it at this console:' }),
      h('pre', { class: 'block', text: 'sudo WISP_CONSOLE=<this-console>:8750 WISP_GROUP=prod \\\n  WISP_CA_PEM="$(cat ca.crt)" WISP_CERT_PEM="$(cat agent.crt)" WISP_KEY_PEM="$(cat agent.key)" \\\n  ./packaging/install.sh' }),
      h('p', { class: 'muted' }, 'The sensor starts in monitor mode and appears here within a few seconds. See ', h('code', { text: 'docs/installation.md' }), '.'));
  }

  pages.alerts = {
    title: 'Alerts',
    mount(main, params) {
      this.f = { status: params.get('status') || 'open', severity: params.get('severity') || '', host: params.get('host') || '', actor: params.get('actor') || '', q: params.get('q') || '', rule: params.get('rule') || '' };
      const sync = () => { history.replaceState(null, '', '/alerts' + qs(this.f)); this.load(); };
      const q = h('input', { id: 'alert-q', type: 'search', placeholder: 'Search rule, title, command, host…', value: this.f.q, oninput: debounce(() => { this.f.q = q.value; sync(); }) });
      this.hostSel = select('alert-host', [['', 'All hosts']], this.f.host, (v) => { this.f.host = v; sync(); });
      main.append(h('div', { class: 'filters' },
        h('div', { class: 'field search' }, h('label', { for: 'alert-q', text: 'Search' }), q),
        h('div', { class: 'field' }, h('label', { text: 'Status' }), seg([['open', 'Open'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved'], ['all', 'All']], this.f.status, (v) => { this.f.status = v; sync(); }, 'Status')),
        h('div', { class: 'field' }, h('label', { for: 'alert-sev', text: 'Severity' }), select('alert-sev', [['', 'Any'], ['low', 'Low and above'], ['medium', 'Medium and above'], ['high', 'High and above'], ['critical', 'Critical only']], this.f.severity, (v) => { this.f.severity = v; sync(); })),
        h('div', { class: 'field' }, h('label', { for: 'alert-host', text: 'Host' }), this.hostSel),
        h('div', { class: 'field' }, h('label', { for: 'alert-actor', text: 'Actor' }), select('alert-actor', [['', 'Anyone'], ['ai', 'AI agents'], ['human', 'Humans'], ['code', 'Code'], ['ci', 'CI'], ['service', 'Services'], ['console', 'Console']], this.f.actor, (v) => { this.f.actor = v; sync(); }))));
      this.meta = h('div', { class: 'result-meta' });
      this.out = h('div', {}, h('div', { class: 'loading', text: 'Loading alerts…' }));
      main.append(this.meta, this.out);
      api('/api/hosts?state=all').then((hs) => { for (const x of hs) this.hostSel.append(h('option', { value: x.name, text: x.name })); this.hostSel.value = this.f.host; }).catch(() => {});
    },
    async load() {
      const f = { ...this.f, status: this.f.status === 'all' ? '' : this.f.status, limit: 500 };
      const rows = await api('/api/alerts' + qs(f));
      this.meta.textContent = rows.length >= 500 ? 'Showing the newest 500 matching alerts' : `${fmtNum(rows.length)} matching alert${rows.length === 1 ? '' : 's'}`;
      clear(this.out).append(table([
        { label: 'Severity', cell: (a) => sevChip(a.severity) },
        { label: 'When', cell: (a) => timeEl(a.ts) },
        { label: 'Detection', cls: 'title-cell', cell: (a) => [h('b', { text: a.rule }), h('div', { class: 'muted', text: a.title })] },
        { label: 'Host', cell: (a) => h('span', { class: 'nowrap', text: a.host }) },
        { label: 'Actor', cell: (a) => actorBadge(a.actor, a.actor_src) },
        { label: 'Command', cell: (a) => h('div', { class: 'cmd', title: a.cmd || '', text: a.cmd || '–' }) },
        { label: 'Response', cell: (a) => a.action || '–' },
        { label: 'Status', cell: (a) => cap(a.status) },
      ], rows, { page: 100, onRow: (a) => alertDrawer(a, () => this.load()), rowLabel: (a) => `${a.severity} ${a.rule} on ${a.host}`,
        emptyNode: empty(this.f.status === 'open' ? 'No open alerts match' : 'No alerts match', 'Adjust the filters, or check back later.') }));
    },
  };

  pages.incidents = {
    title: 'Incidents',
    mount(main, params) {
      this.f = { status: params.get('status') || '', priority: params.get('priority') || '', host: params.get('host') || '' };
      const sync = () => { history.replaceState(null, '', '/incidents' + qs(this.f)); this.load(); };
      main.append(h('p', { class: 'muted', style: { marginTop: 0 } }, 'Related alerts on a host (the same actor or process lineage, close in time) are correlated into one incident and ranked by what matters: severity, how many stages of an attack it shows, whether it spread, whether the host is exposed, and whether the sensor already stopped it.'));
      main.append(h('div', { class: 'filters' },
        h('div', { class: 'field' }, h('label', { text: 'Status' }), seg([['', 'Active'], ['open', 'Open'], ['acknowledged', 'Acknowledged'], ['resolved', 'Resolved'], ['all', 'All']], this.f.status, (v) => { this.f.status = v; sync(); }, 'Status')),
        h('div', { class: 'field' }, h('label', { text: 'Priority' }), seg([['', 'Any'], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3'], ['P4', 'P4']], this.f.priority, (v) => { this.f.priority = v; sync(); }, 'Priority'))));
      this.meta = h('div', { class: 'result-meta' });
      this.out = h('div', {}, h('div', { class: 'loading', text: 'Correlating alerts…' }));
      main.append(this.meta, this.out);
    },
    async load() {
      const rows = await api('/api/incidents' + qs({ ...this.f, limit: 500 }));
      this.meta.textContent = `${fmtNum(rows.length)} incident${rows.length === 1 ? '' : 's'}${rows.length >= 500 ? ' (first 500)' : ''}`;
      clear(this.out).append(table([
        { label: 'Priority', cell: (i) => prioChip(i.priority) },
        { label: 'Score', num: true, cell: (i) => String(i.score) },
        { label: 'Incident', cls: 'title-cell', cell: (i) => [h('b', { text: i.host }), h('div', { class: 'muted', text: i.summary })] },
        { label: 'Alerts', num: true, cell: (i) => fmtNum(i.alert_count) },
        { label: 'Actor', cell: (i) => h('span', { class: 'nowrap', text: (i.actors || []).join(', ') }) },
        { label: 'AI', cell: (i) => (i.ai ? verdictChip(i.ai.verdict) : h('span', { class: 'muted', text: '–' })) },
        { label: 'Last activity', cell: (i) => timeEl(i.last_ts) },
        { label: 'Status', cell: (i) => [cap(i.status), i.contained ? h('div', { class: 'muted', text: 'contained' }) : null] },
      ], rows, { page: 100, onRow: (i) => incidentDrawer(i.id, () => this.load()), rowLabel: (i) => `${i.priority} incident on ${i.host}`,
        emptyNode: empty(this.f.status === 'resolved' ? 'No resolved incidents' : 'No active incidents', 'Incidents appear when sensors report alerts.') }));
    },
  };

  pages.suggestions = {
    title: 'Suggestions',
    mount(main, params) {
      this.view = params.get('view') || 'inbox';
      const runBtn = can('operator') ? h('button', { class: 'btn small', type: 'button', onclick: async () => {
        try { const r = await api('/api/analysis/run', { method: 'POST' }); toast(r.proposed ? `${r.proposed} new suggestion${r.proposed === 1 ? '' : 's'}` : 'No new suggestions'); this.load(); }
        catch (e) { toast(e.message, true); }
      } }, 'Analyze now') : null;
      main.append(h('p', { class: 'muted', style: { marginTop: 0 } }, 'We suggest, you approve, we solve. Wisp watches incidents, fleet health, rule noise and exploitable software and proposes concrete fixes. Nothing changes until someone with the right role approves; every decision is recorded with their name.'));
      main.append(h('div', { class: 'filters' }, h('div', { class: 'field' }, h('label', { text: 'Show' }),
        seg([['inbox', 'Waiting for approval'], ['history', 'Decided']], this.view, (v) => { this.view = v; history.replaceState(null, '', '/suggestions' + qs({ view: v })); this.load(); }, 'Show')),
        h('div', { class: 'field', style: { marginLeft: 'auto', alignSelf: 'flex-end' } }, runBtn)));
      this.out = h('div', {}, h('div', { class: 'loading', text: 'Loading suggestions…' }));
      main.append(this.out);
    },
    async load() {
      if (this.view === 'inbox') {
        const rows = await api('/api/suggestions');
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        rows.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
        clear(this.out).append(rows.length ? h('ul', { class: 'list suggs card' }, rows.map((sg) => suggestionCard(sg, () => this.load())))
          : h('div', { class: 'card' }, empty('Nothing waiting for approval', 'The analysis runs every minute; new suggestions appear here.')));
        return;
      }
      const rows = (await api('/api/suggestions?status=all')).filter((x) => x.status !== 'proposed');
      clear(this.out).append(table([
        { label: 'Decided', cell: (x) => timeEl(x.decided_at) },
        { label: 'Suggestion', cls: 'title-cell', cell: (x) => [h('b', { text: x.title }), h('div', { class: 'muted', text: describeAction(x.action) })] },
        { label: 'Source', cell: (x) => (x.source === 'ai' ? aiBadge() : h('span', { class: 'badge', text: 'Analysis' })) },
        { label: 'Outcome', cell: (x) => h('span', { class: 'badge ' + (x.status === 'applied' || x.status === 'accepted' ? 'enforce' : ''), text: cap(x.status) }) },
        { label: 'By', cell: (x) => x.decided_by || '–' },
        { label: 'Result', cell: (x) => h('div', { class: 'cmd', title: x.result || '', text: x.result || '–' }) },
      ], rows, { page: 100, emptyNode: empty('No decisions yet') }));
    },
  };

  pages.analysis = {
    title: 'Analysis',
    mount(main) {
      this.health = h('div', { class: 'card' }, h('div', { class: 'loading', text: 'Checking fleet health…' }));
      this.ai = h('div', { class: 'card' });
      this.rules = h('div', {}, h('div', { class: 'loading', text: 'Reviewing rules…' }));
      main.append(h('div', { class: 'grid two' }, this.health, this.ai), h('div', { class: 'spacer' }),
        h('h2', { class: 'section-title', text: 'Rule review' }),
        h('p', { class: 'muted', text: 'Per-rule volume, spread and triage outcomes over the console\'s alert window. Triage notes that say “benign” or “false positive” count as noise.' }), this.rules);
      this.drawAi();
    },
    async drawAi() {
      const st = await getAiStatus();
      const card = clear(this.ai);
      card.append(h('h2', {}, 'Ask about your fleet', aiBadge()));
      if (!st.enabled) { card.append(h('p', { class: 'muted' }, 'The AI assistant is off. ', st.reason || ''), h('p', { class: 'hint', text: 'Incidents, suggestions and rule review work without it.' })); return; }
      card.append(h('p', { class: 'muted', style: { marginTop: 0 }, text: `Answers come from the console's own data through read-only tools. Secrets are redacted before anything leaves the console. Model ${st.model}; ${st.used_this_hour} of ${st.max_per_hour} requests used this hour.` }));
      if (!can('operator')) { card.append(h('p', { class: 'muted', text: 'Asking requires the operator role.' })); return; }
      const q = h('textarea', { id: 'ask-q', 'aria-label': 'Question', placeholder: 'e.g. Which AI agents touched credentials this week, and on which hosts?' });
      const out = h('div', { 'aria-live': 'polite' });
      const status = h('span', { class: 'muted', role: 'status' });
      const btn = h('button', { class: 'btn primary', type: 'submit' }, icon('i-spark'), 'Ask');
      card.append(h('form', { onsubmit: async (e) => {
        e.preventDefault();
        if (!q.value.trim()) return;
        btn.disabled = true; clear(out);
        try {
          const job = await runAiJob('ask', { question: q.value.trim() }, (j, secs) => { status.textContent = `${j.status === 'queued' ? 'Queued' : 'Looking at your fleet'}… ${secs}s`; });
          status.textContent = '';
          out.append(h('div', { class: 'answer', text: job.result.answer || '(no answer)' }),
            job.result.tool_calls.length ? h('p', { class: 'hint', text: 'Looked at: ' + job.result.tool_calls.map((c) => c.name.replace(/_/g, ' ')).join(', ') }) : null);
        } catch (err) { status.textContent = ''; out.append(h('p', { class: 'err', text: err.message })); }
        btn.disabled = false;
      } }, q, h('div', { class: 'row', style: { marginTop: '8px' } }, btn, status)), out);
    },
    async load() {
      const [hl, rules] = await Promise.all([api('/api/analysis/health'), api('/api/analysis/rules')]);
      const STATUS = { ok: ['good', 'Healthy'], attention: ['medium', 'Needs attention'], critical: ['critical', 'Action needed'] };
      const [cls, label] = STATUS[hl.status] || STATUS.attention;
      clear(this.health).append(h('h2', {}, 'Fleet health'),
        h('div', { class: 'row' }, cls === 'good' ? h('span', { class: 'badge active' }, h('span', { class: 'dot' }), label) : sevChip(cls === 'critical' ? 'critical' : 'medium'),
          cls !== 'good' ? h('b', { text: label }) : null, h('span', { class: 'muted', text: `${hl.sensors_connected} of ${hl.hosts_live} sensors connected` })),
        hl.findings.length ? h('ul', { class: 'list' }, hl.findings.map((f) => h('li', { class: 'finding' }, sevChip(f.severity),
          h('div', { class: 'grow' }, h('b', { text: f.title }), h('div', { class: 'muted', text: f.detail }),
            f.hosts.length ? h('div', { class: 'chips' }, f.hosts.slice(0, 12).map((x) => h('a', { class: 'chip', href: '#', onclick: (e) => { e.preventDefault(); hostDrawer(x); } }, x)), f.hosts.length > 12 ? h('span', { class: 'muted', text: `+${f.hosts.length - 12} more` }) : null) : null))))
          : empty('Nothing to fix', 'Every sensor is reporting, within budget, on one version, with a strong identity.'));
      const ASSESS = { noisy: ['medium', 'Noisy'], ready_to_enforce: ['high', 'Ready to block'], ok: ['info', 'OK'] };
      clear(this.rules).append(table([
        { label: 'Rule', cls: 'title-cell', cell: (r) => [h('b', { text: r.rule }), h('div', { class: 'muted', text: r.title })] },
        { label: 'Severity', cell: (r) => sevChip(r.severity) },
        { label: 'Alerts', num: true, cell: (r) => fmtNum(r.alerts) },
        { label: 'Hosts', num: true, cell: (r) => fmtNum(r.hosts.length) },
        { label: 'Triaged / benign', num: true, cell: (r) => `${r.acknowledged + r.resolved} / ${r.benign}` },
        { label: 'Top program', cell: (r) => (r.programs[0] ? h('code', { text: `${r.programs[0].program} (${Math.round((100 * r.programs[0].alerts) / r.alerts)}%)` }) : '–') },
        { label: 'Assessment', cell: (r) => { const [c, t] = ASSESS[r.assessment] || ASSESS.ok; return r.assessment === 'ok' ? h('span', { class: 'muted', text: t }) : h('span', { class: `sev ${c}` }, icon(`i-sev-${c}`), t); } },
        { label: 'AI', cell: (r) => (r.ai ? h('span', { class: 'badge ai', text: cap(r.ai.result.verdict.replace('_', ' ')) }) : h('span', { class: 'muted', text: '–' })) },
      ], rules, { page: 50, onRow: (r) => this.ruleDrawer(r), rowLabel: (r) => `Rule ${r.rule}`, emptyNode: empty('No alerts yet', 'Rules are reviewed once they fire.') }));
    },
    ruleDrawer(r) {
      openDrawer(`Rule ${r.rule}`, async (body) => {
        if (!aiStatus) await getAiStatus();
        clear(body);
        body.append(h('p', { class: 'lead', text: r.title }));
        body.append(h('dl', { class: 'kv' },
          h('dt', { text: 'Severity' }), h('dd', {}, sevChip(r.severity)),
          h('dt', { text: 'ATT&CK' }), h('dd', { text: r.technique || '–' }),
          h('dt', { text: 'Response' }), h('dd', { text: r.action || '–' }),
          h('dt', { text: 'Alerts' }), h('dd', { text: `${fmtNum(r.alerts)} on ${r.hosts.length} host${r.hosts.length === 1 ? '' : 's'}` }),
          h('dt', { text: 'Triage' }), h('dd', { text: `${r.open} open · ${r.acknowledged} acknowledged · ${r.resolved} resolved (${r.benign} as benign)` }),
          h('dt', { text: 'Programs' }), h('dd', {}, r.programs.length ? h('div', { class: 'chips' }, r.programs.map((p) => h('span', { class: 'chip', text: `${p.program} ×${p.alerts}` }))) : '–')));
        if (r.advice) body.append(h('div', { class: 'card' }, h('b', { text: 'Recommendation' }), h('p', { text: r.advice })));
        const aiBox = h('div', {}, h('h3', { text: 'AI review' }));
        if (r.ai) {
          const res = r.ai.result;
          aiBox.append(h('div', { class: 'card ai-card' }, h('div', { class: 'row' }, aiBadge(), h('b', { text: cap(res.verdict.replace('_', ' ')) }), h('span', { class: 'muted grow', style: { textAlign: 'right' } }, timeEl(r.ai.ts))),
            h('p', { text: res.assessment }),
            (res.proposals || []).map((p) => h('div', {}, h('div', { class: 'muted', text: `${cap(p.change)}: ${p.rationale}` }), h('pre', { class: 'block', text: p.rule_line }))),
            res.suggestions && res.suggestions.length ? h('p', { class: 'hint' }, 'Valid rule lines were added to ', h('a', { href: '/suggestions' }, 'Suggestions'), ' for approval.') : null));
        }
        aiBox.append(aiButton(r.ai ? 'Review again' : 'Ask AI to review this rule', 'curate', { rule: r.rule }, async () => {
          const fresh = (await api('/api/analysis/rules')).find((x) => x.rule === r.rule);
          if (fresh) this.ruleDrawer(fresh);
          if (current === this) this.load();
        }));
        body.append(aiBox);
        body.append(h('a', { class: 'btn small', href: `/alerts${qs({ rule: r.rule, status: 'all' })}` }, 'All alerts for this rule'));
      });
    },
  };

  pages.hosts = {
    title: 'Hosts',
    mount(main, params) {
      this.f = { state: params.get('state') || '', group: params.get('group') || '', q: params.get('q') || '' };
      const sync = () => { history.replaceState(null, '', '/hosts' + qs(this.f)); this.load(); };
      const q = h('input', { id: 'host-q', type: 'search', placeholder: 'Filter by hostname…', value: this.f.q, oninput: debounce(() => { this.f.q = q.value; this.render(); }) });
      this.groupSel = select('host-group', [['', 'All groups']], this.f.group, (v) => { this.f.group = v; sync(); });
      main.append(h('div', { class: 'filters' },
        h('div', { class: 'field search' }, h('label', { for: 'host-q', text: 'Search' }), q),
        h('div', { class: 'field' }, h('label', { text: 'State' }), seg([['', 'Live'], ['active', 'Active'], ['stale', 'Stale'], ['decommissioned', 'Decommissioned'], ['all', 'All']], this.f.state, (v) => { this.f.state = v; sync(); }, 'State')),
        h('div', { class: 'field' }, h('label', { for: 'host-group', text: 'Group' }), this.groupSel)));
      this.meta = h('div', { class: 'result-meta' });
      this.out = h('div', {}, h('div', { class: 'loading', text: 'Loading hosts…' }));
      main.append(this.meta, this.out);
    },
    async load() {
      const [rows, all] = await Promise.all([api('/api/hosts' + qs({ state: this.f.state, group: this.f.group })), api('/api/hosts?state=all')]);
      const groups = [...new Set(all.map((x) => x.group).filter(Boolean))].sort();
      const cur = this.groupSel.value;
      clear(this.groupSel).append(h('option', { value: '', text: 'All groups' }), groups.map((g) => h('option', { value: g, text: g })));
      this.groupSel.value = cur;
      this.rows = rows;
      this.render();
    },
    render() {
      const q = this.f.q.toLowerCase();
      const rows = (this.rows || []).filter((x) => !q || x.name.toLowerCase().includes(q));
      this.meta.textContent = `${fmtNum(rows.length)} host${rows.length === 1 ? '' : 's'}`;
      clear(this.out).append(table([
        { label: 'Host', cls: 'title-cell', cell: (x) => [h('b', { text: x.name }), h('div', { class: 'muted', text: x.group || '–' })] },
        { label: 'State', cell: (x) => stateBadge(x.state) },
        { label: 'Mode', cell: (x) => modeBadge(x.mode) },
        { label: 'Identity', cell: (x) => TRUST[x.trust] || x.trust || '–' },
        { label: 'Sensor CPU', num: true, cell: (x) => [fmtPct(x.cpu_pct), meter(x.cpu_pct, 0.05, { inline: true, label: 'CPU against the 0.05% budget' })] },
        { label: 'Alerts', num: true, cell: (x) => fmtNum(x.alerts) },
        { label: 'Version', cell: (x) => x.version || '–' },
        { label: 'Last seen', cell: (x) => timeEl(x.last_seen) },
      ], rows, { page: 100, onRow: (x) => hostDrawer(x.name), rowLabel: (x) => `Host ${x.name}, ${x.state}`,
        emptyNode: this.rows && this.rows.length ? empty('No hosts match the filter') : onboarding() }));
    },
  };

  pages.investigate = {
    title: 'Investigate',
    mount(main, params) {
      const keys = ['q', 'type', 'host', 'rule', 'actor', 'pid', 'since', 'until'];
      this.f = Object.fromEntries(keys.map((k) => [k, params.get(k) || '']));
      const inp = (k, label, attrs = {}) => { const el = h('input', { id: `inv-${k}`, value: this.f[k], ...attrs }); this[k] = el; return h('div', { class: 'field' }, h('label', { for: `inv-${k}`, text: label }), el); };
      const typeSel = select('inv-type', [['', 'Any type'], ['alert', 'Alerts'], ['inventory', 'Inventory'], ['lifecycle', 'Host lifecycle'], ['hello', 'Sensor connects'], ['bye', 'Sensor exits'], ['triage', 'Triage'], ['rollout', 'Rollouts']], this.f.type, () => {});
      this.typeSel = typeSel;
      const local = (iso) => (iso ? iso.slice(0, 16) : '');
      const form = h('form', { class: 'card', onsubmit: (e) => { e.preventDefault(); this.submit(); } },
        h('div', { class: 'planner' },
          h('div', { class: 'field' }, h('label', { for: 'inv-q', text: 'Contains text' }), this.q = h('input', { id: 'inv-q', type: 'search', value: this.f.q, placeholder: 'e.g. id_rsa, 10.0.0.5, curl' })),
          h('div', { class: 'field' }, h('label', { for: 'inv-type', text: 'Event type' }), typeSel),
          inp('host', 'Host'), inp('rule', 'Rule', { placeholder: 'e.g. CRED-001' }), inp('actor', 'Actor', { placeholder: 'ai, human, ci…' }), inp('pid', 'Process ID', { inputmode: 'numeric' }),
          h('div', { class: 'field' }, h('label', { for: 'inv-since', text: 'From' }), this.since = h('input', { id: 'inv-since', type: 'datetime-local', value: local(this.f.since) })),
          h('div', { class: 'field' }, h('label', { for: 'inv-until', text: 'To' }), this.until = h('input', { id: 'inv-until', type: 'datetime-local', value: local(this.f.until) })),
          h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit' }, icon('i-search'), 'Search'), h('button', { class: 'btn', type: 'button', onclick: () => { navigate('/investigate'); } }, 'Clear'))));
      main.append(form, h('p', { class: 'hint' }, 'Searches the console\'s durable event journal (alerts, inventory, lifecycle, triage, rollouts). For every exec and network flow on one host, run ',
        h('code', { text: 'sudo wispd --search …' }), ' on that host, e.g. ', h('code', { text: 'tree=<pid>' }), ' rebuilds a full process tree.'));
      this.meta = h('div', { class: 'result-meta', style: { marginTop: '16px' } });
      this.out = h('div', {});
      main.append(this.meta, this.out);
      this.auto = false;
    },
    submit() {
      const toIso = (v) => (v ? new Date(v).toISOString() : '');
      this.f = { q: this.q.value.trim(), type: this.typeSel.value, host: this.host.value.trim(), rule: this.rule.value.trim(), actor: this.actor.value.trim(), pid: this.pid.value.trim(), since: toIso(this.since.value), until: toIso(this.until.value) };
      history.replaceState(null, '', '/investigate' + qs(this.f));
      this.load();
    },
    async load() {
      const has = Object.values(this.f).some(Boolean);
      if (!has) { this.meta.textContent = ''; clear(this.out).append(empty('Search the event journal', 'Set at least one filter above. Results are newest first.')); return; }
      const rows = await api('/api/events' + qs({ ...this.f, limit: 300 }));
      this.meta.textContent = rows.length >= 300 ? 'Showing the newest 300 matching events' : `${fmtNum(rows.length)} matching event${rows.length === 1 ? '' : 's'}`;
      if (!rows.length) { clear(this.out).append(empty('No events match', 'Widen the time range or remove a filter.')); return; }
      clear(this.out).append(h('ul', { class: 'timeline' }, rows.map((e) => h('li', {}, h('details', {},
        h('summary', {}, h('span', { class: 't', title: abs(e.ts), text: abs(e.ts) }), h('span', {}, e.type === 'alert' ? sevChip(e.severity) : h('span', { class: 'badge', text: e.type })),
          h('span', { text: e.host || '–' }), h('span', { class: 'cmd', text: e.title || e.rule || e.name || e.change || e.reason || e.action || e.cmd || '' })),
        h('pre', { class: 'block', text: JSON.stringify(e, null, 2) }))))));
    },
  };

  pages.vulnerabilities = {
    title: 'Vulnerabilities',
    mount(main, params) {
      this.tier = params.get('tier') || '';
      this.q = '';
      this.segWrap = h('div', { class: 'field' }, h('label', { text: 'Tier' }));
      const q = h('input', { id: 'vuln-q', type: 'search', placeholder: 'Package, CVE or host…', oninput: debounce(() => { this.q = q.value.toLowerCase(); this.render(); }, 150) });
      main.append(h('p', { class: 'muted', style: { marginTop: 0 } }, 'Ranked by what an attacker can actually use: ', h('b', { text: 'exploited' }), ' (an alert on the host involves the package), ',
        h('b', { text: 'reachable' }), ' (affected version installed and its runtime is executing), ', h('b', { text: 'dormant' }), ' (installed, runtime not seen running), ', h('b', { text: 'theoretical' }), ' (version unknown).'));
      main.append(h('div', { class: 'filters' }, h('div', { class: 'field search' }, h('label', { for: 'vuln-q', text: 'Search' }), q), this.segWrap));
      this.out = h('div', {}, h('div', { class: 'loading', text: 'Loading findings…' }));
      main.append(this.out);
    },
    async load() {
      this.rows = await api('/api/vulns');
      const counts = {};
      for (const f of this.rows) counts[f.tier] = (counts[f.tier] || 0) + 1;
      const opts = [['', `All (${this.rows.length})`], ...['exploited', 'reachable', 'dormant', 'theoretical'].map((t) => [t, `${cap(t)} (${counts[t] || 0})`])];
      this.segWrap.replaceChildren(h('label', { text: 'Tier' }), seg(opts, this.tier, (v) => { this.tier = v; history.replaceState(null, '', '/vulnerabilities' + qs({ tier: v })); this.render(); }, 'Tier'));
      this.render();
    },
    render() {
      const rows = this.rows.filter((f) => (!this.tier || f.tier === this.tier) && (!this.q || `${f.name} ${f.cve} ${f.host} ${f.ecosystem}`.toLowerCase().includes(this.q)));
      clear(this.out).append(table([
        { label: 'Tier', cell: (f) => tierChip(f.tier) },
        { label: 'Vulnerability', cell: (f) => h('code', { text: f.cve }) },
        { label: 'Package', cls: 'title-cell', cell: (f) => [h('b', { text: f.name }), h('div', { class: 'muted', text: `${f.ecosystem} · ${f.version || '?'}` })] },
        { label: 'Host', cell: (f) => f.host },
        { label: 'CVSS', num: true, cell: (f) => (f.cvss ? f.cvss.toFixed(1) : '–') },
        { label: 'Why this tier', cell: (f) => h('span', { class: 'muted', text: f.note || '' }) },
      ], rows, { page: 100, onRow: (f) => hostDrawer(f.host), rowLabel: (f) => `${f.tier} ${f.cve} ${f.name} on ${f.host}`, emptyNode: empty(this.rows.length ? 'No findings match' : 'No known-vulnerable software on the fleet', this.rows.length ? '' : 'Findings appear as sensors report their inventory.') }));
    },
  };

  pages.posture = {
    title: 'Posture',
    mount(main) { this.el = main; main.append(h('div', { class: 'loading', text: 'Scoring the fleet…' })); },
    async load() {
      const p = await api('/api/posture');
      const main = clear(this.el);
      const grades = { A: 0, B: 0, C: 0, D: 0, F: 0 };
      for (const x of p.hosts) grades[x.grade]++;
      const maxG = Math.max(1, ...Object.values(grades));
      main.append(h('div', { class: 'grid two' },
        h('div', { class: 'card' }, h('h2', { text: 'Fleet attack-surface score' }),
          h('div', { class: 'gauge' }, gauge(p.fleet_score), h('div', {}, h('div', { class: 'row' }, h('span', { class: 'big', text: String(p.fleet_score) }), gradeEl(p.fleet_grade)),
            h('div', { class: 'muted', text: `Average of ${p.hosts.length} live host${p.hosts.length === 1 ? '' : 's'}; 100 means nothing found.` }))),
          h('p', { class: 'muted', style: { marginBottom: 0 } }, 'Each host starts at 100 and loses points for exploited, reachable and dormant vulnerable software, unsanctioned tooling, never-seen programs, high and critical alerts, an identity not anchored in hardware, and running in monitor mode.')),
        h('div', { class: 'card' }, h('h2', { text: 'Hosts by grade' }),
          h('ul', { class: 'list' }, Object.entries(grades).map(([g, n]) => h('li', {}, gradeEl(g), h('span', { class: 'grow' }),
            h('span', { class: 'barcell', 'aria-hidden': 'true' }, h('span', { style: { width: `${(n / maxG) * 100}%` } })), h('span', { class: 'n', text: fmtNum(n) })))))));
      main.append(h('div', { class: 'spacer' }), h('h2', { class: 'section-title', text: 'Hosts, weakest first' }));
      main.append(table([
        { label: 'Host', cell: (x) => h('b', { text: x.host }) },
        { label: 'Grade', cell: (x) => gradeEl(x.grade) },
        { label: 'Score', num: true, cell: (x) => String(x.score) },
        { label: 'Mode', cell: (x) => modeBadge(x.mode) },
        { label: 'Identity', cell: (x) => TRUST[x.trust] || x.trust || '–' },
        { label: 'Findings', cell: (x) => (x.findings.length ? h('ul', { class: 'findings' }, x.findings.map((f) => h('li', { text: f }))) : h('span', { class: 'muted', text: 'None' })) },
      ], p.hosts, { page: 100, onRow: (x) => hostDrawer(x.host), rowLabel: (x) => `${x.host} grade ${x.grade}`, emptyNode: onboarding() }));
    },
  };

  // FNV-1a 32 -- identical to the console's cohort bucketing, so the planner
  // previews exactly which hosts a stage will reach.
  function bucket(name) {
    let x = 0x811c9dc5;
    for (const b of new TextEncoder().encode(name)) { x ^= b; x = Math.imul(x, 0x01000193) >>> 0; }
    return x % 100;
  }

  pages.rollouts = {
    title: 'Rollouts',
    mount(main) {
      this.f = { action: 'enforce', group: '', percent: 5 };
      this.planner = h('div', {});
      this.history = h('div', {}, h('div', { class: 'loading', text: 'Loading rollout history…' }));
      main.append(this.planner, h('div', { class: 'spacer' }), h('h2', { class: 'section-title', text: 'History' }), this.history);
      this.drawPlanner();
    },
    async drawPlanner() {
      const wrap = clear(this.planner);
      if (!can('deployer')) {
        wrap.append(h('div', { class: 'card' }, h('h2', { text: 'Staged rollouts' }), h('p', { class: 'muted', text: 'Starting a rollout requires the deployer role or higher. You can review the history below.' })));
        return;
      }
      const hosts = (await api('/api/hosts')).filter((x) => x.state !== 'decommissioned');
      this.hosts = hosts;
      const groups = [...new Set(hosts.map((x) => x.group).filter(Boolean))].sort();
      const preview = h('div', { class: 'preview', 'aria-live': 'polite' });
      const pct = h('input', { id: 'ro-pct', type: 'range', min: '1', max: '100', value: String(this.f.percent), 'aria-label': 'Percentage of the group' });
      const pctNum = h('input', { id: 'ro-pct-n', type: 'number', min: '1', max: '100', value: String(this.f.percent), style: { width: '76px' }, 'aria-label': 'Percentage' });
      const setPct = (v) => { v = Math.max(1, Math.min(100, Number(v) || 1)); this.f.percent = v; pct.value = pctNum.value = String(v); paint(); };
      pct.addEventListener('input', () => setPct(pct.value));
      pctNum.addEventListener('change', () => setPct(pctNum.value));
      const paint = () => {
        const pool = hosts.filter((x) => !this.f.group || x.group === this.f.group);
        const cohort = pool.filter((x) => bucket(x.name) < this.f.percent).sort((a, b) => a.name.localeCompare(b.name));
        const offline = cohort.filter((x) => !x.connected).length;
        clear(preview).append(h('div', {}, h('b', { text: `${cohort.length} of ${pool.length} host${pool.length === 1 ? '' : 's'}` }), ` in ${this.f.group || 'all groups'} will receive “${actionLabel(this.f.action)}”.`,
          offline ? h('span', { class: 'muted', text: ` ${offline} of them are not connected and will be reported as failed.` }) : null),
          cohort.length ? h('div', { class: 'chips' }, cohort.slice(0, 24).map((x) => h('span', { class: 'chip', text: x.name })), cohort.length > 24 ? h('span', { class: 'muted', text: `+${cohort.length - 24} more` }) : null) : null);
        go.disabled = !cohort.length;
      };
      const go = h('button', { class: 'btn primary', type: 'button', onclick: () => this.start() }, 'Start rollout');
      wrap.append(h('div', { class: 'card' }, h('h2', { text: 'Plan a staged rollout' }),
        h('p', { class: 'muted', style: { marginTop: 0 } }, 'Push a change to a fixed slice of a group. Raising the percentage only ever adds hosts, so your canary hosts stay in every later stage.'),
        h('div', { class: 'planner' },
          h('div', { class: 'field' }, h('label', { for: 'ro-action', text: 'Change' }), select('ro-action', [['enforce', 'Switch to enforce'], ['monitor', 'Switch to monitor'], ['reload', 'Reload policy']], this.f.action, (v) => { this.f.action = v; paint(); })),
          h('div', { class: 'field' }, h('label', { for: 'ro-group', text: 'Group' }), select('ro-group', [['', 'All groups'], ...groups.map((g) => [g, g])], this.f.group, (v) => { this.f.group = v; paint(); })),
          h('div', { class: 'field' }, h('label', { for: 'ro-pct', text: 'Stage' }), h('div', { class: 'stages' }, [5, 25, 50, 100].map((v) => h('button', { class: 'btn small', type: 'button', onclick: () => setPct(v) }, `${v}%`)))),
          h('div', { class: 'field' }, h('label', { for: 'ro-pct', text: 'Percentage' }), h('div', { class: 'row' }, pct, pctNum))),
        preview, h('div', { class: 'row end', style: { marginTop: '14px' } }, go)));
      paint();
    },
    async start() {
      const f = this.f;
      const ok = await confirmDialog(`${actionLabel(f.action)} for ${f.percent}% of ${f.group || 'all groups'}?`,
        [h('p', { text: f.action === 'enforce' ? 'Hosts in this stage will start blocking policy violations: matching processes are killed.' : f.action === 'monitor' ? 'Hosts in this stage will stop blocking and only report.' : 'Hosts in this stage re-read their policy files.' }),
          h('p', { class: 'muted', text: 'The stage is recorded in the audit journal with your name.' })], 'Start rollout', f.action === 'enforce');
      if (!ok) return;
      try {
        const r = await api('/api/policy/rollout' + qs({ action: f.action, group: f.group, percent: f.percent }), { method: 'POST' });
        toast(`Rollout sent to ${r.delivered.length} of ${r.cohort.length} host${r.cohort.length === 1 ? '' : 's'}`, r.failed.length > 0);
        this.load();
      } catch (e) { toast(e.message, true); }
    },
    async load() {
      const rows = await api('/api/policy/rollout');
      clear(this.history).append(table([
        { label: 'When', cell: (r) => timeEl(r.ts) },
        { label: 'Change', cell: (r) => actionLabel(r.action) },
        { label: 'Group', cell: (r) => r.group || 'All groups' },
        { label: 'Stage', num: true, cell: (r) => `${r.percent}%` },
        { label: 'Hosts', num: true, cell: (r) => fmtNum(r.cohort.length) },
        { label: 'Delivered', num: true, cell: (r) => fmtNum(r.delivered.length) },
        { label: 'Failed', num: true, cell: (r) => (r.failed.length ? h('span', { class: 'sev high' }, icon('i-sev-high'), fmtNum(r.failed.length)) : '0') },
        { label: 'By', cell: (r) => r.by || '–' },
      ], rows, { emptyNode: empty('No rollouts yet', 'Plan your first stage above, starting with a small canary percentage.') }));
    },
  };
  const actionLabel = (a) => ({ enforce: 'Switch to enforce', monitor: 'Switch to monitor', reload: 'Reload policy' }[a] || a);

  pages.settings = {
    title: 'Settings',
    mount(main) { this.el = main; },
    async load() {
      const [v, ai] = await Promise.all([api('/api/version'), getAiStatus()]);
      const main = clear(this.el);
      const perms = { viewer: 'View everything on the console.', deployer: 'View, plus run staged rollouts and approve rollout suggestions.', operator: 'Deployer, plus triage, approve suggestions, ask the AI assistant, push policy to single hosts and read vault secrets.', admin: 'Everything, including writing vault secrets.' };
      main.append(h('div', { class: 'grid two' },
        h('div', { class: 'card' }, h('h2', { text: 'Account' }),
          h('dl', { class: 'kv' }, h('dt', { text: 'Signed in as' }), h('dd', { text: me.name || '–' }), h('dt', { text: 'Role' }), h('dd', {}, h('b', { text: cap(me.role) }), h('div', { class: 'muted', text: perms[me.role] || '' }))),
          v.auth ? h('div', { class: 'row', style: { marginTop: '16px' } }, h('button', { class: 'btn', type: 'button', onclick: () => { store.clearToken(); showSignin('You have signed out.'); } }, 'Sign out'))
            : h('p', { class: 'muted', text: 'This console runs in development mode without authentication.' })),
        h('div', { class: 'card' }, h('h2', { text: 'Appearance' }),
          h('div', { class: 'field' }, h('label', { text: 'Theme' }), seg([['system', 'System'], ['light', 'Light'], ['dark', 'Dark']], store.pref('theme', 'system'), (t) => { store.setPref('theme', t); applyTheme(); }, 'Theme')),
          h('div', { class: 'field', style: { marginTop: '14px' } }, h('label', { for: 'set-refresh', text: 'Refresh data every' }),
            select('set-refresh', [['10', '10 seconds'], ['30', '30 seconds'], ['60', '1 minute'], ['0', 'Never (manual)']], store.pref('refresh', '10'), (x) => { store.setPref('refresh', x); schedule(); }))),
        h('div', { class: 'card' }, h('h2', { text: 'About this console' }),
          h('dl', { class: 'kv' }, h('dt', { text: 'Version' }), h('dd', { text: v.version }), h('dt', { text: 'Runtime' }), h('dd', { text: v.runtime }),
            h('dt', { text: 'Uptime' }), h('dd', { text: `${Math.floor(v.uptime_s / 3600)}h ${Math.floor((v.uptime_s % 3600) / 60)}m` }),
            h('dt', { text: 'Authentication' }), h('dd', { text: v.auth ? 'API tokens (RBAC)' : 'Disabled (development mode)' }),
            h('dt', { text: 'Health' }), h('dd', {}, h('a', { href: '/healthz', target: '_blank', rel: 'noopener' }, '/healthz'), ' · ', h('a', { href: '/readyz', target: '_blank', rel: 'noopener' }, '/readyz')))),
        h('div', { class: 'card' }, h('h2', {}, 'AI assistant', aiBadge()),
          h('dl', { class: 'kv' }, h('dt', { text: 'Status' }), h('dd', { text: ai.enabled ? 'On' : `Off: ${ai.reason || ''}` }),
            ai.model ? [h('dt', { text: 'Model' }), h('dd', { text: `${ai.model} (effort ${ai.effort})` }), h('dt', { text: 'Usage' }), h('dd', { text: `${ai.used_this_hour} of ${ai.max_per_hour} requests this hour` })] : null),
          h('p', { class: 'hint', text: 'The assistant only proposes. Its recommendations are checked by the console and wait for approval like any other suggestion; secrets are redacted before data is sent. Configure it with -ai-key-file or the vault secret anthropic/api-key (docs/analysis.md).' })),
        h('div', { class: 'card' }, h('h2', { text: 'Keyboard' }),
          h('dl', { class: 'kv' }, h('dt', {}, h('code', { text: 'g' }), ' then a letter'), h('dd', { text: 'Go to: o overview, n incidents, u suggestions, y analysis, a alerts, h hosts, i investigate, v vulnerabilities, p posture, r rollouts, s settings' }),
            h('dt', {}, h('code', { text: '/' })), h('dd', { text: 'Focus the search box' }), h('dt', {}, h('code', { text: 'Esc' })), h('dd', { text: 'Close a panel or dialog' })))));
    },
  };

  // ---- router + refresh loop -----------------------------------------------
  const ROUTES = { '/': 'overview', '/incidents': 'incidents', '/suggestions': 'suggestions', '/analysis': 'analysis', '/alerts': 'alerts', '/hosts': 'hosts', '/investigate': 'investigate', '/vulnerabilities': 'vulnerabilities', '/posture': 'posture', '/rollouts': 'rollouts', '/settings': 'settings' };
  let current = null, timer = null, paused = false, loading = false;

  async function render() {
    const name = ROUTES[location.pathname] || 'overview';
    const page = pages[name];
    current = page;
    document.querySelectorAll('.side nav a').forEach((a) => { if (a.dataset.route === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    $('#title').textContent = page.title;
    document.title = `${page.title} · Wisp Console`;
    const main = clear($('#main'));
    page.mount(main, new URLSearchParams(location.search));
    await refresh(true);
    $('#side').classList.remove('open');
    $('#menu').setAttribute('aria-expanded', 'false');
  }
  async function refresh(first) {
    if (!current || loading) return;
    loading = true;
    try {
      await current.load();
      updateNavCount();
    } catch (e) {
      if (e.status !== 401 && first) clear($('#main')).append(errorBox(e));
    } finally { loading = false; paintLive(); }
  }
  async function updateNavCount() {
    try {
      const sm = await api('/api/summary');
      const n = (sm.alerts.open_by_severity.critical || 0) + (sm.alerts.open_by_severity.high || 0);
      const c = $('#nav-alerts');
      c.textContent = String(n); c.hidden = !n; c.title = `${n} open high or critical alerts`;
      const sg = await api('/api/suggestions');
      const cs = $('#nav-suggestions');
      cs.textContent = String(sg.length); cs.hidden = !sg.length; cs.title = `${sg.length} suggestion${sg.length === 1 ? '' : 's'} waiting for approval`;
    } catch { /* shown by banner */ }
  }
  function schedule() {
    clearInterval(timer);
    const secs = Number(store.pref('refresh', '10'));
    if (!secs) return;
    timer = setInterval(() => {
      if (paused || document.hidden || !$('#drawer').hidden || !$('#confirm').hidden) { paintLive(); return; }
      if (document.activeElement && document.activeElement.matches('input,select,textarea')) { paintLive(); return; }
      refresh(false);
    }, secs * 1000);
  }
  function navigate(path) {
    if (path !== location.pathname + location.search) history.pushState(null, '', path);
    render();
    $('#main').focus();
  }

  // ---- sign-in -------------------------------------------------------------
  function showSignin(msg) {
    clearInterval(timer);
    $('#app').hidden = true; $('#drawer').hidden = true; $('#signin').hidden = false;
    const err = $('#signin-err');
    err.textContent = msg || ''; err.hidden = !msg;
    $('#token').value = ''; $('#token').focus();
  }
  async function start() {
    if (!store.token) {
      // No token yet: check once whether this console runs without auth
      // (development mode) before showing the sign-in form.
      const r = await fetch('/api/session', { cache: 'no-store' }).catch(() => null);
      const sess = r && r.ok ? await r.json() : { auth: true };
      if (sess.auth) { showSignin(''); return; }
    }
    try {
      me = await api('/api/me');
    } catch (e) {
      if (e.status !== 401) { showSignin(e.message); }
      return;
    }
    $('#signin').hidden = true; $('#app').hidden = false;
    clear($('#who')).append(h('b', { text: me.name }), ` · ${me.role}`);
    api('/api/version').then((v) => { $('#ver').textContent = `v${v.version}`; }).catch(() => {});
    await render();
    schedule();
  }

  // ---- wiring --------------------------------------------------------------
  document.addEventListener('DOMContentLoaded', () => {
    applyTheme();
    matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyTheme);
    $('#theme').addEventListener('click', () => {
      const dark = document.documentElement.getAttribute('data-theme') === 'dark' || (!document.documentElement.getAttribute('data-theme') && matchMedia('(prefers-color-scheme: dark)').matches);
      store.setPref('theme', dark ? 'light' : 'dark'); applyTheme();
    });
    $('#pause').addEventListener('click', () => {
      paused = !paused;
      const b = $('#pause');
      clear(b).append(icon(paused ? 'i-play' : 'i-pause'));
      b.setAttribute('aria-label', paused ? 'Resume auto-refresh' : 'Pause auto-refresh'); b.title = b.getAttribute('aria-label');
      if (!paused) refresh(false);
      paintLive();
    });
    $('#menu').addEventListener('click', () => { const o = $('#side').classList.toggle('open'); $('#menu').setAttribute('aria-expanded', String(o)); });
    $('#drawer-close').addEventListener('click', closeDrawer);
    $('#drawer').addEventListener('click', (e) => { if (e.target.id === 'drawer') closeDrawer(); });
    $('#drawer').addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); trapFocus($('#drawer'), e); });
    $('#signin-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const tok = $('#token').value.trim();
      if (!tok) return;
      store.clearToken(); store.setToken(tok, $('#remember').checked);
      try { me = await api('/api/me'); start(); }
      catch (err) { store.clearToken(); showSignin(err.status === 401 ? 'That token was not accepted.' : err.message); }
    });
    // in-app navigation for same-origin links
    document.addEventListener('click', (e) => {
      const a = e.target.closest('a[href]');
      if (!a || a.target || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      const url = new URL(a.href, location.href);
      if (url.origin !== location.origin || !(url.pathname in ROUTES)) return;
      e.preventDefault();
      if (!$('#drawer').hidden) $('#drawer').hidden = true;
      navigate(url.pathname + url.search);
    });
    addEventListener('popstate', render);
    // keyboard: "g x" navigation, "/" search
    let g = false;
    document.addEventListener('keydown', (e) => {
      if (e.target.matches('input,select,textarea') || e.metaKey || e.ctrlKey || e.altKey || $('#app').hidden) return;
      if (e.key === '/') { const s = $('#main input[type="search"]'); if (s) { e.preventDefault(); s.focus(); } return; }
      if (g) { g = false; const m = { o: '/', n: '/incidents', u: '/suggestions', y: '/analysis', a: '/alerts', h: '/hosts', i: '/investigate', v: '/vulnerabilities', p: '/posture', r: '/rollouts', s: '/settings' }[e.key]; if (m) navigate(m); return; }
      if (e.key === 'g') { g = true; setTimeout(() => (g = false), 1200); }
    });
    setInterval(paintLive, 15000);
    start();
  });
})();
