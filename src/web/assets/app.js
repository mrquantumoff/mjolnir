'use strict';

const TOKEN_KEY = 'gorynych.token';
const FORMS_KEY = 'gorynych.forms';
const PEERS_KEY = 'gorynych.recentPeers';
const MAX_RECENT_PEERS = 8;
const POLL_ACTIVE_MS = 500;
const POLL_IDLE_MS = 3000;
const RATE_SMOOTHING = 0.3;
const MAX_LISTED_PATHS = 3;

const STATUS = {
  connecting: { label: 'Connecting', tone: 'pending' },
  handshaking: { label: 'Handshaking', tone: 'pending' },
  transferring: { label: 'Transferring', tone: 'active' },
  finishing: { label: 'Finishing', tone: 'active' },
  done: { label: 'Done', tone: 'ok' },
  failed: { label: 'Failed', tone: 'bad' },
  cancelled: { label: 'Cancelled', tone: 'muted' },
};

const CIPHER_LABELS = {
  Aes256Gcm: 'AES-256-GCM',
  ChaCha20Poly1305: 'ChaCha20-Poly1305',
};

const app = {
  token: null,
  authFailed: false,
  sendPaths: [],
  cards: new Map(),
  rates: new Map(),
  poll: { timer: null, inFlight: false, again: false },
};

const fsModal = {
  mode: 'files',
  path: null,
  parent: null,
  selected: new Set(),
  onConfirm: null,
  returnFocus: null,
  seq: 0,
};

class ApiError extends Error {
  constructor(status, message, field) {
    super(message);
    this.status = status;
    this.field = field;
  }
}

function $(id) {
  return document.getElementById(id);
}

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value == null || value === false) continue;
    if (key === 'class') el.className = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  for (const child of children.flat()) {
    if (child != null && child !== false) el.append(child);
  }
  return el;
}

function loadJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function saveJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Storage may be disabled or full; remembering values is best effort.
  }
}

function readToken() {
  const params = new URLSearchParams(location.hash.slice(1));
  const fromHash = params.get('token');
  if (fromHash) {
    try {
      sessionStorage.setItem(TOKEN_KEY, fromHash);
    } catch {
      // Without sessionStorage the token still works until the next reload.
    }
    history.replaceState(null, '', location.pathname + location.search);
    return fromHash;
  }
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function showAuthError() {
  app.authFailed = true;
  clearTimeout(app.poll.timer);
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {}
  closeBrowser();
  $('app').hidden = true;
  $('auth-error').hidden = false;
}

async function api(method, path, body) {
  const headers = { Authorization: 'Bearer ' + app.token };
  const options = { method, headers };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    if (body !== undefined) options.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, options);
  } catch {
    throw new ApiError(0, 'Cannot reach gorynych serve. Is it still running?', null);
  }
  if (res.status === 401) {
    showAuthError();
    throw new ApiError(401, 'Unauthorized', null);
  }
  if (res.status === 204) return null;
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const message = (data && data.error) || 'Request failed (HTTP ' + res.status + ')';
    throw new ApiError(res.status, message, (data && data.field) || null);
  }
  return data;
}

function showNotice(message) {
  const notice = $('notice');
  notice.textContent = message || '';
  notice.hidden = !message;
}

function formatBytes(n) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? value + ' B' : value.toFixed(value < 10 ? 2 : 1) + ' ' + units[unit];
}

function formatChunkSize(n) {
  return n >= 1048576 ? n / 1048576 + ' MiB' : n / 1024 + ' KiB';
}

function formatDuration(ms) {
  if (ms < 10000) return (Math.max(0, ms) / 1000).toFixed(1) + 's';
  const total = Math.max(0, Math.round(ms / 1000));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const pad = (n) => String(n).padStart(2, '0');
  if (hours > 0) return hours + 'h ' + pad(minutes) + 'm';
  if (minutes > 0) return minutes + 'm ' + pad(seconds) + 's';
  return seconds + 's';
}

function formatRate(bytesPerSecond) {
  return (bytesPerSecond / 1048576).toFixed(1) + ' MiB/s';
}

function abbreviateKey(key) {
  return key.length > 8 ? key.slice(0, 8) + '\u2026' : key;
}

function plural(n, word) {
  return n + ' ' + word + (n === 1 ? '' : 's');
}

function flashButton(button, text) {
  if (!button.dataset.label) button.dataset.label = button.textContent;
  button.textContent = text;
  clearTimeout(Number(button.dataset.flashTimer));
  button.dataset.flashTimer = String(setTimeout(() => {
    button.textContent = button.dataset.label;
  }, 1500));
}

function selectText(el) {
  const range = document.createRange();
  range.selectNodeContents(el);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

async function copyText(text, button, sourceEl) {
  try {
    await navigator.clipboard.writeText(text);
    flashButton(button, 'Copied');
  } catch {
    selectText(sourceEl);
    flashButton(button, 'Press Ctrl+C');
  }
}

async function loadIdentity() {
  try {
    const identity = await api('GET', '/api/identity');
    $('public-key').textContent = identity.public_key;
    $('key-path').textContent = identity.key_path;
  } catch (err) {
    if (err.status === 401) return;
    $('public-key').textContent = 'unavailable';
    $('key-path').textContent = 'Could not load your identity: ' + err.message;
  }
}

function togglePanel(which) {
  const panels = { send: 'send-panel', receive: 'receive-panel' };
  for (const [name, id] of Object.entries(panels)) {
    const open = name === which && $(id).hidden;
    $(id).hidden = !open;
    $('toggle-' + name).setAttribute('aria-expanded', String(open));
    if (open) $(id).querySelector('input, textarea, select').focus();
  }
}

function closePanels() {
  for (const name of ['send', 'receive']) {
    $(name + '-panel').hidden = true;
    $('toggle-' + name).setAttribute('aria-expanded', 'false');
  }
}

function clearErrors(form) {
  for (const el of form.querySelectorAll('[data-field-error], [data-form-error]')) {
    el.textContent = '';
    el.hidden = true;
  }
  for (const el of form.querySelectorAll('[aria-invalid]')) el.removeAttribute('aria-invalid');
}

function showFormError(form, field, message) {
  const fieldEl = field ? form.querySelector('[data-field-error="' + CSS.escape(field) + '"]') : null;
  const target = fieldEl || form.querySelector('[data-form-error]');
  target.textContent = message;
  target.hidden = false;
  const input = field ? form.elements.namedItem(field) : null;
  if (input && input.setAttribute) input.setAttribute('aria-invalid', 'true');
}

async function submitJob(form, path, body) {
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await api('POST', path, body);
    closePanels();
    requestPoll();
    return true;
  } catch (err) {
    if (err.status !== 401) showFormError(form, err.field, err.message);
    return false;
  } finally {
    button.disabled = false;
  }
}

function readSendForm() {
  return {
    addr: $('send-addr').value.trim(),
    peer: $('send-peer').value.trim(),
    paths: app.sendPaths.slice(),
    connections: Number($('send-connections').value),
    chunk_size: Number($('send-chunk').value),
    cipher: $('send-cipher').value,
  };
}

function readReceiveForm() {
  return {
    listen: $('receive-listen').value.trim(),
    authorized: parseAuthorized($('receive-authorized').value),
    out_dir: $('receive-out').value.trim(),
    force: $('receive-force').checked,
  };
}

function parseAuthorized(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => line.split(/\s+/)[0]);
}

async function onSendSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  clearErrors(form);
  const body = readSendForm();
  if (body.paths.length === 0) {
    showFormError(form, 'paths', 'Add at least one file or folder.');
    return;
  }
  if (!Number.isInteger(body.connections) || body.connections < 1 || body.connections > 64) {
    showFormError(form, 'connections', 'Use a whole number from 1 to 64.');
    return;
  }
  if (await submitJob(form, '/api/send', body)) {
    rememberPeer(body.addr, body.peer);
    app.sendPaths = [];
    renderSendPaths();
  }
}

function onReceiveSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  clearErrors(form);
  submitJob(form, '/api/receive', readReceiveForm());
}

function saveForms() {
  saveJson(FORMS_KEY, {
    send: {
      addr: $('send-addr').value,
      peer: $('send-peer').value,
      connections: $('send-connections').value,
      chunk_size: $('send-chunk').value,
      cipher: $('send-cipher').value,
    },
    receive: {
      listen: $('receive-listen').value,
      out_dir: $('receive-out').value,
      authorized: $('receive-authorized').value,
      force: $('receive-force').checked,
    },
  });
}

function restoreValue(id, value) {
  if (typeof value !== 'string') return;
  const el = $(id);
  if (el.tagName === 'SELECT' && ![...el.options].some((o) => o.value === value)) return;
  el.value = value;
}

function restoreForms() {
  const saved = loadJson(FORMS_KEY, null);
  if (!saved || typeof saved !== 'object') return;
  const send = saved.send || {};
  const receive = saved.receive || {};
  restoreValue('send-addr', send.addr);
  restoreValue('send-peer', send.peer);
  restoreValue('send-connections', send.connections);
  restoreValue('send-chunk', send.chunk_size);
  restoreValue('send-cipher', send.cipher);
  restoreValue('receive-listen', receive.listen);
  restoreValue('receive-out', receive.out_dir);
  restoreValue('receive-authorized', receive.authorized);
  if (typeof receive.force === 'boolean') $('receive-force').checked = receive.force;
}

function loadRecentPeers() {
  const peers = loadJson(PEERS_KEY, []);
  if (!Array.isArray(peers)) return [];
  return peers.filter((p) => p && typeof p.addr === 'string' && typeof p.peer === 'string');
}

function rememberPeer(addr, peer) {
  const others = loadRecentPeers().filter((p) => p.addr !== addr || p.peer !== peer);
  saveJson(PEERS_KEY, [{ addr, peer }, ...others].slice(0, MAX_RECENT_PEERS));
  renderRecentPeers();
}

function renderRecentPeers() {
  const peers = loadRecentPeers();
  const list = $('recent-peer-list');
  list.replaceChildren(...peers.map((p) => h('button', {
    type: 'button',
    class: 'chip mono',
    title: p.addr + '\n' + p.peer,
    onclick: () => pickPeer(p),
  }, p.addr + ' \u00b7 ' + abbreviateKey(p.peer))));
  $('recent-peers').hidden = peers.length === 0;
}

function pickPeer(peer) {
  $('send-addr').value = peer.addr;
  $('send-peer').value = peer.peer;
  saveForms();
}

function renderSendPaths() {
  const list = $('send-paths');
  if (app.sendPaths.length === 0) {
    list.replaceChildren(h('li', { class: 'path-empty muted' }, 'Nothing chosen yet.'));
    return;
  }
  list.replaceChildren(...app.sendPaths.map((path) => h('li', { class: 'path-item' },
    h('code', { class: 'mono path-text' }, path),
    h('button', {
      type: 'button',
      class: 'button small ghost',
      'aria-label': 'Remove ' + path,
      onclick: () => removeSendPath(path),
    }, 'Remove'),
  )));
}

function addSendPaths(paths) {
  for (const path of paths) {
    if (!app.sendPaths.includes(path)) app.sendPaths.push(path);
  }
  renderSendPaths();
  if (app.sendPaths.length > 0) {
    const error = $('send-form').querySelector('[data-field-error="paths"]');
    error.hidden = true;
  }
}

function removeSendPath(path) {
  app.sendPaths = app.sendPaths.filter((p) => p !== path);
  renderSendPaths();
}

function openBrowser(mode, startPath, onConfirm) {
  fsModal.mode = mode;
  fsModal.onConfirm = onConfirm;
  fsModal.selected = new Set();
  fsModal.path = null;
  fsModal.parent = null;
  fsModal.returnFocus = document.activeElement;
  $('fs-title').textContent = mode === 'folder' ? 'Choose output folder' : 'Choose files and folders';
  $('fs-confirm').textContent = mode === 'folder' ? 'Use this folder' : 'Add selected';
  $('fs-entries').replaceChildren();
  $('fs-roots').replaceChildren();
  $('fs-path').textContent = '';
  setBrowserError(null);
  updateBrowserFooter();
  $('fs-modal').hidden = false;
  document.body.classList.add('modal-open');
  $('fs-close').focus();
  loadDirectory(startPath || null, true);
}

function closeBrowser() {
  if ($('fs-modal').hidden) return;
  $('fs-modal').hidden = true;
  document.body.classList.remove('modal-open');
  fsModal.seq += 1;
  if (fsModal.returnFocus && fsModal.returnFocus.focus) fsModal.returnFocus.focus();
}

function confirmBrowser() {
  const picked = fsModal.mode === 'folder' ? fsModal.path : [...fsModal.selected];
  const onConfirm = fsModal.onConfirm;
  closeBrowser();
  onConfirm(picked);
}

function setBrowserError(message) {
  const box = $('fs-error');
  box.textContent = message || '';
  box.hidden = !message;
}

async function loadDirectory(path, fallBackToHome) {
  const seq = ++fsModal.seq;
  const query = path == null ? '' : '?path=' + encodeURIComponent(path);
  $('fs-entries').classList.add('is-loading');
  try {
    const listing = await api('GET', '/api/fs' + query);
    if (seq !== fsModal.seq) return;
    setBrowserError(null);
    renderDirectory(listing);
  } catch (err) {
    if (seq !== fsModal.seq || err.status === 401) return;
    setBrowserError(err.message);
    if (fallBackToHome && path != null) {
      await loadDirectory(null, false);
      if (fsModal.seq === seq + 1) setBrowserError(err.message + '\nShowing your home folder instead.');
    }
  } finally {
    if (seq === fsModal.seq) $('fs-entries').classList.remove('is-loading');
  }
}

function renderDirectory(listing) {
  fsModal.path = listing.path;
  fsModal.parent = listing.parent;
  $('fs-path').textContent = listing.path;
  $('fs-up').disabled = listing.parent == null;
  $('fs-roots').replaceChildren(...(listing.roots || []).map((root) => h('button', {
    type: 'button',
    class: 'chip mono',
    onclick: () => loadDirectory(root, false),
  }, root)));
  const entries = listing.entries || [];
  const items = entries.map(renderEntry);
  if (items.length === 0) items.push(h('li', { class: 'fs-empty muted' }, 'This folder is empty.'));
  $('fs-entries').replaceChildren(...items);
  $('fs-entries').scrollTop = 0;
  updateBrowserFooter();
}

function renderEntry(entry) {
  const size = entry.is_dir || entry.size == null ? '' : formatBytes(entry.size);
  const folderOnly = fsModal.mode === 'folder';
  const name = entry.is_dir
    ? h('button', { type: 'button', class: 'entry-name link', onclick: () => loadDirectory(entry.path, false) }, entry.name + '/')
    : h('span', { class: 'entry-name' + (folderOnly ? ' muted' : '') }, entry.name);
  const checkbox = folderOnly ? null : h('input', {
    type: 'checkbox',
    'aria-label': 'Select ' + entry.name,
    checked: fsModal.selected.has(entry.path),
    onchange: (event) => toggleSelected(entry.path, event.currentTarget.checked),
  });
  if (checkbox && !entry.is_dir) name.addEventListener('click', () => checkbox.click());
  return h('li', { class: 'fs-entry' + (folderOnly && !entry.is_dir ? ' is-disabled' : '') },
    checkbox,
    name,
    h('span', { class: 'entry-size muted tiny' }, size),
  );
}

function toggleSelected(path, checked) {
  if (checked) fsModal.selected.add(path);
  else fsModal.selected.delete(path);
  updateBrowserFooter();
}

function updateBrowserFooter() {
  if (fsModal.mode === 'folder') {
    $('fs-count').textContent = '';
    $('fs-confirm').disabled = fsModal.path == null;
    return;
  }
  const count = fsModal.selected.size;
  $('fs-count').textContent = count === 0 ? 'Nothing selected' : plural(count, 'item') + ' selected';
  $('fs-confirm').disabled = count === 0;
}

function statusOf(transfer) {
  return transfer.state === 'running' ? transfer.progress.phase : transfer.state;
}

function statusInfo(transfer) {
  const status = statusOf(transfer);
  if (transfer.kind === 'receive' && status === 'connecting') return { label: 'Listening', tone: 'pending' };
  return STATUS[status] || { label: status, tone: 'pending' };
}

function isUnspecifiedHost(addr) {
  return /^(0\.0\.0\.0|\[::\]):\d+$/.test(addr);
}

function buildSendDetails(spec) {
  const shown = spec.paths.slice(0, MAX_LISTED_PATHS);
  const hidden = spec.paths.length - shown.length;
  return [
    h('div', { class: 'card-meta' },
      'Peer ',
      h('code', { class: 'mono', title: spec.peer }, abbreviateKey(spec.peer)),
      ' \u00b7 ' + plural(spec.connections, 'connection'),
      ' \u00b7 ' + formatChunkSize(spec.chunk_size) + ' chunks',
      ' \u00b7 ' + (CIPHER_LABELS[spec.cipher] || spec.cipher)),
    h('ul', { class: 'card-files' },
      shown.map((path) => h('li', null, h('code', { class: 'mono' }, path))),
      hidden > 0 ? h('li', { class: 'muted' }, '+' + hidden + ' more') : null),
  ];
}

function buildReceiveDetails(spec, refs) {
  refs.boundLabel = h('span', { class: 'muted small' }, 'Listening on');
  refs.boundAddr = h('code', { class: 'mono bound-addr' }, spec.listen);
  refs.boundHint = h('p', { class: 'muted tiny' }, 'Senders connect to this machine\u2019s IP address on that port.');
  const copy = h('button', {
    type: 'button',
    class: 'button small',
    onclick: (event) => copyText(refs.boundAddr.textContent, event.currentTarget, refs.boundAddr),
  }, 'Copy');
  return [
    h('div', { class: 'bound' }, refs.boundLabel, refs.boundAddr, copy),
    refs.boundHint,
    h('div', { class: 'card-meta' },
      plural(spec.authorized.length, 'authorized key'),
      ' \u00b7 into ',
      h('code', { class: 'mono' }, spec.out_dir),
      spec.force ? ' \u00b7 overwrites existing files' : ''),
  ];
}

function buildCard(transfer) {
  const refs = {};
  const isSend = transfer.kind === 'send';
  const created = new Date(transfer.created_at_ms).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
  refs.badge = h('span', { class: 'badge' });
  refs.fill = h('div', { class: 'progress-fill' });
  refs.bar = h('div', { class: 'progress', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100 }, refs.fill);
  refs.bytes = h('span', { class: 'stat-bytes' });
  refs.rate = h('span', { class: 'stat' });
  refs.eta = h('span', { class: 'stat' });
  refs.conns = h('span', { class: 'stat' });
  refs.error = h('div', { class: 'error-box', role: 'alert', hidden: true });
  refs.report = h('div', { class: 'report', hidden: true });
  refs.actionError = h('p', { class: 'field-error', hidden: true });
  refs.cancel = h('button', { type: 'button', class: 'button small', onclick: () => cancelTransfer(transfer.id, refs) }, 'Cancel');
  refs.remove = h('button', { type: 'button', class: 'button small ghost', onclick: () => removeTransfer(transfer.id, refs) }, 'Remove');
  const details = isSend ? buildSendDetails(transfer.spec) : buildReceiveDetails(transfer.spec, refs);
  refs.root = h('li', { class: 'card card-' + transfer.kind },
    h('div', { class: 'card-head' },
      h('span', { class: 'kind' }, isSend ? 'Send' : 'Receive'),
      isSend ? h('span', { class: 'card-target' }, 'to ', h('code', { class: 'mono' }, transfer.spec.addr)) : null,
      h('span', { class: 'card-time muted tiny' }, created),
      refs.badge),
    details,
    refs.bar,
    h('div', { class: 'card-stats' }, refs.bytes, refs.rate, refs.eta, refs.conns),
    refs.error,
    refs.report,
    h('div', { class: 'card-actions' }, refs.actionError, refs.cancel, refs.remove));
  return refs;
}

function sampleRate(transfer) {
  const p = transfer.progress;
  if (transfer.state !== 'running' || p.phase !== 'transferring') {
    app.rates.delete(transfer.id);
    return null;
  }
  const prev = app.rates.get(transfer.id);
  const sample = { bytes: p.bytes_done, t: transfer.elapsed_ms, ewma: prev ? prev.ewma : null };
  if (prev) {
    const dt = sample.t - prev.t;
    if (dt <= 0) return prev.ewma;
    const instant = ((sample.bytes - prev.bytes) / dt) * 1000;
    sample.ewma = prev.ewma == null ? instant : RATE_SMOOTHING * instant + (1 - RATE_SMOOTHING) * prev.ewma;
  }
  app.rates.set(transfer.id, sample);
  return sample.ewma;
}

function progressText(transfer) {
  const p = transfer.progress;
  if (p.bytes_total > 0) {
    const pct = Math.floor((p.bytes_done / p.bytes_total) * 100);
    return formatBytes(p.bytes_done) + ' of ' + formatBytes(p.bytes_total) + ' (' + pct + '%)';
  }
  if (transfer.state !== 'running') return formatBytes(p.bytes_done);
  return transfer.kind === 'receive' ? 'Waiting for sender\u2026' : statusInfo(transfer).label + '\u2026';
}

function progressPercent(transfer) {
  const p = transfer.progress;
  if (p.bytes_total > 0) return Math.min(100, (p.bytes_done / p.bytes_total) * 100);
  return transfer.state === 'done' ? 100 : 0;
}

function reportText(report) {
  const parts = [plural(report.files, 'file'), formatBytes(report.bytes), formatDuration(report.elapsed_ms)];
  if (report.elapsed_ms > 0) parts.push(formatRate((report.bytes / report.elapsed_ms) * 1000) + ' average');
  return parts.join(' \u00b7 ');
}

function updateCard(refs, transfer) {
  const running = transfer.state === 'running';
  const info = statusInfo(transfer);
  const p = transfer.progress;
  refs.root.dataset.tone = info.tone;
  refs.badge.textContent = info.label;
  refs.badge.className = 'badge badge-' + info.tone;

  const pct = progressPercent(transfer);
  refs.fill.style.width = pct + '%';
  refs.bar.setAttribute('aria-valuenow', String(Math.round(pct)));
  refs.bar.classList.toggle('is-waiting', running && p.bytes_total === 0);
  refs.bytes.textContent = progressText(transfer);

  const rate = sampleRate(transfer);
  const showRate = rate != null && rate >= 0;
  refs.rate.hidden = !showRate;
  refs.eta.hidden = !(showRate && rate > 0 && p.bytes_total > 0);
  if (showRate) refs.rate.textContent = formatRate(rate);
  if (!refs.eta.hidden) refs.eta.textContent = formatDuration(((p.bytes_total - p.bytes_done) / rate) * 1000) + ' left';
  refs.conns.hidden = !running || p.active_connections === 0;
  refs.conns.textContent = plural(p.active_connections, 'connection') + ' active';

  refs.error.hidden = !transfer.error;
  refs.error.textContent = transfer.error || '';
  refs.report.hidden = !transfer.report;
  refs.report.textContent = transfer.report ? reportText(transfer.report) : '';

  if (refs.boundAddr) {
    const addr = transfer.bound_addr || transfer.spec.listen;
    refs.boundAddr.textContent = addr;
    refs.boundLabel.textContent = running ? 'Listening on' : 'Listened on';
    refs.boundHint.hidden = !running || !isUnspecifiedHost(addr);
  }
  refs.cancel.hidden = !running;
  refs.remove.hidden = running;
}

function renderTransfers(transfers) {
  const list = $('transfer-list');
  const seen = new Set();
  transfers.forEach((transfer, index) => {
    seen.add(transfer.id);
    let refs = app.cards.get(transfer.id);
    if (!refs) {
      refs = buildCard(transfer);
      app.cards.set(transfer.id, refs);
    }
    updateCard(refs, transfer);
    if (list.children[index] !== refs.root) list.insertBefore(refs.root, list.children[index] || null);
  });
  for (const [id, refs] of app.cards) {
    if (!seen.has(id)) dropCard(id, refs);
  }
  $('transfers-empty').hidden = transfers.length > 0;
}

function dropCard(id, refs) {
  refs.root.remove();
  app.cards.delete(id);
  app.rates.delete(id);
}

function showCardError(refs, message) {
  refs.actionError.textContent = message || '';
  refs.actionError.hidden = !message;
}

async function cancelTransfer(id, refs) {
  showCardError(refs, null);
  refs.cancel.disabled = true;
  try {
    const transfer = await api('POST', '/api/transfers/' + id + '/cancel', {});
    updateCard(refs, transfer);
  } catch (err) {
    if (err.status !== 401) showCardError(refs, err.message);
  } finally {
    refs.cancel.disabled = false;
    requestPoll();
  }
}

async function removeTransfer(id, refs) {
  showCardError(refs, null);
  refs.remove.disabled = true;
  try {
    await api('DELETE', '/api/transfers/' + id);
    dropCard(id, refs);
    $('transfers-empty').hidden = app.cards.size > 0;
  } catch (err) {
    if (err.status !== 401) showCardError(refs, err.message);
  } finally {
    refs.remove.disabled = false;
    requestPoll();
  }
}

function schedulePoll(delay) {
  clearTimeout(app.poll.timer);
  app.poll.timer = setTimeout(pollTransfers, delay);
}

function requestPoll() {
  if (app.authFailed) return;
  if (app.poll.inFlight) app.poll.again = true;
  else schedulePoll(0);
}

async function pollTransfers() {
  app.poll.timer = null;
  app.poll.inFlight = true;
  let delay = POLL_IDLE_MS;
  try {
    const data = await api('GET', '/api/transfers');
    const transfers = data.transfers || [];
    renderTransfers(transfers);
    showNotice(null);
    if (transfers.some((t) => t.state === 'running')) delay = POLL_ACTIVE_MS;
  } catch (err) {
    if (err.status !== 401) showNotice('Could not refresh transfers: ' + err.message);
  }
  app.poll.inFlight = false;
  if (app.authFailed) return;
  schedulePoll(app.poll.again ? 0 : delay);
  app.poll.again = false;
}

function onKeydown(event) {
  if (event.key === 'Escape' && !$('fs-modal').hidden) {
    event.preventDefault();
    closeBrowser();
  }
}

function bindEvents() {
  $('toggle-send').addEventListener('click', () => togglePanel('send'));
  $('toggle-receive').addEventListener('click', () => togglePanel('receive'));
  $('copy-key').addEventListener('click', (event) => copyText($('public-key').textContent, event.currentTarget, $('public-key')));
  $('send-form').addEventListener('submit', onSendSubmit);
  $('receive-form').addEventListener('submit', onReceiveSubmit);
  $('send-form').addEventListener('input', saveForms);
  $('receive-form').addEventListener('input', saveForms);
  $('add-paths').addEventListener('click', () => openBrowser('files', null, addSendPaths));
  $('browse-out').addEventListener('click', () => openBrowser('folder', $('receive-out').value.trim(), (path) => {
    $('receive-out').value = path;
    saveForms();
  }));
  $('fs-up').addEventListener('click', () => {
    if (fsModal.parent != null) loadDirectory(fsModal.parent, false);
  });
  $('fs-close').addEventListener('click', closeBrowser);
  $('fs-cancel').addEventListener('click', closeBrowser);
  $('fs-confirm').addEventListener('click', confirmBrowser);
  $('fs-modal').addEventListener('click', (event) => {
    if (event.target === event.currentTarget) closeBrowser();
  });
  document.addEventListener('keydown', onKeydown);
  // Pasting a fresh #token URL into an open tab only changes the fragment, so reload to pick it up.
  window.addEventListener('hashchange', () => {
    if (new URLSearchParams(location.hash.slice(1)).get('token')) location.reload();
  });
}

function init() {
  bindEvents();
  app.token = readToken();
  if (!app.token) {
    showAuthError();
    return;
  }
  $('app').hidden = false;
  restoreForms();
  renderRecentPeers();
  renderSendPaths();
  loadIdentity();
  pollTransfers();
}

init();
