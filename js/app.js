/* =====================================================================
   JWT Decoder Pro — app.js
   Decodes and inspects a JWT's header + payload. Never verifies a
   signature, never asks for a secret/key. Classic script (no modules).
   Depends on window.WUS (core.js).
   ===================================================================== */
(function () {
  'use strict';

  var WUS = window.WUS;
  var STORE_KEY = 'jwtdecoder.state';

  /* ----------------------------- DOM refs ---------------------------- */
  var tokenInput   = document.getElementById('tokenInput');
  var tokenStats   = document.getElementById('tokenStats');

  var statusBadge  = document.getElementById('statusBadge');
  var statusText   = document.getElementById('statusText');

  var errorPanel   = document.getElementById('errorPanel');
  var errorMsg     = document.getElementById('errorMsg');

  var warningsRow  = document.getElementById('warnings');

  var claimsPanel  = document.getElementById('claimsPanel');
  var claimsGrid   = document.getElementById('claimsGrid');
  var headerBadges = document.getElementById('headerBadges');

  var headerOutput = document.getElementById('headerOutput');
  var headerCode   = document.getElementById('headerCode');
  var headerEmpty  = document.getElementById('headerEmpty');

  var payloadOutput = document.getElementById('payloadOutput');
  var payloadCode   = document.getElementById('payloadCode');
  var payloadEmpty  = document.getElementById('payloadEmpty');

  var lastHeaderJson = '';
  var lastPayloadJson = '';
  var liveIntervals = [];

  /* Standard claims rendered in their own dedicated cards above — every
     other top-level payload claim is still shown, just generically. */
  var KNOWN_CLAIMS = { iss: 1, sub: 1, aud: 1, exp: 1, iat: 1, nbf: 1 };

  /* =================================================================
     BASE64URL DECODE (UTF-8 safe)
     ================================================================= */
  function base64UrlDecodeToString(seg) {
    // Strip any whitespace picked up from copy/paste (line wraps in a
    // terminal, email, or code block) before computing padding — otherwise
    // a stray newline/space throws off the length%4 check even though the
    // underlying base64 data is perfectly valid.
    var b64 = seg.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    var pad = b64.length % 4;
    if (pad === 2) b64 += '==';
    else if (pad === 3) b64 += '=';
    else if (pad !== 0) throw new Error('Invalid base64url segment length');
    var binary = atob(b64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    if (window.TextDecoder) {
      return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    }
    // Fallback for very old browsers.
    return decodeURIComponent(escape(binary));
  }

  function base64UrlEncodeString(str) {
    var bytes;
    if (window.TextEncoder) {
      bytes = new TextEncoder().encode(str);
    } else {
      var utf8 = unescape(encodeURIComponent(str));
      bytes = new Uint8Array(utf8.length);
      for (var i = 0; i < utf8.length; i++) bytes[i] = utf8.charCodeAt(i);
    }
    var binary = '';
    for (var j = 0; j < bytes.length; j++) binary += String.fromCharCode(bytes[j]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /* =================================================================
     SYNTAX HIGHLIGHTING (adapted from JSON Formatter Pro)
     ================================================================= */
  function highlight(jsonText) {
    var re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false)\b|\b(null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}\[\],:])/g;
    var out = '';
    var lastIndex = 0;
    var m;
    while ((m = re.exec(jsonText)) !== null) {
      if (m.index > lastIndex) out += WUS.escapeHtml(jsonText.slice(lastIndex, m.index));
      lastIndex = re.lastIndex;
      if (m[1] !== undefined) {
        var isKey = m[2] !== undefined;
        out += '<span class="' + (isKey ? 'tok-key' : 'tok-string') + '">' + WUS.escapeHtml(m[1]) + '</span>';
        if (isKey) out += '<span class="tok-punct">' + WUS.escapeHtml(m[2]) + '</span>';
      } else if (m[3] !== undefined) {
        out += '<span class="tok-boolean">' + m[3] + '</span>';
      } else if (m[4] !== undefined) {
        out += '<span class="tok-null">' + m[4] + '</span>';
      } else if (m[5] !== undefined) {
        out += '<span class="tok-number">' + WUS.escapeHtml(m[5]) + '</span>';
      } else if (m[6] !== undefined) {
        var cls = (m[6] === '{' || m[6] === '}' || m[6] === '[' || m[6] === ']') ? 'tok-brace' : 'tok-punct';
        out += '<span class="' + cls + '">' + WUS.escapeHtml(m[6]) + '</span>';
      }
    }
    if (lastIndex < jsonText.length) out += WUS.escapeHtml(jsonText.slice(lastIndex));
    return out;
  }

  /* =================================================================
     STATUS / helpers
     ================================================================= */
  function setStatus(state, text) {
    statusBadge.classList.remove('is-valid', 'is-error', 'is-warning');
    if (state) statusBadge.classList.add('is-' + state);
    statusText.textContent = text;
  }

  function clearLiveIntervals() {
    liveIntervals.forEach(function (id) { clearInterval(id); });
    liveIntervals = [];
  }

  function showError(msg) {
    errorMsg.textContent = msg;
    errorPanel.hidden = false;
  }
  function clearError() {
    errorPanel.hidden = true;
  }

  function clearAllOutputs() {
    clearLiveIntervals();
    lastHeaderJson = '';
    lastPayloadJson = '';
    headerCode.innerHTML = '';
    payloadCode.innerHTML = '';
    headerEmpty.classList.remove('is-hidden');
    payloadEmpty.classList.remove('is-hidden');
    claimsPanel.hidden = true;
    warningsRow.hidden = true;
    warningsRow.innerHTML = '';
    headerBadges.innerHTML = '';
    claimsGrid.innerHTML = '';
  }

  /* =================================================================
     TIME FORMATTING
     ================================================================= */
  function humanDate(unixSeconds) {
    var d = new Date(unixSeconds * 1000);
    if (isNaN(d.getTime())) return 'Invalid date';
    try { return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' }); }
    catch (e) { return d.toString(); }
  }

  function durationParts(ms) {
    var neg = ms < 0;
    ms = Math.abs(ms);
    var s = Math.floor(ms / 1000);
    var days = Math.floor(s / 86400); s -= days * 86400;
    var h = Math.floor(s / 3600); s -= h * 3600;
    var m = Math.floor(s / 60); s -= m * 60;
    var parts = [];
    if (days) parts.push(days + 'd');
    if (h || days) parts.push(h + 'h');
    if (m || h || days) parts.push(m + 'm');
    parts.push(s + 's');
    return { neg: neg, text: parts.join(' ') };
  }

  function attachLiveCountdown(el, unixSeconds, kind) {
    function tick() {
      var diffMs = unixSeconds * 1000 - Date.now();
      var d = durationParts(diffMs);
      if (kind === 'exp') {
        if (d.neg) { el.textContent = 'Expired ' + d.text + ' ago'; el.className = 'claim-sub is-expired'; }
        else { el.textContent = 'Expires in ' + d.text; el.className = 'claim-sub is-active'; }
      } else if (kind === 'nbf') {
        if (d.neg) { el.textContent = 'Valid since ' + d.text + ' ago'; el.className = 'claim-sub is-active'; }
        else { el.textContent = 'Not valid for another ' + d.text; el.className = 'claim-sub is-expired'; }
      } else if (kind === 'iat') {
        if (d.neg) { el.textContent = 'Issued ' + d.text + ' ago'; el.className = 'claim-sub'; }
        else { el.textContent = 'Issued ' + d.text + ' from now'; el.className = 'claim-sub'; }
      }
    }
    tick();
    var id = setInterval(tick, 1000);
    liveIntervals.push(id);
  }

  /* =================================================================
     RENDERING
     ================================================================= */
  function badge(text, variant) {
    var span = document.createElement('span');
    span.className = 'badge' + (variant ? ' badge--' + variant : '');
    span.textContent = text;
    return span;
  }

  function renderHeaderBadges(header) {
    headerBadges.innerHTML = '';
    if (header && header.typ !== undefined) headerBadges.appendChild(badge('typ: ' + header.typ, 'info'));
    if (header && header.alg !== undefined) {
      var isNone = String(header.alg).toLowerCase() === 'none';
      headerBadges.appendChild(badge('alg: ' + header.alg, isNone ? 'danger' : 'success'));
    }
  }

  function claimCard(label, value, subEl) {
    var card = document.createElement('div');
    card.className = 'claim-card';
    var l = document.createElement('div'); l.className = 'claim-label'; l.textContent = label;
    var v = document.createElement('div'); v.className = 'claim-value'; v.textContent = value;
    card.appendChild(l); card.appendChild(v);
    if (subEl) card.appendChild(subEl);
    return card;
  }

  function renderClaims(header, payload) {
    claimsGrid.innerHTML = '';
    renderHeaderBadges(header);

    if (payload && payload.exp !== undefined && !isNaN(Number(payload.exp))) {
      var expSub = document.createElement('div'); expSub.className = 'claim-sub';
      claimsGrid.appendChild(claimCard('exp', humanDate(payload.exp), expSub));
      attachLiveCountdown(expSub, Number(payload.exp), 'exp');
    }
    if (payload && payload.iat !== undefined && !isNaN(Number(payload.iat))) {
      var iatSub = document.createElement('div'); iatSub.className = 'claim-sub';
      claimsGrid.appendChild(claimCard('iat (issued at)', humanDate(payload.iat), iatSub));
      attachLiveCountdown(iatSub, Number(payload.iat), 'iat');
    }
    if (payload && payload.nbf !== undefined && !isNaN(Number(payload.nbf))) {
      var nbfSub = document.createElement('div'); nbfSub.className = 'claim-sub';
      claimsGrid.appendChild(claimCard('nbf (not before)', humanDate(payload.nbf), nbfSub));
      attachLiveCountdown(nbfSub, Number(payload.nbf), 'nbf');
    }
    if (payload && payload.sub !== undefined) claimsGrid.appendChild(claimCard('sub', String(payload.sub)));
    if (payload && payload.iss !== undefined) claimsGrid.appendChild(claimCard('iss', String(payload.iss)));
    if (payload && payload.aud !== undefined) {
      var aud = Array.isArray(payload.aud) ? payload.aud.join(', ') : String(payload.aud);
      claimsGrid.appendChild(claimCard('aud', aud));
    }

    // Any other top-level payload claims, shown generically.
    if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
      Object.keys(payload).sort().forEach(function (key) {
        if (KNOWN_CLAIMS[key]) return;
        var v = payload[key];
        var text = v === null ? 'null' : (typeof v === 'object' ? JSON.stringify(v) : String(v));
        claimsGrid.appendChild(claimCard(key, text));
      });
    }

    claimsPanel.hidden = claimsGrid.children.length === 0 && headerBadges.children.length === 0;
  }

  function renderWarnings(header, sigMissing) {
    warningsRow.innerHTML = '';
    var flags = [];
    if (header && String(header.alg).toLowerCase() === 'none') {
      flags.push(badge('⚠ alg is "none" — this token requires NO signature at all', 'danger'));
    }
    if (sigMissing) {
      flags.push(badge('⚠ Signature segment is empty or missing', 'danger'));
    }
    flags.forEach(function (b) { warningsRow.appendChild(b); });
    warningsRow.hidden = flags.length === 0;
    return flags.length > 0;
  }

  /* =================================================================
     CORE DECODE
     ================================================================= */
  function decode() {
    clearError();
    var raw = tokenInput.value.trim();

    if (!raw) {
      clearAllOutputs();
      setStatus('', 'Ready');
      return;
    }

    var parts = raw.split('.');
    if (parts.length < 2 || parts.length > 3) {
      clearAllOutputs();
      showError('A JWT must have 2 or 3 dot-separated segments (header.payload[.signature]). Found ' + parts.length + '.');
      setStatus('error', 'Invalid');
      return;
    }

    var headerJson, payloadJson, headerObj, payloadObj;
    try {
      headerJson = base64UrlDecodeToString(parts[0]);
      headerObj = JSON.parse(headerJson);
    } catch (e) {
      clearAllOutputs();
      showError('Could not decode header: ' + e.message);
      setStatus('error', 'Invalid');
      return;
    }
    try {
      payloadJson = base64UrlDecodeToString(parts[1]);
      payloadObj = JSON.parse(payloadJson);
    } catch (e) {
      clearAllOutputs();
      showError('Could not decode payload: ' + e.message);
      setStatus('error', 'Invalid');
      return;
    }

    clearLiveIntervals();

    var prettyHeader = JSON.stringify(headerObj, null, 2);
    var prettyPayload = JSON.stringify(payloadObj, null, 2);
    lastHeaderJson = prettyHeader;
    lastPayloadJson = prettyPayload;

    headerCode.innerHTML = highlight(prettyHeader);
    payloadCode.innerHTML = highlight(prettyPayload);
    headerEmpty.classList.add('is-hidden');
    payloadEmpty.classList.add('is-hidden');

    var sigMissing = parts.length < 3 || !parts[2];
    var hasWarning = renderWarnings(headerObj, sigMissing);
    renderClaims(headerObj, payloadObj);

    if (hasWarning) setStatus('warning', 'Decoded — warnings');
    else setStatus('valid', 'Decoded');
  }

  var decodeDebounced = WUS.debounce(decode, 250);

  /* =================================================================
     ACTIONS
     ================================================================= */
  function copyHeader() {
    if (!lastHeaderJson) { WUS.toast('Nothing to copy yet', 'error'); return; }
    WUS.copy(lastHeaderJson, 'Header JSON copied');
  }
  function copyPayload() {
    if (!lastPayloadJson) { WUS.toast('Nothing to copy yet', 'error'); return; }
    WUS.copy(lastPayloadJson, 'Payload JSON copied');
  }

  function clearAll() {
    tokenInput.value = '';
    clearAllOutputs();
    clearError();
    setStatus('', 'Ready');
    updateTokenStats();
    WUS.store.remove(STORE_KEY);
    tokenInput.focus();
  }

  /* Builds a realistic, entirely fake sample JWT client-side — header and
     payload are base64url-encoded locally, the signature segment is a
     harmless dummy string. No network call, no real JWT service involved. */
  function buildSampleToken() {
    var now = Math.floor(Date.now() / 1000);
    var header = { alg: 'HS256', typ: 'JWT' };
    var payload = {
      sub: '1234567890',
      name: 'Ada Lovelace',
      iss: 'https://auth.example.com',
      aud: 'https://api.example.com',
      roles: ['admin', 'engineer'],
      iat: now - 300,
      nbf: now - 300,
      exp: now + 3600
    };
    var headerPart = base64UrlEncodeString(JSON.stringify(header));
    var payloadPart = base64UrlEncodeString(JSON.stringify(payload));
    var signaturePart = base64UrlEncodeString('sample-signature-not-a-real-hmac-do-not-trust');
    return headerPart + '.' + payloadPart + '.' + signaturePart;
  }

  function loadSample() {
    tokenInput.value = buildSampleToken();
    updateTokenStats();
    decode();
    persist();
    WUS.toast('Sample token loaded');
  }

  function updateTokenStats() {
    var len = tokenInput.value.length;
    tokenStats.textContent = len.toLocaleString() + (len === 1 ? ' char' : ' chars');
  }

  /* =================================================================
     PERSISTENCE
     ================================================================= */
  function persist() {
    WUS.store.set(STORE_KEY, { token: tokenInput.value });
  }
  var persistDebounced = WUS.debounce(persist, 400);

  function restore() {
    var saved = WUS.store.get(STORE_KEY, null);
    if (!saved || typeof saved.token !== 'string') return;
    tokenInput.value = saved.token;
    updateTokenStats();
    decode();
  }

  /* =================================================================
     SHORTCUTS HELP MODAL
     ================================================================= */
  var helpBackdrop = document.getElementById('helpBackdrop');
  var helpClose    = document.getElementById('helpClose');
  var shortcutRows = document.getElementById('shortcutRows');

  var SHORTCUTS = [
    { keys: ['mod', '⏎'], desc: 'Decode now' },
    { keys: ['mod', 'K'], desc: 'Clear token' },
    { keys: ['?'], desc: 'Show this help' },
    { keys: ['Esc'], desc: 'Close dialog' }
  ];

  function buildShortcutTable() {
    var html = '';
    SHORTCUTS.forEach(function (s) {
      var kbds = s.keys.map(function (k) { return '<kbd>' + WUS.escapeHtml(k) + '</kbd>'; }).join('');
      html += '<tr><td>' + WUS.escapeHtml(s.desc) + '</td><td>' + kbds + '</td></tr>';
    });
    shortcutRows.innerHTML = html;
  }

  function openHelp() { helpBackdrop.hidden = false; helpClose.focus(); }
  function closeHelp() { helpBackdrop.hidden = true; }

  helpClose.addEventListener('click', closeHelp);
  helpBackdrop.addEventListener('click', function (e) { if (e.target === helpBackdrop) closeHelp(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !helpBackdrop.hidden) closeHelp();
  });
  var helpBtns = document.querySelectorAll('[data-shortcut-help]');
  for (var i = 0; i < helpBtns.length; i++) helpBtns[i].addEventListener('click', openHelp);

  /* =================================================================
     WIRING
     ================================================================= */
  document.getElementById('btnClear').addEventListener('click', clearAll);
  document.getElementById('btnSample').addEventListener('click', loadSample);
  document.getElementById('btnCopyHeader').addEventListener('click', copyHeader);
  document.getElementById('btnCopyPayload').addEventListener('click', copyPayload);

  tokenInput.addEventListener('input', function () {
    updateTokenStats();
    decodeDebounced();
    persistDebounced();
  });

  tokenInput.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      decode();
    }
  });

  WUS.registerShortcut('mod+enter', function () { decode(); }, 'Decode now');
  WUS.registerShortcut('mod+k', function () { clearAll(); }, 'Clear token');
  WUS.registerShortcut('?', function () { openHelp(); }, 'Show shortcuts');

  /* =================================================================
     INIT
     ================================================================= */
  buildShortcutTable();
  updateTokenStats();
  restore();
})();
