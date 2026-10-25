// Wspólne funkcje frontendu: wywołania API, wylogowanie, timer bezczynności.

async function api(method, url, body) {
  const res = await fetch(url, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !url.startsWith('/api/login')) {
    location.href = '/login.html' + (data.expired ? '?expired=1' : '');
    throw new Error(data.error);
  }
  return { ok: res.ok, status: res.status, data };
}

function showMsg(el, text, type = 'error') {
  el.textContent = text;
  el.className = 'msg ' + type;
}

async function logout(expired = false) {
  await fetch('/api/logout', { method: 'POST' });
  location.href = '/login.html' + (expired ? '?expired=1' : '');
}

// Automatyczne wylogowanie po bezczynności.
function startIdleTimer(minutes, counterEl) {
  const limit = minutes * 60000;
  let last = Date.now();
  const reset = () => { last = Date.now(); };
  ['mousemove', 'keydown', 'click', 'scroll'].forEach((e) => addEventListener(e, reset, { passive: true }));
  const tick = () => {
    const left = limit - (Date.now() - last);
    if (left <= 0) return logout(true);
    if (counterEl) {
      const s = Math.ceil(left / 1000);
      counterEl.textContent = `Wylogowanie za ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
    }
  };
  tick();
  setInterval(tick, 1000);
}

// Tworzy element z tekstem - bez innerHTML, żeby dane użytkowników nie mogły wstrzyknąć HTML (XSS).
function el(tag, text, attrs = {}) {
  const e = document.createElement(tag);
  if (text !== undefined && text !== null) e.textContent = text;
  Object.assign(e, attrs);
  return e;
}

async function loadMe() {
  const { data } = await api('GET', '/api/me');
  if (data.mustChange && !location.pathname.startsWith('/change-password')) location.href = '/change-password.html';
  document.querySelectorAll('[data-who]').forEach((n) => { n.textContent = `${data.login} (${data.role})`; });
  startIdleTimer(data.sessionTimeoutMinutes, document.querySelector('[data-idle]'));
  return data;
}

// Tryb widoku: Standard / Pro; Wybór jest zapamiętany w przeglądarce.
(function viewMode() {
  const css = document.createElement('link');
  css.rel = 'stylesheet';
  css.href = '/theme-pro.css';
  document.head.append(css);

  let mode = 'standard';
  try { mode = localStorage.getItem('viewMode') || 'standard'; } catch { /* np. tryb prywatny */ }

  const btn = el('button', null, { type: 'button', className: 'theme-toggle', title: 'Przełącz widok Standard / Pro' });
  const apply = () => {
    document.body.classList.toggle('pro', mode === 'pro');
    btn.textContent = mode === 'pro' ? 'Widok: Pro' : 'Widok: Standard';
  };
  btn.onclick = () => {
    mode = mode === 'pro' ? 'standard' : 'pro';
    try { localStorage.setItem('viewMode', mode); } catch { /* ignorujemy */ }
    apply();
  };
  document.body.append(btn);
  apply();
})();
