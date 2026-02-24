/**
 * Sentinel IDS — script.js
 * Fetches /alerts every 5 s, parses JSON, renders table + summary cards.
 * No frameworks. No external dependencies.
 */

'use strict';

/* ── DOM references ─────────────────────────────────────── */
const alertBody = document.getElementById('alertBody');
const alertCount = document.getElementById('alertCount');
const lastUpdated = document.getElementById('lastUpdated');
const statusDot = document.getElementById('statusDot');
const statusLabel = document.getElementById('statusLabel');
const placeholderRow = document.getElementById('placeholderRow');
const btnClear = document.getElementById('btnClear');

const countEls = {
    total: document.getElementById('count-total'),
    DDoS: document.getElementById('count-ddos'),
    DoS: document.getElementById('count-dos'),
    PortScan: document.getElementById('count-portscan'),
    BruteForce: document.getElementById('count-bruteforce'),
};

/* Modal refs */
const alertModal = document.getElementById('alertModal');
const modalClose = document.getElementById('modalClose');
const modalCloseBtn = document.getElementById('modalCloseBtn');
const modalBadge = document.getElementById('modalBadge');
const modalReceivedAt = document.getElementById('modalReceivedAt');
const mTimestamp = document.getElementById('mTimestamp');
const mSrcIp = document.getElementById('mSrcIp');
const mDstIp = document.getElementById('mDstIp');
const mProtocol = document.getElementById('mProtocol');
const mScoreFill = document.getElementById('mScoreFill');
const mScorePct = document.getElementById('mScorePct');

/* ── State ──────────────────────────────────────────────── */
let cleared = false;           // true while "Clear" is active
let prevTimestamps = new Set();
const rowDataMap = new Map();       // key → raw alert object for modal

/* ── Helpers ────────────────────────────────────────────── */

/** Format ISO or "YYYY-MM-DD HH:MM:SS" to local readable string */
function fmtTime(raw) {
    if (!raw) return '—';
    const d = new Date(raw.replace(' ', 'T'));
    if (isNaN(d)) return raw;
    return d.toLocaleString(undefined, {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        hour12: false,
    });
}

/** Return badge HTML for a given attack type */
function badgeFor(type) {
    const map = {
        ddos: ['DDoS', 'badge--ddos'],
        dos: ['DoS', 'badge--dos'],
        portscan: ['Port Scan', 'badge--portscan'],
        bruteforce: ['Brute Force', 'badge--bruteforce'],
    };
    const key = (type || '').toLowerCase().replace(/[\s_-]/g, '');
    const [label, cls] = map[key] || [type || 'Unknown', 'badge--unknown'];
    return `<span class="badge ${cls}">${label}</span>`;
}

/** Normalise attack_type key to match countEls keys */
function normaliseType(type) {
    const map = {
        ddos: 'DDoS',
        dos: 'DoS',
        portscan: 'PortScan',
        bruteforce: 'BruteForce',
    };
    return map[(type || '').toLowerCase().replace(/[\s_-]/g, '')] || null;
}

/** Build the confidence cell */
function confidenceCell(raw) {
    const pct = Math.min(100, Math.max(0, Math.round((raw ?? 0) * 100)));
    let fillClass = 'high';
    if (pct < 50) fillClass = 'low';
    else if (pct < 80) fillClass = 'medium';

    return `
    <td>
      <div class="confidence-wrap">
        <div class="confidence-bar">
          <div class="confidence-fill ${fillClass}" style="width:${pct}%"></div>
        </div>
        <span class="confidence-pct">${pct}%</span>
      </div>
    </td>`;
}

/** Animate a counter element to a target value */
function animateCount(el, target) {
    const current = parseInt(el.textContent, 10) || 0;
    if (current === target) return;
    const step = Math.ceil(Math.abs(target - current) / 12);
    const dir = target > current ? 1 : -1;
    const tick = () => {
        const now = parseInt(el.textContent, 10) || 0;
        const next = now + dir * step;
        if ((dir > 0 && next >= target) || (dir < 0 && next <= target)) {
            el.textContent = target;
        } else {
            el.textContent = next;
            requestAnimationFrame(tick);
        }
    };
    requestAnimationFrame(tick);
}

/** Human-readable protocol label */
function protocolLabel(proto) {
    if (proto === null || proto === undefined) return '—';
    const names = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6', 58: 'ICMPv6' };
    const n = parseInt(proto, 10);
    return isNaN(n) ? String(proto) : (names[n] ? `${names[n]} (${n})` : String(n));
}

/* ── Modal ──────────────────────────────────────────────── */

function openModal(alert) {
    const pct = Math.min(100, Math.max(0, Math.round((alert.confidence ?? 0) * 100)));
    let fillClass = 'high';
    if (pct < 50) fillClass = 'low';
    else if (pct < 80) fillClass = 'medium';

    // Badge
    const badgeHTML = badgeFor(alert.attack_type);
    modalBadge.outerHTML; // keep ref alive
    modalBadge.className = 'badge ' + badgeHTML.match(/class="([^"]+)"/)?.[1]?.split(' ').slice(1).join(' ');
    modalBadge.textContent = badgeHTML.replace(/<[^>]+>/g, '');

    // Fields
    mTimestamp.textContent = fmtTime(alert.timestamp) || '—';
    mSrcIp.textContent = alert.src_ip || '—';
    mDstIp.textContent = alert.dst_ip || '—';
    mProtocol.textContent = protocolLabel(alert.protocol);
    modalReceivedAt.textContent = alert.received_at || '—';

    // Score bar
    mScoreFill.className = `modal-score-fill ${fillClass}`;
    mScoreFill.style.width = '0%';          // reset for animation
    mScorePct.textContent = `${pct}%`;

    // Show modal
    alertModal.removeAttribute('hidden');
    // rAF so CSS transition fires after display:flex kicks in
    requestAnimationFrame(() => {
        alertModal.classList.add('is-open');
        requestAnimationFrame(() => { mScoreFill.style.width = `${pct}%`; });
    });

    // Trap focus on close button
    modalClose.focus();
}

function closeModal() {
    alertModal.classList.remove('is-open');
    // Wait for transition before hiding
    alertModal.addEventListener('transitionend', () => {
        if (!alertModal.classList.contains('is-open')) {
            alertModal.setAttribute('hidden', '');
        }
    }, { once: true });
}

/* ── Render ─────────────────────────────────────────────── */

function renderTable(alerts) {
    if (cleared) return; // user has cleared the view temporarily

    if (!alerts.length) {
        alertBody.innerHTML = '';
        alertBody.appendChild(placeholderRowEmpty());
        alertCount.textContent = '0 alerts';
        return;
    }

    // Remove placeholder
    const ph = alertBody.querySelector('#placeholderRow');
    if (ph) ph.remove();

    // Build fragment
    const frag = document.createDocumentFragment();
    const newSet = new Set();

    alerts.forEach(a => {
        const key = a.timestamp + a.src_ip + a.dst_ip + a.attack_type;
        newSet.add(key);
        rowDataMap.set(key, a);   // store for modal

        // Check if already rendered
        const existing = alertBody.querySelector(`[data-key="${CSS.escape(key)}"]`);
        if (existing) return;

        const tr = document.createElement('tr');
        tr.dataset.key = key;
        tr.classList.add('new-row');
        tr.setAttribute('title', 'Click for details');
        tr.innerHTML = `
      <td>${fmtTime(a.timestamp)}</td>
      <td>${escapeHtml(a.src_ip || '—')}</td>
      <td>${escapeHtml(a.dst_ip || '—')}</td>
      <td>${badgeFor(a.attack_type)}</td>
      ${confidenceCell(a.confidence)}
    `;
        // Click handler — open modal with this alert's data
        tr.addEventListener('click', () => {
            const data = rowDataMap.get(tr.dataset.key);
            if (data) openModal(data);
        });
        frag.appendChild(tr);
    });

    // Prepend new rows at top
    alertBody.insertBefore(frag, alertBody.firstChild);

    // Remove stale rows (no longer in latest data)
    const allRows = alertBody.querySelectorAll('tr[data-key]');
    allRows.forEach(row => {
        if (!newSet.has(row.dataset.key)) row.remove();
    });

    const total = alertBody.querySelectorAll('tr[data-key]').length;
    alertCount.textContent = `${total} alert${total !== 1 ? 's' : ''}`;
}

/** Plain empty-state row (no spinner) */
function placeholderRowEmpty() {
    const tr = document.createElement('tr');
    tr.id = 'placeholderRow';
    tr.className = 'placeholder-row';
    tr.innerHTML = `<td colspan="5">
    <div class="placeholder-content">
      <span>No alerts found.</span>
    </div>
  </td>`;
    return tr;
}

function updateSummary(alerts) {
    const counts = { DDoS: 0, DoS: 0, PortScan: 0, BruteForce: 0 };
    alerts.forEach(a => {
        const k = normaliseType(a.attack_type);
        if (k && k in counts) counts[k]++;
    });
    const total = alerts.length;

    animateCount(countEls.total, total);
    Object.keys(counts).forEach(k => animateCount(countEls[k], counts[k]));
}

function setServerOnline(online) {
    if (online) {
        statusDot.className = 'status-dot online';
        statusLabel.textContent = 'Server Online';
    } else {
        statusDot.className = 'status-dot offline';
        statusLabel.textContent = 'Server Offline';
    }
}

function updateTimestamp() {
    const now = new Date();
    lastUpdated.textContent = now.toLocaleTimeString(undefined, { hour12: false });
}

/** Simple HTML escape to prevent XSS */
function escapeHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/* ── Fetch ──────────────────────────────────────────────── */

async function loadAlerts() {
    try {
        const res = await fetch('/alerts', { cache: 'no-store' });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);

        const raw = await res.json();

        // Sort descending by timestamp
        const alerts = raw.slice().sort((a, b) => {
            const ta = new Date(a.timestamp?.replace(' ', 'T') || 0).getTime();
            const tb = new Date(b.timestamp?.replace(' ', 'T') || 0).getTime();
            return tb - ta;
        });

        setServerOnline(true);
        updateTimestamp();
        updateSummary(alerts);
        renderTable(alerts);

    } catch (err) {
        console.error('[Sentinel IDS] Fetch error:', err.message);
        setServerOnline(false);
        // Leave existing data visible — do not wipe the table on transient errors
    }
}

/* ── Clear button ───────────────────────────────────────── */
btnClear.addEventListener('click', () => {
    cleared = !cleared;
    if (cleared) {
        alertBody.innerHTML = '';
        const tr = document.createElement('tr');
        tr.className = 'placeholder-row';
        tr.innerHTML = `<td colspan="5"><div class="placeholder-content">
      <span>Display cleared. Data continues to refresh in the background.</span>
    </div></td>`;
        alertBody.appendChild(tr);
        btnClear.textContent = '↺ Restore';
        alertCount.textContent = '—';
    } else {
        btnClear.textContent = '✕ Clear';
        // Force immediate re-render
        prevTimestamps = new Set();
        loadAlerts();
    }
});

/* ── Modal close wiring ─────────────────────────────────── */
modalClose.addEventListener('click', closeModal);
modalCloseBtn.addEventListener('click', closeModal);

// Click on dark backdrop (but not inside the box) closes modal
alertModal.addEventListener('click', e => {
    if (e.target === alertModal) closeModal();
});

// Escape key
document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && alertModal.classList.contains('is-open')) closeModal();
});

/* ── Bootstrap ──────────────────────────────────────────── */
loadAlerts();
setInterval(loadAlerts, 5000);
