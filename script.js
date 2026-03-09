// ── State ────────────────────────────────────────────────────────────────────
let alerts = [];
let blockedIPs = new Set();

// ── Fetch alerts ─────────────────────────────────────────────────────────────
async function fetchAlerts() {
  try {
    const res = await fetch('/alerts');
    if (!res.ok) return;
    alerts = await res.json();
    render();
    document.getElementById('last-update').textContent =
      'UPDATED ' + new Date().toLocaleTimeString();
  } catch (e) {
    console.error('Fetch failed:', e);
  }
}

// ── Render ───────────────────────────────────────────────────────────────────
function render() {
  const reversed = [...alerts].reverse();

  // Stats
  const attacks   = alerts.filter(a => a.attack_type !== 'Benign').length;
  const blocked   = alerts.filter(a => a.block_status && a.block_status !== 'none').length;
  const lastScore = alerts.length ? alerts[alerts.length - 1].anomaly_score : null;

  document.getElementById('stat-total').textContent   = alerts.length;
  document.getElementById('stat-attacks').textContent = attacks;
  document.getElementById('stat-blocked').textContent = blocked;
  document.getElementById('stat-score').textContent   = lastScore !== null ? lastScore.toFixed(1) : '—';

  // Rebuild blocked IPs from alerts
  blockedIPs = new Set(
    alerts
      .filter(a => a.block_status === 'permanent' || a.block_status === 'temporary')
      .map(a => a.src_ip)
  );
  renderBlocks();

  // Table
  if (reversed.length === 0) {
    document.getElementById('table-container').innerHTML =
      '<div class="empty-state"><p>AWAITING TRAFFIC DATA...</p></div>';
    return;
  }

  const rows = reversed.map(a => {
    const score = a.anomaly_score !== null && a.anomaly_score !== undefined
                  ? Number(a.anomaly_score) : null;

    const scoreHTML = score !== null
      ? `<div class="score-wrap">
           <span>${score.toFixed(1)}</span>
           <div class="score-bar-bg">
             <div class="score-bar-fill"
                  style="width:${score}%;
                         background:${score >= 70 ? 'var(--danger)' : score >= 40 ? 'var(--warn)' : 'var(--ok)'}">
             </div>
           </div>
         </div>`
      : '<span style="color:var(--text-dim)">—</span>';

    const blockClass = a.block_status === 'permanent' ? 'status-permanent'
                     : a.block_status === 'temporary'  ? 'status-temporary'
                     : 'status-none';
    const blockText  = a.block_status ? a.block_status.toUpperCase() : 'NONE';

    const proto = a.protocol === 6  ? 'TCP'
                : a.protocol === 17 ? 'UDP'
                : a.protocol === 1  ? 'ICMP'
                : (a.protocol ?? '—');

    const ts = a.timestamp ? a.timestamp.replace('T', ' ').slice(0, 19) : '—';

    return `<tr>
      <td class="td-time">${ts}</td>
      <td class="td-ip">${a.src_ip || '—'}</td>
      <td>${a.dst_ip || '—'}</td>
      <td>${proto}</td>
      <td>${badgeHTML(a.attack_type)}</td>
      <td>${scoreHTML}</td>
      <td class="${blockClass}">${blockText}</td>
    </tr>`;
  }).join('');

  document.getElementById('table-container').innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Src IP</th>
          <th>Dst IP</th>
          <th>Proto</th>
          <th>Attack Type</th>
          <th>Anomaly Score</th>
          <th>Block Status</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function badgeHTML(type) {
  if (!type) return '<span class="badge badge-default">UNKNOWN</span>';
  const t = type.toLowerCase();
  const cls = t.includes('ddos')                          ? 'badge-ddos'
            : t.includes('dos')                           ? 'badge-dos'
            : t.includes('portscan') || t.includes('port')? 'badge-portscan'
            : t.includes('brute')                         ? 'badge-bruteforce'
            : t.includes('benign') || t.includes('normal')? 'badge-benign'
            : 'badge-default';
  return `<span class="badge ${cls}">${type.toUpperCase()}</span>`;
}

// ── Blocked IPs ───────────────────────────────────────────────────────────────
function renderBlocks() {
  const container = document.getElementById('blocked-list');
  if (blockedIPs.size === 0) {
    container.innerHTML = '<span class="no-blocks">NO ACTIVE BLOCKS</span>';
    return;
  }
  container.innerHTML = [...blockedIPs].map(ip => {
    const latest = [...alerts].reverse().find(a => a.src_ip === ip);
    const type   = latest ? latest.block_status.toUpperCase() : '';
    return `<div class="block-chip">
      <span>${ip}</span>
      <span class="block-type">${type}</span>
      <button class="unblock-btn" onclick="unblockIP('${ip}')">UNBLOCK</button>
    </div>`;
  }).join('');
}

async function unblockIP(ip) {
  try {
    const res = await fetch('/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip })
    });
    const data = await res.json();
    if (data.status === 'queued' || data.status === 'already_queued') {
      showToast(`UNBLOCK QUEUED → ${ip}`);
      blockedIPs.delete(ip);
      renderBlocks();
    }
  } catch (e) {
    showToast('ERROR: Could not reach server');
  }
}

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 3000);
}

// ── Init ──────────────────────────────────────────────────────────────────────
fetchAlerts();
setInterval(fetchAlerts, 5000);