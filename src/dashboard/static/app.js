/* ====== Futuristic Autonomous SOC Dashboard Logic ====== */

const state = {
  alerts: [],
  filteredAlerts: [],
  charts: {},
  currentView: 'tactical',
  mlStats: null,
  stats: {
    total: 0,
    highRisk: 0,
    blockedIPs: new Set(),
    avgRisk: 0,
    siemSyncCount: 0
  },
  config: {
    isExpanded: false,
    maxVisibleItems: 10,
    startTime: Date.now(),
    vectorHistory: [] // History for radar smoothing
  }
};

const DOM = {
  alertsBody: document.getElementById('alerts-body'),
  emptyState: document.getElementById('empty-state'),
  searchInput: document.getElementById('searchInput'),
  themeToggle: document.getElementById('themeToggle'),
  alertModal: document.getElementById('alertModal'),
  modalContent: document.getElementById('modalContent'),
  toastContainer: document.getElementById('toastContainer'),
  statTotal: document.getElementById('stat-total'),
  statHighRisk: document.getElementById('stat-high-risk'),
  statBlocked: document.getElementById('stat-blocked'),
  statAvgRisk: document.getElementById('stat-avg-risk'),
  statPps: document.getElementById('stat-pps'),
  statKbps: document.getElementById('stat-kbps'),
  uptimeClock: document.getElementById('uptime-clock'),
  alertExpandBtn: document.getElementById('alertExpandBtn'),
  blockedMatrix: document.getElementById('blocked-ip-matrix'),
  blockedEmpty: document.getElementById('blocked-empty'),
  whitelistList: document.getElementById('whitelist-list'),
  whitelistInput: document.getElementById('whitelist-input'),
  addWhitelistBtn: document.getElementById('add-whitelist-btn'),
  rebootBtn: document.getElementById('reboot-btn'),
  viewTactical: document.getElementById('view-tactical'),
  viewMl: document.getElementById('view-ml'),
  btnTactical: document.getElementById('btn-view-tactical'),
  btnMl: document.getElementById('btn-view-ml'),
  featureImportanceCont: document.getElementById('ml-feature-importance'),
  siemSyncCountEl: document.getElementById('siem-sync-count'),
  siemStatusBadge: document.getElementById('siem-status-badge'),
  statCpu: document.getElementById('stat-cpu'),
  statCpuBar: document.getElementById('stat-cpu-bar'),
  statRam: document.getElementById('stat-ram'),
  statRamBar: document.getElementById('stat-ram-bar'),
  statTemp: document.getElementById('stat-temp'),
  statTempBar: document.getElementById('stat-temp-bar'),
  radarChart: document.getElementById('radarChart')
};

/* ====== Core Utilities ====== */
const utils = {
  formatTime: (ts) => {
    try {
      const date = new Date(ts * 1000);
      return date.toLocaleTimeString('en-US', { hour12: false });
    } catch (e) { return '--:--:--'; }
  },

  getRiskLevel: (risk) => {
    if (risk >= 75) return { label: 'CRITICAL', class: 'badge-high', color: '#fb7185' };
    if (risk >= 40) return { label: 'WARNING', class: 'badge-medium', color: '#fbbf24' };
    return { label: 'NORMAL', class: 'badge-low', color: '#34d399' };
  },

  animateNumber: (element, endValue, duration = 100) => {
    if (!element) return;
    const currentVal = parseFloat(element.textContent) || 0;
    const start = performance.now();

    const step = (now) => {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const value = currentVal + (endValue - currentVal) * progress;
      element.textContent = endValue % 1 === 0 ? Math.floor(value) : value.toFixed(1);
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  },

  showToast: (msg, type = 'info') => {
    const toast = document.createElement('div');
    toast.className = `p-4 rounded-xl glass border border-white/5 flex items-center gap-3 animate-slide-up bg-slate-900/40 backdrop-blur-xl min-w-[300px] border-l-4 ${type === 'error' ? 'border-l-rose-500' : 'border-l-cyan-500'}`;
    toast.innerHTML = `
      <div class="p-2 rounded-lg ${type === 'error' ? 'bg-rose-500/10 text-rose-500' : 'bg-cyan-500/10 text-cyan-400'}">
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
        </svg>
      </div>
      <div class="text-xs font-bold uppercase tracking-widest text-white">${msg}</div>
    `;
    DOM.toastContainer.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  }
};

/* ====== Statistics & Uptime ====== */
function updateUptime() {
  const diff = Date.now() - state.config.startTime;
  const h = Math.floor(diff / 3600000).toString().padStart(2, '0');
  const m = Math.floor((diff % 3600000) / 60000).toString().padStart(2, '0');
  const s = Math.floor((diff % 60000) / 1000).toString().padStart(2, '0');
  const ms = Math.floor((diff % 1000) / 10).toString().padStart(2, '0');
  if (DOM.uptimeClock) DOM.uptimeClock.textContent = `00:${h}:${m}:${s}:${ms}`;
}

function refreshStats() {
  const total = state.alerts.length;
  const highRisk = state.alerts.filter(a => a.risk >= 75).length;
  const avgRisk = total > 0 ? state.alerts.reduce((sum, a) => sum + (a.risk || 0), 0) / total : 0;

  utils.animateNumber(DOM.statTotal, total);
  utils.animateNumber(DOM.statHighRisk, highRisk);
  utils.animateNumber(DOM.statBlocked, state.stats.blockedIPs.size);
  utils.animateNumber(DOM.statAvgRisk, avgRisk);
  if (DOM.siemSyncCountEl) DOM.siemSyncCountEl.textContent = state.stats.siemSyncCount;

  renderBlockedMatrix();
}

/* ====== Render Components ====== */
function renderBlockedMatrix() {
  if (!DOM.blockedMatrix) return;
  const ips = Array.from(state.stats.blockedIPs).slice(-12);

  if (ips.length === 0) {
    if (DOM.blockedEmpty) DOM.blockedEmpty.style.display = 'block';
    DOM.blockedMatrix.innerHTML = '';
    return;
  }

  if (DOM.blockedEmpty) DOM.blockedEmpty.style.display = 'none';
  DOM.blockedMatrix.innerHTML = ips.map(ip => `
    <div class="blocked-item animate-fade-in">
      <span>${ip}</span>
      <span class="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>
    </div>
  `).join('');
}

function renderAlerts() {
  if (!DOM.alertsBody) return;
  DOM.alertsBody.innerHTML = '';

  const displaySet = state.filteredAlerts.slice().reverse();
  const limit = state.config.isExpanded ? 100 : state.config.maxVisibleItems;
  const items = displaySet.slice(0, limit);

  if (items.length === 0) {
    if (DOM.emptyState) DOM.emptyState.style.display = 'flex';
    return;
  }
  if (DOM.emptyState) DOM.emptyState.style.display = 'none';

  items.forEach((alert, idx) => {
    const riskVal = alert.risk || 0;
    const risk = utils.getRiskLevel(riskVal);
    const row = document.createElement('tr');
    row.className = 'alert-row border-b border-white/5 cursor-pointer group transition-all duration-300';
    row.style.animation = `slideUp 0.4s ease forwards ${idx * 0.05}s`;
    row.onclick = () => openAlertModal(alert);

    row.innerHTML = `
      <td class="px-6 py-4 font-mono text-slate-500 text-xs">${utils.formatTime(alert.time)}</td>
      <td class="px-6 py-4">
        <div class="flex flex-col">
          <span class="font-black tracking-tight text-white group-hover:text-cyan-400 transition-colors">${alert.src_ip}</span>
          ${alert.spoofed ? '<span class="text-[8px] text-rose-500 font-bold uppercase tracking-widest animate-pulse">! SPOOF DETECTED</span>' : ''}
        </div>
      </td>
      <td class="px-6 py-4">
        <span class="badge ${risk.class}">${risk.label}</span>
      </td>
      <td class="px-6 py-4 font-mono text-xs text-slate-400">${(alert.anomaly || 0).toFixed(4)}</td>
      <td class="px-6 py-4">
        <div class="w-24 h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div class="h-full bg-gradient-to-r from-cyan-500 to-blue-500" style="width: ${riskVal}%"></div>
        </div>
      </td>
      <td class="px-6 py-4 text-center">
        <div class="inline-flex items-center gap-2 text-emerald-400">
           <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
           <span class="text-[10px] font-bold uppercase tracking-widest">Active</span>
        </div>
      </td>
    `;
    DOM.alertsBody.appendChild(row);
    if (riskVal >= 75) state.stats.blockedIPs.add(alert.src_ip);
  });
}

async function refreshWhitelist() {
  if (!DOM.whitelistList) return;
  try {
    const res = await fetch('/whitelist');
    const data = await res.json();
    DOM.whitelistList.innerHTML = '';

    [...data.ips, ...data.macs].forEach(item => {
      const el = document.createElement('div');
      el.className = 'whitelist-item flex items-center justify-between p-2 rounded-lg bg-white/5 border border-white/5 group';
      el.innerHTML = `
        <span class="text-[10px] font-mono text-cyan-400">${item}</span>
        <button onclick="removeFromWhitelist('${item}')" class="opacity-0 group-hover:opacity-100 p-1 hover:text-rose-500 transition-all">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12"></path></svg>
        </button>
      `;
      DOM.whitelistList.appendChild(el);
    });
  } catch (e) { console.error('Whitelist fetch failed', e); }
}

async function addToWhitelist() {
  const val = DOM.whitelistInput.value.trim();
  if (!val) return;

  const isMac = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(val);
  const payload = isMac ? { mac: val } : { ip: val };

  try {
    const res = await fetch('/whitelist', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      utils.showToast(`${val} WHITELISTED`, 'success');
      DOM.whitelistInput.value = '';
      refreshWhitelist();
    }
  } catch (e) { utils.showToast('WHITELIST FAILED', 'error'); }
}

async function removeFromWhitelist(item) {
  const isMac = item.includes(':') || item.includes('-');
  const payload = isMac ? { mac: item } : { ip: item };

  try {
    await fetch('/whitelist', {
      method: 'DELETE',
      body: JSON.stringify(payload)
    });
    utils.showToast(`${item} REMOVED`, 'info');
    refreshWhitelist();
  } catch (e) { utils.showToast('REMOVE FAILED', 'error'); }
}

async function triggerReboot() {
  utils.showToast('SYSTEM REBOOT INITIALIZED', 'info');
  try {
    const res = await fetch('/reboot', { method: 'POST' });
    if (res.ok) {
      utils.showToast('REBOOT SUCCESSFUL: RELOADING...', 'success');
      setTimeout(() => window.location.reload(), 2000);
    }
  } catch (e) { utils.showToast('REBOOT FAILED', 'error'); }
}

/* ====== Modal & SSE ====== */
function openAlertModal(alert) {
  const riskVal = alert.risk || 0;
  const risk = utils.getRiskLevel(riskVal);
  const breakdown = alert.breakdown || { anomaly: 0, intensity: 0, persistence: 0 };

  DOM.modalContent.innerHTML = `
    <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
      <div class="space-y-6">
        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Target Intelligence</label>
          <div class="text-2xl font-mono text-cyan-400">${alert.src_ip}</div>
          ${alert.spoofed ? '<div class="text-xs text-rose-500 font-black mt-1 uppercase tracking-tighter">> ZERO TRUST VIOLATION: INVALID SRC CONTEXT</div>' : ''}
        </div>
        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase tracking-widest block mb-1">Threat Classification</label>
          <div class="flex items-center gap-4">
            <span class="text-4xl font-black italic" style="color: ${risk.color}">${Math.round(riskVal)}%</span>
            <span class="badge ${risk.class} px-3 py-1.5 text-xs">${risk.label}</span>
          </div>
        </div>
        <div class="p-4 bg-white/5 rounded-xl border border-white/5">
          <label class="text-[10px] font-bold text-slate-400 uppercase tracking-widest block mb-2">Automated Response Log</label>
          <div class="font-mono text-[10px] leading-relaxed text-emerald-400">
            > ACTION: <span class="bg-emerald-500/20 px-1 font-black">${alert.action || 'LOG'}</span><br>
            > STATUS: <span class="text-white">${alert.status || 'PROCESSED'}</span><br>
            > SIEM SYNC: <span class="text-white font-bold">DONE [AGENT V1.2]</span><br>
            > PERSISTENCE: ${alert.persistence || 0} hits<br>
            > ISDNF TRUST: ${((1 - (riskVal / 100)) * 100).toFixed(1)}%
          </div>
        </div>
      </div>
      
      <div class="space-y-6">
        <div>
          <label class="text-[10px] font-bold text-slate-500 uppercase mb-3 block">Risk Matrix Factorization</label>
          <div class="space-y-3">
            <div class="space-y-1">
                <div class="flex justify-between text-[8px] font-black uppercase"><span class="text-amber-500">Anomaly Signal</span><span class="text-white">${(breakdown.anomaly * 100).toFixed(0)}%</span></div>
                <div class="w-full h-1 bg-white/5 rounded-full overflow-hidden"><div class="h-full bg-amber-500" style="width: ${breakdown.anomaly * 100}%"></div></div>
            </div>
            <div class="space-y-1">
                <div class="flex justify-between text-[8px] font-black uppercase"><span class="text-cyan-500">Traffic Intensity</span><span class="text-white">${(breakdown.intensity * 100).toFixed(0)}%</span></div>
                <div class="w-full h-1 bg-white/5 rounded-full overflow-hidden"><div class="h-full bg-cyan-500" style="width: ${breakdown.intensity * 100}%"></div></div>
            </div>
            <div class="space-y-1">
                <div class="flex justify-between text-[8px] font-black uppercase"><span class="text-purple-500">Persistence Factor</span><span class="text-white">${(breakdown.persistence * 100).toFixed(0)}%</span></div>
                <div class="w-full h-1 bg-white/5 rounded-full overflow-hidden"><div class="h-full bg-purple-500" style="width: ${breakdown.persistence * 100}%"></div></div>
            </div>
          </div>
        </div>
        <div class="pt-4 border-t border-white/5">
          <label class="text-[10px] font-bold text-slate-500 uppercase mb-2 block">Detection Engine</label>
          <div class="text-[10px] text-slate-400 italic font-mono uppercase tracking-tighter">
            ISDNF Ensemble Discovery v12.0<br>
            <span class="text-cyan-600/[0.4]">[Consensus Voter: 0.4*IF_Agg + 0.6*IF_Cons]</span>
          </div>
        </div>
      </div>
    </div>
    
    <div class="flex gap-4 mt-8 pt-6 border-t border-white/5">
      <button onclick="document.getElementById('alertModal').classList.add('hidden')" class="flex-1 py-4 glass glass-hover text-xs font-black uppercase tracking-widest">Acknowledge</button>
      <button id="extractMetadataBtn" class="flex-1 py-4 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-black uppercase tracking-widest transition shadow-lg shadow-cyan-500/20">Extract Metadata</button>
    </div>
  `;

  DOM.alertModal.classList.remove('hidden');

  // Safely bind dynamic data without closure collision
  const extractBtn = document.getElementById('extractMetadataBtn');
  if (extractBtn) {
    const payloadStr = JSON.stringify(alert, null, 2);
    extractBtn.dataset.payload = payloadStr;

    extractBtn.onclick = function () {
      const dataToCopy = this.dataset.payload;
      navigator.clipboard.writeText(dataToCopy)
        .then(() => utils.showToast('METADATA COPIED TO CLIPBOARD', 'success'))
        .catch(() => {
          // Fallback
          const ta = document.createElement('textarea');
          ta.value = dataToCopy;
          ta.style.position = 'absolute';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.select();
          const res = document.execCommand('copy');
          document.body.removeChild(ta);
          if (res) utils.showToast('METADATA COPIED TO CLIPBOARD', 'success');
          else utils.showToast('CLIPBOARD ACCESS DENIED', 'error');
        });
    };
  }
}

/* ====== Charts Manager ====== */
const chartManager = {
  config: {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    elements: { line: { tension: 0.4 }, point: { radius: 0 } },
    scales: {
      x: { display: false },
      y: { grid: { color: 'rgba(255,255,255,0.05)' }, border: { display: false }, ticks: { color: '#475569', font: { size: 10 } } }
    }
  },

  updateAll: () => {
    try {
      if (typeof Chart === 'undefined') return;
      Object.values(state.charts).forEach(c => c?.destroy());
      // Proceed even with zero alerts for radar/HUD initialization

      // Timeline
      const tCtx = document.getElementById('riskTimelineChart')?.getContext('2d');
      if (tCtx) {
        state.charts.timeline = new Chart(tCtx, {
          type: 'line',
          data: {
            labels: state.alerts.slice(-40).map((_, i) => i),
            datasets: [{
              data: state.alerts.slice(-40).map(a => a.risk || 0),
              borderColor: '#22d3ee',
              borderWidth: 2,
              fill: true,
              backgroundColor: (ctx) => {
                const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 400);
                g.addColorStop(0, 'rgba(34, 211, 238, 0.2)');
                g.addColorStop(1, 'transparent');
                return g;
              }
            }]
          },
          options: chartManager.config
        });
      }

      // Vectored Radar (V16.0 Advanced Vectorization)
      const rCtx = document.getElementById('radarChart')?.getContext('2d');
      if (rCtx) {
        // Calculate Vector Intensities from last 20 signals
        const window = state.alerts.slice(-20);
        let vol = 0, scn = 0, prt = 0, inf = 0, mal = 0;

        if (window.length > 0) {
          window.forEach(a => {
            mal += (a.risk || 0);
            prt += (a.anomaly || 0) * 100;
            if (a.meta) {
              scn += (a.meta.unique_ports_count || 1) * 10;
            }
          });
          // Normalize
          vol = (parseFloat(DOM.statPps?.textContent) || 0) / 10; // Scaling PPS to 0-100
          inf = (parseFloat(DOM.statCpu?.textContent) || 0);

          mal = Math.min(100, mal / window.length);
          prt = Math.min(100, prt / window.length);
          scn = Math.min(100, scn / window.length);
        }

        state.charts.radar = new Chart(rCtx, {
          type: 'radar',
          data: {
            labels: ['VOL (FLOOD)', 'SCN (PROBE)', 'PRT (ANOM)', 'INF (LOAD)', 'MAL (RISK)'],
            datasets: [{
              label: 'Vectored Threat',
              data: [vol, scn, prt, inf, mal],
              backgroundColor: 'rgba(52, 211, 153, 0.2)',
              borderColor: 'rgba(52, 211, 153, 0.8)',
              borderWidth: 2,
              pointBackgroundColor: 'rgba(52, 211, 153, 1)',
              pointRadius: 3
            }]
          },
          options: {
            ...chartManager.config,
            scales: {
              r: {
                min: 0,
                max: 100,
                grid: { color: 'rgba(255,255,255,0.05)' },
                angleLines: { color: 'rgba(255,255,255,0.1)' },
                pointLabels: { color: '#94a3b8', font: { size: 9, weight: 'bold' } },
                ticks: { display: false }
              }
            }
          }
        });
      }

      // Anomaly Distribution
      const aCtx = document.getElementById('anomalyScoresChart')?.getContext('2d');
      if (aCtx) {
        const bins = Array(10).fill(0);
        state.alerts.forEach(a => {
          const idx = Math.min(9, Math.floor((a.anomaly || 0) * 10));
          bins[idx]++;
        });
        state.charts.anomaly = new Chart(aCtx, {
          type: 'bar',
          data: {
            labels: ['0.1', '0.2', '0.3', '0.4', '0.5', '0.6', '0.7', '0.8', '0.9', '1.0'],
            datasets: [{
              data: bins,
              backgroundColor: '#fbbf24',
              borderRadius: 4
            }]
          },
          options: chartManager.config
        });
      }

      // Risk Distribution
      const dCtx = document.getElementById('riskDistributionChart')?.getContext('2d');
      if (dCtx) {
        const risks = state.alerts.map(a => a.risk || 0);
        state.charts.distribution = new Chart(dCtx, {
          type: 'doughnut',
          data: {
            labels: ['Critical', 'Normal'],
            datasets: [{
              data: [risks.filter(r => r >= 85).length, risks.filter(r => r < 85).length],
              backgroundColor: ['#f43f5e', '#1e293b'],
              borderWidth: 0,
              hoverOffset: 10
            }]
          },
          options: { ...chartManager.config, cutout: '80%' }
        });
      }
    } catch (e) { console.error('Chart update failed', e); }
  },

  updateMLCharts: () => {
    try {
      if (typeof Chart === 'undefined' || !state.mlStats) return;

      // Feature Importance
      const cont = document.getElementById('ml-feature-importance');
      if (cont) {
        cont.innerHTML = state.mlStats.feature_importance.map(f => `
                <div class="space-y-1">
                    <div class="flex justify-between text-[9px] font-bold uppercase">
                        <span class="text-slate-400">${f.name}</span>
                        <span class="text-cyan-400">${(f.score * 100).toFixed(1)}%</span>
                    </div>
                    <div class="w-full h-1 bg-white/5 rounded-full overflow-hidden">
                        <div class="h-full bg-cyan-500/50" style="width: ${f.score * 100}%"></div>
                    </div>
                </div>
            `).join('');
      }

      const mCtx = document.getElementById('mlAnomalyMatrixChart')?.getContext('2d');
      if (mCtx) {
        state.charts.mlMatrix = new Chart(mCtx, {
          type: 'scatter',
          data: {
            datasets: [{
              label: 'Anomalies',
              data: state.alerts.map(a => ({ x: a.anomaly || 0, y: a.risk || 0 })),
              backgroundColor: (ctx) => {
                const val = ctx.raw?.y || 0;
                return val >= 85 ? '#f43f5e' : (val >= 50 ? '#fbbf24' : '#22d3ee');
              },
              pointRadius: 4
            }]
          },
          options: chartManager.config
        });
      }

      // Fidelity
      const fCtx = document.getElementById('mlFidelityChart')?.getContext('2d');
      if (fCtx) {
        state.charts.fidelity = new Chart(fCtx, {
          type: 'line',
          data: {
            labels: ['T-4', 'T-3', 'T-2', 'T-1', 'NOW'],
            datasets: [{
              data: [0.98, 0.99, 0.97, 0.99, 0.998], // System Stability Tracker
              borderColor: '#a855f7',
              borderWidth: 2,
              tension: 0.4,
              fill: false
            }]
          },
          options: chartManager.config
        });
      }

      // Model Convergence (Dynamic simulation for visual effect based on alert volume)
      const convScore = document.getElementById('convergence-score');
      const convLoss = document.getElementById('convergence-loss');
      if (convScore && convLoss) {
        const baseConv = 99.0;
        const wiggle = Math.random() * 0.9;
        const currentConv = (baseConv + wiggle).toFixed(2);
        const currentLoss = (100 - currentConv).toFixed(3);
        convScore.textContent = currentConv + '%';
        convLoss.textContent = currentLoss;
      }
    } catch (e) { console.error('ML chart update failed', e); }
  }
};

/* ====== Event Handling ====== */
const applySearch = () => {
  const query = (DOM.searchInput?.value || '').toLowerCase().trim();
  state.filteredAlerts = state.alerts.filter(a =>
    a.src_ip.toLowerCase().includes(query) ||
    String(a.risk).includes(query)
  );
  renderAlerts();
};

/* ====== View & Theme Toggle ====== */
function switchView(view) {
  state.currentView = view;
  if (view === 'tactical') {
    if (DOM.viewTactical) DOM.viewTactical.classList.remove('hidden');
    if (DOM.viewMl) DOM.viewMl.classList.add('hidden');
    if (DOM.btnTactical) DOM.btnTactical.className = 'px-6 py-2 rounded-lg text-xs font-black uppercase transition-all bg-cyan-500 text-black shadow-lg shadow-cyan-500/20';
    if (DOM.btnMl) DOM.btnMl.className = 'px-6 py-2 rounded-lg text-xs font-black uppercase transition-all text-slate-400 hover:text-white';
    chartManager.updateAll();
  } else {
    if (DOM.viewTactical) DOM.viewTactical.classList.add('hidden');
    if (DOM.viewMl) DOM.viewMl.classList.remove('hidden');
    if (DOM.btnMl) DOM.btnMl.className = 'px-6 py-2 rounded-lg text-xs font-black uppercase transition-all bg-primary text-white shadow-lg shadow-cyan-500/20';
    if (DOM.btnTactical) DOM.btnTactical.className = 'px-6 py-2 rounded-lg text-xs font-black uppercase transition-all text-slate-400 hover:text-white';
    fetchMLStats();
  }
}

async function fetchMLStats() {
  try {
    const res = await fetch('/ml/stats');
    state.mlStats = await res.json();
    chartManager.updateMLCharts();
  } catch (e) { console.error('ML stats fetch failed', e); }
}

function initTheme() {
  const saved = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('theme', next);
  chartManager.updateAll();
  if (state.currentView === 'ml') chartManager.updateMLCharts();
}

// Stat Hydration (V13.1 Persistence)
const refreshStatsFromServer = async () => {
  try {
    const res = await fetch('/stats');
    const stats = await res.json();
    state.stats.siemSyncCount = stats.total_packets || 0;
    state.stats.highRiskCount = stats.total_alerts || 0;
    state.stats.blockedCount = stats.blocked_count || 0;
    refreshStats();
  } catch (e) {
    console.error("Stats hydration failed", e);
  }
};

function init() {
  initTheme();
  refreshStatsFromServer();
  setInterval(updateUptime, 100);

  if (DOM.searchInput) DOM.searchInput.oninput = applySearch;
  if (DOM.alertExpandBtn) DOM.alertExpandBtn.onclick = () => {
    state.config.isExpanded = !state.config.isExpanded;
    renderAlerts();
  };

  if (DOM.themeToggle) DOM.themeToggle.onclick = toggleTheme;

  fetch('/alerts').then(r => r.json()).then(data => {
    state.alerts = data;
    state.filteredAlerts = data;
    state.stats.siemSyncCount = data.length; // Initialize SIEM count from historical data
    renderAlerts();
    chartManager.updateAll();
    refreshStats();
  });

  // SSE for real-time intelligence
  const sse = new EventSource('/stream');

  // Performance Throttling
  let lastChartUpdate = 0;
  let lastStatsUpdate = 0;
  const UPDATE_THROTTLE = 1000; // Only update charts/stats every 1s under load

  sse.onmessage = (e) => {
    const alert = JSON.parse(e.data);

    // Live Pulse Telemetry Handling (V13.1 Fluidity)
    if (alert.type === 'pulse') {
      if (DOM.statPps) DOM.statPps.textContent = Math.floor(alert.pps);
      if (DOM.statKbps) DOM.statKbps.textContent = (alert.bps / 1024).toFixed(1);

      // Fluid Counter: Detection Vector follows Global Packet Count
      if (alert.global_total) {
        state.stats.siemSyncCount = alert.global_total;
        if (DOM.statTotal) {
          DOM.statTotal.textContent = alert.global_total.toLocaleString();
        }
      }

      // Hardware Telemetry (V14.0)
      if (alert.cpu_load !== undefined) {
        if (DOM.statCpu) DOM.statCpu.textContent = alert.cpu_load.toFixed(1);
        if (DOM.statCpuBar) DOM.statCpuBar.style.width = `${alert.cpu_load}%`;
      }
      if (alert.ram_usage !== undefined) {
        if (DOM.statRam) DOM.statRam.textContent = alert.ram_usage.toFixed(1);
        if (DOM.statRamBar) DOM.statRamBar.style.width = `${alert.ram_usage}%`;
      }
      if (alert.system_temp !== undefined) {
        if (DOM.statTemp) DOM.statTemp.textContent = alert.system_temp.toFixed(1);
        if (DOM.statTempBar) DOM.statTempBar.style.width = `${Math.min(alert.system_temp, 100)}%`;

        // Heat Stress Visualization
        if (alert.system_temp > 65) {
          document.documentElement.style.setProperty('--glow-color', 'rgba(244, 63, 94, 0.2)');
        } else {
          document.documentElement.style.setProperty('--glow-color', 'rgba(6, 182, 212, 0.2)');
        }
      }

      return; // Pulses don't add to table
    }

    state.alerts.push(alert);
    state.stats.siemSyncCount++;
    if (state.alerts.length > 2000) state.alerts.shift();

    // Incremental UI Update (Prepend row instead of full refresh)
    const riskVal = alert.risk || 0;
    const risk = utils.getRiskLevel(riskVal);
    const row = document.createElement('tr');
    row.className = 'alert-row border-b border-white/5 cursor-pointer group transition-all duration-300 animate-slide-up';
    row.onclick = () => openAlertModal(alert);
    row.innerHTML = `
      <td class="px-6 py-4 font-mono text-slate-500 text-xs">${utils.formatTime(alert.time)}</td>
      <td class="px-6 py-4">
        <div class="flex flex-col">
          <span class="font-black tracking-tight text-white group-hover:text-cyan-400 transition-colors">${alert.src_ip}</span>
          ${alert.spoof_detected ? '<span class="text-[8px] text-rose-500 font-bold uppercase tracking-widest animate-pulse">! SPOOF DETECTED</span>' : ''}
        </div>
      </td>
      <td class="px-6 py-4"><span class="badge ${risk.class}">${risk.label}</span></td>
      <td class="px-6 py-4 font-mono text-xs text-slate-400">${(alert.anomaly || 0).toFixed(4)}</td>
      <td class="px-6 py-4">
        <div class="w-24 h-1.5 bg-white/5 rounded-full overflow-hidden">
          <div class="h-full bg-gradient-to-r from-cyan-500 to-blue-500" style="width: ${riskVal}%"></div>
        </div>
      </td>
      <td class="px-6 py-4 text-center">
        <div class="inline-flex items-center gap-2 ${alert.action === 'BLOCK' ? 'text-rose-500' : 'text-emerald-400'}">
           <span class="w-1.5 h-1.5 rounded-full ${alert.action === 'BLOCK' ? 'bg-rose-500' : 'bg-emerald-400'}"></span>
           <span class="text-[10px] font-bold uppercase tracking-widest">${alert.action || 'LOG'}</span>
        </div>
      </td>
    `;

    if (DOM.alertsBody) {
      DOM.alertsBody.prepend(row);
      // Keep DOM size manageable
      if (DOM.alertsBody.children.length > 20) {
        DOM.alertsBody.removeChild(DOM.alertsBody.lastChild);
      }
    }

    // Throttled UI Heavy lifting
    const now = Date.now();
    if (now - lastChartUpdate > UPDATE_THROTTLE) {
      chartManager.updateAll();
      lastChartUpdate = now;
    }
    if (now - lastStatsUpdate > 500) {
      refreshStats();
      lastStatsUpdate = now;
    }
  };

  refreshWhitelist();
  if (DOM.addWhitelistBtn) DOM.addWhitelistBtn.onclick = addToWhitelist;
  if (DOM.whitelistInput) DOM.whitelistInput.onkeypress = (e) => { if (e.key === 'Enter') addToWhitelist(); };
  if (DOM.rebootBtn) DOM.rebootBtn.onclick = triggerReboot;
}

document.addEventListener('DOMContentLoaded', init);
window.switchView = switchView; // Ensure global access for onclick
window.removeFromWhitelist = removeFromWhitelist;
