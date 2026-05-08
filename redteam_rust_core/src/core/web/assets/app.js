/**
 * Mimikri 4.0 Dashboard Controller
 */

function getToken() {
    return sessionStorage.getItem('dashboard_token') || '';
}

function authHeaders() {
    return { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' };
}

async function authFetch(url, opts = {}) {
    opts.headers = { ...authHeaders(), ...(opts.headers || {}) };
    const res = await fetch(url, opts);
    if (res.status === 401) { window.location.href = '/login'; }
    return res;
}

const UI = {
    tabs: document.querySelectorAll('.nav-links li'),
    panes: document.querySelectorAll('.tab-pane'),
    stream: document.getElementById('finding-stream'),
    ramValue: document.getElementById('stat-ram'),
    ramFill: document.getElementById('ram-fill'),
    tokenValue: document.getElementById('stat-tokens'),
    tokenFill: document.getElementById('token-fill'),
    containerStat: document.getElementById('stat-containers'),
    swarmContainer: document.getElementById('swarm-container'),
    modal: document.getElementById('modal-overlay')
};

// --- State Management ---
let state = {
    activeTab: 'overview',
    stats: { ram_mb: 0, ram_limit_mb: 1, tokens_used: 0, token_limit: 0 },
    agents: [],
    graphInitialized: false
};

// --- Navigation ---
UI.tabs.forEach(li => {
    li.addEventListener('click', () => {
        const tab = li.getAttribute('data-tab');
        document.querySelector('.nav-links li.active').classList.remove('active');
        document.querySelector('.tab-pane.active').classList.remove('active');
        
        li.classList.add('active');
        document.getElementById(tab).classList.add('active');
        state.activeTab = tab;
        
        // Rebranding tab title
        let title = li.textContent.trim();
        if (title.includes("Overview")) title = "Mimikri Operational Overview";
        document.getElementById('tab-title').textContent = title;
        
        if (tab === 'graph' && !state.graphInitialized) {
            initAttackGraph();
            state.graphInitialized = true;
        }
        if (tab === 'credentials') fetchCredentials();
    });
});

// --- SSE Engine ---
function initSSE() {
    const token = getToken();
    const evtSource = new EventSource("/api/v1/findings/stream?token=" + token);

    evtSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === "finding") {
            addFindingToStream(data.payload);
            refreshData(); // Updates tables and graph on new findings
        } else if (data.type === "heartbeat") {
            updateGlobalStats(data.stats);
        } else if (data.type === "approval_request") {
            showApprovalModal(data.payload);
        }
    };

    evtSource.onerror = () => {
        UI.stream.insertAdjacentHTML('afterbegin', '<div class="stream-item" style="color: var(--accent)">[SYSTEM] Reconnecting to core...</div>');
    };
}

function addFindingToStream(finding) {
    const time = new Date().toLocaleTimeString();
    const html = `
        <div class="stream-item">
            <span class="time">[${time}]</span>
            <span class="severity sev-${finding.severity.toLowerCase()}">${finding.severity}</span>
            <span class="msg"><strong>${finding.tool}</strong>: ${finding.title}</span>
        </div>
    `;
    UI.stream.insertAdjacentHTML('afterbegin', html);
    if (UI.stream.children.length > 100) UI.stream.removeChild(UI.stream.lastChild);
}

// --- Data Fetching ---
async function refreshData() {
    fetchTargets();
    fetchFindings();
    fetchSwarmStatus();
    fetchStats();
    if (state.activeTab === 'graph') updateAttackGraph();
    if (state.activeTab === 'roi') fetchRoiData();
    if (state.activeTab === 'credentials') fetchCredentials();
}

async function fetchCredentials() {
    const res = await authFetch('/api/v1/credentials');
    const data = await res.json();
    const tbody = document.querySelector('#credentials-table tbody');
    tbody.innerHTML = data.map(c => {
        let statusClass = 'badge-idle';
        if (c.status === 'Working') statusClass = 'badge-active';
        if (c.status === 'Failed') statusClass = 'badge-critical';
        if (c.status === 'Partial Failure') statusClass = 'badge-warning';
        if (c.status === 'Not Added') statusClass = 'badge-passive';

        return `
            <tr>
                <td><strong>${c.service}</strong></td>
                <td><span class="status-badge ${statusClass}">${c.status}</span></td>
                <td><code style="font-size:0.7rem">${c.last_check || 'Never'}</code></td>
                <td style="color:var(--accent); font-size:0.7rem">${c.error || 'None'}</td>
            </tr>
        `;
    }).join('');
}

async function fetchRoiData() {
    // 1. Fetch Metrics (Baseline)
    const mRes = await authFetch('/api/v1/metrics');
    const m = await mRes.json();
    
    document.getElementById('roi-findings-in').textContent = m.findings_in;
    document.getElementById('roi-fpf-drops').textContent = m.fpf_drops;
    document.getElementById('roi-premium-calls').textContent = m.premium_calls;
    document.getElementById('roi-local-calls').textContent = m.local_qwen;
    
    const killRate = m.findings_in > 0 ? (m.fpf_drops / m.findings_in * 100).toFixed(1) : "0";
    document.getElementById('roi-kill-rate').textContent = `${killRate}%`;

    // 2. Fetch Rankings (Phase 1)
    const rRes = await authFetch('/api/v1/roi/rankings');
    const rankings = await rRes.json();
    const tbody = document.querySelector('#roi-table tbody');
    tbody.innerHTML = rankings.map(r => {
        const potential = r[1] > 80 ? 'HIGH' : r[1] > 50 ? 'MED' : 'LOW';
        return `
            <tr>
                <td><strong>${r[0]}</strong></td>
                <td><code>${r[1].toFixed(1)}</code></td>
                <td><span class="status-badge badge-${potential.toLowerCase()}">${potential}</span></td>
            </tr>
        `;
    }).join('');
}

async function fetchStats() {
    const res = await authFetch('/api/v1/stats');
    const stats = await res.json();
    updateGlobalStats(stats);
}

function updateGlobalStats(stats) {
    UI.ramValue.textContent = `${stats.ram_mb} MB`;
    UI.tokenValue.textContent = `${stats.tokens_used} / ${stats.token_limit}`;
    
    const ramPct = (stats.ram_mb / stats.ram_limit_mb) * 100;
    const tokenPct = stats.token_limit > 0 ? (stats.tokens_used / stats.token_limit) * 100 : 0;
    
    UI.ramFill.style.width = `${Math.min(ramPct, 100)}%`;
    UI.tokenFill.style.width = `${Math.min(tokenPct, 100)}%`;
}

async function fetchTargets() {
    const res = await authFetch('/api/v1/targets');
    const targets = await res.json();
    const tbody = document.querySelector('#target-table tbody');
    tbody.innerHTML = targets.map(t => `
        <tr>
            <td><strong>${t.host}</strong></td>
            <td><code>${t.ip || '---'}</code></td>
            <td><span class="status-badge badge-${t.status.toLowerCase()}">${t.status}</span></td>
            <td style="color: var(--accent)">${t.findings_count}</td>
            <td style="font-size: 0.75rem; color: var(--text-dim)">${t.last_action || 'Pending'}</td>
        </tr>
    `).join('');
}

async function fetchFindings() {
    const res = await authFetch('/api/v1/targets'); // Finding list is derived from targets in current API
    const targets = await res.json();
    const tbody = document.querySelector('#finding-table tbody');
    
    let rows = [];
    targets.forEach(t => {
        // Mocking finding display for list view
        rows.push(`<tr><td colspan="5" style="background: rgba(255,0,0,0.05); font-weight: 800; font-size: 0.7rem;">TARGET: ${t.host}</td></tr>`);
    });
    tbody.innerHTML = rows.join('');
}

async function fetchSwarmStatus() {
    const res = await authFetch('/api/v1/swarm/status');
    const data = await res.json();
    UI.swarmContainer.innerHTML = data.agents.map(a => `
        <div class="agent-card">
            <h4>${a.role} <span>●</span></h4>
            <div class="agent-status">STATUS: ${a.status}</div>
            <div class="agent-status" style="font-size: 0.6rem; margin-top: 5px;">LAST: ${a.last_action}</div>
        </div>
    `).join('');
}

// --- D3.js Attack Graph ---
let simulation, svg, link, node;

function initAttackGraph() {
    const width = document.getElementById('attack-graph-canvas').clientWidth;
    const height = 600;

    svg = d3.select("#attack-graph-canvas")
        .append("svg")
        .attr("width", width)
        .attr("height", height);

    simulation = d3.forceSimulation()
        .force("link", d3.forceLink().id(d.id).distance(100))
        .force("charge", d3.forceManyBody().strength(-300))
        .force("center", d3.forceCenter(width / 2, height / 2));
        
    updateAttackGraph();
}

async function updateAttackGraph() {
    const res = await authFetch('/api/v1/attack-graph');
    const data = await res.json();
    if (!svg) return;

    svg.selectAll("*").remove();
    
    const links = data.links;
    const nodes = data.nodes;

    const link = svg.append("g")
        .attr("stroke", "#330000")
        .selectAll("line")
        .data(links)
        .join("line");

    const node = svg.append("g")
        .selectAll("circle")
        .data(nodes)
        .join("circle")
        .attr("r", d => d.type === 'target' ? 12 : 6)
        .attr("fill", d => d.type === 'target' ? "#cc0000" : "#ff4500")
        .call(drag(simulation));

    node.append("title").text(d => d.label);

    simulation.nodes(nodes).on("tick", () => {
        link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        node.attr("cx", d => d.x).attr("cy", d => d.y);
    });

    simulation.force("link").links(links);
}

function drag(simulation) {
    return d3.drag()
        .on("start", (event) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            event.subject.fx = event.subject.x;
            event.subject.fy = event.subject.y;
        })
        .on("drag", (event) => {
            event.subject.fx = event.x;
            event.subject.fy = event.y;
        })
        .on("end", (event) => {
            if (!event.active) simulation.alphaTarget(0);
            event.subject.fx = null;
            event.subject.fy = null;
        });
}

// --- Approvals ---
function showApprovalModal(req) {
    document.getElementById('modal-desc').textContent = `${req.requested_by} requests ${req.action} on ${req.reason}. Risk Level: ${req.risk_level}`;
    UI.modal.style.display = 'flex';
    
    document.getElementById('btn-approve').onclick = () => decide(req.id, 'approve');
    document.getElementById('btn-reject').onclick = () => decide(req.id, 'reject');
}

async function decide(id, decision) {
    await authFetch(`/api/v1/approvals/${id}/decision`, {
        method: 'POST',
        body: JSON.stringify({ decision, reason: "Executed via Dashboard" })
    });
    UI.modal.style.display = 'none';
}

// --- Mission Form ---
document.getElementById('missionForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const result = document.getElementById('m-result');
    result.style.display = 'none';

    const payload = {
        target: document.getElementById('m-target').value.trim(),
        program_name: document.getElementById('m-program').value.trim(),
        in_scope: document.getElementById('m-inscope').value.split('\n').map(s => s.trim()).filter(Boolean),
        out_of_scope: document.getElementById('m-outscope').value.split('\n').map(s => s.trim()).filter(Boolean),
        profile: document.getElementById('m-profile').value,
        stealth: document.getElementById('m-stealth').checked,
        vuln_scan: document.getElementById('m-vulnscan').checked,
        oob_enabled: document.getElementById('m-oob').checked,
        use_swarm: document.getElementById('m-swarm').checked,
        max_concurrency: parseInt(document.getElementById('m-concurrency').value),
        notes: document.getElementById('m-notes').value.trim(),
    };

    try {
        const res = await authFetch('/api/v2/missions', { method: 'POST', body: JSON.stringify(payload) });
        result.style.display = 'block';
        if (res.status === 202) {
            result.style.color = '#00cc66';
            result.textContent = '✅ Mission queued successfully.';
            e.target.reset();
            document.getElementById('m-concval').textContent = '20';
        } else {
            result.style.color = '#ff4444';
            result.textContent = '❌ Error: ' + await res.text();
        }
    } catch (err) {
        result.style.display = 'block';
        result.style.color = '#ff4444';
        result.textContent = '❌ Network error: ' + err.message;
    }
});

// --- Bounty Exporter ---
async function exportReport(platform) {
    const status = document.getElementById('export-status');
    status.style.display = 'block';
    status.style.color = 'var(--text-dim)';
    status.textContent = `⏳ Generating ${platform.toUpperCase()} report...`;

    try {
        const res = await authFetch('/api/v2/export', {
            method: 'POST',
            body: JSON.stringify({ platform }),
        });

        if (!res.ok) {
            status.style.color = '#ff4444';
            status.textContent = '❌ Export failed: ' + await res.text();
            return;
        }

        const blob = await res.blob();
        const disposition = res.headers.get('Content-Disposition') || '';
        const filenameMatch = disposition.match(/filename="([^"]+)"/);
        const filename = filenameMatch ? filenameMatch[1] : `report_${platform}.md`;

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);

        status.style.color = '#00cc66';
        status.textContent = `✅ Report downloaded: ${filename}`;
    } catch (err) {
        status.style.color = '#ff4444';
        status.textContent = '❌ Network error: ' + err.message;
    }
}

// --- Kickoff ---
initSSE();
setInterval(refreshData, 5000);
refreshData();
