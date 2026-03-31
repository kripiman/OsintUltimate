// Navigation Logic
document.querySelectorAll('.nav-links li').forEach(li => {
    li.addEventListener('click', () => {
        document.querySelectorAll('.nav-links li').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
        
        li.classList.add('active');
        const tab = li.getAttribute('data-tab');
        document.getElementById(tab).classList.add('active');
        
        document.getElementById('tab-title').textContent = li.textContent.trim();
    });
});

// SSE Controller
const streamContainer = document.getElementById('finding-stream');
const ramValue = document.getElementById('stat-ram');
const ramFill = document.getElementById('ram-fill');
const threadStat = document.getElementById('stat-threads');
const proxyStat = document.getElementById('stat-proxies');

function initSSE() {
    const evtSource = new EventSource("/api/v1/findings/stream");

    evtSource.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === "finding") {
            addFindingToStream(data.payload);
        } else if (data.type === "heartbeat") {
            updateStats(data.stats);
        }
    };

    evtSource.onerror = (err) => {
        console.error("SSE failed:", err);
        streamContainer.insertAdjacentHTML('afterbegin', '<div class="system-msg" style="color: red">Connection lost. Reconnecting...</div>');
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
    streamContainer.insertAdjacentHTML('afterbegin', html);
    
    // Pruning
    if (streamContainer.children.length > 500) {
        streamContainer.removeChild(streamContainer.lastChild);
    }
}

function updateStats(stats) {
    ramValue.textContent = `${stats.ram_mb} MB`;
    threadStat.textContent = stats.active_threads;
    proxyStat.textContent = stats.active_proxies;
    
    const ramPercent = (stats.ram_mb / stats.ram_limit_mb) * 100;
    ramFill.style.width = `${Math.min(ramPercent, 100)}%`;
    
    if (ramPercent > 80) ramFill.style.backgroundColor = 'var(--critical)';
    else if (ramPercent > 60) ramFill.style.backgroundColor = 'var(--high)';
    else ramFill.style.backgroundColor = 'var(--accent)';
}

// Target Fetcher
async function fetchTargets() {
    try {
        const response = await fetch('/api/v1/targets');
        const targets = await response.json();
        const tbody = document.querySelector('#target-table tbody');
        tbody.innerHTML = '';
        
        targets.forEach(t => {
            const row = `
                <tr>
                    <td><strong>${t.host}</strong></td>
                    <td><code style="color: var(--text-dim)">${t.ip || '---'}</code></td>
                    <td><span class="status-badge badge-${t.status.toLowerCase()}">${t.status}</span></td>
                    <td style="color: var(--accent)">${t.findings_count}</td>
                    <td style="font-size: 0.8rem; color: var(--text-dim)">${t.last_action || 'Pending'}</td>
                </tr>
            `;
            tbody.insertAdjacentHTML('beforeend', row);
        });
    } catch (e) {
        console.error("Fetch targets failed:", e);
    }
}

// Initial Kickoff
initSSE();
setInterval(fetchTargets, 5000);
fetchTargets();
