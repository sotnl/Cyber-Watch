/* ── LIVE CLOCK ── */
function updateClock() {
    const clock = document.getElementById("live-clock");
    if (clock) {
        const now = new Date();
        clock.innerHTML = now.toLocaleDateString(undefined, {
            year: 'numeric', month: 'long', day: 'numeric'
        }) + ' | ' + now.toLocaleTimeString();
    }
}
setInterval(updateClock, 1000);
updateClock();


/* ── SYSTEM STATUS ROTATOR ── */
const statuses = [
    "AI Surveillance Active", "Monitoring CCTV Channels",
    "Firewall Protection Enabled", "Threat Detection Running",
    "Scanning Unauthorized Access", "All Systems Operational"
];
let statusIndex = 0;
function rotateStatus() {
    const status = document.getElementById("system-status");
    if (status) {
        status.innerHTML = statuses[statusIndex];
        statusIndex = (statusIndex + 1) % statuses.length;
    }
}
setInterval(rotateStatus, 4000);


/* ── TOAST SYSTEM ── */
function showToast(message, type = 'info') {
    let container = document.getElementById('cw-toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'cw-toast-container';
        container.style.cssText = `
            position:fixed; top:20px; right:20px; z-index:9999;
            display:flex; flex-direction:column; gap:10px;
        `;
        document.body.appendChild(container);
    }

    const colors = {
        danger:  { bg: '#2b0d0d', border: '#ef444455', text: '#ef4444' },
        success: { bg: '#0d2b1a', border: '#22c55e55', text: '#22c55e' },
        info:    { bg: '#0d1e2b', border: '#00d4ff55', text: '#00d4ff' },
        warn:    { bg: '#2b1f0d', border: '#f59e0b55', text: '#f59e0b' },
    };
    const c = colors[type] || colors.info;

    const toast = document.createElement('div');
    toast.style.cssText = `
        padding:12px 20px; border-radius:10px; font-size:13px;
        font-family:'Inter',sans-serif; font-weight:500;
        background:${c.bg}; border:1px solid ${c.border}; color:${c.text};
        min-width:280px; opacity:0; transform:translateX(40px);
        transition:all 0.3s ease;
    `;
    toast.textContent = message;
    container.appendChild(toast);
    requestAnimationFrame(() => {
        toast.style.opacity = '1';
        toast.style.transform = 'translateX(0)';
    });
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(40px)';
        setTimeout(() => toast.remove(), 400);
    }, 5000);
}


/* ── FEATURE 1: Real-time alert polling via /api/stats ── */
let prevFailed = null;
let prevBlocked = null;
let prevLastEventTime = null;

async function pollStats() {
    try {
        const res = await fetch('/api/stats');
        if (!res.ok) return;
        const data = await res.json();

        // On first load just store baseline, don't alert
        if (prevFailed === null) {
            prevFailed = data.failed_today;
            prevBlocked = data.blocked;
            prevLastEventTime = data.last_event?.time;
            return;
        }

        // New failed login
        if (data.failed_today > prevFailed) {
            const diff = data.failed_today - prevFailed;
            showToast(`⚠ ${diff} new unauthorized login attempt${diff > 1 ? 's' : ''} detected!`, 'danger');
            playThreatAlert();
        }

        // New blocked device
        if (data.blocked > prevBlocked) {
            showToast(`🚫 A device was blocked (brute force detected).`, 'warn');
        }

        // Update dashboard stat cards if present (no page reload needed)
        const failedCard = document.querySelector(".stat-card.red h1");
        const accessCard = document.querySelector(".stat-card.blue h1");
        const blockedCard = document.querySelector(".stat-card.yellow h1");
        if (failedCard) failedCard.textContent = data.failed_today;
        if (accessCard) accessCard.textContent = data.success_today;
        if (blockedCard) blockedCard.textContent = data.blocked;

        prevFailed  = data.failed_today;
        prevBlocked = data.blocked;
        prevLastEventTime = data.last_event?.time;

    } catch (e) {
        // silently fail — server may be restarting
    }
}

// Poll every 5 seconds
setInterval(pollStats, 5000);
pollStats(); // run immediately on page load


/* ── THREAT ALERT SOUND ── */
function playThreatAlert() {
    const audio = new Audio(
        "https://assets.mixkit.co/active_storage/sfx/2869/2869-preview.mp3"
    );
    audio.volume = 0.3;
    audio.play().catch(() => {}); // ignore autoplay policy errors
}


/* ── AUTO REFRESH ALERTS LIST (dashboard only) ── */
setInterval(() => {
    fetch(window.location.href)
        .then(r => r.text())
        .then(html => {
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const newAlerts = doc.querySelector('.alerts-list');
            const currentAlerts = document.querySelector('.alerts-list');
            if (newAlerts && currentAlerts) {
                currentAlerts.innerHTML = newAlerts.innerHTML;
            }
        })
        .catch(() => {});
}, 10000);


/* ── Camera status is managed by the inline script in dashboard.html ── */
/* checkCameraFeed() removed: camera.onload/onerror don't fire for srcObject streams */
