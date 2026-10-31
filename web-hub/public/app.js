document.addEventListener('DOMContentLoaded', () => {
    // Register Service Worker for PWA
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/sw.js').catch(err => console.log('SW registration skipped', err));
    }

    let currentRules = { domains: [], packages: [] };
    let isProtectionActive = true;

    // Elements
    const networkChip = document.getElementById('ipText');
    const qrImage = document.getElementById('qrImage');
    const mobileUrlDisplay = document.getElementById('mobileUrlDisplay');
    const copyUrlBtn = document.getElementById('copyUrlBtn');

    // Phone simulator elements
    const statusCard = document.getElementById('statusCard');
    const statusIcon = document.getElementById('statusIcon');
    const statusTitle = document.getElementById('statusTitle');
    const statusSubtitle = document.getElementById('statusSubtitle');
    const btnToggleStatus = document.getElementById('btnToggleStatus');
    const btnTriggerIntervention = document.getElementById('btnTriggerIntervention');

    // Domain tester elements
    const domainInput = document.getElementById('domainInput');
    const btnTestDomain = document.getElementById('btnTestDomain');
    const evalResult = document.getElementById('evalResult');
    const testChips = document.querySelectorAll('.test-chip');

    // Database elements
    const domList = document.getElementById('domList');
    const pkgList = document.getElementById('pkgList');
    const domCount = document.getElementById('domCount');
    const pkgCount = document.getElementById('pkgCount');
    const ruleCountBadge = document.getElementById('ruleCountBadge');
    const dbSearchInput = document.getElementById('dbSearchInput');

    // Initialize Network Info & Dynamic URL
    async function initNetworkInfo() {
        try {
            const res = await fetch('/api/network-info');
            const data = await res.json();
            const fullUrl = `http://${data.localIp}:${data.port}`;
            
            networkChip.textContent = fullUrl;
            mobileUrlDisplay.textContent = fullUrl;
            qrImage.src = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(fullUrl)}`;
        } catch (err) {
            console.warn('Using default network URL:', err);
        }
    }

    // Tab Switching
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');

            tabButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetEl = document.getElementById(`tab-${targetTab}`);
            if (targetEl) targetEl.classList.add('active');
        });
    });

    // Copy URL Button
    copyUrlBtn.addEventListener('click', () => {
        const textToCopy = mobileUrlDisplay.textContent;
        navigator.clipboard.writeText(textToCopy).then(() => {
            const prev = copyUrlBtn.textContent;
            copyUrlBtn.textContent = 'Copied!';
            setTimeout(() => copyUrlBtn.textContent = prev, 1500);
        });
    });

    // Toggle Protection inside Phone Simulator
    btnToggleStatus.addEventListener('click', () => {
        isProtectionActive = !isProtectionActive;

        if (isProtectionActive) {
            statusCard.classList.remove('paused');
            statusIcon.textContent = '🛡️';
            statusTitle.textContent = 'Protection is Active';
            statusTitle.style.color = 'var(--green)';
            statusSubtitle.textContent = 'Web and network requests to gambling domains are filtered locally.';
            btnToggleStatus.textContent = 'Pause Protection';
            btnToggleStatus.className = 'action-btn pause';
        } else {
            statusCard.classList.add('paused');
            statusIcon.textContent = '⚠️';
            statusTitle.textContent = 'Protection is Paused';
            statusTitle.style.color = 'var(--amber)';
            statusSubtitle.textContent = 'Local DNS sinkhole is paused. Tap below to resume.';
            btnToggleStatus.textContent = 'Enable Protection';
            btnToggleStatus.className = 'action-btn';
        }
    });

    // Jump to Intervention Screen Preview
    btnTriggerIntervention.addEventListener('click', () => {
        const pauseTabBtn = document.querySelector('[data-tab="pause-demo"]');
        if (pauseTabBtn) pauseTabBtn.click();
    });

    // Live Domain Tester
    async function evaluateDomain(domain) {
        if (!domain.trim()) return;

        evalResult.style.display = 'block';
        evalResult.className = 'eval-result';
        evalResult.innerHTML = '<p>Evaluating domain against verified rule database...</p>';

        try {
            const res = await fetch(`/api/test-domain?domain=${encodeURIComponent(domain)}`);
            const data = await res.json();

            if (data.blocked) {
                evalResult.className = 'eval-result blocked';
                evalResult.innerHTML = `
                    <div class="eval-header">
                        <span>🔴 BLOCKED — Wagering Service Detected</span>
                    </div>
                    <div class="eval-detail">
                        <strong>Requested Host:</strong> <code>${data.cleanDomain}</code><br>
                        <strong>Matching Rule:</strong> <code>${data.matchedRule}</code> (${data.matchType})<br>
                        <strong>Filter Action:</strong> Local DNS synthesizes <code>0.0.0.0</code> / <code>NXDOMAIN</code>.<br>
                        <strong>Reason:</strong> ${data.reason}
                    </div>
                `;
            } else {
                evalResult.className = 'eval-result allowed';
                evalResult.innerHTML = `
                    <div class="eval-header">
                        <span>🟢 ALLOWED — Permitted Domain</span>
                    </div>
                    <div class="eval-detail">
                        <strong>Requested Host:</strong> <code>${data.cleanDomain}</code><br>
                        <strong>Verification:</strong> Clean hostname. Not present on wagering blocklist.<br>
                        <strong>Filter Action:</strong> Standard DNS query forwarded to upstream resolver (<code>1.1.1.1</code>).<br>
                        <strong>False Positive Check:</strong> Passed successfully.
                    </div>
                `;
            }
        } catch (e) {
            evalResult.className = 'eval-result';
            evalResult.innerHTML = `<p style="color:red">Error evaluating: ${e.message}</p>`;
        }
    }

    btnTestDomain.addEventListener('click', () => {
        evaluateDomain(domainInput.value);
    });

    domainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            evaluateDomain(domainInput.value);
        }
    });

    testChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const testVal = chip.getAttribute('data-test');
            domainInput.value = testVal;
            evaluateDomain(testVal);
        });
    });

    // Load Rule Counts from network-info
    async function loadRuleCounts() {
        try {
            const res = await fetch('/api/network-info');
            const data = await res.json();
            const statDom = document.getElementById('statDomains');
            const statApp = document.getElementById('statApps');
            if (statDom) statDom.textContent = `${data.activeRulesCount}+`;
            if (statApp) statApp.textContent = `${data.activePackagesCount}+`;
        } catch (e) {
            console.error('Failed to load counts:', e);
        }
    }

    // Run initial loaders
    initNetworkInfo();
    loadRuleCounts();
    evaluateDomain('bet365.com'); // Run initial test
});
