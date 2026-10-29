const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');

const PORT = 8085;
const HOST = '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, 'public');
const RULES_FILE = path.join(__dirname, 'data', 'rules.json');

// Master Admin PIN (Default: 8888)
const DEFAULT_ADMIN_PIN = "8888";
const ADMIN_AUTH_TOKEN = "bettingshield-admin-token-secure-8888";

// Load or initialize rules from JSON file
let rulesData = {
    version: 1,
    lastUpdated: Date.now(),
    adminPin: DEFAULT_ADMIN_PIN,
    domains: [],
    packages: []
};

function loadRules() {
    try {
        if (fs.existsSync(RULES_FILE)) {
            const raw = fs.readFileSync(RULES_FILE, 'utf8');
            rulesData = JSON.parse(raw);
        }
    } catch (e) {
        console.error('Error reading rules.json:', e);
    }
}

function saveRules() {
    try {
        rulesData.lastUpdated = Date.now();
        rulesData.version = (rulesData.version || 1) + 1;
        fs.writeFileSync(RULES_FILE, JSON.stringify(rulesData, null, 2), 'utf8');
    } catch (e) {
        console.error('Error writing rules.json:', e);
    }
}

loadRules();

// MIME types dictionary
const MIME_TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.mobileconfig': 'application/x-apple-aspen-config; charset=utf-8',
    '.apk': 'application/vnd.android.package-archive'
};

function getLocalIpAddress() {
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
        for (const iface of interfaces[name] || []) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '192.168.31.186';
}

function evaluateDomain(input) {
    if (!input) return { blocked: false, reason: "Empty domain" };
    let clean = input.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0].split(':')[0];
    if (clean.endsWith('.')) clean = clean.slice(0, -1);

    for (const rule of rulesData.domains) {
        if (clean === rule) {
            return {
                blocked: true,
                cleanDomain: clean,
                matchedRule: rule,
                matchType: "Exact Domain Match",
                reason: `Identified as verified wagering domain (${rule})`
            };
        }
        if (clean.endsWith('.' + rule)) {
            return {
                blocked: true,
                cleanDomain: clean,
                matchedRule: rule,
                matchType: "Subdomain Match",
                reason: `Subdomain of verified wagering provider (${rule})`
            };
        }
    }

    return {
        blocked: false,
        cleanDomain: clean,
        matchedRule: null,
        matchType: "No Match",
        reason: "Permitted. Clean domain (False-positive check passed)."
    };
}

// Helper: Extract domain name from raw DNS query wire packet
function extractDnsDomain(buf) {
    try {
        if (!buf || buf.length < 12) return null;
        let offset = 12;
        const labels = [];
        while (offset < buf.length) {
            const len = buf[offset++];
            if (len === 0) break;
            if (offset + len > buf.length) return null;
            labels.push(buf.toString('utf8', offset, offset + len));
            offset += len;
        }
        return labels.join('.').toLowerCase();
    } catch (e) {
        return null;
    }
}

// Helper: Synthesize RFC-compliant 0.0.0.0 DNS response for blocked queries
function buildBlockedDnsResponse(buf) {
    let offset = 12;
    while (offset < buf.length && buf[offset] !== 0) {
        offset += buf[offset] + 1;
    }
    offset += 5; // skip null byte + QTYPE (2) + QCLASS (2)
    const qLen = offset;
    const res = Buffer.alloc(qLen + 16);
    buf.copy(res, 0, 0, qLen);

    // Header flags: Standard Response, Authoritative, Recursion Available, No Error (0x8180)
    res.writeUInt16BE(0x8180, 2);
    res.writeUInt16BE(1, 4);  // QDCOUNT: 1
    res.writeUInt16BE(1, 6);  // ANCOUNT: 1
    res.writeUInt16BE(0, 8);  // NSCOUNT: 0
    res.writeUInt16BE(0, 10); // ARCOUNT: 0

    // Answer RR
    const aOff = qLen;
    res.writeUInt16BE(0xc00c, aOff);     // Name pointer to QNAME at offset 12
    res.writeUInt16BE(0x0001, aOff + 2); // Type A (IPv4)
    res.writeUInt16BE(0x0001, aOff + 4); // Class IN
    res.writeUInt32BE(60, aOff + 6);     // TTL 60 seconds
    res.writeUInt16BE(4, aOff + 10);     // Data length: 4 bytes
    res.writeUInt8(0, aOff + 12);        // 0.0.0.0
    res.writeUInt8(0, aOff + 13);
    res.writeUInt8(0, aOff + 14);
    res.writeUInt8(0, aOff + 15);
    return res;
}

// Helper: Forward legitimate query to upstream Cloudflare DNS over HTTPS
function forwardDohQuery(queryBuf) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: '1.1.1.1',
            port: 443,
            path: '/dns-query',
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message',
                'Content-Length': queryBuf.length
            },
            timeout: 5000
        };

        const forwardReq = https.request(options, (forwardRes) => {
            const chunks = [];
            forwardRes.on('data', chunk => chunks.push(chunk));
            forwardRes.on('end', () => {
                resolve({ status: forwardRes.statusCode, body: Buffer.concat(chunks) });
            });
        });

        forwardReq.on('error', (err) => reject(err));
        forwardReq.on('timeout', () => {
            forwardReq.destroy();
            reject(new Error('DoH upstream timeout'));
        });

        forwardReq.write(queryBuf);
        forwardReq.end();
    });
}

// Request Helper to parse JSON body
function parseJsonBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(JSON.parse(body || '{}'));
            } catch (e) {
                resolve({});
            }
        });
    });
}

function checkAdminAuth(req) {
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader === `Bearer ${ADMIN_AUTH_TOKEN}`) {
        return true;
    }
    const cookie = req.headers['cookie'] || '';
    if (cookie.includes(`admin_token=${ADMIN_AUTH_TOKEN}`)) {
        return true;
    }
    return false;
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', '*');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${pathname} from ${req.socket.remoteAddress}`);

    // API: Network and Server Information
    if (pathname === '/api/network-info') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            localIp: getLocalIpAddress(),
            port: PORT,
            activeRulesCount: rulesData.domains.length,
            activePackagesCount: rulesData.packages.length,
            version: rulesData.version,
            status: "Engine Operational"
        }));
        return;
    }

    // API: Test Domain Real-time
    if (pathname === '/api/test-domain') {
        const domain = parsedUrl.searchParams.get('domain') || '';
        const result = evaluateDomain(domain);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(result));
        return;
    }

    // API: Active Rules for Android BettingShield App Auto-Sync
    if (pathname === '/api/rules') {
        loadRules();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            version: rulesData.version,
            timestamp: rulesData.lastUpdated,
            domains: rulesData.domains,
            packages: rulesData.packages,
            signature: "bettingshield-verified-v1"
        }));
        return;
    }

    // Dynamic Hosts File Endpoint for Android (AdAway / BettingShield / hosts)
    if (pathname === '/hosts.txt') {
        loadRules();
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        let hosts = `# BettingShield Dynamic Wagering Blocklist\n# Version: ${rulesData.version}\n# Updated: ${new Date(rulesData.lastUpdated).toISOString()}\n\n`;
        for (const domain of rulesData.domains) {
            hosts += `0.0.0.0 ${domain}\n`;
            hosts += `0.0.0.0 www.${domain}\n`;
        }
        res.end(hosts);
        return;
    }

    // RFC 8484 DNS over HTTPS (DoH) Resolver
    if (pathname === '/dns-query') {
        let queryBuf = null;
        if (req.method === 'GET') {
            const dnsParam = parsedUrl.searchParams.get('dns');
            if (dnsParam) {
                try {
                    queryBuf = Buffer.from(dnsParam, 'base64url');
                } catch (e) {
                    queryBuf = null;
                }
            }
        } else if (req.method === 'POST') {
            queryBuf = await new Promise((resolve) => {
                const chunks = [];
                req.on('data', chunk => chunks.push(chunk));
                req.on('end', () => resolve(Buffer.concat(chunks)));
            });
        }

        if (!queryBuf || queryBuf.length < 12) {
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Invalid DNS query packet');
            return;
        }

        loadRules();
        const domain = extractDnsDomain(queryBuf);
        const evalResult = evaluateDomain(domain);

        if (evalResult.blocked) {
            console.log(`[DOH BLOCKED] ${domain} (${evalResult.matchedRule}) from ${req.socket.remoteAddress}`);
            const blockedResponse = buildBlockedDnsResponse(queryBuf);
            res.writeHead(200, {
                'Content-Type': 'application/dns-message',
                'Content-Length': blockedResponse.length,
                'Cache-Control': 'max-age=60'
            });
            res.end(blockedResponse);
            return;
        }

        // Forward allowed query to upstream Cloudflare DNS
        try {
            const upstream = await forwardDohQuery(queryBuf);
            res.writeHead(upstream.status, {
                'Content-Type': 'application/dns-message',
                'Content-Length': upstream.body.length
            });
            res.end(upstream.body);
        } catch (err) {
            console.error('[DOH UPSTREAM ERROR]', err.message);
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            res.end('Upstream DNS unreachable');
        }
        return;
    }

    // Apple iOS Encrypted DNS Profile (.mobileconfig)
    if (pathname === '/api/ios-profile' || pathname === '/bettingshield.mobileconfig') {
        const hostHeader = req.headers.host || `${getLocalIpAddress()}:${PORT}`;
        const isHttps = req.connection.encrypted || req.headers['x-forwarded-proto'] === 'https';
        const serverUrl = isHttps 
            ? `https://${hostHeader}/dns-query` 
            : `https://doh.cleanbrowsing.org/doh/family-filter/`;

        const profileXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>${serverUrl}</string>
                <key>ServerAddresses</key>
                <array>
                    <string>1.1.1.1</string>
                    <string>8.8.8.8</string>
                </array>
            </dict>
            <key>PayloadDescription</key>
            <string>Enforces 24/7 wagering and betting prevention DNS filtering for iPhone and iPad.</string>
            <key>PayloadDisplayName</key>
            <string>BettingShield DNS Protection</string>
            <key>PayloadIdentifier</key>
            <string>com.bettingshield.dns</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>9F2579D6-1188-4444-8888-A45F13BC4567</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>BettingShield device-wide encrypted DNS filtering profile for iOS.</string>
    <key>PayloadDisplayName</key>
    <string>BettingShield Safe Guard</string>
    <key>PayloadIdentifier</key>
    <string>com.bettingshield.profile</string>
    <key>PayloadOrganization</key>
    <string>BettingShield Privacy</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>5D3E8488-29F7-4493-9F93-7CDD6C824E52</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>`;
        res.writeHead(200, {
            'Content-Type': 'application/x-apple-aspen-config; charset=utf-8',
            'Content-Disposition': 'attachment; filename="BettingShield.mobileconfig"'
        });
        res.end(profileXml);
        return;
    }

    // ==========================================
    // ADMIN API ENDPOINTS (Secured by PIN / Auth)
    // ==========================================

    // Admin Login API
    if (pathname === '/api/admin/login' && req.method === 'POST') {
        const body = await parseJsonBody(req);
        const pin = body.pin || '';
        const validPin = rulesData.adminPin || DEFAULT_ADMIN_PIN;

        if (pin === validPin) {
            res.writeHead(200, {
                'Content-Type': 'application/json',
                'Set-Cookie': `admin_token=${ADMIN_AUTH_TOKEN}; Path=/; HttpOnly`
            });
            res.end(JSON.stringify({ success: true, token: ADMIN_AUTH_TOKEN }));
        } else {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: "Incorrect Admin PIN" }));
        }
        return;
    }

    // Admin Fetch Full Rules
    if (pathname === '/api/admin/rules') {
        if (!checkAdminAuth(req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Unauthorized. Admin PIN required." }));
            return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            version: rulesData.version,
            lastUpdated: rulesData.lastUpdated,
            domains: rulesData.domains,
            packages: rulesData.packages
        }));
        return;
    }

    // Admin Add Domain
    if (pathname === '/api/admin/add-domain' && req.method === 'POST') {
        if (!checkAdminAuth(req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Unauthorized." }));
            return;
        }
        const body = await parseJsonBody(req);
        let domain = (body.domain || '').trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
        if (domain.endsWith('.')) domain = domain.slice(0, -1);

        if (!domain || !domain.includes('.')) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Invalid domain format." }));
            return;
        }

        if (!rulesData.domains.includes(domain)) {
            rulesData.domains.unshift(domain);
            saveRules();
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, domain, totalCount: rulesData.domains.length }));
        return;
    }

    // Admin Delete Domain
    if (pathname === '/api/admin/delete-domain' && req.method === 'POST') {
        if (!checkAdminAuth(req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Unauthorized." }));
            return;
        }
        const body = await parseJsonBody(req);
        const domain = (body.domain || '').trim().toLowerCase();

        rulesData.domains = rulesData.domains.filter(d => d.toLowerCase() !== domain);
        saveRules();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, deleted: domain, totalCount: rulesData.domains.length }));
        return;
    }

    // Admin Add Package
    if (pathname === '/api/admin/add-package' && req.method === 'POST') {
        if (!checkAdminAuth(req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Unauthorized." }));
            return;
        }
        const body = await parseJsonBody(req);
        const pkg = (body.package || '').trim();
        const name = (body.name || pkg).trim();
        const category = (body.category || 'Wagering').trim();

        if (!pkg || !pkg.includes('.')) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Invalid package identifier." }));
            return;
        }

        const existing = rulesData.packages.find(p => p.package === pkg);
        if (!existing) {
            rulesData.packages.unshift({ package: pkg, name, category });
            saveRules();
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, package: pkg, totalCount: rulesData.packages.length }));
        return;
    }

    // Admin Delete Package
    if (pathname === '/api/admin/delete-package' && req.method === 'POST') {
        if (!checkAdminAuth(req)) {
            res.writeHead(401, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: "Unauthorized." }));
            return;
        }
        const body = await parseJsonBody(req);
        const pkg = (body.package || '').trim();

        rulesData.packages = rulesData.packages.filter(p => p.package !== pkg);
        saveRules();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true, deleted: pkg, totalCount: rulesData.packages.length }));
        return;
    }

    // Static Files Handler
    let reqPath = pathname === '/' ? '/index.html' : pathname;
    let filePath = path.join(PUBLIC_DIR, reqPath);

    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
        filePath = path.join(PUBLIC_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(500);
            res.end('Server Error');
            return;
        }
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
    });
});

server.listen(PORT, HOST, () => {
    const localIp = getLocalIpAddress();
    console.log(`=======================================================`);
    console.log(`🛡️  BettingShield Engine & Admin Portal Active`);
    console.log(`=======================================================`);
    console.log(`📱 User Mobile Hub:    http://${localIp}:${PORT}`);
    console.log(`🔒 Admin Control Page:  http://${localIp}:${PORT}/admin.html`);
    console.log(`🔑 Master Admin PIN:   ${rulesData.adminPin || DEFAULT_ADMIN_PIN}`);
    console.log(`=======================================================`);
});
