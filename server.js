/**
 * FW Audit Dashboard — Check Point Management API proxy server
 *
 * Handles HTTPS (incl. self-signed certs), session management,
 * pagination, and rule/section flattening.
 *
 * Usage:
 *   npm install
 *   node server.js
 *   open http://localhost:3737
 */

'use strict';

const express        = require('express');
const axios          = require('axios');
const https          = require('https');
const path           = require('path');
const { execFile }   = require('child_process');
const dgram          = require('dgram');
const net            = require('net');
const Database       = require('better-sqlite3');

const app  = express();
const PORT = process.env.PORT || 3737;

app.use(express.json());
app.use(express.static(path.join(__dirname)));   // serve index.html

// ─── helpers ─────────────────────────────────────────────────────────────────

/** Create an axios instance pre-configured for a Check Point management server.
 *  rejectUnauthorized=false so self-signed certs don't break the connection. */
function cpClient(server, port) {
  return axios.create({
    baseURL:    `https://${server}:${port}/web_api`,
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout:    60_000,
    headers:    { 'Content-Type': 'application/json' },
  });
}

/** Iteratively flatten access-sections so every leaf is an access-rule.
 *  Uses an explicit stack to avoid call-stack overflow on deep rulebases. */
function flattenRulebase(items = []) {
  const out = [];
  const stack = [...items];
  while (stack.length) {
    const item = stack.pop();
    if (item.type === 'access-section') {
      const children = item.rulebase || [];
      // push in reverse so original order is preserved
      for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
    } else {
      out.push(item);
    }
  }
  return out;
}

/** Pull every page of a Check Point paginated endpoint. */
async function fetchAllPages(cp, sid, endpoint, extraBody = {}) {
  const LIMIT = 500;
  let offset = 0;
  let total  = Infinity;
  const all  = [];

  while (offset < total) {
    const resp = await cp.post(
      endpoint,
      { limit: LIMIT, offset, 'details-level': 'full', ...extraBody },
      { headers: { 'X-chkp-sid': sid } }
    );
    const d = resp.data;
    total   = d.total ?? d.to ?? (d.objects?.length || 0);
    const items = d.objects || d.rulebase || d.packages || d['access-layers'] || [];
    all.push(...items);
    offset += LIMIT;
    if (!items.length || all.length >= total) break;
  }
  return all;
}

/** Normalise a raw CP rule object into the format the dashboard expects.
 *  objDict: Map<uid, {name, ...}> built from objects-dictionary responses. */
function normaliseRule(rule, objDict = new Map()) {
  // Resolve a single value: may be a full object {name,uid}, a plain UID string,
  // or a primitive. Returns the human-readable name.
  const resolve = val => {
    if (!val) return '';
    if (typeof val === 'object' && val.name) return val.name;     // already full object
    if (typeof val === 'string') {
      const hit = objDict.get(val);
      return hit ? (hit.name || val) : val;                       // lookup uid → name
    }
    return String(val);
  };
  const names = arr => (arr || []).map(resolve).filter(Boolean).join(', ');
  const action = resolve(rule.action);

  // Hits: CP API returns either an integer (older) or an object with value/last-date/first-date/level
  const h = rule.hits;
  let hitCount = '', hitLevel = '', lastHit = '', firstHit = '';
  if (h !== undefined && h !== null) {
    if (typeof h === 'number') {
      hitCount = h;
    } else if (typeof h === 'object') {
      hitCount  = h.value      ?? h.total ?? '';
      hitLevel  = h.level      ?? '';                              // none|low|medium|high|very-high
      lastHit   = h['last-date']?.['iso-8601']  || h['last-date']  || '';
      firstHit  = h['first-date']?.['iso-8601'] || h['first-date'] || '';
    }
  }

  return {
    name:      rule.name      || `rule-${rule['rule-number'] || rule.uid}`,
    rule_num:  rule['rule-number'] ?? '',
    enabled:   rule.enabled !== false ? 'Yes' : 'No',
    action,
    src_zone:  names(rule['from-zone']),
    src:       names(rule.source),
    dst_zone:  names(rule['to-zone']),
    dst:       names(rule.destination),
    service:   names(rule.service),
    hits:      hitCount,
    hit_level: hitLevel,
    last_hit:  lastHit,
    first_hit: firstHit,
    comment:   rule.comments  || rule.comment || '',
  };
}

// ─── routes ──────────────────────────────────────────────────────────────────

/** POST /api/cp/login
 *  Body: { server, port?, username, password, domain? }
 *  Returns: { sid, api_server_version, ... }
 */
app.post('/api/cp/login', async (req, res) => {
  const { server, port = 443, username, password, domain } = req.body;
  if (!server || !username || !password)
    return res.status(400).json({ error: 'server, username and password are required' });

  const cp = cpClient(server, port);
  const payload = { user: username, password };
  if (domain) payload.domain = domain;

  try {
    const r = await cp.post('/login', payload);
    res.json(r.data);   // includes sid, api_server_version, etc.
  } catch (err) {
    const msg  = err.response?.data?.message || err.message;
    const code = err.response?.status        || 500;
    res.status(code).json({ error: msg, details: err.response?.data });
  }
});

/** POST /api/cp/logout
 *  Body: { server, port?, sid }
 */
app.post('/api/cp/logout', async (req, res) => {
  const { server, port = 443, sid } = req.body;
  try {
    const cp = cpClient(server, port);
    await cp.post('/logout', {}, { headers: { 'X-chkp-sid': sid } });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** POST /api/cp/packages
 *  Body: { server, port?, sid }
 *  Returns: { packages: [...] }
 */
app.post('/api/cp/packages', async (req, res) => {
  const { server, port = 443, sid } = req.body;
  try {
    const cp  = cpClient(server, port);
    const all = await fetchAllPages(cp, sid, '/show-packages');
    res.json({ packages: all });
  } catch (err) {
    const msg  = err.response?.data?.message || err.message;
    const code = err.response?.status        || 500;
    res.status(code).json({ error: msg, details: err.response?.data });
  }
});

/** POST /api/cp/layers
 *  Body: { server, port?, sid }
 *  Returns: { layers: [...] }   — all access-layers on the server
 */
app.post('/api/cp/layers', async (req, res) => {
  const { server, port = 443, sid } = req.body;
  try {
    const cp  = cpClient(server, port);
    const all = await fetchAllPages(cp, sid, '/show-access-layers');
    res.json({ layers: all });
  } catch (err) {
    const msg  = err.response?.data?.message || err.message;
    const code = err.response?.status        || 500;
    res.status(code).json({ error: msg, details: err.response?.data });
  }
});

/** POST /api/cp/rules
 *  Body: { server, port?, sid, name?, uid? }
 *    name or uid identifies the access layer / rulebase
 *  Returns: { total, rules: [...] }  — normalised rule objects
 */
app.post('/api/cp/rules', async (req, res) => {
  const { server, port = 443, sid, name, uid } = req.body;
  if (!name && !uid)
    return res.status(400).json({ error: 'name or uid of the access layer is required' });

  const cp      = cpClient(server, port);
  const extra   = uid ? { uid } : { name };
  const LIMIT   = 500;
  let offset    = 0;
  let total     = Infinity;
  const allRaw  = [];
  const objDict = new Map();   // uid → object, accumulated across all pages

  try {
    while (offset < total) {
      const resp = await cp.post(
        '/show-access-rulebase',
        { limit: LIMIT, offset, 'use-object-dictionary': true, 'details-level': 'full', 'show-hits': true, ...extra },
        { headers: { 'X-chkp-sid': sid } }
      );
      const d = resp.data;
      total   = d.total ?? (d.rulebase?.length || 0);

      // Accumulate the objects-dictionary returned alongside each page
      for (const obj of (d['objects-dictionary'] || [])) {
        if (obj.uid) objDict.set(obj.uid, obj);
      }

      const flat = flattenRulebase(d.rulebase || []);
      allRaw.push(...flat);
      offset += LIMIT;
      if (!d.rulebase?.length || allRaw.length >= total) break;
    }

    const rules = allRaw.map(r => normaliseRule(r, objDict));
    res.json({ total: rules.length, rules });
  } catch (err) {
    const msg  = err.response?.data?.message || err.message;
    const code = err.response?.status        || 500;
    res.status(code).json({ error: msg, details: err.response?.data });
  }
});

/** POST /api/cp/domains
 *  Body: { server, port?, sid }
 *  For Multi-Domain servers — lists all managed domains.
 */
app.post('/api/cp/domains', async (req, res) => {
  const { server, port = 443, sid } = req.body;
  try {
    const cp  = cpClient(server, port);
    const all = await fetchAllPages(cp, sid, '/show-domains');
    res.json({ domains: all });
  } catch (err) {
    const msg  = err.response?.data?.message || err.message;
    const code = err.response?.status        || 500;
    res.status(code).json({ error: msg, details: err.response?.data });
  }
});

/** POST /api/cp/gateways
 *  Returns all gateway/cluster objects with full detail.
 *  Tries multiple endpoints in order so it works across CP versions
 *  and read-only permission profiles.
 */
app.post('/api/cp/gateways', async (req, res) => {
  const { server, port = 443, sid } = req.body;
  const cp = cpClient(server, port);
  const tried = [];

  try {
    // ── Strategy 1: dedicated simple-gateway / simple-cluster endpoints (R80.20+)
    const [gwResp, clResp] = await Promise.allSettled([
      fetchAllPages(cp, sid, '/show-simple-gateways', { 'details-level': 'full' }),
      fetchAllPages(cp, sid, '/show-simple-clusters',  { 'details-level': 'full' }),
    ]);
    tried.push('show-simple-gateways', 'show-simple-clusters');
    const s1 = [
      ...(gwResp.status === 'fulfilled' ? gwResp.value : []),
      ...(clResp.status === 'fulfilled' ? clResp.value : []),
    ];
    if (s1.length) return res.json({ gateways: s1, source: 'show-simple-gateways' });

    // ── Strategy 2: show-gateways-and-servers (older API / broader permission)
    tried.push('show-gateways-and-servers');
    try {
      const s2 = await fetchAllPages(cp, sid, '/show-gateways-and-servers', { 'details-level': 'full' });
      if (s2.length) return res.json({ gateways: s2, source: 'show-gateways-and-servers' });
    } catch (_) {}

    // ── Strategy 3: show-objects filtered by type (works with any read permission)
    tried.push('show-objects?type=simple-gateway');
    const gwTypes = ['simple-gateway', 'simple-cluster', 'CpmiGatewayCluster', 'checkpoint-host'];
    const s3 = [];
    for (const type of gwTypes) {
      try {
        const objs = await fetchAllPages(cp, sid, '/show-objects', { type, 'details-level': 'full' });
        s3.push(...objs);
      } catch (_) {}
    }
    if (s3.length) return res.json({ gateways: s3, source: 'show-objects' });

    // ── Nothing found — return empty with diagnostics
    res.json({
      gateways: [],
      source: 'none',
      tried,
      hint: 'No gateways found. Ensure the audit user has "Gateways & Servers" Read permission in SmartConsole → Manage & Settings → Permissions & Administrators.',
    });
  } catch (err) {
    const msg  = err.response?.data?.message || err.message;
    const code = err.response?.status        || 500;
    res.status(code).json({ error: msg, tried });
  }
});

/** POST /api/cp/topology
 *  Body: { server, port?, sid, uid, objectType?, rawObject? }
 *
 *  If rawObject is provided (full CP object already fetched by the gateways
 *  call) it is used directly — no second API call is made. This handles
 *  non-standard gateway types like CpmiGatewayCkp that don't work with
 *  show-simple-gateway / show-object.
 *
 *  Otherwise falls back to several API endpoints in order.
 */
app.post('/api/cp/topology', async (req, res) => {
  const { server, port = 443, sid, uid, objectType, rawObject } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid is required' });

  let raw = null;

  // ── Fast path: caller already has the full object ─────────────
  if (rawObject && rawObject.uid) {
    raw = rawObject;
    console.log(`[topology] Using cached object "${raw.name}" (type=${raw.type})`);
  } else {
    // ── API fetch with fallbacks ───────────────────────────────
    const cp = cpClient(server, port);
    const headers = { 'X-chkp-sid': sid };
    const errors = [];

    const isCluster = /cluster/i.test(objectType || '');
    const endpoints = isCluster
      ? ['/show-simple-cluster', '/show-simple-gateway', '/show-object']
      : ['/show-simple-gateway', '/show-simple-cluster', '/show-object'];

    for (const endpoint of endpoints) {
      try {
        const r = await cp.post(endpoint, { uid, 'details-level': 'full' }, { headers });
        if (r.data && r.data.uid) { raw = r.data; break; }
      } catch (e) {
        errors.push(`${endpoint}: ${e.response?.data?.message || e.message}`);
      }
    }

    if (!raw) {
      console.error(`[topology] All endpoints failed for uid=${uid}:`, errors);
      return res.status(404).json({
        error: `Could not fetch gateway object. Tried: ${endpoints.join(', ')}`,
        details: errors,
      });
    }
    console.log(`[topology] Loaded "${raw.name}" (type=${raw.type}) via API`);
  }

  // Normalise interfaces
  const ifaces = (raw.interfaces || []).map(iface => {
    // topology can be a plain string ("internal","external","dmz")
    // OR an object like { "leads-to": "internal", ... } on full Gaia objects
    const topoRaw = iface.topology;
    const topo = (
      typeof topoRaw === 'string' ? topoRaw :
      typeof topoRaw === 'object' && topoRaw !== null
        ? (topoRaw['leads-to'] || topoRaw.name || topoRaw.type || Object.values(topoRaw).find(v => typeof v === 'string') || '')
        : ''
    ).toLowerCase();

    const ipv4    = iface['ipv4-address'] || iface['ipv6-address'] || '';
    const mask    = iface['ipv4-mask-length'] ?? iface['subnet-mask'] ?? '';
    const leads   = (iface['topology-settings']?.['ip-address-behind-this-interface'] || '').toLowerCase();

    // zone name: explicit or derived from topology type
    const zoneName = iface['security-zone-settings']?.['specific-zone-value']
                  || iface['security-zone-settings']?.['specific-zone']
                  || iface['topology-automatic-calculated']
                  || topo || 'unknown';

    // collect networks behind this interface
    const nets = [];
    if (iface['topology-settings']?.['specific-network']) {
      const sn = iface['topology-settings']['specific-network'];
      nets.push(typeof sn === 'object' ? (sn.name || sn.subnet || '') : sn);
    }
    if (ipv4 && mask !== '') nets.push(`${ipv4}/${mask}`);

    return {
      name:     iface.name || iface['interface-name'] || '?',
      ipv4,
      mask,
      cidr:     ipv4 && mask !== '' ? `${ipv4}/${mask}` : '',
      topology: topo || 'unknown',
      zone:     typeof zoneName === 'object' ? (zoneName.name || 'unknown') : zoneName,
      leads,
      antiSpoofing: iface['anti-spoofing'] ?? false,
      networks: nets.filter(Boolean),
    };
  });

  res.json({
    uid:       raw.uid,
    name:      raw.name,
    type:      raw.type,
    ipv4:      raw['ipv4-address'] || '',
    version:   raw['os-name'] || raw.version || '',
    platform:  raw['hardware'] || '',
    policy:    raw['policy']?.name || '',
    interfaces: ifaces,
  });
});

/** POST /api/cp/debug-gw
 *  Returns the raw CP object for a given uid — useful for diagnosing
 *  unknown gateway types. Hits /show-object which works for any type.
 */
app.post('/api/cp/debug-gw', async (req, res) => {
  const { server, port = 443, sid, uid } = req.body;
  if (!uid) return res.status(400).json({ error: 'uid is required' });
  const cp = cpClient(server, port);
  try {
    const r = await cp.post('/show-object', { uid, 'details-level': 'full' }, { headers: { 'X-chkp-sid': sid } });
    res.json(r.data);
  } catch (err) {
    res.status(err.response?.status || 500).json({
      error: err.response?.data?.message || err.message,
      details: err.response?.data,
    });
  }
});

// ─── network discovery ───────────────────────────────────────────────────────

/** Ping a single IP; resolves to true if reachable. */
function pingOne(ip) {
  return new Promise(resolve => {
    // -c 1 -W 1 on Linux; -c 1 -t 1 on macOS
    const args = process.platform === 'darwin'
      ? ['-c','1','-t','1', ip]
      : ['-c','1','-W','1', ip];
    execFile('ping', args, { timeout: 2000 }, err => resolve(!err));
  });
}

/** Read system ARP table (works on Linux & macOS). */
function readArp() {
  return new Promise((resolve) => {
    execFile('arp', ['-an'], { timeout: 3000 }, (err, stdout) => {
      const devices = [];
      if (err) return resolve(devices);
      const lines = stdout.split('\n');
      for (const line of lines) {
        // Linux: ? (10.0.0.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
        // macOS: ? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope ...
        const m = line.match(/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)\s+.*?(?:on\s+(\S+))?/i);
        if (!m) continue;
        const [, ip, mac, iface] = m;
        if (mac === '(incomplete)' || mac === 'ff:ff:ff:ff:ff:ff') continue;
        devices.push({ ip, mac: mac.toLowerCase(), iface: iface || '', status: 'arp' });
      }
      resolve(devices);
    });
  });
}

/** POST /api/discover
 *  Body: { subnet?: string }
 *  Returns: { devices: [{ip,mac,iface,status}] }
 */
app.post('/api/discover', async (req, res) => {
  try {
    const arpDevices = await readArp();
    const byIp = {};
    for (const d of arpDevices) byIp[d.ip] = d;

    // If a subnet was provided, try to ping the whole /24 or /16 range
    const { subnet } = req.body;
    if (subnet) {
      const m = subnet.match(/^(\d+)\.(\d+)\.(\d+)\.\d+\/(\d+)$/);
      if (m) {
        const [, a, b, c, prefix] = m.map(Number);
        const targets = [];
        if (prefix >= 24) {
          for (let i = 1; i < 255; i++) targets.push(`${a}.${b}.${c}.${i}`);
        } else if (prefix >= 16) {
          for (let ci = 0; ci < 256; ci++)
            for (let i = 1; i < 255; i++) targets.push(`${a}.${b}.${ci}.${i}`);
        }
        // Ping in batches of 40 concurrently
        const BATCH = 40;
        for (let i = 0; i < targets.length; i += BATCH) {
          const batch = targets.slice(i, i + BATCH);
          await Promise.all(batch.map(async ip => {
            const alive = await pingOne(ip);
            if (alive) {
              if (!byIp[ip]) byIp[ip] = { ip, mac: '', iface: '', status: 'up' };
              else byIp[ip].status = 'up';
            }
          }));
        }
      }
    }

    res.json({ devices: Object.values(byIp) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── SQLite traffic database ──────────────────────────────────────────────────

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'traffic.db');
const db = new Database(DB_PATH);

db.exec(`
  PRAGMA journal_mode=WAL;

  CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       INTEGER NOT NULL,
    src      TEXT NOT NULL,
    dst      TEXT NOT NULL,
    action   TEXT,
    service  TEXT,
    app      TEXT DEFAULT '',
    bytes    INTEGER DEFAULT 0,
    allowed  INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS nodes (
    ip       TEXT PRIMARY KEY,
    allow_c  INTEGER DEFAULT 0,
    drop_c   INTEGER DEFAULT 0,
    bytes    INTEGER DEFAULT 0,
    last_ts  INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS edges (
    src      TEXT NOT NULL,
    dst      TEXT NOT NULL,
    allow_c  INTEGER DEFAULT 0,
    drop_c   INTEGER DEFAULT 0,
    service  TEXT DEFAULT '',
    app      TEXT DEFAULT '',
    last_ts  INTEGER DEFAULT 0,
    PRIMARY KEY(src, dst)
  );

  CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
`);

// Prepared statements for hot path (UDP handler)
const stmtInsertEvent  = db.prepare(`INSERT INTO events(ts,src,dst,action,service,app,bytes,allowed) VALUES(?,?,?,?,?,?,?,?)`);
const stmtUpsertNode   = db.prepare(`
  INSERT INTO nodes(ip,allow_c,drop_c,bytes,last_ts) VALUES(?,?,?,?,?)
  ON CONFLICT(ip) DO UPDATE SET
    allow_c = allow_c + excluded.allow_c,
    drop_c  = drop_c  + excluded.drop_c,
    bytes   = bytes   + excluded.bytes,
    last_ts = MAX(last_ts, excluded.last_ts)
`);
const stmtUpsertEdge   = db.prepare(`
  INSERT INTO edges(src,dst,allow_c,drop_c,service,app,last_ts) VALUES(?,?,?,?,?,?,?)
  ON CONFLICT(src,dst) DO UPDATE SET
    allow_c = allow_c + excluded.allow_c,
    drop_c  = drop_c  + excluded.drop_c,
    service = COALESCE(NULLIF(excluded.service,''), edges.service),
    app     = COALESCE(NULLIF(excluded.app,''), edges.app),
    last_ts = MAX(last_ts, excluded.last_ts)
`);

// Wrap the three writes in a single transaction for speed
const insertTraffic = db.transaction((ev, allowed) => {
  const ts = ev.ts;
  stmtInsertEvent.run(ts, ev.src, ev.dst, ev.action, ev.service||'', ev.app||'', ev.bytes||0, allowed?1:0);
  stmtUpsertNode.run(ev.src, allowed?1:0, allowed?0:1, ev.bytes||0, ts);
  stmtUpsertNode.run(ev.dst, 0, 0, 0, ts);
  stmtUpsertEdge.run(ev.src, ev.dst, allowed?1:0, allowed?0:1, ev.service||'', ev.app||'', ts);
});

// ─── syslog receiver (live traffic) ──────────────────────────────────────────

let syslogSocket = null;
const sseClients = new Set();
let ssePushInterval = null;

const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

// Raw log ring-buffer for /api/syslog/rawlog debug endpoint (last 100 lines)
const rawLogRing = [];
function pushRawLog(line) {
  rawLogRing.push({ ts: Date.now(), line: line.slice(0, 500) });
  if (rawLogRing.length > 100) rawLogRing.shift();
}

/** Parse a CP R80/R81/R82 syslog message — key:"value"; format */
function parseSyslogEvent(raw) {
  const kv = {};
  let m;

  // CP R8x native: key:"value";
  const cpRe = /\b(\w+):"([^"]*)"/g;
  while ((m = cpRe.exec(raw)) !== null) kv[m[1].toLowerCase()] = m[2];

  // unquoted: key:value;
  const cpRe2 = /\b(\w+):([^";{}\[\]\s]+)/g;
  while ((m = cpRe2.exec(raw)) !== null) { const k=m[1].toLowerCase(); if(!kv[k]) kv[k]=m[2]; }

  // CEF fallback
  const cefM = raw.match(/CEF:\d+\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|([^|]*)\|(\d+)\|(.*)/s);
  if (cefM) {
    const extRe = /(\w+)=((?:[^\s\\]|\\.)*)/g;
    let em;
    while ((em = extRe.exec(cefM[3])) !== null) { const k=em[1].toLowerCase(); if(!kv[k]) kv[k]=em[2]; }
    if (!kv.action) kv.action = cefM[1] || '';
  }

  // key=value fallback
  const kvRe = /\b(src|dst|action|service|proto|app|bytes|origin|orig)\s*=\s*([^\s;|,\]]+)/gi;
  while ((m = kvRe.exec(raw)) !== null) { const k=m[1].toLowerCase(); if(!kv[k]) kv[k]=m[2]; }

  const src = kv.src || kv.orig || kv.origin || kv.xlatesrc;
  const dst = kv.dst || kv.xlatedst;
  if (!src || !dst || !IP_RE.test(src) || !IP_RE.test(dst)) return null;

  // app: APPI blade identification (rich name like "ChatGPT", "YouTube")
  // service: protocol/port-level name (https, dns, smtp)
  const app     = kv.appi_name || kv.app_name || kv.application || kv.app || '';
  const service = kv.service || kv.proto || '';

  return {
    ts:      Date.now(),
    src, dst,
    action:  kv.action || 'unknown',
    service: service || app,  // fallback so service is never empty if we have app
    app,
    bytes:   parseInt(kv.bytes) || 0,
  };
}

// Add app column to existing DB if upgrading from older schema (idempotent)
try { db.exec(`ALTER TABLE events ADD COLUMN app TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE edges  ADD COLUMN app TEXT DEFAULT ''`); } catch {}

function buildSnapshot(windowSec = 3600) {
  const cutoff = windowSec ? Date.now() - windowSec * 1000 : 0;
  const where  = cutoff ? 'WHERE last_ts >= ?' : '';
  const args   = cutoff ? [cutoff] : [];

  const nodes  = db.prepare(`SELECT ip, allow_c, drop_c, bytes, last_ts FROM nodes ${where} ORDER BY (allow_c+drop_c) DESC LIMIT 500`).all(...args);
  const edges  = db.prepare(`SELECT src, dst, allow_c, drop_c, service, app, last_ts FROM edges ${where} ORDER BY (allow_c+drop_c) DESC LIMIT 2000`).all(...args);
  const recent = db.prepare(`SELECT ts,src,dst,action,service,app,bytes FROM events ORDER BY ts DESC LIMIT 200`).all();
  const total  = db.prepare(`SELECT COUNT(*) as c FROM events`).get().c;

  // Top applications: aggregate by app (fall back to service), count events + bytes
  const topApps = db.prepare(`
    SELECT
      COALESCE(NULLIF(app,''), service, 'unknown') AS name,
      COUNT(*) AS events,
      SUM(bytes) AS bytes,
      SUM(allowed) AS allow_c,
      COUNT(*) - SUM(allowed) AS drop_c
    FROM events
    ${cutoff ? 'WHERE ts >= ?' : ''}
    GROUP BY name
    ORDER BY events DESC
    LIMIT 20
  `).all(...args);

  return {
    type: 'snapshot', ts: Date.now(),
    totalEvents: total,
    nodes:       nodes.map(n => ({ ip:n.ip, allow:n.allow_c, drop:n.drop_c, bytes:n.bytes, lastSeen:n.last_ts })),
    edges:       edges.map(e => ({ src:e.src, dst:e.dst, allow:e.allow_c, drop:e.drop_c, service:e.service, app:e.app, lastSeen:e.last_ts })),
    recentEvents: recent,
    topApps,
  };
}

function broadcastSSE(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  for (const res of sseClients) {
    try { res.write(data); }
    catch { sseClients.delete(res); }
  }
}

/** POST /api/syslog/start — start UDP listener + 5s SSE push */
app.post('/api/syslog/start', (req, res) => {
  const port        = parseInt(req.body.port) || 5140;
  const intervalSec = parseInt(req.body.intervalSec) || 5;

  if (syslogSocket) { try { syslogSocket.close(); } catch {} syslogSocket = null; }
  if (ssePushInterval) { clearInterval(ssePushInterval); ssePushInterval = null; }

  syslogSocket = dgram.createSocket('udp4');

  syslogSocket.on('message', (msg) => {
    const raw = msg.toString('utf8').trim();
    pushRawLog(raw);
    const ev = parseSyslogEvent(raw);
    if (ev) insertTraffic(ev, /accept|allow|permit/i.test(ev.action));
  });

  syslogSocket.on('error', (err) => { console.error('[syslog] error:', err.message); });

  syslogSocket.bind(port, '0.0.0.0', () => {
    console.log(`[syslog] listening UDP :${port}, pushing every ${intervalSec}s`);
    // Push snapshot to connected browsers every N seconds
    ssePushInterval = setInterval(() => {
      if (sseClients.size > 0) {
        broadcastSSE(buildSnapshot());
      }
    }, intervalSec * 1000);
    res.json({ ok: true, port, intervalSec });
  });

  syslogSocket.on('error', (err) => { if (!res.headersSent) res.status(500).json({ error: err.message }); });
});

/** POST /api/syslog/stop */
app.post('/api/syslog/stop', (_req, res) => {
  if (syslogSocket) { try { syslogSocket.close(); } catch {} syslogSocket = null; }
  if (ssePushInterval) { clearInterval(ssePushInterval); ssePushInterval = null; }
  res.json({ ok: true });
});

/** POST /api/syslog/clear — wipe DB tables */
app.post('/api/syslog/clear', (_req, res) => {
  db.exec(`DELETE FROM events; DELETE FROM nodes; DELETE FROM edges;`);
  broadcastSSE({ type: 'clear' });
  res.json({ ok: true });
});

/** GET /api/syslog/stream — SSE; sends current snapshot immediately on connect */
app.get('/api/syslog/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();
  res.write(`data: ${JSON.stringify(buildSnapshot())}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
});

/** GET /api/syslog/snapshot */
app.get('/api/syslog/snapshot', (_req, res) => res.json(buildSnapshot()));

/** GET /api/syslog/rawlog — last 100 raw UDP lines for debugging */
app.get('/api/syslog/rawlog', (_req, res) => {
  res.json({ count: rawLogRing.length, logs: rawLogRing });
});

// ─── log collector ────────────────────────────────────────────────────────────

const SEV_TO_SYSLOG = { CRITICAL: 2, HIGH: 4, MEDIUM: 5, LOW: 6, OK: 7 };

function buildSyslogMsg(cfg, severity, msg) {
  const pri = (cfg.facility * 8) + (SEV_TO_SYSLOG[severity] ?? 6);
  const ts  = new Date().toUTCString().replace(/GMT$/, '').trim();
  const tag = cfg.tag || 'AIVERTO-AUDIT';
  return `<${pri}>${ts} ${tag}: ${msg}`;
}

function buildCefMsg(cfg, ev) {
  const pri = (cfg.facility * 8) + (SEV_TO_SYSLOG[ev.severity] ?? 6);
  const ts  = new Date().toUTCString().replace(/GMT$/, '').trim();
  const sevNum = { CRITICAL: 10, HIGH: 8, MEDIUM: 5, LOW: 3 }[ev.severity] ?? 1;
  const ext = [
    `src=${ev.src||''}`,
    `dst=${ev.dst||''}`,
    `spt=0`,
    `app=${ev.service||''}`,
    `act=${ev.action||''}`,
    `cnt=${ev.hits||0}`,
    `msg=${(ev.flags||'').replace(/\|/g,'\\|')}`,
    `flexString1=${ev.name||''}`,
    `flexString1Label=RuleName`,
  ].join(' ');
  const cef = `CEF:0|CheckPoint|Firewall-Audit|1.0|${ev.ruleNum}|${ev.name||'Rule '+ev.ruleNum}|${sevNum}|${ext}`;
  return `<${pri}>${ts} ${cfg.tag||'AIVERTO-AUDIT'}: ${cef}`;
}

function buildJsonMsg(cfg, ev) {
  const pri = (cfg.facility * 8) + (SEV_TO_SYSLOG[ev.severity] ?? 6);
  const ts  = new Date().toUTCString().replace(/GMT$/, '').trim();
  const payload = JSON.stringify({ timestamp: new Date().toISOString(), severity: ev.severity, ...ev });
  return `<${pri}>${ts} ${cfg.tag||'AIVERTO-AUDIT'}: ${payload}`;
}

function sendMsgToCollector(cfg, msg) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(msg + '\n');
    if (cfg.proto === 'tcp') {
      const sock = net.createConnection({ host: cfg.host, port: cfg.port }, () => {
        sock.write(buf);
        sock.end();
      });
      sock.setTimeout(4000);
      sock.on('close', resolve);
      sock.on('error', reject);
      sock.on('timeout', () => { sock.destroy(); reject(new Error('TCP timeout')); });
    } else {
      const client = dgram.createSocket('udp4');
      client.send(buf, 0, buf.length, cfg.port, cfg.host, err => {
        client.close();
        err ? reject(err) : resolve();
      });
    }
  });
}

/** POST /api/log-test — send a single test syslog message */
app.post('/api/log-test', async (req, res) => {
  const { host, port = 514, proto = 'udp', format = 'syslog', facility = 20, tag = 'AIVERTO-AUDIT' } = req.body;
  if (!host) return res.status(400).json({ error: 'host is required' });
  const cfg = { host, port, proto, format, facility, tag };
  const msg = buildSyslogMsg(cfg, 'LOW', 'AIVERTO-AUDIT connectivity test — OK');
  try {
    await sendMsgToCollector(cfg, msg);
    res.json({ message: `Test message sent to ${host}:${port} [${proto.toUpperCase()}]` });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

/** POST /api/log-send — send all audit events */
app.post('/api/log-send', async (req, res) => {
  const { host, port = 514, proto = 'udp', format = 'cef', facility = 20, tag = 'AIVERTO-AUDIT', events = [] } = req.body;
  if (!host) return res.status(400).json({ error: 'host is required' });
  const cfg = { host, port, proto, format, facility, tag };
  let sent = 0, failed = 0;
  for (const ev of events) {
    let msg;
    if (format === 'cef')    msg = buildCefMsg(cfg, ev);
    else if (format === 'json') msg = buildJsonMsg(cfg, ev);
    else                     msg = buildSyslogMsg(cfg, ev.severity, `rule="${ev.name}" flags="${ev.flags}" src="${ev.src}" dst="${ev.dst}" svc="${ev.service}" action="${ev.action}" hits=${ev.hits}`);
    try { await sendMsgToCollector(cfg, msg); sent++; }
    catch { failed++; }
  }
  res.json({ sent, failed });
});

// ─── start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  FW Audit Dashboard running → http://localhost:${PORT}\n`);
});
