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

const express = require('express');
const axios   = require('axios');
const https   = require('https');
const path    = require('path');

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

/** Recursively flatten access-sections so every leaf is an access-rule. */
function flattenRulebase(items = []) {
  const out = [];
  for (const item of items) {
    if (item.type === 'access-section') {
      out.push(...flattenRulebase(item.rulebase || []));
    } else {
      out.push(item);   // access-rule (or anything else)
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

// ─── start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  FW Audit Dashboard running → http://localhost:${PORT}\n`);
});
