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
        { limit: LIMIT, offset, 'use-object-dictionary': true, 'details-level': 'full', ...extra },
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

// ─── start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n  FW Audit Dashboard running → http://localhost:${PORT}\n`);
});
