/**
 * BoredRoom CRM — Express API Server
 * Phase 14 — Port 3001
 */
'use strict';

const express = require('express');
const cors    = require('cors');
const path    = require('path');
const bcrypt  = require('bcryptjs');

const db                        = require('./db');
const { signToken, requireAuth } = require('./auth');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ──────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'] }));
app.use(express.json({ limit: '10mb' }));

// ── Serve frontend static files ─────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '..')));

// ── Helpers ─────────────────────────────────────────────────────────────────
function uid() { return Math.random().toString(36).slice(2) + Date.now().toString(36); }

// Convert snake_case DB rows to camelCase for frontend compatibility
function rowToContact(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    email: r.email,
    phone: r.phone,
    company: r.company_id,
    title: r.title,
    stage: r.stage,
    owner: r.owner,
    tags: safeJSON(r.tags, []),
    notes: r.notes,
    customFields: safeJSON(r.custom_fields, {}),
    leadSource: r.lead_source || '',
    territory: r.territory || '',
    referredBy: r.referred_by || '',
    createdAt: r.created_at,
    lastActivity: r.last_activity,
  };
}

function rowToDeal(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    company: r.company_id,
    contact: r.contact_id,
    value: r.value,
    stage: r.stage,
    owner: r.owner,
    closeDate: r.close_date,
    notes: r.notes,
    probability: r.probability,
    winReason: r.win_reason,
    lossReason: r.loss_reason,
    movedAt: r.moved_at,
    leadSource: r.lead_source || '',
    currency: r.currency || 'USD',
    videoCallUrl: r.video_call_url || null,
    videoCallTime: r.video_call_time || null,
    createdAt: r.created_at,
  };
}

function rowToCompany(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    industry: r.industry,
    website: r.website,
    phone: r.phone,
    address: r.address,
    city: r.city,
    territory: r.territory || '',
    notes: r.notes,
    createdAt: r.created_at,
  };
}

function rowToActivity(r) {
  if (!r) return null;
  return {
    id: r.id,
    type: r.type,
    contactId: r.contact_id,
    dealId: r.deal_id,
    note: r.note,
    date: r.date,
    createdAt: r.created_at,
  };
}

function rowToTask(r) {
  if (!r) return null;
  return {
    id:            r.id,
    title:         r.title,
    dueDate:       r.due_date,
    contactId:     r.contact_id,
    dealId:        r.deal_id,
    priority:      r.priority,
    status:        r.status,
    assignedOwner: r.assigned_owner || '',
    createdAt:     r.created_at,
  };
}

function rowToInvoice(r) {
  if (!r) return null;
  return {
    id: r.id,
    number: r.number,
    contactId: r.contact_id,
    dealId: r.deal_id,
    status: r.status,
    items: safeJSON(r.items, []),
    subtotal: r.subtotal,
    tax: r.tax,
    total: r.total,
    issueDate: r.issue_date,
    dueDate: r.due_date,
    notes: r.notes,
    createdAt: r.created_at,
  };
}

function rowToProduct(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    description: r.description,
    price: r.price,
    category: r.category,
    billing: r.billing,
    active: Boolean(r.active),
    sku: r.sku || '',
    quantityOnHand: r.quantity_on_hand != null ? r.quantity_on_hand : 0,
    reorderPoint: r.reorder_point != null ? r.reorder_point : 0,
    createdAt: r.created_at,
  };
}

function rowToSmartList(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    entity: r.entity,
    criteria: safeJSON(r.criteria, []),
    createdAt: r.created_at,
  };
}

function rowToSequence(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    steps: safeJSON(r.steps, []),
    createdAt: r.created_at,
  };
}

function rowToProposal(r) {
  if (!r) return null;
  return {
    id:            r.id,
    dealId:        r.deal_id,
    contactId:     r.contact_id,
    title:         r.title,
    content:       r.content,
    status:        r.status,
    token:         r.token,
    viewedAt:      r.viewed_at,
    createdAt:     r.created_at,
    // Phase 18 e-signature fields
    signatureData:  r.signature_data  || null,
    signatureToken: r.signature_token || null,
    signedAt:       r.signed_at       || null,
  };
}

function safeJSON(str, fallback) {
  try { return str ? JSON.parse(str) : fallback; } catch { return fallback; }
}

// ── Auth Routes ─────────────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { email, password, totpToken } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  // Phase 26: Check TOTP if enabled
  if (user.totp_enabled) {
    if (!totpToken) {
      return res.status(200).json({ requiresTOTP: true });
    }
    // Use inline TOTP verifier (crypto is available here since Phase 26 routes define these helpers)
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    function b32dec(s) {
      let bits = 0, value = 0; const out = [];
      for (const c of s.toUpperCase().replace(/=+$/, '')) {
        const idx = chars.indexOf(c); if (idx === -1) continue;
        value = (value << 5) | idx; bits += 5;
        if (bits >= 8) { bits -= 8; out.push((value >>> bits) & 0xff); }
      }
      return Buffer.from(out);
    }
    function checkTOTP(secret, token) {
      for (const w of [-1, 0, 1]) {
        const counter = Math.floor(Date.now() / 1000 / 30) + w;
        const buf = Buffer.alloc(8); buf.writeBigInt64BE(BigInt(counter));
        const hmac = require('crypto').createHmac('sha1', b32dec(secret)).update(buf).digest();
        const offset = hmac[hmac.length - 1] & 0xf;
        const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset+1] << 16 | hmac[offset+2] << 8 | hmac[offset+3]) % 1000000;
        if (code.toString().padStart(6, '0') === token.toString().trim()) return true;
      }
      return false;
    }
    if (!checkTOTP(user.totp_secret, totpToken)) {
      return res.status(401).json({ error: 'Invalid authentication code' });
    }
  }

  const token = signToken({ userId: user.id, orgId: user.org_id, role: user.role, email: user.email, name: user.name });
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

app.post('/api/auth/register', (req, res) => {
  const { email, password, name, orgName } = req.body;
  if (!email || !password || !name) return res.status(400).json({ error: 'Name, email, and password required' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const orgId = 'org_' + uid();
  const userId = 'user_' + uid();
  const hash = bcrypt.hashSync(password, 10);

  const createOrg  = db.prepare('INSERT INTO orgs (id, name) VALUES (?, ?)');
  const createUser = db.prepare('INSERT INTO users (id, org_id, email, password, name, role) VALUES (?, ?, ?, ?, ?, ?)');

  db.transaction(() => {
    createOrg.run(orgId, orgName || name + "'s Org");
    createUser.run(userId, orgId, email.toLowerCase().trim(), hash, name, 'admin');
  })();

  const token = signToken({ userId, orgId, role: 'admin', email, name });
  res.status(201).json({ token, user: { id: userId, email, name, role: 'admin' } });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, email, name, role FROM users WHERE id = ?').get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ── Bulk Import (for localStorage migration) ────────────────────────────────
app.post('/api/import', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contacts, companies, deals, activities, tasks, invoices, products, settings } = req.body;

  try {
    db.transaction(() => {
      // Companies
      if (Array.isArray(companies)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO companies (id, org_id, name, industry, website, phone, address, city, territory, notes, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        companies.forEach(c => ins.run(c.id || uid(), orgId, c.name, c.industry, c.website, c.phone, c.address, c.city, c.territory||'', c.notes, c.createdAt || Date.now()));
      }
      // Contacts
      if (Array.isArray(contacts)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO contacts (id, org_id, name, email, phone, company_id, title, stage, owner, tags, notes, custom_fields, lead_source, territory, created_at, last_activity)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        contacts.forEach(c => ins.run(c.id || uid(), orgId, c.name, c.email, c.phone, c.company, c.title, c.stage, c.owner, JSON.stringify(c.tags||[]), c.notes, JSON.stringify(c.customFields||{}), c.leadSource||'', c.territory||'', c.createdAt||Date.now(), c.lastActivity));
      }
      // Deals
      if (Array.isArray(deals)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO deals (id, org_id, name, company_id, contact_id, value, stage, owner, close_date, notes, probability, win_reason, loss_reason, lead_source, moved_at, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        deals.forEach(d => ins.run(d.id || uid(), orgId, d.name, d.company, d.contact, d.value||0, d.stage, d.owner, d.closeDate, d.notes, d.probability, d.winReason, d.lossReason, d.leadSource||'', d.movedAt, d.createdAt||Date.now()));
      }
      // Activities
      if (Array.isArray(activities)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
        activities.forEach(a => ins.run(a.id || uid(), orgId, a.type, a.contactId, a.dealId, a.note, a.date, a.createdAt||Date.now()));
      }
      // Tasks
      if (Array.isArray(tasks)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO tasks (id, org_id, title, due_date, contact_id, deal_id, priority, status, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        tasks.forEach(t => ins.run(t.id || uid(), orgId, t.title, t.dueDate, t.contactId, t.dealId, t.priority, t.status, t.createdAt||Date.now()));
      }
      // Invoices
      if (Array.isArray(invoices)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO invoices (id, org_id, number, contact_id, deal_id, status, items, subtotal, tax, total, issue_date, due_date, notes, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        invoices.forEach(inv => ins.run(inv.id || uid(), orgId, inv.number, inv.contactId, inv.dealId, inv.status, JSON.stringify(inv.items||[]), inv.subtotal||0, inv.tax||0, inv.total||0, inv.issueDate, inv.dueDate, inv.notes, inv.createdAt||Date.now()));
      }
      // Products
      if (Array.isArray(products)) {
        const ins = db.prepare(`INSERT OR REPLACE INTO products (id, org_id, name, description, price, category, billing, active, sku, quantity_on_hand, reorder_point, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        products.forEach(p => ins.run(p.id || uid(), orgId, p.name, p.description||'', p.price||0, p.category||'', p.billing||'one-time', p.active !== false ? 1 : 0, p.sku||null, p.quantityOnHand||0, p.reorderPoint||0, p.createdAt||Date.now()));
      }
      // Settings
      if (settings) {
        const ins = db.prepare('INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, ?, ?)');
        Object.entries(settings).forEach(([k, v]) => {
          if (v !== null && v !== undefined) {
            ins.run(orgId, k, typeof v === 'string' ? v : JSON.stringify(v));
          }
        });
      }
      // Phase 15: Doc Links
      const docLinks = req.body.documents || req.body.docLinks || [];
      if (Array.isArray(docLinks) && docLinks.length) {
        const ins = db.prepare(`INSERT OR REPLACE INTO doc_links (id, org_id, title, url, type, entity_type, entity_id, notes, date_added, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        docLinks.forEach(d => ins.run(d.id || uid(), orgId, d.title, d.url, d.type||'other', d.entityType||'', d.entityId||'', d.notes, d.dateAdded||new Date().toISOString().slice(0,10), d.createdAt||Date.now()));
      }
      // Phase 15: Competitor Entries
      const competitorEntries = req.body.competitorEntries || [];
      if (Array.isArray(competitorEntries) && competitorEntries.length) {
        const ins = db.prepare(`INSERT OR REPLACE INTO competitor_entries (id, org_id, deal_id, name, position, strengths, weaknesses, date_noted, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        competitorEntries.forEach(e => ins.run(e.id || uid(), orgId, e.dealId, e.name, e.position||'tied', e.strengths, e.weaknesses, e.dateNoted, e.createdAt||Date.now()));
      }
      // Phase 15: Campaigns
      const campaigns = req.body.campaigns || [];
      if (Array.isArray(campaigns) && campaigns.length) {
        const ins = db.prepare(`INSERT OR REPLACE INTO campaigns (id, org_id, name, subject, audience_type, audience_list_id, audience_contact_ids, send_date, status, sent_count, opened, replied, deals_influenced, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        campaigns.forEach(c => ins.run(c.id || uid(), orgId, c.name, c.subject, c.audienceType||'manual', c.audienceListId||'', JSON.stringify(c.audienceContactIds||[]), c.sendDate, c.status||'draft', c.sentCount||0, c.opened||0, c.replied||0, JSON.stringify(c.dealsInfluenced||[]), c.createdAt||Date.now()));
      }
      // Phase 16: Call Logs
      const callLogs = req.body.callLogs || [];
      if (Array.isArray(callLogs) && callLogs.length) {
        const ins = db.prepare(`INSERT OR REPLACE INTO call_logs (id, org_id, contact_id, type, direction, date, duration, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        callLogs.forEach(c => ins.run(c.id||uid(), orgId, c.contactId||null, c.type||'call', c.direction||'outbound', c.date, c.duration||0, c.notes, c.createdAt||Date.now()));
      }
      // Phase 16: Renewals
      const renewals = req.body.renewals || [];
      if (Array.isArray(renewals) && renewals.length) {
        const ins = db.prepare(`INSERT OR REPLACE INTO renewals (id, org_id, contact_id, company_id, service_name, start_date, renewal_date, mrr, status, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
        renewals.forEach(r => ins.run(r.id||uid(), orgId, r.contactId||null, r.companyId||null, r.serviceName, r.startDate||'', r.renewalDate||'', r.mrr||0, r.status||'Active', r.notes||'', r.createdAt||Date.now()));
      }
    })();

    res.json({ ok: true, message: 'Import successful' });
  } catch (err) {
    console.error('Import error:', err);
    res.status(500).json({ error: 'Import failed: ' + err.message });
  }
});

// ── Companies ───────────────────────────────────────────────────────────────
app.get('/api/companies', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM companies WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToCompany));
});

app.get('/api/companies/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM companies WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToCompany(row));
});

app.post('/api/companies', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const id = b.id || 'c_' + uid();
  db.prepare(`INSERT INTO companies (id, org_id, name, industry, website, phone, address, city, territory, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, orgId, b.name, b.industry, b.website, b.phone, b.address, b.city, b.territory||'', b.notes, b.createdAt || Date.now());
  auditLog(orgId, userId, userName, 'company', id, b.name, 'created');
  res.status(201).json(rowToCompany(db.prepare('SELECT * FROM companies WHERE id = ?').get(id)));
});

app.put('/api/companies/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const result = db.prepare(`UPDATE companies SET name=?, industry=?, website=?, phone=?, address=?, city=?, territory=?, notes=?
    WHERE id = ? AND org_id = ?`).run(b.name, b.industry, b.website, b.phone, b.address, b.city, b.territory||'', b.notes, req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  auditLog(orgId, userId, userName, 'company', req.params.id, b.name, 'updated');
  res.json(rowToCompany(db.prepare('SELECT * FROM companies WHERE id = ?').get(req.params.id)));
});

app.delete('/api/companies/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const before = db.prepare('SELECT name FROM companies WHERE id = ? AND org_id = ?').get(req.params.id, orgId);
  const result = db.prepare('DELETE FROM companies WHERE id = ? AND org_id = ?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  auditLog(orgId, userId, userName, 'company', req.params.id, before?.name, 'deleted');
  res.json({ ok: true });
});

// ── Contacts ────────────────────────────────────────────────────────────────
app.get('/api/contacts', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM contacts WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToContact));
});

app.get('/api/contacts/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM contacts WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToContact(row));
});

app.post('/api/contacts', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const id = b.id || 'p_' + uid();
  db.prepare(`INSERT INTO contacts (id, org_id, name, email, phone, company_id, title, stage, owner, tags, notes, custom_fields, lead_source, territory, referred_by, created_at, last_activity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, b.email, b.phone, b.company, b.title, b.stage||'Lead', b.owner,
    JSON.stringify(b.tags||[]), b.notes, JSON.stringify(b.customFields||{}),
    b.leadSource||'', b.territory||'', b.referredBy||null,
    b.createdAt||Date.now(), b.lastActivity||null
  );
  auditLog(orgId, userId, userName, 'contact', id, b.name, 'created');
  const newContact = rowToContact(db.prepare('SELECT * FROM contacts WHERE id = ?').get(id));
  // Phase 23: Fire workflow rules on contact creation
  setImmediate(() => executeWorkflowRules('contact_created', 'contact', newContact, orgId).catch(() => {}));
  // Phase 25: Slack notification
  setImmediate(() => fireSlackNotification(orgId, 'contact_created',
    `*New Contact Created*\n- Name: ${newContact.name}\n- Email: ${newContact.email || 'N/A'}\n- Stage: ${newContact.stage}`
  ).catch(() => {}));
  res.status(201).json(newContact);
});

app.put('/api/contacts/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const before = db.prepare('SELECT * FROM contacts WHERE id = ? AND org_id = ?').get(req.params.id, orgId);
  const result = db.prepare(`UPDATE contacts SET name=?, email=?, phone=?, company_id=?, title=?, stage=?, owner=?, tags=?, notes=?, custom_fields=?, lead_source=?, territory=?, referred_by=?, last_activity=?
    WHERE id = ? AND org_id = ?`).run(
    b.name, b.email, b.phone, b.company, b.title, b.stage, b.owner,
    JSON.stringify(b.tags||[]), b.notes, JSON.stringify(b.customFields||{}),
    b.leadSource||'', b.territory||'', b.referredBy||null,
    b.lastActivity||null, req.params.id, orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  if (before && before.stage !== b.stage) auditLog(orgId, userId, userName, 'contact', req.params.id, b.name, 'updated', 'stage', before.stage, b.stage);
  else auditLog(orgId, userId, userName, 'contact', req.params.id, b.name, 'updated');
  res.json(rowToContact(db.prepare('SELECT * FROM contacts WHERE id = ?').get(req.params.id)));
});

app.delete('/api/contacts/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const before = db.prepare('SELECT name FROM contacts WHERE id = ? AND org_id = ?').get(req.params.id, orgId);
  const result = db.prepare('DELETE FROM contacts WHERE id = ? AND org_id = ?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  auditLog(orgId, userId, userName, 'contact', req.params.id, before?.name, 'deleted');
  res.json({ ok: true });
});

// ── Deals ───────────────────────────────────────────────────────────────────
app.get('/api/deals', requireAuth, (req, res) => {
  const { orgId, role, userId } = req.user;
  if (role === 'rep') {
    // Reps only see deals assigned to them via owner_tag
    const userRow = db.prepare('SELECT owner_tag, name FROM users WHERE id = ?').get(userId);
    const ownerTag = userRow?.owner_tag || userRow?.name || '';
    if (ownerTag) {
      const rows = db.prepare('SELECT * FROM deals WHERE org_id = ? AND owner = ? ORDER BY created_at DESC').all(orgId, ownerTag);
      return res.json(rows.map(rowToDeal));
    }
  }
  const rows = db.prepare('SELECT * FROM deals WHERE org_id = ? ORDER BY created_at DESC').all(orgId);
  res.json(rows.map(rowToDeal));
});

app.get('/api/deals/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM deals WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToDeal(row));
});

app.post('/api/deals', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const id = b.id || 'd_' + uid();
  const stage = b.stage || 'To Contact';
  const now = Date.now();
  db.prepare(`INSERT INTO deals (id, org_id, name, company_id, contact_id, value, stage, owner, close_date, notes, probability, win_reason, loss_reason, lead_source, currency, moved_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, b.company, b.contact, b.value||0, stage, b.owner,
    b.closeDate, b.notes, b.probability, b.winReason, b.lossReason,
    b.leadSource||'', b.currency||'USD', b.movedAt||now, b.createdAt||now
  );
  auditLog(orgId, userId, userName, 'deal', id, b.name, 'created');
  // Phase 20: Log initial stage
  try {
    db.prepare('INSERT INTO deal_stage_log (id, org_id, deal_id, stage, entered_at) VALUES (?, ?, ?, ?, ?)').run('dsl_' + uid(), orgId, id, stage, now);
  } catch(e) { /* non-fatal */ }
  const newDeal = rowToDeal(db.prepare('SELECT * FROM deals WHERE id = ?').get(id));
  // Phase 23: Fire workflow rules on deal creation
  setImmediate(() => executeWorkflowRules('deal_created', 'deal', newDeal, orgId).catch(() => {}));
  // Phase 25: Slack notification
  setImmediate(() => fireSlackNotification(orgId, 'deal_created',
    `*New Deal Created*\n- Name: ${newDeal.name}\n- Value: $${(newDeal.value||0).toLocaleString()}\n- Stage: ${newDeal.stage}\n- Owner: ${newDeal.owner || 'Unassigned'}`
  ).catch(() => {}));
  res.status(201).json(newDeal);
});

app.put('/api/deals/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const before = db.prepare('SELECT * FROM deals WHERE id = ? AND org_id = ?').get(req.params.id, orgId);
  const result = db.prepare(`UPDATE deals SET name=?, company_id=?, contact_id=?, value=?, stage=?, owner=?, close_date=?, notes=?, probability=?, win_reason=?, loss_reason=?, lead_source=?, currency=?, moved_at=?
    WHERE id = ? AND org_id = ?`).run(
    b.name, b.company, b.contact, b.value||0, b.stage, b.owner,
    b.closeDate, b.notes, b.probability, b.winReason, b.lossReason,
    b.leadSource||'', b.currency||'USD', b.movedAt||Date.now(), req.params.id, orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  const updatedDeal = db.prepare('SELECT * FROM deals WHERE id = ?').get(req.params.id);
  if (before && before.stage !== b.stage) {
    auditLog(orgId, userId, userName, 'deal', req.params.id, b.name, 'updated', 'stage', before.stage, b.stage);
    // Phase 20: Log stage transition for SLA tracking
    try {
      const now = Date.now();
      db.prepare('UPDATE deal_stage_log SET exited_at=? WHERE deal_id=? AND org_id=? AND exited_at IS NULL').run(now, req.params.id, orgId);
      db.prepare('INSERT INTO deal_stage_log (id, org_id, deal_id, stage, entered_at) VALUES (?, ?, ?, ?, ?)').run('dsl_' + uid(), orgId, req.params.id, b.stage, now);
    } catch(e) { /* non-fatal */ }
    // Phase 21: Auto-create commission if deal moved to Won
    if (b.stage === 'Won') {
      try {
        if (updatedDeal) {
          const existing = db.prepare('SELECT id FROM commissions WHERE deal_id=? AND org_id=?').get(req.params.id, orgId);
          if (!existing && updatedDeal.owner) {
            const user = db.prepare("SELECT id FROM users WHERE org_id=? AND (owner_tag=? OR name=?) LIMIT 1").get(orgId, updatedDeal.owner, updatedDeal.owner);
            if (user) {
              const rateRow = db.prepare('SELECT rate_percent FROM commission_rates WHERE org_id=? AND user_id=? ORDER BY created_at DESC LIMIT 1').get(orgId, user.id);
              if (rateRow && rateRow.rate_percent) {
                const amount = (updatedDeal.value * rateRow.rate_percent) / 100;
                const cid = 'comm_' + uid();
                db.prepare('INSERT INTO commissions (id, org_id, deal_id, user_id, amount, rate_percent, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                  .run(cid, orgId, req.params.id, user.id, amount, rateRow.rate_percent, 'Pending', Date.now());
              }
            }
          }
        }
      } catch(e) { /* non-fatal */ }
    }
    // Phase 23: Fire workflow rules on stage change
    if (updatedDeal) {
      setImmediate(() => executeWorkflowRules('deal_stage_change', 'deal', rowToDeal(updatedDeal), orgId).catch(() => {}));
    }
    // Phase 25: Slack notification for deal won
    if (b.stage === 'Won' && updatedDeal) {
      setImmediate(() => fireSlackNotification(orgId, 'deal_won',
        `*Deal Won*\n- Deal: ${b.name}\n- Value: $${(b.value||0).toLocaleString()}\n- Owner: ${b.owner || 'Unassigned'}`
      ).catch(() => {}));
    }
  } else {
    auditLog(orgId, userId, userName, 'deal', req.params.id, b.name, 'updated');
  }
  res.json(rowToDeal(updatedDeal));
});

app.delete('/api/deals/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const before = db.prepare('SELECT name FROM deals WHERE id = ? AND org_id = ?').get(req.params.id, orgId);
  const result = db.prepare('DELETE FROM deals WHERE id = ? AND org_id = ?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  auditLog(orgId, userId, userName, 'deal', req.params.id, before?.name, 'deleted');
  res.json({ ok: true });
});

// ── Activities ──────────────────────────────────────────────────────────────
app.get('/api/activities', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM activities WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToActivity));
});

app.post('/api/activities', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'a_' + uid();
  db.prepare(`INSERT INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.type||'Note', b.contactId, b.dealId, b.note,
    b.date||new Date().toISOString(), b.createdAt||Date.now()
  );
  // Update contact last_activity
  if (b.contactId) {
    db.prepare('UPDATE contacts SET last_activity = ? WHERE id = ? AND org_id = ?').run(Date.now(), b.contactId, orgId);
  }
  res.status(201).json(rowToActivity(db.prepare('SELECT * FROM activities WHERE id = ?').get(id)));
});

app.put('/api/activities/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE activities SET type=?, contact_id=?, deal_id=?, note=?, date=?
    WHERE id = ? AND org_id = ?`).run(b.type, b.contactId, b.dealId, b.note, b.date, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToActivity(db.prepare('SELECT * FROM activities WHERE id = ?').get(req.params.id)));
});

app.delete('/api/activities/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM activities WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Tasks ───────────────────────────────────────────────────────────────────
app.get('/api/tasks', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM tasks WHERE org_id = ? ORDER BY due_date ASC').all(req.user.orgId);
  res.json(rows.map(rowToTask));
});

app.post('/api/tasks', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'tk_' + uid();
  db.prepare(`INSERT INTO tasks (id, org_id, title, due_date, contact_id, deal_id, priority, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.title, b.dueDate, b.contactId, b.dealId,
    b.priority||'Medium', b.status||'Open', b.createdAt||Date.now()
  );
  res.status(201).json(rowToTask(db.prepare('SELECT * FROM tasks WHERE id = ?').get(id)));
});

app.put('/api/tasks/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE tasks SET title=?, due_date=?, contact_id=?, deal_id=?, priority=?, status=?, assigned_owner=?
    WHERE id = ? AND org_id = ?`).run(b.title, b.dueDate, b.contactId, b.dealId, b.priority, b.status, b.assignedOwner||'', req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToTask(db.prepare('SELECT * FROM tasks WHERE id = ?').get(req.params.id)));
});

app.delete('/api/tasks/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM tasks WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Invoices ─────────────────────────────────────────────────────────────────
app.get('/api/invoices', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM invoices WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToInvoice));
});

app.get('/api/invoices/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM invoices WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToInvoice(row));
});

app.post('/api/invoices', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'inv_' + uid();
  db.prepare(`INSERT INTO invoices (id, org_id, number, contact_id, deal_id, status, items, subtotal, tax, total, issue_date, due_date, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.number, b.contactId, b.dealId, b.status||'Draft',
    JSON.stringify(b.items||[]), b.subtotal||0, b.tax||0, b.total||0,
    b.issueDate, b.dueDate, b.notes, b.createdAt||Date.now()
  );
  res.status(201).json(rowToInvoice(db.prepare('SELECT * FROM invoices WHERE id = ?').get(id)));
});

app.put('/api/invoices/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE invoices SET number=?, contact_id=?, deal_id=?, status=?, items=?, subtotal=?, tax=?, total=?, issue_date=?, due_date=?, notes=?
    WHERE id = ? AND org_id = ?`).run(
    b.number, b.contactId, b.dealId, b.status,
    JSON.stringify(b.items||[]), b.subtotal||0, b.tax||0, b.total||0,
    b.issueDate, b.dueDate, b.notes, req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToInvoice(db.prepare('SELECT * FROM invoices WHERE id = ?').get(req.params.id)));
});

app.delete('/api/invoices/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM invoices WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Products ─────────────────────────────────────────────────────────────────
app.get('/api/products', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM products WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToProduct));
});

app.post('/api/products', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'pr_' + uid();
  db.prepare(`INSERT INTO products (id, org_id, name, description, price, category, billing, active, sku, quantity_on_hand, reorder_point, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, b.description, b.price||0, b.category,
    b.billing||'one-time', b.active !== false ? 1 : 0,
    b.sku || null, b.quantityOnHand != null ? b.quantityOnHand : 0,
    b.reorderPoint != null ? b.reorderPoint : 0, b.createdAt||Date.now()
  );
  res.status(201).json(rowToProduct(db.prepare('SELECT * FROM products WHERE id = ?').get(id)));
});

app.put('/api/products/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE products SET name=?, description=?, price=?, category=?, billing=?, active=?, sku=?, quantity_on_hand=?, reorder_point=?
    WHERE id = ? AND org_id = ?`).run(
    b.name, b.description, b.price||0, b.category, b.billing, b.active !== false ? 1 : 0,
    b.sku || null, b.quantityOnHand != null ? b.quantityOnHand : 0,
    b.reorderPoint != null ? b.reorderPoint : 0,
    req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToProduct(db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id)));
});

// PATCH /api/products/:id/adjust-inventory
app.patch('/api/products/:id/adjust-inventory', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { adjustment, reason } = req.body; // adjustment: integer (positive=add, negative=remove)
  if (adjustment == null) return res.status(400).json({ error: 'adjustment required' });
  const product = db.prepare('SELECT * FROM products WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!product) return res.status(404).json({ error: 'Not found' });
  const newQty = Math.max(0, (product.quantity_on_hand || 0) + parseInt(adjustment));
  db.prepare('UPDATE products SET quantity_on_hand=? WHERE id=? AND org_id=?').run(newQty, req.params.id, orgId);
  res.json({ id: req.params.id, quantityOnHand: newQty, adjustment, reason: reason || '' });
});

app.delete('/api/products/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM products WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Playbooks ─────────────────────────────────────────────────────────────────
// Stored as a single settings key "playbooks"
app.get('/api/playbooks', requireAuth, (req, res) => {
  const row = db.prepare('SELECT value FROM settings WHERE org_id = ? AND key = ?').get(req.user.orgId, 'playbooks');
  res.json(safeJSON(row?.value, []));
});

app.put('/api/playbooks', requireAuth, (req, res) => {
  db.prepare('INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, ?, ?)').run(
    req.user.orgId, 'playbooks', JSON.stringify(req.body)
  );
  res.json(req.body);
});

// ── Smart Lists ──────────────────────────────────────────────────────────────
app.get('/api/smart-lists', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM smart_lists WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToSmartList));
});

app.post('/api/smart-lists', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'sl_' + uid();
  db.prepare(`INSERT INTO smart_lists (id, org_id, name, entity, criteria, created_at)
    VALUES (?, ?, ?, ?, ?, ?)`).run(id, orgId, b.name, b.entity||'contacts', JSON.stringify(b.criteria||[]), Date.now());
  res.status(201).json(rowToSmartList(db.prepare('SELECT * FROM smart_lists WHERE id = ?').get(id)));
});

app.put('/api/smart-lists/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE smart_lists SET name=?, entity=?, criteria=? WHERE id = ? AND org_id = ?`).run(
    b.name, b.entity, JSON.stringify(b.criteria||[]), req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToSmartList(db.prepare('SELECT * FROM smart_lists WHERE id = ?').get(req.params.id)));
});

app.delete('/api/smart-lists/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM smart_lists WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Sequences ──────────────────────────────────────────────────────────────
app.get('/api/sequences', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM sequences WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToSequence));
});

app.post('/api/sequences', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'seq_' + uid();
  db.prepare(`INSERT INTO sequences (id, org_id, name, steps, created_at) VALUES (?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, JSON.stringify(b.steps||[]), Date.now()
  );
  res.status(201).json(rowToSequence(db.prepare('SELECT * FROM sequences WHERE id = ?').get(id)));
});

app.put('/api/sequences/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE sequences SET name=?, steps=? WHERE id = ? AND org_id = ?`).run(
    b.name, JSON.stringify(b.steps||[]), req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToSequence(db.prepare('SELECT * FROM sequences WHERE id = ?').get(req.params.id)));
});

app.delete('/api/sequences/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM sequences WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Proposals ──────────────────────────────────────────────────────────────
app.get('/api/proposals', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM proposals WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToProposal));
});

app.post('/api/proposals', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'prop_' + uid();
  const token = b.token || uid() + uid();
  db.prepare(`INSERT INTO proposals (id, org_id, deal_id, contact_id, title, content, status, token, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.dealId, b.contactId, b.title, b.content, b.status||'Draft', token, Date.now()
  );
  res.status(201).json(rowToProposal(db.prepare('SELECT * FROM proposals WHERE id = ?').get(id)));
});

app.put('/api/proposals/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE proposals SET deal_id=?, contact_id=?, title=?, content=?, status=?
    WHERE id = ? AND org_id = ?`).run(b.dealId, b.contactId, b.title, b.content, b.status, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToProposal(db.prepare('SELECT * FROM proposals WHERE id = ?').get(req.params.id)));
});

app.delete('/api/proposals/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM proposals WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Public proposal view (no auth)
app.get('/api/proposals/view/:token', (req, res) => {
  const row = db.prepare('SELECT * FROM proposals WHERE token = ?').get(req.params.token);
  if (!row) return res.status(404).json({ error: 'Not found' });
  db.prepare('UPDATE proposals SET viewed_at = ? WHERE token = ?').run(Date.now(), req.params.token);
  res.json(rowToProposal(row));
});

// ── Settings ───────────────────────────────────────────────────────────────
app.get('/api/settings', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM settings WHERE org_id = ?').all(req.user.orgId);
  const out = {};
  rows.forEach(r => {
    try { out[r.key] = JSON.parse(r.value); } catch { out[r.key] = r.value; }
  });
  res.json(out);
});

app.put('/api/settings', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const ins = db.prepare('INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, ?, ?)');
  db.transaction(() => {
    Object.entries(req.body).forEach(([k, v]) => {
      ins.run(orgId, k, typeof v === 'string' ? v : JSON.stringify(v));
    });
  })();
  res.json({ ok: true });
});

app.put('/api/settings/:key', requireAuth, (req, res) => {
  db.prepare('INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, ?, ?)').run(
    req.user.orgId, req.params.key, JSON.stringify(req.body)
  );
  res.json({ ok: true });
});

// ── Phase 15: Doc Links ──────────────────────────────────────────────────────
function rowToDocLink(r) {
  if (!r) return null;
  return {
    id:         r.id,
    title:      r.title,
    url:        r.url,
    type:       r.type,
    entityType: r.entity_type,
    entityId:   r.entity_id,
    notes:      r.notes,
    dateAdded:  r.date_added,
    createdAt:  r.created_at,
  };
}

app.get('/api/doc-links', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM doc_links WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToDocLink));
});

app.post('/api/doc-links', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'dl_' + uid();
  db.prepare(`INSERT INTO doc_links (id, org_id, title, url, type, entity_type, entity_id, notes, date_added, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.title, b.url, b.type||'other',
    b.entityType||'', b.entityId||'', b.notes,
    b.dateAdded||new Date().toISOString().slice(0,10),
    b.createdAt||Date.now()
  );
  res.status(201).json(rowToDocLink(db.prepare('SELECT * FROM doc_links WHERE id = ?').get(id)));
});

app.put('/api/doc-links/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE doc_links SET title=?, url=?, type=?, entity_type=?, entity_id=?, notes=?, date_added=?
    WHERE id = ? AND org_id = ?`).run(
    b.title, b.url, b.type||'other', b.entityType||'', b.entityId||'',
    b.notes, b.dateAdded, req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToDocLink(db.prepare('SELECT * FROM doc_links WHERE id = ?').get(req.params.id)));
});

app.delete('/api/doc-links/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM doc_links WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Phase 15: Competitor Entries ─────────────────────────────────────────────
function rowToCompetitorEntry(r) {
  if (!r) return null;
  return {
    id:         r.id,
    dealId:     r.deal_id,
    name:       r.name,
    position:   r.position,
    strengths:  r.strengths,
    weaknesses: r.weaknesses,
    dateNoted:  r.date_noted,
    createdAt:  r.created_at,
  };
}

app.get('/api/competitor-entries', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM competitor_entries WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToCompetitorEntry));
});

app.post('/api/competitor-entries', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'ce_' + uid();
  db.prepare(`INSERT INTO competitor_entries (id, org_id, deal_id, name, position, strengths, weaknesses, date_noted, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.dealId, b.name, b.position||'tied',
    b.strengths, b.weaknesses, b.dateNoted, b.createdAt||Date.now()
  );
  res.status(201).json(rowToCompetitorEntry(db.prepare('SELECT * FROM competitor_entries WHERE id = ?').get(id)));
});

app.put('/api/competitor-entries/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE competitor_entries SET deal_id=?, name=?, position=?, strengths=?, weaknesses=?, date_noted=?
    WHERE id = ? AND org_id = ?`).run(
    b.dealId, b.name, b.position||'tied', b.strengths, b.weaknesses, b.dateNoted,
    req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToCompetitorEntry(db.prepare('SELECT * FROM competitor_entries WHERE id = ?').get(req.params.id)));
});

app.delete('/api/competitor-entries/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM competitor_entries WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Phase 15: Email Campaigns ────────────────────────────────────────────────
function rowToCampaign(r) {
  if (!r) return null;
  return {
    id:                 r.id,
    name:               r.name,
    subject:            r.subject,
    audienceType:       r.audience_type,
    audienceListId:     r.audience_list_id,
    audienceContactIds: safeJSON(r.audience_contact_ids, []),
    sendDate:           r.send_date,
    status:             r.status,
    sentCount:          r.sent_count,
    opened:             r.opened,
    replied:            r.replied,
    dealsInfluenced:    safeJSON(r.deals_influenced, []),
    createdAt:          r.created_at,
  };
}

app.get('/api/campaigns', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM campaigns WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToCampaign));
});

app.get('/api/campaigns/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM campaigns WHERE id = ? AND org_id = ?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToCampaign(row));
});

app.post('/api/campaigns', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'cam_' + uid();
  db.prepare(`INSERT INTO campaigns (id, org_id, name, subject, audience_type, audience_list_id, audience_contact_ids, send_date, status, sent_count, opened, replied, deals_influenced, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, b.subject, b.audienceType||'manual', b.audienceListId||'',
    JSON.stringify(b.audienceContactIds||[]), b.sendDate, b.status||'draft',
    b.sentCount||0, b.opened||0, b.replied||0,
    JSON.stringify(b.dealsInfluenced||[]), b.createdAt||Date.now()
  );
  res.status(201).json(rowToCampaign(db.prepare('SELECT * FROM campaigns WHERE id = ?').get(id)));
});

app.put('/api/campaigns/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE campaigns SET name=?, subject=?, audience_type=?, audience_list_id=?, audience_contact_ids=?, send_date=?, status=?, sent_count=?, opened=?, replied=?, deals_influenced=?
    WHERE id = ? AND org_id = ?`).run(
    b.name, b.subject, b.audienceType||'manual', b.audienceListId||'',
    JSON.stringify(b.audienceContactIds||[]), b.sendDate, b.status||'draft',
    b.sentCount||0, b.opened||0, b.replied||0,
    JSON.stringify(b.dealsInfluenced||[]),
    req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToCampaign(db.prepare('SELECT * FROM campaigns WHERE id = ?').get(req.params.id)));
});

app.delete('/api/campaigns/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM campaigns WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Phase 16: Audit Logging Helper ──────────────────────────────────────────
function auditLog(orgId, userId, userName, entityType, entityId, entityName, action, fieldName, oldValue, newValue) {
  try {
    db.prepare(`INSERT INTO audit_log (id, org_id, user_id, user_name, entity_type, entity_id, entity_name, action, field_name, old_value, new_value, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      'al_' + uid(), orgId, userId||'', userName||'',
      entityType, entityId||'', entityName||'',
      action, fieldName||'', oldValue!=null?String(oldValue):'', newValue!=null?String(newValue):'',
      Date.now()
    );
  } catch(e) { /* non-fatal */ }
}

// ── Phase 16: Call / SMS Logs ────────────────────────────────────────────────
function rowToCallLog(r) {
  if (!r) return null;
  return {
    id: r.id, contactId: r.contact_id, type: r.type,
    direction: r.direction, date: r.date, duration: r.duration,
    notes: r.notes, createdAt: r.created_at,
  };
}

app.get('/api/call-logs', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM call_logs WHERE org_id = ? ORDER BY date DESC').all(req.user.orgId);
  res.json(rows.map(rowToCallLog));
});

app.post('/api/call-logs', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const id = b.id || 'cl_' + uid();
  db.prepare(`INSERT INTO call_logs (id, org_id, contact_id, type, direction, date, duration, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.contactId||null, b.type||'call', b.direction||'outbound',
    b.date||new Date().toISOString(), b.duration||0, b.notes, b.createdAt||Date.now()
  );
  const contact = db.prepare('SELECT name FROM contacts WHERE id = ?').get(b.contactId);
  auditLog(orgId, userId, userName, 'call_log', id, contact?.name, 'created', 'type', '', b.type||'call');
  // Update contact last_activity
  if (b.contactId) db.prepare('UPDATE contacts SET last_activity = ? WHERE id = ? AND org_id = ?').run(Date.now(), b.contactId, orgId);
  res.status(201).json(rowToCallLog(db.prepare('SELECT * FROM call_logs WHERE id = ?').get(id)));
});

app.put('/api/call-logs/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE call_logs SET contact_id=?, type=?, direction=?, date=?, duration=?, notes=?
    WHERE id = ? AND org_id = ?`).run(b.contactId, b.type, b.direction, b.date, b.duration||0, b.notes, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToCallLog(db.prepare('SELECT * FROM call_logs WHERE id = ?').get(req.params.id)));
});

app.delete('/api/call-logs/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM call_logs WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Phase 16: Renewals ───────────────────────────────────────────────────────
function rowToRenewal(r) {
  if (!r) return null;
  return {
    id: r.id, contactId: r.contact_id, companyId: r.company_id,
    serviceName: r.service_name, startDate: r.start_date,
    renewalDate: r.renewal_date, mrr: r.mrr, status: r.status,
    notes: r.notes, createdAt: r.created_at,
  };
}

app.get('/api/renewals', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM renewals WHERE org_id = ? ORDER BY renewal_date ASC').all(req.user.orgId);
  res.json(rows.map(rowToRenewal));
});

app.post('/api/renewals', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const id = b.id || 'ren_' + uid();
  db.prepare(`INSERT INTO renewals (id, org_id, contact_id, company_id, service_name, start_date, renewal_date, mrr, status, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.contactId||null, b.companyId||null, b.serviceName,
    b.startDate||'', b.renewalDate||'', b.mrr||0, b.status||'Active',
    b.notes||'', b.createdAt||Date.now()
  );
  auditLog(orgId, userId, userName, 'renewal', id, b.serviceName, 'created');
  res.status(201).json(rowToRenewal(db.prepare('SELECT * FROM renewals WHERE id = ?').get(id)));
});

app.put('/api/renewals/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const result = db.prepare(`UPDATE renewals SET contact_id=?, company_id=?, service_name=?, start_date=?, renewal_date=?, mrr=?, status=?, notes=?
    WHERE id = ? AND org_id = ?`).run(
    b.contactId||null, b.companyId||null, b.serviceName,
    b.startDate||'', b.renewalDate||'', b.mrr||0, b.status||'Active',
    b.notes||'', req.params.id, orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  auditLog(orgId, userId, userName, 'renewal', req.params.id, b.serviceName, 'updated', 'status', '', b.status);
  res.json(rowToRenewal(db.prepare('SELECT * FROM renewals WHERE id = ?').get(req.params.id)));
});

app.delete('/api/renewals/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const before = db.prepare('SELECT service_name FROM renewals WHERE id = ? AND org_id = ?').get(req.params.id, orgId);
  const result = db.prepare('DELETE FROM renewals WHERE id = ? AND org_id = ?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  auditLog(orgId, userId, userName, 'renewal', req.params.id, before?.service_name, 'deleted');
  res.json({ ok: true });
});

// ── Phase 16: Audit Log ──────────────────────────────────────────────────────
app.get('/api/audit-log', requireAuth, (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit||'200'), 500);
  const offset = parseInt(req.query.offset||'0');
  const rows = db.prepare('SELECT * FROM audit_log WHERE org_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(req.user.orgId, limit, offset);
  const total = db.prepare('SELECT COUNT(*) as c FROM audit_log WHERE org_id = ?').get(req.user.orgId);
  res.json({ entries: rows, total: total.c });
});

// ── Phase 16: Subscriptions ──────────────────────────────────────────────────
function rowToSubscription(r) {
  if (!r) return null;
  return {
    id:           r.id,
    companyId:    r.company_id,
    planName:     r.plan_name,
    mrr:          r.mrr,
    billingCycle: r.billing_cycle,
    startDate:    r.start_date,
    renewalDate:  r.renewal_date,
    status:       r.status,
    notes:        r.notes,
    createdAt:    r.created_at,
  };
}

app.get('/api/subscriptions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToSubscription));
});

app.post('/api/subscriptions', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = b.id || 'sub_' + uid();
  db.prepare(`INSERT INTO subscriptions (id, org_id, company_id, plan_name, mrr, billing_cycle, start_date, renewal_date, status, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.companyId||null, b.planName||'', b.mrr||0,
    b.billingCycle||'monthly', b.startDate||null, b.renewalDate||null,
    b.status||'active', b.notes||'', b.createdAt||Date.now()
  );
  res.status(201).json(rowToSubscription(db.prepare('SELECT * FROM subscriptions WHERE id = ?').get(id)));
});

app.put('/api/subscriptions/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE subscriptions SET company_id=?, plan_name=?, mrr=?, billing_cycle=?, start_date=?, renewal_date=?, status=?, notes=?
    WHERE id = ? AND org_id = ?`).run(
    b.companyId||null, b.planName||'', b.mrr||0,
    b.billingCycle||'monthly', b.startDate||null, b.renewalDate||null,
    b.status||'active', b.notes||'',
    req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToSubscription(db.prepare('SELECT * FROM subscriptions WHERE id = ?').get(req.params.id)));
});

app.delete('/api/subscriptions/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM subscriptions WHERE id = ? AND org_id = ?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Phase 17: User Management ────────────────────────────────────────────────
app.get('/api/users', requireAuth, (req, res) => {
  const { orgId, role } = req.user;
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ error: 'Access denied' });
  const rows = db.prepare('SELECT id, org_id, email, name, role, owner_tag, created_at FROM users WHERE org_id = ? ORDER BY created_at ASC').all(orgId);
  res.json(rows.map(r => ({ id: r.id, email: r.email, name: r.name, role: r.role, ownerTag: r.owner_tag || '', createdAt: r.created_at })));
});

app.post('/api/users/invite', requireAuth, (req, res) => {
  const { orgId, role } = req.user;
  if (role !== 'admin') return res.status(403).json({ error: 'Admin required' });
  const { email, name, role: newRole, ownerTag, password } = req.body;
  if (!email || !name) return res.status(400).json({ error: 'Email and name required' });
  const validRoles = ['admin', 'manager', 'rep'];
  const assignedRole = validRoles.includes(newRole) ? newRole : 'rep';
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const id = 'user_' + uid();
  const tempPassword = password || 'BoredRoom2025!';
  const hash = bcrypt.hashSync(tempPassword, 10);
  db.prepare(`INSERT INTO users (id, org_id, email, password, name, role, owner_tag, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, orgId, email.toLowerCase().trim(), hash, name, assignedRole, ownerTag || '', Date.now());
  res.status(201).json({ id, email, name, role: assignedRole, ownerTag: ownerTag || '', tempPassword, message: 'User created. Share credentials manually.' });
});

app.put('/api/users/:id', requireAuth, (req, res) => {
  const { orgId, role } = req.user;
  if (role !== 'admin') return res.status(403).json({ error: 'Admin required' });
  const { name, role: newRole, ownerTag } = req.body;
  const validRoles = ['admin', 'manager', 'rep'];
  const assignedRole = validRoles.includes(newRole) ? newRole : 'rep';
  const result = db.prepare('UPDATE users SET name=?, role=?, owner_tag=? WHERE id=? AND org_id=?')
    .run(name, assignedRole, ownerTag || '', req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  const row = db.prepare('SELECT id, email, name, role, owner_tag, created_at FROM users WHERE id=?').get(req.params.id);
  res.json({ id: row.id, email: row.email, name: row.name, role: row.role, ownerTag: row.owner_tag || '', createdAt: row.created_at });
});

app.put('/api/users/:id/password', requireAuth, (req, res) => {
  const { orgId, role, userId } = req.user;
  // Admins can reset anyone; users can reset their own
  if (role !== 'admin' && userId !== req.params.id) return res.status(403).json({ error: 'Access denied' });
  const { password } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('UPDATE users SET password=? WHERE id=? AND org_id=?').run(hash, req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, (req, res) => {
  const { orgId, role, userId } = req.user;
  if (role !== 'admin') return res.status(403).json({ error: 'Admin required' });
  if (req.params.id === userId) return res.status(400).json({ error: 'Cannot delete your own account' });
  const result = db.prepare('DELETE FROM users WHERE id=? AND org_id=?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

// ── Phase 17: Saved Searches ──────────────────────────────────────────────────
app.get('/api/saved-searches', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  const rows = db.prepare('SELECT * FROM saved_searches WHERE org_id = ? ORDER BY created_at ASC').all(orgId);
  res.json(rows.map(r => ({
    id: r.id, userId: r.user_id, name: r.name, entity: r.entity,
    filters: (() => { try { return JSON.parse(r.filters); } catch { return {}; } })(),
    createdAt: r.created_at,
  })));
});

app.post('/api/saved-searches', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  const { name, entity, filters } = req.body;
  if (!name || !entity) return res.status(400).json({ error: 'Name and entity required' });
  const id = 'ss_' + uid();
  db.prepare(`INSERT INTO saved_searches (id, org_id, user_id, name, entity, filters, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, orgId, userId, name, entity, JSON.stringify(filters || {}), Date.now());
  res.status(201).json({ id, userId, name, entity, filters: filters || {}, createdAt: Date.now() });
});

app.delete('/api/saved-searches/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM saved_searches WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ── Phase 17: Data Export ─────────────────────────────────────────────────────
app.get('/api/export/contacts', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM contacts WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  const format = req.query.format || 'json';
  if (format === 'csv') {
    const headers = ['id','name','email','phone','title','stage','owner','notes','lead_source','territory','created_at'];
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="contacts.csv"');
    return res.send(csv);
  }
  res.json(rows.map(rowToContact));
});

app.get('/api/export/companies', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM companies WHERE org_id = ? ORDER BY name ASC').all(req.user.orgId);
  const format = req.query.format || 'json';
  if (format === 'csv') {
    const headers = ['id','name','industry','website','phone','address','city','territory','notes','created_at'];
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="companies.csv"');
    return res.send(csv);
  }
  res.json(rows.map(rowToCompany));
});

app.get('/api/export/deals', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM deals WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  const format = req.query.format || 'json';
  if (format === 'csv') {
    const headers = ['id','name','value','stage','owner','close_date','lead_source','notes','created_at'];
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="deals.csv"');
    return res.send(csv);
  }
  res.json(rows.map(rowToDeal));
});

app.get('/api/export/invoices', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM invoices WHERE org_id = ? ORDER BY created_at DESC').all(req.user.orgId);
  const format = req.query.format || 'json';
  if (format === 'csv') {
    const headers = ['id','number','status','total','issue_date','due_date','notes','created_at'];
    const csv = [headers.join(','), ...rows.map(r => headers.map(h => JSON.stringify(r[h] ?? '')).join(','))].join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="invoices.csv"');
    return res.send(csv);
  }
  res.json(rows.map(rowToInvoice));
});

app.get('/api/export/full', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const data = {
    exportedAt: new Date().toISOString(),
    contacts:    db.prepare('SELECT * FROM contacts WHERE org_id=?').all(orgId).map(rowToContact),
    companies:   db.prepare('SELECT * FROM companies WHERE org_id=?').all(orgId).map(rowToCompany),
    deals:       db.prepare('SELECT * FROM deals WHERE org_id=?').all(orgId).map(rowToDeal),
    activities:  db.prepare('SELECT * FROM activities WHERE org_id=?').all(orgId).map(rowToActivity),
    tasks:       db.prepare('SELECT * FROM tasks WHERE org_id=?').all(orgId).map(rowToTask),
    invoices:    db.prepare('SELECT * FROM invoices WHERE org_id=?').all(orgId).map(rowToInvoice),
    products:    db.prepare('SELECT * FROM products WHERE org_id=?').all(orgId).map(rowToProduct),
    renewals:    db.prepare('SELECT * FROM renewals WHERE org_id=?').all(orgId).map(rowToRenewal),
    campaigns:   db.prepare('SELECT * FROM campaigns WHERE org_id=?').all(orgId).map(rowToCampaign),
    settings:    (() => { const rows = db.prepare('SELECT key,value FROM settings WHERE org_id=?').all(orgId); const out = {}; rows.forEach(r => { try { out[r.key] = JSON.parse(r.value); } catch { out[r.key] = r.value; } }); return out; })(),
  };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="boredroom-backup.json"');
  res.json(data);
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 18: Pipeline Forecast AI ───────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function computeForecastScore(deal, orgId) {
  const now = Date.now();
  const MS_DAY = 86400000;

  // Factor 1: Freshness — deals stale >30 days in stage score lower
  const daysInStage = Math.max(0, (now - (deal.moved_at || deal.created_at)) / MS_DAY);
  const freshnessScore = Math.max(0, 1 - (daysInStage / 30)) * 25; // 0–25pts

  // Factor 2: Engagement — activity count in last 14 days
  const since14 = now - 14 * MS_DAY;
  const recentActivities = db.prepare(
    `SELECT COUNT(*) as c FROM activities WHERE org_id=? AND deal_id=? AND created_at>=?`
  ).get(orgId, deal.id, since14);
  const engagementScore = Math.min(25, (recentActivities.c || 0) * 5); // 0–25pts (5pt per activity, max 5)

  // Factor 3: Urgency — days until close date
  let urgencyScore = 10; // neutral
  if (deal.close_date) {
    const closeMs = new Date(deal.close_date).getTime();
    const daysToClose = (closeMs - now) / MS_DAY;
    if (daysToClose < 0) urgencyScore = 5;        // Past due — bad
    else if (daysToClose <= 7) urgencyScore = 25; // Very soon — high urgency = good pressure
    else if (daysToClose <= 30) urgencyScore = 20;
    else if (daysToClose <= 90) urgencyScore = 15;
    else urgencyScore = 8;
  }

  // Factor 4: Size fit — deal value vs avg won deal
  const wonDeals = db.prepare(`SELECT value FROM deals WHERE org_id=? AND stage='Won' AND value>0`).all(orgId);
  let sizeFitScore = 12.5; // neutral
  if (wonDeals.length > 0) {
    const avgWon = wonDeals.reduce((s, d) => s + d.value, 0) / wonDeals.length;
    const ratio  = (deal.value || 0) / avgWon;
    if (ratio >= 0.5 && ratio <= 2.0) sizeFitScore = 25;      // Good fit
    else if (ratio >= 0.3 && ratio <= 3.0) sizeFitScore = 18; // Acceptable
    else sizeFitScore = 8;                                      // Very small or very large
  }

  // Factor 5: Owner win rate
  const owner = deal.owner || '';
  let ownerScore = 12.5; // neutral if no owner
  if (owner) {
    const totalOwnerDeals = db.prepare(`SELECT COUNT(*) as c FROM deals WHERE org_id=? AND owner=? AND (stage='Won' OR stage='Lost')`).get(orgId, owner);
    const wonOwnerDeals   = db.prepare(`SELECT COUNT(*) as c FROM deals WHERE org_id=? AND owner=? AND stage='Won'`).get(orgId, owner);
    const total = totalOwnerDeals.c || 0;
    const won   = wonOwnerDeals.c   || 0;
    if (total >= 3) {
      ownerScore = (won / total) * 25;
    } else {
      ownerScore = 12.5; // not enough data
    }
  }

  // Combine: weighted sum / 100
  const raw = freshnessScore + engagementScore + urgencyScore + sizeFitScore + ownerScore;
  // Clamp to 0–100
  return Math.round(Math.min(100, Math.max(0, raw)));
}

app.get('/api/forecast/deals', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const activeStages = ['To Contact', 'Contacted', 'Proposal Sent', 'Negotiation'];
  const deals = db.prepare(`SELECT * FROM deals WHERE org_id=? AND stage NOT IN ('Won','Lost') ORDER BY value DESC`).all(orgId);
  const scored = deals.map(d => ({
    id:            d.id,
    name:          d.name,
    value:         d.value || 0,
    stage:         d.stage,
    owner:         d.owner,
    closeDate:     d.close_date,
    forecastScore: computeForecastScore(d, orgId),
  }));
  res.json(scored);
});

app.get('/api/forecast/summary', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const now = new Date();
  const deals = db.prepare(`SELECT * FROM deals WHERE org_id=? AND stage NOT IN ('Won','Lost')`).all(orgId);

  function monthKey(d) { return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0'); }

  const thisMonthKey  = monthKey(now);
  const nextMonthDate = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  const nextMonthKey  = monthKey(nextMonthDate);

  // Quarter boundary
  const qMonth = Math.floor(now.getMonth() / 3) * 3;
  const qEnd   = new Date(now.getFullYear(), qMonth + 3, 0); // last day of quarter

  let thisMonthExp = 0, nextMonthExp = 0, thisQtrExp = 0;

  deals.forEach(d => {
    const score = computeForecastScore(d, orgId) / 100;
    const exp   = (d.value || 0) * score;
    if (d.close_date) {
      const cd = d.close_date.slice(0, 7);
      if (cd === thisMonthKey)  thisMonthExp  += exp;
      if (cd === nextMonthKey)  nextMonthExp  += exp;
      if (d.close_date <= qEnd.toISOString().slice(0, 10)) thisQtrExp += exp;
    }
  });

  // Trend: last 6 months of actual closed + weighted forecast
  const months = [];
  for (let i = 5; i >= 0; i--) {
    const d   = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const key = monthKey(d);
    const endKey = monthKey(new Date(d.getFullYear(), d.getMonth() + 1, 0));
    const won = db.prepare(`SELECT SUM(value) as s FROM deals WHERE org_id=? AND stage='Won' AND close_date BETWEEN ? AND ?`)
      .get(orgId, key + '-01', endKey + '-31');
    months.push({ month: key, actual: won.s || 0 });
  }

  res.json({ thisMonthExp, nextMonthExp, thisQtrExp, trend: months });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 18: Quote/Proposal e-Signature ─────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// Request signature — generates a unique signature_token and returns the link
app.post('/api/proposals/:id/request-signature', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const prop = db.prepare('SELECT * FROM proposals WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!prop) return res.status(404).json({ error: 'Not found' });
  // Reuse existing signature_token or generate new one
  const sigToken = prop.signature_token || uid() + uid();
  db.prepare('UPDATE proposals SET signature_token=?, status=? WHERE id=? AND org_id=?')
    .run(sigToken, 'Awaiting Signature', req.params.id, orgId);
  res.json({ sigToken, sigUrl: `/sign/${sigToken}` });
});

// Public: get proposal for signing (no auth required)
app.get('/api/proposals/sign/:token', (req, res) => {
  const prop = db.prepare('SELECT * FROM proposals WHERE signature_token=?').get(req.params.token);
  if (!prop) return res.status(404).json({ error: 'Not found or invalid token' });

  // Get contact & deal info for display
  const contact = prop.contact_id ? db.prepare('SELECT name, email FROM contacts WHERE id=?').get(prop.contact_id) : null;
  const deal    = prop.deal_id    ? db.prepare('SELECT name, value FROM deals WHERE id=?').get(prop.deal_id)       : null;

  res.json({
    id:         prop.id,
    title:      prop.title,
    content:    prop.content,
    status:     prop.status,
    signedAt:   prop.signed_at,
    signatureData: prop.signature_data,
    contact:    contact ? { name: contact.name, email: contact.email } : null,
    deal:       deal    ? { name: deal.name,    value: deal.value }    : null,
  });
});

// Public: submit signature
app.post('/api/proposals/sign/:token', (req, res) => {
  const prop = db.prepare('SELECT * FROM proposals WHERE signature_token=?').get(req.params.token);
  if (!prop) return res.status(404).json({ error: 'Not found or invalid token' });
  if (prop.signed_at) return res.status(409).json({ error: 'Already signed' });

  const { signatureData } = req.body;
  if (!signatureData || !signatureData.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Invalid signature data' });
  }

  db.prepare('UPDATE proposals SET signature_data=?, signed_at=?, status=? WHERE signature_token=?')
    .run(signatureData, Date.now(), 'Signed', req.params.token);
  res.json({ ok: true, signedAt: Date.now() });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 18: Bulk Task Operations ───────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/tasks/bulk-assign', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { ids, assignedOwner, dueDate } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No task IDs provided' });

  db.transaction(() => {
    ids.forEach(id => {
      const updates = ['assigned_owner=?'];
      const values  = [assignedOwner || ''];
      if (dueDate !== undefined && dueDate !== null) {
        updates.push('due_date=?');
        values.push(dueDate);
      }
      values.push(id, orgId);
      db.prepare(`UPDATE tasks SET ${updates.join(',')} WHERE id=? AND org_id=?`).run(...values);
    });
  })();
  res.json({ ok: true, updated: ids.length });
});

app.post('/api/tasks/bulk-complete', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { ids } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No task IDs provided' });
  db.transaction(() => {
    ids.forEach(id => db.prepare(`UPDATE tasks SET status='Done' WHERE id=? AND org_id=?`).run(id, orgId));
  })();
  res.json({ ok: true, updated: ids.length });
});

app.post('/api/tasks/bulk-delete', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { ids } = req.body;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No task IDs provided' });
  db.transaction(() => {
    ids.forEach(id => db.prepare(`DELETE FROM tasks WHERE id=? AND org_id=?`).run(id, orgId));
  })();
  res.json({ ok: true, deleted: ids.length });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 18: Email Log ───────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToEmailLog(r) {
  if (!r) return null;
  return {
    id:        r.id,
    contactId: r.contact_id,
    subject:   r.subject,
    body:      r.body,
    direction: r.direction,
    date:      r.date,
    createdAt: r.created_at,
  };
}

app.get('/api/email-logs', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contactId = req.query.contactId;
  const rows = contactId
    ? db.prepare('SELECT * FROM email_logs WHERE org_id=? AND contact_id=? ORDER BY date DESC').all(orgId, contactId)
    : db.prepare('SELECT * FROM email_logs WHERE org_id=? ORDER BY date DESC').all(orgId);
  res.json(rows.map(rowToEmailLog));
});

app.post('/api/email-logs', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  if (!b.subject) return res.status(400).json({ error: 'Subject required' });
  const id = 'el_' + uid();
  db.prepare(`INSERT INTO email_logs (id, org_id, contact_id, subject, body, direction, date, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.contactId || null, b.subject, b.body || '',
    b.direction || 'outbound', b.date || new Date().toISOString().slice(0, 10), Date.now()
  );
  // Update contact last_activity
  if (b.contactId) db.prepare('UPDATE contacts SET last_activity=? WHERE id=? AND org_id=?').run(Date.now(), b.contactId, orgId);
  auditLog(orgId, userId, userName, 'email_log', id, b.subject, 'created');
  res.status(201).json(rowToEmailLog(db.prepare('SELECT * FROM email_logs WHERE id=?').get(id)));
});

app.put('/api/email-logs/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE email_logs SET contact_id=?, subject=?, body=?, direction=?, date=?
    WHERE id=? AND org_id=?`).run(b.contactId || null, b.subject, b.body || '', b.direction || 'outbound', b.date, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToEmailLog(db.prepare('SELECT * FROM email_logs WHERE id=?').get(req.params.id)));
});

app.delete('/api/email-logs/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM email_logs WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Email log summary for Reports
app.get('/api/email-logs/summary', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const total    = db.prepare('SELECT COUNT(*) as c FROM email_logs WHERE org_id=?').get(orgId);
  const inbound  = db.prepare(`SELECT COUNT(*) as c FROM email_logs WHERE org_id=? AND direction='inbound'`).get(orgId);
  const outbound = db.prepare(`SELECT COUNT(*) as c FROM email_logs WHERE org_id=? AND direction='outbound'`).get(orgId);

  // Last 30 days by direction
  const since30 = Date.now() - 30 * 86400000;
  const recent  = db.prepare(`SELECT direction, COUNT(*) as c FROM email_logs WHERE org_id=? AND created_at>=? GROUP BY direction`).all(orgId, since30);

  res.json({
    total:    total.c,
    inbound:  inbound.c,
    outbound: outbound.c,
    recent,
  });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 18: Contact Merge (server-side) ────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/contacts/merge', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { winnerId, loserId, fields } = req.body;
  if (!winnerId || !loserId) return res.status(400).json({ error: 'winnerId and loserId required' });
  if (winnerId === loserId)  return res.status(400).json({ error: 'Cannot merge a contact with itself' });

  const winner = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(winnerId, orgId);
  const loser  = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(loserId,  orgId);
  if (!winner) return res.status(404).json({ error: 'Winner contact not found' });
  if (!loser)  return res.status(404).json({ error: 'Loser contact not found' });

  // Determine which fields to keep (default: winner)
  const f = fields || {};
  const pick = (field, winnerVal, loserVal) => {
    return f[field] === 'loser' ? loserVal : winnerVal;
  };

  try {
    db.transaction(() => {
      // Merge tags
      const mergedTags = [...new Set([...safeJSON(winner.tags, []), ...safeJSON(loser.tags, [])])];

      // Update winner with chosen fields
      db.prepare(`UPDATE contacts SET
        name=?, email=?, phone=?, title=?, company_id=?, owner=?, stage=?, notes=?, tags=?,
        territory=?, lead_source=?
        WHERE id=? AND org_id=?`).run(
        pick('name',      winner.name,       loser.name),
        pick('email',     winner.email,      loser.email),
        pick('phone',     winner.phone,      loser.phone),
        pick('title',     winner.title,      loser.title),
        pick('company_id',winner.company_id, loser.company_id),
        pick('owner',     winner.owner,      loser.owner),
        pick('stage',     winner.stage,      loser.stage),
        pick('notes',     winner.notes,      loser.notes),
        JSON.stringify(mergedTags),
        pick('territory', winner.territory,  loser.territory),
        pick('lead_source',winner.lead_source, loser.lead_source),
        winnerId, orgId
      );

      // Reassign all related data from loser to winner
      db.prepare('UPDATE activities  SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE deals       SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE tasks       SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE call_logs   SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE email_logs  SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE invoices    SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE proposals   SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);
      db.prepare('UPDATE renewals    SET contact_id=? WHERE contact_id=? AND org_id=?').run(winnerId, loserId, orgId);

      // Delete loser
      db.prepare('DELETE FROM contacts WHERE id=? AND org_id=?').run(loserId, orgId);
    })();

    auditLog(orgId, userId, userName, 'contact', winnerId, winner.name, 'merged', 'loserId', loserId, winner.name);
    res.json({ ok: true, winnerId, loserName: loser.name });
  } catch (err) {
    console.error('Merge error:', err);
    res.status(500).json({ error: 'Merge failed: ' + err.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 19: Webhooks / Integration Hub ─────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

const https = require('https');
const http  = require('http');

// Fire outbound webhooks for a given event (non-blocking)
function fireWebhooks(orgId, event, entityType, entityId, data) {
  try {
    const hooks = db.prepare(`SELECT * FROM webhooks WHERE org_id=? AND active=1`).all(orgId);
    hooks.forEach(hook => {
      const events = (() => { try { return JSON.parse(hook.events); } catch { return []; } })();
      if (!events.includes(event)) return;
      const payload = JSON.stringify({ event, entityType, entityId, data, timestamp: Date.now() });
      try {
        const u = new URL(hook.url);
        const lib = u.protocol === 'https:' ? https : http;
        const req = lib.request({
          hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
          path: u.pathname + u.search, method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-BoredRoom-Event': event },
        }, () => {});
        req.on('error', () => {});
        req.write(payload);
        req.end();
      } catch(e) { /* invalid URL — skip */ }
    });
  } catch(e) { /* non-fatal */ }
}

// Create an in-app notification
function createNotification(orgId, userId, type, message, entityType, entityId) {
  try {
    db.prepare(`INSERT INTO notifications (id, org_id, user_id, type, message, entity_type, entity_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      'notif_' + uid(), orgId, userId || '', type, message,
      entityType || '', entityId || '', Date.now()
    );
  } catch(e) { /* non-fatal */ }
}

// Broadcast notification to all org users
function broadcastNotification(orgId, type, message, entityType, entityId) {
  try {
    const users = db.prepare('SELECT id FROM users WHERE org_id=?').all(orgId);
    users.forEach(u => createNotification(orgId, u.id, type, message, entityType, entityId));
  } catch(e) { /* non-fatal */ }
}

function rowToWebhook(r) {
  if (!r) return null;
  return {
    id:        r.id,
    url:       r.url,
    events:    (() => { try { return JSON.parse(r.events); } catch { return []; } })(),
    active:    Boolean(r.active),
    createdAt: r.created_at,
  };
}

app.get('/api/webhooks', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM webhooks WHERE org_id=? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToWebhook));
});

app.post('/api/webhooks', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { url, events } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });
  const id = 'wh_' + uid();
  db.prepare(`INSERT INTO webhooks (id, org_id, url, events, active, created_at) VALUES (?, ?, ?, ?, 1, ?)`).run(
    id, orgId, url, JSON.stringify(events || []), Date.now()
  );
  res.status(201).json(rowToWebhook(db.prepare('SELECT * FROM webhooks WHERE id=?').get(id)));
});

app.put('/api/webhooks/:id', requireAuth, (req, res) => {
  const { url, events, active } = req.body;
  const result = db.prepare('UPDATE webhooks SET url=?, events=?, active=? WHERE id=? AND org_id=?')
    .run(url, JSON.stringify(events || []), active !== false ? 1 : 0, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToWebhook(db.prepare('SELECT * FROM webhooks WHERE id=?').get(req.params.id)));
});

app.delete('/api/webhooks/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM webhooks WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Test webhook — send sample payload, return response status
app.post('/api/webhooks/:id/test', requireAuth, (req, res) => {
  const hook = db.prepare('SELECT * FROM webhooks WHERE id=? AND org_id=?').get(req.params.id, req.user.orgId);
  if (!hook) return res.status(404).json({ error: 'Not found' });
  const payload = JSON.stringify({
    event: 'webhook.test',
    entityType: 'webhook',
    entityId: hook.id,
    data: { message: 'This is a test payload from BoredRoom CRM', webhookId: hook.id },
    timestamp: Date.now(),
  });
  try {
    const u = new URL(hook.url);
    const lib = u.protocol === 'https:' ? https : http;
    const options = {
      hostname: u.hostname, port: u.port || (u.protocol === 'https:' ? 443 : 80),
      path: u.pathname + u.search, method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'X-BoredRoom-Event': 'webhook.test' },
      timeout: 8000,
    };
    const outReq = lib.request(options, (inRes) => {
      let body = '';
      inRes.on('data', c => { body += c; });
      inRes.on('end', () => {
        res.json({ status: inRes.statusCode, body: body.slice(0, 500) });
      });
    });
    outReq.on('error', (err) => res.json({ status: 0, error: err.message }));
    outReq.on('timeout', () => { outReq.destroy(); res.json({ status: 0, error: 'Request timed out' }); });
    outReq.write(payload);
    outReq.end();
  } catch(e) {
    res.json({ status: 0, error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 19: Custom Fields Builder ──────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToCustomFieldDef(r) {
  if (!r) return null;
  return {
    id:         r.id,
    name:       r.name,
    type:       r.type,
    entityType: r.entity_type,
    options:    (() => { try { return JSON.parse(r.options); } catch { return []; } })(),
    required:   Boolean(r.required),
    sortOrder:  r.sort_order,
    createdAt:  r.created_at,
  };
}

app.get('/api/custom-field-defs', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM custom_field_defs WHERE org_id=? ORDER BY sort_order ASC, created_at ASC').all(req.user.orgId);
  res.json(rows.map(rowToCustomFieldDef));
});

app.post('/api/custom-field-defs', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  if (!b.name) return res.status(400).json({ error: 'Name required' });
  const id = 'cfd_' + uid();
  const maxOrder = db.prepare('SELECT MAX(sort_order) as m FROM custom_field_defs WHERE org_id=? AND entity_type=?').get(orgId, b.entityType || 'contact');
  const sortOrder = (maxOrder?.m || 0) + 1;
  db.prepare(`INSERT INTO custom_field_defs (id, org_id, name, type, entity_type, options, required, sort_order, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, b.type || 'text', b.entityType || 'contact',
    JSON.stringify(b.options || []), b.required ? 1 : 0, sortOrder, Date.now()
  );
  res.status(201).json(rowToCustomFieldDef(db.prepare('SELECT * FROM custom_field_defs WHERE id=?').get(id)));
});

app.put('/api/custom-field-defs/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare('UPDATE custom_field_defs SET name=?, type=?, entity_type=?, options=?, required=? WHERE id=? AND org_id=?')
    .run(b.name, b.type || 'text', b.entityType || 'contact', JSON.stringify(b.options || []), b.required ? 1 : 0, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToCustomFieldDef(db.prepare('SELECT * FROM custom_field_defs WHERE id=?').get(req.params.id)));
});

app.delete('/api/custom-field-defs/:id', requireAuth, (req, res) => {
  // Also delete values
  db.prepare('DELETE FROM custom_field_values WHERE field_id=? AND org_id=?').run(req.params.id, req.user.orgId);
  const result = db.prepare('DELETE FROM custom_field_defs WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Custom field values
app.get('/api/custom-field-values', requireAuth, (req, res) => {
  const { entityType, entityId } = req.query;
  if (!entityType || !entityId) return res.status(400).json({ error: 'entityType and entityId required' });
  const rows = db.prepare('SELECT * FROM custom_field_values WHERE org_id=? AND entity_type=? AND entity_id=?')
    .all(req.user.orgId, entityType, entityId);
  res.json(rows.map(r => ({ id: r.id, fieldId: r.field_id, entityType: r.entity_type, entityId: r.entity_id, value: r.value })));
});

app.post('/api/custom-field-values', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { entityType, entityId, fieldId, value } = req.body;
  if (!entityType || !entityId || !fieldId) return res.status(400).json({ error: 'entityType, entityId, fieldId required' });
  const id = 'cfv_' + uid();
  db.prepare(`INSERT OR REPLACE INTO custom_field_values (id, org_id, entity_type, entity_id, field_id, value, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(id, orgId, entityType, entityId, fieldId, value || '', Date.now());
  res.status(201).json({ id, fieldId, entityType, entityId, value: value || '' });
});

// Bulk upsert custom field values for an entity
app.put('/api/custom-field-values/:entityType/:entityId', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { entityType, entityId } = req.params;
  const values = req.body; // { fieldId: value, ... }
  if (typeof values !== 'object') return res.status(400).json({ error: 'Body must be object of fieldId:value' });
  const stmt = db.prepare(`INSERT OR REPLACE INTO custom_field_values (id, org_id, entity_type, entity_id, field_id, value, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`);
  db.transaction(() => {
    Object.entries(values).forEach(([fieldId, value]) => {
      stmt.run('cfv_' + uid(), orgId, entityType, entityId, fieldId, String(value ?? ''), Date.now());
    });
  })();
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 19: In-App Notifications Center ────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/notifications', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  const limit = Math.min(parseInt(req.query.limit || '50'), 200);
  const rows = db.prepare(`SELECT * FROM notifications WHERE org_id=? AND (user_id='' OR user_id=?) ORDER BY created_at DESC LIMIT ?`)
    .all(orgId, userId, limit);
  res.json(rows.map(r => ({
    id: r.id, type: r.type, message: r.message,
    entityType: r.entity_type, entityId: r.entity_id,
    read: Boolean(r.read), createdAt: r.created_at,
  })));
});

app.get('/api/notifications/unread-count', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  const row = db.prepare(`SELECT COUNT(*) as c FROM notifications WHERE org_id=? AND (user_id='' OR user_id=?) AND read=0`)
    .get(orgId, userId);
  res.json({ count: row.c });
});

app.patch('/api/notifications/:id/read', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  db.prepare(`UPDATE notifications SET read=1 WHERE id=? AND org_id=? AND (user_id='' OR user_id=?)`)
    .run(req.params.id, orgId, userId);
  res.json({ ok: true });
});

app.post('/api/notifications/mark-all-read', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  db.prepare(`UPDATE notifications SET read=1 WHERE org_id=? AND (user_id='' OR user_id=?)`)
    .run(orgId, userId);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 19: Goals & Quotas per Rep ─────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/user-goals', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare('SELECT * FROM user_goals WHERE org_id=? ORDER BY year DESC, period DESC').all(orgId);
  res.json(rows.map(r => ({
    id: r.id, userId: r.user_id, periodType: r.period_type,
    year: r.year, period: r.period, goalAmount: r.goal_amount, createdAt: r.created_at,
  })));
});

app.put('/api/user-goals', requireAuth, (req, res) => {
  const { orgId, role } = req.user;
  if (role !== 'admin' && role !== 'manager') return res.status(403).json({ error: 'Admin or Manager required' });
  const goals = req.body; // Array of { userId, periodType, year, period, goalAmount }
  if (!Array.isArray(goals)) return res.status(400).json({ error: 'Expected array' });
  db.transaction(() => {
    goals.forEach(g => {
      const id = 'ug_' + uid();
      db.prepare(`INSERT OR REPLACE INTO user_goals (id, org_id, user_id, period_type, year, period, goal_amount, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
        id, orgId, g.userId, g.periodType || 'monthly', g.year, g.period, g.goalAmount || 0, Date.now()
      );
    });
  })();
  res.json({ ok: true });
});

// Goals attainment summary — won deals vs goal for current period
app.get('/api/user-goals/attainment', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;
  const quarter = Math.ceil(month / 3);

  const users = db.prepare('SELECT id, name FROM users WHERE org_id=?').all(orgId);
  const results = users.map(u => {
    // Monthly goal
    const monthGoalRow = db.prepare(`SELECT goal_amount FROM user_goals WHERE org_id=? AND user_id=? AND period_type='monthly' AND year=? AND period=?`)
      .get(orgId, u.id, year, month);
    // Quarterly goal
    const qGoalRow = db.prepare(`SELECT goal_amount FROM user_goals WHERE org_id=? AND user_id=? AND period_type='quarterly' AND year=? AND period=?`)
      .get(orgId, u.id, year, quarter);

    // Won deals this month
    const monthStart = `${year}-${String(month).padStart(2,'0')}-01`;
    const monthEnd   = `${year}-${String(month).padStart(2,'0')}-31`;
    const wonMonth = db.prepare(`SELECT COALESCE(SUM(value),0) as s FROM deals WHERE org_id=? AND stage='Won' AND close_date BETWEEN ? AND ?`)
      .get(orgId, monthStart, monthEnd);

    // Won deals this quarter
    const qMonthStart = (quarter - 1) * 3 + 1;
    const qMonthEnd   = quarter * 3;
    const qStart = `${year}-${String(qMonthStart).padStart(2,'0')}-01`;
    const qEnd   = `${year}-${String(qMonthEnd).padStart(2,'0')}-31`;
    const wonQ = db.prepare(`SELECT COALESCE(SUM(value),0) as s FROM deals WHERE org_id=? AND stage='Won' AND close_date BETWEEN ? AND ?`)
      .get(orgId, qStart, qEnd);

    return {
      userId: u.id, userName: u.name,
      monthlyGoal: monthGoalRow?.goal_amount || 0,
      quarterlyGoal: qGoalRow?.goal_amount || 0,
      wonThisMonth: wonMonth.s || 0,
      wonThisQuarter: wonQ.s || 0,
    };
  });

  res.json(results);
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 19: Knowledge Base / Notes Wiki ────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToKBNote(r) {
  if (!r) return null;
  return {
    id:        r.id,
    title:     r.title,
    body:      r.body || '',
    tags:      (() => { try { return JSON.parse(r.tags); } catch { return []; } })(),
    pinned:    Boolean(r.pinned),
    companyId: r.company_id || null,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
  };
}

app.get('/api/kb-notes', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { q, companyId, tag } = req.query;
  let sql = 'SELECT * FROM kb_notes WHERE org_id=?';
  const params = [orgId];
  if (companyId) { sql += ' AND company_id=?'; params.push(companyId); }
  if (q) { sql += ' AND (title LIKE ? OR body LIKE ?)'; params.push('%'+q+'%', '%'+q+'%'); }
  sql += ' ORDER BY pinned DESC, updated_at DESC';
  let rows = db.prepare(sql).all(...params);
  if (tag) rows = rows.filter(r => {
    try { return JSON.parse(r.tags).includes(tag); } catch { return false; }
  });
  res.json(rows.map(rowToKBNote));
});

app.get('/api/kb-notes/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM kb_notes WHERE id=? AND org_id=?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToKBNote(row));
});

app.post('/api/kb-notes', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  if (!b.title) return res.status(400).json({ error: 'Title required' });
  const id = 'kbn_' + uid();
  const now = Date.now();
  db.prepare(`INSERT INTO kb_notes (id, org_id, title, body, tags, pinned, company_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.title, b.body || '', JSON.stringify(b.tags || []),
    b.pinned ? 1 : 0, b.companyId || null, now, now
  );
  res.status(201).json(rowToKBNote(db.prepare('SELECT * FROM kb_notes WHERE id=?').get(id)));
});

app.put('/api/kb-notes/:id', requireAuth, (req, res) => {
  const b = req.body;
  const now = Date.now();
  const result = db.prepare(`UPDATE kb_notes SET title=?, body=?, tags=?, pinned=?, company_id=?, updated_at=?
    WHERE id=? AND org_id=?`).run(
    b.title, b.body || '', JSON.stringify(b.tags || []),
    b.pinned ? 1 : 0, b.companyId || null, now,
    req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToKBNote(db.prepare('SELECT * FROM kb_notes WHERE id=?').get(req.params.id)));
});

app.delete('/api/kb-notes/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM kb_notes WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 19: Wire webhooks + notifications into existing event handlers ──
// ══════════════════════════════════════════════════════════════════════════

// Patch deals POST to fire deal.created webhook + notification
// Note: app._router.stack is accessed lazily; use dedicated event endpoints instead
const _origDealPost = null; // route-patch removed; use /api/events/* endpoints below
// We use a middleware that intercepts after the route handler by patching via re-registration.
// Actually, simpler: add hooks inline via a separate route patch applied on app startup.
// The cleanest way for this architecture: use a response-intercepting middleware per route.
// We'll add a dedicated event-firing endpoint that the frontend calls after important actions.

// Simplified event endpoints for frontend to notify server of events (fire webhooks + notifications)
app.post('/api/events/deal-created', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  const { dealId } = req.body;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(dealId, orgId);
  if (!deal) return res.json({ ok: true });
  fireWebhooks(orgId, 'deal.created', 'deal', dealId, { name: deal.name, value: deal.value, stage: deal.stage });
  broadcastNotification(orgId, 'deal_created', `New deal created: ${deal.name}`, 'deal', dealId);
  res.json({ ok: true });
});

app.post('/api/events/deal-won', requireAuth, (req, res) => {
  const { orgId, userId } = req.user;
  const { dealId } = req.body;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(dealId, orgId);
  if (!deal) return res.json({ ok: true });
  fireWebhooks(orgId, 'deal.won', 'deal', dealId, { name: deal.name, value: deal.value });
  broadcastNotification(orgId, 'deal_won', `Deal won: ${deal.name} ($${(deal.value||0).toLocaleString()})`, 'deal', dealId);
  res.json({ ok: true });
});

app.post('/api/events/deal-stage-changed', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId, fromStage, toStage } = req.body;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(dealId, orgId);
  if (!deal) return res.json({ ok: true });
  broadcastNotification(orgId, 'deal_stage', `Deal "${deal.name}" moved to ${toStage}`, 'deal', dealId);
  res.json({ ok: true });
});

app.post('/api/events/contact-created', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contactId } = req.body;
  const contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(contactId, orgId);
  if (!contact) return res.json({ ok: true });
  fireWebhooks(orgId, 'contact.created', 'contact', contactId, { name: contact.name, email: contact.email });
  res.json({ ok: true });
});

app.post('/api/events/task-assigned', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { taskId, assignedUserId } = req.body;
  const task = db.prepare('SELECT * FROM tasks WHERE id=? AND org_id=?').get(taskId, orgId);
  if (!task) return res.json({ ok: true });
  createNotification(orgId, assignedUserId || '', 'task_assigned', `Task assigned to you: ${task.title}`, 'task', taskId);
  res.json({ ok: true });
});

app.post('/api/events/contact-merged', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { winnerId, loserName } = req.body;
  broadcastNotification(orgId, 'contact_merged', `Contact merged: ${loserName} merged into primary`, 'contact', winnerId);
  res.json({ ok: true });
});

// Check for overdue items and generate notifications
app.post('/api/events/check-overdue', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const todayStr = new Date().toISOString().slice(0, 10);

  // Overdue tasks
  const overdueTasks = db.prepare(`SELECT * FROM tasks WHERE org_id=? AND status='Open' AND due_date < ? AND due_date IS NOT NULL`).all(orgId, todayStr);
  overdueTasks.forEach(t => {
    const exists = db.prepare(`SELECT id FROM notifications WHERE org_id=? AND entity_id=? AND type='task_overdue' AND created_at > ?`)
      .get(orgId, t.id, Date.now() - 24 * 3600 * 1000);
    if (!exists) {
      fireWebhooks(orgId, 'task.overdue', 'task', t.id, { title: t.title, dueDate: t.due_date });
      broadcastNotification(orgId, 'task_overdue', `Overdue task: ${t.title}`, 'task', t.id);
    }
  });

  // Overdue invoices
  const overdueInvoices = db.prepare(`SELECT * FROM invoices WHERE org_id=? AND status IN ('Sent','Overdue') AND due_date < ?`).all(orgId, todayStr);
  overdueInvoices.forEach(inv => {
    const exists = db.prepare(`SELECT id FROM notifications WHERE org_id=? AND entity_id=? AND type='invoice_overdue' AND created_at > ?`)
      .get(orgId, inv.id, Date.now() - 24 * 3600 * 1000);
    if (!exists) {
      fireWebhooks(orgId, 'invoice.overdue', 'invoice', inv.id, { number: inv.number, total: inv.total });
      broadcastNotification(orgId, 'invoice_overdue', `Overdue invoice: ${inv.number} ($${(inv.total||0).toFixed(2)})`, 'invoice', inv.id);
    }
  });

  // Renewals due within 3 days
  const in3Days = new Date(Date.now() + 3 * 86400000).toISOString().slice(0, 10);
  const dueRenewals = db.prepare(`SELECT * FROM renewals WHERE org_id=? AND status='Active' AND renewal_date BETWEEN ? AND ?`).all(orgId, todayStr, in3Days);
  dueRenewals.forEach(r => {
    const exists = db.prepare(`SELECT id FROM notifications WHERE org_id=? AND entity_id=? AND type='renewal_due' AND created_at > ?`)
      .get(orgId, r.id, Date.now() - 24 * 3600 * 1000);
    if (!exists) {
      broadcastNotification(orgId, 'renewal_due', `Renewal due soon: ${r.service_name} on ${r.renewal_date}`, 'renewal', r.id);
    }
  });

  res.json({ ok: true, overdueTasks: overdueTasks.length, overdueInvoices: overdueInvoices.length, dueRenewals: dueRenewals.length });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20.1: Time Tracking ─────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToTimeEntry(r) {
  if (!r) return null;
  return {
    id: r.id,
    dealId: r.deal_id || null,
    contactId: r.contact_id || null,
    userId: r.user_id || null,
    description: r.description || '',
    hours: r.hours || 0,
    rate: r.rate || 0,
    billable: Boolean(r.billable),
    date: r.date || '',
    invoiceId: r.invoice_id || null,
    createdAt: r.created_at,
  };
}

app.get('/api/time-entries', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId, contactId, billable, userId } = req.query;
  let sql = 'SELECT * FROM time_entries WHERE org_id=?';
  const params = [orgId];
  if (dealId)    { sql += ' AND deal_id=?';    params.push(dealId); }
  if (contactId) { sql += ' AND contact_id=?'; params.push(contactId); }
  if (userId)    { sql += ' AND user_id=?';    params.push(userId); }
  if (billable === 'true')  { sql += ' AND billable=1'; }
  if (billable === 'false') { sql += ' AND billable=0'; }
  sql += ' ORDER BY date DESC, created_at DESC';
  res.json(db.prepare(sql).all(...params).map(rowToTimeEntry));
});

app.post('/api/time-entries', requireAuth, (req, res) => {
  const { orgId, userId: authUserId } = req.user;
  const b = req.body;
  const id = 'te_' + uid();
  db.prepare(`INSERT INTO time_entries (id, org_id, deal_id, contact_id, user_id, description, hours, rate, billable, date, invoice_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.dealId || null, b.contactId || null, b.userId || authUserId,
    b.description || '', b.hours || 0, b.rate || 0,
    b.billable !== false ? 1 : 0, b.date || new Date().toISOString().slice(0, 10),
    b.invoiceId || null, Date.now()
  );
  res.status(201).json(rowToTimeEntry(db.prepare('SELECT * FROM time_entries WHERE id=?').get(id)));
});

app.put('/api/time-entries/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE time_entries SET deal_id=?, contact_id=?, user_id=?, description=?, hours=?, rate=?, billable=?, date=?, invoice_id=?
    WHERE id=? AND org_id=?`).run(
    b.dealId || null, b.contactId || null, b.userId || null,
    b.description || '', b.hours || 0, b.rate || 0,
    b.billable !== false ? 1 : 0, b.date, b.invoiceId || null,
    req.params.id, req.user.orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToTimeEntry(db.prepare('SELECT * FROM time_entries WHERE id=?').get(req.params.id)));
});

app.delete('/api/time-entries/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM time_entries WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Mark time entries as invoiced (set invoice_id)
app.post('/api/time-entries/mark-invoiced', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { entryIds, invoiceId } = req.body;
  if (!Array.isArray(entryIds) || !invoiceId) return res.status(400).json({ error: 'entryIds and invoiceId required' });
  const stmt = db.prepare('UPDATE time_entries SET invoice_id=? WHERE id=? AND org_id=?');
  db.transaction(() => {
    entryIds.forEach(id => stmt.run(invoiceId, id, orgId));
  })();
  res.json({ ok: true });
});

// Time totals for a deal
app.get('/api/time-entries/totals', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId, contactId } = req.query;
  let sql = 'SELECT COALESCE(SUM(hours),0) as totalHours, COALESCE(SUM(CASE WHEN billable=1 THEN hours*rate ELSE 0 END),0) as billableAmount FROM time_entries WHERE org_id=?';
  const params = [orgId];
  if (dealId) { sql += ' AND deal_id=?'; params.push(dealId); }
  if (contactId) { sql += ' AND contact_id=?'; params.push(contactId); }
  const row = db.prepare(sql).get(...params);
  res.json({ totalHours: row.totalHours, billableAmount: row.billableAmount });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20.2: Product Bundles ───────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToBundle(r) {
  if (!r) return null;
  const items = db.prepare(`SELECT bi.*, p.name as product_name, p.price as product_price FROM bundle_items bi
    JOIN products p ON bi.product_id = p.id WHERE bi.bundle_id=? ORDER BY bi.rowid`).all(r.id);
  return {
    id: r.id,
    name: r.name,
    description: r.description || '',
    items: items.map(i => ({
      id: i.id, productId: i.product_id, productName: i.product_name,
      productPrice: i.product_price, quantity: i.quantity
    })),
    createdAt: r.created_at,
  };
}

app.get('/api/product-bundles', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM product_bundles WHERE org_id=? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToBundle));
});

app.get('/api/product-bundles/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM product_bundles WHERE id=? AND org_id=?').get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToBundle(row));
});

app.post('/api/product-bundles', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = 'pb_' + uid();
  db.prepare('INSERT INTO product_bundles (id, org_id, name, description, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, b.name, b.description || '', Date.now());
  // Insert items
  if (Array.isArray(b.items)) {
    const stmt = db.prepare('INSERT INTO bundle_items (id, org_id, bundle_id, product_id, quantity) VALUES (?, ?, ?, ?, ?)');
    b.items.forEach(item => stmt.run('bi_' + uid(), orgId, id, item.productId, item.quantity || 1));
  }
  res.status(201).json(rowToBundle(db.prepare('SELECT * FROM product_bundles WHERE id=?').get(id)));
});

app.put('/api/product-bundles/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const result = db.prepare('UPDATE product_bundles SET name=?, description=? WHERE id=? AND org_id=?')
    .run(b.name, b.description || '', req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  // Replace items
  db.prepare('DELETE FROM bundle_items WHERE bundle_id=? AND org_id=?').run(req.params.id, orgId);
  if (Array.isArray(b.items)) {
    const stmt = db.prepare('INSERT INTO bundle_items (id, org_id, bundle_id, product_id, quantity) VALUES (?, ?, ?, ?, ?)');
    b.items.forEach(item => stmt.run('bi_' + uid(), orgId, req.params.id, item.productId, item.quantity || 1));
  }
  res.json(rowToBundle(db.prepare('SELECT * FROM product_bundles WHERE id=?').get(req.params.id)));
});

app.delete('/api/product-bundles/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  db.prepare('DELETE FROM bundle_items WHERE bundle_id=? AND org_id=?').run(req.params.id, orgId);
  const result = db.prepare('DELETE FROM product_bundles WHERE id=? AND org_id=?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20.3: Checklist Templates + Deal Checklists ────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToChecklistTemplate(r) {
  if (!r) return null;
  const items = db.prepare('SELECT * FROM checklist_items WHERE template_id=? ORDER BY sort_order ASC').all(r.id);
  return {
    id: r.id, name: r.name,
    items: items.map(i => ({ id: i.id, title: i.title, sortOrder: i.sort_order })),
    createdAt: r.created_at,
  };
}

app.get('/api/checklist-templates', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM checklist_templates WHERE org_id=? ORDER BY name ASC').all(req.user.orgId);
  res.json(rows.map(rowToChecklistTemplate));
});

app.post('/api/checklist-templates', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = 'ct_' + uid();
  db.prepare('INSERT INTO checklist_templates (id, org_id, name, created_at) VALUES (?, ?, ?, ?)')
    .run(id, orgId, b.name, Date.now());
  if (Array.isArray(b.items)) {
    const stmt = db.prepare('INSERT INTO checklist_items (id, org_id, template_id, title, sort_order) VALUES (?, ?, ?, ?, ?)');
    b.items.forEach((item, idx) => stmt.run('ci_' + uid(), orgId, id, item.title || item, idx));
  }
  res.status(201).json(rowToChecklistTemplate(db.prepare('SELECT * FROM checklist_templates WHERE id=?').get(id)));
});

app.put('/api/checklist-templates/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const result = db.prepare('UPDATE checklist_templates SET name=? WHERE id=? AND org_id=?')
    .run(b.name, req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  db.prepare('DELETE FROM checklist_items WHERE template_id=? AND org_id=?').run(req.params.id, orgId);
  if (Array.isArray(b.items)) {
    const stmt = db.prepare('INSERT INTO checklist_items (id, org_id, template_id, title, sort_order) VALUES (?, ?, ?, ?, ?)');
    b.items.forEach((item, idx) => stmt.run('ci_' + uid(), orgId, req.params.id, item.title || item, idx));
  }
  res.json(rowToChecklistTemplate(db.prepare('SELECT * FROM checklist_templates WHERE id=?').get(req.params.id)));
});

app.delete('/api/checklist-templates/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  db.prepare('DELETE FROM checklist_items WHERE template_id=? AND org_id=?').run(req.params.id, orgId);
  const result = db.prepare('DELETE FROM checklist_templates WHERE id=? AND org_id=?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Deal Checklists (live instances)
function rowToDealChecklist(r) {
  if (!r) return null;
  const items = db.prepare('SELECT * FROM deal_checklist_items WHERE checklist_id=? ORDER BY sort_order ASC').all(r.id);
  const total = items.length;
  const done  = items.filter(i => i.done).length;
  return {
    id: r.id, dealId: r.deal_id, templateId: r.template_id, name: r.name,
    total, done, progress: total > 0 ? Math.round((done / total) * 100) : 0,
    items: items.map(i => ({ id: i.id, title: i.title, done: Boolean(i.done), sortOrder: i.sort_order })),
    createdAt: r.created_at,
  };
}

app.get('/api/deal-checklists', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId } = req.query;
  let sql = 'SELECT * FROM deal_checklists WHERE org_id=?';
  const params = [orgId];
  if (dealId) { sql += ' AND deal_id=?'; params.push(dealId); }
  sql += ' ORDER BY created_at ASC';
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(rowToDealChecklist));
});

// Apply a template to a deal
app.post('/api/deal-checklists', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId, templateId, name } = req.body;
  if (!dealId) return res.status(400).json({ error: 'dealId required' });
  const id = 'dc_' + uid();
  const checklistName = name || (templateId ? (db.prepare('SELECT name FROM checklist_templates WHERE id=?').get(templateId)?.name || 'Checklist') : 'Checklist');
  db.prepare('INSERT INTO deal_checklists (id, org_id, deal_id, template_id, name, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, orgId, dealId, templateId || null, checklistName, Date.now());
  // Copy items from template
  if (templateId) {
    const templateItems = db.prepare('SELECT * FROM checklist_items WHERE template_id=? ORDER BY sort_order ASC').all(templateId);
    const stmt = db.prepare('INSERT INTO deal_checklist_items (id, org_id, checklist_id, title, done, sort_order) VALUES (?, ?, ?, ?, ?, ?)');
    templateItems.forEach((item, idx) => stmt.run('dci_' + uid(), orgId, id, item.title, 0, idx));
  }
  res.status(201).json(rowToDealChecklist(db.prepare('SELECT * FROM deal_checklists WHERE id=?').get(id)));
});

app.delete('/api/deal-checklists/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  db.prepare('DELETE FROM deal_checklist_items WHERE checklist_id=? AND org_id=?').run(req.params.id, orgId);
  const result = db.prepare('DELETE FROM deal_checklists WHERE id=? AND org_id=?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Toggle a checklist item done/undone
app.patch('/api/deal-checklist-items/:id/toggle', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const item = db.prepare('SELECT * FROM deal_checklist_items WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!item) return res.status(404).json({ error: 'Not found' });
  db.prepare('UPDATE deal_checklist_items SET done=? WHERE id=?').run(item.done ? 0 : 1, req.params.id);
  const updated = db.prepare('SELECT * FROM deal_checklist_items WHERE id=?').get(req.params.id);
  res.json({ id: updated.id, done: Boolean(updated.done) });
});

// Get checklist progress summary for a deal (for deal cards)
app.get('/api/deal-checklists/progress/:dealId', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const checklists = db.prepare('SELECT * FROM deal_checklists WHERE deal_id=? AND org_id=?').all(req.params.dealId, orgId);
  let total = 0, done = 0;
  checklists.forEach(cl => {
    const items = db.prepare('SELECT * FROM deal_checklist_items WHERE checklist_id=?').all(cl.id);
    total += items.length;
    done  += items.filter(i => i.done).length;
  });
  res.json({ total, done, progress: total > 0 ? Math.round((done / total) * 100) : null });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20.4: Email Templates 2.0 (category support) ───────────────────
// ══════════════════════════════════════════════════════════════════════════
// Email templates are stored in settings.emailTemplates as JSON array.
// Each template: { id, name, subject, body, category }
// The existing settings CRUD already handles this — no new tables needed.
// Frontend handles variable substitution and preview.

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20.5: SLA / Stage History ──────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// Log a stage transition
app.post('/api/deal-stage-log', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId, stage, enteredAt } = req.body;
  if (!dealId || !stage) return res.status(400).json({ error: 'dealId and stage required' });
  // Close out any open entry for this deal
  db.prepare(`UPDATE deal_stage_log SET exited_at=? WHERE deal_id=? AND org_id=? AND exited_at IS NULL`)
    .run(enteredAt || Date.now(), dealId, orgId);
  // Insert new entry
  const id = 'dsl_' + uid();
  db.prepare('INSERT INTO deal_stage_log (id, org_id, deal_id, stage, entered_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, dealId, stage, enteredAt || Date.now());
  res.status(201).json({ id, dealId, stage, enteredAt: enteredAt || Date.now() });
});

// Get stage history for a deal
app.get('/api/deal-stage-log/:dealId', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare('SELECT * FROM deal_stage_log WHERE deal_id=? AND org_id=? ORDER BY entered_at ASC').all(req.params.dealId, orgId);
  res.json(rows.map(r => ({
    id: r.id, dealId: r.deal_id, stage: r.stage,
    enteredAt: r.entered_at, exitedAt: r.exited_at,
    daysSpent: r.exited_at
      ? Math.round((r.exited_at - r.entered_at) / 86400000 * 10) / 10
      : Math.round((Date.now() - r.entered_at) / 86400000 * 10) / 10,
  })));
});

// SLA compliance report
app.get('/api/sla-report', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const slaLimits = (() => {
    const row = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slaLimits'").get(orgId);
    try { return row ? JSON.parse(row.value) : {}; } catch { return {}; }
  })();
  const stages = db.prepare('SELECT DISTINCT stage FROM deal_stage_log WHERE org_id=?').all(orgId).map(r => r.stage);
  const report = stages.map(stage => {
    const entries = db.prepare('SELECT * FROM deal_stage_log WHERE org_id=? AND stage=?').all(orgId, stage);
    const daysArr = entries.map(r => {
      const end = r.exited_at || Date.now();
      return (end - r.entered_at) / 86400000;
    });
    const avgDays = daysArr.length > 0 ? daysArr.reduce((a,b) => a + b, 0) / daysArr.length : 0;
    const slaLimit = slaLimits[stage] || null;
    const compliant = slaLimit ? daysArr.filter(d => d <= slaLimit).length : daysArr.length;
    return {
      stage,
      count: entries.length,
      avgDays: Math.round(avgDays * 10) / 10,
      slaLimit,
      compliantCount: compliant,
      pctCompliant: entries.length > 0 ? Math.round((compliant / entries.length) * 100) : 100,
    };
  });
  res.json(report);
});

// Check which deals are exceeding SLA in current stage
app.get('/api/deals-sla-status', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const slaLimits = (() => {
    const row = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slaLimits'").get(orgId);
    try { return row ? JSON.parse(row.value) : {}; } catch { return {}; }
  })();
  const openEntries = db.prepare(`SELECT * FROM deal_stage_log WHERE org_id=? AND exited_at IS NULL`).all(orgId);
  const result = {};
  openEntries.forEach(entry => {
    const daysInStage = (Date.now() - entry.entered_at) / 86400000;
    const limit = slaLimits[entry.stage];
    result[entry.deal_id] = {
      stage: entry.stage, daysInStage: Math.round(daysInStage * 10) / 10,
      slaLimit: limit || null,
      slaBreached: limit ? daysInStage > limit : false,
    };
  });
  res.json(result);
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20: Deal Room (Client Portal) ──────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// Generate or retrieve portal token for a deal
app.post('/api/deals/:id/portal-token', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  let token = deal.portal_token;
  if (!token) {
    token = crypto.randomBytes(24).toString('hex');
    db.prepare('UPDATE deals SET portal_token=? WHERE id=? AND org_id=?').run(token, req.params.id, orgId);
  }
  res.json({ token, url: `/portal/${token}` });
});

// Public: Get portal data for a deal (no auth required)
app.get('/api/portal/:token', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });

  const stagesRow = db.prepare(`SELECT value FROM settings WHERE org_id=? AND key='pipelineStages'`).get(deal.org_id);
  const stages = safeJSON(stagesRow?.value, []).map(s => s.name || s);
  const stageIdx = stages.indexOf(deal.stage);

  const activities = db.prepare(`SELECT type, note, date FROM activities WHERE deal_id=? ORDER BY created_at DESC LIMIT 10`).all(deal.id);
  const docs = db.prepare(`SELECT title, url, type, date_added FROM doc_links WHERE entity_type='deal' AND entity_id=? ORDER BY date_added DESC`).all(deal.id);
  const proposal = db.prepare(`SELECT title, status, signed_at, viewed_at, created_at FROM proposals WHERE deal_id=? ORDER BY created_at DESC LIMIT 1`).get(deal.id);
  const qas = db.prepare(`SELECT id, author_name, question, answer, answered_at, created_at FROM portal_qas WHERE deal_id=? ORDER BY created_at ASC`).all(deal.id);

  res.json({ dealName: deal.name, stage: deal.stage, stages, stageIdx, value: deal.value, closeDate: deal.close_date, activities, docs, proposal, qas });
});

// Public: Submit a Q&A question (no auth)
app.post('/api/portal/:token/qa', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const { authorName, question } = req.body;
  if (!question || !authorName) return res.status(400).json({ error: 'authorName and question required' });
  const id = 'pqa_' + uid();
  db.prepare(`INSERT INTO portal_qas (id, org_id, deal_id, author_name, question, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .run(id, deal.org_id, deal.id, authorName, question, Date.now());
  try {
    const users = db.prepare('SELECT id FROM users WHERE org_id=?').all(deal.org_id);
    users.forEach(u => {
      db.prepare(`INSERT INTO notifications (id, org_id, user_id, type, message, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
        .run('notif_' + uid(), deal.org_id, u.id, 'portal_qa', `New question on "${deal.name}" from ${authorName}`, 'deal', deal.id, Date.now());
    });
  } catch(e) {}
  res.status(201).json({ id, authorName, question, answer: null, createdAt: Date.now() });
});

// Internal: Get Q&A for a deal (authenticated)
app.get('/api/deals/:id/portal-qa', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare(`SELECT * FROM portal_qas WHERE org_id=? AND deal_id=? ORDER BY created_at ASC`).all(orgId, req.params.id);
  res.json(rows.map(r => ({ id: r.id, authorName: r.author_name, question: r.question, answer: r.answer, answeredAt: r.answered_at, createdAt: r.created_at })));
});

// Internal: Answer a Q&A question (authenticated)
app.post('/api/deals/:id/portal-qa/:qaId/answer', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { answer } = req.body;
  if (!answer) return res.status(400).json({ error: 'answer required' });
  const result = db.prepare(`UPDATE portal_qas SET answer=?, answered_at=? WHERE id=? AND org_id=?`)
    .run(answer, Date.now(), req.params.qaId, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20: Workflow Automation (Stage Triggers) ────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToWorkflowRule(r) {
  if (!r) return null;
  return { id: r.id, name: r.name, triggerStage: r.trigger_stage, actions: safeJSON(r.actions, []), active: Boolean(r.active), createdAt: r.created_at };
}

function runWorkflowEngine(orgId, dealId, toStage) {
  try {
    const rules = db.prepare(`SELECT * FROM workflow_rules WHERE org_id=? AND trigger_stage=? AND active=1`).all(orgId, toStage);
    if (!rules.length) return;
    const deal = db.prepare('SELECT * FROM deals WHERE id=?').get(dealId);
    if (!deal) return;
    rules.forEach(rule => {
      safeJSON(rule.actions, []).forEach(action => {
        try {
          if (action.type === 'create_task') {
            const daysOut = parseInt(action.dueDays || 3);
            const dueDate = new Date(Date.now() + daysOut * 86400000).toISOString().slice(0, 10);
            db.prepare(`INSERT INTO tasks (id, org_id, title, due_date, deal_id, priority, status, assigned_owner, created_at) VALUES (?, ?, ?, ?, ?, 'Medium', 'Open', ?, ?)`)
              .run('wf_tk_' + uid(), orgId, action.taskTitle || 'Follow-up task', dueDate, dealId, deal.owner || '', Date.now());
          } else if (action.type === 'notify') {
            const users = db.prepare('SELECT id FROM users WHERE org_id=?').all(orgId);
            users.forEach(u => db.prepare(`INSERT INTO notifications (id, org_id, user_id, type, message, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
              .run('notif_' + uid(), orgId, u.id, 'workflow', action.notifyMessage || `Deal "${deal.name}" moved to ${toStage}`, 'deal', dealId, Date.now()));
          } else if (action.type === 'log_activity') {
            db.prepare(`INSERT INTO activities (id, org_id, type, deal_id, note, date, created_at) VALUES (?, ?, 'Note', ?, ?, ?, ?)`)
              .run('wf_act_' + uid(), orgId, dealId, action.activityNote || `Stage changed to ${toStage}`, new Date().toISOString(), Date.now());
          }
        } catch(e) {}
      });
    });
  } catch(e) {}
}

app.get('/api/workflow-rules', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM workflow_rules WHERE org_id=? ORDER BY created_at ASC').all(req.user.orgId);
  res.json(rows.map(rowToWorkflowRule));
});

app.post('/api/workflow-rules', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  if (!b.name || !b.triggerStage) return res.status(400).json({ error: 'name and triggerStage required' });
  const id = 'wfr_' + uid();
  db.prepare(`INSERT INTO workflow_rules (id, org_id, name, trigger_stage, actions, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, orgId, b.name, b.triggerStage, JSON.stringify(b.actions || []), b.active !== false ? 1 : 0, Date.now());
  res.status(201).json(rowToWorkflowRule(db.prepare('SELECT * FROM workflow_rules WHERE id=?').get(id)));
});

app.put('/api/workflow-rules/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare(`UPDATE workflow_rules SET name=?, trigger_stage=?, actions=?, active=? WHERE id=? AND org_id=?`)
    .run(b.name, b.triggerStage, JSON.stringify(b.actions || []), b.active !== false ? 1 : 0, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToWorkflowRule(db.prepare('SELECT * FROM workflow_rules WHERE id=?').get(req.params.id)));
});

app.delete('/api/workflow-rules/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM workflow_rules WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Hook workflow engine into deal stage changes via deal PUT
// We use a wrapper middleware that intercepts deal updates
app.use((req, res, next) => {
  if (req.method === 'PUT' && /^\/api\/deals\/[^/]+$/.test(req.path)) {
    const dealId = req.path.split('/')[3];
    try { req._wfBeforeStage = (db.prepare('SELECT stage FROM deals WHERE id=?').get(dealId) || {}).stage; } catch(e) {}
    const origJson = res.json.bind(res);
    res.json = function(body) {
      if (body && body.stage && req._wfBeforeStage && req._wfBeforeStage !== body.stage && req.user?.orgId) {
        try { runWorkflowEngine(req.user.orgId, body.id, body.stage); } catch(e) {}
      }
      return origJson(body);
    };
  }
  next();
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20: API Key Management ─────────────────────────════════════════
// ══════════════════════════════════════════════════════════════════════════

// Middleware: accept X-API-Key header as alternative auth (registered after other routes)
app.use((req, res, next) => {
  const apiKeyHeader = req.headers['x-api-key'];
  if (!apiKeyHeader || req.user) return next();
  try {
    const hash = crypto.createHash('sha256').update(apiKeyHeader).digest('hex');
    const keyRow = db.prepare('SELECT * FROM api_keys WHERE key_hash=?').get(hash);
    if (!keyRow) return next();
    if (keyRow.expires_at && keyRow.expires_at < Date.now()) return next();
    const user = db.prepare(`SELECT id, org_id, name, role, owner_tag FROM users WHERE org_id=? LIMIT 1`).get(keyRow.org_id);
    if (!user) return next();
    db.prepare('UPDATE api_keys SET last_used=? WHERE id=?').run(Date.now(), keyRow.id);
    req.user = { userId: user.id, orgId: user.org_id, name: user.name, role: user.role, ownerTag: user.owner_tag || '', apiKey: true, keyScope: keyRow.scope };
  } catch(e) {}
  next();
});

function rowToApiKey(r) {
  if (!r) return null;
  return { id: r.id, name: r.name, keyPrefix: r.key_prefix, scope: r.scope, lastUsed: r.last_used, expiresAt: r.expires_at, createdAt: r.created_at };
}

app.get('/api/api-keys', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM api_keys WHERE org_id=? ORDER BY created_at DESC').all(req.user.orgId).map(rowToApiKey));
});

app.post('/api/api-keys', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { name, scope, expiresAt } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const rawKey  = 'br_' + (scope === 'read' ? 'ro' : 'rw') + '_' + crypto.randomBytes(20).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const prefix  = rawKey.slice(0, 12) + '...';
  const id      = 'ak_' + uid();
  db.prepare(`INSERT INTO api_keys (id, org_id, name, key_hash, key_prefix, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, orgId, name, keyHash, prefix, scope || 'read', expiresAt || null, Date.now());
  res.status(201).json({ ...rowToApiKey(db.prepare('SELECT * FROM api_keys WHERE id=?').get(id)), rawKey });
});

app.delete('/api/api-keys/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM api_keys WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 20: Saved Custom Reports ───────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToSavedReport(r) {
  if (!r) return null;
  return { id: r.id, name: r.name, config: safeJSON(r.config, {}), createdAt: r.created_at };
}

app.get('/api/saved-reports', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM saved_reports WHERE org_id=? ORDER BY created_at DESC').all(req.user.orgId).map(rowToSavedReport));
});

app.post('/api/saved-reports', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { name, config } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const id = 'sr_' + uid();
  db.prepare(`INSERT INTO saved_reports (id, org_id, name, config, created_at) VALUES (?, ?, ?, ?, ?)`)
    .run(id, orgId, name, JSON.stringify(config || {}), Date.now());
  res.status(201).json(rowToSavedReport(db.prepare('SELECT * FROM saved_reports WHERE id=?').get(id)));
});

app.put('/api/saved-reports/:id', requireAuth, (req, res) => {
  const { name, config } = req.body;
  const result = db.prepare('UPDATE saved_reports SET name=?, config=? WHERE id=? AND org_id=?')
    .run(name, JSON.stringify(config || {}), req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToSavedReport(db.prepare('SELECT * FROM saved_reports WHERE id=?').get(req.params.id)));
});

app.delete('/api/saved-reports/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM saved_reports WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Install Tracker ─────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToInstall(r) {
  if (!r) return null;
  return {
    id:              r.id,
    contactId:       r.contact_id,
    companyId:       r.company_id,
    productId:       r.product_id,
    productName:     r.product_name,
    installDate:     r.install_date,
    serialNumber:    r.serial_number,
    warrantyExpiry:  r.warranty_expiry,
    serviceInterval: r.service_interval,
    lastService:     r.last_service,
    nextService:     r.next_service,
    notes:           r.notes,
    createdAt:       r.created_at,
  };
}

app.get('/api/installs', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contactId, companyId } = req.query;
  let query = 'SELECT * FROM installs WHERE org_id = ?';
  const params = [orgId];
  if (contactId) { query += ' AND contact_id = ?'; params.push(contactId); }
  if (companyId) { query += ' AND company_id = ?'; params.push(companyId); }
  query += ' ORDER BY install_date DESC';
  res.json(db.prepare(query).all(...params).map(rowToInstall));
});

app.get('/api/installs/upcoming', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const today = new Date().toISOString().slice(0, 10);
  const in30  = new Date(Date.now() + 30*86400000).toISOString().slice(0, 10);
  const rows  = db.prepare(
    `SELECT * FROM installs WHERE org_id=? AND next_service IS NOT NULL AND next_service <= ? AND next_service >= ? ORDER BY next_service ASC`
  ).all(orgId, in30, today);
  res.json(rows.map(rowToInstall));
});

app.post('/api/installs', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const id = 'inst_' + uid();
  db.prepare(`INSERT INTO installs (id, org_id, contact_id, company_id, product_id, product_name, install_date, serial_number, warranty_expiry, service_interval, last_service, next_service, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.contactId||null, b.companyId||null, b.productId||null, b.productName||'',
    b.installDate||null, b.serialNumber||null, b.warrantyExpiry||null,
    b.serviceInterval||0, b.lastService||null, b.nextService||null,
    b.notes||null, Date.now()
  );
  res.status(201).json(rowToInstall(db.prepare('SELECT * FROM installs WHERE id=?').get(id)));
});

app.put('/api/installs/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const result = db.prepare(`UPDATE installs SET contact_id=?, company_id=?, product_id=?, product_name=?, install_date=?, serial_number=?, warranty_expiry=?, service_interval=?, last_service=?, next_service=?, notes=?
    WHERE id=? AND org_id=?`).run(
    b.contactId||null, b.companyId||null, b.productId||null, b.productName||'',
    b.installDate||null, b.serialNumber||null, b.warrantyExpiry||null,
    b.serviceInterval||0, b.lastService||null, b.nextService||null,
    b.notes||null, req.params.id, orgId
  );
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToInstall(db.prepare('SELECT * FROM installs WHERE id=?').get(req.params.id)));
});

app.delete('/api/installs/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM installs WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Data Health Endpoint ───────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/data-health', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contacts  = db.prepare('SELECT * FROM contacts WHERE org_id=?').all(orgId);
  const companies = db.prepare('SELECT * FROM companies WHERE org_id=?').all(orgId);
  const deals     = db.prepare('SELECT * FROM deals WHERE org_id=?').all(orgId);
  const ninetyDaysAgo = Date.now() - 90 * 86400000;

  // Completeness
  const contactFieldCount = 7;
  const contactScore = contacts.length ? contacts.reduce((sum, c) => {
    let filled = 0;
    if (c.name)          filled++;
    if (c.email)         filled++;
    if (c.phone)         filled++;
    if (c.company_id)    filled++;
    if (c.title)         filled++;
    if (c.stage)         filled++;
    if (c.last_activity) filled++;
    return sum + filled / contactFieldCount;
  }, 0) / contacts.length * 100 : 100;

  const companyFieldCount = 5;
  const companyScore = companies.length ? companies.reduce((sum, c) => {
    let filled = 0;
    if (c.name)     filled++;
    if (c.website)  filled++;
    if (c.phone)    filled++;
    if (c.industry) filled++;
    if (c.city)     filled++;
    return sum + filled / companyFieldCount;
  }, 0) / companies.length * 100 : 100;

  const dealFieldCount = 5;
  const dealScore = deals.length ? deals.reduce((sum, d) => {
    let filled = 0;
    if (d.name)       filled++;
    if (d.close_date) filled++;
    if (d.owner)      filled++;
    if (d.value)      filled++;
    if (d.contact_id) filled++;
    return sum + filled / dealFieldCount;
  }, 0) / deals.length * 100 : 100;

  const overallScore = Math.round((contactScore + companyScore + dealScore) / 3);

  // Issues
  const missingEmail   = contacts.filter(c => !c.email).map(c => ({ id: c.id, name: c.name }));
  const missingPhone   = contacts.filter(c => !c.phone).map(c => ({ id: c.id, name: c.name }));
  const missingWebsite = companies.filter(c => !c.website).map(c => ({ id: c.id, name: c.name }));
  const missingClose   = deals.filter(d => !d.close_date && d.stage !== 'Won' && d.stage !== 'Lost').map(d => ({ id: d.id, name: d.name }));
  const missingOwner   = deals.filter(d => !d.owner).map(d => ({ id: d.id, name: d.name }));
  const staleContacts  = contacts.filter(c => c.last_activity && c.last_activity < ninetyDaysAgo).map(c => ({ id: c.id, name: c.name, lastActivity: c.last_activity }));

  // Duplicate detection: same email
  const emailMap = {};
  contacts.forEach(c => { if (c.email) { (emailMap[c.email] = emailMap[c.email] || []).push({ id: c.id, name: c.name }); } });
  const dupByEmail = Object.entries(emailMap).filter(([, arr]) => arr.length > 1).map(([email, arr]) => ({ email, contacts: arr }));

  // Duplicate detection: same company + name prefix
  const nameMap = {};
  contacts.forEach(c => { const key = (c.company_id||'_') + '|' + c.name.toLowerCase().slice(0,8); (nameMap[key] = nameMap[key] || []).push({ id: c.id, name: c.name }); });
  const dupByName = Object.entries(nameMap).filter(([, arr]) => arr.length > 1).map(([, arr]) => arr);

  res.json({
    overallScore,
    scores: { contacts: Math.round(contactScore), companies: Math.round(companyScore), deals: Math.round(dealScore) },
    issues: { missingEmail, missingPhone, missingWebsite, missingClose, missingOwner, staleContacts, dupByEmail, dupByName },
    counts: { contacts: contacts.length, companies: companies.length, deals: deals.length },
  });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Commission Tracking ────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/commission-rates', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM commission_rates WHERE org_id=? ORDER BY user_id, created_at DESC').all(req.user.orgId);
  res.json(rows.map(r => ({ id: r.id, userId: r.user_id, ratePercent: r.rate_percent, effectiveFrom: r.effective_from, createdAt: r.created_at })));
});

app.post('/api/commission-rates', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { userId, ratePercent, effectiveFrom } = req.body;
  if (!userId || ratePercent == null) return res.status(400).json({ error: 'userId and ratePercent required' });
  db.prepare('DELETE FROM commission_rates WHERE org_id=? AND user_id=?').run(orgId, userId);
  const id = 'cr_' + uid();
  db.prepare('INSERT INTO commission_rates (id, org_id, user_id, rate_percent, effective_from, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, orgId, userId, ratePercent, effectiveFrom || new Date().toISOString().slice(0,10), Date.now());
  res.status(201).json({ id, userId, ratePercent, effectiveFrom });
});

app.get('/api/commissions', requireAuth, (req, res) => {
  const { userId, status, from, to } = req.query;
  let sql = `SELECT c.*, d.name as deal_name, d.value as deal_value, u.name as user_name
             FROM commissions c
             LEFT JOIN deals d ON d.id = c.deal_id
             LEFT JOIN users u ON u.id = c.user_id
             WHERE c.org_id=?`;
  const params = [req.user.orgId];
  if (userId) { sql += ' AND c.user_id=?'; params.push(userId); }
  if (status) { sql += ' AND c.status=?'; params.push(status); }
  if (from)   { sql += ' AND c.created_at>=?'; params.push(new Date(from).getTime()); }
  if (to)     { sql += ' AND c.created_at<=?'; params.push(new Date(to).getTime() + 86399999); }
  sql += ' ORDER BY c.created_at DESC';
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(r => ({
    id: r.id, dealId: r.deal_id, userId: r.user_id, amount: r.amount,
    ratePercent: r.rate_percent, status: r.status, paidAt: r.paid_at,
    createdAt: r.created_at, dealName: r.deal_name, dealValue: r.deal_value, userName: r.user_name
  })));
});

app.get('/api/commissions/summary', requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT c.user_id, u.name as user_name,
      SUM(CASE WHEN c.status='Pending' THEN c.amount ELSE 0 END) as pending,
      SUM(CASE WHEN c.status='Approved' THEN c.amount ELSE 0 END) as approved,
      SUM(CASE WHEN c.status='Paid' THEN c.amount ELSE 0 END) as paid,
      COUNT(*) as total_count
    FROM commissions c
    LEFT JOIN users u ON u.id = c.user_id
    WHERE c.org_id=?
    GROUP BY c.user_id
  `).all(req.user.orgId);
  res.json(rows.map(r => ({ userId: r.user_id, userName: r.user_name, pending: r.pending||0, approved: r.approved||0, paid: r.paid||0, totalCount: r.total_count })));
});

app.post('/api/commissions', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { dealId, userId, amount, ratePercent, status } = req.body;
  if (!dealId || !userId || amount == null) return res.status(400).json({ error: 'dealId, userId, amount required' });
  const id = 'comm_' + uid();
  db.prepare('INSERT INTO commissions (id, org_id, deal_id, user_id, amount, rate_percent, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, orgId, dealId, userId, amount, ratePercent || 0, status || 'Pending', Date.now());
  res.status(201).json({ id, dealId, userId, amount, ratePercent, status: status || 'Pending' });
});

app.put('/api/commissions/:id', requireAuth, (req, res) => {
  const { status, paidAt } = req.body;
  const result = db.prepare('UPDATE commissions SET status=?, paid_at=? WHERE id=? AND org_id=?')
    .run(status, paidAt || null, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

app.delete('/api/commissions/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM commissions WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

function autoCreateCommission(orgId, deal) {
  try {
    if (!deal || deal.stage !== 'Won' || !deal.value) return;
    const existing = db.prepare('SELECT id FROM commissions WHERE deal_id=? AND org_id=?').get(deal.id, orgId);
    if (existing) return;
    if (!deal.owner) return;
    const user = db.prepare("SELECT id FROM users WHERE org_id=? AND (owner_tag=? OR name=?) LIMIT 1").get(orgId, deal.owner, deal.owner);
    if (!user) return;
    const rateRow = db.prepare('SELECT rate_percent FROM commission_rates WHERE org_id=? AND user_id=? ORDER BY created_at DESC LIMIT 1').get(orgId, user.id);
    const rate = rateRow ? rateRow.rate_percent : 0;
    if (!rate) return;
    const amount = (deal.value * rate) / 100;
    const id = 'comm_' + uid();
    db.prepare('INSERT INTO commissions (id, org_id, deal_id, user_id, amount, rate_percent, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, orgId, deal.id, user.id, amount, rate, 'Pending', Date.now());
  } catch(e) { console.warn('Commission auto-create:', e.message); }
}

app.post('/api/deals/:id/check-commission', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  autoCreateCommission(orgId, deal);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Custom Report Builder ──────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/reports/run', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { entity, fields, groupBy, chartType, filters } = req.body;
  if (!entity || !fields || !fields.length) return res.status(400).json({ error: 'entity and fields required' });
  try {
    const entityTableMap = { contacts: 'contacts', deals: 'deals', companies: 'companies', activities: 'activities' };
    const table = entityTableMap[entity];
    if (!table) return res.status(400).json({ error: 'Invalid entity' });

    const fieldColMap = {
      name: 'name', email: 'email', phone: 'phone', title: 'title', stage: 'stage',
      owner: 'owner', lead_source: 'lead_source', territory: 'territory',
      created_at: 'created_at', last_activity: 'last_activity', tags: 'tags',
      value: 'value', close_date: 'close_date', probability: 'probability',
      win_reason: 'win_reason', loss_reason: 'loss_reason', currency: 'currency',
      industry: 'industry', website: 'website', city: 'city',
      type: 'type', note: 'note', date: 'date', notes: 'notes',
    };

    const selectedCols = fields.filter(f => fieldColMap[f]);
    if (!selectedCols.length) return res.status(400).json({ error: 'No valid fields' });

    let sql = `SELECT ${selectedCols.map(f => `t.${fieldColMap[f]} as ${f}`).join(', ')} FROM ${table} t WHERE t.org_id=?`;
    const params = [orgId];

    if (Array.isArray(filters)) {
      filters.forEach(f => {
        if (f.field && fieldColMap[f.field] && f.value !== '') {
          const col = `t.${fieldColMap[f.field]}`;
          if (f.op === 'eq')   { sql += ` AND ${col}=?`; params.push(f.value); }
          if (f.op === 'neq')  { sql += ` AND ${col}!=?`; params.push(f.value); }
          if (f.op === 'gt')   { sql += ` AND CAST(${col} AS REAL)>?`; params.push(Number(f.value)); }
          if (f.op === 'lt')   { sql += ` AND CAST(${col} AS REAL)<?`; params.push(Number(f.value)); }
          if (f.op === 'like') { sql += ` AND ${col} LIKE ?`; params.push('%'+f.value+'%'); }
        }
      });
    }

    const rows = db.prepare(sql + ' ORDER BY t.created_at DESC LIMIT 500').all(...params);

    let groupedResult = null;
    if (groupBy && fieldColMap[groupBy]) {
      const grouped = {};
      rows.forEach(row => {
        const key = row[groupBy] || '(none)';
        if (!grouped[key]) grouped[key] = { key, count: 0, totalValue: 0 };
        grouped[key].count++;
        if (row.value) grouped[key].totalValue += Number(row.value) || 0;
      });
      groupedResult = Object.values(grouped).sort((a,b) => b.count - a.count);
    }
    res.json({ rows, grouped: groupedResult, total: rows.length, fields, entity, groupBy, chartType });
  } catch(e) {
    res.status(500).json({ error: 'Report failed: ' + e.message });
  }
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Client Portal V2 ───────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/portal-v2/:token', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });

  const stagesRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='pipelineStages'").get(deal.org_id);
  const stages = safeJSON(stagesRow ? stagesRow.value : null, []).map(s => s.name || s);
  const stageIdx = stages.indexOf(deal.stage);

  const activities = db.prepare('SELECT type, note, date FROM activities WHERE deal_id=? ORDER BY created_at DESC LIMIT 10').all(deal.id);
  const docs = db.prepare("SELECT id, title, url, type, date_added FROM doc_links WHERE entity_type='deal' AND entity_id=? ORDER BY date_added DESC").all(deal.id);
  const uploadedDocs = db.prepare("SELECT id, title, date_added FROM doc_links WHERE entity_type='portal_upload' AND entity_id=? ORDER BY date_added DESC").all(deal.id);
  const proposal = db.prepare('SELECT title, status, signed_at, viewed_at, created_at FROM proposals WHERE deal_id=? ORDER BY created_at DESC LIMIT 1').get(deal.id);
  const comments = db.prepare('SELECT id, author_name, body, created_at FROM portal_comments WHERE deal_id=? ORDER BY created_at ASC').all(deal.id);
  const checklists = db.prepare('SELECT id, name FROM deal_checklists WHERE deal_id=?').all(deal.id);
  const checklistsWithItems = checklists.map(cl => {
    const items = db.prepare('SELECT title, done, sort_order FROM deal_checklist_items WHERE checklist_id=? ORDER BY sort_order').all(cl.id);
    return { ...cl, items };
  });

  // Phase 22: include invoices
  const invoiceRows = db.prepare('SELECT id, number, status, total, issue_date, due_date, items, notes FROM invoices WHERE deal_id=? ORDER BY created_at DESC').all(deal.id);
  const reviewedInvoiceIds = db.prepare('SELECT invoice_id FROM portal_invoice_reviews WHERE deal_id=?').all(deal.id).map(r => r.invoice_id);
  const invoices = invoiceRows.map(inv => ({
    id: inv.id, number: inv.number, status: inv.status, total: inv.total,
    issueDate: inv.issue_date, dueDate: inv.due_date,
    items: safeJSON(inv.items, []), notes: inv.notes,
    reviewed: reviewedInvoiceIds.includes(inv.id)
  }));

  res.json({ dealName: deal.name, stage: deal.stage, stages, stageIdx, value: deal.value, closeDate: deal.close_date, activities, docs, uploadedDocs, proposal, comments, checklists: checklistsWithItems, invoices });
});

app.post('/api/portal-v2/:token/comment', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const { authorName, body } = req.body;
  if (!authorName || !body) return res.status(400).json({ error: 'authorName and body required' });
  const id = 'pc_' + uid();
  db.prepare('INSERT INTO portal_comments (id, org_id, deal_id, token, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, deal.org_id, deal.id, req.params.token, authorName, body, Date.now());
  try {
    const users = db.prepare('SELECT id FROM users WHERE org_id=?').all(deal.org_id);
    users.forEach(u => {
      db.prepare('INSERT INTO notifications (id, org_id, user_id, type, message, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run('notif_' + uid(), deal.org_id, u.id, 'portal_comment', `New comment on "${deal.name}" from ${authorName}`, 'deal', deal.id, Date.now());
    });
  } catch(e) {}
  res.status(201).json({ id, authorName, body, createdAt: Date.now() });
});

app.post('/api/portal-v2/:token/upload', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const { fileName, fileData } = req.body;
  if (!fileName || !fileData) return res.status(400).json({ error: 'fileName and fileData required' });
  const id = 'dl_' + uid();
  const today = new Date().toISOString().slice(0,10);
  db.prepare('INSERT INTO doc_links (id, org_id, title, url, type, entity_type, entity_id, notes, date_added, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, deal.org_id, fileName, '', 'other', 'portal_upload', deal.id, fileData, today, Date.now());
  res.status(201).json({ id, fileName, dateAdded: today });
});

app.get('/api/deals/:id/portal-comments', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare('SELECT * FROM portal_comments WHERE org_id=? AND deal_id=? ORDER BY created_at ASC').all(orgId, req.params.id);
  res.json(rows.map(r => ({ id: r.id, authorName: r.author_name, body: r.body, createdAt: r.created_at })));
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Meeting Scheduler ──────────────════════════════════════════
// ══════════════════════════════════════════════════════════════════════════

function rowToMeeting(r) {
  if (!r) return null;
  return { id: r.id, contactId: r.contact_id, dealId: r.deal_id, title: r.title, description: r.description, scheduledAt: r.scheduled_at, durationMin: r.duration_min, location: r.location, status: r.status, createdBy: r.created_by, createdAt: r.created_at };
}

app.get('/api/meetings', requireAuth, (req, res) => {
  const { status, contactId, dealId } = req.query;
  let sql = 'SELECT * FROM meetings WHERE org_id=?';
  const params = [req.user.orgId];
  if (status)    { sql += ' AND status=?'; params.push(status); }
  if (contactId) { sql += ' AND contact_id=?'; params.push(contactId); }
  if (dealId)    { sql += ' AND deal_id=?'; params.push(dealId); }
  sql += ' ORDER BY scheduled_at ASC';
  res.json(db.prepare(sql).all(...params).map(rowToMeeting));
});

app.post('/api/meetings', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { contactId, dealId, title, description, scheduledAt, durationMin, location, status } = req.body;
  if (!title || !scheduledAt) return res.status(400).json({ error: 'title and scheduledAt required' });
  const id = 'mtg_' + uid();
  db.prepare('INSERT INTO meetings (id, org_id, contact_id, deal_id, title, description, scheduled_at, duration_min, location, status, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, orgId, contactId||null, dealId||null, title, description||'', scheduledAt, durationMin||30, location||'', status||'Scheduled', userName||userId, Date.now());
  try {
    const actId = 'a_' + uid();
    db.prepare('INSERT INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(actId, orgId, 'Meeting', contactId||null, dealId||null, `Meeting: ${title}${location ? ' @ '+location : ''}`, scheduledAt, Date.now());
    if (contactId) db.prepare('UPDATE contacts SET last_activity=? WHERE id=? AND org_id=?').run(Date.now(), contactId, orgId);
  } catch(e) {}
  // Phase 25: Slack notification for meeting scheduled
  setImmediate(() => fireSlackNotification(orgId, 'meeting_scheduled',
    `*Meeting Scheduled*\n- Title: ${title}\n- When: ${scheduledAt}\n- Duration: ${durationMin||30} min${location ? '\n- Location: '+location : ''}`
  ).catch(() => {}));
  res.status(201).json(rowToMeeting(db.prepare('SELECT * FROM meetings WHERE id=?').get(id)));
});

app.put('/api/meetings/:id', requireAuth, (req, res) => {
  const { contactId, dealId, title, description, scheduledAt, durationMin, location, status } = req.body;
  const result = db.prepare('UPDATE meetings SET contact_id=?, deal_id=?, title=?, description=?, scheduled_at=?, duration_min=?, location=?, status=? WHERE id=? AND org_id=?')
    .run(contactId||null, dealId||null, title, description||'', scheduledAt, durationMin||30, location||'', status||'Scheduled', req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToMeeting(db.prepare('SELECT * FROM meetings WHERE id=?').get(req.params.id)));
});

app.delete('/api/meetings/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM meetings WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 21: Territory Assignments V2 ───────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToTerritory(r) {
  if (!r) return null;
  return { id: r.id, name: r.name, description: r.description, repIds: safeJSON(r.rep_ids, []), createdAt: r.created_at };
}

app.get('/api/territories', requireAuth, (req, res) => {
  res.json(db.prepare('SELECT * FROM territories WHERE org_id=? ORDER BY name ASC').all(req.user.orgId).map(rowToTerritory));
});

app.post('/api/territories', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { name, description, repIds } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const id = 'terr_' + uid();
  db.prepare('INSERT INTO territories (id, org_id, name, description, rep_ids, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, orgId, name, description||'', JSON.stringify(repIds||[]), Date.now());
  res.status(201).json(rowToTerritory(db.prepare('SELECT * FROM territories WHERE id=?').get(id)));
});

app.put('/api/territories/:id', requireAuth, (req, res) => {
  const { name, description, repIds } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const result = db.prepare('UPDATE territories SET name=?, description=?, rep_ids=? WHERE id=? AND org_id=?')
    .run(name, description||'', JSON.stringify(repIds||[]), req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToTerritory(db.prepare('SELECT * FROM territories WHERE id=?').get(req.params.id)));
});

app.delete('/api/territories/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM territories WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

app.get('/api/territories/leaderboard', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const territories = db.prepare('SELECT * FROM territories WHERE org_id=? ORDER BY name ASC').all(orgId);
  const result = territories.map(t => {
    const terr = rowToTerritory(t);
    const wonDeals = db.prepare("SELECT d.value FROM deals d LEFT JOIN contacts c ON c.id=d.contact_id WHERE d.org_id=? AND d.stage='Won' AND c.territory=?").all(orgId, t.name);
    const revenue = wonDeals.reduce((s, d) => s + (d.value||0), 0);
    const openRow = db.prepare("SELECT COUNT(*) as c FROM deals d LEFT JOIN contacts c ON c.id=d.contact_id WHERE d.org_id=? AND d.stage NOT IN ('Won','Lost') AND c.territory=?").get(orgId, t.name);
    return { ...terr, wonDeals: wonDeals.length, revenue, openDeals: openRow ? openRow.c : 0 };
  });
  res.json(result);
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 22: Recurring Task Templates ───────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function rowToRecurringTemplate(r) {
  if (!r) return null;
  return {
    id: r.id, orgId: r.org_id, title: r.title, description: r.description,
    assignedTo: r.assigned_to, frequency: r.frequency,
    dayOfWeek: r.day_of_week, dayOfMonth: r.day_of_month,
    dealId: r.deal_id, active: Boolean(r.active),
    lastGeneratedAt: r.last_generated_at, createdAt: r.created_at
  };
}

app.get('/api/recurring-templates', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM recurring_task_templates WHERE org_id=? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToRecurringTemplate));
});

app.post('/api/recurring-templates', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  if (!b.title || !b.frequency) return res.status(400).json({ error: 'title and frequency required' });
  const id = 'rt_' + uid();
  db.prepare('INSERT INTO recurring_task_templates (id, org_id, title, description, assigned_to, frequency, day_of_week, day_of_month, deal_id, active, last_generated_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, orgId, b.title, b.description||'', b.assignedTo||'', b.frequency, b.dayOfWeek||1, b.dayOfMonth||1, b.dealId||null, b.active !== false ? 1 : 0, null, Date.now());
  res.status(201).json(rowToRecurringTemplate(db.prepare('SELECT * FROM recurring_task_templates WHERE id=?').get(id)));
});

app.put('/api/recurring-templates/:id', requireAuth, (req, res) => {
  const b = req.body;
  const result = db.prepare('UPDATE recurring_task_templates SET title=?, description=?, assigned_to=?, frequency=?, day_of_week=?, day_of_month=?, deal_id=?, active=? WHERE id=? AND org_id=?')
    .run(b.title, b.description||'', b.assignedTo||'', b.frequency, b.dayOfWeek||1, b.dayOfMonth||1, b.dealId||null, b.active ? 1 : 0, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToRecurringTemplate(db.prepare('SELECT * FROM recurring_task_templates WHERE id=?').get(req.params.id)));
});

app.delete('/api/recurring-templates/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM recurring_task_templates WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Generate due recurring tasks
app.post('/api/recurring-templates/generate', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const templates = db.prepare("SELECT * FROM recurring_task_templates WHERE org_id=? AND active=1").all(orgId);
  const now = Date.now();
  const today = new Date();
  const todayDOW = today.getDay(); // 0=Sun, 1=Mon ... 6=Sat
  const todayDOM = today.getDate();
  const todayStr = today.toISOString().slice(0, 10);
  const created = [];

  templates.forEach(tmpl => {
    const lastGen = tmpl.last_generated_at;
    let isDue = false;

    if (tmpl.frequency === 'daily') {
      // Due if never generated or last generated before today
      if (!lastGen || lastGen < new Date(todayStr).getTime()) isDue = true;
    } else if (tmpl.frequency === 'weekly') {
      // Due if today is the configured day_of_week and not yet generated this week
      if (todayDOW === tmpl.day_of_week) {
        // Check if already generated today or later this week
        const weekStart = new Date(today); weekStart.setDate(today.getDate() - todayDOW);
        weekStart.setHours(0,0,0,0);
        if (!lastGen || lastGen < weekStart.getTime()) isDue = true;
      }
    } else if (tmpl.frequency === 'monthly') {
      // Due if today is the configured day_of_month and not yet generated this month
      if (todayDOM === tmpl.day_of_month) {
        const monthStart = new Date(today.getFullYear(), today.getMonth(), 1);
        if (!lastGen || lastGen < monthStart.getTime()) isDue = true;
      }
    }

    if (isDue) {
      const taskId = 'tk_rt_' + uid();
      // Due date = today
      const dueDate = todayStr;
      try {
        db.prepare('INSERT INTO tasks (id, org_id, title, due_date, contact_id, deal_id, priority, status, assigned_owner, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .run(taskId, orgId, tmpl.title, dueDate, null, tmpl.deal_id||null, 'Medium', 'Open', tmpl.assigned_to||'', now);
        db.prepare('UPDATE recurring_task_templates SET last_generated_at=? WHERE id=?').run(now, tmpl.id);
        auditLog(orgId, userId, userName, 'task', taskId, tmpl.title, 'created', null, null, 'recurring');
        created.push({ id: taskId, title: tmpl.title, dueDate });
      } catch(e) { /* non-fatal */ }
    }
  });

  res.json({ generated: created.length, tasks: created });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 22: Deal Health Scoring ────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function computeDealHealthScore(deal, orgId) {
  let total = 0;
  const breakdown = {};
  const now = Date.now();

  // 1. Lead score from contact (20 pts)
  let leadPts = 0;
  if (deal.contact_id) {
    const contact = db.prepare('SELECT * FROM contacts WHERE id=?').get(deal.contact_id);
    if (contact) {
      // Calculate lead score inline (matches Phase 15 scoring logic)
      let ls = 0;
      const la = contact.last_activity;
      if (la) { const daysAgo = (now - la) / 86400000; if (daysAgo < 7) ls += 30; else if (daysAgo < 30) ls += 15; else if (daysAgo < 90) ls += 5; }
      if (contact.email) ls += 10; if (contact.phone) ls += 5; if (contact.company_id) ls += 5;
      const stage = contact.stage || 'Lead';
      const stageMap = { 'Lead':5, 'Qualified':20, 'Prospect':30, 'Customer':40, 'Churned':0 };
      ls += stageMap[stage] || 5;
      const tags = safeJSON(contact.tags, []);
      if (tags.length > 0) ls += Math.min(tags.length * 5, 15);
      const actCount = db.prepare('SELECT COUNT(*) as c FROM activities WHERE contact_id=?').get(contact.id)?.c || 0;
      ls += Math.min(actCount * 5, 20);
      if (ls > 100) ls = 100;
      leadPts = Math.round((ls / 100) * 20);
    }
  }
  breakdown.leadScore = leadPts;
  total += leadPts;

  // 2. Activity recency — last 14 days (20 pts)
  const recentActs = db.prepare("SELECT COUNT(*) as c FROM activities WHERE deal_id=? AND created_at > ?").get(deal.id, now - 14 * 86400000)?.c || 0;
  let actPts = 0;
  if (recentActs >= 3) actPts = 20;
  else if (recentActs >= 1) actPts = 12;
  else actPts = 0;
  breakdown.activityRecency = actPts;
  total += actPts;

  // 3. Deal age vs avg cycle (15 pts)
  let agePts = 0;
  const dealAgeMs = now - (deal.created_at || now);
  const dealAgeDays = Math.max(0, dealAgeMs / 86400000);
  // Compute avg closed deal cycle (filter out invalid/negative cycles)
  const closedDeals = db.prepare("SELECT created_at, moved_at FROM deals WHERE org_id=? AND stage='Won' AND moved_at IS NOT NULL").all(orgId);
  let avgDays = 90; // default
  const validCycles = closedDeals
    .map(cd => (cd.moved_at - cd.created_at) / 86400000)
    .filter(days => days > 0 && days < 3650); // only sane values (0-10 years)
  if (validCycles.length > 0) {
    avgDays = validCycles.reduce((s, d) => s + d, 0) / validCycles.length;
  }
  if (dealAgeDays <= avgDays * 0.5) agePts = 15;
  else if (dealAgeDays <= avgDays) agePts = 10;
  else if (dealAgeDays <= avgDays * 1.5) agePts = 5;
  else agePts = 0;
  breakdown.dealAge = agePts;
  total += agePts;

  // 4. Proposal status — sent/signed boosts (15 pts)
  let propPts = 0;
  const proposal = db.prepare('SELECT status, signed_at FROM proposals WHERE deal_id=? ORDER BY created_at DESC LIMIT 1').get(deal.id);
  if (proposal) {
    if (proposal.signed_at || proposal.status === 'Signed') propPts = 15;
    else if (proposal.status === 'Sent' || proposal.status === 'Viewed') propPts = 10;
    else propPts = 5;
  }
  breakdown.proposalStatus = propPts;
  total += propPts;

  // 5. SLA compliance — not breaching (15 pts)
  let slaPts = 15;
  try {
    const slaSettings = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slaLimits'").get(orgId);
    if (slaSettings) {
      const slaLimits = safeJSON(slaSettings.value, {});
      const stageLimit = slaLimits[deal.stage];
      if (stageLimit) {
        const stageLogs = db.prepare('SELECT * FROM deal_stage_log WHERE deal_id=? AND stage=? AND exited_at IS NULL ORDER BY entered_at DESC LIMIT 1').all(deal.id, deal.stage);
        if (stageLogs.length) {
          const daysInCurrentStage = (now - stageLogs[0].entered_at) / 86400000;
          if (daysInCurrentStage > stageLimit) slaPts = 0;
          else if (daysInCurrentStage > stageLimit * 0.8) slaPts = 7;
        }
      }
    }
  } catch(e) { /* non-fatal */ }
  breakdown.slaCompliance = slaPts;
  total += slaPts;

  // 6. Time tracking — any hours logged (15 pts)
  let timePts = 0;
  const timeEntries = db.prepare('SELECT SUM(hours) as h FROM time_entries WHERE deal_id=?').get(deal.id);
  const totalHours = timeEntries?.h || 0;
  if (totalHours >= 10) timePts = 15;
  else if (totalHours >= 2) timePts = 10;
  else if (totalHours > 0) timePts = 5;
  breakdown.timeTracking = timePts;
  total += timePts;

  const label = total >= 70 ? 'Healthy' : total >= 40 ? 'At Risk' : 'Critical';
  return { score: total, label, breakdown, dealId: deal.id, dealName: deal.name, stage: deal.stage, value: deal.value, owner: deal.owner };
}

app.get('/api/deal-health-scores', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const openDeals = db.prepare("SELECT * FROM deals WHERE org_id=? AND stage NOT IN ('Won','Lost') ORDER BY created_at DESC").all(orgId);
  const scores = openDeals.map(d => computeDealHealthScore(d, orgId));
  scores.sort((a, b) => b.score - a.score);
  res.json(scores);
});

app.get('/api/deals/:id/health-score', requireAuth, (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(req.params.id, req.user.orgId);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  res.json(computeDealHealthScore(deal, req.user.orgId));
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 22: Bulk Deal Operations ───────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.post('/api/deals-bulk-edit', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { dealIds, field, value } = req.body;
  if (!dealIds || !Array.isArray(dealIds) || !field) return res.status(400).json({ error: 'dealIds and field required' });

  const allowedFields = ['stage', 'owner', 'close_date'];
  const fieldMap = { stage: 'stage', owner: 'owner', closeDate: 'close_date', close_date: 'close_date' };
  const col = fieldMap[field];
  if (!col) return res.status(400).json({ error: 'Invalid field' });

  const updated = [];
  db.transaction(() => {
    dealIds.forEach(id => {
      const before = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(id, orgId);
      if (!before) return;
      const oldVal = before[col];
      db.prepare(`UPDATE deals SET ${col}=?, moved_at=? WHERE id=? AND org_id=?`).run(value, Date.now(), id, orgId);
      auditLog(orgId, userId, userName, 'deal', id, before.name, 'bulk_updated', col, oldVal, value);
      // Stage log if stage changed
      if (col === 'stage' && before.stage !== value) {
        try {
          const now = Date.now();
          db.prepare('UPDATE deal_stage_log SET exited_at=? WHERE deal_id=? AND org_id=? AND exited_at IS NULL').run(now, id, orgId);
          db.prepare('INSERT INTO deal_stage_log (id, org_id, deal_id, stage, entered_at) VALUES (?, ?, ?, ?, ?)').run('dsl_' + uid(), orgId, id, value, now);
        } catch(e) {}
      }
      updated.push(id);
    });
  })();
  res.json({ updated: updated.length, ids: updated });
});

app.post('/api/deals-bulk-delete', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { dealIds } = req.body;
  if (!dealIds || !Array.isArray(dealIds)) return res.status(400).json({ error: 'dealIds required' });

  const deleted = [];
  db.transaction(() => {
    dealIds.forEach(id => {
      const before = db.prepare('SELECT name FROM deals WHERE id=? AND org_id=?').get(id, orgId);
      if (!before) return;
      db.prepare('DELETE FROM deals WHERE id=? AND org_id=?').run(id, orgId);
      auditLog(orgId, userId, userName, 'deal', id, before.name, 'bulk_deleted');
      deleted.push(id);
    });
  })();
  res.json({ deleted: deleted.length, ids: deleted });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 22: Client-Facing Invoice Portal ───────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// Extend portal-v2 GET to include invoices (patch of existing handler above)
// We add a separate endpoint to keep things clean
app.get('/api/portal-v2/:token/invoices', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const invoices = db.prepare('SELECT id, number, status, total, issue_date, due_date, items, notes FROM invoices WHERE deal_id=? ORDER BY created_at DESC').all(deal.id);
  const reviews = db.prepare('SELECT invoice_id FROM portal_invoice_reviews WHERE deal_id=?').all(deal.id).map(r => r.invoice_id);
  res.json(invoices.map(inv => ({
    id: inv.id, number: inv.number, status: inv.status, total: inv.total,
    issueDate: inv.issue_date, dueDate: inv.due_date,
    items: safeJSON(inv.items, []), notes: inv.notes,
    reviewed: reviews.includes(inv.id)
  })));
});

app.post('/api/portal-v2/:token/invoice/:invoiceId/reviewed', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const invoice = db.prepare('SELECT * FROM invoices WHERE id=? AND deal_id=?').get(req.params.invoiceId, deal.id);
  if (!invoice) return res.status(404).json({ error: 'Invoice not found' });

  // Check if already reviewed
  const existing = db.prepare('SELECT id FROM portal_invoice_reviews WHERE invoice_id=? AND deal_id=?').get(req.params.invoiceId, deal.id);
  if (existing) { return res.json({ ok: true, alreadyReviewed: true }); }

  const id = 'pir_' + uid();
  db.prepare('INSERT INTO portal_invoice_reviews (id, org_id, invoice_id, deal_id, token, reviewed_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, deal.org_id, req.params.invoiceId, deal.id, req.params.token, Date.now(), Date.now());
  // Update invoice status to "Reviewed" (keep original status for accounting, just flag)
  try {
    // Add portal_comment about review
    db.prepare('INSERT INTO portal_comments (id, org_id, deal_id, token, author_name, body, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run('pc_' + uid(), deal.org_id, deal.id, req.params.token, 'Client', `Invoice ${invoice.number} marked as Reviewed`, Date.now());
  } catch(e) {}
  res.json({ ok: true, reviewedAt: Date.now() });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 22: Referral Stats ─────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/referral-stats', requireAuth, (req, res) => {
  const { orgId } = req.user;
  // Find all contacts who referred others (referred_by is set)
  const contacts = db.prepare('SELECT * FROM contacts WHERE org_id=?').all(orgId);
  const deals = db.prepare("SELECT * FROM deals WHERE org_id=?").all(orgId);

  // Build referral map: referrer_id -> list of contact_ids they referred
  const referralMap = {};
  contacts.forEach(c => {
    const refById = c.referred_by || c.referred_by_contact_id;
    if (refById) {
      if (!referralMap[refById]) referralMap[refById] = [];
      referralMap[refById].push(c.id);
    }
  });

  const result = Object.entries(referralMap).map(([referrerId, referredIds]) => {
    const referrer = contacts.find(c => c.id === referrerId);
    // Total deal value from referred contacts
    const totalDealValue = referredIds.reduce((sum, cid) => {
      const cDeals = deals.filter(d => d.contact_id === cid);
      return sum + cDeals.reduce((s, d) => s + (d.value || 0), 0);
    }, 0);
    const wonValue = referredIds.reduce((sum, cid) => {
      const wonDeals = deals.filter(d => d.contact_id === cid && d.stage === 'Won');
      return sum + wonDeals.reduce((s, d) => s + (d.value || 0), 0);
    }, 0);
    return {
      referrerId,
      referrerName: referrer ? referrer.name : 'Unknown',
      referralCount: referredIds.length,
      referredContactIds: referredIds,
      totalDealValue,
      wonDealValue: wonValue
    };
  }).sort((a, b) => b.referralCount - a.referralCount);

  res.json(result);
});

app.get('/api/contacts/:id/referral-chain', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!contact) return res.status(404).json({ error: 'Not found' });

  // Who referred this contact
  const refById = contact.referred_by || contact.referred_by_contact_id;
  const referredBy = refById ? db.prepare('SELECT id, name, email FROM contacts WHERE id=? AND org_id=?').get(refById, orgId) : null;

  // Who has this contact referred
  const referredContacts = db.prepare("SELECT id, name, email, stage FROM contacts WHERE (referred_by=? OR referred_by_contact_id=?) AND org_id=?").all(contact.id, contact.id, orgId);

  res.json({ referredBy, referredContacts });
});

// ── Phase 22: Email Inbox Integration ──────────────────────────────────────

function generateMockEmails(orgId, count = 15) {
  const senders = [
    { name: 'Sarah Mitchell',  email: 'sarah.mitchell@acmecorp.com'    },
    { name: 'James Harlow',    email: 'james.harlow@vertexlabs.io'     },
    { name: 'Lena Vogel',      email: 'l.vogel@globaltech.de'          },
    { name: 'David Kim',       email: 'd.kim@brighthorizon.com'        },
    { name: 'Priya Nair',      email: 'priya.nair@nexusventures.co'    },
    { name: 'Tom Bauer',       email: 'tbauer@ironclad.net'            },
    { name: 'Ana Costa',       email: 'ana@cloudpeak.com'              },
    { name: 'Michael Scott',   email: 'm.scott@dundermifflin.com'      },
  ];
  const subjects = [
    'Re: Proposal for Q2 project',
    'Follow-up from our call',
    'Question about pricing tiers',
    'Contract review - please advise',
    'Ready to move forward',
    'Need a few clarifications',
    'Updated requirements document',
    'Checking in on timeline',
    'Decision coming next week',
    'Can we schedule a demo?',
    'Thank you for the presentation',
    'Integration questions',
    'Executive sign-off received',
    'Renewal discussion - early next month',
    'Invoice received, processing payment',
  ];
  const bodies = [
    'Hi, just wanted to follow up on the proposal we discussed last week. Can we schedule a call to go over the details?',
    'Thanks for your time today. I shared your proposal with my team and we have a few questions.',
    'Could you clarify the pricing for the enterprise tier? We are evaluating multiple vendors.',
    'I have reviewed the contract and have a few comments. Please see attached.',
    'Great news - we are ready to proceed. Please send over the final paperwork.',
    'A couple of things I need cleared up before we can move forward.',
    'Attached please find the updated requirements from our engineering team.',
    'What does the implementation timeline look like? We need to plan for Q3.',
    'We expect to have a decision for you by end of next week.',
    'Would it be possible to arrange a live demo for our VP of Operations?',
  ];

  const now = Date.now();
  const DAY = 86400000;
  return Array.from({ length: count }, (_, i) => {
    const sender  = senders[i % senders.length];
    const subject = subjects[i % subjects.length];
    const body    = bodies[i % bodies.length];
    return {
      id:          uid(),
      org_id:      orgId,
      message_uid: `mock-${Date.now()}-${i}`,
      from_email:  sender.email,
      from_name:   sender.name,
      to_email:    'inbox@boredroom.com',
      subject,
      body_text:   body,
      received_at: now - (i * DAY * 0.7),
      read_at:     i > 3 ? now - (i * DAY * 0.5) : null,
      linked_contact_id: null,
      linked_deal_id:    null,
      activity_logged:   0,
      created_at:  Date.now(),
    };
  });
}

// GET /api/email/config — returns current email config (no password)
app.get('/api/email/config', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const row = db.prepare('SELECT id, org_id, host, port, email, mock_mode, enabled, last_synced, created_at FROM email_inbox_config WHERE org_id=?').get(orgId);
  res.json(row || null);
});

// POST /api/email/connect — save IMAP config
app.post('/api/email/connect', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { host, port, email, password, mock_mode } = req.body;
  
  const now = Date.now();

  const existing = db.prepare('SELECT id FROM email_inbox_config WHERE org_id=?').get(orgId);
  if (existing) {
    db.prepare(`UPDATE email_inbox_config SET host=?, port=?, email=?, ${password ? 'password=?,' : ''} mock_mode=?, enabled=1, updated_at=? WHERE org_id=?`)
      .run(...(password ? [host, port || 993, email, password, mock_mode ? 1 : 0, now, orgId] : [host, port || 993, email, mock_mode ? 1 : 0, now, orgId]));
  } else {
    db.prepare('INSERT INTO email_inbox_config (id, org_id, host, port, email, password, mock_mode, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)')
      .run(uid(), orgId, host || null, port || 993, email || null, password || null, mock_mode ? 1 : 0, now, now);
  }
  const saved = db.prepare('SELECT id, org_id, host, port, email, mock_mode, enabled, last_synced, created_at FROM email_inbox_config WHERE org_id=?').get(orgId);
  res.json({ success: true, config: saved });
});

// POST /api/email/sync — sync inbox (mock or real; no external deps = mock only)
app.post('/api/email/sync', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const config = db.prepare('SELECT * FROM email_inbox_config WHERE org_id=?').get(orgId);

  // Always use mock data (no external IMAP library; real IMAP left for future phase)
  const existingCount = db.prepare('SELECT COUNT(*) as c FROM email_inbox_messages WHERE org_id=?').get(orgId).c;
  let inserted = 0;

  if (existingCount === 0) {
    const mocks = generateMockEmails(orgId, 15);
    const ins = db.prepare(`INSERT OR IGNORE INTO email_inbox_messages
      (id, org_id, message_uid, from_email, from_name, to_email, subject, body_text, received_at, read_at, linked_contact_id, linked_deal_id, activity_logged, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    // Auto-match contacts by email address
    const contacts = db.prepare('SELECT id, email FROM contacts WHERE org_id=? AND email IS NOT NULL').all(orgId);
    const emailMap = {};
    contacts.forEach(c => { if (c.email) emailMap[c.email.toLowerCase()] = c.id; });

    const stmt = db.transaction(() => {
      mocks.forEach(m => {
        const contactId = emailMap[m.from_email.toLowerCase()] || null;
        ins.run(m.id, m.org_id, m.message_uid, m.from_email, m.from_name, m.to_email,
          m.subject, m.body_text, m.received_at, m.read_at,
          contactId, m.linked_deal_id, m.activity_logged, m.created_at);
        inserted++;
      });
    });
    stmt();
  }

  // Update last_synced
  if (config) {
    db.prepare('UPDATE email_inbox_config SET last_synced=? WHERE org_id=?').run(Date.now(), orgId);
  } else {
    // Auto-create mock config if none exists
    
    db.prepare('INSERT OR IGNORE INTO email_inbox_config (id, org_id, mock_mode, enabled, last_synced, created_at, updated_at) VALUES (?, ?, 1, 1, ?, ?, ?)')
      .run(uid(), orgId, Date.now(), Date.now(), Date.now());
  }

  const total = db.prepare('SELECT COUNT(*) as c FROM email_inbox_messages WHERE org_id=?').get(orgId).c;
  res.json({ success: true, inserted, total, mode: 'mock' });
});

// GET /api/email/inbox — list synced messages
app.get('/api/email/inbox', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { search, unread, limit = 50, offset = 0 } = req.query;
  let sql = 'SELECT m.*, c.name as contact_name FROM email_inbox_messages m LEFT JOIN contacts c ON c.id=m.linked_contact_id WHERE m.org_id=?';
  const params = [orgId];
  if (unread === '1') { sql += ' AND m.read_at IS NULL'; }
  if (search) { sql += ' AND (m.subject LIKE ? OR m.from_name LIKE ? OR m.from_email LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  sql += ' ORDER BY m.received_at DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));
  const messages = db.prepare(sql).all(...params);
  const unreadCount = db.prepare('SELECT COUNT(*) as c FROM email_inbox_messages WHERE org_id=? AND read_at IS NULL').get(orgId).c;
  res.json({ messages, unreadCount, total: messages.length });
});

// GET /api/email/inbox/:id — single message + mark read
app.get('/api/email/inbox/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const msg = db.prepare('SELECT m.*, c.name as contact_name FROM email_inbox_messages m LEFT JOIN contacts c ON c.id=m.linked_contact_id WHERE m.id=? AND m.org_id=?').get(req.params.id, orgId);
  if (!msg) return res.status(404).json({ error: 'Not found' });
  if (!msg.read_at) {
    db.prepare('UPDATE email_inbox_messages SET read_at=? WHERE id=?').run(Date.now(), req.params.id);
    msg.read_at = Date.now();
  }
  res.json(msg);
});

// POST /api/email/inbox/:id/link-contact — link message to contact + log activity
app.post('/api/email/inbox/:id/link-contact', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contactId } = req.body;
  const msg = db.prepare('SELECT * FROM email_inbox_messages WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!msg) return res.status(404).json({ error: 'Not found' });

  db.prepare('UPDATE email_inbox_messages SET linked_contact_id=?, activity_logged=0 WHERE id=?').run(contactId, req.params.id);

  // Log as email activity
  if (!msg.activity_logged) {
    
    db.prepare(`INSERT INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at)
      VALUES (?, ?, 'email', ?, ?, ?, ?, ?)`)
      .run(uid(), orgId, contactId, msg.linked_deal_id || null,
        `Inbound email: ${msg.subject || '(no subject)'}\n\nFrom: ${msg.from_name || ''} <${msg.from_email}>\n\n${msg.body_text || ''}`,
        msg.received_at, Date.now());
    db.prepare('UPDATE email_inbox_messages SET activity_logged=1 WHERE id=?').run(req.params.id);
  }

  const updated = db.prepare('SELECT m.*, c.name as contact_name FROM email_inbox_messages m LEFT JOIN contacts c ON c.id=m.linked_contact_id WHERE m.id=?').get(req.params.id);
  res.json({ success: true, message: updated });
});

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 23: Pipeline Automation / Workflow Triggers ────────────────────
// ══════════════════════════════════════════════════════════════════════════

// ── Internal: execute workflow rules for an event ──────────────────────────
async function executeWorkflowRules(triggerEvent, entityType, entity, orgId) {
  try {
    const http = require('http');
    const rules = db.prepare(
      "SELECT * FROM workflow_rules WHERE org_id=? AND active=1 AND (trigger_event=? OR trigger_event IS NULL)"
    ).all(orgId, triggerEvent);

    for (const rule of rules) {
      const actions = safeJSON(rule.actions, []);
      const condition = safeJSON(rule.trigger_condition || rule.trigger_stage || '{}', {});
      let conditionMet = true;

      // Evaluate condition for deal_stage_change
      if (triggerEvent === 'deal_stage_change' && condition.stage) {
        conditionMet = entity.stage === condition.stage;
      }
      // For deal_created / contact_created: always fire if condition is empty
      if (!conditionMet) continue;

      let status = 'success', errorMsg = null;
      try {
        for (const action of actions) {
          if (action.type === 'create_task') {
            const dueOffset = parseInt(action.dueOffset || 1, 10);
            const dueDate = new Date(Date.now() + dueOffset * 86400000).toISOString().slice(0, 10);
            db.prepare(`INSERT INTO tasks (id, org_id, title, due_date, contact_id, deal_id, priority, status, assigned_owner, created_at)
              VALUES (?, ?, ?, ?, ?, ?, 'Medium', 'Open', ?, ?)`).run(
              'wftsk_' + uid(), orgId,
              action.title || 'Follow-up Task',
              dueDate,
              entityType === 'contact' ? entity.id : (entity.contact_id || null),
              entityType === 'deal' ? entity.id : null,
              action.assignee || '',
              Date.now()
            );
          } else if (action.type === 'log_activity') {
            db.prepare(`INSERT INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
              .run('wfact_' + uid(), orgId,
                action.activityType || 'Note',
                entityType === 'contact' ? entity.id : (entity.contact_id || null),
                entityType === 'deal' ? entity.id : null,
                action.note || `Workflow: ${rule.name}`,
                new Date().toISOString(), Date.now());
          } else if (action.type === 'send_webhook') {
            const url = action.webhookUrl;
            if (url) {
              try {
                const payload = JSON.stringify({ event: triggerEvent, rule: rule.name, entity, entityType, timestamp: Date.now() });
                const urlObj = new URL(url);
                const reqOpts = {
                  hostname: urlObj.hostname, port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
                  path: urlObj.pathname + urlObj.search, method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
                };
                await new Promise((resolve) => {
                  const req = http.request(reqOpts, (r) => { r.resume(); resolve(); });
                  req.on('error', () => resolve());
                  req.setTimeout(5000, () => { req.destroy(); resolve(); });
                  req.write(payload); req.end();
                });
              } catch(e) { /* webhook errors are non-fatal */ }
            }
          } else if (action.type === 'update_deal_field') {
            if (entityType === 'deal' && action.field && action.value !== undefined) {
              const allowed = ['stage', 'owner', 'close_date', 'notes'];
              if (allowed.includes(action.field)) {
                db.prepare(`UPDATE deals SET ${action.field}=? WHERE id=? AND org_id=?`).run(action.value, entity.id, orgId);
              }
            }
          }
        }
      } catch(e) {
        status = 'error'; errorMsg = e.message;
      }

      // Log execution
      try {
        db.prepare(`INSERT INTO workflow_executions (id, org_id, rule_id, trigger_event, entity_type, entity_id, entity_name, status, error, executed_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
          'wfe_' + uid(), orgId, rule.id, triggerEvent,
          entityType, entity.id || '', entity.name || entity.title || '',
          status, errorMsg, Date.now()
        );
      } catch(e) {}
    }
  } catch(e) {
    // Non-fatal
  }
}

// GET /api/workflow-rules
app.get('/api/workflow-rules', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM workflow_rules WHERE org_id=? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(r => ({
    id: r.id, name: r.name, triggerEvent: r.trigger_event || 'deal_stage_change',
    triggerCondition: safeJSON(r.trigger_condition || r.trigger_stage || '{}', {}),
    actions: safeJSON(r.actions, []),
    active: Boolean(r.active), createdAt: r.created_at
  })));
});

// POST /api/workflow-rules
app.post('/api/workflow-rules', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { name, triggerEvent, triggerCondition, actions, active } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const id = 'wfr_' + uid();
  db.prepare(`INSERT INTO workflow_rules (id, org_id, name, trigger_event, trigger_condition, trigger_stage, actions, active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, name,
    triggerEvent || 'deal_stage_change',
    JSON.stringify(triggerCondition || {}),
    triggerCondition?.stage || '',
    JSON.stringify(actions || []),
    active !== false ? 1 : 0,
    Date.now()
  );
  res.status(201).json({ id, name, triggerEvent, triggerCondition, actions, active: active !== false });
});

// PUT /api/workflow-rules/:id
app.put('/api/workflow-rules/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { name, triggerEvent, triggerCondition, actions, active } = req.body;
  const result = db.prepare(`UPDATE workflow_rules SET name=?, trigger_event=?, trigger_condition=?, trigger_stage=?, actions=?, active=? WHERE id=? AND org_id=?`)
    .run(name, triggerEvent || 'deal_stage_change', JSON.stringify(triggerCondition || {}),
      triggerCondition?.stage || '', JSON.stringify(actions || []), active ? 1 : 0, req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// DELETE /api/workflow-rules/:id
app.delete('/api/workflow-rules/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM workflow_rules WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// GET /api/workflow-rules/:id/executions
app.get('/api/workflow-rules/:id/executions', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM workflow_executions WHERE org_id=? AND rule_id=? ORDER BY executed_at DESC LIMIT 10').all(req.user.orgId, req.params.id);
  res.json(rows);
});

// Note: workflow execution hooks are added directly to the deal PUT, deal POST,
// and contact POST route handlers above (search for "Phase 23" comments).

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 23: Contact Scoring Automation ─────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

function computeContactScore(contact, orgId) {
  const rules = db.prepare('SELECT * FROM scoring_rules WHERE org_id=? ORDER BY created_at ASC').all(orgId);
  const breakdown = [];
  let total = 0;

  // Get deal count for contact
  const dealCount = db.prepare('SELECT COUNT(*) as c FROM deals WHERE contact_id=? AND org_id=?').get(contact.id, orgId)?.c || 0;
  // Get last activity
  const lastActRow = db.prepare('SELECT MAX(created_at) as la FROM activities WHERE contact_id=? AND org_id=?').get(contact.id, orgId);
  const lastActivity = lastActRow?.la || contact.last_activity || null;
  const daysSinceActivity = lastActivity ? Math.floor((Date.now() - lastActivity) / 86400000) : 9999;

  for (const rule of rules) {
    let fieldValue = null;
    const f = rule.field;
    if (f === 'title')      fieldValue = contact.title || '';
    else if (f === 'stage') fieldValue = contact.stage || '';
    else if (f === 'tags')  fieldValue = safeJSON(contact.tags, []).join(',');
    else if (f === 'email') fieldValue = contact.email || '';
    else if (f === 'deal_count') fieldValue = dealCount;
    else if (f === 'days_since_activity') fieldValue = daysSinceActivity;
    else fieldValue = contact[f] || '';

    let matched = false;
    const ruleVal = rule.value;
    const fvStr = String(fieldValue).toLowerCase();
    const rvStr = String(ruleVal).toLowerCase();

    if (rule.operator === 'equals')        matched = fvStr === rvStr;
    else if (rule.operator === 'contains') matched = fvStr.includes(rvStr);
    else if (rule.operator === 'greater_than') matched = parseFloat(fieldValue) > parseFloat(ruleVal);
    else if (rule.operator === 'less_than')    matched = parseFloat(fieldValue) < parseFloat(ruleVal);
    else if (rule.operator === 'not_empty')    matched = !!fieldValue && fvStr !== '';
    else if (rule.operator === 'is_empty')     matched = !fieldValue || fvStr === '';

    if (matched) {
      total += rule.points;
      breakdown.push({ ruleId: rule.id, label: rule.label || `${f} ${rule.operator} "${ruleVal}"`, field: f, points: rule.points, matched: true });
    }
  }

  // Clamp to 0-100
  const clamped = Math.max(0, Math.min(100, total));
  return { score: clamped, rawScore: total, breakdown };
}

// GET /api/scoring-rules
app.get('/api/scoring-rules', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM scoring_rules WHERE org_id=? ORDER BY created_at ASC').all(req.user.orgId);
  res.json(rows.map(r => ({ id: r.id, field: r.field, operator: r.operator, value: r.value, points: r.points, label: r.label, createdAt: r.created_at })));
});

// POST /api/scoring-rules
app.post('/api/scoring-rules', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { field, operator, value, points, label } = req.body;
  if (!field || !operator) return res.status(400).json({ error: 'field and operator required' });
  const id = 'sr_' + uid();
  db.prepare('INSERT INTO scoring_rules (id, org_id, field, operator, value, points, label, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, orgId, field, operator, value || '', parseInt(points) || 0, label || '', Date.now());
  res.status(201).json({ id, field, operator, value, points, label });
});

// PUT /api/scoring-rules/:id
app.put('/api/scoring-rules/:id', requireAuth, (req, res) => {
  const { field, operator, value, points, label } = req.body;
  const result = db.prepare('UPDATE scoring_rules SET field=?, operator=?, value=?, points=?, label=? WHERE id=? AND org_id=?')
    .run(field, operator, value || '', parseInt(points) || 0, label || '', req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// DELETE /api/scoring-rules/:id
app.delete('/api/scoring-rules/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM scoring_rules WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// GET /api/contacts/:id/score-breakdown
app.get('/api/contacts/:id/score-breakdown', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!contact) return res.status(404).json({ error: 'Not found' });
  const result = computeContactScore(contact, orgId);
  // Update the lead score in contacts table (if contacts table has leadScore column — it doesn't natively, use custom_fields)
  // Store in a special setting or just return
  res.json(result);
});

// POST /api/scoring-rules/recalculate-all
app.post('/api/scoring-rules/recalculate-all', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contacts = db.prepare('SELECT * FROM contacts WHERE org_id=?').all(orgId);
  let updated = 0;
  for (const contact of contacts) {
    const { score } = computeContactScore(contact, orgId);
    // Store score in custom_fields JSON
    try {
      const cf = safeJSON(contact.custom_fields, {});
      cf.__leadScore = score;
      db.prepare('UPDATE contacts SET custom_fields=? WHERE id=?').run(JSON.stringify(cf), contact.id);
      updated++;
    } catch(e) {}
  }
  res.json({ updated, total: contacts.length });
});

// Patch contact GET to auto-compute score
app.get('/api/contacts/:id/auto-score', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!contact) return res.status(404).json({ error: 'Not found' });
  const result = computeContactScore(contact, orgId);
  try {
    const cf = safeJSON(contact.custom_fields, {});
    cf.__leadScore = result.score;
    db.prepare('UPDATE contacts SET custom_fields=? WHERE id=?').run(JSON.stringify(cf), contact.id);
  } catch(e) {}
  res.json(result);
});

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 23: Multi-Currency & Localization ───────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// GET /api/currencies
app.get('/api/currencies', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM currencies WHERE org_id=? ORDER BY code ASC').all(req.user.orgId);
  res.json(rows.map(r => ({ id: r.id, code: r.code, symbol: r.symbol, name: r.name, rate: r.exchange_rate_to_usd, active: Boolean(r.active), createdAt: r.created_at })));
});

// POST /api/currencies — add new currency
app.post('/api/currencies', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { code, symbol, name, rate } = req.body;
  if (!code || !symbol || !name) return res.status(400).json({ error: 'code, symbol, name required' });
  const id = 'cur_' + uid();
  try {
    db.prepare('INSERT INTO currencies (id, org_id, code, symbol, name, exchange_rate_to_usd, active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)')
      .run(id, orgId, code.toUpperCase(), symbol, name, parseFloat(rate) || 1.0, Date.now());
  } catch(e) {
    return res.status(400).json({ error: 'Currency code already exists for this org' });
  }
  res.status(201).json({ id, code: code.toUpperCase(), symbol, name, rate: parseFloat(rate) || 1.0, active: true });
});

// PUT /api/currencies/:id
app.put('/api/currencies/:id', requireAuth, (req, res) => {
  const { symbol, name, rate, active } = req.body;
  const result = db.prepare('UPDATE currencies SET symbol=?, name=?, exchange_rate_to_usd=?, active=? WHERE id=? AND org_id=?')
    .run(symbol, name, parseFloat(rate) || 1.0, active ? 1 : 0, req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// DELETE /api/currencies/:id
app.delete('/api/currencies/:id', requireAuth, (req, res) => {
  // Soft delete (set active=0) for safety
  const result = db.prepare('UPDATE currencies SET active=0 WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 23: Deal Room Enhancements ─────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// PUT /api/deals/:id/video-call — update video call info
app.put('/api/deals/:id/video-call', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { videoCallUrl, videoCallTime } = req.body;
  const result = db.prepare('UPDATE deals SET video_call_url=?, video_call_time=? WHERE id=? AND org_id=?')
    .run(videoCallUrl || null, videoCallTime || null, req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true, videoCallUrl, videoCallTime });
});

// GET /api/deals/:id/video-call
app.get('/api/deals/:id/video-call', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deal = db.prepare('SELECT video_call_url, video_call_time FROM deals WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  res.json({ videoCallUrl: deal.video_call_url || null, videoCallTime: deal.video_call_time || null });
});

// Portal view logging: add to portal-v2 GET
// We extend the existing handler via middleware
app.use('/api/portal-v2/:token', (req, res, next) => {
  if (req.method !== 'GET') return next();
  try {
    const deal = db.prepare('SELECT id, org_id FROM deals WHERE portal_token=?').get(req.params.token);
    if (deal) {
      // Hash the IP for privacy
      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.connection?.remoteAddress || '';
      const crypto = require('crypto');
      const ipHash = crypto.createHash('sha256').update(ip).digest('hex').slice(0, 16);
      db.prepare('INSERT INTO portal_views (id, org_id, deal_id, token, ip_hash, viewed_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run('pv_' + uid(), deal.org_id, deal.id, req.params.token, ipHash, Date.now());
    }
  } catch(e) { /* non-fatal */ }
  next();
});

// GET /api/deals/:id/portal-analytics
app.get('/api/deals/:id/portal-analytics', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deal = db.prepare('SELECT id, portal_token FROM deals WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  if (!deal.portal_token) return res.json({ totalViews: 0, uniqueVisitors: 0, lastViewed: null, trendByDay: [] });

  const views = db.prepare('SELECT * FROM portal_views WHERE deal_id=? ORDER BY viewed_at DESC').all(deal.id);
  const totalViews = views.length;
  const uniqueVisitors = new Set(views.map(v => v.ip_hash)).size;
  const lastViewed = views.length > 0 ? views[0].viewed_at : null;

  // Trend: last 7 days
  const now = Date.now();
  const trendByDay = [];
  for (let i = 6; i >= 0; i--) {
    const dayStart = now - i * 86400000 - (now % 86400000);
    const dayEnd = dayStart + 86400000;
    const label = new Date(dayStart).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    const count = views.filter(v => v.viewed_at >= dayStart && v.viewed_at < dayEnd).length;
    trendByDay.push({ label, count });
  }

  res.json({ totalViews, uniqueVisitors, lastViewed, trendByDay });
});

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 23: Duplicate Detection & Data Hygiene ─────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// GET /api/hygiene/contact-duplicates
app.get('/api/hygiene/contact-duplicates', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contacts = db.prepare('SELECT * FROM contacts WHERE org_id=? ORDER BY name ASC').all(orgId);

  const duplicateSets = [];
  const seen = new Set();

  // Email duplicates
  const emailMap = {};
  contacts.forEach(c => {
    if (c.email) {
      const key = c.email.toLowerCase().trim();
      if (!emailMap[key]) emailMap[key] = [];
      emailMap[key].push(c);
    }
  });
  Object.values(emailMap).forEach(group => {
    if (group.length > 1) {
      const ids = group.map(c => c.id).sort().join('|');
      if (!seen.has(ids)) {
        seen.add(ids);
        duplicateSets.push({ reason: 'Matching email', contacts: group.map(rowToContact) });
      }
    }
  });

  // Name similarity duplicates (fuzzy: first 5 chars match)
  const nameMap = {};
  contacts.forEach(c => {
    if (c.name) {
      const key = c.name.toLowerCase().trim().slice(0, 5);
      if (!nameMap[key]) nameMap[key] = [];
      nameMap[key].push(c);
    }
  });
  Object.values(nameMap).forEach(group => {
    if (group.length > 1) {
      // Filter pairs that aren't already caught by email
      const pairs = [];
      for (let i = 0; i < group.length; i++) {
        for (let j = i + 1; j < group.length; j++) {
          const ids = [group[i].id, group[j].id].sort().join('|');
          if (!seen.has(ids)) {
            seen.add(ids);
            pairs.push([group[i], group[j]]);
          }
        }
      }
      pairs.forEach(([a, b]) => {
        duplicateSets.push({ reason: 'Similar name', contacts: [rowToContact(a), rowToContact(b)] });
      });
    }
  });

  res.json(duplicateSets.slice(0, 50));
});

// GET /api/hygiene/company-duplicates
app.get('/api/hygiene/company-duplicates', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const companies = db.prepare('SELECT * FROM companies WHERE org_id=? ORDER BY name ASC').all(orgId);

  const duplicateSets = [];
  const seen = new Set();

  // Name similarity
  const nameMap = {};
  companies.forEach(c => {
    if (c.name) {
      const key = c.name.toLowerCase().trim().slice(0, 6);
      if (!nameMap[key]) nameMap[key] = [];
      nameMap[key].push(c);
    }
  });
  Object.values(nameMap).forEach(group => {
    if (group.length > 1) {
      for (let i = 0; i < group.length; i++) {
        for (let j = i + 1; j < group.length; j++) {
          const ids = [group[i].id, group[j].id].sort().join('|');
          if (!seen.has(ids)) {
            seen.add(ids);
            duplicateSets.push({
              reason: 'Similar name',
              companies: [rowToCompany(group[i]), rowToCompany(group[j])]
            });
          }
        }
      }
    }
  });

  res.json(duplicateSets.slice(0, 50));
});

// GET /api/hygiene/inactive-contacts
app.get('/api/hygiene/inactive-contacts', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const threshold = Date.now() - 90 * 86400000;
  const contacts = db.prepare(`
    SELECT c.* FROM contacts c
    WHERE c.org_id=?
      AND (c.last_activity IS NULL OR c.last_activity < ?)
      AND c.stage != 'Won'
    ORDER BY c.last_activity ASC NULLS FIRST
    LIMIT 100
  `).all(orgId, threshold);
  res.json(contacts.map(rowToContact));
});

// GET /api/hygiene/inactive-deals
app.get('/api/hygiene/inactive-deals', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const threshold = Date.now() - 30 * 86400000;
  const deals = db.prepare(`
    SELECT d.* FROM deals d
    WHERE d.org_id=?
      AND d.stage NOT IN ('Won','Lost')
      AND (d.moved_at IS NULL OR d.moved_at < ?)
    ORDER BY d.moved_at ASC NULLS FIRST
    LIMIT 100
  `).all(orgId, threshold);
  res.json(deals.map(rowToDeal));
});

// GET /api/hygiene/contacts-missing-info
app.get('/api/hygiene/contacts-missing-info', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contacts = db.prepare(`
    SELECT * FROM contacts
    WHERE org_id=?
      AND (email IS NULL OR email = '' OR phone IS NULL OR phone = '')
    ORDER BY created_at DESC
    LIMIT 100
  `).all(orgId);
  res.json(contacts.map(rowToContact));
});

// Workflow hooks are applied directly in the route handlers above.

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 23: Smart Today Queue ───────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/today-queue', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const todayStr  = new Date().toISOString().slice(0, 10);
  const now       = Date.now();

  // ── Tasks ──────────────────────────────────────────────────────────────
  const tasks = db.prepare(`
    SELECT t.*, c.name as contact_name, d.name as deal_name
    FROM tasks t
    LEFT JOIN contacts c ON c.id = t.contact_id
    LEFT JOIN deals d ON d.id = t.deal_id
    WHERE t.org_id=? AND t.status='Open' AND t.due_date IS NOT NULL AND t.due_date <= ?
    ORDER BY t.due_date ASC
  `).all(orgId, todayStr).map(r => ({
    id: r.id, kind: 'task', title: r.title,
    dueDate: r.due_date, priority: r.priority,
    overdue: r.due_date < todayStr,
    dueToday: r.due_date === todayStr,
    contactId: r.contact_id, contactName: r.contact_name,
    dealId: r.deal_id, dealName: r.deal_name,
    assignedOwner: r.assigned_owner || ''
  }));

  // ── Meetings ───────────────────────────────────────────────────────────
  const meetings = db.prepare(`
    SELECT m.*, c.name as contact_name, d.name as deal_name
    FROM meetings m
    LEFT JOIN contacts c ON c.id = m.contact_id
    LEFT JOIN deals d ON d.id = m.deal_id
    WHERE m.org_id=? AND m.status='Scheduled'
      AND substr(m.scheduled_at,1,10) = ?
    ORDER BY m.scheduled_at ASC
  `).all(orgId, todayStr).map(r => ({
    id: r.id, kind: 'meeting', title: r.title,
    scheduledAt: r.scheduled_at, durationMin: r.duration_min,
    overdue: false, dueToday: true,
    contactId: r.contact_id, contactName: r.contact_name,
    dealId: r.deal_id, dealName: r.deal_name,
    location: r.location || ''
  }));

  // ── Deals closing today ────────────────────────────────────────────────
  const deals = db.prepare(`
    SELECT d.*, c.name as contact_name
    FROM deals d
    LEFT JOIN contacts c ON c.id = d.contact_id
    WHERE d.org_id=? AND d.stage NOT IN ('Won','Lost')
      AND d.close_date IS NOT NULL AND d.close_date <= ?
    ORDER BY d.close_date ASC, d.value DESC
  `).all(orgId, todayStr).map(r => ({
    id: r.id, kind: 'deal', title: r.name,
    value: r.value || 0, stage: r.stage,
    closeDate: r.close_date,
    overdue: r.close_date < todayStr,
    dueToday: r.close_date === todayStr,
    contactId: r.contact_id, contactName: r.contact_name,
    owner: r.owner || ''
  }));

  // ── Activities with follow-up in next 24h (recent open tasks created today) ─
  const recentFollowUps = db.prepare(`
    SELECT a.*, c.name as contact_name, d.name as deal_name
    FROM activities a
    LEFT JOIN contacts c ON c.id = a.contact_id
    LEFT JOIN deals d ON d.id = a.deal_id
    WHERE a.org_id=? AND substr(a.date,1,10) = ?
      AND a.type IN ('Follow-up','Call','Email')
    ORDER BY a.created_at DESC
    LIMIT 20
  `).all(orgId, todayStr).map(r => ({
    id: r.id, kind: 'activity', title: `${r.type}: ${(r.note||'').slice(0,60)}`,
    type: r.type, date: r.date,
    overdue: false, dueToday: true,
    contactId: r.contact_id, contactName: r.contact_name,
    dealId: r.deal_id, dealName: r.deal_name
  }));

  res.json({
    date: todayStr,
    tasks,
    meetings,
    deals,
    followUps: recentFollowUps,
    summary: {
      total: tasks.length + meetings.length + deals.length + recentFollowUps.length,
      overdue: [...tasks, ...deals].filter(x => x.overdue).length
    }
  });
});

// ── Phase 23: Automation Rules ───────────────────────────────────────────────
db.prepare(`CREATE TABLE IF NOT EXISTS automation_rules (
  id TEXT PRIMARY KEY, org_id TEXT, name TEXT, enabled INTEGER DEFAULT 1,
  trigger_type TEXT, trigger_config TEXT, actions TEXT, created_at TEXT
)`).run();

function rowToAutomationRule(r) {
  return { id: r.id, orgId: r.org_id, name: r.name, enabled: !!r.enabled,
    triggerType: r.trigger_type, triggerConfig: JSON.parse(r.trigger_config||'{}'),
    actions: JSON.parse(r.actions||'[]'), createdAt: r.created_at };
}

app.get('/api/automation-rules', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM automation_rules WHERE org_id=? ORDER BY created_at DESC').all(req.user.orgId);
  res.json(rows.map(rowToAutomationRule));
});
app.post('/api/automation-rules', requireAuth, (req, res) => {
  const b = req.body; const id = 'ar_' + Date.now();
  db.prepare('INSERT INTO automation_rules (id,org_id,name,enabled,trigger_type,trigger_config,actions,created_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(id, req.user.orgId, b.name||'New Rule', b.enabled!==false?1:0, b.triggerType||'deal_stage_change',
      JSON.stringify(b.triggerConfig||{}), JSON.stringify(b.actions||[]), new Date().toISOString());
  res.status(201).json(rowToAutomationRule(db.prepare('SELECT * FROM automation_rules WHERE id=?').get(id)));
});
app.put('/api/automation-rules/:id', requireAuth, (req, res) => {
  const b = req.body;
  db.prepare('UPDATE automation_rules SET name=?,enabled=?,trigger_type=?,trigger_config=?,actions=? WHERE id=? AND org_id=?')
    .run(b.name, b.enabled!==false?1:0, b.triggerType, JSON.stringify(b.triggerConfig||{}), JSON.stringify(b.actions||[]), req.params.id, req.user.orgId);
  res.json(rowToAutomationRule(db.prepare('SELECT * FROM automation_rules WHERE id=?').get(req.params.id)));
});
app.delete('/api/automation-rules/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM automation_rules WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  res.json({ ok: true });
});

// ══════════════════════════════════════════════════════════════════════════
// ── PHASE 24 ──────────────────────────────────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────
// 1. EMAIL COMPOSER — SMTP Settings + Compose/Send endpoint
// ─────────────────────────────────────────────────────────────────────────

// Update rowToEmailLog to include Phase 24 fields (patched here via separate function)
function rowToEmailLogV2(r) {
  if (!r) return null;
  return {
    id:        r.id,
    contactId: r.contact_id,
    dealId:    r.deal_id || null,
    subject:   r.subject,
    body:      r.body,
    direction: r.direction,
    status:    r.status || 'Sent',
    date:      r.date,
    createdAt: r.created_at,
  };
}

// GET /api/settings/smtp
app.get('/api/settings/smtp', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const row = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='smtp'").get(orgId);
  if (!row) return res.json({ configured: false });
  try {
    const cfg = JSON.parse(row.value);
    // Mask password
    res.json({ configured: true, host: cfg.host, port: cfg.port, user: cfg.user, from: cfg.from });
  } catch { res.json({ configured: false }); }
});

// POST /api/settings/smtp
app.post('/api/settings/smtp', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { host, port, user, pass, from } = req.body;
  const cfg = { host, port: parseInt(port) || 587, user, pass, from };
  db.prepare('INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, ?, ?)')
    .run(orgId, 'smtp', JSON.stringify(cfg));
  res.json({ ok: true });
});

// DELETE /api/settings/smtp
app.delete('/api/settings/smtp', requireAuth, (req, res) => {
  db.prepare("DELETE FROM settings WHERE org_id=? AND key='smtp'").run(req.user.orgId);
  res.json({ ok: true });
});

// POST /api/email/send  — compose and send
app.post('/api/email/send', requireAuth, async (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { contactId, dealId, to, subject, body } = req.body;
  if (!subject) return res.status(400).json({ error: 'Subject required' });

  const now = new Date();
  const id = 'el_' + Date.now().toString(36);

  // Save to email_logs
  db.prepare(`INSERT INTO email_logs (id, org_id, contact_id, deal_id, subject, body, direction, status, date, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'Outbound', 'Sent', ?, ?)`).run(
    id, orgId, contactId || null, dealId || null, subject, body || '',
    now.toISOString().slice(0, 10), now.getTime()
  );
  if (contactId) db.prepare('UPDATE contacts SET last_activity=? WHERE id=? AND org_id=?').run(now.getTime(), contactId, orgId);

  // Try SMTP delivery
  let smtpResult = null;
  try {
    const smtpRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='smtp'").get(orgId);
    if (smtpRow) {
      const cfg = JSON.parse(smtpRow.value);
      if (cfg.host && cfg.user && cfg.pass) {
        const nodemailer = require('nodemailer');
        const transporter = nodemailer.createTransport({
          host: cfg.host, port: cfg.port || 587,
          auth: { user: cfg.user, pass: cfg.pass },
          tls: { rejectUnauthorized: false },
        });
        await transporter.sendMail({
          from: cfg.from || cfg.user,
          to: to || cfg.user,
          subject,
          text: body || '',
        });
        smtpResult = 'sent';
      }
    }
  } catch (smtpErr) {
    console.error('SMTP delivery error (non-fatal):', smtpErr.message);
    smtpResult = 'smtp_error';
  }

  auditLog(orgId, userId, userName, 'email', id, subject, 'sent');
  res.status(201).json({
    ok: true, id,
    simulated: smtpResult === null,
    smtpError: smtpResult === 'smtp_error',
  });
});

// GET /api/email-logs with extended fields (V2)
app.get('/api/email-logs/v2', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contactId, dealId } = req.query;
  let sql = 'SELECT * FROM email_logs WHERE org_id=?';
  const params = [orgId];
  if (contactId) { sql += ' AND contact_id=?'; params.push(contactId); }
  if (dealId)    { sql += ' AND deal_id=?';    params.push(dealId); }
  sql += ' ORDER BY date DESC';
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(rowToEmailLogV2));
});

// ─────────────────────────────────────────────────────────────────────────
// 2. DEAL WIN/LOSS ANALYTICS V2
// ─────────────────────────────────────────────────────────────────────────

// GET /api/reports/winloss-trend — monthly win rates last 12 months
app.get('/api/reports/winloss-trend', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const months = [];
  for (let i = 11; i >= 0; i--) {
    const d = new Date();
    d.setMonth(d.getMonth() - i);
    const year  = d.getFullYear();
    const month = d.getMonth() + 1;
    const label = d.toLocaleString('default', { month: 'short', year: '2-digit' });
    const prefix = `${year}-${String(month).padStart(2,'0')}`;
    const won  = db.prepare(`SELECT COUNT(*) as c FROM deals WHERE org_id=? AND stage='Won' AND close_date LIKE ?`).get(orgId, prefix + '%');
    const lost = db.prepare(`SELECT COUNT(*) as c FROM deals WHERE org_id=? AND stage='Lost' AND close_date LIKE ?`).get(orgId, prefix + '%');
    const total = (won.c || 0) + (lost.c || 0);
    months.push({ label, won: won.c, lost: lost.c, total, winRate: total > 0 ? Math.round((won.c / total) * 100) : null });
  }
  res.json(months);
});

// GET /api/reports/lost-by-stage
app.get('/api/reports/lost-by-stage', requireAuth, (req, res) => {
  const { orgId } = req.user;
  // We use deal_stage_log to determine which stage they were lost at
  const rows = db.prepare(`
    SELECT d.loss_reason, dsl.stage, COUNT(*) as count
    FROM deals d
    LEFT JOIN (
      SELECT deal_id, stage FROM deal_stage_log
      WHERE (deal_id, entered_at) IN (
        SELECT deal_id, MAX(entered_at) FROM deal_stage_log GROUP BY deal_id
      )
    ) dsl ON dsl.deal_id = d.id
    WHERE d.org_id=? AND d.stage='Lost'
    GROUP BY d.loss_reason, dsl.stage
    ORDER BY count DESC
  `).all(orgId);
  res.json(rows);
});

// GET /api/reports/lost-by-rep
app.get('/api/reports/lost-by-rep', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare(`
    SELECT owner,
      SUM(CASE WHEN stage='Won' THEN 1 ELSE 0 END) as won,
      SUM(CASE WHEN stage='Lost' THEN 1 ELSE 0 END) as lost,
      COUNT(*) as total,
      ROUND(AVG(CASE WHEN stage='Won' THEN value ELSE NULL END), 2) as avg_won_value,
      ROUND(AVG(CASE WHEN stage='Lost' THEN value ELSE NULL END), 2) as avg_lost_value
    FROM deals WHERE org_id=? AND stage IN ('Won','Lost') AND owner IS NOT NULL AND owner != ''
    GROUP BY owner ORDER BY won DESC
  `).all(orgId);
  res.json(rows.map(r => ({
    owner: r.owner, won: r.won, lost: r.lost, total: r.total,
    winRate: r.total > 0 ? Math.round((r.won / r.total) * 100) : 0,
    avgWonValue: r.avg_won_value || 0, avgLostValue: r.avg_lost_value || 0,
  })));
});

// GET /api/reports/deal-characteristics
app.get('/api/reports/deal-characteristics', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const won  = db.prepare(`SELECT value, created_at, close_date FROM deals WHERE org_id=? AND stage='Won'`).all(orgId);
  const lost = db.prepare(`SELECT value, created_at, close_date FROM deals WHERE org_id=? AND stage='Lost'`).all(orgId);

  function calc(deals) {
    if (!deals.length) return { avgValue: 0, avgAgeDays: 0, count: 0 };
    const avgValue = deals.reduce((s,d) => s + (d.value||0), 0) / deals.length;
    const avgAgeDays = deals.reduce((s,d) => {
      const created = d.created_at || Date.now();
      const closed  = d.close_date ? new Date(d.close_date).getTime() : Date.now();
      return s + Math.max(0, (closed - created) / 86400000);
    }, 0) / deals.length;
    return { avgValue: Math.round(avgValue), avgAgeDays: Math.round(avgAgeDays), count: deals.length };
  }

  // Activities per deal
  function avgActivities(deals) {
    if (!deals.length) return 0;
    const ids = deals.map((_,i) => `'${i}'`); // placeholder, we do it properly:
    return 0; // simplified — activity count needs separate query
  }

  const wonStats  = calc(won);
  const lostStats = calc(lost);

  // Activity counts
  const wonIds  = db.prepare(`SELECT id FROM deals WHERE org_id=? AND stage='Won'`).all(orgId).map(r => r.id);
  const lostIds = db.prepare(`SELECT id FROM deals WHERE org_id=? AND stage='Lost'`).all(orgId).map(r => r.id);

  const actWon  = wonIds.length  ? db.prepare(`SELECT deal_id, COUNT(*) as c FROM activities WHERE org_id=? AND deal_id IN (${wonIds.map(()=>'?').join(',')}) GROUP BY deal_id`).all(orgId, ...wonIds) : [];
  const actLost = lostIds.length ? db.prepare(`SELECT deal_id, COUNT(*) as c FROM activities WHERE org_id=? AND deal_id IN (${lostIds.map(()=>'?').join(',')}) GROUP BY deal_id`).all(orgId, ...lostIds) : [];

  const avgActWon  = actWon.length  ? Math.round(actWon.reduce((s,r) => s + r.c, 0) / Math.max(wonIds.length, 1))  : 0;
  const avgActLost = actLost.length ? Math.round(actLost.reduce((s,r) => s + r.c, 0) / Math.max(lostIds.length, 1)) : 0;

  res.json({
    won:  { ...wonStats,  avgActivities: avgActWon },
    lost: { ...lostStats, avgActivities: avgActLost },
  });
});

// ── Loss Reason Taxonomy CRUD ────────────────────────────────────────────
app.get('/api/loss-reason-taxonomy', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM loss_reason_taxonomy WHERE org_id=? ORDER BY sort_order ASC, created_at ASC').all(req.user.orgId);
  res.json(rows);
});

app.post('/api/loss-reason-taxonomy', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { reason } = req.body;
  if (!reason) return res.status(400).json({ error: 'Reason required' });
  const id = 'lrt_' + Date.now().toString(36);
  const maxOrder = db.prepare('SELECT MAX(sort_order) as m FROM loss_reason_taxonomy WHERE org_id=?').get(orgId);
  const order = (maxOrder.m || 0) + 1;
  db.prepare('INSERT INTO loss_reason_taxonomy (id, org_id, reason, sort_order, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, reason, order, Date.now());
  res.status(201).json(db.prepare('SELECT * FROM loss_reason_taxonomy WHERE id=?').get(id));
});

app.put('/api/loss-reason-taxonomy/:id', requireAuth, (req, res) => {
  const { reason, sort_order } = req.body;
  db.prepare('UPDATE loss_reason_taxonomy SET reason=?, sort_order=? WHERE id=? AND org_id=?')
    .run(reason, sort_order || 0, req.params.id, req.user.orgId);
  res.json(db.prepare('SELECT * FROM loss_reason_taxonomy WHERE id=?').get(req.params.id));
});

app.delete('/api/loss-reason-taxonomy/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM loss_reason_taxonomy WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────
// 3. CONTACT ENGAGEMENT TIMELINE
// ─────────────────────────────────────────────────────────────────────────

// GET /api/contacts/:id/score-history
app.get('/api/contacts/:id/score-history', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare('SELECT * FROM lead_score_history WHERE org_id=? AND contact_id=? ORDER BY created_at ASC')
    .all(orgId, req.params.id);
  res.json(rows);
});

// POST /api/contacts/:id/score-snapshot
app.post('/api/contacts/:id/score-snapshot', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contactId = req.params.id;
  const score = parseInt(req.body.score) || 0;
  const id = 'lsh_' + Date.now().toString(36);
  db.prepare('INSERT INTO lead_score_history (id, org_id, contact_id, score, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, contactId, score, Date.now());
  res.status(201).json({ id, contactId, score, createdAt: Date.now() });
});

// GET /api/contacts/:id/activity-heatmap — 52 weeks of activity counts
app.get('/api/contacts/:id/activity-heatmap', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contactId = req.params.id;
  // Get activities from last 52 weeks
  const since = Date.now() - 52 * 7 * 86400000;
  const rows = db.prepare(`
    SELECT date FROM activities
    WHERE org_id=? AND contact_id=? AND created_at >= ?
  `).all(orgId, contactId, since);

  // Build week map
  const weekMap = {};
  rows.forEach(r => {
    if (!r.date) return;
    const d = new Date(r.date);
    const weekStart = new Date(d);
    weekStart.setDate(d.getDate() - d.getDay()); // start of week (Sunday)
    const key = weekStart.toISOString().slice(0, 10);
    weekMap[key] = (weekMap[key] || 0) + 1;
  });

  // Build array of 52 weeks
  const weeks = [];
  const now = new Date();
  for (let i = 51; i >= 0; i--) {
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - now.getDay() - i * 7);
    const key = weekStart.toISOString().slice(0, 10);
    weeks.push({ week: key, count: weekMap[key] || 0 });
  }
  res.json(weeks);
});

// GET /api/contacts/:id/activity-breakdown — pie chart data
app.get('/api/contacts/:id/activity-breakdown', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare(`
    SELECT type, COUNT(*) as count FROM activities
    WHERE org_id=? AND contact_id=?
    GROUP BY type ORDER BY count DESC
  `).all(orgId, req.params.id);
  res.json(rows);
});

// ─────────────────────────────────────────────────────────────────────────
// 4. TASK DEPENDENCIES
// ─────────────────────────────────────────────────────────────────────────

// GET /api/task-dependencies?taskId=...
app.get('/api/task-dependencies', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { taskId } = req.query;
  if (!taskId) return res.status(400).json({ error: 'taskId required' });
  // What this task depends on (blocked by)
  const blockedBy = db.prepare(`
    SELECT td.*, t.title as dep_title, t.status as dep_status, t.due_date as dep_due_date
    FROM task_dependencies td
    JOIN tasks t ON t.id = td.depends_on_task_id
    WHERE td.org_id=? AND td.task_id=?
  `).all(orgId, taskId);
  // What depends on this task (blocking)
  const blocking = db.prepare(`
    SELECT td.*, t.title as dep_title, t.status as dep_status, t.due_date as dep_due_date
    FROM task_dependencies td
    JOIN tasks t ON t.id = td.task_id
    WHERE td.org_id=? AND td.depends_on_task_id=?
  `).all(orgId, taskId);
  res.json({ blockedBy, blocking });
});

// POST /api/task-dependencies
app.post('/api/task-dependencies', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { taskId, dependsOnTaskId } = req.body;
  if (!taskId || !dependsOnTaskId) return res.status(400).json({ error: 'taskId and dependsOnTaskId required' });
  if (taskId === dependsOnTaskId) return res.status(400).json({ error: 'Task cannot depend on itself' });

  // Check for circular dependency (simple: check if dependsOnTaskId already depends on taskId)
  const existing = db.prepare('SELECT id FROM task_dependencies WHERE org_id=? AND task_id=? AND depends_on_task_id=?').get(orgId, dependsOnTaskId, taskId);
  if (existing) return res.status(400).json({ error: 'Circular dependency detected' });

  const id = 'td_' + Date.now().toString(36);
  try {
    db.prepare('INSERT INTO task_dependencies (id, org_id, task_id, depends_on_task_id, created_at) VALUES (?, ?, ?, ?, ?)')
      .run(id, orgId, taskId, dependsOnTaskId, Date.now());
    res.status(201).json({ id, taskId, dependsOnTaskId });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Dependency already exists' });
    throw err;
  }
});

// DELETE /api/task-dependencies/:id
app.delete('/api/task-dependencies/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM task_dependencies WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  res.json({ ok: true });
});

// GET /api/tasks/:id/blocked — check if task is blocked
app.get('/api/tasks/:id/blocked', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deps = db.prepare(`
    SELECT td.*, t.status as dep_status
    FROM task_dependencies td
    JOIN tasks t ON t.id = td.depends_on_task_id
    WHERE td.org_id=? AND td.task_id=?
  `).all(orgId, req.params.id);
  const isBlocked = deps.some(d => d.dep_status !== 'Done');
  res.json({ blocked: isBlocked, dependencies: deps });
});

// GET /api/tasks/with-dependencies — all tasks + blocked status
app.get('/api/tasks/with-dependencies', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const tasks = db.prepare('SELECT * FROM tasks WHERE org_id=? ORDER BY created_at DESC').all(orgId);
  // For each task, check if any of its dependencies are not done
  const result = tasks.map(t => {
    const deps = db.prepare(`
      SELECT td.depends_on_task_id, ta.status
      FROM task_dependencies td
      JOIN tasks ta ON ta.id = td.depends_on_task_id
      WHERE td.org_id=? AND td.task_id=?
    `).all(orgId, t.id);
    const blocked = deps.some(d => d.status !== 'Done');
    return { ...t, blocked, depCount: deps.length };
  });
  res.json(result);
});

// Patch task completion to enforce dependencies (server-side)
// This intercepts the standard task PUT to block completion if deps aren't done.
// We'll wrap this check inside the original task PATCH route.
// For Phase 24: add a separate PATCH /api/tasks/:id/complete that enforces deps
app.patch('/api/tasks/:id/complete', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { id } = req.params;
  // Check if all dependencies are done
  const deps = db.prepare(`
    SELECT td.depends_on_task_id, ta.status
    FROM task_dependencies td
    JOIN tasks ta ON ta.id = td.depends_on_task_id
    WHERE td.org_id=? AND td.task_id=?
  `).all(orgId, id);
  const blocked = deps.filter(d => d.status !== 'Done');
  if (blocked.length > 0) {
    return res.status(422).json({
      error: `Cannot complete: ${blocked.length} blocking task(s) must be done first.`,
      blockedBy: blocked,
    });
  }
  db.prepare("UPDATE tasks SET status='Done' WHERE id=? AND org_id=?").run(id, orgId);
  auditLog(orgId, userId, userName, 'task', id, '', 'completed');
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────
// 5. INVENTORY / ASSET TRACKING
// ─────────────────────────────────────────────────────────────────────────

function rowToAsset(r) {
  if (!r) return null;
  return {
    id:                r.id,
    name:              r.name,
    type:              r.type,
    serialNumber:      r.serial_number || '',
    purchaseDate:      r.purchase_date || '',
    warrantyExpiry:    r.warranty_expiry || '',
    value:             r.value || 0,
    status:            r.status,
    assignedContactId: r.assigned_contact_id || null,
    assignedDealId:    r.assigned_deal_id || null,
    notes:             r.notes || '',
    createdAt:         r.created_at,
    // Joined fields
    contactName:       r.contact_name || null,
    dealName:          r.deal_name || null,
  };
}

app.get('/api/assets', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { type, status, contactId, dealId } = req.query;
  let sql = `
    SELECT a.*, c.name as contact_name, d.name as deal_name
    FROM assets a
    LEFT JOIN contacts c ON c.id = a.assigned_contact_id
    LEFT JOIN deals d ON d.id = a.assigned_deal_id
    WHERE a.org_id=?
  `;
  const params = [orgId];
  if (type)      { sql += ' AND a.type=?';                 params.push(type); }
  if (status)    { sql += ' AND a.status=?';               params.push(status); }
  if (contactId) { sql += ' AND a.assigned_contact_id=?';  params.push(contactId); }
  if (dealId)    { sql += ' AND a.assigned_deal_id=?';     params.push(dealId); }
  sql += ' ORDER BY a.created_at DESC';
  res.json(db.prepare(sql).all(...params).map(rowToAsset));
});

// GET /api/assets/expiring must come BEFORE /api/assets/:id to avoid route conflict
app.get('/api/assets/expiring', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const days = parseInt(req.query.days) || 30;
  const todayStr = new Date().toISOString().slice(0, 10);
  const futureStr = new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
  const rows = db.prepare(`
    SELECT a.*, c.name as contact_name, d.name as deal_name
    FROM assets a
    LEFT JOIN contacts c ON c.id = a.assigned_contact_id
    LEFT JOIN deals d ON d.id = a.assigned_deal_id
    WHERE a.org_id=? AND a.warranty_expiry IS NOT NULL AND a.warranty_expiry != ''
      AND a.warranty_expiry >= ? AND a.warranty_expiry <= ? AND a.status='Active'
    ORDER BY a.warranty_expiry ASC
  `).all(orgId, todayStr, futureStr);
  res.json(rows.map(rowToAsset));
});

app.get('/api/assets/:id', requireAuth, (req, res) => {
  const row = db.prepare(`
    SELECT a.*, c.name as contact_name, d.name as deal_name
    FROM assets a
    LEFT JOIN contacts c ON c.id = a.assigned_contact_id
    LEFT JOIN deals d ON d.id = a.assigned_deal_id
    WHERE a.id=? AND a.org_id=?
  `).get(req.params.id, req.user.orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(rowToAsset(row));
});

app.post('/api/assets', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  if (!b.name) return res.status(400).json({ error: 'Name required' });
  const id = 'ast_' + Date.now().toString(36);
  db.prepare(`INSERT INTO assets (id, org_id, name, type, serial_number, purchase_date, warranty_expiry, value, status, assigned_contact_id, assigned_deal_id, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, orgId, b.name, b.type || 'Other', b.serialNumber || null,
    b.purchaseDate || null, b.warrantyExpiry || null, b.value || 0,
    b.status || 'Active', b.assignedContactId || null, b.assignedDealId || null,
    b.notes || null, Date.now()
  );
  auditLog(orgId, userId, userName, 'asset', id, b.name, 'created');
  res.status(201).json(rowToAsset(db.prepare('SELECT a.*, c.name as contact_name, d.name as deal_name FROM assets a LEFT JOIN contacts c ON c.id=a.assigned_contact_id LEFT JOIN deals d ON d.id=a.assigned_deal_id WHERE a.id=?').get(id)));
});

app.put('/api/assets/:id', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  db.prepare(`UPDATE assets SET name=?, type=?, serial_number=?, purchase_date=?, warranty_expiry=?, value=?, status=?, assigned_contact_id=?, assigned_deal_id=?, notes=? WHERE id=? AND org_id=?`)
    .run(b.name, b.type || 'Other', b.serialNumber || null, b.purchaseDate || null, b.warrantyExpiry || null, b.value || 0, b.status || 'Active', b.assignedContactId || null, b.assignedDealId || null, b.notes || null, req.params.id, orgId);
  auditLog(orgId, userId, userName, 'asset', req.params.id, b.name, 'updated');
  res.json(rowToAsset(db.prepare('SELECT a.*, c.name as contact_name, d.name as deal_name FROM assets a LEFT JOIN contacts c ON c.id=a.assigned_contact_id LEFT JOIN deals d ON d.id=a.assigned_deal_id WHERE a.id=?').get(req.params.id)));
});

app.delete('/api/assets/:id', requireAuth, (req, res) => {
  const result = db.prepare('DELETE FROM assets WHERE id=? AND org_id=?').run(req.params.id, req.user.orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// GET /api/reports/assets — asset value by type + full list
app.get('/api/reports/assets', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const byType = db.prepare(`
    SELECT type, COUNT(*) as count, SUM(value) as total_value
    FROM assets WHERE org_id=? AND status='Active'
    GROUP BY type ORDER BY total_value DESC
  `).all(orgId);
  const expiring = db.prepare(`
    SELECT a.*, c.name as contact_name
    FROM assets a
    LEFT JOIN contacts c ON c.id = a.assigned_contact_id
    WHERE a.org_id=? AND a.warranty_expiry IS NOT NULL AND a.warranty_expiry != ''
      AND a.warranty_expiry >= ? AND a.warranty_expiry <= ?
    ORDER BY a.warranty_expiry ASC
    LIMIT 50
  `).all(orgId, new Date().toISOString().slice(0, 10), new Date(Date.now() + 90 * 86400000).toISOString().slice(0, 10));
  res.json({ byType, expiring: expiring.map(rowToAsset) });
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 24: ADVANCED GLOBAL SEARCH
// ─────────────────────────────────────────────────────────────────────────
app.get('/api/search', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const q = (req.query.q || '').trim();
  if (!q || q.length < 2) return res.json({ query: q, groups: [] });

  const like = `%${q}%`;
  const LIMIT = 5;

  const contacts = db.prepare(`
    SELECT id, name, email, title, phone FROM contacts
    WHERE org_id=? AND (name LIKE ? OR email LIKE ? OR title LIKE ? OR phone LIKE ?)
    ORDER BY name LIMIT ?
  `).all(orgId, like, like, like, like, LIMIT).map(r => ({
    id: r.id, label: r.name,
    sub: [r.title, r.email].filter(Boolean).join(' · '),
    type: 'contact', action: `showContactDetail('${r.id}')`
  }));

  const companies = db.prepare(`
    SELECT id, name, industry, city FROM companies
    WHERE org_id=? AND (name LIKE ? OR industry LIKE ? OR city LIKE ?)
    ORDER BY name LIMIT ?
  `).all(orgId, like, like, like, LIMIT).map(r => ({
    id: r.id, label: r.name,
    sub: [r.industry, r.city].filter(Boolean).join(' · '),
    type: 'company', action: `editCompanyModal('${r.id}')`
  }));

  const deals = db.prepare(`
    SELECT id, name, stage, value FROM deals
    WHERE org_id=? AND (name LIKE ? OR stage LIKE ?)
    ORDER BY name LIMIT ?
  `).all(orgId, like, like, LIMIT).map(r => ({
    id: r.id, label: r.name,
    sub: `${r.stage} · $${(r.value||0).toLocaleString()}`,
    type: 'deal', action: `showDealDetail('${r.id}')`
  }));

  const activities = db.prepare(`
    SELECT id, type, date, note FROM activities
    WHERE org_id=? AND (type LIKE ? OR note LIKE ?)
    ORDER BY date DESC LIMIT ?
  `).all(orgId, like, like, LIMIT).map(r => ({
    id: r.id, label: r.type,
    sub: `${r.type} · ${r.date || ''}`,
    type: 'activity', action: `navigateTo('activities')`
  }));

  const invoices = db.prepare(`
    SELECT id, number, status, total FROM invoices
    WHERE org_id=? AND (number LIKE ? OR status LIKE ?)
    ORDER BY created_at DESC LIMIT ?
  `).all(orgId, like, like, LIMIT).map(r => ({
    id: r.id, label: `Invoice #${r.number}`,
    sub: `${r.status} · $${(r.total||0).toLocaleString()}`,
    type: 'invoice', action: `showInvoiceDetail('${r.id}')`
  }));

  // Check if tables exist before querying
  let notes = [];
  try {
    notes = db.prepare(`
      SELECT id, title, body FROM kb_notes
      WHERE org_id=? AND (title LIKE ? OR body LIKE ?)
      ORDER BY created_at DESC LIMIT ?
    `).all(orgId, like, like, LIMIT).map(r => ({
      id: r.id, label: r.title || 'Note',
      sub: (r.body || '').slice(0, 60),
      type: 'note', action: `navigateTo('kb')`
    }));
  } catch(_) {}

  let emailLogs = [];
  try {
    emailLogs = db.prepare(`
      SELECT el.id, el.subject, el.date, c.name as contact_name FROM email_logs el
      LEFT JOIN contacts c ON c.id = el.contact_id
      WHERE el.org_id=? AND (el.subject LIKE ? OR el.body LIKE ?)
      ORDER BY el.created_at DESC LIMIT ?
    `).all(orgId, like, like, LIMIT).map(r => ({
      id: r.id, label: r.subject,
      sub: `Email · ${r.contact_name || ''} · ${r.date || ''}`,
      type: 'email', action: `navigateTo('inbox')`
    }));
  } catch(_) {}

  const groups = [
    { type: 'contact',  label: 'Contacts',   items: contacts   },
    { type: 'company',  label: 'Companies',  items: companies  },
    { type: 'deal',     label: 'Deals',      items: deals      },
    { type: 'activity', label: 'Activities', items: activities },
    { type: 'invoice',  label: 'Invoices',   items: invoices   },
    { type: 'note',     label: 'Notes',      items: notes      },
    { type: 'email',    label: 'Emails',     items: emailLogs  },
  ].filter(g => g.items.length > 0);

  res.json({ query: q, groups });
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 24: CONTACT UNIFIED TIMELINE
// ─────────────────────────────────────────────────────────────────────────
app.get('/api/contacts/:id/timeline', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contactId = req.params.id;
  const events = [];

  // Activities
  try {
    db.prepare(`SELECT id, type, date, note, created_at FROM activities WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 50`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Activity', subtype: r.type,
        date: r.date || new Date(r.created_at).toISOString().slice(0,10),
        ts: r.created_at,
        title: r.type,
        description: r.note || '',
      }));
  } catch(_) {}

  // Emails
  try {
    db.prepare(`SELECT id, subject, body, direction, date, created_at FROM email_logs WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 50`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Email', subtype: r.direction || 'Outbound',
        date: r.date,
        ts: r.created_at,
        title: r.subject,
        description: (r.body || '').slice(0, 120),
      }));
  } catch(_) {}

  // Deals
  try {
    db.prepare(`SELECT id, name, stage, value, created_at, close_date FROM deals WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 20`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Deal', subtype: r.stage,
        date: new Date(r.created_at).toISOString().slice(0,10),
        ts: r.created_at,
        title: r.name,
        description: `Stage: ${r.stage} · Value: $${(r.value||0).toLocaleString()}`,
      }));
  } catch(_) {}

  // Tasks
  try {
    db.prepare(`SELECT id, title, status, due_date, created_at FROM tasks WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 30`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Task', subtype: r.status,
        date: r.due_date || new Date(r.created_at).toISOString().slice(0,10),
        ts: r.created_at,
        title: r.title,
        description: `Status: ${r.status}`,
      }));
  } catch(_) {}

  // Invoices
  try {
    db.prepare(`SELECT id, number, status, total, created_at, due_date FROM invoices WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 20`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Invoice', subtype: r.status,
        date: new Date(r.created_at).toISOString().slice(0,10),
        ts: r.created_at,
        title: `Invoice #${r.number}`,
        description: `${r.status} · $${(r.total||0).toLocaleString()}`,
      }));
  } catch(_) {}

  // Call logs
  try {
    db.prepare(`SELECT id, contact_id, duration, notes, direction, created_at FROM call_logs WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 30`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Call', subtype: r.direction || '',
        date: new Date(r.created_at).toISOString().slice(0,10),
        ts: r.created_at,
        title: `${r.direction || 'Call'} · ${r.duration || ''}`,
        description: r.notes || '',
      }));
  } catch(_) {}

  // Meetings
  try {
    db.prepare(`SELECT id, title, description, scheduled_at, status, created_at FROM meetings WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 20`)
      .all(orgId, contactId).forEach(r => events.push({
        id: r.id, type: 'Meeting', subtype: r.status || '',
        date: r.scheduled_at ? r.scheduled_at.slice(0,10) : new Date(r.created_at).toISOString().slice(0,10),
        ts: r.created_at,
        title: r.title || 'Meeting',
        description: r.description || '',
      }));
  } catch(_) {}

  // Sort by ts descending
  events.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  res.json(events);
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 24: PAYMENT LINKS
// ─────────────────────────────────────────────────────────────────────────
const crypto24 = require('crypto');
db.prepare(`CREATE TABLE IF NOT EXISTS invoice_payment_tokens (
  id TEXT PRIMARY KEY, org_id TEXT, invoice_id TEXT, token TEXT UNIQUE,
  paid_at INTEGER, created_at INTEGER
)`).run();

// POST /api/invoices/:id/payment-link — generate token
app.post('/api/invoices/:id/payment-link', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const invoiceId = req.params.id;
  const invoice = db.prepare('SELECT * FROM invoices WHERE id=? AND org_id=?').get(invoiceId, orgId);
  if (!invoice) return res.status(404).json({ error: 'Invoice not found' });

  // Check if a token already exists
  let existing = db.prepare('SELECT * FROM invoice_payment_tokens WHERE invoice_id=? AND org_id=? AND paid_at IS NULL').get(invoiceId, orgId);
  if (existing) return res.json({ token: existing.token, url: `/payment/${existing.token}` });

  const token = crypto24.randomBytes(24).toString('hex');
  const id = 'ipt_' + Date.now().toString(36);
  db.prepare('INSERT INTO invoice_payment_tokens (id, org_id, invoice_id, token, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, invoiceId, token, Date.now());
  res.json({ token, url: `/payment/${token}` });
});

// GET /api/pay/:token — public, no auth
app.get('/api/pay/:token', (req, res) => {
  const row = db.prepare('SELECT ipt.*, i.number, i.total, i.status, i.due_date, i.items, c.name as contact_name, c.email as contact_email, o.name as org_name FROM invoice_payment_tokens ipt JOIN invoices i ON i.id = ipt.invoice_id LEFT JOIN contacts c ON c.id = i.contact_id LEFT JOIN orgs o ON o.id = ipt.org_id WHERE ipt.token=?').get(req.params.token);
  if (!row) return res.status(404).json({ error: 'Payment link not found or expired' });
  if (row.paid_at) return res.json({ alreadyPaid: true, paidAt: row.paid_at, invoiceNumber: row.number, total: row.total });

  // Check for Stripe key in settings
  let stripeKey = null;
  try {
    const sk = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='stripe_publishable_key'").get(row.org_id);
    if (sk) stripeKey = sk.value;
  } catch(_) {}

  res.json({
    token: row.token,
    invoiceId: row.invoice_id,
    invoiceNumber: row.number,
    total: row.total,
    status: row.status,
    dueDate: row.due_date,
    contactName: row.contact_name,
    contactEmail: row.contact_email,
    orgName: row.org_name,
    lineItems: (() => { try { return JSON.parse(row.items || '[]'); } catch(_) { return []; } })(),
    stripeKey,
  });
});

// POST /api/pay/:token — simulate payment
app.post('/api/pay/:token', (req, res) => {
  const row = db.prepare('SELECT * FROM invoice_payment_tokens WHERE token=?').get(req.params.token);
  if (!row) return res.status(404).json({ error: 'Payment link not found' });
  if (row.paid_at) return res.status(409).json({ error: 'Already paid' });

  const now = Date.now();
  db.prepare('UPDATE invoice_payment_tokens SET paid_at=? WHERE token=?').run(now, req.params.token);
  db.prepare("UPDATE invoices SET status='Paid' WHERE id=?").run(row.invoice_id);
  res.json({ ok: true, paidAt: now, invoiceId: row.invoice_id });
});

// GET /api/products/inventory-alerts — products below reorder point
app.get('/api/products/inventory-alerts', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare(`
    SELECT * FROM products
    WHERE org_id=? AND active=1 AND reorder_point > 0 AND quantity_on_hand <= reorder_point
    ORDER BY (reorder_point - quantity_on_hand) DESC
  `).all(orgId).map(rowToProduct);
  res.json(rows);
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 25: AI DEAL COACHING
// ─────────────────────────────────────────────────────────────────────────

// GET /api/deals/:id/coaching — rule-based coaching tips + talking points
app.get('/api/deals/:id/coaching', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!deal) return res.status(404).json({ error: 'Deal not found' });

  const now = Date.now();
  const tips = [];

  // 1. Days since last activity
  const lastActivity = db.prepare(
    'SELECT MAX(created_at) as lat FROM activities WHERE deal_id=? AND org_id=?'
  ).get(req.params.id, orgId);
  const daysSinceActivity = lastActivity?.lat
    ? Math.floor((now - lastActivity.lat) / 86400000)
    : 999;

  if (daysSinceActivity >= 14) {
    tips.push({
      priority: 'high',
      category: 'Activity',
      tip: `No activity in ${daysSinceActivity} days — schedule a follow-up call or send a check-in email today.`,
    });
  } else if (daysSinceActivity >= 7) {
    tips.push({
      priority: 'medium',
      category: 'Activity',
      tip: `Last activity was ${daysSinceActivity} days ago — consider reaching out to maintain momentum.`,
    });
  }

  // 2. Proposal sent but no signature
  const proposal = db.prepare(
    "SELECT * FROM proposals WHERE deal_id=? AND org_id=? ORDER BY created_at DESC LIMIT 1"
  ).get(req.params.id, orgId);
  if (proposal && proposal.status === 'Sent' && !proposal.signed_at) {
    const proposalAgeDays = Math.floor((now - proposal.created_at) / 86400000);
    if (proposalAgeDays >= 7) {
      tips.push({
        priority: 'high',
        category: 'Proposal',
        tip: `Proposal sent ${proposalAgeDays} days ago with no signature — consider scheduling a walk-through call to address objections.`,
      });
    } else if (proposalAgeDays >= 3) {
      tips.push({
        priority: 'medium',
        category: 'Proposal',
        tip: `Proposal sent ${proposalAgeDays} days ago — confirm it was received and ask if they have questions.`,
      });
    }
  }

  // 3. Competitor count
  const competitorCount = db.prepare(
    'SELECT COUNT(*) as c FROM competitor_entries WHERE deal_id=? AND org_id=?'
  ).get(req.params.id, orgId)?.c || 0;
  if (competitorCount >= 3) {
    tips.push({
      priority: 'high',
      category: 'Competition',
      tip: `${competitorCount} competitors tracked — prepare a differentiation doc or comparison table before the next call.`,
    });
  } else if (competitorCount >= 1) {
    tips.push({
      priority: 'medium',
      category: 'Competition',
      tip: `${competitorCount} competitor(s) in this deal — review their strengths and prepare counter-positioning.`,
    });
  }

  // 4. Close date proximity
  if (deal.close_date) {
    const closeTs = new Date(deal.close_date).getTime();
    const daysToClose = Math.floor((closeTs - now) / 86400000);
    if (daysToClose < 0 && !['Won','Lost'].includes(deal.stage)) {
      tips.push({
        priority: 'high',
        category: 'Close Date',
        tip: `Close date was ${Math.abs(daysToClose)} day(s) ago and the deal is still open — update the close date or escalate internally.`,
      });
    } else if (daysToClose >= 0 && daysToClose <= 7 && !['Won','Lost'].includes(deal.stage)) {
      tips.push({
        priority: 'high',
        category: 'Close Date',
        tip: `Deal closes in ${daysToClose} day(s) — ensure contract, legal review, and decision-maker sign-off are all in motion.`,
      });
    } else if (daysToClose > 7 && daysToClose <= 21 && !['Won','Lost'].includes(deal.stage)) {
      tips.push({
        priority: 'medium',
        category: 'Close Date',
        tip: `${daysToClose} days until expected close — lock in next steps and get a verbal commitment on timeline.`,
      });
    }
  }

  // 5. Stage-specific tips
  const stage = deal.stage || '';
  if (stage === 'To Contact') {
    tips.push({
      priority: 'medium',
      category: 'Stage',
      tip: 'Deal is in "To Contact" — prioritize outreach. Reference a relevant case study or industry insight in the first message.',
    });
  } else if (stage === 'Contacted') {
    tips.push({
      priority: 'medium',
      category: 'Stage',
      tip: 'Discovery call pending — prepare 5 open-ended questions about their current pain points and timeline.',
    });
  } else if (stage === 'Negotiation') {
    tips.push({
      priority: 'high',
      category: 'Stage',
      tip: 'In negotiation — have a clear walk-away price defined and identify any non-price concessions you can offer.',
    });
  }

  // 6. SLA breach check
  const slaSettings = (() => {
    try {
      const row = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slaLimits'").get(orgId);
      return row ? JSON.parse(row.value) : {};
    } catch { return {}; }
  })();
  const currentStageSla = slaSettings[stage];
  if (currentStageSla) {
    const stageEntry = db.prepare(
      'SELECT entered_at FROM deal_stage_log WHERE deal_id=? AND stage=? ORDER BY entered_at DESC LIMIT 1'
    ).get(req.params.id, stage);
    if (stageEntry) {
      const daysInStage = Math.floor((now - stageEntry.entered_at) / 86400000);
      if (daysInStage > currentStageSla) {
        tips.push({
          priority: 'high',
          category: 'SLA',
          tip: `SLA breached: deal has been in "${stage}" for ${daysInStage} days (limit: ${currentStageSla}) — escalate or move forward.`,
        });
      }
    }
  }

  // 7. Time tracked vs deal value
  const timeTotal = db.prepare(
    'SELECT SUM(hours) as h FROM time_entries WHERE deal_id=? AND org_id=?'
  ).get(req.params.id, orgId)?.h || 0;
  if (timeTotal > 20 && (deal.value || 0) < 10000) {
    tips.push({
      priority: 'medium',
      category: 'Efficiency',
      tip: `${timeTotal.toFixed(1)} hours tracked on a $${(deal.value||0).toLocaleString()} deal — evaluate whether the effort justifies the deal size.`,
    });
  }

  // Pick top 5, sorted by priority
  const priorityOrder = { high: 0, medium: 1, low: 2 };
  const finalTips = tips
    .sort((a, b) => (priorityOrder[a.priority] || 1) - (priorityOrder[b.priority] || 1))
    .slice(0, 5);

  // ── Talking Points ──────────────────────────────────────────────────────
  const talkingPoints = [];
  // Contact info
  let contact = null;
  if (deal.contact_id) {
    contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(deal.contact_id, orgId);
  }
  if (contact) {
    if (contact.title) talkingPoints.push(`Contact is ${contact.title} — lead with outcomes that matter at their level, not technical features.`);
  }

  // Company info
  let company = null;
  if (deal.company_id) {
    company = db.prepare('SELECT * FROM companies WHERE id=? AND org_id=?').get(deal.company_id, orgId);
  }
  if (company) {
    const industryStr = company.industry ? ` in ${company.industry}` : '';
    talkingPoints.push(`${company.name}${industryStr} — reference industry-specific ROI data or a comparable customer story.`);
  }

  // Last activity topic from notes
  const lastAct = db.prepare(
    'SELECT note, type FROM activities WHERE deal_id=? AND org_id=? ORDER BY created_at DESC LIMIT 1'
  ).get(req.params.id, orgId);
  if (lastAct?.note) {
    const snippet = lastAct.note.length > 80 ? lastAct.note.slice(0, 80) + '...' : lastAct.note;
    talkingPoints.push(`Last ${lastAct.type || 'activity'}: "${snippet}" — reference this context to show continuity.`);
  }

  // Fallback
  if (talkingPoints.length === 0) {
    talkingPoints.push('No prior activity found — start with open questions about their current process and pain points.');
  }

  res.json({ tips: finalTips, talkingPoints: talkingPoints.slice(0, 3) });
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 25: CONTACT RELATIONSHIP MAPPING
// ─────────────────────────────────────────────────────────────────────────

// GET /api/contacts/:id/relationships — graph data
app.get('/api/contacts/:id/relationships', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contactId = req.params.id;

  const contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(contactId, orgId);
  if (!contact) return res.status(404).json({ error: 'Not found' });

  const nodes = [];
  const edges = [];

  // Center node: this contact
  nodes.push({ id: contactId, type: 'contact', label: contact.name, primary: true });

  // Company node
  let company = null;
  if (contact.company_id) {
    company = db.prepare('SELECT * FROM companies WHERE id=? AND org_id=?').get(contact.company_id, orgId);
    if (company) {
      nodes.push({ id: company.id, type: 'company', label: company.name });
      edges.push({ from: contactId, to: company.id, label: 'works at' });
    }
  }

  // Linked deals
  const deals = db.prepare('SELECT * FROM deals WHERE contact_id=? AND org_id=? LIMIT 5').all(contactId, orgId);
  deals.forEach(d => {
    nodes.push({ id: d.id, type: 'deal', label: d.name, stage: d.stage, value: d.value });
    edges.push({ from: contactId, to: d.id, label: 'linked deal' });
  });

  // Co-contacts at same company
  if (company) {
    const coContacts = db.prepare(
      'SELECT * FROM contacts WHERE company_id=? AND org_id=? AND id!=? LIMIT 5'
    ).all(company.id, orgId, contactId);
    coContacts.forEach(c => {
      if (!nodes.find(n => n.id === c.id)) {
        nodes.push({ id: c.id, type: 'contact', label: c.name, title: c.title });
      }
      edges.push({ from: contactId, to: c.id, label: 'colleague' });
    });
  }

  // Referred contacts (this contact referred others)
  const referred = db.prepare(
    'SELECT * FROM contacts WHERE referred_by=? AND org_id=? LIMIT 5'
  ).all(contactId, orgId);
  referred.forEach(c => {
    if (!nodes.find(n => n.id === c.id)) {
      nodes.push({ id: c.id, type: 'contact', label: c.name });
    }
    edges.push({ from: contactId, to: c.id, label: 'referred' });
  });

  // Who referred this contact
  if (contact.referred_by) {
    const referrer = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(contact.referred_by, orgId);
    if (referrer && !nodes.find(n => n.id === referrer.id)) {
      nodes.push({ id: referrer.id, type: 'contact', label: referrer.name });
      edges.push({ from: referrer.id, to: contactId, label: 'referred' });
    }
  }

  res.json({ nodes, edges });
});

// GET /api/companies/:id/connections — contacts at this company with stats
app.get('/api/companies/:id/connections', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const companyId = req.params.id;

  const contacts = db.prepare('SELECT * FROM contacts WHERE company_id=? AND org_id=? ORDER BY name ASC').all(companyId, orgId);

  const result = contacts.map(c => {
    const dealCount = db.prepare('SELECT COUNT(*) as n FROM deals WHERE contact_id=? AND org_id=?').get(c.id, orgId)?.n || 0;
    const wonCount  = db.prepare("SELECT COUNT(*) as n FROM deals WHERE contact_id=? AND org_id=? AND stage='Won'").get(c.id, orgId)?.n || 0;

    // Simple health score (reuse Phase 22 logic basics)
    const actCount  = db.prepare('SELECT COUNT(*) as n FROM activities WHERE contact_id=? AND org_id=?').get(c.id, orgId)?.n || 0;
    const health = Math.min(100, (actCount * 5) + (wonCount * 20) + (dealCount * 10) + (c.last_activity ? 20 : 0));

    return {
      id: c.id,
      name: c.name,
      title: c.title || '',
      email: c.email || '',
      stage: c.stage || '',
      dealCount,
      wonCount,
      healthScore: health,
    };
  });

  res.json(result);
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 25: ADVANCED EMAIL SEQUENCES V2
// ─────────────────────────────────────────────────────────────────────────

// GET /api/sequence-enrollments
app.get('/api/sequence-enrollments', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const rows = db.prepare(`
    SELECT se.*, c.name as contact_name, c.email as contact_email
    FROM sequence_enrollments se
    LEFT JOIN contacts c ON c.id = se.contact_id
    WHERE se.org_id=?
    ORDER BY se.enrolled_at DESC
  `).all(orgId);
  res.json(rows.map(r => ({
    id: r.id,
    contactId: r.contact_id,
    contactName: r.contact_name || '',
    contactEmail: r.contact_email || '',
    sequenceId: r.sequence_id,
    currentStep: r.current_step,
    enrolledAt: r.enrolled_at,
    lastAdvanced: r.last_advanced,
    status: r.status,
  })));
});

// POST /api/sequence-enrollments — enroll one or more contacts
app.post('/api/sequence-enrollments', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contactIds, sequenceId } = req.body;
  if (!sequenceId || !Array.isArray(contactIds) || !contactIds.length) {
    return res.status(400).json({ error: 'contactIds and sequenceId required' });
  }

  const ins = db.prepare(`
    INSERT OR IGNORE INTO sequence_enrollments (id, org_id, contact_id, sequence_id, current_step, enrolled_at, status, created_at)
    VALUES (?, ?, ?, ?, 0, ?, 'Active', ?)
  `);

  const now = Date.now();
  const created = [];
  db.transaction(() => {
    contactIds.forEach(cid => {
      const id = 'se_' + uid();
      ins.run(id, orgId, cid, sequenceId, now, now);
      created.push(id);
    });
  })();

  res.status(201).json({ ok: true, enrolled: created.length });
});

// PATCH /api/sequence-enrollments/:id/advance
app.patch('/api/sequence-enrollments/:id/advance', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const enr = db.prepare('SELECT * FROM sequence_enrollments WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!enr) return res.status(404).json({ error: 'Not found' });

  // Load sequence to determine total steps
  let steps = [];
  try {
    const seqRow = db.prepare('SELECT steps FROM sequences WHERE id=? AND org_id=?').get(enr.sequence_id, orgId);
    if (seqRow) steps = JSON.parse(seqRow.steps || '[]');
  } catch {}

  const nextStep = enr.current_step + 1;
  const newStatus = nextStep >= steps.length ? 'Completed' : enr.status;

  db.prepare('UPDATE sequence_enrollments SET current_step=?, last_advanced=?, status=? WHERE id=? AND org_id=?')
    .run(nextStep, Date.now(), newStatus, req.params.id, orgId);

  res.json({ ok: true, currentStep: nextStep, status: newStatus });
});

// PATCH /api/sequence-enrollments/:id/pause
app.patch('/api/sequence-enrollments/:id/pause', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const result = db.prepare("UPDATE sequence_enrollments SET status='Paused' WHERE id=? AND org_id=?").run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// PATCH /api/sequence-enrollments/:id/resume
app.patch('/api/sequence-enrollments/:id/resume', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const result = db.prepare("UPDATE sequence_enrollments SET status='Active' WHERE id=? AND org_id=?").run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// DELETE /api/sequence-enrollments/:id
app.delete('/api/sequence-enrollments/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const result = db.prepare('DELETE FROM sequence_enrollments WHERE id=? AND org_id=?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 25: SALES FORECASTING V2
// ─────────────────────────────────────────────────────────────────────────

// GET /api/reports/forecast-v2?seasonality=0
app.get('/api/reports/forecast-v2', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const seasonality = parseFloat(req.query.seasonality || '0'); // -0.20 to +0.20

  const now = new Date();
  const thisMonth = now.getMonth(); // 0-indexed
  const thisYear  = now.getFullYear();
  const thisQ     = Math.floor(thisMonth / 3);

  // Helper: get YYYY-MM string for a month offset
  function monthStr(year, month) {
    return `${year}-${String(month + 1).padStart(2, '0')}`;
  }

  // Get all open deals with close dates
  const allDeals = db.prepare("SELECT * FROM deals WHERE org_id=? AND stage NOT IN ('Won','Lost')").all(orgId);

  // Health score calc (simplified from Phase 22)
  function healthScore(deal) {
    let score = 50;
    const stageScores = { 'To Contact': 10, 'Contacted': 25, 'Proposal Sent': 50, 'Negotiation': 75 };
    score = stageScores[deal.stage] || 50;

    const actCount = db.prepare('SELECT COUNT(*) as n FROM activities WHERE deal_id=? AND org_id=?').get(deal.id, orgId)?.n || 0;
    score += Math.min(20, actCount * 3);

    const ageDays = Math.floor((Date.now() - deal.created_at) / 86400000);
    if (ageDays > 90) score -= 15;

    return Math.max(0, Math.min(100, score));
  }

  // This month range
  const monthStart = new Date(thisYear, thisMonth, 1).toISOString().slice(0, 10);
  const monthEnd   = new Date(thisYear, thisMonth + 1, 0).toISOString().slice(0, 10);

  // This quarter range
  const qStart = new Date(thisYear, thisQ * 3, 1).toISOString().slice(0, 10);
  const qEnd   = new Date(thisYear, thisQ * 3 + 3, 0).toISOString().slice(0, 10);

  // ── Three tiers ──────────────────────────────────────────────────────────
  let commit = 0, bestCase = 0, pipeline = 0;
  let commitCount = 0, bestCaseCount = 0, pipelineCount = 0;

  allDeals.forEach(d => {
    const hs = healthScore(d);
    const prob = hs / 100;
    const val = d.value || 0;
    const closeDate = d.close_date || '';

    // Commit: health > 70% and closing this month
    if (hs > 70 && closeDate >= monthStart && closeDate <= monthEnd) {
      commit += val;
      commitCount++;
    }

    // Best Case: all open deals closing this month × health probability
    if (closeDate >= monthStart && closeDate <= monthEnd) {
      bestCase += val * prob;
      bestCaseCount++;
    }

    // Pipeline: all open deals closing this quarter × 50% (then apply seasonality)
    if (closeDate >= qStart && closeDate <= qEnd) {
      pipeline += val * 0.5 * (1 + seasonality);
      pipelineCount++;
    }
  });

  // ── Last month for variance ───────────────────────────────────────────────
  const lastMonthIdx  = thisMonth === 0 ? 11 : thisMonth - 1;
  const lastMonthYear = thisMonth === 0 ? thisYear - 1 : thisYear;
  const lmStart = new Date(lastMonthYear, lastMonthIdx, 1).toISOString().slice(0, 10);
  const lmEnd   = new Date(lastMonthYear, lastMonthIdx + 1, 0).toISOString().slice(0, 10);

  const lastMonthWon = db.prepare(
    "SELECT COALESCE(SUM(value),0) as total FROM deals WHERE org_id=? AND stage='Won' AND close_date>=? AND close_date<=?"
  ).get(orgId, lmStart, lmEnd)?.total || 0;

  // ── 6-month forecast table ───────────────────────────────────────────────
  const forecastTable = [];
  for (let i = 0; i < 6; i++) {
    const mIdx  = (thisMonth + i) % 12;
    const mYear = thisYear + Math.floor((thisMonth + i) / 12);
    const ms = new Date(mYear, mIdx, 1).toISOString().slice(0, 10);
    const me = new Date(mYear, mIdx + 1, 0).toISOString().slice(0, 10);

    const monthDeals = allDeals.filter(d => d.close_date >= ms && d.close_date <= me);
    const mCommit    = monthDeals.filter(d => healthScore(d) > 70).reduce((s, d) => s + (d.value || 0), 0);
    const mBest      = monthDeals.reduce((s, d) => s + (d.value || 0) * (healthScore(d) / 100), 0);
    const mPipeline  = monthDeals.reduce((s, d) => s + (d.value || 0) * 0.5 * (1 + seasonality), 0);
    const mWon = db.prepare(
      "SELECT COALESCE(SUM(value),0) as total FROM deals WHERE org_id=? AND stage='Won' AND close_date>=? AND close_date<=?"
    ).get(orgId, ms, me)?.total || 0;

    forecastTable.push({
      month: monthStr(mYear, mIdx),
      committed: Math.round(mCommit),
      bestCase: Math.round(mBest),
      pipeline: Math.round(mPipeline),
      dealsClosing: monthDeals.length,
      wonRevenue: Math.round(mWon),
    });
  }

  res.json({
    commit: Math.round(commit),
    bestCase: Math.round(bestCase),
    pipeline: Math.round(pipeline),
    commitCount,
    bestCaseCount,
    pipelineCount,
    lastMonthWon: Math.round(lastMonthWon),
    forecastTable,
    seasonality,
    generatedAt: now.toISOString(),
  });
});

// GET /api/reports/forecast-v2/csv — exportable CSV
app.get('/api/reports/forecast-v2/csv', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const seasonality = parseFloat(req.query.seasonality || '0');

  // Reuse logic inline
  const now = new Date();
  const thisMonth = now.getMonth();
  const thisYear  = now.getFullYear();

  function healthScore(deal) {
    let score = 50;
    const stageScores = { 'To Contact': 10, 'Contacted': 25, 'Proposal Sent': 50, 'Negotiation': 75 };
    score = stageScores[deal.stage] || 50;
    const actCount = db.prepare('SELECT COUNT(*) as n FROM activities WHERE deal_id=? AND org_id=?').get(deal.id, orgId)?.n || 0;
    score += Math.min(20, actCount * 3);
    return Math.max(0, Math.min(100, score));
  }

  const allDeals = db.prepare("SELECT * FROM deals WHERE org_id=? AND stage NOT IN ('Won','Lost')").all(orgId);

  const rows = [['Month', 'Committed', 'Best Case', 'Pipeline', 'Deals Closing', 'Won Revenue']];
  for (let i = 0; i < 6; i++) {
    const mIdx  = (thisMonth + i) % 12;
    const mYear = thisYear + Math.floor((thisMonth + i) / 12);
    const ms = new Date(mYear, mIdx, 1).toISOString().slice(0, 10);
    const me = new Date(mYear, mIdx + 1, 0).toISOString().slice(0, 10);
    const mStr = `${mYear}-${String(mIdx + 1).padStart(2, '0')}`;
    const monthDeals = allDeals.filter(d => d.close_date >= ms && d.close_date <= me);
    const mCommit   = monthDeals.filter(d => healthScore(d) > 70).reduce((s, d) => s + (d.value || 0), 0);
    const mBest     = monthDeals.reduce((s, d) => s + (d.value || 0) * (healthScore(d) / 100), 0);
    const mPipeline = monthDeals.reduce((s, d) => s + (d.value || 0) * 0.5 * (1 + seasonality), 0);
    const mWon = db.prepare("SELECT COALESCE(SUM(value),0) as total FROM deals WHERE org_id=? AND stage='Won' AND close_date>=? AND close_date<=?").get(orgId, ms, me)?.total || 0;
    rows.push([mStr, Math.round(mCommit), Math.round(mBest), Math.round(mPipeline), monthDeals.length, Math.round(mWon)]);
  }

  const csv = rows.map(r => r.join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="forecast.csv"');
  res.send(csv);
});

// ─────────────────────────────────────────────────────────────────────────
// PHASE 25: SLACK NOTIFICATIONS INTEGRATION
// ─────────────────────────────────────────────────────────────────────────

// POST /api/settings/slack/notify — frontend fires this for overdue events
app.post('/api/settings/slack/notify', requireAuth, async (req, res) => {
  const { orgId } = req.user;
  const { event, message } = req.body;
  if (!event || !message) return res.status(400).json({ error: 'event and message required' });
  try {
    await fireSlackNotification(orgId, event, message);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/settings/slack
app.get('/api/settings/slack', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const webhookRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slack_webhook_url'").get(orgId);
  const eventsRow  = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slack_enabled_events'").get(orgId);
  res.json({
    webhookUrl: webhookRow?.value || '',
    enabledEvents: eventsRow ? JSON.parse(eventsRow.value || '[]') : [],
  });
});

// PUT /api/settings/slack
app.put('/api/settings/slack', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { webhookUrl, enabledEvents } = req.body;
  db.prepare("INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, 'slack_webhook_url', ?)").run(orgId, webhookUrl || '');
  db.prepare("INSERT OR REPLACE INTO settings (org_id, key, value) VALUES (?, 'slack_enabled_events', ?)").run(orgId, JSON.stringify(enabledEvents || []));
  res.json({ ok: true });
});

// POST /api/settings/slack/test — sends a test message
app.post('/api/settings/slack/test', requireAuth, async (req, res) => {
  const { orgId } = req.user;
  const webhookRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slack_webhook_url'").get(orgId);
  const url = webhookRow?.value;
  if (!url) return res.status(400).json({ error: 'No Slack webhook URL configured' });

  try {
    const https = require('https');
    const http  = require('http');
    const payload = JSON.stringify({ text: '*BoredRoom CRM* — Test notification. Your Slack integration is working.' });
    await sendSlackMessage(url, payload);
    res.json({ ok: true, message: 'Test message sent' });
  } catch(err) {
    res.status(500).json({ error: 'Failed to send: ' + err.message });
  }
});

// Helper: send Slack webhook
function sendSlackMessage(webhookUrl, text) {
  return new Promise((resolve, reject) => {
    const payload = typeof text === 'string' ? text : JSON.stringify(text);
    const urlObj = new (require('url').URL)(webhookUrl);
    const lib = webhookUrl.startsWith('https') ? require('https') : require('http');
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) },
    };
    const req = lib.request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// Helper: fire Slack notification if event is enabled
async function fireSlackNotification(orgId, event, message) {
  try {
    const webhookRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slack_webhook_url'").get(orgId);
    const eventsRow  = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='slack_enabled_events'").get(orgId);
    if (!webhookRow?.value) return;
    const enabledEvents = eventsRow ? JSON.parse(eventsRow.value || '[]') : [];
    if (!enabledEvents.includes(event)) return;
    await sendSlackMessage(webhookRow.value, JSON.stringify({ text: message }));
  } catch(e) {
    // Non-fatal
  }
}

// ══════════════════════════════════════════════════════════════════════════════
// PHASE 26 — Calendar, MRR Metrics, Support Tickets, CSV Import Mapping, 2FA
// ══════════════════════════════════════════════════════════════════════════════

// ── Row helper ───────────────────────────────────────────────────────────────
function rowToTicket(r) {
  if (!r) return null;
  return {
    id: r.id, orgId: r.org_id, title: r.title, description: r.description,
    status: r.status, priority: r.priority, category: r.category,
    assignedTo: r.assigned_to, contactId: r.contact_id, dealId: r.deal_id,
    createdBy: r.created_by,
    createdAt: r.created_at, updatedAt: r.updated_at, resolvedAt: r.resolved_at,
  };
}

// ── 1. Calendar API ──────────────────────────────────────────────────────────
app.get('/api/calendar', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { start, end } = req.query;
  if (!start || !end) return res.status(400).json({ error: 'start and end required' });

  const startMs = new Date(start).getTime();
  const endMs   = new Date(end).getTime();

  const events = [];

  // Tasks (due_date)
  const tasks = db.prepare(`
    SELECT t.*, c.name as contact_name, d.name as deal_name
    FROM tasks t
    LEFT JOIN contacts c ON t.contact_id = c.id
    LEFT JOIN deals d ON t.deal_id = d.id
    WHERE t.org_id = ? AND t.due_date IS NOT NULL AND t.due_date != ''
  `).all(orgId);
  tasks.forEach(t => {
    const dt = new Date(t.due_date);
    if (!isNaN(dt) && dt >= new Date(start) && dt <= new Date(end)) {
      events.push({
        id: 'task_' + t.id, type: 'task', title: t.title,
        date: t.due_date, entityId: t.id, entityType: 'task',
        contactId: t.contact_id, dealId: t.deal_id,
        meta: { priority: t.priority, status: t.status, contactName: t.contact_name, dealName: t.deal_name },
      });
    }
  });

  // Meetings (scheduled_at)
  const meetings = db.prepare(`
    SELECT m.*, c.name as contact_name, d.name as deal_name
    FROM meetings m
    LEFT JOIN contacts c ON m.contact_id = c.id
    LEFT JOIN deals d ON m.deal_id = d.id
    WHERE m.org_id = ?
  `).all(orgId);
  meetings.forEach(m => {
    const dt = new Date(m.scheduled_at);
    if (!isNaN(dt) && dt >= new Date(start) && dt <= new Date(end)) {
      events.push({
        id: 'meeting_' + m.id, type: 'meeting', title: m.title,
        date: m.scheduled_at.slice(0, 10), time: m.scheduled_at,
        entityId: m.id, entityType: 'meeting',
        contactId: m.contact_id, dealId: m.deal_id,
        meta: { status: m.status, duration: m.duration_min, contactName: m.contact_name, dealName: m.deal_name },
      });
    }
  });

  // Deal close dates
  const deals = db.prepare(`
    SELECT id, name, close_date, stage, value, contact_id, company_id
    FROM deals WHERE org_id = ? AND close_date IS NOT NULL AND close_date != ''
  `).all(orgId);
  deals.forEach(d => {
    const dt = new Date(d.close_date);
    if (!isNaN(dt) && dt >= new Date(start) && dt <= new Date(end)) {
      events.push({
        id: 'deal_' + d.id, type: 'deal', title: d.name + ' (Close)',
        date: d.close_date, entityId: d.id, entityType: 'deal',
        meta: { stage: d.stage, value: d.value },
      });
    }
  });

  // Renewals (renewal_date)
  const renewals = db.prepare(`
    SELECT r.*, c.name as contact_name
    FROM renewals r LEFT JOIN contacts c ON r.contact_id = c.id
    WHERE r.org_id = ? AND r.renewal_date IS NOT NULL AND r.renewal_date != ''
  `).all(orgId);
  renewals.forEach(r => {
    const dt = new Date(r.renewal_date);
    if (!isNaN(dt) && dt >= new Date(start) && dt <= new Date(end)) {
      events.push({
        id: 'renewal_' + r.id, type: 'followup', title: r.service_name + ' Renewal',
        date: r.renewal_date, entityId: r.id, entityType: 'renewal',
        meta: { status: r.status, mrr: r.mrr, contactName: r.contact_name },
      });
    }
  });

  // Recurring task instances (generate from templates for date range)
  const recurringTemplates = db.prepare(`
    SELECT * FROM recurring_task_templates WHERE org_id = ? AND active = 1
  `).all(orgId);
  recurringTemplates.forEach(tpl => {
    const startDate = new Date(start);
    const endDate   = new Date(end);
    let cursor = new Date(startDate);
    while (cursor <= endDate) {
      let match = false;
      if (tpl.frequency === 'daily') match = true;
      else if (tpl.frequency === 'weekly' && cursor.getDay() === (tpl.day_of_week || 1)) match = true;
      else if (tpl.frequency === 'monthly' && cursor.getDate() === (tpl.day_of_month || 1)) match = true;
      if (match) {
        const dateStr = cursor.toISOString().slice(0, 10);
        events.push({
          id: 'recurring_' + tpl.id + '_' + dateStr, type: 'task',
          title: '[Recurring] ' + tpl.title,
          date: dateStr, entityId: tpl.id, entityType: 'recurring',
          meta: { recurring: true },
        });
      }
      cursor.setDate(cursor.getDate() + 1);
    }
  });

  res.json(events);
});

// ── 2. MRR Metrics API ───────────────────────────────────────────────────────
app.get('/api/metrics/mrr', requireAuth, (req, res) => {
  const { orgId } = req.user;

  // Current active renewals MRR
  const activeRenewals = db.prepare(
    "SELECT mrr, service_name, contact_id, company_id, renewal_date FROM renewals WHERE org_id = ? AND LOWER(status) = 'active'"
  ).all(orgId);
  const totalMRR = activeRenewals.reduce((s, r) => s + (r.mrr || 0), 0);
  const totalARR = totalMRR * 12;

  // Also check subscriptions table
  const activeSubs = db.prepare(
    "SELECT mrr, plan_name, company_id FROM subscriptions WHERE org_id = ? AND status = 'active'"
  ).all(orgId);
  const subsMRR = activeSubs.reduce((s, s2) => s + (s2.mrr || 0), 0);

  const combinedMRR = totalMRR + subsMRR;
  const combinedARR = combinedMRR * 12;

  // MRR by month (last 12 months) — approximate from created_at of renewals
  const now = new Date();
  const mrrByMonth = [];
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
    const label = d.toLocaleString('default', { month: 'short', year: '2-digit' });
    // Count renewals created before end of this month and still active
    const endOfMonth = new Date(d.getFullYear(), d.getMonth() + 1, 0).getTime();
    const mrr = db.prepare(
      "SELECT COALESCE(SUM(mrr),0) as total FROM renewals WHERE org_id=? AND LOWER(status)='active' AND created_at <= ?"
    ).get(orgId, endOfMonth)?.total || 0;
    const smrr = db.prepare(
      "SELECT COALESCE(SUM(mrr),0) as total FROM subscriptions WHERE org_id=? AND status='active' AND created_at <= ?"
    ).get(orgId, endOfMonth)?.total || 0;
    mrrByMonth.push({ label, mrr: mrr + smrr, month: d.toISOString().slice(0, 7) });
  }

  // Churn: churned renewals in last 30 days
  const thirtyDaysAgo = Date.now() - 30 * 86400000;
  const churnedMRR = db.prepare(
    "SELECT COALESCE(SUM(mrr),0) as total FROM renewals WHERE org_id=? AND LOWER(status) IN ('churned','cancelled','canceled')"
  ).get(orgId)?.total || 0;

  const newMRR = db.prepare(
    "SELECT COALESCE(SUM(mrr),0) as total FROM renewals WHERE org_id=? AND LOWER(status)='active' AND created_at >= ?"
  ).get(orgId, thirtyDaysAgo)?.total || 0;

  const totalBase = combinedMRR + churnedMRR;
  const churnRate = totalBase > 0 ? ((churnedMRR / totalBase) * 100) : 0;
  // NRR: (current MRR - churned) / (current MRR - new MRR this month) * 100
  const prevMRR = Math.max(combinedMRR - newMRR, 0);
  const nrr = prevMRR > 0 ? (((combinedMRR - churnedMRR) / prevMRR) * 100) : 100;

  // Top 10 accounts by MRR
  const topAccounts = db.prepare(`
    SELECT r.service_name, r.mrr, r.contact_id, r.company_id,
           c.name as contact_name, co.name as company_name
    FROM renewals r
    LEFT JOIN contacts c ON r.contact_id = c.id
    LEFT JOIN companies co ON r.company_id = co.id
    WHERE r.org_id = ? AND LOWER(r.status) = 'active'
    ORDER BY r.mrr DESC LIMIT 10
  `).all(orgId);

  res.json({
    mrr: combinedMRR,
    arr: combinedARR,
    churnRate: Math.round(churnRate * 10) / 10,
    nrr: Math.round(nrr * 10) / 10,
    newMRR,
    churnedMRR,
    mrrByMonth,
    topAccounts: topAccounts.map(a => ({
      name: a.company_name || a.contact_name || a.service_name,
      serviceName: a.service_name,
      mrr: a.mrr,
      companyId: a.company_id,
      contactId: a.contact_id,
    })),
  });
});

// ── 3. Support Tickets API ───────────────────────────────────────────────────
app.get('/api/tickets', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { status, priority, assigned } = req.query;
  let sql = `SELECT t.*, c.name as contact_name, d.name as deal_name
    FROM tickets t
    LEFT JOIN contacts c ON t.contact_id = c.id
    LEFT JOIN deals d ON t.deal_id = d.id
    WHERE t.org_id = ?`;
  const params = [orgId];
  if (status)   { sql += ' AND t.status = ?';      params.push(status); }
  if (priority) { sql += ' AND t.priority = ?';    params.push(priority); }
  if (assigned) { sql += ' AND t.assigned_to = ?'; params.push(assigned); }
  sql += ' ORDER BY t.created_at DESC';
  const rows = db.prepare(sql).all(...params);
  res.json(rows.map(r => ({ ...rowToTicket(r), contactName: r.contact_name, dealName: r.deal_name })));
});

app.get('/api/tickets/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const row = db.prepare(`
    SELECT t.*, c.name as contact_name, d.name as deal_name
    FROM tickets t
    LEFT JOIN contacts c ON t.contact_id = c.id
    LEFT JOIN deals d ON t.deal_id = d.id
    WHERE t.id = ? AND t.org_id = ?
  `).get(req.params.id, orgId);
  if (!row) return res.status(404).json({ error: 'Not found' });
  const comments = db.prepare('SELECT * FROM ticket_comments WHERE ticket_id = ? ORDER BY created_at ASC').all(req.params.id);
  res.json({ ...rowToTicket(row), contactName: row.contact_name, dealName: row.deal_name, comments });
});

app.post('/api/tickets', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const b = req.body;
  const id = 'tkt_' + uid();
  db.prepare(`INSERT INTO tickets (id, org_id, title, description, status, priority, category, assigned_to, contact_id, deal_id, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, orgId, b.title, b.description||'', b.status||'Open', b.priority||'Medium',
    b.category||'', b.assignedTo||'', b.contactId||null, b.dealId||null, userId, Date.now(), Date.now());
  res.status(201).json(rowToTicket(db.prepare('SELECT * FROM tickets WHERE id=?').get(id)));
});

app.put('/api/tickets/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const b = req.body;
  const resolvedAt = (b.status === 'Resolved' || b.status === 'Closed')
    ? (db.prepare('SELECT resolved_at FROM tickets WHERE id=?').get(req.params.id)?.resolved_at || Date.now())
    : null;
  const result = db.prepare(`UPDATE tickets SET title=?, description=?, status=?, priority=?, category=?,
    assigned_to=?, contact_id=?, deal_id=?, updated_at=?, resolved_at=?
    WHERE id=? AND org_id=?`
  ).run(b.title, b.description||'', b.status, b.priority, b.category||'',
    b.assignedTo||'', b.contactId||null, b.dealId||null, Date.now(), resolvedAt,
    req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json(rowToTicket(db.prepare('SELECT * FROM tickets WHERE id=?').get(req.params.id)));
});

app.delete('/api/tickets/:id', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const result = db.prepare('DELETE FROM tickets WHERE id=? AND org_id=?').run(req.params.id, orgId);
  if (!result.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Ticket comments
app.post('/api/tickets/:id/comments', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { body, internal } = req.body;
  if (!body) return res.status(400).json({ error: 'body required' });
  const ticket = db.prepare('SELECT id FROM tickets WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!ticket) return res.status(404).json({ error: 'Ticket not found' });
  const id = 'tc_' + uid();
  db.prepare(`INSERT INTO ticket_comments (id, org_id, ticket_id, author_id, author_name, body, internal, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, orgId, req.params.id, userId, userName, body, internal ? 1 : 0, Date.now());
  // Update ticket updated_at
  db.prepare('UPDATE tickets SET updated_at=? WHERE id=?').run(Date.now(), req.params.id);
  const comment = db.prepare('SELECT * FROM ticket_comments WHERE id=?').get(id);
  res.status(201).json(comment);
});

app.delete('/api/tickets/:ticketId/comments/:commentId', requireAuth, (req, res) => {
  const { orgId } = req.user;
  db.prepare('DELETE FROM ticket_comments WHERE id=? AND org_id=?').run(req.params.commentId, orgId);
  res.json({ ok: true });
});

// ── 4. CSV Import Mapping API ────────────────────────────────────────────────
// POST /api/import/preview — takes CSV rows + mapping, returns preview + duplicate check
app.post('/api/import/preview', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { rows, mapping, entityType } = req.body;
  if (!rows || !mapping || !entityType) return res.status(400).json({ error: 'rows, mapping, entityType required' });

  const preview = rows.slice(0, 3).map(row => {
    const mapped = {};
    Object.entries(mapping).forEach(([csvCol, crmField]) => {
      if (crmField && crmField !== '__ignore__') mapped[crmField] = row[csvCol];
    });
    return mapped;
  });

  // Duplicate check
  const duplicates = [];
  if (entityType === 'contacts') {
    rows.forEach((row, i) => {
      const emailField = Object.entries(mapping).find(([, v]) => v === 'email')?.[0];
      const nameField  = Object.entries(mapping).find(([, v]) => v === 'name')?.[0];
      const email = emailField ? row[emailField] : null;
      const name  = nameField  ? row[nameField]  : null;
      let dup = null;
      if (email) dup = db.prepare('SELECT id, name, email FROM contacts WHERE org_id=? AND LOWER(email)=LOWER(?)').get(orgId, email);
      if (!dup && name) dup = db.prepare('SELECT id, name, email FROM contacts WHERE org_id=? AND LOWER(name)=LOWER(?)').get(orgId, name);
      if (dup) duplicates.push({ rowIndex: i, existingId: dup.id, existingName: dup.name, existingEmail: dup.email });
    });
  }

  res.json({ preview, duplicates, totalRows: rows.length });
});

// POST /api/import/execute — execute import with mapping + merge/skip choices
app.post('/api/import/execute', requireAuth, (req, res) => {
  const { orgId, userId, name: userName } = req.user;
  const { rows, mapping, entityType, duplicateActions } = req.body;
  if (!rows || !mapping || !entityType) return res.status(400).json({ error: 'rows, mapping, entityType required' });

  let created = 0, updated = 0, skipped = 0;

  db.transaction(() => {
    if (entityType === 'contacts') {
      const ins = db.prepare(`INSERT INTO contacts (id, org_id, name, email, phone, title, stage, owner, notes, lead_source, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      const upd = db.prepare(`UPDATE contacts SET name=?, email=?, phone=?, title=?, stage=?, owner=?, notes=?, lead_source=? WHERE id=?`);

      rows.forEach((row, i) => {
        const mapped = {};
        Object.entries(mapping).forEach(([csvCol, crmField]) => {
          if (crmField && crmField !== '__ignore__') mapped[crmField] = row[csvCol];
        });
        if (!mapped.name) { skipped++; return; }

        const dupAction = duplicateActions?.[i] || 'skip';
        let existingId = null;
        if (mapped.email) {
          const dup = db.prepare('SELECT id FROM contacts WHERE org_id=? AND LOWER(email)=LOWER(?)').get(orgId, mapped.email);
          if (dup) existingId = dup.id;
        }
        if (!existingId && mapped.name) {
          const dup = db.prepare('SELECT id FROM contacts WHERE org_id=? AND LOWER(name)=LOWER(?)').get(orgId, mapped.name);
          if (dup) existingId = dup.id;
        }

        if (existingId) {
          if (dupAction === 'skip') { skipped++; return; }
          if (dupAction === 'merge') {
            upd.run(mapped.name, mapped.email||'', mapped.phone||'', mapped.title||'', mapped.stage||'Lead', mapped.owner||'', mapped.notes||'', mapped.leadSource||'', existingId);
            updated++;
          }
        } else {
          ins.run('c_' + uid(), orgId, mapped.name, mapped.email||'', mapped.phone||'', mapped.title||'', mapped.stage||'Lead', mapped.owner||'', mapped.notes||'', mapped.leadSource||'', Date.now());
          created++;
        }
      });
    } else if (entityType === 'companies') {
      const ins = db.prepare(`INSERT INTO companies (id, org_id, name, industry, website, phone, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
      rows.forEach(row => {
        const mapped = {};
        Object.entries(mapping).forEach(([csvCol, crmField]) => {
          if (crmField && crmField !== '__ignore__') mapped[crmField] = row[csvCol];
        });
        if (!mapped.name) { skipped++; return; }
        const dup = db.prepare('SELECT id FROM companies WHERE org_id=? AND LOWER(name)=LOWER(?)').get(orgId, mapped.name);
        if (dup) { skipped++; return; }
        ins.run('co_' + uid(), orgId, mapped.name, mapped.industry||'', mapped.website||'', mapped.phone||'', mapped.notes||'', Date.now());
        created++;
      });
    }
  })();

  auditLog(orgId, userId, userName, 'import', null, entityType, 'csv_import');
  res.json({ ok: true, created, updated, skipped, total: rows.length });
});

// ── 5. Two-Factor Authentication (TOTP) ─────────────────────────────────────

// Minimal TOTP implementation (HMAC-SHA1, RFC 6238)
// Note: crypto is already required earlier in server.js

function base32Decode(base32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const output = [];
  for (const c of base32.toUpperCase().replace(/=+$/, '')) {
    const idx = chars.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { bits -= 8; output.push((value >>> bits) & 0xff); }
  }
  return Buffer.from(output);
}

function base32Encode(buf) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { bits -= 5; output += chars[(value >>> bits) & 31]; }
  }
  if (bits > 0) output += chars[(value << (5 - bits)) & 31];
  return output;
}

function generateTOTP(secret, window = 0) {
  const counter = Math.floor(Date.now() / 1000 / 30) + window;
  const buf = Buffer.alloc(8);
  buf.writeBigInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24 |
                  hmac[offset+1] << 16 |
                  hmac[offset+2] << 8 |
                  hmac[offset+3]) % 1000000;
  return code.toString().padStart(6, '0');
}

function verifyTOTP(secret, token) {
  for (const w of [-1, 0, 1]) {
    if (generateTOTP(secret, w) === token) return true;
  }
  return false;
}

// POST /api/auth/2fa/setup — generate TOTP secret
app.post('/api/auth/2fa/setup', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.totp_enabled) return res.status(400).json({ error: '2FA already enabled. Disable first.' });

  const secretBytes = crypto.randomBytes(20);
  const secret = base32Encode(secretBytes);
  db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(secret, user.id);

  const issuer = 'BoredRoom CRM';
  const label  = encodeURIComponent(issuer + ':' + user.email);
  const uri    = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

  res.json({ secret, uri });
});

// POST /api/auth/2fa/verify — verify code and enable 2FA
app.post('/api/auth/2fa/verify', requireAuth, (req, res) => {
  const { token } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.userId);
  if (!user || !user.totp_secret) return res.status(400).json({ error: 'Run setup first' });
  if (!token) return res.status(400).json({ error: 'token required' });

  if (!verifyTOTP(user.totp_secret, token.toString().trim())) {
    return res.status(401).json({ error: 'Invalid code' });
  }

  db.prepare('UPDATE users SET totp_enabled=1 WHERE id=?').run(user.id);
  res.json({ ok: true, message: '2FA enabled successfully' });
});

// POST /api/auth/2fa/disable
app.post('/api/auth/2fa/disable', requireAuth, (req, res) => {
  const { token } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'Not found' });
  if (!user.totp_enabled) return res.status(400).json({ error: '2FA not enabled' });

  if (!verifyTOTP(user.totp_secret, token?.toString()?.trim() || '')) {
    return res.status(401).json({ error: 'Invalid code' });
  }

  db.prepare('UPDATE users SET totp_enabled=0, totp_secret=NULL WHERE id=?').run(user.id);
  res.json({ ok: true });
});

// GET /api/auth/2fa/status
app.get('/api/auth/2fa/status', requireAuth, (req, res) => {
  const user = db.prepare('SELECT totp_enabled FROM users WHERE id=?').get(req.user.userId);
  res.json({ enabled: !!(user?.totp_enabled) });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 26 Deliverable 3: Pipeline Analytics Deep Dive ─────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/reports/pipeline-deep-dive', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const now = Date.now();

  // Get pipeline stages
  const stagesRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='pipelineStages'").get(orgId);
  const stages = safeJSON(stagesRow ? stagesRow.value : null, []).map(s => s.name || s).filter(s => s !== 'Lost');

  // All deals
  const allDeals = db.prepare('SELECT * FROM deals WHERE org_id=?').all(orgId);
  const wonDeals = allDeals.filter(d => d.stage === 'Won');

  // Per-stage: how many deals ever reached this stage
  // Use deal_stage_log for precision
  const stageFunnel = stages.map(stage => {
    const reached = db.prepare('SELECT COUNT(DISTINCT deal_id) as c FROM deal_stage_log WHERE org_id=? AND stage=?').get(orgId, stage);
    return { stage, count: reached ? reached.c : 0 };
  });

  // Conversion rates: from stage[i] → stage[i+1]
  const conversionRates = stageFunnel.map((item, i) => {
    if (i === 0) return { stage: item.stage, count: item.count, conversionRate: 100 };
    const prev = stageFunnel[i - 1].count || 1;
    return { stage: item.stage, count: item.count, conversionRate: Math.round((item.count / prev) * 100) };
  });

  // Average days per stage
  const avgDaysPerStage = stages.map(stage => {
    const entries = db.prepare('SELECT entered_at, exited_at FROM deal_stage_log WHERE org_id=? AND stage=? AND exited_at IS NOT NULL').all(orgId, stage);
    if (!entries.length) return { stage, avgDays: 0 };
    const totalMs = entries.reduce((sum, e) => sum + (e.exited_at - e.entered_at), 0);
    return { stage, avgDays: +(totalMs / entries.length / 86400000).toFixed(1) };
  });

  // Bottleneck: deals stuck in each stage > 14 days (still in that stage, no exited_at)
  const stuckDeals = stages.map(stage => {
    const cutoff = now - 14 * 86400000;
    const stuck = db.prepare('SELECT COUNT(*) as c FROM deal_stage_log WHERE org_id=? AND stage=? AND exited_at IS NULL AND entered_at < ?').get(orgId, stage, cutoff);
    return { stage, stuckCount: stuck ? stuck.c : 0 };
  });

  // Find worst bottleneck
  const bottleneck = [...avgDaysPerStage].sort((a, b) => b.avgDays - a.avgDays)[0];

  // Stage velocity: this quarter vs last quarter
  const quarterMs = 91 * 86400000;
  const thisQStart = now - quarterMs;
  const lastQStart = now - 2 * quarterMs;
  const lastQEnd   = now - quarterMs;

  const velocityComparison = stages.map(stage => {
    function avgDaysInRange(start, end) {
      const entries = db.prepare(
        'SELECT entered_at, exited_at FROM deal_stage_log WHERE org_id=? AND stage=? AND exited_at IS NOT NULL AND entered_at >= ? AND entered_at <= ?'
      ).all(orgId, stage, start, end);
      if (!entries.length) return null;
      const total = entries.reduce((s, e) => s + (e.exited_at - e.entered_at), 0);
      return +(total / entries.length / 86400000).toFixed(1);
    }
    const thisQ = avgDaysInRange(thisQStart, now);
    const lastQ = avgDaysInRange(lastQStart, lastQEnd);
    return { stage, thisQ, lastQ, delta: (thisQ !== null && lastQ !== null) ? +(thisQ - lastQ).toFixed(1) : null };
  });

  res.json({
    stages,
    conversionRates,
    avgDaysPerStage,
    stuckDeals,
    bottleneck,
    velocityComparison,
    totalDeals: allDeals.length,
    wonDeals: wonDeals.length,
  });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 26 Deliverable 4: Client Health Dashboard ───────────────────────
// ══════════════════════════════════════════════════════════════════════════

app.get('/api/customers', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const now = Date.now();

  const wonDeals = db.prepare('SELECT * FROM deals WHERE org_id=? AND stage=? ORDER BY created_at DESC').all(orgId, 'Won');

  const customers = wonDeals.map(deal => {
    // Contact
    const contact = deal.contact_id
      ? db.prepare('SELECT * FROM contacts WHERE id=?').get(deal.contact_id)
      : null;

    // Company
    const company = deal.company_id
      ? db.prepare('SELECT * FROM companies WHERE id=?').get(deal.company_id)
      : null;

    // Renewal
    const renewal = deal.contact_id
      ? db.prepare('SELECT * FROM renewals WHERE org_id=? AND (contact_id=? OR company_id=?) ORDER BY renewal_date ASC LIMIT 1').get(orgId, deal.contact_id, deal.company_id || '')
      : null;

    // Open tasks
    const taskCount = db.prepare("SELECT COUNT(*) as c FROM tasks WHERE org_id=? AND deal_id=? AND status='Open'").get(orgId, deal.id);

    // Last activity
    const lastAct = db.prepare('SELECT date FROM activities WHERE org_id=? AND deal_id=? ORDER BY created_at DESC LIMIT 1').get(orgId, deal.id);

    // Health score (composite: based on last activity recency, tasks, NPS if any)
    let healthScore = 70; // baseline
    if (lastAct && lastAct.date) {
      const daysSince = (now - new Date(lastAct.date).getTime()) / 86400000;
      if (daysSince < 30) healthScore += 15;
      else if (daysSince > 90) healthScore -= 20;
    }
    if (taskCount && taskCount.c > 3) healthScore -= 10;

    // NPS
    const latestNPS = db.prepare('SELECT score FROM nps_scores WHERE org_id=? AND deal_id=? ORDER BY created_at DESC LIMIT 1').get(orgId, deal.id);
    if (latestNPS) {
      if (latestNPS.score >= 9) healthScore += 10;
      else if (latestNPS.score <= 6) healthScore -= 15;
    }

    // Contact lead score
    if (contact) {
      const latestContactScore = db.prepare('SELECT score FROM lead_score_history WHERE org_id=? AND contact_id=? ORDER BY created_at DESC LIMIT 1').get(orgId, deal.contact_id);
      if (latestContactScore) {
        healthScore = Math.round((healthScore + latestContactScore.score) / 2);
      }
    }

    healthScore = Math.max(0, Math.min(100, healthScore));

    // Last invoice
    const lastInvoice = db.prepare('SELECT number, status, total, due_date FROM invoices WHERE org_id=? AND deal_id=? ORDER BY created_at DESC LIMIT 1').get(orgId, deal.id);

    return {
      dealId: deal.id,
      dealName: deal.name,
      dealValue: deal.value,
      closeDate: deal.close_date,
      stage: deal.stage,
      contactId: contact ? contact.id : null,
      contactName: contact ? contact.name : null,
      companyName: company ? company.name : (contact ? contact.company_id : null),
      renewalDate: renewal ? renewal.renewal_date : null,
      renewalService: renewal ? renewal.service_name : null,
      openTasks: taskCount ? taskCount.c : 0,
      lastActivityDate: lastAct ? lastAct.date : null,
      healthScore,
      npsScore: latestNPS ? latestNPS.score : null,
      lastInvoice: lastInvoice ? { number: lastInvoice.number, status: lastInvoice.status, total: lastInvoice.total, dueDate: lastInvoice.due_date } : null,
    };
  });

  res.json(customers);
});

app.get('/api/customers/:dealId', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const deal = db.prepare('SELECT * FROM deals WHERE id=? AND org_id=? AND stage=?').get(req.params.dealId, orgId, 'Won');
  if (!deal) return res.status(404).json({ error: 'Customer not found' });

  const contact = deal.contact_id ? db.prepare('SELECT * FROM contacts WHERE id=?').get(deal.contact_id) : null;
  const company = deal.company_id ? db.prepare('SELECT * FROM companies WHERE id=?').get(deal.company_id) : null;
  const renewal = db.prepare('SELECT * FROM renewals WHERE org_id=? AND (contact_id=? OR company_id=?) ORDER BY renewal_date ASC LIMIT 1').get(orgId, deal.contact_id || '', deal.company_id || '');
  const tasks = db.prepare("SELECT * FROM tasks WHERE org_id=? AND deal_id=? AND status='Open' ORDER BY due_date ASC").all(orgId, deal.id);
  const activities = db.prepare('SELECT * FROM activities WHERE org_id=? AND deal_id=? ORDER BY created_at DESC LIMIT 20').all(orgId, deal.id);
  const invoices = db.prepare('SELECT * FROM invoices WHERE org_id=? AND deal_id=? ORDER BY created_at DESC').all(orgId, deal.id);
  const npsScores = db.prepare('SELECT * FROM nps_scores WHERE org_id=? AND deal_id=? ORDER BY created_at DESC').all(orgId, deal.id);

  // Lead score history for contact
  const scoreHistory = deal.contact_id
    ? db.prepare('SELECT score, created_at FROM lead_score_history WHERE org_id=? AND contact_id=? ORDER BY created_at ASC LIMIT 30').all(orgId, deal.contact_id)
    : [];

  res.json({
    deal: rowToDeal(deal),
    contact: rowToContact(contact),
    company: rowToCompany(company),
    renewal,
    tasks: tasks.map(rowToTask),
    activities: activities.map(rowToActivity),
    invoices: invoices.map(rowToInvoice),
    npsScores,
    scoreHistory,
  });
});

// GET NPS scores for a deal
app.get('/api/customers/:dealId/nps', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const scores = db.prepare('SELECT * FROM nps_scores WHERE org_id=? AND deal_id=? ORDER BY created_at DESC').all(orgId, req.params.dealId);
  res.json(scores);
});

// POST NPS score
app.post('/api/customers/:dealId/nps', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const { contactId, score, comment } = req.body;
  if (score === undefined || score === null || score < 0 || score > 10) return res.status(400).json({ error: 'Score must be 0-10' });
  const id = 'nps_' + uid();
  const today = new Date().toISOString().slice(0, 10);
  db.prepare('INSERT INTO nps_scores (id, org_id, contact_id, deal_id, score, comment, submitted_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, orgId, contactId || null, req.params.dealId, score, comment || '', today, Date.now());
  res.status(201).json({ id, score, comment, submittedAt: today });
});

// ══════════════════════════════════════════════════════════════════════════
// ── Phase 26 Deliverable 5: Deal Room V2 ─────────────────────────────────
// ══════════════════════════════════════════════════════════════════════════

// Override portal-v2 GET to return threaded comments + client checklist actions + video_call_url
// We use a new endpoint to avoid conflicts with the existing GET handler
app.get('/api/portal-v2-v26/:token', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });

  const stagesRow = db.prepare("SELECT value FROM settings WHERE org_id=? AND key='pipelineStages'").get(deal.org_id);
  const stages = safeJSON(stagesRow ? stagesRow.value : null, []).map(s => s.name || s);
  const stageIdx = stages.indexOf(deal.stage);

  const activities = db.prepare('SELECT type, note, date FROM activities WHERE deal_id=? ORDER BY created_at DESC LIMIT 10').all(deal.id);
  const docs = db.prepare("SELECT id, title, url, type, date_added FROM doc_links WHERE entity_type='deal' AND entity_id=? ORDER BY date_added DESC").all(deal.id);
  const uploadedDocs = db.prepare("SELECT id, title, date_added FROM doc_links WHERE entity_type='portal_upload' AND entity_id=? ORDER BY date_added DESC").all(deal.id);
  const proposal = db.prepare('SELECT title, status, signed_at, viewed_at, created_at FROM proposals WHERE deal_id=? ORDER BY created_at DESC LIMIT 1').get(deal.id);

  // Threaded comments (include parent_comment_id)
  const allComments = db.prepare('SELECT id, author_name, body, parent_comment_id, created_at FROM portal_comments WHERE deal_id=? ORDER BY created_at ASC').all(deal.id);

  // Checklists with items
  const checklists = db.prepare('SELECT id, name FROM deal_checklists WHERE deal_id=?').all(deal.id);
  const clientActions = db.prepare('SELECT item_id, checked_by_name, checked_at FROM client_checklist_actions WHERE deal_id=?').all(deal.id);
  const clientActionMap = {};
  clientActions.forEach(a => { clientActionMap[a.item_id] = a; });

  const checklistsWithItems = checklists.map(cl => {
    const items = db.prepare('SELECT id, title, done, sort_order FROM deal_checklist_items WHERE checklist_id=? ORDER BY sort_order').all(cl.id);
    return {
      ...cl,
      items: items.map(item => ({
        ...item,
        clientChecked: !!clientActionMap[item.id],
        clientCheckedBy: clientActionMap[item.id] ? clientActionMap[item.id].checked_by_name : null,
      }))
    };
  });

  // Invoices with review status
  const invoiceRows = db.prepare('SELECT id, number, status, total, issue_date, due_date, items, notes FROM invoices WHERE deal_id=? ORDER BY created_at DESC').all(deal.id);
  const reviewedInvoiceIds = db.prepare('SELECT invoice_id FROM portal_invoice_reviews WHERE deal_id=?').all(deal.id).map(r => r.invoice_id);
  const invoices = invoiceRows.map(inv => ({
    id: inv.id, number: inv.number, status: inv.status, total: inv.total,
    issueDate: inv.issue_date, dueDate: inv.due_date,
    items: safeJSON(inv.items, []), notes: inv.notes,
    reviewed: reviewedInvoiceIds.includes(inv.id)
  }));

  // Log view
  try {
    db.prepare('INSERT INTO portal_views (id, org_id, deal_id, token, ip_hash, viewed_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run('pv_' + uid(), deal.org_id, deal.id, req.params.token, '', Date.now());
  } catch(e) {}

  res.json({
    dealName: deal.name,
    stage: deal.stage,
    stages,
    stageIdx,
    value: deal.value,
    closeDate: deal.close_date,
    videoCallUrl: deal.video_call_url || null,
    videoCallTime: deal.video_call_time || null,
    activities,
    docs,
    uploadedDocs,
    proposal,
    comments: allComments,
    checklists: checklistsWithItems,
    invoices,
  });
});

// POST threaded comment (supports parent_comment_id)
app.post('/api/portal-v2-v26/:token/comment', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const { authorName, body, parentCommentId } = req.body;
  if (!authorName || !body) return res.status(400).json({ error: 'authorName and body required' });
  const id = 'pc_' + uid();
  db.prepare('INSERT INTO portal_comments (id, org_id, deal_id, token, author_name, body, parent_comment_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, deal.org_id, deal.id, req.params.token, authorName, body, parentCommentId || null, Date.now());
  // Notify CRM users
  try {
    const users = db.prepare('SELECT id FROM users WHERE org_id=?').all(deal.org_id);
    users.forEach(u => {
      db.prepare('INSERT INTO notifications (id, org_id, user_id, type, message, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run('notif_' + uid(), deal.org_id, u.id, 'portal_comment', `New comment on "${deal.name}" from ${authorName}`, 'deal', deal.id, Date.now());
    });
  } catch(e) {}
  res.status(201).json({ id, authorName, body, parentCommentId: parentCommentId || null, createdAt: Date.now() });
});

// POST client checklist action
app.post('/api/portal-v2-v26/:token/client-checklist', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });
  const { itemId, checkedByName, checked } = req.body;
  if (!itemId || !checkedByName) return res.status(400).json({ error: 'itemId and checkedByName required' });

  if (checked === false || checked === 'false') {
    // Uncheck
    db.prepare('DELETE FROM client_checklist_actions WHERE deal_id=? AND item_id=?').run(deal.id, itemId);
    return res.json({ ok: true, checked: false });
  }

  const id = 'cca_' + uid();
  db.prepare('INSERT OR REPLACE INTO client_checklist_actions (id, org_id, deal_id, item_id, checked_by_name, checked_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, deal.org_id, deal.id, itemId, checkedByName, Date.now());
  res.status(201).json({ ok: true, checked: true, checkedByName });
});

// GET download package (text listing of all docs)
app.get('/api/portal-v2-v26/:token/download-package', (req, res) => {
  const deal = db.prepare('SELECT * FROM deals WHERE portal_token=?').get(req.params.token);
  if (!deal) return res.status(404).json({ error: 'Not found' });

  const docs = db.prepare("SELECT title, url, type, date_added FROM doc_links WHERE entity_type='deal' AND entity_id=? ORDER BY date_added DESC").all(deal.id);

  let content = `Document Package — ${deal.name}\n`;
  content += `Generated: ${new Date().toISOString().slice(0,10)}\n`;
  content += '='.repeat(60) + '\n\n';

  if (docs.length === 0) {
    content += 'No documents linked to this deal.\n';
  } else {
    docs.forEach((doc, i) => {
      content += `${i + 1}. ${doc.title}\n`;
      if (doc.url) content += `   URL: ${doc.url}\n`;
      if (doc.type) content += `   Type: ${doc.type}\n`;
      if (doc.date_added) content += `   Added: ${doc.date_added}\n`;
      content += '\n';
    });
  }

  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', `attachment; filename="document-package-${deal.id}.txt"`);
  res.send(content);
});

// ── Phase 26 Deliverable 2: AI Email Draft (server-side data) ─────────────

app.get('/api/contacts/:id/email-context', requireAuth, (req, res) => {
  const { orgId } = req.user;
  const contact = db.prepare('SELECT * FROM contacts WHERE id=? AND org_id=?').get(req.params.id, orgId);
  if (!contact) return res.status(404).json({ error: 'Not found' });

  const lastActivity = db.prepare('SELECT * FROM activities WHERE contact_id=? AND org_id=? ORDER BY created_at DESC LIMIT 1').get(req.params.id, orgId);
  const openDeals = db.prepare("SELECT * FROM deals WHERE contact_id=? AND org_id=? AND stage NOT IN ('Won','Lost') ORDER BY created_at DESC").all(req.params.id, orgId);
  const enrollment = db.prepare("SELECT se.*, s.name as seq_name FROM sequence_enrollments se JOIN sequences s ON se.sequence_id=s.id WHERE se.contact_id=? AND se.org_id=? AND se.status='Active' LIMIT 1").get(req.params.id, orgId);
  const lastEmail = db.prepare("SELECT * FROM email_logs WHERE contact_id=? AND org_id=? ORDER BY created_at DESC LIMIT 1").get(req.params.id, orgId);

  const now = Date.now();
  const daysSinceActivity = lastActivity
    ? Math.floor((now - lastActivity.created_at) / 86400000)
    : null;
  const daysSinceEmail = lastEmail
    ? Math.floor((now - lastEmail.created_at) / 86400000)
    : null;

  const company = contact.company_id
    ? db.prepare('SELECT * FROM companies WHERE id=?').get(contact.company_id)
    : null;

  res.json({
    contact: rowToContact(contact),
    company: rowToCompany(company),
    lastActivity: lastActivity ? rowToActivity(lastActivity) : null,
    openDeals: openDeals.map(rowToDeal),
    sequenceEnrollment: enrollment ? { sequenceName: enrollment.seq_name, currentStep: enrollment.current_step, status: enrollment.status } : null,
    daysSinceActivity,
    daysSinceEmail,
  });
});

// ── Hubnot Chat ─────────────────────────────────────────────────────────────
app.post('/api/chat', requireAuth, async (req, res) => {
  try {
    const { message, history = [] } = req.body;
    if (!message) return res.status(400).json({ error: 'message required' });

    // Pull live CRM context from DB
    const dealRows  = db.prepare(`SELECT stage, value, probability FROM deals WHERE deleted_at IS NULL`).all();
    const pipeline  = dealRows.reduce((s, d) => s + (d.value || 0), 0);
    const weighted  = dealRows.reduce((s, d) => s + ((d.value || 0) * ((d.probability || 0) / 100)), 0);
    const byStage   = dealRows.reduce((acc, d) => { acc[d.stage] = (acc[d.stage] || 0) + 1; return acc; }, {});
    const contacts  = db.prepare(`SELECT COUNT(*) as n FROM contacts WHERE deleted_at IS NULL`).get();
    const companies = db.prepare(`SELECT COUNT(*) as n FROM companies WHERE deleted_at IS NULL`).get();
    const tasks     = db.prepare(`SELECT COUNT(*) as n FROM tasks WHERE done=0`).get();
    const recentAct = db.prepare(`SELECT type, note, contact_id FROM activities ORDER BY created_at DESC LIMIT 5`).all();

    const crmContext = `
You are O'Brien, Andrew Emmel's AI assistant, embedded in Hubnot (a custom CRM built for BoredRoom).
Andrew is a 38-year-old entrepreneur in Minot, North Dakota. He runs Prairie Pumping (concrete), plays music, and is building ND.AI (AI consulting) and BoredRoom (a CRM/tech platform).
Be sharp, direct, and useful. No corporate speak. You have real-time access to Hubnot data:

LIVE CRM SNAPSHOT:
- Total pipeline: $${pipeline.toLocaleString()}
- Weighted forecast: $${Math.round(weighted).toLocaleString()}
- Deals by stage: ${JSON.stringify(byStage)}
- Contacts: ${contacts.n} | Companies: ${companies.n}
- Open tasks: ${tasks.n}
- Recent activity: ${recentAct.map(a => `${a.type}: ${(a.note||'').slice(0,60)}`).join(' | ')}
`.trim();

    // Build messages for OpenClaw
    const messages = [
      { role: 'system', content: crmContext },
      ...history.slice(-8),
      { role: 'user', content: message }
    ];

    // Call OpenClaw gateway
    const ocRes = await fetch('http://localhost:18789/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer 2086b1b6db2ef39dce29f7d55fc608647e7851c78a74569a',
        'x-openclaw-agent-id': 'main'
      },
      body: JSON.stringify({ model: 'openclaw', messages, max_tokens: 800 })
    });

    if (!ocRes.ok) {
      const err = await ocRes.text();
      console.error('[Hubnot chat] OpenClaw error:', err);
      return res.status(502).json({ error: 'OpenClaw gateway error', detail: err });
    }

    const data = await ocRes.json();
    const reply = data?.choices?.[0]?.message?.content || '(no response)';
    res.json({ reply });

  } catch (err) {
    console.error('[Hubnot chat] Error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '26.0.0', time: new Date().toISOString() });
});

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 BoredRoom CRM API running on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
});
