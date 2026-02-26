/**
 * BoredRoom CRM — SQLite Database Layer
 * Phase 14
 */
'use strict';

const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'data', 'crm.db');

// Ensure data directory exists
const fs = require('fs');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ─────────────────────────────────────────────────────────────────
db.exec(`
  -- Organizations (multi-tenant root)
  CREATE TABLE IF NOT EXISTS orgs (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Users
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email       TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,
    name        TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin','user')),
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Companies
  CREATE TABLE IF NOT EXISTS companies (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    industry    TEXT,
    website     TEXT,
    phone       TEXT,
    address     TEXT,
    city        TEXT,
    notes       TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Contacts
  CREATE TABLE IF NOT EXISTS contacts (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    email         TEXT,
    phone         TEXT,
    company_id    TEXT REFERENCES companies(id) ON DELETE SET NULL,
    title         TEXT,
    stage         TEXT DEFAULT 'Lead',
    owner         TEXT,
    tags          TEXT DEFAULT '[]',
    notes         TEXT,
    custom_fields TEXT DEFAULT '{}',
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    last_activity INTEGER
  );

  -- Deals
  CREATE TABLE IF NOT EXISTS deals (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    company_id  TEXT REFERENCES companies(id) ON DELETE SET NULL,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    value       REAL DEFAULT 0,
    stage       TEXT DEFAULT 'To Contact',
    owner       TEXT,
    close_date  TEXT,
    notes       TEXT,
    probability REAL,
    win_reason  TEXT,
    loss_reason TEXT,
    moved_at    INTEGER,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Activities
  CREATE TABLE IF NOT EXISTS activities (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    type        TEXT NOT NULL DEFAULT 'Note',
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
    note        TEXT,
    date        TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Tasks
  CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    due_date    TEXT,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
    priority    TEXT DEFAULT 'Medium',
    status      TEXT DEFAULT 'Open',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Invoices
  CREATE TABLE IF NOT EXISTS invoices (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    number      TEXT NOT NULL,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
    status      TEXT DEFAULT 'Draft',
    items       TEXT DEFAULT '[]',
    subtotal    REAL DEFAULT 0,
    tax         REAL DEFAULT 0,
    total       REAL DEFAULT 0,
    issue_date  TEXT,
    due_date    TEXT,
    notes       TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Products
  CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    price       REAL DEFAULT 0,
    category    TEXT,
    billing     TEXT DEFAULT 'one-time',
    active      INTEGER DEFAULT 1,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Playbooks
  CREATE TABLE IF NOT EXISTS playbooks (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    stage       TEXT NOT NULL,
    steps       TEXT DEFAULT '[]',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Smart Lists
  CREATE TABLE IF NOT EXISTS smart_lists (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    entity      TEXT DEFAULT 'contacts',
    criteria    TEXT DEFAULT '[]',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Sequences
  CREATE TABLE IF NOT EXISTS sequences (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    steps       TEXT DEFAULT '[]',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Proposals
  CREATE TABLE IF NOT EXISTS proposals (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    title       TEXT,
    content     TEXT,
    status      TEXT DEFAULT 'Draft',
    token       TEXT UNIQUE,
    viewed_at   INTEGER,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Settings (key-value per org)
  CREATE TABLE IF NOT EXISTS settings (
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       TEXT,
    PRIMARY KEY (org_id, key)
  );

  -- Phase 15: Document / File Links
  CREATE TABLE IF NOT EXISTS doc_links (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    url          TEXT,
    type         TEXT DEFAULT 'other',
    entity_type  TEXT DEFAULT '',
    entity_id    TEXT DEFAULT '',
    notes        TEXT,
    date_added   TEXT,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 15: Competitor Entries (per-deal)
  CREATE TABLE IF NOT EXISTS competitor_entries (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id     TEXT REFERENCES deals(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    position    TEXT DEFAULT 'tied',
    strengths   TEXT,
    weaknesses  TEXT,
    date_noted  TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 15: Email Campaigns
  CREATE TABLE IF NOT EXISTS campaigns (
    id                   TEXT PRIMARY KEY,
    org_id               TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    subject              TEXT,
    audience_type        TEXT DEFAULT 'manual',
    audience_list_id     TEXT,
    audience_contact_ids TEXT DEFAULT '[]',
    send_date            TEXT,
    status               TEXT DEFAULT 'draft',
    sent_count           INTEGER DEFAULT 0,
    opened               INTEGER DEFAULT 0,
    replied              INTEGER DEFAULT 0,
    deals_influenced     TEXT DEFAULT '[]',
    created_at           INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 16: Subscriptions / Recurring Revenue
  CREATE TABLE IF NOT EXISTS subscriptions (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    company_id    TEXT REFERENCES companies(id) ON DELETE SET NULL,
    plan_name     TEXT NOT NULL,
    mrr           REAL DEFAULT 0,
    billing_cycle TEXT DEFAULT 'monthly',
    start_date    TEXT,
    renewal_date  TEXT,
    status        TEXT DEFAULT 'active',
    notes         TEXT,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 16: Call / SMS Logs
  CREATE TABLE IF NOT EXISTS call_logs (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    type        TEXT NOT NULL DEFAULT 'call',
    direction   TEXT NOT NULL DEFAULT 'outbound',
    date        TEXT NOT NULL,
    duration    INTEGER DEFAULT 0,
    notes       TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 16: Renewal / Subscription Tracking
  CREATE TABLE IF NOT EXISTS renewals (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id   TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    company_id   TEXT REFERENCES companies(id) ON DELETE SET NULL,
    service_name TEXT NOT NULL,
    start_date   TEXT,
    renewal_date TEXT,
    mrr          REAL DEFAULT 0,
    status       TEXT DEFAULT 'Active',
    notes        TEXT,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 16: Audit / Activity Log
  CREATE TABLE IF NOT EXISTS audit_log (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id      TEXT,
    user_name    TEXT,
    entity_type  TEXT NOT NULL,
    entity_id    TEXT,
    entity_name  TEXT,
    action       TEXT NOT NULL,
    field_name   TEXT,
    old_value    TEXT,
    new_value    TEXT,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 17: Saved Searches / Pinned Filters
  CREATE TABLE IF NOT EXISTS saved_searches (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT,
    name        TEXT NOT NULL,
    entity      TEXT NOT NULL DEFAULT 'contacts',
    filters     TEXT DEFAULT '{}',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 18: Email Logs (manual email logging against contacts)
  CREATE TABLE IF NOT EXISTS email_logs (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    subject     TEXT NOT NULL,
    body        TEXT,
    direction   TEXT NOT NULL DEFAULT 'outbound',
    date        TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 19: Webhooks / Integration Hub
  CREATE TABLE IF NOT EXISTS webhooks (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    events     TEXT DEFAULT '[]',
    active     INTEGER DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 19: Custom Field Definitions
  CREATE TABLE IF NOT EXISTS custom_field_defs (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL DEFAULT 'text',
    entity_type TEXT NOT NULL DEFAULT 'contact',
    options     TEXT DEFAULT '[]',
    required    INTEGER DEFAULT 0,
    sort_order  INTEGER DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 19: Custom Field Values
  CREATE TABLE IF NOT EXISTS custom_field_values (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id   TEXT NOT NULL,
    field_id    TEXT NOT NULL REFERENCES custom_field_defs(id) ON DELETE CASCADE,
    value       TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(org_id, entity_type, entity_id, field_id)
  );

  -- Phase 19: In-App Notifications
  CREATE TABLE IF NOT EXISTS notifications (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT,
    type        TEXT NOT NULL DEFAULT 'info',
    message     TEXT NOT NULL,
    entity_type TEXT DEFAULT '',
    entity_id   TEXT DEFAULT '',
    read        INTEGER DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 19: User Goals
  CREATE TABLE IF NOT EXISTS user_goals (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL,
    period_type TEXT NOT NULL DEFAULT 'monthly',
    year        INTEGER NOT NULL,
    period      INTEGER NOT NULL,
    goal_amount REAL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(org_id, user_id, period_type, year, period)
  );

  -- Phase 19: Knowledge Base Notes
  CREATE TABLE IF NOT EXISTS kb_notes (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    body        TEXT DEFAULT '',
    tags        TEXT DEFAULT '[]',
    pinned      INTEGER DEFAULT 0,
    company_id  TEXT REFERENCES companies(id) ON DELETE SET NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 20: Time Tracking
  CREATE TABLE IF NOT EXISTS time_entries (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    user_id     TEXT,
    description TEXT,
    hours       REAL DEFAULT 0,
    rate        REAL DEFAULT 0,
    billable    INTEGER DEFAULT 1,
    date        TEXT,
    invoice_id  TEXT REFERENCES invoices(id) ON DELETE SET NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 20: Product Bundles
  CREATE TABLE IF NOT EXISTS product_bundles (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS bundle_items (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    bundle_id   TEXT NOT NULL REFERENCES product_bundles(id) ON DELETE CASCADE,
    product_id  TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    quantity    REAL DEFAULT 1
  );

  -- Phase 20: Checklist Templates
  CREATE TABLE IF NOT EXISTS checklist_templates (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS checklist_items (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    template_id TEXT NOT NULL REFERENCES checklist_templates(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    sort_order  INTEGER DEFAULT 0
  );

  -- Phase 20: Deal Checklists (live instances)
  CREATE TABLE IF NOT EXISTS deal_checklists (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id     TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    template_id TEXT,
    name        TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS deal_checklist_items (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    checklist_id TEXT NOT NULL REFERENCES deal_checklists(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    done         INTEGER DEFAULT 0,
    sort_order   INTEGER DEFAULT 0
  );

  -- Phase 20: Deal Stage Log (SLA tracking)
  CREATE TABLE IF NOT EXISTS deal_stage_log (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id     TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    stage       TEXT NOT NULL,
    entered_at  INTEGER NOT NULL,
    exited_at   INTEGER
  );
`);

// Phase 20: New tables for Deal Room, Workflow Automation, API Keys, Report Builder
db.exec(`
  CREATE TABLE IF NOT EXISTS portal_qas (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    deal_id     TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    author_name TEXT NOT NULL,
    question    TEXT NOT NULL,
    answer      TEXT,
    answered_at INTEGER,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS workflow_rules (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL,
    name          TEXT NOT NULL,
    trigger_stage TEXT NOT NULL,
    actions       TEXT NOT NULL DEFAULT '[]',
    active        INTEGER DEFAULT 1,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    key_prefix  TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT 'read',
    last_used   INTEGER,
    expires_at  INTEGER,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS saved_reports (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    name       TEXT NOT NULL,
    config     TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

const p20Alters = [
  'ALTER TABLE deals ADD COLUMN portal_token TEXT',
];
p20Alters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// ── Phase 21: Commission Tracking, Portal Comments, Meetings, Territories ──
db.exec(`
  CREATE TABLE IF NOT EXISTS commission_rates (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL,
    rate_percent   REAL NOT NULL DEFAULT 0,
    effective_from TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS commissions (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id      TEXT REFERENCES deals(id) ON DELETE SET NULL,
    user_id      TEXT NOT NULL,
    amount       REAL NOT NULL DEFAULT 0,
    rate_percent REAL NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'Pending',
    paid_at      INTEGER,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS portal_comments (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id     TEXT REFERENCES deals(id) ON DELETE CASCADE,
    token       TEXT NOT NULL,
    author_name TEXT NOT NULL,
    body        TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS meetings (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id   TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    deal_id      TEXT REFERENCES deals(id) ON DELETE SET NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    scheduled_at TEXT NOT NULL,
    duration_min INTEGER DEFAULT 30,
    location     TEXT,
    status       TEXT NOT NULL DEFAULT 'Scheduled',
    created_by   TEXT,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS territories (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    rep_ids     TEXT DEFAULT '[]',
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

// ── Phase 21: Installs Table + Column Migrations ────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS installs (
    id               TEXT PRIMARY KEY,
    org_id           TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id       TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    company_id       TEXT REFERENCES companies(id) ON DELETE SET NULL,
    product_id       TEXT REFERENCES products(id) ON DELETE SET NULL,
    product_name     TEXT,
    install_date     TEXT,
    serial_number    TEXT,
    warranty_expiry  TEXT,
    service_interval INTEGER DEFAULT 0,
    last_service     TEXT,
    next_service     TEXT,
    notes            TEXT,
    created_at       INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

const p21Alters = [
  'ALTER TABLE deals    ADD COLUMN currency     TEXT DEFAULT \'USD\'',
  'ALTER TABLE contacts ADD COLUMN referred_by  TEXT',
];
p21Alters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// Phase 18: Add columns to existing tables
const p18Alters = [
  // E-signature columns on proposals
  'ALTER TABLE proposals ADD COLUMN signature_data TEXT',
  'ALTER TABLE proposals ADD COLUMN signature_token TEXT',
  'ALTER TABLE proposals ADD COLUMN signed_at INTEGER',
  // Bulk assign: track assigned owner on tasks
  'ALTER TABLE tasks ADD COLUMN assigned_owner TEXT',
];
p18Alters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// Phase 19: no column alters needed (all new tables)

// Phase 16: Add new columns to existing tables (safe — errors silently ignored if already added)
const p16Alters = [
  'ALTER TABLE contacts  ADD COLUMN lead_source TEXT',
  'ALTER TABLE contacts  ADD COLUMN territory   TEXT',
  'ALTER TABLE deals     ADD COLUMN lead_source TEXT',
  'ALTER TABLE companies ADD COLUMN territory   TEXT',
];
p16Alters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// Phase 17: Migrate users table to remove CHECK constraint and support admin/manager/rep roles
// Also add owner_tag column for rep-level deal filtering
try {
  const tableInfo = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get();
  const needsMigration = tableInfo && (tableInfo.sql.includes("CHECK") || !tableInfo.sql.includes('owner_tag'));
  if (needsMigration) {
    db.exec(`PRAGMA foreign_keys=OFF;`);
    db.exec(`
      CREATE TABLE IF NOT EXISTS users_p17 (
        id          TEXT PRIMARY KEY,
        org_id      TEXT NOT NULL,
        email       TEXT NOT NULL UNIQUE,
        password    TEXT NOT NULL,
        name        TEXT NOT NULL,
        role        TEXT NOT NULL DEFAULT 'admin',
        owner_tag   TEXT DEFAULT '',
        created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
      );
      INSERT OR IGNORE INTO users_p17 (id, org_id, email, password, name, role, owner_tag, created_at)
        SELECT id, org_id, email, password, name,
          CASE WHEN role = 'user' THEN 'rep' ELSE role END,
          '',
          created_at FROM users;
      DROP TABLE users;
      ALTER TABLE users_p17 RENAME TO users;
    `);
    db.exec(`PRAGMA foreign_keys=ON;`);
  }
} catch(e) {
  try { db.exec(`PRAGMA foreign_keys=ON;`); } catch(_) {}
}

// Phase 17: Add owner_tag column if missing (for already-migrated DBs)
try { db.exec('ALTER TABLE users ADD COLUMN owner_tag TEXT DEFAULT \'\''); } catch(_) {}

// ── Seed Admin Data ─────────────────────────────────────────────────────────
function seedIfEmpty() {
  const existing = db.prepare('SELECT COUNT(*) as c FROM users').get();
  if (existing.c > 0) return; // Already seeded

  console.log('🌱 Seeding default admin user and sample data...');

  const orgId = 'org_boredroom';
  const userId = 'user_admin';
  const passwordHash = bcrypt.hashSync('BoredRoom2025!', 10);

  // Org
  db.prepare('INSERT INTO orgs (id, name) VALUES (?, ?)').run(orgId, 'BoredRoom');

  // Admin user
  db.prepare(`INSERT INTO users (id, org_id, email, password, name, role)
    VALUES (?, ?, ?, ?, ?, ?)`).run(userId, orgId, 'admin@boredroom.com', passwordHash, 'Admin', 'admin');

  const now = Date.now();
  const d = (daysAgo) => now - daysAgo * 86400000;

  // Companies
  const companies = [
    { id: 'c1', name: 'Apex Dynamics',     industry: 'Technology',  website: 'apexdynamics.io',       phone: '312-555-0900', address: '100 W Monroe St',  city: 'Chicago',       notes: 'Series B startup, strong growth trajectory.' },
    { id: 'c2', name: 'Meridian Capital',  industry: 'Finance',     website: 'meridiancap.com',        phone: '312-555-0400', address: '200 S LaSalle St', city: 'Chicago',       notes: 'Mid-market PE firm, 3 active funds.' },
    { id: 'c3', name: 'Vantage Health',    industry: 'Healthcare',  website: 'vantagehealth.com',      phone: '773-555-0200', address: '1200 W Addison',   city: 'Chicago',       notes: 'Regional hospital network, 12 locations.' },
    { id: 'c4', name: 'Northlake Partners',industry: 'Real Estate', website: 'northlakepartners.com',  phone: '',             address: '',                 city: 'Chicago',       notes: 'Commercial real estate, Chicago focus.' },
    { id: 'c5', name: 'Cortex Labs',       industry: 'Technology',  website: 'cortexlabs.ai',          phone: '415-555-0700', address: '340 Pine St',      city: 'San Francisco', notes: 'AI tooling startup, fast-moving team.' },
  ];

  const insComp = db.prepare(`INSERT INTO companies (id, org_id, name, industry, website, phone, address, city, notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  companies.forEach((c, i) => insComp.run(c.id, orgId, c.name, c.industry, c.website, c.phone, c.address, c.city, c.notes, d(60 - i*10)));

  // Contacts
  const contacts = [
    { id: 'p1', name: 'Sarah Mitchell',  email: 'smitchell@apexdynamics.io', phone: '312-555-0182', company: 'c1', title: 'VP of Sales',       stage: 'Customer',  owner: 'AW', tags: ['enterprise','vip'],              notes: 'Primary champion. Loves async updates.', createdAt: d(55), lastActivity: d(2) },
    { id: 'p2', name: 'James Harlow',    email: 'jharlow@meridiancap.com',   phone: '312-555-0247', company: 'c2', title: 'Managing Director', stage: 'Qualified', owner: 'AW', tags: ['finance','decision-maker'],       notes: 'Met at FinTech Summit. Follow up in Q2.', createdAt: d(40), lastActivity: d(5) },
    { id: 'p3', name: 'Priya Nair',      email: 'pnair@vantagehealth.com',   phone: '773-555-0091', company: 'c3', title: 'CTO',               stage: 'Prospect',  owner: 'AW', tags: ['healthcare','technical'],         notes: 'Very technical. Wants a deep-dive demo.', createdAt: d(28), lastActivity: d(1) },
    { id: 'p4', name: 'Derek Okonkwo',   email: 'derek@northlakepartners.com',phone: '312-555-0374', company: 'c4', title: 'Founder',           stage: 'Lead',      owner: 'AW', tags: ['real-estate','warm'],            notes: 'Intro via LinkedIn. Early stage.', createdAt: d(18), lastActivity: d(7) },
    { id: 'p5', name: 'Lena Vogel',      email: 'lvogel@cortexlabs.ai',      phone: '415-555-0129', company: 'c5', title: 'CEO',               stage: 'Qualified', owner: 'AW', tags: ['startup','ai'],                  notes: 'Fast decision cycle. Evaluate this month.', createdAt: d(9), lastActivity: d(0) },
    { id: 'p6', name: 'Marcus Chen',     email: 'mchen@apexdynamics.io',     phone: '312-555-0563', company: 'c1', title: 'Engineering Lead',  stage: 'Customer',  owner: 'AW', tags: ['technical','enterprise'],         notes: 'Technical evaluator for Apex.', createdAt: d(50), lastActivity: d(3) },
    { id: 'p7', name: 'Rachel Torres',   email: 'rtorres@meridiancap.com',   phone: '312-555-0831', company: 'c2', title: 'Associate',         stage: 'Lead',      owner: 'AW', tags: ['finance'],                       notes: 'Secondary contact at Meridian.', createdAt: d(35), lastActivity: d(12) },
  ];

  const insCont = db.prepare(`INSERT INTO contacts (id, org_id, name, email, phone, company_id, title, stage, owner, tags, notes, created_at, last_activity)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  contacts.forEach(c => insCont.run(c.id, orgId, c.name, c.email, c.phone, c.company, c.title, c.stage, c.owner, JSON.stringify(c.tags), c.notes, c.createdAt, c.lastActivity));

  // Deals
  const deals = [
    { id: 'd1', name: 'Apex Dynamics — Enterprise',   company: 'c1', contact: 'p1', value: 84000,  stage: 'Won',           owner: 'AW', closeDate: new Date(d(-15)).toISOString().slice(0,10), notes: 'Closed. Annual contract. Auto-renewal.', createdAt: d(90), movedAt: d(15) },
    { id: 'd2', name: 'Meridian Capital — Platform',  company: 'c2', contact: 'p2', value: 62000,  stage: 'Negotiation',   owner: 'AW', closeDate: new Date(d(-20)).toISOString().slice(0,10), notes: 'Final pricing discussion ongoing.', createdAt: d(50), movedAt: d(8) },
    { id: 'd3', name: 'Vantage Health — Integration', company: 'c3', contact: 'p3', value: 120000, stage: 'Proposal Sent', owner: 'AW', closeDate: new Date(d(-30)).toISOString().slice(0,10), notes: 'Proposal sent 3/1. Waiting on board approval.', createdAt: d(35), movedAt: d(14) },
    { id: 'd4', name: 'Northlake — Starter',          company: 'c4', contact: 'p4', value: 18000,  stage: 'Contacted',     owner: 'AW', closeDate: new Date(d(-45)).toISOString().slice(0,10), notes: 'Discovery call done. Needs ROI analysis.', createdAt: d(20), movedAt: d(10) },
    { id: 'd5', name: 'Cortex Labs — Growth',         company: 'c5', contact: 'p5', value: 36000,  stage: 'To Contact',    owner: 'AW', closeDate: new Date(d(-60)).toISOString().slice(0,10), notes: 'Warm lead. Schedule intro this week.', createdAt: d(10), movedAt: d(10) },
    { id: 'd6', name: 'Apex Dynamics — Expansion',    company: 'c1', contact: 'p6', value: 45000,  stage: 'Contacted',     owner: 'AW', closeDate: new Date(d(-40)).toISOString().slice(0,10), notes: 'Upsell on top of existing contract.', createdAt: d(25), movedAt: d(5) },
  ];

  const insDeal = db.prepare(`INSERT INTO deals (id, org_id, name, company_id, contact_id, value, stage, owner, close_date, notes, created_at, moved_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  deals.forEach(deal => insDeal.run(deal.id, orgId, deal.name, deal.company, deal.contact, deal.value, deal.stage, deal.owner, deal.closeDate, deal.notes, deal.createdAt, deal.movedAt));

  // Activities
  const activities = [
    { id: 'a1', type: 'Call',    contactId: 'p1', dealId: 'd1', note: 'Renewal call — confirmed auto-renewal for next year. Sarah very happy with product velocity.', date: new Date(d(2)).toISOString(), createdAt: d(2) },
    { id: 'a2', type: 'Email',   contactId: 'p3', dealId: 'd3', note: "Sent proposal deck and pricing sheet. CC'd procurement lead.", date: new Date(d(14)).toISOString(), createdAt: d(14) },
    { id: 'a3', type: 'Meeting', contactId: 'p2', dealId: 'd2', note: 'In-person at their Chicago office. Tour of platform. Strong positive signals from James.', date: new Date(d(8)).toISOString(), createdAt: d(8) },
    { id: 'a4', type: 'Note',    contactId: 'p5', dealId: 'd5', note: 'LinkedIn intro went well. Lena responded within 2h — schedule a 30-min discovery ASAP.', date: new Date(d(1)).toISOString(), createdAt: d(1) },
    { id: 'a5', type: 'Task',    contactId: 'p4', dealId: 'd4', note: 'Build custom ROI model for Northlake — Derek mentioned $2M in potential portfolio impact.', date: new Date(d(7)).toISOString(), createdAt: d(7) },
    { id: 'a6', type: 'Call',    contactId: 'p6', dealId: 'd6', note: 'Discovery call with Marcus — upsell path clear, needs engineering sign-off.', date: new Date(d(5)).toISOString(), createdAt: d(5) },
    { id: 'a7', type: 'Email',   contactId: 'p1', dealId: null, note: 'Quarterly check-in email. Shared product roadmap PDF.', date: new Date(d(3)).toISOString(), createdAt: d(3) },
  ];

  const insAct = db.prepare(`INSERT INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  activities.forEach(a => insAct.run(a.id, orgId, a.type, a.contactId, a.dealId, a.note, a.date, a.createdAt));

  // Tasks
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  const nextWeek  = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);

  const insTsk = db.prepare(`INSERT INTO tasks (id, org_id, title, due_date, contact_id, deal_id, priority, status, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  insTsk.run('tk1', orgId, 'Send follow-up proposal to James Harlow', yesterday, 'p2', 'd2', 'High',   'Open', d(3));
  insTsk.run('tk2', orgId, 'Schedule discovery call with Lena Vogel',  nextWeek,  'p5', 'd5', 'Medium', 'Open', d(1));

  // Products
  const products = [
    { id: 'pr1', name: 'Starter Plan',      description: 'Up to 5 users, core CRM features',            price: 299,  category: 'SaaS',         billing: 'monthly' },
    { id: 'pr2', name: 'Growth Plan',       description: 'Up to 25 users, automation + reporting',       price: 799,  category: 'SaaS',         billing: 'monthly' },
    { id: 'pr3', name: 'Enterprise Plan',   description: 'Unlimited users, dedicated support, SLAs',     price: 2499, category: 'SaaS',         billing: 'monthly' },
    { id: 'pr4', name: 'Onboarding Pack',   description: '3-day onboarding workshop + data migration',   price: 4500, category: 'Professional', billing: 'one-time' },
    { id: 'pr5', name: 'API Access',        description: 'Full REST API access + webhooks',               price: 199,  category: 'Add-on',       billing: 'monthly' },
    { id: 'pr6', name: 'Custom Reporting',  description: 'Bespoke dashboard + BI connector setup',       price: 2000, category: 'Professional', billing: 'one-time' },
  ];

  const insProd = db.prepare(`INSERT INTO products (id, org_id, name, description, price, category, billing, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  products.forEach((p, i) => insProd.run(p.id, orgId, p.name, p.description, p.price, p.category, p.billing, d(30 - i)));

  // Default settings
  const insSet = db.prepare('INSERT INTO settings (org_id, key, value) VALUES (?, ?, ?)');
  insSet.run(orgId, 'pipelineStages', JSON.stringify([
    { name: 'To Contact',    color: '#6366f1', probability: 0.10 },
    { name: 'Contacted',     color: '#3b82f6', probability: 0.25 },
    { name: 'Proposal Sent', color: '#eab308', probability: 0.50 },
    { name: 'Negotiation',   color: '#f97316', probability: 0.75 },
    { name: 'Won',           color: '#22c55e', probability: 1.00 },
    { name: 'Lost',          color: '#ef4444', probability: 0.00 },
  ]));
  insSet.run(orgId, 'emailTemplates', JSON.stringify([]));
  insSet.run(orgId, 'invoiceSettings', JSON.stringify({
    companyName: 'BoredRoom',
    companyAddress: '',
    taxRate: 0,
    currency: 'USD',
    prefix: 'INV-',
    nextNumber: 1001,
  }));
  insSet.run(orgId, 'playbooks', JSON.stringify([
    {
      id: 'pb1',
      stage: 'To Contact',
      steps: ['Research company on LinkedIn', 'Find key decision maker', 'Draft personalized outreach email']
    },
    {
      id: 'pb2',
      stage: 'Contacted',
      steps: ['Send follow-up within 48h', 'Schedule discovery call', 'Share one-pager or case study']
    },
    {
      id: 'pb3',
      stage: 'Proposal Sent',
      steps: ['Confirm proposal received', 'Address objections within 24h', 'Schedule proposal walk-through call', 'Send ROI calculator']
    },
    {
      id: 'pb4',
      stage: 'Negotiation',
      steps: ['Get legal review scheduled', 'Confirm champion internally', 'Prepare final pricing sheet', 'Set decision deadline']
    },
  ]));

  console.log('✅ Seed complete. Admin: admin@boredroom.com / BoredRoom2025!');
}

// ── Phase 22: Recurring Task Templates + Invoice Reviews ────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS recurring_task_templates (
    id                TEXT PRIMARY KEY,
    org_id            TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title             TEXT NOT NULL,
    description       TEXT,
    assigned_to       TEXT,
    frequency         TEXT NOT NULL DEFAULT 'weekly',
    day_of_week       INTEGER DEFAULT 1,
    day_of_month      INTEGER DEFAULT 1,
    deal_id           TEXT REFERENCES deals(id) ON DELETE SET NULL,
    active            INTEGER DEFAULT 1,
    last_generated_at INTEGER,
    created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS portal_invoice_reviews (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    invoice_id   TEXT NOT NULL,
    deal_id      TEXT,
    token        TEXT NOT NULL,
    reviewed_at  INTEGER NOT NULL,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

// Phase 22: add referred_by_contact_id alias column if not present
// (referred_by already serves this purpose, added in Phase 21)
try { db.exec("ALTER TABLE contacts ADD COLUMN referred_by_contact_id TEXT"); } catch(_) {}

// Phase 22: Email Inbox Integration tables
db.exec(`
  CREATE TABLE IF NOT EXISTS email_inbox_config (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL UNIQUE REFERENCES orgs(id) ON DELETE CASCADE,
    host        TEXT,
    port        INTEGER DEFAULT 993,
    email       TEXT,
    password    TEXT,
    mock_mode   INTEGER DEFAULT 1,
    enabled     INTEGER DEFAULT 1,
    last_synced INTEGER,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    updated_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  CREATE TABLE IF NOT EXISTS email_inbox_messages (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    message_uid   TEXT,
    from_email    TEXT NOT NULL,
    from_name     TEXT,
    to_email      TEXT,
    subject       TEXT,
    body_text     TEXT,
    body_html     TEXT,
    received_at   INTEGER NOT NULL,
    read_at       INTEGER,
    linked_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    linked_deal_id    TEXT REFERENCES deals(id) ON DELETE SET NULL,
    activity_logged   INTEGER DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

seedIfEmpty();

// ── Phase 23: Workflow Triggers, Contact Scoring, Multi-Currency, Deal Room, Hygiene ──
db.exec(`
  -- Phase 23: Upgrade workflow_rules to support full trigger model
  -- (existing table has trigger_stage; we ADD the new columns gracefully)
  CREATE TABLE IF NOT EXISTS workflow_executions (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    trigger_event TEXT NOT NULL,
    entity_type TEXT NOT NULL DEFAULT 'deal',
    entity_id   TEXT,
    entity_name TEXT,
    status      TEXT NOT NULL DEFAULT 'success',
    error       TEXT,
    executed_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 23: Contact Scoring Rules
  CREATE TABLE IF NOT EXISTS scoring_rules (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    field       TEXT NOT NULL,
    operator    TEXT NOT NULL DEFAULT 'equals',
    value       TEXT NOT NULL DEFAULT '',
    points      INTEGER NOT NULL DEFAULT 0,
    label       TEXT,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 23: Currencies
  CREATE TABLE IF NOT EXISTS currencies (
    id                TEXT PRIMARY KEY,
    org_id            TEXT NOT NULL,
    code              TEXT NOT NULL,
    symbol            TEXT NOT NULL DEFAULT '$',
    name              TEXT NOT NULL,
    exchange_rate_to_usd REAL NOT NULL DEFAULT 1.0,
    active            INTEGER NOT NULL DEFAULT 1,
    created_at        INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(org_id, code)
  );

  -- Phase 23: Portal Views (deal room analytics)
  CREATE TABLE IF NOT EXISTS portal_views (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    deal_id     TEXT NOT NULL,
    token       TEXT NOT NULL,
    ip_hash     TEXT NOT NULL DEFAULT '',
    viewed_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

// Phase 23: Alter workflow_rules to add new columns
const p23WorkflowAlters = [
  "ALTER TABLE workflow_rules ADD COLUMN trigger_event TEXT DEFAULT 'deal_stage_change'",
  "ALTER TABLE workflow_rules ADD COLUMN trigger_condition TEXT DEFAULT '{}'",
];
p23WorkflowAlters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// Phase 23: Alter deals table for video call fields
const p23DealAlters = [
  "ALTER TABLE deals ADD COLUMN video_call_url TEXT",
  "ALTER TABLE deals ADD COLUMN video_call_time TEXT",
];
p23DealAlters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// Phase 23: Seed default currencies if none exist
function seedCurrencies() {
  const existing = db.prepare("SELECT COUNT(*) as c FROM currencies").get();
  if (existing.c > 0) return;
  const orgs = db.prepare("SELECT id FROM orgs").all();
  const defaultCurrencies = [
    { code: 'USD', symbol: '$',   name: 'US Dollar',        rate: 1.0 },
    { code: 'EUR', symbol: '€',   name: 'Euro',              rate: 0.92 },
    { code: 'GBP', symbol: '£',   name: 'British Pound',    rate: 0.79 },
    { code: 'CAD', symbol: 'CA$', name: 'Canadian Dollar',  rate: 1.36 },
    { code: 'AUD', symbol: 'A$',  name: 'Australian Dollar', rate: 1.55 },
    { code: 'MXN', symbol: 'MX$', name: 'Mexican Peso',     rate: 17.2 },
  ];
  const ins = db.prepare("INSERT OR IGNORE INTO currencies (id, org_id, code, symbol, name, exchange_rate_to_usd, active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)");
  const { randomBytes } = require('crypto');
  orgs.forEach(org => {
    defaultCurrencies.forEach(c => {
      const id = 'cur_' + c.code + '_' + org.id.slice(-6);
      ins.run(id, org.id, c.code, c.symbol, c.name, c.rate, Date.now());
    });
  });
}
try { seedCurrencies(); } catch(e) { console.error('Currency seed error (non-fatal):', e.message); }

// ── Phase 24: Email Composer, Win/Loss V2, Engagement Timeline, Task Deps, Assets ──
db.exec(`
  -- Phase 24: Lead Score History (engagement timeline)
  CREATE TABLE IF NOT EXISTS lead_score_history (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id  TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    score       INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 24: Task Dependencies
  CREATE TABLE IF NOT EXISTS task_dependencies (
    id                 TEXT PRIMARY KEY,
    org_id             TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    task_id            TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    created_at         INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(task_id, depends_on_task_id)
  );

  -- Phase 24: Assets / Inventory Tracking
  CREATE TABLE IF NOT EXISTS assets (
    id                  TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    type                TEXT NOT NULL DEFAULT 'Other',
    serial_number       TEXT,
    purchase_date       TEXT,
    warranty_expiry     TEXT,
    value               REAL DEFAULT 0,
    status              TEXT NOT NULL DEFAULT 'Active',
    assigned_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    assigned_deal_id    TEXT REFERENCES deals(id) ON DELETE SET NULL,
    notes               TEXT,
    created_at          INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 24: Loss Reason Taxonomy (canonical reasons)
  CREATE TABLE IF NOT EXISTS loss_reason_taxonomy (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    reason      TEXT NOT NULL,
    sort_order  INTEGER DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

// Phase 24: Alter email_logs to add status and deal_id columns
const p24Alters = [
  "ALTER TABLE email_logs ADD COLUMN status TEXT DEFAULT 'Sent'",
  "ALTER TABLE email_logs ADD COLUMN deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL",
  // Phase 24: Product Inventory Tracking
  "ALTER TABLE products ADD COLUMN sku TEXT",
  "ALTER TABLE products ADD COLUMN quantity_on_hand INTEGER DEFAULT 0",
  "ALTER TABLE products ADD COLUMN reorder_point INTEGER DEFAULT 0",
];
p24Alters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// Phase 24: Invoice Payment Tokens table
db.exec(`
  CREATE TABLE IF NOT EXISTS invoice_payment_tokens (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL,
    invoice_id TEXT NOT NULL,
    token      TEXT NOT NULL UNIQUE,
    paid_at    INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

// ── Phase 25: AI Deal Coaching, Relationship Mapping, Sequences V2, Forecasting V2, Slack ──
db.exec(`
  -- Phase 25: Sequence Enrollments (drip campaign tracking)
  CREATE TABLE IF NOT EXISTS sequence_enrollments (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id      TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    sequence_id     TEXT NOT NULL,
    current_step    INTEGER NOT NULL DEFAULT 0,
    enrolled_at     INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    status          TEXT NOT NULL DEFAULT 'Active',
    last_advanced   INTEGER,
    created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(contact_id, sequence_id)
  );
`);

// Phase 25: Alter sequences table to support per-step delays and conditions (stored in steps JSON)
// No column changes needed — steps JSON already holds arbitrary objects; we just enrich them in frontend.

// ── Phase 26: Tickets, Ticket Comments, TOTP 2FA ────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS tickets (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    description  TEXT,
    status       TEXT NOT NULL DEFAULT 'Open',
    priority     TEXT NOT NULL DEFAULT 'Medium',
    category     TEXT,
    assigned_to  TEXT,
    contact_id   TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    deal_id      TEXT REFERENCES deals(id) ON DELETE SET NULL,
    created_by   TEXT,
    created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    updated_at   INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    resolved_at  INTEGER
  );

  CREATE TABLE IF NOT EXISTS ticket_comments (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    ticket_id   TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    author_id   TEXT,
    author_name TEXT NOT NULL,
    body        TEXT NOT NULL,
    internal    INTEGER DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
`);

// Phase 26: TOTP columns on users
const p26Alters = [
  "ALTER TABLE users ADD COLUMN totp_secret TEXT",
  "ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0",
];
p26Alters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

// ── Phase 26: NPS Scores, Client Checklist Actions, Portal Comment Threads ──
db.exec(`
  -- Phase 26: NPS Scores (per customer/deal)
  CREATE TABLE IF NOT EXISTS nps_scores (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    deal_id     TEXT REFERENCES deals(id) ON DELETE SET NULL,
    score       INTEGER NOT NULL CHECK(score >= 0 AND score <= 10),
    comment     TEXT,
    submitted_at TEXT NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );

  -- Phase 26: Client-side checklist actions (client checks off portal items)
  CREATE TABLE IF NOT EXISTS client_checklist_actions (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    deal_id         TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
    item_id         TEXT NOT NULL,
    checked_by_name TEXT NOT NULL,
    checked_at      INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    UNIQUE(deal_id, item_id)
  );
`);

// Phase 26: Add parent_comment_id to portal_comments for threading
const p26DBAlters = [
  "ALTER TABLE portal_comments ADD COLUMN parent_comment_id TEXT DEFAULT NULL",
];
p26DBAlters.forEach(sql => { try { db.exec(sql); } catch(_) {} });

module.exports = db;
