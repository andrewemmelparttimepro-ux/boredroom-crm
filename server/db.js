/**
 * BoredRoom CRM — PostgreSQL Database Layer
 * Migrated from better-sqlite3 to pg (node-postgres)
 */
'use strict';

const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { AsyncLocalStorage } = require('async_hooks');

// AsyncLocalStorage for transaction client propagation
// When inside a transaction, db.prepare() uses the transaction client
const txStorage = new AsyncLocalStorage();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost')
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err.message);
});

// ── SQL Transformation Helpers ───────────────────────────────────────────
function flatArgs(args) {
  if (args.length === 1 && Array.isArray(args[0])) return args[0];
  // Flatten spread array at end
  const out = [];
  for (const a of args) {
    if (Array.isArray(a)) out.push(...a);
    else out.push(a);
  }
  return out;
}

function convertPlaceholders(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function transformSql(sql) {
  let s = sql.trim();

  // INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
  if (/^INSERT OR IGNORE INTO/i.test(s)) {
    s = s.replace(/^INSERT OR IGNORE INTO/i, 'INSERT INTO');
    if (!/ON CONFLICT/i.test(s)) {
      // If it ends with ) just add ON CONFLICT DO NOTHING
      s = s + ' ON CONFLICT DO NOTHING';
    }
  }
  // INSERT OR REPLACE → INSERT ... ON CONFLICT (id) DO UPDATE SET ...
  else if (/^INSERT OR REPLACE INTO/i.test(s)) {
    s = s.replace(/^INSERT OR REPLACE INTO/i, 'INSERT INTO');
    if (!/ON CONFLICT/i.test(s)) {
      const m = s.match(/INSERT INTO\s+\w+\s*\(([^)]+)\)/i);
      if (m) {
        const cols = m[1].split(',').map(c => c.trim()).filter(c => c && c !== 'id');
        if (cols.length > 0) {
          const setClause = cols.map(c => `${c}=EXCLUDED.${c}`).join(', ');
          s = s + ` ON CONFLICT (id) DO UPDATE SET ${setClause}`;
        } else {
          s = s + ' ON CONFLICT (id) DO NOTHING';
        }
      } else {
        s = s + ' ON CONFLICT DO NOTHING';
      }
    }
  }

  return convertPlaceholders(s);
}

// ── prepare() compatibility wrapper ─────────────────────────────────────
function prepare(sql) {
  const pgSql = transformSql(sql);
  return {
    async get(...args) {
      const params = flatArgs(args);
      const conn = txStorage.getStore() || pool;
      try {
        const result = await conn.query(pgSql, params);
        return result.rows[0] ?? null;
      } catch(e) {
        console.error('DB get error:', e.message, '\nSQL:', pgSql, '\nParams:', params);
        throw e;
      }
    },
    async all(...args) {
      const params = flatArgs(args);
      const conn = txStorage.getStore() || pool;
      try {
        const result = await conn.query(pgSql, params);
        return result.rows;
      } catch(e) {
        console.error('DB all error:', e.message, '\nSQL:', pgSql, '\nParams:', params);
        throw e;
      }
    },
    async run(...args) {
      const params = flatArgs(args);
      const conn = txStorage.getStore() || pool;
      try {
        const result = await conn.query(pgSql, params);
        return { changes: result.rowCount, rowCount: result.rowCount };
      } catch(e) {
        console.error('DB run error:', e.message, '\nSQL:', pgSql, '\nParams:', params);
        throw e;
      }
    },
  };
}

// ── exec() for raw SQL ───────────────────────────────────────────────────
async function exec(sql) {
  const conn = txStorage.getStore() || pool;
  try {
    await conn.query(sql);
  } catch(e) {
    // Ignore "already exists" errors during schema creation
    if (!e.message.includes('already exists') && !e.message.includes('duplicate column') &&
        !e.message.includes('already exists') && !e.message.includes('already exists')) {
      console.error('DB exec error:', e.message);
      throw e;
    }
  }
}

// ── transaction() wrapper ─────────────────────────────────────────────────
// Uses AsyncLocalStorage to propagate the transaction client to all db.prepare() calls
// Usage: await db.transaction(async () => { await db.prepare(...).run(...); })
async function transaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Run fn() with the client stored in AsyncLocalStorage
    // All db.prepare().get/all/run() calls inside fn() will use this client
    const result = await txStorage.run(client, fn);
    await client.query('COMMIT');
    return result;
  } catch(e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

// ── Schema Creation ──────────────────────────────────────────────────────
async function createSchema() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS orgs (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        owner_tag TEXT DEFAULT '',
        totp_secret TEXT,
        totp_enabled INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS companies (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        industry TEXT,
        website TEXT,
        phone TEXT,
        address TEXT,
        city TEXT,
        territory TEXT,
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS contacts (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        title TEXT,
        stage TEXT DEFAULT 'Lead',
        owner TEXT,
        tags TEXT DEFAULT '[]',
        notes TEXT,
        custom_fields TEXT DEFAULT '{}',
        lead_source TEXT,
        territory TEXT,
        referred_by TEXT,
        referred_by_contact_id TEXT,
        created_at BIGINT NOT NULL DEFAULT 0,
        last_activity BIGINT
      );

      CREATE TABLE IF NOT EXISTS deals (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        value REAL DEFAULT 0,
        stage TEXT DEFAULT 'To Contact',
        owner TEXT,
        close_date TEXT,
        notes TEXT,
        probability REAL,
        win_reason TEXT,
        loss_reason TEXT,
        moved_at BIGINT,
        lead_source TEXT,
        currency TEXT DEFAULT 'USD',
        portal_token TEXT,
        video_call_url TEXT,
        video_call_time TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS activities (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        type TEXT NOT NULL DEFAULT 'Note',
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        note TEXT,
        date TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        due_date TEXT,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        priority TEXT DEFAULT 'Medium',
        status TEXT DEFAULT 'Open',
        assigned_owner TEXT DEFAULT '',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS invoices (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        number TEXT NOT NULL,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        status TEXT DEFAULT 'Draft',
        items TEXT DEFAULT '[]',
        subtotal REAL DEFAULT 0,
        tax REAL DEFAULT 0,
        total REAL DEFAULT 0,
        issue_date TEXT,
        due_date TEXT,
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        price REAL DEFAULT 0,
        category TEXT,
        billing TEXT DEFAULT 'one-time',
        active INTEGER DEFAULT 1,
        sku TEXT,
        quantity_on_hand INTEGER DEFAULT 0,
        reorder_point INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS playbooks (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        stage TEXT NOT NULL,
        steps TEXT DEFAULT '[]',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS smart_lists (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        entity TEXT DEFAULT 'contacts',
        criteria TEXT DEFAULT '[]',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS sequences (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        steps TEXT DEFAULT '[]',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS proposals (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        title TEXT,
        content TEXT,
        status TEXT DEFAULT 'Draft',
        token TEXT UNIQUE,
        viewed_at BIGINT,
        signature_data TEXT,
        signature_token TEXT,
        signed_at BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS settings (
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        key TEXT NOT NULL,
        value TEXT,
        PRIMARY KEY (org_id, key)
      );

      CREATE TABLE IF NOT EXISTS doc_links (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        url TEXT,
        type TEXT DEFAULT 'other',
        entity_type TEXT DEFAULT '',
        entity_id TEXT DEFAULT '',
        notes TEXT,
        date_added TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS competitor_entries (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT REFERENCES deals(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        position TEXT DEFAULT 'tied',
        strengths TEXT,
        weaknesses TEXT,
        date_noted TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS campaigns (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        subject TEXT,
        audience_type TEXT DEFAULT 'manual',
        audience_list_id TEXT,
        audience_contact_ids TEXT DEFAULT '[]',
        send_date TEXT,
        status TEXT DEFAULT 'draft',
        sent_count INTEGER DEFAULT 0,
        opened INTEGER DEFAULT 0,
        replied INTEGER DEFAULT 0,
        deals_influenced TEXT DEFAULT '[]',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        plan_name TEXT NOT NULL,
        mrr REAL DEFAULT 0,
        billing_cycle TEXT DEFAULT 'monthly',
        start_date TEXT,
        renewal_date TEXT,
        status TEXT DEFAULT 'active',
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS call_logs (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        type TEXT NOT NULL DEFAULT 'call',
        direction TEXT NOT NULL DEFAULT 'outbound',
        date TEXT NOT NULL,
        duration INTEGER DEFAULT 0,
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS renewals (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        service_name TEXT NOT NULL,
        start_date TEXT,
        renewal_date TEXT,
        mrr REAL DEFAULT 0,
        status TEXT DEFAULT 'Active',
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS audit_log (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id TEXT,
        user_name TEXT,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        entity_name TEXT,
        action TEXT NOT NULL,
        field_name TEXT,
        old_value TEXT,
        new_value TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS saved_searches (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id TEXT,
        name TEXT NOT NULL,
        entity TEXT NOT NULL DEFAULT 'contacts',
        filters TEXT DEFAULT '{}',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS email_logs (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        subject TEXT NOT NULL,
        body TEXT,
        direction TEXT NOT NULL DEFAULT 'outbound',
        status TEXT DEFAULT 'Sent',
        date TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS webhooks (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        events TEXT DEFAULT '[]',
        active INTEGER DEFAULT 1,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS custom_field_defs (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'text',
        entity_type TEXT NOT NULL DEFAULT 'contact',
        options TEXT DEFAULT '[]',
        required INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS custom_field_values (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        entity_type TEXT NOT NULL,
        entity_id TEXT NOT NULL,
        field_id TEXT NOT NULL REFERENCES custom_field_defs(id) ON DELETE CASCADE,
        value TEXT,
        created_at BIGINT NOT NULL DEFAULT 0,
        UNIQUE(org_id, entity_type, entity_id, field_id)
      );

      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id TEXT,
        type TEXT NOT NULL DEFAULT 'info',
        message TEXT NOT NULL,
        entity_type TEXT DEFAULT '',
        entity_id TEXT DEFAULT '',
        read INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS user_goals (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL,
        period_type TEXT NOT NULL DEFAULT 'monthly',
        year INTEGER NOT NULL,
        period INTEGER NOT NULL,
        goal_amount REAL DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0,
        UNIQUE(org_id, user_id, period_type, year, period)
      );

      CREATE TABLE IF NOT EXISTS kb_notes (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        body TEXT DEFAULT '',
        tags TEXT DEFAULT '[]',
        pinned INTEGER DEFAULT 0,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        created_at BIGINT NOT NULL DEFAULT 0,
        updated_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS time_entries (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        user_id TEXT,
        description TEXT,
        hours REAL DEFAULT 0,
        rate REAL DEFAULT 0,
        billable INTEGER DEFAULT 1,
        date TEXT,
        invoice_id TEXT REFERENCES invoices(id) ON DELETE SET NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS product_bundles (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS bundle_items (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        bundle_id TEXT NOT NULL REFERENCES product_bundles(id) ON DELETE CASCADE,
        product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
        quantity REAL DEFAULT 1
      );

      CREATE TABLE IF NOT EXISTS checklist_templates (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS checklist_items (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        template_id TEXT NOT NULL REFERENCES checklist_templates(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS deal_checklists (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
        template_id TEXT,
        name TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS deal_checklist_items (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        checklist_id TEXT NOT NULL REFERENCES deal_checklists(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        done INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS deal_stage_log (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
        stage TEXT NOT NULL,
        entered_at BIGINT NOT NULL,
        exited_at BIGINT
      );

      CREATE TABLE IF NOT EXISTS portal_qas (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        deal_id TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
        author_name TEXT NOT NULL,
        question TEXT NOT NULL,
        answer TEXT,
        answered_at BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS workflow_rules (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        trigger_stage TEXT,
        trigger_event TEXT DEFAULT 'deal_stage_change',
        trigger_condition TEXT DEFAULT '{}',
        actions TEXT NOT NULL DEFAULT '[]',
        active INTEGER DEFAULT 1,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'read',
        last_used BIGINT,
        expires_at BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS saved_reports (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        name TEXT NOT NULL,
        config TEXT NOT NULL DEFAULT '{}',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS commission_rates (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL,
        rate_percent REAL NOT NULL DEFAULT 0,
        effective_from TEXT NOT NULL DEFAULT '',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS commissions (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        user_id TEXT NOT NULL,
        amount REAL NOT NULL DEFAULT 0,
        rate_percent REAL NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'Pending',
        paid_at BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS portal_comments (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT REFERENCES deals(id) ON DELETE CASCADE,
        token TEXT NOT NULL,
        author_name TEXT NOT NULL,
        body TEXT NOT NULL,
        parent_comment_id TEXT DEFAULT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS meetings (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        title TEXT NOT NULL,
        description TEXT,
        scheduled_at TEXT NOT NULL,
        duration_min INTEGER DEFAULT 30,
        location TEXT,
        status TEXT NOT NULL DEFAULT 'Scheduled',
        created_by TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS territories (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        description TEXT,
        rep_ids TEXT DEFAULT '[]',
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS installs (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        company_id TEXT REFERENCES companies(id) ON DELETE SET NULL,
        product_id TEXT REFERENCES products(id) ON DELETE SET NULL,
        product_name TEXT,
        install_date TEXT,
        serial_number TEXT,
        warranty_expiry TEXT,
        service_interval INTEGER DEFAULT 0,
        last_service TEXT,
        next_service TEXT,
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS recurring_task_templates (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT,
        assigned_to TEXT,
        frequency TEXT NOT NULL DEFAULT 'weekly',
        day_of_week INTEGER DEFAULT 1,
        day_of_month INTEGER DEFAULT 1,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        active INTEGER DEFAULT 1,
        last_generated_at BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS portal_invoice_reviews (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        deal_id TEXT,
        token TEXT NOT NULL,
        reviewed_at BIGINT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS email_inbox_config (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL UNIQUE REFERENCES orgs(id) ON DELETE CASCADE,
        host TEXT,
        port INTEGER DEFAULT 993,
        email TEXT,
        password TEXT,
        mock_mode INTEGER DEFAULT 1,
        enabled INTEGER DEFAULT 1,
        last_synced BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0,
        updated_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS email_inbox_messages (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        message_uid TEXT,
        from_email TEXT NOT NULL,
        from_name TEXT,
        to_email TEXT,
        subject TEXT,
        body_text TEXT,
        body_html TEXT,
        received_at BIGINT NOT NULL,
        read_at BIGINT,
        linked_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        linked_deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        activity_logged INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS workflow_executions (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        trigger_event TEXT NOT NULL,
        entity_type TEXT NOT NULL DEFAULT 'deal',
        entity_id TEXT,
        entity_name TEXT,
        status TEXT NOT NULL DEFAULT 'success',
        error TEXT,
        executed_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS scoring_rules (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        field TEXT NOT NULL,
        operator TEXT NOT NULL DEFAULT 'equals',
        value TEXT NOT NULL DEFAULT '',
        points INTEGER NOT NULL DEFAULT 0,
        label TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS currencies (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        code TEXT NOT NULL,
        symbol TEXT NOT NULL DEFAULT '$',
        name TEXT NOT NULL,
        exchange_rate_to_usd REAL NOT NULL DEFAULT 1.0,
        active INTEGER NOT NULL DEFAULT 1,
        created_at BIGINT NOT NULL DEFAULT 0,
        UNIQUE(org_id, code)
      );

      CREATE TABLE IF NOT EXISTS portal_views (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        deal_id TEXT NOT NULL,
        token TEXT NOT NULL,
        ip_hash TEXT NOT NULL DEFAULT '',
        viewed_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS lead_score_history (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
        score INTEGER NOT NULL DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS task_dependencies (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        depends_on_task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
        created_at BIGINT NOT NULL DEFAULT 0,
        UNIQUE(task_id, depends_on_task_id)
      );

      CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'Other',
        serial_number TEXT,
        purchase_date TEXT,
        warranty_expiry TEXT,
        value REAL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'Active',
        assigned_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        assigned_deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        notes TEXT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS loss_reason_taxonomy (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        reason TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS invoice_payment_tokens (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        paid_at BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS sequence_enrollments (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
        sequence_id TEXT NOT NULL,
        current_step INTEGER NOT NULL DEFAULT 0,
        enrolled_at BIGINT NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'Active',
        last_advanced BIGINT,
        created_at BIGINT NOT NULL DEFAULT 0,
        UNIQUE(contact_id, sequence_id)
      );

      CREATE TABLE IF NOT EXISTS tickets (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL DEFAULT 'Open',
        priority TEXT NOT NULL DEFAULT 'Medium',
        category TEXT,
        assigned_to TEXT,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        created_by TEXT,
        created_at BIGINT NOT NULL DEFAULT 0,
        updated_at BIGINT NOT NULL DEFAULT 0,
        resolved_at BIGINT
      );

      CREATE TABLE IF NOT EXISTS ticket_comments (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        ticket_id TEXT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
        author_id TEXT,
        author_name TEXT NOT NULL,
        body TEXT NOT NULL,
        internal INTEGER DEFAULT 0,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS nps_scores (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
        deal_id TEXT REFERENCES deals(id) ON DELETE SET NULL,
        score INTEGER NOT NULL CHECK(score >= 0 AND score <= 10),
        comment TEXT,
        submitted_at TEXT NOT NULL,
        created_at BIGINT NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS client_checklist_actions (
        id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        deal_id TEXT NOT NULL REFERENCES deals(id) ON DELETE CASCADE,
        item_id TEXT NOT NULL,
        checked_by_name TEXT NOT NULL,
        checked_at BIGINT NOT NULL DEFAULT 0,
        UNIQUE(deal_id, item_id)
      );

      CREATE TABLE IF NOT EXISTS automation_rules (
        id TEXT PRIMARY KEY,
        org_id TEXT,
        name TEXT,
        enabled INTEGER DEFAULT 1,
        trigger_type TEXT,
        trigger_config TEXT,
        actions TEXT,
        created_at TEXT
      );
    `);

    await client.query('COMMIT');
    console.log('✅ Schema created/verified');
  } catch(e) {
    await client.query('ROLLBACK');
    console.error('Schema creation error:', e.message);
    throw e;
  } finally {
    client.release();
  }
}

// ── Seed Admin Data ──────────────────────────────────────────────────────
async function seedIfEmpty() {
  const existing = await pool.query('SELECT COUNT(*) as c FROM users');
  if (parseInt(existing.rows[0].c) > 0) return;

  console.log('🌱 Seeding default admin user and sample data...');

  const orgId = 'org_boredroom';
  const userId = 'user_admin';
  const passwordHash = bcrypt.hashSync('BoredRoom2025!', 10);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query('INSERT INTO orgs (id, name, created_at) VALUES ($1, $2, $3)', [orgId, 'BoredRoom', Date.now()]);
    await client.query('INSERT INTO users (id, org_id, email, password, name, role, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [userId, orgId, 'admin@boredroom.com', passwordHash, 'Admin', 'admin', Date.now()]);

    const now = Date.now();
    const d = (daysAgo) => now - daysAgo * 86400000;

    const companies = [
      { id: 'c1', name: 'Apex Dynamics', industry: 'Technology', website: 'apexdynamics.io', phone: '312-555-0900', address: '100 W Monroe St', city: 'Chicago', notes: 'Series B startup.' },
      { id: 'c2', name: 'Meridian Capital', industry: 'Finance', website: 'meridiancap.com', phone: '312-555-0400', address: '200 S LaSalle St', city: 'Chicago', notes: 'Mid-market PE firm.' },
      { id: 'c3', name: 'Vantage Health', industry: 'Healthcare', website: 'vantagehealth.com', phone: '773-555-0200', address: '1200 W Addison', city: 'Chicago', notes: 'Regional hospital network.' },
      { id: 'c4', name: 'Northlake Partners', industry: 'Real Estate', website: 'northlakepartners.com', phone: '', address: '', city: 'Chicago', notes: 'Commercial real estate.' },
      { id: 'c5', name: 'Cortex Labs', industry: 'Technology', website: 'cortexlabs.ai', phone: '415-555-0700', address: '340 Pine St', city: 'San Francisco', notes: 'AI tooling startup.' },
    ];
    for (const c of companies) {
      await client.query('INSERT INTO companies (id, org_id, name, industry, website, phone, address, city, notes, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
        [c.id, orgId, c.name, c.industry, c.website, c.phone, c.address, c.city, c.notes, d(60)]);
    }

    const contacts = [
      { id: 'p1', name: 'Sarah Mitchell', email: 'smitchell@apexdynamics.io', phone: '312-555-0182', company: 'c1', title: 'VP of Sales', stage: 'Customer', owner: 'AW', tags: ['enterprise','vip'], notes: 'Primary champion.', createdAt: d(55), lastActivity: d(2) },
      { id: 'p2', name: 'James Harlow', email: 'jharlow@meridiancap.com', phone: '312-555-0247', company: 'c2', title: 'Managing Director', stage: 'Qualified', owner: 'AW', tags: ['finance','decision-maker'], notes: 'Met at FinTech Summit.', createdAt: d(40), lastActivity: d(5) },
      { id: 'p3', name: 'Priya Nair', email: 'pnair@vantagehealth.com', phone: '773-555-0091', company: 'c3', title: 'CTO', stage: 'Prospect', owner: 'AW', tags: ['healthcare','technical'], notes: 'Very technical.', createdAt: d(28), lastActivity: d(1) },
      { id: 'p4', name: 'Derek Okonkwo', email: 'derek@northlakepartners.com', phone: '312-555-0374', company: 'c4', title: 'Founder', stage: 'Lead', owner: 'AW', tags: ['real-estate','warm'], notes: 'Intro via LinkedIn.', createdAt: d(18), lastActivity: d(7) },
      { id: 'p5', name: 'Lena Vogel', email: 'lvogel@cortexlabs.ai', phone: '415-555-0129', company: 'c5', title: 'CEO', stage: 'Qualified', owner: 'AW', tags: ['startup','ai'], notes: 'Fast decision cycle.', createdAt: d(9), lastActivity: d(0) },
    ];
    for (const c of contacts) {
      await client.query('INSERT INTO contacts (id, org_id, name, email, phone, company_id, title, stage, owner, tags, notes, created_at, last_activity) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)',
        [c.id, orgId, c.name, c.email, c.phone, c.company, c.title, c.stage, c.owner, JSON.stringify(c.tags), c.notes, c.createdAt, c.lastActivity]);
    }

    const deals = [
      { id: 'd1', name: 'Apex Dynamics — Enterprise', company: 'c1', contact: 'p1', value: 84000, stage: 'Won', owner: 'AW', closeDate: new Date(d(-15)).toISOString().slice(0,10), notes: 'Closed.', createdAt: d(90), movedAt: d(15) },
      { id: 'd2', name: 'Meridian Capital — Platform', company: 'c2', contact: 'p2', value: 62000, stage: 'Negotiation', owner: 'AW', closeDate: new Date(d(-20)).toISOString().slice(0,10), notes: 'Final pricing.', createdAt: d(50), movedAt: d(8) },
      { id: 'd3', name: 'Vantage Health — Integration', company: 'c3', contact: 'p3', value: 120000, stage: 'Proposal Sent', owner: 'AW', closeDate: new Date(d(-30)).toISOString().slice(0,10), notes: 'Proposal sent.', createdAt: d(35), movedAt: d(14) },
      { id: 'd4', name: 'Northlake — Starter', company: 'c4', contact: 'p4', value: 18000, stage: 'Contacted', owner: 'AW', closeDate: new Date(d(-45)).toISOString().slice(0,10), notes: 'Discovery done.', createdAt: d(20), movedAt: d(10) },
      { id: 'd5', name: 'Cortex Labs — Growth', company: 'c5', contact: 'p5', value: 36000, stage: 'To Contact', owner: 'AW', closeDate: new Date(d(-60)).toISOString().slice(0,10), notes: 'Warm lead.', createdAt: d(10), movedAt: d(10) },
    ];
    for (const deal of deals) {
      await client.query('INSERT INTO deals (id, org_id, name, company_id, contact_id, value, stage, owner, close_date, notes, created_at, moved_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
        [deal.id, orgId, deal.name, deal.company, deal.contact, deal.value, deal.stage, deal.owner, deal.closeDate, deal.notes, deal.createdAt, deal.movedAt]);
    }

    const activities = [
      { id: 'a1', type: 'Call', contactId: 'p1', dealId: 'd1', note: 'Renewal call confirmed.', date: new Date(d(2)).toISOString(), createdAt: d(2) },
      { id: 'a2', type: 'Email', contactId: 'p3', dealId: 'd3', note: 'Sent proposal deck.', date: new Date(d(14)).toISOString(), createdAt: d(14) },
      { id: 'a3', type: 'Meeting', contactId: 'p2', dealId: 'd2', note: 'In-person at Chicago office.', date: new Date(d(8)).toISOString(), createdAt: d(8) },
    ];
    for (const a of activities) {
      await client.query('INSERT INTO activities (id, org_id, type, contact_id, deal_id, note, date, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [a.id, orgId, a.type, a.contactId, a.dealId, a.note, a.date, a.createdAt]);
    }

    await client.query('INSERT INTO tasks (id, org_id, title, due_date, contact_id, deal_id, priority, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      ['tk1', orgId, 'Send follow-up proposal to James Harlow', new Date(Date.now() - 86400000).toISOString().slice(0,10), 'p2', 'd2', 'High', 'Open', d(3)]);

    const products = [
      { id: 'pr1', name: 'Starter Plan', description: 'Up to 5 users, core CRM', price: 299, category: 'SaaS', billing: 'monthly' },
      { id: 'pr2', name: 'Growth Plan', description: 'Up to 25 users', price: 799, category: 'SaaS', billing: 'monthly' },
      { id: 'pr3', name: 'Enterprise Plan', description: 'Unlimited users', price: 2499, category: 'SaaS', billing: 'monthly' },
      { id: 'pr4', name: 'Onboarding Pack', description: '3-day workshop', price: 4500, category: 'Professional', billing: 'one-time' },
    ];
    for (const p of products) {
      await client.query('INSERT INTO products (id, org_id, name, description, price, category, billing, active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [p.id, orgId, p.name, p.description, p.price, p.category, p.billing, 1, Date.now()]);
    }

    const pipelineStages = JSON.stringify([
      { name: 'To Contact', color: '#6366f1', probability: 0.10 },
      { name: 'Contacted', color: '#3b82f6', probability: 0.25 },
      { name: 'Proposal Sent', color: '#eab308', probability: 0.50 },
      { name: 'Negotiation', color: '#f97316', probability: 0.75 },
      { name: 'Won', color: '#22c55e', probability: 1.00 },
      { name: 'Lost', color: '#ef4444', probability: 0.00 },
    ]);
    await client.query('INSERT INTO settings (org_id, key, value) VALUES ($1,$2,$3)', [orgId, 'pipelineStages', pipelineStages]);
    await client.query('INSERT INTO settings (org_id, key, value) VALUES ($1,$2,$3)', [orgId, 'emailTemplates', '[]']);
    await client.query('INSERT INTO settings (org_id, key, value) VALUES ($1,$2,$3)', [orgId, 'invoiceSettings', JSON.stringify({
      companyName: 'BoredRoom', companyAddress: '', taxRate: 0, currency: 'USD', prefix: 'INV-', nextNumber: 1001
    })]);

    // Seed default currencies
    const defaultCurrencies = [
      { code: 'USD', symbol: '$', name: 'US Dollar', rate: 1.0 },
      { code: 'EUR', symbol: '€', name: 'Euro', rate: 0.92 },
      { code: 'GBP', symbol: '£', name: 'British Pound', rate: 0.79 },
      { code: 'CAD', symbol: 'CA$', name: 'Canadian Dollar', rate: 1.36 },
    ];
    for (const c of defaultCurrencies) {
      await client.query('INSERT INTO currencies (id, org_id, code, symbol, name, exchange_rate_to_usd, active, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT DO NOTHING',
        ['cur_' + c.code + '_' + orgId.slice(-6), orgId, c.code, c.symbol, c.name, c.rate, 1, Date.now()]);
    }

    await client.query('COMMIT');
    console.log('✅ Seed complete. Admin: admin@boredroom.com / BoredRoom2025!');
  } catch(e) {
    await client.query('ROLLBACK');
    console.error('Seed error:', e.message);
    throw e;
  } finally {
    client.release();
  }
}

// ── Initialize ────────────────────────────────────────────────────────────
async function init() {
  let retries = 5;
  while (retries > 0) {
    try {
      await pool.query('SELECT 1');
      break;
    } catch(e) {
      retries--;
      if (retries === 0) throw e;
      console.log(`DB connection failed, retrying... (${retries} left)`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  await createSchema();
  await seedIfEmpty();
  console.log('✅ Database ready');
}

// ── Export ────────────────────────────────────────────────────────────────
const db = {
  pool,
  prepare,
  exec,
  transaction,
  query: pool.query.bind(pool),
  connect: pool.connect.bind(pool),
  init,
};

module.exports = db;
