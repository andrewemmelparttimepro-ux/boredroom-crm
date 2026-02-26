# Hubnot CRM

BoredRoom's in-house CRM — built by Andrew Emmel + O'Brien (Clipper Smith). HubSpot clone, 26 phases deep.

**Live:** https://boredroom-crm.onrender.com  
**Login:** admin@boredroom.com / BoredRoom2025!

---

## Stack

| Layer | Tech |
|-------|------|
| Backend API | Node.js + Express (port 3001) |
| Database | PostgreSQL (Render managed, free tier) |
| Auth | JWT + bcrypt |
| Frontend | Vanilla JS, served as static files by Express |
| Hosting | Render (auto-deploys on push to `main`) |

**Express serves both the API (`/api/*`) and the frontend from the same port — no separate frontend server needed.**

---

## Run Locally

### Prerequisites
- Node.js 18+
- PostgreSQL running locally **OR** a Render PostgreSQL connection string

### 1. Clone
```bash
git clone https://github.com/andrewemmelparttimepro-ux/boredroom-crm.git
cd boredroom-crm
```

### 2. Configure environment
```bash
cp server/.env.example server/.env
# Edit server/.env with your values
```

Required env vars:
```
DATABASE_URL=postgresql://user:pass@host:5432/dbname
JWT_SECRET=your-secret-key-here
PORT=3001
```

### 3. Install and start
```bash
npm install
cd server && npm install
node server.js
```

Open **http://localhost:3001** in your browser.

### Quick start script
```bash
bash start.sh
```
Starts the API server (and optional Cloudflare tunnel for public URL).

---

## Deploy to Render

Render auto-deploys on every push to `main`. The `render.yaml` in this repo defines the service.

**Render Service ID:** `srv-d6fstrp5pdvs73c4q91g`  
**Render API Key:** (ask Andrew — stored in TOOLS.md)

To manually trigger a deploy:
```bash
git push origin main
```

---

## Project Structure

```
boredroom-crm/
├── index.html          # Frontend app (single-page)
├── app.js              # Frontend JS
├── style.css           # Frontend styles
├── start.sh            # Local launcher
├── ecosystem.config.js # pm2 config (optional, for prod)
├── render.yaml         # Render deploy config
└── server/
    ├── server.js       # Express API (all routes)
    ├── db.js           # PostgreSQL connection
    ├── schema.sql      # DB schema
    └── .env            # Environment variables (not committed)
```

---

## O'Brien Chat Widget

The floating chat button (bottom-right) connects to O'Brien via the OpenClaw gateway.

**Requires:** OpenClaw running locally with the chat completions endpoint enabled.
- Gateway port: `18789`
- Auth token: stored in `server.js` (look for `OPENCLAW_TOKEN` or the Bearer string in `/api/chat`)
- If OpenClaw isn't running, the chat widget will error — that's expected

To use the chat widget, OpenClaw must be running on the same machine as the CRM server.

---

## Features (Phase 26)

- **Dashboard** — pipeline overview, stats, revenue goals
- **Contacts** — full CRUD, custom fields, lead scoring, duplicate detection, merge
- **Companies** — linked to contacts and deals
- **Pipeline (Kanban)** — drag-drop deals, custom stages, probability
- **Activities** — log calls, emails, meetings; quick presets; sequences
- **Tasks** — due dates, priority, owners
- **Invoicing** — create/edit/print/PDF, deal linking, overdue alerts, MRR/ARR
- **Reports** — 5 charts, stage funnel, owner performance, activity trends, cohort analysis
- **Client Portal** — token-protected shareable deal view (Deal Room V2: threaded comments, checklists, video call link)
- **Proposals** — generator with PDF export
- **Sales Playbooks** — team process docs
- **Product Catalog** — link products to invoices
- **Smart Lists** — criteria-based contact segments
- **Global Search** — Cmd+K
- **PWA** — installable on mobile
- **AI Chat** — O'Brien assistant with live CRM context

---

## Default Credentials

| Field | Value |
|-------|-------|
| Email | admin@boredroom.com |
| Password | BoredRoom2025! |

Change these after first login in production.

---

## ⚠️ Notes

- **Render free tier** spins down after 15 min inactivity — first load after idle takes ~30s cold start
- **PostgreSQL expires 2026-03-28** on free tier — upgrade to Render paid ($7/mo) before that date
- Data persists through restarts and deploys (PostgreSQL, not SQLite)
