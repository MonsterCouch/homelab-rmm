# Enterprise Expansion (Phases 1–5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform Homelab RMM into a multi-tenant MSP-grade platform by delivering 3-tier organizational hierarchy, remote desktop multi-monitor & privacy banner, device network isolation, network discovery with SNMP polling, self-service software catalog, ticketing system, and client system tray companion.

**Architecture:** 
- **Data Layer:** SQLite schema migrations for Organizations, Sites, Tickets, Network Devices, and Software Catalog with foreign keys and backwards-compatible defaults.
- **Backend / Agent Layer:** REST APIs for tenancy, tickets, network probe scanning, and software deployment; agent-side Windows Firewall isolation rules, local subnet ARP/ICMP sweeps, and SNMP OID queries.
- **Frontend / Client Layer:** Organization & Site scoping in the web console, dedicated Discovery and Tickets sections, multi-monitor viewer controls in Remote Desktop, and a standalone `rmm-tray.exe` client companion for end-users.

**Tech Stack:** Go 1.27 (`net/http`, `crypto/tls`, SQLite3, ConPTY, Windows API), React 18, TypeScript, Vite.

## Global Constraints
- Preserve `CGO_ENABLED=0` across all binaries.
- All database migrations must be backwards-compatible with existing agent records (default Org/Site created automatically).
- No pushing to GitHub (strict local changes).
- Maintain existing test coverage; run `go test ./...` and `npm run build` after each phase.

---

## Phase 1: 3-Tier Organization Hierarchy (MSP / Client / Site)

### Task 1.1: Database Schema Migrations for Organizations & Sites
**Files:**
- Modify: `internal/server/schema.go`
- Test: `internal/server/schema_test.go` or `internal/server/orgs_test.go`

- [ ] **Step 1: Write unit tests for organization and site table creation and default seeding**
- [ ] **Step 2: Add `organizations` and `sites` tables in `internal/server/schema.go`**
  - Columns for `organizations`: `id TEXT PRIMARY KEY`, `name TEXT NOT NULL`, `created_at DATETIME`
  - Columns for `sites`: `id TEXT PRIMARY KEY`, `org_id TEXT NOT NULL REFERENCES organizations(id)`, `name TEXT NOT NULL`, `created_at DATETIME`
  - Alter `agents` to add `org_id TEXT`, `site_id TEXT`
  - Alter `enrollment_tokens` to add `org_id TEXT`, `site_id TEXT`
  - Auto-seed default organization `"Default"` and default site `"Main"` for existing unassigned devices.
- [ ] **Step 3: Run tests to verify schema migration succeeds cleanly on existing databases**

### Task 1.2: Server API Endpoints for Organizations & Sites
**Files:**
- Create: `internal/server/orgs.go`
- Modify: `internal/server/server.go` (register routes)
- Test: `internal/server/orgs_test.go`

- [ ] **Step 1: Write integration tests for Org/Site CRUD and scoping**
- [ ] **Step 2: Implement handlers:**
  - `GET /api/organizations`, `POST /api/organizations`, `DELETE /api/organizations/{id}`
  - `GET /api/organizations/{id}/sites`, `POST /api/organizations/{id}/sites`, `DELETE /api/sites/{id}`
  - Update `GET /api/agents` and `GET /api/dashboard` to accept optional `?org_id=` and `?site_id=` query filters.
  - Update `POST /api/enrollment-tokens` to associate token with chosen `org_id` and `site_id`.
- [ ] **Step 3: Run `go test ./internal/server` to confirm all endpoints pass**

### Task 1.3: Web Console Organization & Site Selector
**Files:**
- Modify: `web/src/api/client.ts` (add org & site methods)
- Modify: `web/src/components/Layout.tsx` (topbar or sidebar Org/Site switcher)
- Modify: `web/src/pages/Devices.tsx` (filter by Org/Site)
- Modify: `web/src/pages/Settings.tsx` (manage Orgs & Sites)

- [ ] **Step 1: Add TypeScript types and API client functions for organizations and sites**
- [ ] **Step 2: Add Organization & Site management tab under Settings**
- [ ] **Step 3: Add Org/Site filter pills to Devices page and Device Enrollment drawer**
- [ ] **Step 4: Verify with `npm --prefix web run build`**

---

## Phase 2: Remote Desktop (Multi-Monitor + Banner) & Device Isolation

### Task 2.1: Remote Desktop Multi-Monitor Support & Connection Banner
**Files:**
- Modify: `internal/agent/desktop/` (display enumeration & selection)
- Modify: `web/src/pages/device/Desktop.tsx` (monitor switcher dropdown)

- [ ] **Step 1: Implement monitor enumeration in `internal/agent/desktop`**
  - Send `{t: "monitors", count: N, primary: 0}` to viewer on handshake
  - Accept `{t: "select_monitor", monitor: N}` from viewer to switch active capture display
- [ ] **Step 2: Add in-session banner overlay on Windows client session**
  - When viewer connects, render a lightweight translucent banner window ("IT Support is connected")
  - Destroy banner when WebSocket disconnects
- [ ] **Step 3: Add Monitor selector toolbar button in `web/src/pages/device/Desktop.tsx`**

### Task 2.2: Device Network Isolation (Quarantine)
**Files:**
- Modify: `internal/server/schema.go` (add `isolated INTEGER DEFAULT 0` to `agents`)
- Modify: `internal/server/api.go` (add `/api/devices/{id}/isolate` & `unisolate`)
- Modify: `internal/agent/` (firewall isolation action handler)
- Modify: `web/src/pages/device/DeviceDetail.tsx` (Isolate/Unisolate action button)

- [ ] **Step 1: Write backend tests for device isolation state toggling**
- [ ] **Step 2: Implement agent-side Windows Firewall isolation logic:**
  - Create firewall rule blocking all inbound and outbound IP traffic
  - Whitelist outbound TCP to RMM server IP:port, and local UDP 53/67/68 for DNS/DHCP
  - Un-isolation removes the quarantine firewall rules
- [ ] **Step 3: Add UI Quarantine button with confirmation modal and prominent warning banner on device detail page**

---

## Phase 3: Network Discovery & SNMP Polling

### Task 3.1: Network Subnet Discovery Engine
**Files:**
- Create: `internal/agent/discovery.go`
- Create: `internal/server/discovery.go`
- Modify: `internal/server/schema.go` (`network_devices` table)
- Test: `internal/server/discovery_test.go`

- [ ] **Step 1: Create `network_devices` database table**
  - `id`, `site_id`, `ip`, `mac`, `hostname`, `vendor`, `device_type`, `snmp_info`, `status`, `last_seen`
- [ ] **Step 2: Implement agent-side subnet sweeper in `internal/agent/discovery.go`**
  - ARP table lookup and ICMP echo sweep over local `/24` subnet
  - MAC address vendor lookup prefix mapping
- [ ] **Step 3: Implement server ingest endpoint `POST /api/devices/{id}/discovery-results` and query `GET /api/network-devices`**

### Task 3.2: Basic SNMP v2c Poller & UI Tab
**Files:**
- Create: `internal/agent/snmp.go`
- Create: `web/src/pages/NetworkDevices.tsx`
- Modify: `web/src/components/Layout.tsx` (add "Network" navigation link)

- [ ] **Step 1: Implement basic SNMP v2c poller for `sysDescr`, `sysName`, `sysUpTime`**
- [ ] **Step 2: Add Network Discovery page in web UI with discovered device table, MAC vendors, and probe trigger button**
- [ ] **Step 3: Verify build with `npm --prefix web run build` and `go test ./...`**

---

## Phase 4: Self-Service Software Catalog & Ticketing Engine

### Task 4.1: Software Catalog Repository
**Files:**
- Create: `internal/server/software.go`
- Modify: `internal/server/schema.go` (`software_catalog` table)
- Create: `web/src/pages/SoftwareCatalog.tsx`

- [ ] **Step 1: Add `software_catalog` table** (`id`, `name`, `description`, `version`, `icon`, `installer_url`, `installer_sha256`, `silent_args`, `org_id`)
- [ ] **Step 2: Implement CRUD endpoints `/api/software-catalog` and execute install `/api/devices/{id}/install-app`**
- [ ] **Step 3: Build Web UI Catalog manager where admins can register approved installers and view deployment status**

### Task 4.2: Integrated Ticketing Engine
**Files:**
- Create: `internal/server/tickets.go`
- Modify: `internal/server/schema.go` (`tickets`, `ticket_comments` tables)
- Create: `web/src/pages/Tickets.tsx`
- Create: `web/src/pages/TicketDetail.tsx`

- [ ] **Step 1: Add `tickets` and `ticket_comments` database tables**
  - `id`, `org_id`, `site_id`, `agent_id`, `title`, `description`, `reporter_name`, `reporter_email`, `status`, `priority`, `created_at`, `updated_at`
- [ ] **Step 2: Server API handlers:**
  - `GET /api/tickets`, `POST /api/tickets`, `GET /api/tickets/{id}`, `PATCH /api/tickets/{id}`, `POST /api/tickets/{id}/comments`
- [ ] **Step 3: Web UI Ticketing views with status badges, priority filtering, technician response composer, and device links**

---

## Phase 5: Client System Tray Companion (`rmm-tray`)

### Task 5.1: Build `rmm-tray` Application
**Files:**
- Create: `cmd/rmm-tray/main.go`
- Create: `cmd/rmm-tray/tray.go`
- Create: `cmd/rmm-tray/ui.go` (Webview or native dialogs for Ticket Submission and Software Portal)

- [ ] **Step 1: Build system tray icon with Windows Shell_NotifyIcon:**
  - Context menu: "Submit Support Ticket", "Self-Service Software", "Device Status", "Exit"
- [ ] **Step 2: Implement Support Ticket form window:**
  - Subject, Description, Name, Email, optional Screen Capture attachment
  - Sends ticket to local agent or RMM server
- [ ] **Step 3: Implement Self-Service Software window:**
  - Lists approved applications from the catalog; clicking "Install" sends safe `catalog_id` request to local SYSTEM service
- [ ] **Step 4: Add `rmm-tray` build target to `tools/build.ps1` and verify end-to-end**
