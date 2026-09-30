# Remove First-Run Setup Code Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the requirement for a one-time setup code during initial server onboarding so users can create their administrator account directly from the web console on first visit.

**Architecture:** Update server startup and auth endpoints to stop minting and requiring `setupCode`, update `/api/auth/state` to report `setup_code_required: false`, streamline the frontend `Setup.tsx` form by removing the setup code input field, update `rmm-server setup-code` CLI command to inform that no code is needed, and verify all tests pass locally.

**Tech Stack:** Go 1.26, React 19, TypeScript, Vite.

**Spec:** User request to simplify first-run onboarding by removing the initial server setup code requirement.

## Global Constraints
- Keep all actions strictly local; do not push to remote GitHub.
- Maintain atomic first-user creation under `setupMu` lock so concurrent requests cannot create multiple admins.
- Preserve CSRF defense (`X-Requested-With` header via `authGuard`) on `/api/auth/setup`.
- Ensure all Go tests and TypeScript typechecks compile and pass locally.

---

### Task 1: Backend Server & Auth Updates (TDD)

**Files:**
- Modify: `internal/server/security_test.go`
- Modify: `internal/server/testutil_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/api.go`

- [ ] **Step 1: Update security tests to expect setup without code**
  - In `internal/server/security_test.go`:
    - Update `TestSetupAlwaysNeedsTheCode` to `TestFirstRunSetupWithoutCode`: verify first-run setup creates the admin directly with empty/no code, and subsequent setup attempts return 403 `already set up`.
    - Update `TestSetupBehindALoopbackProxyNeedsTheCode` to verify proxy setups succeed directly without code.
    - Update other setup call sites in `security_test.go` and `testutil_test.go` so `code` is empty or not required.

- [ ] **Step 2: Run targeted test to confirm failure**
  ```powershell
  go test ./internal/server -run TestSetup -v
  ```

- [ ] **Step 3: Implement server and API changes**
  - In `internal/server/server.go`:
    - Remove `setupCode string` generation in `New()` (`s.setupCode = randomHex(4)`).
    - In `Run()`, replace the setup code banner with a clean first-run info log:
      `slog.Info("FIRST RUN: no users yet. Open the console to create the administrator.")`
  - In `internal/server/api.go`:
    - In `handleAuthState`: set `"setup_code_required": false`.
    - In `handleSetup`: remove the `s.setupCode` / `in.Code` validation. Retain `s.setupMu` lock and `s.db.UserCount() > 0` check.

- [ ] **Step 4: Run targeted tests and full internal/server suite**
  ```powershell
  go test ./internal/server -run TestSetup -v
  go test ./internal/server -v -run "TestFirstRun|TestAuth"
  ```

---

### Task 2: CLI Subcommand & Main Test Updates

**Files:**
- Modify: `cmd/rmm-server/main.go`
- Modify: `cmd/rmm-server/setupcode.go`
- Modify: `cmd/rmm-server/setupcode_test.go`
- Modify: `cmd/rmm-server/main_test.go`

- [ ] **Step 1: Update main CLI and setupcode subcommand**
  - In `cmd/rmm-server/setupcode.go`:
    - Update `runSetupCode` so if invoked, it prints:
      `Homelab RMM does not require a setup code. Open the web console directly to create the administrator account.`
  - In `cmd/rmm-server/main.go`:
    - Update usage text to reflect that no setup code is required on first run.
  - In `cmd/rmm-server/main_test.go` & `setupcode_test.go`:
    - Update test assertions to match the updated log messages and subcommand output.

- [ ] **Step 2: Verify cmd tests pass**
  ```powershell
  go test ./cmd/... -v
  ```

---

### Task 3: Web UI & E2E Smoke Test Updates

**Files:**
- Modify: `web/src/pages/Setup.tsx`
- Modify: `web/src/api/client.ts`
- Modify: `web/src/state/auth.tsx`
- Modify: `web/e2e/smoke.mjs`

- [ ] **Step 1: Update Frontend Setup page**
  - In `web/src/pages/Setup.tsx`:
    - Remove `code` state and the `Setup code` input `Field`.
    - Submit `username`, `password`, `email` without requiring `code`.
  - In `web/src/api/client.ts`:
    - Update `api.setup` signature to make `code` optional (default empty string `code = ''`).
  - In `web/e2e/smoke.mjs`:
    - Update the setup step to fill username and password and submit directly, verifying it navigates to the dashboard without filling `#su-code`.

- [ ] **Step 2: Run typecheck and web build**
  ```powershell
  cd web
  npm run typecheck
  npm run build
  cd ..
  ```

---

### Task 4: Full Local Test & Verification

- [ ] **Step 1: Run all backend tests**
  ```powershell
  go test ./...
  ```

- [ ] **Step 2: Verify git status is clean and ready locally**
  - Confirm all changes are local and working. Do not push.
