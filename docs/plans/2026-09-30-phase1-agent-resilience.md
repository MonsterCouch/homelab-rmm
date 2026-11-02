# Phase 1 Implementation Plan: Agent Resilience & Hardening

**Document:** `docs/plans/2026-09-30-phase1-agent-resilience.md`  
**Status:** Approved & Ready for Execution  
**Goal:** Transform `rmm-agent` into a self-healing, crash-resilient endpoint service with an out-of-process supervisor, A/B partition staging with a 60-second TLS rollback circuit, Windows Job Object resource quotas, and in-memory secret scrubbing.

---

## 1. Architecture Overview

```
                      +---------------------------------------+
                      |       OS Service Manager (SCM)        |
                      |  (Starts: rmm-agent.exe supervisor)   |
                      +-------------------+-------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |         Supervisor Process            |
                      |  - Manages bin/current (symlink)      |
                      |  - Tracks state.json (slot_a, slot_b) |
                      |  - 60s verification timer on updates  |
                      +--------+---------------------+--------+
                               |                     ^
                     spawns    |                     | IPC Heartbeats &
               rmm-agent run   |                     | Healthy Notify
                               v                     |
                      +------------------------------+--------+
                      |          Worker Process               |
                      |  - Runs from bin/current              |
                      |  - Connects to RMM Server via WS      |
                      |  - Enforces Job Object script limits  |
                      |  - Scrubs output streams              |
                      +---------------------------------------+
```

### Directory Layout
```
C:\Program Files\HomelabRMM\ (or /opt/homelab-rmm/)
├── agent.json                  # Existing agent config & credentials
├── baselines.json              # Local baseline cache
└── bin/
    ├── slot_a/
    │   └── rmm-agent.exe       # Stable binary slot
    ├── slot_b/
    │   └── rmm-agent.exe       # Inactive / upgrade staging slot
    ├── current -> slot_a       # Symlink or directory junction
    └── state.json              # Slot tracking and update state
```

---

## 2. File Modification & Creation Inventory

| File Path | Status | Purpose |
| :--- | :--- | :--- |
| `internal/protocol/protocol.go` | **Modify** | Add `MaxMemoryMB` and `CPULimitPercent` to `protocol.ScriptRun`. |
| `internal/agent/proc_windows.go` | **Modify** | Extend Windows Job Object with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` (default 1024 MB) and CPU rate control. |
| `internal/agent/proc_linux.go` | **Modify** | Implement process memory limits via `setrlimit` or cgroups v2. |
| `internal/agent/scripts.go` | **Modify** | Wrap stdout/stderr streaming with regex-based secret redactor. |
| `internal/supervisor/ipc.go` | **Create** | Local IPC (Named Pipe on Windows, UDS on Linux) for heartbeats and health notifications. |
| `internal/supervisor/slots.go` | **Create** | A/B directory management, symlink/junction manipulation, and `state.json` persistence. |
| `internal/supervisor/supervisor.go` | **Create** | Supervisor loop: process lifecycle, heartbeat monitor, and 60-second rollback circuit. |
| `internal/agent/update.go` | **Modify** | Route updates into inactive slot and notify supervisor instead of raw in-place overwrite. |
| `cmd/rmm-agent/main.go` | **Modify** | Wire `supervisor` subcommand; configure service install to run supervisor mode. |

---

## 3. Step-by-Step Implementation Tasks

### Task 1: Script Resource Quotas & Process Sandboxing
- **Objective:** Prevent runaway scripts from starving or freezing the host OS.
- **Files:** `internal/protocol/protocol.go`, `internal/agent/proc_windows.go`, `internal/agent/proc_linux.go`
- **Implementation Details:**
  1. Add fields to `protocol.ScriptRun`:
     ```go
     MaxMemoryMB     uint64 `json:"max_memory_mb,omitempty"`     // 0 = default (1024 MB)
     CPULimitPercent uint32 `json:"cpu_limit_percent,omitempty"` // 0 = default (80%)
     ```
  2. In `internal/agent/proc_windows.go`:
     - Update `newKillJob()` to `newSandboxedJob(maxMemMB uint64, cpuPercent uint32)`.
     - Set `JOBOBJECT_EXTENDED_LIMIT_INFORMATION` with `JOB_OBJECT_LIMIT_PROCESS_MEMORY` to `maxMemMB * 1024 * 1024` (fallback to 1024 MB if 0).
     - Set `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION` with `JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP` (fallback to 80% if 0).
  3. In `internal/agent/proc_linux.go`:
     - Apply `syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: limit, Max: limit})` in `cmd.SysProcAttr.Credential` or pre-exec hook.

### Task 2: Real-Time Secret Redaction in Script Output Streams
- **Objective:** Prevent technician credentials, API tokens, and private keys from leaking into the database audit log.
- **Files:** `internal/agent/scripts.go`
- **Implementation Details:**
  1. Create a streaming `redactWriter` implementing `io.Writer`.
  2. Implement regex patterns matching:
     - `Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`
     - `(?i)(password|passwd|secret|api_key|token)\s*[:=]\s*([^\s;]+)` -> replace secret group with `[REDACTED]`
     - Private key headers: `-----BEGIN [A-Z ]+ PRIVATE KEY-----`
  3. Wrap `stdout` and `stderr` writers in `runScript()` with `redactWriter`.

### Task 3: Local Supervisor-Worker IPC
- **Objective:** Secure, reliable communication between supervisor and worker on the same host.
- **Files:** `internal/supervisor/ipc.go`
- **Implementation Details:**
  1. **Windows:** Named pipe `\\.\pipe\homelab-rmm-supervisor` with explicit SDDL (`D:P(A;;GA;;;SY)(A;;GA;;;BA)` — strictly `SYSTEM` and `Administrators`).
  2. **Linux:** Unix Domain Socket at `/run/homelab-rmm/supervisor.sock` with `0600` permissions owned by `root`.
  3. Protocol messages (JSON lines):
     - `{"type": "heartbeat", "pid": 1234, "rss_bytes": 35000000}`
     - `{"type": "notify_healthy", "version": "v1.2.0"}` (emitted after successful server TLS + WS auth)
     - `{"type": "request_restart", "reason": "update_staged"}`

### Task 4: A/B Partition Slot Manager
- **Objective:** Safe binary staging and atomic symlink/junction flipping.
- **Files:** `internal/supervisor/slots.go`
- **Implementation Details:**
  1. Define `SlotState`:
     ```go
     type SlotState struct {
         ActiveSlot       string    `json:"active_slot"`       // "slot_a" or "slot_b"
         PendingSlot      string    `json:"pending_slot"`      // "" or slot awaiting verification
         PendingStartedAt time.Time `json:"pending_started_at"` // Timestamp when pending slot was booted
         LastGoodVersion  string    `json:"last_good_version"`
         RollbackCount    int       `json:"rollback_count"`
     }
     ```
  2. Implement:
     - `InitSlots(baseDir string) (*SlotManager, error)`: Ensures directories `bin/slot_a`, `bin/slot_b` exist and initializes `bin/current` symlink / junction.
     - `GetInactiveSlot() string`: Returns the slot not currently pointed to by `current`.
     - `PromotePending() error`: Points `current` to `pending_slot`, writes `state.json`.
     - `ConfirmHealthy() error`: Clears `PendingSlot` in `state.json`.
     - `Rollback() error`: Reverts `current` to `ActiveSlot`, clears `PendingSlot`, increments `RollbackCount`.

### Task 5: Supervisor Lifecycle & 60-Second Rollback Circuit
- **Objective:** Continuously monitor worker health and auto-rollback failed updates.
- **Files:** `internal/supervisor/supervisor.go`
- **Implementation Details:**
  1. Supervisor main loop:
     - Check `state.json`: If `PendingSlot != ""` and `time.Since(PendingStartedAt) > 60*time.Second`, trigger immediate `Rollback()` and restart worker from `ActiveSlot`.
     - Spawn worker: `exec.Command(currentBinaryPath, "run")`.
     - Listen on IPC for heartbeats. If no heartbeat received within 30 seconds, kill worker and restart.
     - When `notify_healthy` message is received over IPC: call `slots.ConfirmHealthy()`.

### Task 6: CLI Subcommand Integration
- **Objective:** Support both `rmm-agent supervisor` (service mode) and `rmm-agent run` (worker mode).
- **Files:** `cmd/rmm-agent/main.go`
- **Implementation Details:**
  1. Subcommand router in `main()`:
     - `rmm-agent supervisor`: Runs the supervisor loop (under `svc.Run` if registered as Windows Service / systemd).
     - `rmm-agent run`: Runs the existing agent worker logic.
     - `rmm-agent install`: Updates service definition to install with `supervisor` argument.
     - Backwards compatibility: If no subcommand is passed, check if running under service manager; if so, default to `supervisor`.

### Task 7: Update Staging Refactoring
- **Objective:** Stop in-place overwrites; write to inactive slot and notify supervisor.
- **Files:** `internal/agent/update.go`, `internal/agent/agent.go`
- **Implementation Details:**
  1. Modify `ApplyUpdate(r io.Reader)`:
     - Ask supervisor for inactive slot path over IPC.
     - Stream new binary into `<inactive_slot>/rmm-agent.exe`.
     - Validate SHA-256 checksum and verify binary header (PE on Windows, ELF on Linux).
     - Send `request_restart` message to supervisor over IPC.
     - Gracefully shutdown worker.

---

## 4. Verification & Testing Criteria

### Automated Unit & Integration Tests
1. **Job Object Quota Test (`internal/agent/proc_windows_test.go`):**
   - Run a test script allocating 1.5 GB memory. Verify process terminates with exit code indicating quota violation, without crashing host or agent.
2. **Secret Redaction Test (`internal/agent/scripts_test.go`):**
   - Stream string containing `Bearer eyJ...`, `password=SuperSecret123;`, and private key blocks. Verify output buffer contains `[REDACTED]` in place of secrets.
3. **Slot Flip & State Test (`internal/supervisor/slots_test.go`):**
   - Test directory creation, symlink/junction pointer changes, and JSON persistence.
4. **Rollback Circuit Test (`internal/supervisor/supervisor_test.go`):**
   - Stage a dummy worker binary that sleeps for 90 seconds without emitting `notify_healthy`. Verify supervisor times out at 60s, rolls back `current` symlink to `slot_a`, and boots original binary.

---

## 5. Execution Order

```
[Task 1: Job Object Quotas] ──> [Task 2: Secret Redaction]
               │
               v
[Task 3: Local IPC Layer] ────> [Task 4: A/B Slot Manager]
               │
               v
[Task 5: Supervisor Core] ────> [Task 6: CLI Subcommand] ──> [Task 7: Update Flow Integration]
               │
               v
[Task 8: Full End-to-End Verification & Rollback Test]
```
