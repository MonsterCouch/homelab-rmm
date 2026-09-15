# Changelog

All notable changes to Homelab RMM. The format follows [Keep a Changelog](https://keepachangelog.com/)
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-15

Initial release.

### Server
- Single binary with embedded web console, JSON API, Server-Sent Events, SQLite (pure Go,
  WAL, versioned migrations) and a self-signed certificate generated on first run.
- Windows service / systemd unit management (`install`, `uninstall`, `start`, `stop`,
  `restart`, `status`) and a `user` CLI (`add`, `passwd`, `list`).
- Agent hub: outbound WebSocket per device, enrolment tokens (uses, expiry, group), per-device
  keys stored hashed, keepalive, config push, live event fan-out to browsers.
- Users with admin / tech / viewer roles, bcrypt passwords, TOTP two-factor, session cookies,
  CSRF header check, same-origin WebSocket check, login rate limiting, audit log.
- Monitoring: metrics history with bucketed queries, inventory snapshots, monitored services,
  maintenance mode.
- Alert engine: cpu, memory, disk, offline, service, reboot required, script failed, patch
  failed and event-pattern rules; sustained thresholds, deduplication, auto-resolve,
  acknowledge, email notifications (STARTTLS / TLS / plain SMTP).
- Scripting: library with categories, parameters, timeouts and OS filters; PowerShell, cmd,
  bash, sh, python; streamed output; queued runs for offline devices; targets by device, group,
  tag or OS; cron-scheduled tasks; automations (run script, email, webhook) on device, alert,
  enrolment, reboot and patch events.
- Patch management: scan/approve/ignore/install with live log, policies with scan and install
  schedules, approved / all / security modes, reboot never / if required / always.
- Relays: browser terminal over a pseudo-terminal, remote desktop bridge with single-use helper
  tokens.
- Device tools: processes, services, event log / journal, file browser with upload and
  download, power actions, Wake-on-LAN via a peer agent on the same subnet.
- Enrolment: install scripts for Windows (PowerShell) and Linux (bash) served per token; agent
  binaries served from `<data>/agents/` or beside the executable.
- Seed data on first start: 17 starter scripts (Windows PowerShell and Linux bash) across
  Maintenance, Diagnostics, Updates, Security and Users; seven default alert rules; `Servers`
  and `Workstations` groups; a scan-every-6-hours patch policy.
- Retention purge (metrics, runs, events, audit, resolved alerts, tokens, sessions).

### Agent (Windows, Linux)
- Service install with certificate pinning by SHA-256 fingerprint, reconnect with backoff,
  identity kept across reinstalls, automatic re-enrolment after key revocation.
- Inventory (hardware, OS, disks, network, software, GPUs, users, pending reboot, antivirus)
  and periodic metrics.
- Scripts with positional parameters, streamed output, timeout and cancel (process-tree kill).
- Shell sessions (ConPTY on Windows, pty on Linux), processes, services, event log (wevtutil)
  and journald, files, power actions, Wake-on-LAN, updates (Windows Update Agent; apt, dnf/yum,
  pacman, zypper), self-update primitive (`agent.update`).
- Remote desktop helper: GDI / X11 capture with 64×64 tile diffing, JPEG/PNG tiles, flow
  control, mouse and keyboard injection (SendInput / XTEST), multi-monitor, clipboard paste,
  Ctrl-Alt-Del; launched in the console session (session 0 → user or SYSTEM token) or as the
  X11 session owner.

### Web console
- React + TypeScript SPA: dashboard, devices with overview / terminal / desktop / processes /
  services / event log / files / software / patches / runs / events tabs, scripts editor,
  runs, tasks with cron editor, automations, alerts and rules, patches, users, audit,
  settings, account (password, TOTP).

### Tooling
- Makefile, `tools/build.sh`, `tools/build.ps1` (cross-compile for windows/amd64,
  windows/arm64, linux/amd64, linux/arm64 and linux/arm agents; release archives with
  checksums), GitHub Actions build and release workflow, Dockerfile (distroless, agents baked
  in) and docker-compose, deploy examples (systemd unit, Caddy, nginx, uninstall scripts).

[Unreleased]: https://github.com/MonsterCouch/homelab-rmm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/MonsterCouch/homelab-rmm/releases/tag/v0.1.0
