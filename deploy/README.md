# deploy/

Examples and helpers for running Homelab RMM. None of these are required: `rmm-server install`
and the enrollment one-liners set everything up on their own. See `docs/OPERATIONS.md` for the
full picture.

| File | Use it when |
|---|---|
| `homelab-rmm-server.service` | you want the server under a dedicated Linux user with systemd hardening instead of the unit `rmm-server install` writes |
| `Caddyfile` | you put Caddy in front of the server (`--insecure` on the server, TLS at the proxy) |
| `nginx.conf` | the same with nginx, including the WebSocket and SSE settings that matter |
| `renew-tailscale-cert.ps1` | automated certificate renewal for Windows servers behind a proxy or without `--tailscale-cert` |
| `uninstall.sh` | removing the agent or the server from a Linux machine |
| `uninstall.ps1` | removing the agent or the server from a Windows machine |
| `../docker-compose.yml`, `../Dockerfile` | running the server as a container |
