# Architectural Roadmap & Future Capabilities

This document tracks enterprise-grade capabilities identified during market comparisons (e.g., against NinjaOne, Datto RMM, ConnectWise) that are planned for future development beyond the core Homelab RMM platform.

---

## 1. Native Endpoint & Cloud Backup
- **Scope**: File & folder backup, full-disk image backup, bare-metal disaster recovery.
- **Architecture**:
  - Integration with storage backends (local NAS via SMB/NFS, S3-compatible cloud storage like MinIO, Wasabi, AWS S3, Backblaze B2).
  - Deduplication and client-side AES-256 encryption.
  - Granular self-service file restoration from the web console and client portal.
- **Current Recommendation**: Pair with dedicated self-hosted backup utilities such as Proxmox Backup Server, Veeam Community Edition, Kopia, or Restic.

---

## 2. Mobile Device Management (MDM) & Apple Ecosystem
- **Scope**: Native Apple MDM (macOS, iOS, iPadOS) and Android Enterprise.
- **Architecture**:
  - Integration with Apple Push Notification service (APNs) and Apple Business Manager (ABM).
  - Enforcing configuration profiles (`.mobileconfig`), FileVault key escrow, remote lock/wipe.
  - Android Enterprise Device Owner provisioning and Google Play private app distribution.
- **Notes**: Requires paid Apple Developer enterprise accounts and dedicated APNs certificates.

---

## 3. Commercial EDR & Managed Antivirus Orchestration
- **Scope**: Centralized policy enforcement, definition distribution, and alert feeds from commercial EDR platforms (CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Bitdefender GravityZone).
- **Architecture**:
  - Webhook ingest pipelines mapping external EDR detection events into the Homelab RMM alerting bus.
  - Automated remediation triggers (e.g., automated device isolation upon high-confidence ransomware detection).

---

## 4. Zero-Knowledge IT Documentation & Credential Vault
- **Scope**: Integrated credential management (IT Glue / Hudu style) directly within the RMM console.
- **Architecture**:
  - Client-side zero-knowledge encrypted vault for server root passwords, switch credentials, WiFi PSKs, and API tokens.
  - Automatic injection of stored credentials into terminal/remote execution sessions without exposing plaintext secrets to technicians.
  - Asset relationship mapping (visual network topology linking physical switch ports to server network interfaces).
