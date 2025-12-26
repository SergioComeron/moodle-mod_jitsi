# Changelog

All notable changes to the Jitsi Meet Moodle plugin will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.2.0] - 2025-01-XX - GCP Auto-Managed Servers (BETA)

### Added
- **GCP Auto-Managed Servers**: Create Jitsi servers in Google Cloud Platform with one click
  - Automatic VM provisioning with Debian 12
  - JWT authentication automatically configured
  - Static IP address management (automatic reservation and reuse)
  - Let's Encrypt SSL certificate provisioning
  - Real-time server status monitoring (Running, Stopped, Provisioning, Error)
  - Start/Stop VM instances from Moodle interface to save costs
  - Detailed provisioning progress modal with status updates
  - DNS configuration helper with copy-to-clipboard functionality
  - Automatic cleanup of failed provisioning attempts

- **Improved Server Management Interface**:
  - Separated views: table view for listing servers, dedicated form view for add/edit
  - "Add new server" button in table view
  - Cancel button in form view for better navigation
  - Clearer visual organization

### Changed
- Removed "Deprecated" settings section (watermark link and simultaneous cameras)
- Server management page now shows only relevant content based on action (list or form)

### Limitations
- ⚠️ **Recording not yet supported** on GCP auto-managed servers
  - Recording and live streaming buttons are disabled on servers created via GCP
  - For recording functionality, use self-hosted servers (Type 1) or 8x8 servers (Type 2)
  - Recording support planned for future releases (v4.3+)

### Technical Details
- GCP servers are identified as type 3 in `jitsi_servers` table
- New database fields for GCP provisioning:
  - `provisioningstatus` (provisioning, ready, error)
  - `provisioningtoken` (64-char token for secure callbacks)
  - `provisioningerror` (error message storage)
  - `gcpinstancename`, `gcpstaticipname`, `gcpproject`, `gcpzone`
- Servers are created in database immediately when VM creation starts
- Startup script handles DNS waiting, Jitsi installation, and Moodle callback
- Recording functionality completely disabled for type 3 servers:
  - Toolbar buttons (`recording`, `livestreaming`) hidden in Jitsi interface
  - Integrated "Stream & Record" switch not displayed when `streamingoption == 1`
  - `liveStreamingEnabled: false` forced in Jitsi configuration

### Security
- JWT credentials (appid/secret) automatically generated during provisioning
- Token-based authentication for VM callbacks
- No manual credential entry required for GCP servers

### Requirements
- Google Cloud Platform account with billing enabled
- Compute Engine API enabled
- Service Account with Compute Admin and Service Account User roles
- **Domain name (FQDN)**: Required for JWT authentication and SSL certificates
- Google API Client PHP library (already included in `api/vendor/` directory)

### Cost Considerations
- Running e2-standard-4 VM: ~$98/month
- Static IP: ~$7/month (when attached to running instance)
- Stop VMs when not in use to reduce costs significantly

### Coming Soon
- v4.3: Jibri pool support for recordings with manual scaling
- v4.4: Automatic Jibri pool scaling

---

## [4.1.x] - Previous Releases

Previous changes not documented in this changelog. See git history for details.
