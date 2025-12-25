# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is **mod_jitsi**, a Moodle activity module plugin that integrates Jitsi Meet videoconferencing into Moodle. The plugin enables teachers to create webconference activities with features like automatic YouTube recording, attendance tracking, JWT authentication, and GCP-based server provisioning.

**Key Features:**
- Jitsi Meet videoconferencing integration
- YouTube streaming and recording via YouTube Data API v3
- JWT token-based authentication for moderator control
- Google Cloud Platform (GCP) automated server provisioning (BETA)
- Attendance tracking and activity completion based on time
- Guest access links for external participants

## Architecture

### Database Schema

The plugin uses 5 main database tables (defined in `db/install.xml`):

1. **jitsi** - Main activity instances
2. **jitsi_record** - Individual recordings linked to activities
3. **jitsi_record_account** - YouTube account credentials for streaming/recording
4. **jitsi_source_record** - Source video metadata (YouTube links, embed status)
5. **jitsi_servers** - Server configurations (public, private, 8x8, or GCP-managed)

### Server Types

Servers in `jitsi_servers` table support multiple types (field: `type`):
- Type 0: Public servers (e.g., meet.jit.si)
- Type 1: Private servers with JWT authentication
- Type 2: 8x8 JaaS servers
- Type 3: GCP auto-managed servers (BETA)

### Key Files

**Core Logic:**
- `lib.php` - Moodle module API implementation (jitsi_supports, jitsi_add_instance, etc.)
- `locallib.php` - Plugin-specific helper functions
- `view.php` - Main activity view page for students/teachers
- `mod_form.php` - Activity instance configuration form

**Server Management:**
- `servermanagement.php` - Server CRUD operations, GCP server provisioning
- `servermanagement_form.php` - Server configuration forms

**OAuth/Authentication:**
- `auth.php` - YouTube OAuth2 authentication flow
- Uses Google API Client library for YouTube Data API v3

**Recording Management:**
- `adminaccounts.php` - Manage YouTube recording accounts
- `adminrecord.php` - Admin recording management interface
- `recordingmatrix.php` - Recording list views

**Events:**
- `classes/event/` - Contains 13+ event classes for logging (session enter/exit, button presses, etc.)

**Scheduled Tasks:**
- `classes/task/cron_task_delete.php` - Deletes recordings from YouTube based on retention policy
- Runs every 5 minutes (configured in `db/tasks.php`)

### Google Cloud Platform Integration

The GCP feature (BETA) allows automated Jitsi server creation:

**Configuration Flow:**
1. Admin configures GCP settings (project ID, zone, machine type, service account JSON)
2. Admin clicks "Create server in Google Cloud" in `servermanagement.php`
3. Plugin **immediately inserts** a record in `jitsi_servers` with:
   - `provisioningstatus='provisioning'`
   - `provisioningtoken` (64-char random token for callback authentication)
   - `gcpinstancename`, `gcpstaticipname`, `gcpproject`, `gcpzone`
4. Plugin provisions a Compute Engine VM with:
   - Jitsi Meet installation via startup script
   - JWT authentication (auto-generated appid/secret)
   - Static IP reservation (reuses available IPs when possible)
   - Let's Encrypt SSL (if DNS configured)
5. VM sends callback to `servermanagement.php?action=jitsiready` when ready
6. Callback **updates** the existing record in `jitsi_servers`:
   - Changes `provisioningstatus` to 'ready' or 'error'
   - Populates `appid`, `secret`, `domain`
   - Stores error message in `provisioningerror` if failed

**Important:** Server record is created BEFORE VM provisioning starts (as of v4.1.1). This ensures failed VMs are visible in the server list and can be cleaned up.

**GCP Dependencies:**
- Requires Google API Client: `api/vendor/google/apiclient`
- Service account needs roles: Compute Admin, Service Account User

### YouTube Integration

Recording flow:
1. Teacher enables recording in session
2. Plugin creates live broadcast via YouTube Data API v3
3. Recording saved to configured YouTube account (from `jitsi_record_account`)
4. Recording metadata stored in `jitsi_record` and `jitsi_source_record`
5. Videos remain "unlisted" on YouTube
6. Scheduled task deletes recordings after retention period

## Development Commands

### Dependencies Installation

Install Google API Client library (required for YouTube/GCP features):
```bash
cd api/
composer install
```

The composer.json specifies:
- PHP 8.0+
- google/apiclient ^2.18.4
- google/apiclient-services ^0.416.0 (YouTube and Compute services)

### Moodle Plugin Standards

This is a Moodle activity module plugin. Standard Moodle development practices apply:

**Version Management:**
- Update `version.php` when making changes (increment `$plugin->version`)
- Current version format: YYYYMMDDXX (e.g., 2025122000)

**Database Changes:**
- Modify `db/install.xml` for schema changes
- Add upgrade steps in `db/upgrade.php`
- Use Moodle's XMLDB editor: Site administration > Development > XMLDB editor

**Language Strings:**
- Add to `lang/en/jitsi.php` (not committed, managed by AMOS)
- Use `get_string('stringkey', 'jitsi')` in code

**Permissions/Capabilities:**
- Defined in `db/access.php`
- Key capabilities: mod/jitsi:moderation, mod/jitsi:record, mod/jitsi:view

**Moodle Coding Standards:**
- Follow Moodle coding guidelines (https://moodledev.io/general/development/policies/codingstyle)
- Use Moodle APIs for database access ($DB->get_record, etc.)
- Use proper context handling (require_login, require_capability)

### Testing in Moodle

Moodle doesn't use traditional unit tests for activity modules. Testing involves:

**Manual Testing:**
1. Install/upgrade the plugin: Site administration > Notifications
2. Add a Jitsi activity to a course
3. Test videoconferencing features as teacher/student
4. Check recording functionality (requires YouTube OAuth setup)

**Debugging:**
- Enable debugging: Site administration > Development > Debugging
- Check `config.php`: `$CFG->debug = (E_ALL | E_STRICT);`
- Review logs: Site administration > Reports > Logs

## Important Notes

### Security Considerations

**YouTube OAuth Tokens:**
- Stored in `jitsi_record_account.clientaccesstoken` and `clientrefreshtoken`
- Never commit OAuth client secrets to version control
- Tokens auto-refresh when expired (handled in `auth.php`)

**JWT Secrets:**
- Server secrets stored in `jitsi_servers.secret` field
- Used to generate JWT tokens for moderator authentication
- Keep GCP service account JSON files secure

**GCP VM Callbacks:**
- `servermanagement.php?action=jitsiready` accepts NO_MOODLE_COOKIES
- Uses token-based authentication (stored in `jitsi_servers.provisioningtoken`)
- Validates instance name and token before updating server record

### Quirks and Gotchas

**Vendor Directory:**
- The `api/vendor/` directory contains Composer dependencies
- Must run `composer install` in `api/` directory after cloning
- Check `auth.php` line 45 for autoloader existence check

**GCP Server Provisioning (Changed in v4.1.1):**
- Server records are now created IMMEDIATELY when VM creation starts
- `provisioningstatus` field tracks state: 'provisioning', 'ready', or 'error'
- Failed servers appear in server list and can be deleted (cleanup VM + static IP)
- No longer uses `mdl_config_plugins` for temporary state (moved to `jitsi_servers` table)
- Query failed servers: `SELECT * FROM jitsi_servers WHERE provisioningstatus = 'error'`

**8x8 JaaS vs GCP:**
- 8x8 servers use different authentication (privatekey field)
- GCP servers auto-generate appid/secret during provisioning
- Both use JWT but with different key formats

**Recording Deletion:**
- "Deleted" recordings marked with `jitsi_record.deleted = 1`
- Not immediately removed from YouTube
- Scheduled task `cron_task_delete` performs actual deletion
- Can manually delete: Site administration > Plugins > Activity modules > Jitsi > Recordings

**Calendar Integration:**
- Activities create calendar events (timeopen/timeclose)
- Handled in `lib.php` via `jitsi_update_calendar()`

### Integration Points

**Moodle Core Integration:**
- Activity completion: `FEATURE_COMPLETION_HAS_RULES` in `lib.php`
- Calendar: Events created for scheduled sessions
- Backup/Restore: `FEATURE_BACKUP_MOODLE2` supported (see `backup/` directory)
- Mobile app: Mobile templates in `templates/mobile_*.mustache`

**External APIs:**
- YouTube Data API v3 (recording/streaming)
- Google Compute Engine API (server provisioning)
- Jitsi Meet External API (embedded conferencing)

## Common Workflows

### Adding a New Server Type

1. Add new type constant in relevant code
2. Update `jitsi_servers` table if needed (db/upgrade.php)
3. Add server creation logic in `servermanagement.php`
4. Update server selection UI in plugin settings
5. Handle JWT generation if applicable

### Modifying Recording Retention

1. Update scheduled task in `classes/task/cron_task_delete.php`
2. Check configuration in plugin settings
3. Task runs every 5 minutes by default (db/tasks.php)

### Extending Event Logging

1. Create new event class in `classes/event/`
2. Extend `\core\event\base`
3. Trigger event in appropriate location (view.php, lib.php, etc.)
4. Events appear in Moodle's standard logs

## File Structure Notes

- `/api/` - Google API Client Composer dependencies (not part of Moodle core)
- `/backup/` - Moodle backup/restore implementation
- `/classes/` - Namespaced PHP classes (events, tasks, external API)
- `/db/` - Database schema, capabilities, upgrade scripts, scheduled tasks
- `/lang/` - Language strings (managed by Moodle AMOS)
- `/pix/` - Plugin icons and images
- `/templates/` - Mustache templates (mobile app views)
