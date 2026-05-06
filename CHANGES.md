# Changelog
## v5.0.3
# Changed

 * bump phpseclib/phpseclib from 3.0.51 to 3.0.52 in /api (#189)

---

## v5.0.2
# Fixed

 * remove duplicate Content-Type and extra bracket in portal_action unregister curl call

---

## v5.0.1
# Fixed

 * resolve moodle.org prechecker errors in v5.0.0
 * enforce NOT NULL on jitsi_record.deleted for upgraded sites

---

## v5.0.0
# Added

 * feat!: mod_jitsi Account portal, attendance report, recording view tracking, presence and security hardening
 * add session stats to weekly telemetry ping
 * hide native Jitsi recording button on GCP servers (type 3)
 * replace streaming switch with two toggle buttons (Streaming + Record)
 * show recording badge for GCP/Jibri using recordingStatusChanged API
 * make user names in presence dropdown link to Moodle profile
 * add dropdown with connected user names in view.php
 * decouple presence heartbeat to 30s interval, tighten staleness to 90s
 * replace single-counter participant tracking with presence table
 * add inviteemail setting to enable/disable email invitation feature
 * add send invitation by email page
 * add copy button to invitation URLs in activity settings
 * add aria-label to session join button for screen readers
 * reorganize view.php with Session tab (metrics+badges+card+help) and Recordings tab
 * move metrics outside card, center card with avatar/name/button only
 * add user avatar and name to session card in view.php
 * redesign session status block in view.php with card layout
 * redesign logged-in user view on guest join page with card and avatar
 * redesign guest join page with card layout, fix SQL injection in token lookup
 * store enter timestamps in jitsi_usage_daily.times, show in attendance report
 * remove date filter from live sessions — show all-time data, move filter to recordings tab
 * add dates attended column to live sessions table
 * split attendance report into 3 tabs — live sessions, recordings, course overview
 * format heatmap timestamps as MM:SS or H:MM:SS
 * replace click panel with instant hover tooltip for heatmap viewers
 * interactive heatmap — click segment to see which students watched it
 * add tooltips to heatmap bars showing exact counts per bucket
 * track replay counts per segment bucket in heatmap
 * split attendance report into activity/course tabs
 * recording analytics — heatmap and course dashboard
 * include license_key in telemetry ping for migration resilience
 * detect portal deactivation flag and clear local config
 * declare mod_jitsi portal telemetry in privacy provider
 * collect site name and URL at registration; update privacy texts
 * gate recording views tracking and segment bars behind portal registration
 * gate attendance report and usage stats behind portal registration
 * auto-fetch license key on settings page load when pending
 * replace telemetry checkbox with portal registration flow
 * add nudge notice in settings to encourage telemetry opt-in
 * opt-in usage telemetry system (#184)
 * expand telemetry opt-in description to clearly state what is and is not collected
 * opt-in weekly telemetry ping to developer stats endpoint (#184)
 * move AI generation to dropdown above video; show GDPR modal on generate; accordion shows only generated content
 * remove direct link button from GCS recordings to enforce in-Moodle playback tracking
 * GCS recording view tracking with segment progress bar (#183)
 * track and report link clicks for non-embeddable recordings (8x8, external, Jibri)
 * show recording name in teacher view instead of generic numbering
 * track real watched segments with progress bar for students and teachers
 * track video milestones at 25/50/75/100% and show in report
 * add recording views section to attendancereport.php
 * track GCS recording views via play event (#183)
 * fallback to live logstore query when precomputed data not available
 * attendance report per activity (#182)
 * validate start date is before end date in stats form
 * functional improvements to session usage statistics
 * show available date range on stats page
 * precompute daily usage stats and add top-users section
 * lazy-load recordings tab via AJAX
 * extend XMLDB schema lint tests with additional validations (#178)
# Fixed

 * use MutationObserver for recordings tab to support Bootstrap 4 and 5
 * use variable for referrerpolicy to avoid phpcs mangling
 * phpcs style fix in view_table.php
 * add referrerpolicy to YouTube iframes to prevent Error 153
 * correctly enable YouTube embedding after stream ends
 * replace SQL injection in recordun.php with parameterised query
 * phpcs style fixes in portal_action and portal_register
 * replace shared COLLECT_SECRET with per-install license_key auth
 * declare global $PAGE in enter_session()
 * change_field_notnull before UPDATE NULL in ai_transcription_status upgrade
 * make ai_transcription_status nullable in existing installs
 * fix phpcs warnings in provider (line length and comment capitalisation)
 * apply phpcs style fixes to provider and lang file
 * security hardening across plugin and portal
 * extract user fields string to variable to satisfy phpcs line length
 * include all name fields required by fullname() in presence user queries
 * add missing embed NOT NULL fix in jitsi_source_record (#137)
 * remove blank line at start of control structure
 * replace non-standard separators in upgrade comments
 * correct schema inconsistencies reported in issue #137
 * replace emoji icons with Font Awesome fa-rss and fa-circle
 * use event flag to avoid timeout overriding API-set button states
 * initialize stream/record button states on session load
 * move recordbtn and streambtn strings to correct alphabetical positions
 * split long line in recordingStatusChanged handler
 * split long line in presence dropdown JS
 * bump version to register mod_jitsi_get_presence_users web service
 * correct alphabetical order of noconnectedusers string
 * move noconnectedusers string to correct alphabetical position
 * remove camera emoji from guest join page
 * allow guest access to universal.php without requiring Moodle login
 * use $SITE->fullname instead of $CFG->fullname in portal registration
 * move $hasanydata definition before dates query — was always false
 * use get_recordset_sql for dates query to avoid userid key deduplication
 * correct alphabetical order for attendancedates string
 * remove duplicate unit suffix in heatmap tooltip JS
 * format heatmap timestamps with explicit units (min, h) instead of MM:SS
 * restore missing docblock for jitsi_render_heatmap_bar
 * set cursor:default on orange heatmap bar — not clickable
 * bump version to register get_bucket_viewers external service
 * pass strings from PHP to avoid async str loading in heatmap JS
 * wrap long tracker init line to stay within 132 chars
 * show course dashboard nav link regardless of portal registration
 * add confirm dialog and portal notification on unregister
 * handle portal unavailability gracefully in all curl calls
 * alphabetical order for portal privacy strings
 * show contact admin message to non-admins on gated features
 * alphabetical order for portalrequired string
 * remove duplicate heading in portal_register.php
 * simplify portal_register.php form; move session stats link to top
 * phpcs formatting
 * replace embedded form with standalone portal_register.php page
 * capitalize inline comment
 * phpcs comment style
 * phpcs settings.php
 * move mod_jitsi Account section to top of settings page
 * rename to mod_jitsi Account throughout
 * remove duplicate telemetrynudge string
 * update portal section title, description and button spacing
 * phpcs formatting in settings.php and lang string order
 * rename stats subdomain to portal.sergiocomeron.com
 * move telemetrynudge strings to correct alphabetical position
 * rotate telemetry secret key
 * update telemetry endpoint URL in settings description
 * update telemetry endpoint to stats.sergiocomeron.com
 * detect active server via mod_jitsi/server config instead of inuse field
 * remove blank line after opening brace
 * remove stopPropagation from AI handler; re-init inplace_editable after AJAX content load
 * monochrome FA icons in AI dropdown; remove accordion wrapper, show tabs directly
 * register JS strings with mod_jitsi component to match M.util.get_string calls
 * register click handler with only core/ajax+notification; load modal_factory lazily with native confirm fallback
 * use core/modal_factory for GDPR confirmation instead of Bootstrap modal directly
 * use monochrome FA icon in AI dropdown button to match accordion header
 * use flex row for actions area so AI dropdown stays on same line as delete/hide icons
 * use monochrome FA icon for AI Tools accordion header; reduce header size
 * use loadedmetadata to capture duration and render seeded bar immediately on page load
 * declare global $USER in col_id so segment bar loads on page entry
 * seed JS tracker with existing DB segments so bar persists across sessions
 * split long line for name fields query
 * include all name fields in user queries to avoid fullname() debugging notice
 * move recordingaccesslog string before recordingbloquedby alphabetically
 * move recordingaccesslog string to correct alphabetical position
 * detect seeks via timeupdate delta instead of seeking/seeked events to avoid timing race
 * move watchprogress string to correct alphabetical position
 * code style - space after function keyword, watchprogress string ordering
 * track milestones via cumulative playback seconds instead of scrubber position
 * default todate includes end of today instead of yesterday midnight
 * prevent $cm overwrite in transcription parser; log milestone 0 directly from delegation handler
 * use event delegation for recording view tracking to support lazy-loaded recordings
 * correct jitsi_record column name from sourcerecord to source
 * replace sql_like with PHP strpos for GCS filter; use get_recordset_sql for milestone events
 * replace sql_like CASE WHEN with PHP aggregation for recording milestones
 * use existing uniqueusers string instead of missing totaluniqueusers
 * add attendance report to secondary navigation instead of header action
 * move add_header_action before header() output
 * use Moodle header action icon for attendance report link
 * correct 3 bugs in sessionusagestats page
 * phpcs lang string key order
 * phpcs style fixes in lang file
 * phpcs style fixes in sessionusagestats.php
 * phpcs style fixes in aggregate_usage_stats task
 * remove duplicate page heading in sessionusagestats
 * improve sessionusagestats.php performance and remove dead code (#180)
 * resolve moodle.org prechecker warnings
 * bump version to 2026042102 for server compatibility [skip ci]
 * avoid loading all recordings into memory on view.php
 * resolve ESLint warnings in call.js and remaining prechecker leftovers
# Changed

 * Merge branch 'origin/master' into master — keep version 4.6.8 from dev
 * Merge branch 'dev' into master
 * update README to reflect GCP recording support and simplicity
 * update telemetry strings to list new session stats fields
 * add table of contents to README
 * update README with heatmap, course overview and 3-tab attendance report
 * Merge pull request #185 from SergioComeron/feat/recording-analytics
 * merge course dashboard into attendance report, remove standalone page
 * clarify why Dropbox links cannot be captured automatically
 * clarify OAuth Testing mode and test users terminology
 * clarify OAuth test users are Google accounts, not YouTube accounts
 * rewrite streaming/recording section with GCP/Jibri as recommended method
 * clarify telemetry is automatic on registration, no separate toggle
 * fix registration flow description
 * remove basic attendees report from features list
 * clarify GCP only requires a Google Cloud account with billing
 * rewrite intro to focus on server options instead of meet.jit.si
 * restructure README — move mod_jitsi Account to top, fix grammar, remove outdated announcement
 * remove outdated ansible playbook reference
 * remove outdated permissions screenshot and moderator icon reference
 * add missing capabilities to permissions section; fix viewusersonsession typo
 * update README with mod_jitsi Account, attendance report and recording views
 * restore original telemetry secret (rotation not viable in open-source plugin)
 * hardcode telemetry endpoint/key; show URL in setting description instead of editable fields
 * remove old attendees tab, replaced by attendancereport.php
 * Merge master into dev
 * Merge branch 'master' into dev

---

## v4.6.3
# Fixed

 * resolve remaining moodle.org prechecker warnings (#176) (#177)

---

## v4.6.2
# Fixed

 * phpcs style in xmldb_schema_test
 * remove empty string DEFAULT from CHAR NOT NULL columns in install.xml (#175)
# Changed

 * Merge branch 'dev' into master
 * Merge branch 'fix/xmldb-char-not-null-defaults' into dev
 * add schema lint test for CHAR NOT NULL columns with empty default (#175)
 * Merge branch 'master' into dev
 * clean up CHANGES.md — consolidate v4.6.0 and v4.6.1 entries [skip ci]

---

## v4.6.1
### Added

 * AI enable toggle (`aienabled`) — disabled by default for GDPR safety (#174)
 * GDPR data notice tab in recordings view for users with AI generation capabilities (#174)
 * GCP zone selector — dropdown with ~30 zones replacing free-text input (#174)
 * Configurable Vertex AI processing region (`vertexairegion`) with EU default (#174)
 * Privacy metadata declarations for Vertex AI external location and AI-generated fields (#174)
 * Dedicated "AI Features" settings section, separate from Experimental (#174)
 * README documentation for AI features, DPA/GDPR requirements and data retention (#174)

### Fixed

 * Default Vertex AI region and GCP zone changed to `europe-west1` / `europe-west1-b` (#174)
 * GDPR notice tab now appears last and is not auto-activated (#174)
 * AI generation endpoints return error when `aienabled` is off (#174)

---

## v4.6.0
### Added

 * **Jibri pool** — simultaneous GCS recordings via a pool of Jibri VMs with status badges, add/remove VM and pool size control (#163)
 * Per-server GCP machine type selection with specs
 * Jibri status monitor (`jibri-monitor.sh`) for automatic pool management and immediate top-up when a unit goes busy
 * **AI transcription** of GCS recordings with clickable timestamps and chapter headings (#166, #167)
 * Students can view AI-generated content (summary, quiz, transcription) when available
 * **Private sessions** — symmetric 1-on-1 rooms between coursemates, direct access from user profiles (#170)
 * `call.php` — coursemate search, call history and incoming call modal (#170)
 * **Web Push notifications** for incoming private session calls (#171)
 * **Tutoring schedule** — teachers define per-course availability; students see badge and warning outside hours (#171)

### Fixed

 * Match Jibri room names when separator (e.g. dot) is stripped from MP4 filename
 * Install `jibri-monitor.sh` from scratch in image-based VM startup script
 * Disable live streaming in `configOverwrite` using both legacy and current Jitsi keys
 * Hide recording/streaming buttons while Jibri pool entry is provisioning
 * Delete AI quiz course module when its recording is deleted
 * Hide Chrome automation infobar in Jibri recordings (#164)
 * Grant moderator role to both participants in private sessions (#170)
 * Base64url encoding for Web Push keys; `mailto:` VAPID subject (#171)
 * Remove explicit SW scope to support Moodle subdirectory installs (#171)
 * Various Jibri pool lifecycle fixes (stop/start VMs, idle marking, provisioning timeout)

---

## v4.5.0
# Added

 * merge dev into master (AI summary and quiz for GCS recordings, phpseclib 3.0.51)
 * AI summary and quiz generation for GCS recordings (#162)
 * add AI true/false quiz generation for GCS recordings
 * add AI summary generation for GCS recordings via Vertex AI Gemini
 * embed GCS recordings inline with <video> tag
 * add Google Storage service files to vendor
 * GCS integration for Jibri recordings with per-server toggle
 * delete physical Jibri recording file when removed from Moodle
 * enable live streaming on GCP servers with Jibri
 * enable live streaming for GCP servers when Jibri is ready
 * show warning badge on Jibri recordings when server may be offline
 * complete Jibri recording integration for GCP servers
 * add optional Jibri recording support for GCP servers (#145)
# Fixed

 * check quiz cmid existence before building buttons so generate button reappears immediately
 * reset ai_quiz_id if quiz cmid no longer exists so generate button reappears
 * set page=1 on all quiz slots so all questions appear on one page
 * hide AI buttons when content already generated; show error state for failed attempts
 * add quiz_sections row required by Moodle to display quiz questions
 * do not set name=null in quiz_grade_items insert (Moodle 5.x column is NOT NULL)
 * create quiz_grade_items entry and set quizgradeitemid in slots (Moodle 4.2+/5.x)
 * increase Vertex AI curl timeout to 300s for larger videos
 * create course module before quiz_slots so context is available for question_references
 * handle Moodle 5.x question_references and quiz_slots schema changes
 * pass course object (not cm) to course_add_cm_to_section
 * capture curl error details for better debugging
 * detect question_bank_entry vs question_bank_entries table (Moodle 4.x vs 5.x)
 * use gs:// URI for Vertex AI video access (handles large files correctly)
 * revert to v1 endpoint without thinkingConfig (worked for id=18)
 * move thinkingConfig inside generationConfig
 * use v1beta1 endpoint and thinkingBudget=0 for gemini-2.5-flash
 * use gemini-2.0-flash for video analysis (2.5-flash is thinking model with different constraints)
 * pass user language when queuing AI summary task
 * generate AI summary in site default language
 * use HTTPS URL instead of gs:// URI for Vertex AI video access
 * use gemini-2.5-flash model name for Vertex AI
 * use gemini-1.5-flash-001 model for broader Vertex AI availability
 * phpcs style fixes in generate_ai_summary task
 * attach compute service account to Jibri VMs so gsutil uses ADC
 * use Moodle file storage credentials for GCS object deletion
 * hide edit button for Jibri and GCS recordings
 * add Storage to apiclient-services and use namespaced class names
 * preserve GCS enable/disable button when JS updates action cell
 * catch invalid JSON token exception in deleterecordyoutube
 * make Jibri recording warning badge more discrete
 * make Jibri recording warning badge more discrete
 * fix PHP heredoc indentation in PYJITSICFG block
 * show Moodle-integrated streaming switch on GCP servers when Jibri ready
 * use Python to apply Jitsi Meet config changes instead of sed
 * add --disable-blink-features=AutomationControlled to suppress Chrome banner
 * suppress Chrome automation banner in Jibri recordings
 * read Jibri external IP dynamically from GCP metadata at recording time
 * add hiddenDomain at top-level config to hide Jibri from participants
 * hide Jibri recorder participant from Jitsi conference view
 * phpcs style fixes in lib.php and servermanagement.php
 * preserve Add Jibri button when JS updates action cell dynamically
 * phpcs style fixes and remove duplicate lang string
# Changed

 * merge master (phpseclib 3.0.51 bump) into dev; resolve version conflict
 * Merge feature/145-gcp-jibri-recording into dev

---

## v4.4.5
# Fixed

 * extract release notes correctly from CHANGES.md [skip ci]
# Changed

 * Merge pull request #165 from SergioComeron/dependabot/composer/api/phpseclib/phpseclib-3.0.51
 * bump phpseclib/phpseclib from 3.0.50 to 3.0.51 in /api
 * reschedule google/apiclient update to 1:00 UTC (3:00 Madrid) [skip ci]
 * remove notify-rebase-needed workflow [skip ci]
 * add stale workflow to auto-close inactive issues [skip ci]

---

## v4.4.4
# Changed

 * Merge pull request #159 from SergioComeron/chore/update-google-apiclient
 * update google/apiclient from v2.19.0 to v2.19.2

---

## v4.4.3
# Fixed

 * upgrade MySQL image to 8.4 for MOODLE_500_STABLE compatibility
# Changed

 * also run CI on push to dev branch

---

## v4.4.2
# Fixed

 * set max_input_vars=5000 for PHP in CI to meet Moodle requirement

---

## v4.4.1
# Fixed

 * install en_AU.UTF-8 locale and remove MOODLE_501_STABLE from CI matrix

---

## v4.4.0
# Added

 * auto-generate CHANGES.md entry on version bump
# Fixed

 * start JVB before Jicofo to prevent bridge unavailable race condition on boot
 * generate config.php via PHP to avoid heredoc indentation issues in CI
 * create moodledata directories before PHPUnit init in CI
 * add config.php creation step before PHPUnit init in CI
 * avoid template literals in YAML workflow to prevent syntax errors
 * sort interface names alphabetically in privacy provider
 * replace echo with mtrace and translate strings to English in cron_task_delete
# Changed

 * also run on pull requests to master
 * add tests for base64url, istimedout, generatecode, isoriginal, jitsi_supports and isdeletable
 * add MySQL to test matrix alongside PostgreSQL
 * test against Moodle 4.5, 5.0 and 5.1 using matrix strategy
 * add more lifecycle tests for timecreated, timemodified, course and independence
 * add lifecycle tests for add, update and delete instance
 * run checks on push to master instead of PRs
 * run checks only on PRs to master, not on every push

---

## v4.3.1
# Changed
 * CI/CD: replace github-tag-action with native git versioning to avoid tag conflicts
 * CI/CD: strip v prefix from plugin release string for moodle.org compatibility

---

## v4.3.0 (2026040501)
# Fixed
 * External invitations redirect to login for unauthenticated users on Moodle 5.0
 * Existing 8x8.vc recordings with no expiry updated via upgrade step
 * GCP server moderation: moderator added to JWT context.user, fix token_owner_party module and server config
 * GCP startup script re-ran on every reboot causing JWT credential mismatch and all users joining as moderators (issue #143)
 * PHP nowdoc indentation error in GCP startup script
 * Compact recording row: remove duplicate date, use Download label for 8x8 links
 * Dropbox config excluded for 8x8 servers and warning shown in settings
 * Room name not passed to Jitsi API for servers without JWT (meet.jit.si, type=0), causing users to land on Jitsi homepage instead of joining the correct room (issue #138)
# Added
 * **External/Dropbox recording link management** (issue #141): manually add and manage recording links for Dropbox and other external providers
 * Automatic recording link capture via Jitsi `recordingLinkAvailable` event for JaaS paid accounts
 * Force 24h expiry for 8x8.vc recording links when no TTL is provided by JaaS
 * Allow Dropbox recording config on JaaS servers
 * Session usage statistics page with date range filtering, monthly chart, top courses/categories, and CSV/Excel download
 * Chat and polls settings toggle
 * Transcription setting toggle
 * GitHub Actions workflow to auto-update google/apiclient
 * **Send user email to Jitsi** (issue #115): new admin setting (disabled by default) to pass the user's Moodle email to the Jitsi JWT. Declared in privacy provider for GDPR compliance.
# Changed
 * Compact single-line layout for non-embedded recording links; date shown as secondary text next to editable name
 * sessionusagestats link moved to top of settings page
 * Improved sessionusagestats UI and queries (monthly breakdown, top categories)
 * google/apiclient minimum version bumped to ^2.19.0
 * Security: updated phpseclib to 3.0.50 and firebase/php-jwt to v7.0.3
 * Remove require_login from formuniversal.php to allow unauthenticated access
 * Add note to README about jitsi-token-moderation-plugin requirement for JWT moderation on self-hosted servers (issue #133)

---

## v4.2.0 (2025012700)
# Fixed
 * Mobile app error
 * Cache error
# Added
 * Add channellast configuration
 * **GCP Auto-Managed Servers**: Create Jitsi servers in Google Cloud Platform with one click
 * Automatic VM provisioning with Debian 12
 * JWT authentication automatically configured
 * Static IP address management (automatic reservation and reuse)
 * Let's Encrypt SSL certificate provisioning
 * Real-time server status monitoring (Running, Stopped, Provisioning, Error)
 * Start/Stop VM instances from Moodle interface to save costs
 * Detailed provisioning progress modal with status updates
 * DNS configuration helper with copy-to-clipboard functionality
 * Automatic cleanup of failed provisioning attempts
 * **Improved Server Management Interface**:
 * Separated views: table view for listing servers, dedicated form view for add/edit
 * "Add new server" button in table view
 * Cancel button in form view for better navigation
 * Clearer visual organization
# Changed
 * Removed "Deprecated" settings section (watermark link and simultaneous cameras)
 * Server management page now shows only relevant content based on action (list or form)
# Limitations
 * ⚠️ **Recording not yet supported** on GCP auto-managed servers
 * Recording and live streaming buttons are disabled on servers created via GCP
 * For recording functionality, use self-hosted servers (Type 1) or 8x8 servers (Type 2)
 * Recording support planned for future releases (v4.3+)

---

## v4.0 ()
# Fixed
 * Code style corrections
 * Some errors in the exception strings.
# Changed
 * Server management. Stores and manages multiple Jitsi servers.
 * Upgrade google api php to 2.18.4.
 * Config parameters migration. 
# Aded
 * Add Google api compute.
 
---

## v3.5 (20025041400)
# Fixed
 * Escape single quotes in the username before creating the session. #134
# Changed
 * Upgrade google api php to 2.18.3
 * data-toggle deprecation
 * deprecation custom-switch
 * deprecation text-right
# Added
 * Course overview integration

## v3.4.13 (2025028601)
# Fixed
  * tokeninvitacion empty when restore.

---

## v3.4.12 (2025021600)
# Fixed
  * Fixes problem with tokeninvitacion
  
  ---

## v3.4.11 (2024120100)
# Fixed
  * Fixes issue where recordings in shared sessions were not displayed in secondary sessions
# Changed
  * New version Google api 2.18.2
  ---

## v3.4.10 (2024111800)
# Changed
  * Now the attendance report has a button to view reports for a specific day
# Fixed
  * Final deprecation of MESSAGE_DEFAULT_LOGGEDOFF / MESSAGE_DEFAULT_LOGGEDIN
  * Fixed problem with timeopen and timeclose on shared sessions

---

## v3.4.9 (2024100900)
## Added
	*	A button is added to generate the list of participants and attended minutes.
	*	A page with graphs and statistics is added.

---

## v3.4.8 (2024092600)
## Fixed
  * Update mod_form.php to add completion rules with suffix based on branch version #128
## Added
  * Add experimental function to share stream with users outside the moodle. 
  * Cache for getminutes functions
## Changed
  * Replace tabs with buttons in view.
---

## v3.4.5 (2024081300)
## Fixed
  * Fix inplace editable recordname in view_table.php #127

## v3.4.4 (2024050900)
## Fixed
  * Fixed problems new recordings table
   
 ---

## v3.4.3 (2024050900)
## Added
 * Breakoutroom options
## Changed
 * Improved adaptation when expanding the window.
 * New Google Api 2.16.0
 
 ---

## v3.4.2 (2024032100)
## Added
 * Attendance user list now linked with user profile
## Fixed
 * Fixes the problem that caused the search filters to not be respected when turning pages.
 * Fix error writing to the database when creating a new jitsi activity when inviteopcions is activated #126
 * Fix the URL is not valid when jitsi_id is first name + lasta name or alias #125
## Changed
 * New function normalizesessionname for normalize session name.

---

## v3.4.1 (2024022800)
### Added
 * Attendance user list now linked with user profile
 * Attendance info show minutes today
### Fixed
 * Fix problem with end date and start date on shared sessions
 * Show acces button on form universal when user is logged
 * Fix problem with search pagination when search with user or recorder filter
### Changed
 * New explication for external link on configuration page
 * Pagination for attendees table

---

## v3.4 (2023020900)
### Added
 * Add user and recorder filter for search recordings
 * Add latency parameter
 * New capability for view records. 
 * Add startwithaudiomuted and startwithvideomuted parameters
### Fixed
 * Private sessions error.
 * Url validation for username.
### Changed
 * New mode for share sessions on courses. Now if you want to share a session between two or more courses you have to copy the token that you will find on the configuration page and enter it in the course where you want to share it.
 * URL link for guest users now is on configuration page. 
 * New Google Api 2.15.3
 * Refactoring doembedable function

---

## v3.3.9 (2023102300)
### Added 
* Show course on search videos page
* Add max participants assistant in search result
* Add log url in error mail
* New set recordings not for kids #122. (Pay attention to this new parameter. Before this update the videos were marked as suitable for children. If you want to continue marking videos with this restriction, please activate this option. By default it is disabled.)
### Fixed
* Delete mod_jitsi_delete_recordsource service from services #121
* Index.php corrections. (visibility, table, etc...)
* Delete title and description for v4.0
* Fix for cross-version compatibility, the $flags parameter should be explicitly set
* Add boostrap video responsive for videos on search page
* Fix redirect to login page when enter with link.
* Fix problem when edit record title
* Fix error with str_replace. Replace numbers.
### Changed
* User on search page is firstname and lastname. Username is on tooltip
* Update records with no participants on recordings on air page
* Add footer for link pages if is loggedin and delete intro for 4
* Order at mod_jitsi_inplace_editable.
* Better presentation videos recording on search page

---

## v3.3.4 (2023062700)
### Added
* Round Robin: Add rotating shift queue for recordings. Recordings are now distributed among all session recordings if they are in the queue.
* Link to user profile on recording search page
* Mail to admin when doembeable get an error
### Fixed
* Fix problem with log error on doembedable function
* delete mod_jitsi_delete_recordsource service from services (#121)
### Changed
* Google api client to 2.15.0
* Search page for recordings now show thumbnails
* Remove heading for better appearence on moodle 4

## v3.3.3 (2023052400)
### Added
* Add page with search recordings for administrators

---

## v3.3.2 (2023050300)
### Added
* Add page with live recordings for administrators
* Recordings are locked by the user who started them. Preventing others from stopping them.
* IMPORTANT: new Scheduled tasks is enabled by default in order to delete recordings that are marked
  as deleted by teachers and new setting are included to set the retention period. Disable this task
  if you prefer to manually delete YouTube recordings.
* New section on settings for news and updates information.
* Max number of participants of a seession recorded is saved in source_record table.

### Fixed
* Fixed url for recordings to delete
* Fixed error with return create_stream function 

### Changed
* Pagination for the "Recordings available to delete" list.
* New view with tabs for recordings, help and participanting resume
* Recordings that don't have a link to the recording are not displayed on the jitsi page
* Google api 2.13.1 version
* Access buton now is primary button
* new getclientgoogleapi function to get the google api client
* Switch to record not visible for users without capability
* Help tab is always visible

---

## v3.3 (2022122300)
### Fixed
* Fix problem with timecreated when it's first time
* Solves problems with the French language.
### Changed
* Improvement in the counting of participants

---

## v3.3 (2022122300)
### Added
* New status field for better error handling in recordings
### Fixed
* Added timeclose and timeopen to coursemodule info
* Fixed validitytime check
### Changed
* New version Google api v.2.13.0

---

## v3.2.18 (2022111900)
### Added
* Whiteboard added
### Fixed
* Fixed double competibility output on view.php for moodles v>311
* Fixes issue where teachers couldn't assign capabilities
* #110 Plugin v.3.2.17 does not work when jitsi_password is configurated
### Changed
* Disables all invite functions from the app
* Embedable value based on youtube response

---

## v3.2.17 (2022110701)
### Added
* Add gues link information in mod_form and view page
* New capabilities deleterecord and editrecordname
### Fixed
* Fixed exception - Call to undefined method admin_settingpage::hide_if() on versions less than 37
* Fixed problems with special characteres for chrome 

---

## v3.2.16 (2022101700)
### Added
* Shows the author of a recording in the deleted list
* Add to log when user press button record, cam, microphone, share desktop and end button
* Send mails to admins when record fails
* Register participating when user logged enter with guest link
### Fixed 
* Removes warning when restoring with user data and no recordings
* When making a local recording, the session is being recorded banner is not displayed
* Remove unrecorded videos from jitsi (scheduled videos coming soon)
* Fixes issue where students were triggering the switch to record at 5 seconds
* Fixed Dom Focused problem when copy to clipboard on chrome
* Enable recording service with latest versions of jitsi 
### Changed
* Better handling of api requests
* Disable Grant Moderator button
* Disabled record button when teacher enter with guest link
 
---

## v3.2.11 (2022070601)
### Added
* When a teacher marks a video as deleted it should be hidden on youtube. #105
### Fixed 
* The message that the session has not started appears wrong when accessing through invite #102
* Jitsis with a lot of recordings takes a long time to load the access page #104 
* get_objectid_mapping function missing when importing logs #106
### Changed
* Data type mismatch in name field of jitsi_record table RDM #107

---

## v3.2.8 (2022061600)
### Added
* New version api google (v2.12.6)
### Fixed 
* Ilegal character with substr function #100
* Missing language string #81

---

## v3.2.7 (2022060100)
### Added
* New version api google (v2.12.4)
* Validate link invitation with startdate #98
* Added compatibility with 8x8 servers
### Changed
* jitsi_channellastcam deprecated

---

## v3.2.5 (2022041800)
### Changed
* Some strings to strings file
### Fixed
* Fixed 'core_completion\cm_completion_details' not found on moodle v<311 #93
* Fixed session with long names records #94

---

## v3.2.4 (2022041800)
### Changed
* Clean code api php Google. Lower size plugin
* Corrections moodle style guideliness
### Fixed
* Fixed destructure property on chrome

---

## v3.2.3 (2022041300)
### Fixed
* Remove mdl prefix in sql userconnected

---

## v3.2.2 (2022041300)

### Added
* Moodle 4.0 compatibility
### Fixed
* Remove mdl prefix in getminutes function

---

## v3.2.0 ()
### Added
* Multi-account support for recordings.
* Notification when the user enters a private session.
* Allows guest users in a session. These guests can be users with a site account or without an account.
* Show the number of participants in a session and show assistance report.
* Add activity completion with number of minutes in a session.
* Better moderation without tokens.
* Allows to hide the Raise Hand Button.
* Jitsi reactions.
* Participants panel.
### Changed
* The recording button is replaced by a switch
* Default cameras now are 15.
* Watermark link now are deprecated.
* Enable as default the jitsi_invitebuttons, jitsifinishandreturn, jitsi_blurbutton, jitsi_reactions and jitsi_shareyoutube options in config.
* Only users with mod/jitsi:record should be able to launch native drop box recordings.
* Better placed introduction text and help text.
* Minutes to acces now apply only for users with moderation capability.
* Update Google Api Client to Version 2.12.1
### Fixed
* Background options 
* Fixed problem mod_jitsi_external::create_link implementation is missing

---

## v3.1.2 (2021090100)
* Add validity time for link invitations

---

## v3.1.2 (2021072300)
* Fixed problem with Google API and https sites
