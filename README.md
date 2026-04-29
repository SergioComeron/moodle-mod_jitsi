# Jitsi Meet Moodle Plugin

**mod_jitsi** integrates Jitsi Meet videoconferencing into Moodle. To use it in production you need a Jitsi server — the plugin supports three options:

- **JaaS (8x8)** — hosted service, free up to 25 monthly active users. The quickest way to get started. More information at https://jaas.8x8.vc/
- **Self-hosted** — your own Jitsi Meet server with full control and JWT authentication.
- **GCP auto-managed** — the plugin provisions and manages a Jitsi server in Google Cloud Platform automatically. A Google Cloud account with billing enabled is all you need — no manual server setup required (BETA).

The public server at meet.jit.si can be used for quick testing but restricts sessions to 5 minutes and is not suitable for production.

More information about Jitsi Meet at https://jitsi.org/

![jitsi-moodle](doc/pix/jitsi-moodle.png)

Features available in the plugin:

* Schedule webconferences in your course
* Activity completion tracking (conditions related with time attendance)
* Unlimited participants (limits are imposed mainly by bandwidth in your Jitsi servers)
* Moodle profile pictures used as avatar in webconference
* Guest URLs for users in other courses or outside Moodle
* **Private 1-on-1 sessions** — call any coursemate directly from their Moodle profile, with call history and instant notification
* HD Audio/Video
* Multiple participants can share their screen simultaneously
* Tile view, break-out rooms, chat, polls, virtual backgrounds
* YouTube video sharing — pause, rewind and comment videos with all your students
* Full moderation control to silence or remove students (token-based mode recommended — see below)
* YouTube streaming and **automatic recordings publishing** in your course (requires streaming configuration — see below)
* **Dropbox recording** with automatic or manual link publishing in the recordings tab
* **JaaS (8x8) cloud recordings** automatically captured and available for download, expiring after 24 hours
* **Attendance report** — detailed per-activity report with time-on-session per student, recording view tracking and access log *(requires mod_jitsi Account)*
* **Recording view tracking** — progress bars showing exactly which parts of each video each student has watched, persisted between sessions *(requires mod_jitsi Account)*
* **Session usage statistics** — site-wide aggregated stats (sessions, participants, recordings) with daily breakdown *(requires mod_jitsi Account)*

## mod_jitsi Account

Some features require registering your Moodle installation at the **mod_jitsi Account** portal ([portal.sergiocomeron.com](https://portal.sergiocomeron.com)). Registration is free and takes less than a minute.

> **A note on open source transparency**: since mod_jitsi is open source, anyone can modify the code and bypass the registration requirement — we know that. Registration is not about locking features for commercial reasons. It exists purely so the developer can see which Moodle versions, server types and features are actually used, and focus development where it matters most.

### Features that require registration

| Feature | Description |
|---------|-------------|
| Attendance report | Detailed per-activity report: time on session, recording views, access log |
| Recording view tracking | Progress bars showing which parts of each video each student has watched |
| Session usage statistics | Site-wide aggregated stats with daily breakdown |

### How to register

1. Go to **Site administration > Plugins > Activity modules > Jitsi**
2. In the **mod_jitsi Account** section at the top, click **Register & enable**
3. Enter your email address and submit the form
4. Check your email and complete registration at the portal
5. Return to the settings page — it will automatically detect your registration and activate the features

### What data is collected

When you register, the following information is stored:
- Your email address
- Your Moodle site name and URL
- An anonymous hash of your site URL (for telemetry)

Once registered, a weekly anonymous ping is automatically sent containing: server type, Moodle version, plugin version, activity count, and which optional features are enabled. No user data, course data or session content is ever sent.

See the [Privacy Policy](https://portal.sergiocomeron.com/privacy.php) for full details.

## Permissions

These are the permissions populated by default with the plugin. Most of them are available at the activity level so teachers can override some default restrictions.

- **Add a new Jitsi** (mod/jitsi:addinstance): allow to create Jitsi activities.
- **View and copy invite links for guest users** (mod/jitsi:createlink): a teacher could allow students to share the invitation links for guest users.
- **Delete record** (mod/jitsi:deleterecord): allow to mark a recording as deleted. The recording will be set as private in YouTube. Recordings marked as deleted will be deleted in YouTube with the scheduled task (\mod_jitsi\task\cron_task_delete) or by the admin from a list. You may want to prevent non-editing teachers from deleting recordings.
- **Edit record name** (mod/jitsi:editrecordname): allow to rename the title in a recording. You may want to prevent non-editing teachers from renaming recordings.
- **Hide recordings** (mod/jitsi:hide): allow to hide recordings. You may want to prevent non-editing teachers from hiding recordings.
- **Jitsi Moderation** (mod/jitsi:moderation): determines who is moderator in sessions. When "Token configuration" is set, only users with this capability are promoted as Jitsi moderators and a moderator indicator is displayed next to their name. When "Token configuration" is missing, some buttons and features like "mute-everyone" or "kick off participant" are hidden to non-moderator users, but experienced users may be able to bypass these restrictions.
- **Record session** (mod/jitsi:record): allow to start recordings. You could create Jitsi Sessions where students could record themselves.
- **View Jitsi** (mod/jitsi:view): set the users who can see and access Jitsi activities in the course view.
- **Access to the attendees reports** (mod/jitsi:viewusersonsession): allows seeing who is currently in a session. You may want to allow students access to attendees reports.
- **View recordings** (mod/jitsi:viewrecords): allows access to the Recordings tab. Disable this to hide recordings from specific roles.
- **View external recording links** (mod/jitsi:viewexternallink): allows viewing externally-linked recordings (Dropbox, 8x8, manual links).
- **Generate AI summary** (mod/jitsi:generateaisummary): allows generating AI-powered summaries for GCS recordings. Requires AI features to be enabled.
- **Generate AI quiz** (mod/jitsi:generateaiquiz): allows generating AI-powered quizzes from GCS recordings. Requires AI features to be enabled.
- **Generate AI transcription** (mod/jitsi:generateaitranscription): allows generating AI transcriptions for GCS recordings. Requires AI features to be enabled.
- **Access to the attendance report** (mod/jitsi:viewattendance): allows teachers to access the detailed attendance report with recording view tracking. Requires mod_jitsi Account.

## Recording configuration

The plugin supports several recording methods. Choose the one that best fits your infrastructure.

### GCP auto-managed with Jibri (recommended)

The most integrated recording option. When using a **GCP auto-managed server** (Type 3), the plugin automatically provisions a dedicated **Jibri** recording VM alongside the Jitsi server. Recordings are saved directly to **Google Cloud Storage (GCS)** and published automatically in the activity's Recordings tab — no YouTube account or manual intervention required.

This method also unlocks **AI features** (summary, quiz, transcription) powered by Google Vertex AI (Gemini), since recordings are stored in GCS.

To use this method, set up a GCP auto-managed server (see the GCP section below). Recording and AI features are enabled automatically once Jibri is provisioned.

### YouTube Moodle-integrated

Configure the plugin to record sessions to corporate YouTube accounts. Teachers just need to click the **Record and Streaming** switch — recordings are automatically published as unlisted videos and embedded in the activity's Recordings tab. One Jitsi activity can have many recordings.

Recordings are stored as unlisted videos in YouTube. Teachers can hide or delete recordings from the activity; only administrators can permanently delete them from YouTube. A scheduled task handles automatic deletion based on a configurable retention period.

This method uses **YouTube v3 APIs** to:
- create live streaming sessions on the fly
- embed recordings inside Moodle
- delete recordings when no longer needed

**Note**: recordings remain unlisted on YouTube but there is no way to prevent students from sharing the URL externally. Teachers should be aware of this.

Multiple YouTube accounts can be configured — only one is active at a time, but having extras available is useful if YouTube restricts a specific account.

#### Set up your OAuth 2.0 Client ID in Google Cloud

1. Prepare one or more YouTube accounts with live streaming enabled (requires phone verification and a 24-hour wait)
2. Create a project in [Google Cloud Console](https://console.cloud.google.com) and enable the **YouTube Data API v3**
3. Create OAuth 2.0 credentials for a **Web application**, adding the redirect URI shown in the Jitsi plugin settings (e.g. `https://your_moodle_domain/mod/jitsi/auth.php`)
4. In the OAuth consent screen, add the Google accounts associated with your YouTube channels as **authorised users**. Google calls these "Test users" — despite the name, this is the correct setup for production use when you only need a limited set of known accounts. You do not need to publish the app publicly.
5. Copy the **Client ID** and **Client Secret** to the Jitsi plugin settings in Moodle
6. In Moodle, add and authorise your Streaming/Recording Accounts
7. Enable **Live stream** and select **Moodle Integrated** as the Live Streaming Method

**Note on app status**: Google's "Testing" status means only the accounts you explicitly added can authorise the app, and tokens expire every 7 days — requiring periodic re-authorisation in Moodle. To avoid token expiry, either publish the app (Google may require verification depending on scopes) or use the Google Workspace internal mode described below.

**Google Workspace users**: set the "User type" in the OAuth consent screen to **INTERNAL** — no authorised users need to be added and tokens never expire. This is the recommended setup if your institution uses Google Workspace.

**Important**: never delete the OAuth credentials in Google Cloud — doing so will remove all recordings from the associated YouTube accounts.

### YouTube manual (teacher's own account)

Teachers can also stream using their own personal YouTube accounts by creating a "Go Live" stream and copying the stream key into the Jitsi interface. The recording link must then be published manually. This requires no plugin configuration but each teacher needs their own YouTube account with live streaming enabled.

## Dropbox and external recording links

In addition to YouTube streaming, the plugin supports publishing recordings stored in **Dropbox** or retrieved directly from the **JaaS (8x8) cloud recording** system.

### How recording links are captured

When a session ends, the plugin listens to two Jitsi events:

- **`recordingLinkAvailable`** — fired by Jitsi when a recording link is ready (Dropbox or other).
- **`recordingStatusChanged`** — fired when recording stops, may include a direct URL.

Links are saved automatically in the activity's **Recordings** tab. Duplicate links for the same session are ignored.

### JaaS (8x8) cloud recordings

When using a JaaS server with cloud recording enabled, recordings appear automatically in the Recordings tab with a **Download** button. These links are hosted on 8x8's CDN and expire after **24 hours** (or according to your JaaS plan). Once expired, they are automatically hidden from the tab — no manual cleanup is needed.

### Dropbox recordings

If Dropbox is configured in the plugin settings (**App Key** and **Redirect URI**), teachers can record sessions directly to their Dropbox account. Once the recording is saved to Dropbox, the teacher must **manually publish the link** to students:

- After the session, the teacher gets the share link from their Dropbox account.
- In the activity's Recordings tab, the teacher pastes the link using the **"Add recording link"** form.

> When using Dropbox recording, Jitsi fires `recordingStatusChanged` when the recording stops, but the Dropbox URL is not included — it is generated asynchronously by Dropbox after the upload completes. This is why Dropbox links cannot be captured automatically and must be published manually.

#### Dropbox configuration

Navigate to **Site administration > Plugins > Activity modules > Jitsi** and fill in the **Dropbox recording configuration** section:

- **Dropbox App Key**: the App Key from your Dropbox app (Dropbox Developer Console → your app → Settings tab).
- **Dropbox Redirect URI**: the OAuth2 redirect URI registered in your Dropbox app. Must match exactly what you set in the Dropbox App Console — usually `https://your-jitsi-domain/static/oauth.html`.

You need to create a Dropbox app at the [Dropbox App Console](https://www.dropbox.com/developers/apps).

#### Embedding Dropbox videos

When adding a Dropbox link manually, teachers can choose to **embed the video** directly in the Recordings tab by checking the "Embed video (Dropbox)" option. The plugin transforms the Dropbox share URL to a direct streaming URL (`?raw=1`) and renders it with an HTML5 `<video>` player. A fallback "Open recording" link is always shown below the player.

> **Note**: Dropbox has a monthly bandwidth limit on free accounts. If many students view the embedded video simultaneously, Dropbox may temporarily block direct access.

### Managing recording links

Teachers with the **Record session** (`mod/jitsi:record`) capability can:

- **Add** external recording links manually via the form at the bottom of the Recordings tab.
- **Edit** any manually-added link (URL, name, embed option) using the edit icon next to the recording.
- **Hide/show** recordings from students.
- **Delete** recordings from the activity (external links are only removed from Moodle; the actual file in Dropbox or 8x8 is not affected).

The Recordings tab is always visible to teachers even when no recordings exist yet, so they can add links at any time.

### Recording link expiry

The `timeexpires` field in the database controls when a recording link is automatically hidden:

| Source | Expiry |
|--------|--------|
| JaaS (8x8.vc) | 24 hours from creation (or TTL from event if available) |
| Dropbox | Never (permanent) |
| YouTube | Never (managed via YouTube API) |
| Manual entry | Never (permanent) |

Expired recordings are hidden from the tab but not deleted from the database. They can be deleted manually from the Recordings tab.

## Private Sessions

When **Private sessions** is enabled in the plugin settings, any user can start a private 1-on-1 video call with a coursemate — without needing a scheduled Jitsi activity.

### How it works

- **Own profile page**: a "Call someone" link appears that opens the private session hub (`call.php`), where you can search for coursemates and view your call history.
- **Other user's profile page**: a "Start private session" link appears, but only if you share at least one course with that user. Clicking it launches a private session immediately.
- **Call history**: the hub shows your most recent call per contact, ordered by time, with avatars and names. Clicking any entry re-opens the session with that person.
- **Instant notification**: when you enter a private session, Moodle sends a popup notification to the other participant so they know to join.

### Room naming

Private rooms always use the same symmetric name regardless of who initiates: `{siteshortname}-priv-{minUserId}-{maxUserId}`. This means if user A calls user B and later user B calls user A, they both land in the same room.

### Restrictions

- Both participants are automatically moderators.
- Recording and live streaming are **always disabled** in private sessions — there is no course activity associated with the call.
- The search only returns users who share at least one course with you (no calling strangers).

### Enabling private sessions

Go to **Site administration > Plugins > Activity modules > Jitsi** and enable the **Private sessions** setting.

## Token based mode

If you decide to deploy this plugin in production you may would like to install your private Jitsi Meet server with "Token based" mode. This configuration will give you extra control with the moderation privileges.

Jitsi Meet deployment servers can be complex and is beyond the scope of this article. You could explore buying Jitsi Meet as a service with some provider (ie: https://jaas.8x8.vc) with an important discount for Moodle users (read more below).

Many Governmental Education Institutions deploy their own Jitsi servers to be used by their schools or universities... you could ask them if they provide Jitsi token credentials for this configuration.

The token configuration sends users with the `mod/jitsi:moderation` capability as moderators in a Jitsi session — only they are allowed to mute participants, disable cameras or remove participants.

### Required plugin for JWT moderation on self-hosted servers

If you are using a **self-hosted Jitsi server with JWT authentication** (Type 1), you need to install the [**jitsi-token-moderation-plugin**](https://github.com/nvonahsen/jitsi-token-moderation-plugin) on your Jitsi server for moderator roles to work correctly.

Without this plugin, the `moderator` field in the JWT token is ignored by Jitsi and **all users will join as moderators**, regardless of their Moodle role.

This plugin is not required for **8x8 JaaS** (Type 2) or **GCP auto-managed** (Type 3) servers, as moderation is handled natively by those services.

## Recommendations when using public Jitsi servers

The plugin connects by default with the public server at meet.jit.si. There are many other public Jitsi Meet servers — search Google or look at the [Community-run instances list](https://jitsi.github.io/handbook/docs/community/community-instances/). Testing alternative servers is a good idea in case of service disruption or to find one closer to your users.

Bear in mind that meet.jit.si restricts embed mode to **5 minutes per conference**. For production use, you need either a **JaaS (8x8) account** (free up to 25 monthly active users — [pricing](https://jaas.8x8.vc/#/pricing)), a **self-hosted Jitsi server**, or a **GCP auto-managed server** provisioned by this plugin. 8x8 is the company behind the Jitsi project and using their service is the best way to support its future.

## Using a Jitsi as a Service Account

You need to create a [Jitsi as a Service Account](https://jaas.8x8.vc), if you don't already have one.

Once you do, go to the [API Keys](https://jaas.8x8.vc/#/apikeys) page and create a new key pair, name it something meaningful.
Download the private key and store it somewhere safe.

Open the Moodle Jitsi plugin settings and change the values as follows.

- **Domain**: `8x8.vc`
- **Server type**: pick `8x8 Servers`
- **App_ID**: copy it from the JaaS Console API Keys page, i.e. `vpaas-magic-cookie-xxxxx`
- **Api Key ID**: copy it from the keys table in the same page, it should be something like `vpaas-magic-cookie-xxxxx/somehex`
- **Private key**: the contents of the private key you just downloaded from JaaS Console

Save the changes and you're ready to use Jitsi as a Service in your Moodle courses.

## Google Cloud Platform (GCP) Integration - BETA

This plugin includes **experimental support** for automatically creating and managing Jitsi Meet servers in Google Cloud Platform. This feature allows you to:

- Create Jitsi servers on-demand directly from Moodle
- Automatically configure Jitsi Meet with JWT authentication
- Manage server lifecycle (start/stop instances)
- Use static IP addresses for consistent DNS configuration
- Automatic Let's Encrypt SSL certificate provisioning

**⚠️ This feature is in BETA testing**. Use it in production environments with caution.

### Current Limitations

**Recording not yet supported**: GCP auto-managed servers do not currently support recording or live streaming functionality. For recording features, please use:
- Self-hosted servers (Type 1) with Jibri installed
- 8x8 JaaS servers (Type 2)

Recording support for GCP auto-managed servers is planned for future releases.

### Prerequisites

Before using the GCP integration, you need:

1. **Google Cloud Platform Account**
   - Active GCP project with billing enabled
   - Compute Engine API enabled

2. **Service Account with Permissions**
   - Create a service account in your GCP project
   - Grant the following roles:
     - `Compute Admin` (roles/compute.admin) - to create and manage instances
     - `Service Account User` (roles/iam.serviceAccountUser) - to attach service accounts to instances
   - Download the JSON key file for this service account

3. **Domain Name** (Required)
   - A fully qualified domain name (FQDN) that you can point to the VM's IP address
   - Required for JWT authentication configuration and Let's Encrypt SSL certificates
   - Example: `jitsi.example.com`

### Configuration Steps

#### 1. Enable Compute Engine API

In your Google Cloud Console:
1. Go to **APIs & Services > Library**
2. Search for "Compute Engine API"
3. Click "Enable"

#### 2. Create a Service Account

1. Go to **IAM & Admin > Service Accounts**
2. Click "Create Service Account"
3. Name it (e.g., "jitsi-moodle-manager")
4. Grant roles:
   - `Compute Admin`
   - `Service Account User`
5. Click "Create Key" and download the JSON file
6. **Keep this file secure** - it provides full access to your Compute Engine resources

#### 3. Configure the Plugin in Moodle

Navigate to **Site administration > Plugins > Activity modules > Jitsi > Google Cloud (GCP) - BETA** section:

1. **Project ID**: Your GCP project ID (e.g., `my-project-12345`)
   - Find it in GCP Console dashboard

2. **Zone**: The Compute Engine zone where VMs will be created (e.g., `europe-west1-b`)
   - Choose a zone close to your users for better performance
   - List of zones: https://cloud.google.com/compute/docs/regions-zones

3. **Machine Type**: VM size (default: `e2-standard-4`)
   - `e2-standard-2`: 2 vCPUs, 8GB RAM - suitable for small meetings (<20 participants)
   - `e2-standard-4`: 4 vCPUs, 16GB RAM - recommended for medium meetings (<50 participants)
   - `e2-standard-8`: 8 vCPUs, 32GB RAM - for large meetings (>50 participants)
   - Pricing: https://cloud.google.com/compute/vm-instance-pricing

4. **Base Image**: OS image for the VM (default: `projects/debian-cloud/global/images/family/debian-12`)
   - The default Debian 12 image is recommended
   - Do not change unless you have a custom image with Jitsi pre-installed

5. **Network**: VPC network (default: `global/networks/default`)
   - Use `global/networks/default` unless you have a custom VPC setup
   - Format: `global/networks/<network-name>` or `projects/<project>/global/networks/<network-name>`

6. **Hostname (FQDN)** - **Required**: The fully qualified domain name for your Jitsi server (e.g., `jitsi.example.com`)
   - **Mandatory**: Required for JWT authentication and SSL configuration
   - You must configure DNS to point this domain to the VM's IP address (shown during creation)
   - The plugin will reserve a static IP address for consistency
   - Also create an A record for `auth.<your-hostname>` pointing to the same IP

7. **Let's Encrypt Email** - **Required**: Email address for Let's Encrypt notifications (e.g., `admin@example.com`)
   - Used for SSL certificate requests and expiration notices

8. **Service Account JSON**: Upload the JSON key file you downloaded in step 2

#### 4. Configure Firewall Rules (Automatic)

The plugin will automatically create a firewall rule named `mod-jitsi-allow-web` with the following configuration:

- **Ports**:
  - TCP 80 (HTTP)
  - TCP 443 (HTTPS)
  - UDP 10000 (Jitsi video bridge)
- **Target**: Instances tagged with `mod-jitsi-web`
- **Source**: `0.0.0.0/0` (all internet traffic)

If the plugin lacks permissions to create firewall rules automatically, you'll need to create this rule manually in the GCP Console.

### Creating a Jitsi Server

Once configuration is complete:

1. Go to **Site administration > Plugins > Activity modules > Jitsi > Server management**
2. Click the **"Create server in Google Cloud"** button
3. The plugin will:
   - Reserve or reuse an available static IP address
   - Create a Compute Engine VM with the specified configuration
   - Install and configure Jitsi Meet automatically
   - Configure JWT authentication with auto-generated credentials
   - Wait for DNS propagation and obtain a Let's Encrypt SSL certificate
   - Register the server in Moodle's server list

4. **Monitor the creation process**:
   - A modal will show the progress
   - Creation typically takes 5-10 minutes
   - The startup script will wait up to 15 minutes for DNS propagation

5. **Configure DNS** (Required):
   - The modal will display the static IP address assigned to your VM
   - **Immediately** create the following A records in your DNS provider:
     - `jitsi.example.com` → Static IP address (main hostname)
     - `auth.jitsi.example.com` → Same static IP address (required for JWT)
   - DNS settings:
     - Type: A
     - TTL: 300 (recommended for faster propagation)
   - The VM will wait for DNS to propagate before completing installation

### How It Works

#### The Startup Script

The plugin uses a cloud-init/bash startup script that runs on first boot:

1. **DNS Waiting Phase** (0-15 minutes):
   - Checks if the configured hostname resolves to the VM's public IP
   - Waits up to 15 minutes for DNS propagation
   - **Important**: Without proper DNS, JWT authentication may not work correctly

2. **Jitsi Installation**:
   - Installs Jitsi Meet from official repositories
   - Configures Prosody (XMPP server) for JWT authentication using the hostname
   - Generates random App ID and Secret for JWT

3. **SSL Certificate**:
   - If DNS is properly configured → requests Let's Encrypt certificate
   - If DNS is not ready → installs self-signed certificate (browsers will show warnings)

4. **JWT Configuration**:
   - Configures Jicofo and Prosody for token-based authentication
   - Only users with valid JWT tokens (generated by Moodle) can moderate sessions
   - Provides enhanced security and moderation control

5. **Callback to Moodle**:
   - Once complete, the VM notifies Moodle with the JWT credentials
   - Moodle automatically registers the server and makes it available for use

#### Static IP Address Management

- The plugin automatically reserves a static IP address for each server
- If you delete a server, the IP is released back to the pool
- When creating new servers, the plugin reuses available static IPs to avoid quota limits
- Each static IP incurs a small cost (~$0.01/hour or ~$7/month when in use)

### Managing Servers

Once created, servers appear in the **Server Management** interface with the following options:

- **Edit**: Modify server name and configuration
- **Start/Stop**: Control the VM lifecycle to save costs
  - Stopped VMs only incur storage costs (much cheaper than running VMs)
  - Starting a stopped VM takes ~1-2 minutes
- **Delete**: Permanently remove the server
  - **Warning**: This deletes the VM and releases the static IP
  - Existing sessions using this server will no longer work

### Cost Considerations

Running Jitsi servers in GCP incurs costs:

1. **Compute Instance** (when running):
   - e2-standard-2: ~$49/month (8760 hours)
   - e2-standard-4: ~$98/month
   - e2-standard-8: ~$196/month
   - Use "Stop" feature when not in use to save costs

2. **Static IP Address**:
   - ~$7/month per IP when attached to a running instance
   - ~$9/month per IP when reserved but not in use
   - Tip: Delete unused IPs to avoid charges

3. **Storage**:
   - ~$0.17/month per 20GB SSD (default boot disk)

4. **Network Egress** (outbound traffic from VM):
   - First 1GB/month: Free
   - After 1GB: ~$0.12/GB (varies by region)
   - **When this matters**:
     - 1-to-1 calls: Minimal (peer-to-peer, doesn't use server bandwidth)
     - 3+ participants: High (Jitsi Videobridge retransmits all video/audio streams)
   - **Estimation**: A 1-hour conference with 10 participants in HD can use 5-10GB of egress
   - **This can be the largest cost** for institutions with frequent large meetings
   - Consider monitoring actual usage before scaling to many users

**Cost Saving Tips**:
- Stop VMs when not in active use (e.g., outside business hours)
- Delete servers you no longer need
- Consider using Preemptible VMs for testing (not recommended for production)

### Security Considerations

1. **JWT Authentication**: All auto-created servers use JWT authentication by default
   - Only Moodle can generate valid tokens
   - Users cannot join or moderate without Moodle-issued credentials

2. **Service Account Security**:
   - Keep the JSON key file secure
   - Never commit it to version control
   - Rotate keys periodically
   - Use least-privilege: only grant necessary roles

3. **Network Security**:
   - The firewall rule opens ports to the internet (required for Jitsi)
   - Jitsi itself handles authentication via JWT
   - Consider using Cloud Armor for DDoS protection in production

4. **SSL Certificates**:
   - Always use Let's Encrypt certificates in production
   - Self-signed certificates will show browser warnings to users
   - Certificates auto-renew via certbot

## AI Features for GCS Recordings

When GCS (Google Cloud Storage) upload is enabled for a Jibri recording server, recordings stored at `https://storage.googleapis.com/…` can be processed by **Google Vertex AI (Gemini 2.5 Flash)** to generate:

- **AI Summary** — a 3-5 paragraph educational summary of the recording
- **AI Quiz** — a set of true/false questions auto-created as a Moodle quiz
- **AI Transcription** — a timestamped transcript with chapter headings

### Enabling AI features

Navigate to **Site administration > Plugins > Activity modules > Jitsi > AI Features** and:

1. Check **Enable AI features** (`aienabled`). This is **disabled by default**.
2. Select the **Vertex AI region** where recordings will be processed (default: `europe-west1`).

Teachers and editing teachers with the corresponding capabilities (`generateaisummary`, `generateaiquiz`, `generateaitranscription`) will see generation buttons in the Recordings tab for GCS recordings.

### GDPR / Data Protection considerations

> ⚠️ **Important**: enabling AI features sends video recordings to Google Vertex AI for processing. Video recordings contain personal data (image and voice of participants).

Before enabling AI features, your institution **must**:

1. **Sign a Data Processing Agreement (DPA)** with Google Cloud.  
   Google offers a standard DPA as part of the [Google Cloud Terms of Service](https://cloud.google.com/terms/data-processing-addendum). Accepting it in the Cloud Console satisfies GDPR Art. 28 requirements for a processor agreement.

2. **Configure the processing region** to match your data residency requirements.  
   Use `europe-west1` (Belgium) or another EU region to keep data within the European Economic Area. Avoid `us-central1` or other non-EU regions if your institution is subject to GDPR.

3. **Inform participants** that recordings may be processed by an AI service for summarisation and transcription. Update your privacy notice accordingly.

4. **Review retention**: AI-generated content (summaries, transcriptions, quiz questions) is stored in the Moodle database. Apply your standard data retention policy.

The plugin's `privacy/provider.php` declares:
- The external data location `vertexai` (Google Vertex AI) and the nature of data sent (video recordings).
- The `jitsi_source_record` database table storing AI-generated outputs.

For a full list of data exported and deleted per user, see the Moodle Privacy API integration in `classes/privacy/provider.php`.

## Attendance Report

The attendance report (`mod/jitsi:viewattendance`) provides teachers with a detailed breakdown of student participation in each Jitsi activity. It is accessible from the activity's secondary navigation.

### What the report shows

- **Time on session** — total minutes each student spent in live sessions, aggregated across all sessions in the activity
- **Recording views** — for GCS and Dropbox recordings: a visual progress bar showing exactly which segments of each recording the student has watched and the percentage watched
- **Recording access log** — for non-embeddable recordings (8x8, external links): a log of when each student clicked to open the recording

### Requirements

- The `mod/jitsi:viewattendance` capability (granted to teachers by default)
- A registered mod_jitsi Account

## Session Usage Statistics

The session usage statistics page (`/mod/jitsi/sessionusagestats.php`) provides site administrators with an aggregated view of Jitsi usage across the entire Moodle site.

Stats are pre-computed nightly by the `aggregate_usage_stats` scheduled task and include daily breakdowns of sessions, unique participants, total minutes and recordings. A live report can also be generated directly from the activity log.

Requires a registered mod_jitsi Account.

## Disclaimer

This plugin is not related to or partnered with 8x8 Inc. nor with "Jitsi as a Service" (JaaS).
