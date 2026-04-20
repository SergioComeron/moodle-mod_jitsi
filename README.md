# Jitsi Meet moodle plugin
This plugin (**mod_jitsi**) allows teachers **create webconference activities** fully integrated **with Jitsi Meet Servers**.

**Jitsi Meet** is an open-source videoconferencing solution that enables you to easily build and implement secure video conferencing. If you don't know about Jitsi Meet you can try it at https://meet.jit.si/. Many commercial web conference services are deployed using Jitsi Meet because it is extremely scalable. More information about Jitsi can be found at https://jitsi.org/

**Out of the box the plugin works** using the public Jitsi Meet Servers (meet.jit.si). **It's free** and that's the best way to test if this plugin satisfies you. Most of the features in this plugin are available using the public server but probably you'll be restricted to 5 minutes per conference (read more below).

Stop reading here... try the plugin now in your test Moodle environment and return later to continue reading.

![jitsi-moodle](doc/pix/jitsi-moodle.png)

Glad to see you here again. These are some of the Jitsi features inside Moodle you was able to try:

* Schedule webconferences in your course
* Attendees report accounting minutes
* Activity completion tracking (conditions related with time attendance)
* Unlimited participants (limits are imposed mainly by bandwidth in your Jitsi servers)
* Moodle profile pictures used as avatar in webconference
* Guest URLs for users in other courses or out of Moodle
* **Private 1-on-1 sessions** — call any coursemate directly from their Moodle profile, with call history and instant notification
* HD Audio Video
* Multiple participants can share their screen simultaneusly
* Tile view
* Break out rooms
* Chat with emojis
* Polls
* Virtual Backgrounds
* YouTube video sharing... pause, rewind and comment videos with all your students (cool)
* Full moderation control in order to silence or kickoff students (token based mode recomended... see below)
* YouTube streaming and **automatic recordings publishing** in your course...  really cool (requires the streaming configuration... see below)
* **Dropbox recording** with automatic or manual link publishing in the recordings tab
* **JaaS (8x8) cloud recordings** automatically captured and available for download, expiring after 24 hours
* and others...

## Permissions

These are the permissions populated by default with the plugin.

![](doc/pix/permissions.png)

Most of them are available at the activity level so a teachers can override some default restrictions.

- **Add a new Jitsi** (mod/jitsi:addinstance): allow to create Jitsi activities.
- **View and copy invite links for guest users** (mod/jitsi:createlink): a teacher could allow students to share the invitation links for guest users.
- **Delete record** (mod/jitsi:deleterecord): allow to mark a recording as deleted. The recording will be set as private in YouTube.  Recordings marked as deleted will be deleted in YouTube with the scheduled task (\mod_jitsi\task\cron_task_delete) or by the admin from a list. You may want to prevent non-editing teachers from deleting recordings.
- **Edit record name** (mod/jitsi:editrecordname): allow to rename the title in a recording. You may want to prevent non-editing teachers from renaming recordings.
- **Hide recordings** (mod/jitsi:hide): allow to hide recordings. You may want to prevent non-editing teachers from hiding recordings.
- **Jitsi Moderation** (mod/jitsi:moderation): determine who is moderator in sessions. When "Token configuration" is set only users with this rol are promoted as Jitsi moderators and this icon ![image-20220309175303324](doc/pix/moderator_icon.png)is displayed with these users. When "Token configuration" is missing some buttons and features like "mute-everyone" or "kick off participant" are hidden to non moderator user but you must be careful because we are not able to hide all moderation options in scenarios without token configuration and experienced users may be able to bypass these restrictions.
- **Record session** (mod/jitsi:record): allow to start recordings. You could create Jitsi Sessions where students could record themselves.
- **View Jitsi** (mod/jitsi:view): set the users who can see and access Jitsi activities in the course view.
- **Access to the attendees reports** (mod/jitsi:viewuseronsession): you may want to allow students from access to attendees reports.

## Streaming configuration

"Out of the box" teachers can stream and record sessions using their own YouTube accounts. They just need to create a "Go Live" streaming in YouTube and copy the "stream key"  in the "Start  live stream" Jitsi interface and later the teacher can publish the link to the recording in his YouTube channel. That's easy but maybe your teachers haven't YouTube accounts or these are not allowed to stream (YouTube must approve this feature).

For a better experience you can configure the plugin to stream and record in corporate YouTube accounts that previously you prepare to work in that way and your teachers just need to click in the "Record and Streaming" switch.

![record-switch](doc/pix/record-switch.png)

With this advance configuration, recordings will be automatically published to students and teacher can edit the title of every recording. One Jitsi activity can have many recordings.

Recordings will remain on "unlisted" mode in the YouTube accounts so nobody will find them searching in YouTube but there is no way to stop your students from posting the url somewhere unwanted. Your teachers should be warned about it.

![recordings](doc/pix/recordings.png)

Teachers can hide or deleted the recordings in the Jitsi activities but only administrators can order to completely delete the recording in YouTube. This is because backup and restore tasks with user data could cause a recording to be available in different courses (or different Moodle environments). Now an scheduled task is configured by default in order to  remove recordings in YouTube. You can set the retention period for this automatic deletion task.

All the magic works using **YouTube v3 APIs** in order to:

- create live streaming sessions on the fly
- set recordings with "embed" properties to display inside Moodle
- delete recordings when they are no longer needed

So you need to configure your own OAuth 2.0 Client IDs in the Google Cloud Platform and connect one or more YouTube accounts. 

Only ONE YouTube account can be set as "in use", and all the streamings in your Moodle will be saved there. 

Why it's allowed to set up several YouTube accounts? YouTube is unpredictable and we don't know if in the future they could establish quotas for "unlisted" videos or if in some moment they decide to restrict your Live Stream permission caused for reputation problems in some teacher recording (a teacher doesn't should stream Rolling Stones concerts). If  this happens, it is a good idea to have some extra accounts set up... just in case.

### Set up your OAuth 2.0 Client ID in Google Cloud

We recommend to use different Google accounts for your OAuth2 client and for your YouTube accounts. If you are just testing you can use the same account.

On few steps... you must

- prepare one or two YouTube accounts with live streaming features enabled (requires register a phone and wait for 24 hours)
- create a new project in Google Console (https://console.cloud.google.com)
- access to "APIs and services" and enable "youtube data api v3"
- create OAuth2 credentials for a "Web application" adding the "Authorized redirect URIs" you will find in the Jitsi configuration plugin in the "OAuth2 id" instructions... (something like this **`https://your_moodle_domain/mod/jitsi/auth.php`** )
- add your YouTube accounts as "Test users" in the "OAuth2 consent screen"
- Copy "Your Client ID" and "Your Client Secret" to Jitsi config in Moodle
- In Moodle add and authorize your Streaming/Recording Accounts (YouTube accounts)
- In Moodle enable "Live stream" and select "Moodle Integrated" as "Live Streaming Method"

At this moment you have set up an EXTERNAL app in "Testing" and now you can try if everything is working as expected.

We have recorded a screencast with the "how to":

https://youtu.be/BFHMsQYDprA

You should consider to get the status of "Publish App"  because in "Testing", authorizations expire in 7 days and the integrated switch to start recordings will disappear. In that case, as an administrator you should re-authorize your  Streaming/Recording YouTube account. You should read about the limitations when "Testing" status. https://support.google.com/cloud/answer/10311615#publishing-status&zippy=%2Ctesting.

**IMPORTANT**: if your institution has **Google Workspace the "User type" in the "OAuth consent screen" can be "INTERNAL"**. In this way, none "Test users" are required to be added and tokens will never expire. **Probably that's the easiest and fastest way to set up this and you don't need to request the "Publish App"**.

**WARNING**: the credentials should never been deleted in the Google console because all the recordings done will be removed in all the YouTube accounts.

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

> Jitsi events (`recordingLinkAvailable`, `recordingStatusChanged`) always fire with the JaaS CDN link (`8x8.vc`), never with the Dropbox URL — so Dropbox links cannot be captured automatically.

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

Jitsi Meet deployment servers can be complex and is beyond the scope of this article but you can review our ansible playbook ([ansible-jitsi-meet](https://github.com/udima-university/ansible-jitsi-meet)).

Alternatively you could explore on buying Jitsi Meet as a service with some provider (ie: https://jaas.8x8.vc) with an important discount for Moodle users (read more below).

Many Governmental Education Institutions deploy their own Jitsi servers to be used by their schools or universities... you could ask them if they provide Jitsi token credentials for this configuration.

Basically the token configuration send your teachers (or roles with the mod/jitsi:moderation enabled) as moderators in a Jitsi session in a secure mode and only they are allowed to mute participants, disable cameras or kick-off participants.

### Required plugin for JWT moderation on self-hosted servers

If you are using a **self-hosted Jitsi server with JWT authentication** (Type 1), you need to install the [**jitsi-token-moderation-plugin**](https://github.com/nvonahsen/jitsi-token-moderation-plugin) on your Jitsi server for moderator roles to work correctly.

Without this plugin, the `moderator` field in the JWT token is ignored by Jitsi and **all users will join as moderators**, regardless of their Moodle role.

This plugin is not required for **8x8 JaaS** (Type 2) or **GCP auto-managed** (Type 3) servers, as moderation is handled natively by those services.

## Recommendations when using public Jitsi servers

As we said "out of the box", the plugin connects with the public servers at meet.jit.si but there many other public Jitsi Meet servers... just make some search with Google or look at the [Community-run instances list](https://jitsi.github.io/handbook/docs/community/community-instances/).  You should test other servers in order to be able change in case of a disruption service or maybe because you find a public server nearest to your users and with less latency.

## Important announcement from meet.jit.si team

The **meet.jit.si** team recently announced that the embed mode, required by our plugin, **is now restricted and they only allow to use it for 5 minutes on every conference**, but this is enough in order to test if this fits to you. You can [read about this announcement here](https://community.jitsi.org/t/important-embedding-meet-jit-si-in-your-web-app-will-no-longer-be-supported-please-use-jaas/). We would like to thank them for providing such a good service for so many years without restrictions, which helped many schools to continue their activities during the Covid pandemic.

**Jitsi is Open Source** and you can **install your own Jitsi Server** or **rent the service from https://jaas.8x8.vc/**, which is **free up to 25 unique monthly active users**. Read more about it [here](https://jaas.8x8.vc/#/pricing). Probably you could find other unofficial sites providing professional hosting for Jitsi, but 8x8 is the company which supports the Jitsi project and buying their services is the best way to support the project in order to guarantee its future.

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

## Disclaimer

This plugin is not related to or partnered with 8x8 Inc. nor with "Jitsi as a Service" (JaaS).
