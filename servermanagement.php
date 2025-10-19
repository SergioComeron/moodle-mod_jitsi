<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Settings for Jitsi instances
 * @package   mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_login();
require_capability('moodle/site:config', context_system::instance());

global $DB, $OUTPUT, $PAGE;

$PAGE->set_url('/mod/jitsi/servermanagement.php');

$PAGE->set_context(context_system::instance());
$PAGE->set_url('/mod/jitsi/servermanagement.php');
$PAGE->set_title(get_string('servermanagement', 'mod_jitsi'));


require_once($CFG->dirroot . '/mod/jitsi/servermanagement_form.php');
// Try to load Google API PHP Client autoloader from common locations.
$gcpautoloaders = [
    $CFG->dirroot . '/mod/jitsi/api/vendor/autoload.php', // user-provided path
    $CFG->dirroot . '/mod/jitsi/vendor/autoload.php',     // plugin-level vendor
    $CFG->dirroot . '/vendor/autoload.php',               // site-level vendor
];
foreach ($gcpautoloaders as $autoload) {
    if (file_exists($autoload)) {
        require_once($autoload);
        break;
    }
}


$action  = optional_param('action', '', PARAM_ALPHA);
$id      = optional_param('id', 0, PARAM_INT);
$confirm = optional_param('confirm', 0, PARAM_BOOL);

// --- Minimal GCP helpers to create a bare VM (no Jitsi yet) ---

if (!function_exists('mod_jitsi_gcp_ensure_firewall')) {
    /**
     * Ensure there is a permissive firewall rule on the VM's network for web + media ports.
     * Returns one of: 'created' | 'exists' | 'noperms' | 'error:<msg>'.
     */
    function mod_jitsi_gcp_ensure_firewall(\Google\Service\Compute $compute, string $project, string $network): string {
        $rulename = 'mod-jitsi-allow-web';
        // Build full selfLink for network if we received a short path like 'global/networks/default'.
        if (strpos($network, 'projects/') !== 0) {
            $network = sprintf('projects/%s/%s', $project, ltrim($network, '/'));
        }
        // Try a cheap GET first; if we lack permission it will throw.
        try {
            $compute->firewalls->get($project, $rulename);
            return 'exists';
        } catch (\Exception $e) {
            // Proceed to attempt create; we'll classify errors below.
        }
        $fw = new \Google\Service\Compute\Firewall([
            'name' => $rulename,
            'description' => 'Allow HTTP/HTTPS and Jitsi media (UDP/10000) for Moodle Jitsi plugin',
            'direction' => 'INGRESS',
            'priority' => 1000,
            'network' => $network,
            'sourceRanges' => ['0.0.0.0/0'],
            'targetTags' => ['mod-jitsi-web'],
            'allowed' => [
                ['IPProtocol' => 'tcp', 'ports' => ['80', '443']],
                ['IPProtocol' => 'udp', 'ports' => ['10000']],
            ],
        ]);
        try {
            $compute->firewalls->insert($project, $fw);
            return 'created';
        } catch (\Exception $e) {
            $msg = $e->getMessage();
            // 409 Already exists or similar → treat as exists
            if (stripos($msg, 'alreadyexists') !== false || stripos($msg, 'already exists') !== false || stripos($msg, 'duplicate') !== false) {
                return 'exists';
            }
            // Permission errors → assume admin manages firewall; don't warn in UI
            if (stripos($msg, 'permission') !== false || stripos($msg, 'denied') !== false || stripos($msg, 'insufficient') !== false) {
                return 'noperms';
            }
            return 'error:'.$msg;
        }
    }
}
if (!function_exists('mod_jitsi_default_startup_script')) {
    /**
     * Built-in startup script that installs Jitsi Meet on Debian 12.
     * - Reads HOSTNAME_FQDN and LE_EMAIL from instance metadata.
     * - If DNS already points to the VM public IP → uses Let's Encrypt.
     * - Otherwise installs self-signed cert and schedules retries for LE.
     */
    function mod_jitsi_default_startup_script(): string {
        return <<<'BASH'
#!/bin/bash
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive

# Read metadata values (if any)
META="http://metadata.google.internal/computeMetadata/v1"
HOSTNAME_FQDN=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/HOSTNAME_FQDN" || true)
LE_EMAIL=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/LE_EMAIL" || true)
AUTH_DOMAIN=""
if [ -n "$HOSTNAME_FQDN" ]; then
  AUTH_DOMAIN="auth.$HOSTNAME_FQDN"
fi

# If we received a target FQDN, set the system hostname so jitsi-meet uses it
if [ -n "$HOSTNAME_FQDN" ]; then
  hostnamectl set-hostname "$HOSTNAME_FQDN"
  if ! grep -q "$HOSTNAME_FQDN" /etc/hosts; then
    echo "127.0.1.1 $HOSTNAME_FQDN $(echo $HOSTNAME_FQDN | cut -d. -f1)" >> /etc/hosts
  fi
  if [ -n "$AUTH_DOMAIN" ] && ! grep -q "$AUTH_DOMAIN" /etc/hosts; then
    echo "127.0.1.1 $AUTH_DOMAIN auth" >> /etc/hosts
  fi
  # Preseed for jitsi-meet web hostname
  echo "jitsi-meet jitsi-meet/hostname string $HOSTNAME_FQDN" | debconf-set-selections
fi

# Basic packages
apt-get update -y
apt-get install -y curl gnupg2 apt-transport-https ca-certificates ca-certificates-java nginx ufw dnsutils cron

# Jitsi repository
curl https://download.jitsi.org/jitsi-key.gpg.key | gpg --dearmor > /usr/share/keyrings/jitsi.gpg
echo 'deb [signed-by=/usr/share/keyrings/jitsi.gpg] https://download.jitsi.org stable/' > /etc/apt/sources.list.d/jitsi-stable.list
apt-get update -y

# Preseed hostname for JVB
if [ -n "$HOSTNAME_FQDN" ]; then
  echo "jitsi-videobridge jitsi-videobridge/jvb-hostname string $HOSTNAME_FQDN" | debconf-set-selections
fi

MYIP=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/network-interfaces/0/access-configs/0/external-ip" || true)
DNSIP_HOST=""
DNSIP_AUTH=""
WAIT_SECS=0
if [ -n "$HOSTNAME_FQDN" ]; then
  while [ $WAIT_SECS -lt 900 ]; do
    DNSIP_HOST=$(dig +short A "$HOSTNAME_FQDN" @1.1.1.1 | head -n1 || true)
    if [ -n "$AUTH_DOMAIN" ]; then
      DNSIP_AUTH=$(dig +short A "$AUTH_DOMAIN" @1.1.1.1 | head -n1 || true)
    fi
    if [ -n "$MYIP" ] && [ "$MYIP" = "$DNSIP_HOST" ] && { [ -z "$AUTH_DOMAIN" ] || [ "$MYIP" = "$DNSIP_AUTH" ]; }; then
      break
    fi
    sleep 15
    WAIT_SECS=$((WAIT_SECS + 15))
  done
fi

USE_LE=0
if [ -n "$HOSTNAME_FQDN" ] && [ -n "$LE_EMAIL" ] && [ -n "$MYIP" ] && [ -n "$DNSIP_HOST" ] && [ "$MYIP" = "$DNSIP_HOST" ]; then
  if [ -z "$AUTH_DOMAIN" ] || { [ -n "$DNSIP_AUTH" ] && [ "$MYIP" = "$DNSIP_AUTH" ]; }; then
    USE_LE=1
  fi
fi

if [ "$USE_LE" = "1" ]; then
  echo "jitsi-meet-web-config jitsi-meet/cert-choice select Let's Encrypt" | debconf-set-selections
  echo "jitsi-meet-web-config jitsi-meet/cert-email string $LE_EMAIL" | debconf-set-selections
  # Preconfigure certbot to avoid interactive prompts
  mkdir -p /etc/letsencrypt
  cat >/etc/letsencrypt/cli.ini <<EOF
email = $LE_EMAIL
agree-tos = true
non-interactive = true
EOF
else
  echo "jitsi-meet-web-config jitsi-meet/cert-choice select Generate a new self-signed certificate (You will later get a chance to obtain a Let's Encrypt certificate)" | debconf-set-selections
fi

# Install Jitsi Meet
apt-get install -y jitsi-meet

# --- Ensure Prosody main config enables c2s (5222) and includes host configs ---
if [ ! -f /etc/prosody/prosody.cfg.lua ]; then
  cat >/etc/prosody/prosody.cfg.lua <<'EOFPROS'
-- Prosody main config (auto-generated by mod_jitsi)
daemonize = true
c2s_ports = { 5222 }
s2s_ports = { 5269 }
c2s_interfaces = { "*" }
s2s_interfaces = { "*" }
Include "conf.d/*.cfg.lua"
Include "conf.avail/*.cfg.lua"
EOFPROS
  chown root:prosody /etc/prosody/prosody.cfg.lua
  chmod 640 /etc/prosody/prosody.cfg.lua
fi

# --- Ensure VirtualHost for auth.$HOSTNAME_FQDN exists and is enabled ---
if [ -n "$AUTH_DOMAIN" ]; then
  AUTH_CFG="/etc/prosody/conf.avail/${AUTH_DOMAIN}.cfg.lua"
  if [ ! -f "$AUTH_CFG" ]; then
    cat >"$AUTH_CFG" <<'EOFAUTH'
VirtualHost "__AUTH_DOMAIN__"
    authentication = "internal_hashed"
    ssl = {
        key = "/etc/prosody/certs/__AUTH_DOMAIN__.key";
        certificate = "/etc/prosody/certs/__AUTH_DOMAIN__.crt";
    }
EOFAUTH
    sed -i "s#__AUTH_DOMAIN__#${AUTH_DOMAIN}#g" "$AUTH_CFG"
  fi
  ln -sf ../conf.avail/"${AUTH_DOMAIN}.cfg.lua" /etc/prosody/conf.d/"${AUTH_DOMAIN}.cfg.lua"
fi

# --- Ensure Prosody cert symlinks for jitsi & auth and permissions ---
install -d /etc/prosody/certs
if [ -n "$HOSTNAME_FQDN" ]; then
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/etc/prosody/certs/$HOSTNAME_FQDN.crt"
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.key" "/etc/prosody/certs/$HOSTNAME_FQDN.key"
fi
if [ -n "$AUTH_DOMAIN" ]; then
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/etc/prosody/certs/$AUTH_DOMAIN.crt"
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.key" "/etc/prosody/certs/$AUTH_DOMAIN.key"
fi
if [ -f "/etc/jitsi/meet/$HOSTNAME_FQDN.key" ]; then
  chgrp prosody "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
  chmod 640     "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
fi

# Make the current web cert trusted by the OS/Java (works with self-signed until LE is issued)
if [ -n "$HOSTNAME_FQDN" ] && [ -f "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" ]; then
  install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt" || true
  update-ca-certificates || true
fi

# --- Open 5222 (client-to-server) in UFW ---
ufw allow 5222/tcp || true

# --- Create XMPP users focus & jvb and wire passwords into Jicofo/JVB configs ---
if [ -n "$AUTH_DOMAIN" ]; then
  FOCUS_PASS=$(openssl rand -hex 16)
  JVB_PASS=$(openssl rand -hex 16)
  prosodyctl register focus "$AUTH_DOMAIN" "$FOCUS_PASS" || true
  prosodyctl register jvb    "$AUTH_DOMAIN" "$JVB_PASS" || true

  cat >/etc/jitsi/jicofo/jicofo.conf <<EOFJICO
jicofo {
  xmpp {
    client {
      enabled = true
      hostname = "${AUTH_DOMAIN}"
      port = 5222
      domain = "${AUTH_DOMAIN}"
      username = "focus"
      password = "${FOCUS_PASS}"
      tls { enabled = true }
    }
  }
}
EOFJICO
  # Also set legacy env vars for compatibility
  echo "JICOFO_AUTH_USER=focus" >> /etc/jitsi/jicofo/config
  echo "JICOFO_AUTH_PASSWORD=${FOCUS_PASS}" >> /etc/jitsi/jicofo/config

  cat >/etc/jitsi/videobridge/jvb.conf <<EOFJVB
videobridge {
  xmpp-client {
    enabled = true
    hostname = "${AUTH_DOMAIN}"
    port = 5222
    domain = "${AUTH_DOMAIN}"
    username = "jvb"
    password = "${JVB_PASS}"
    tls { enabled = true }
  }
}
EOFJVB
  # Also set legacy env vars for compatibility
  echo "JVB_AUTH_USER=jvb" >> /etc/jitsi/videobridge/config
  echo "JVB_AUTH_PASSWORD=${JVB_PASS}" >> /etc/jitsi/videobridge/config
fi
# --- Mini vhost para auth.$HOSTNAME_FQDN sirviendo el challenge de ACME ---
if [ -n "$AUTH_DOMAIN" ]; then
  mkdir -p /usr/share/jitsi-meet/.well-known/acme-challenge
  cat >/etc/nginx/sites-available/auth-challenge.conf <<EOFNGA
server {
  listen 80;
  listen [::]:80;
  server_name $AUTH_DOMAIN;

  root /usr/share/jitsi-meet;

  location ^~ /.well-known/acme-challenge/ {
    default_type "text/plain";
    alias /usr/share/jitsi-meet/.well-known/acme-challenge/;
  }
  location / { return 204; }
}
EOFNGA
  ln -sf /etc/nginx/sites-available/auth-challenge.conf /etc/nginx/sites-enabled/auth-challenge.conf
  nginx -t && systemctl reload nginx || true
fi
# If DNS was ready, issue LE for both host and auth using acme.sh and install into /etc/jitsi/meet
if [ "$USE_LE" = "1" ]; then
  # Ensure acme.sh is present
  if [ ! -x /opt/acmesh/.acme.sh/acme.sh ]; then
    curl -fsSL https://get.acme.sh | sh -s email=$LE_EMAIL
  fi
  ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
  if [ ! -x "$ACME_BIN" ]; then
    # acme.sh sometimes installs to `/.acme.sh` when run as root; normalize
    if [ -x "/.acme.sh/acme.sh" ]; then
      mkdir -p /opt/acmesh
      ln -sfn /.acme.sh /opt/acmesh/.acme.sh
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    elif [ -x "/root/.acme.sh/acme.sh" ]; then
      mkdir -p /opt/acmesh
      ln -sfn /root/.acme.sh /opt/acmesh/.acme.sh
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    fi
  fi
  $ACME_BIN --set-default-ca --server letsencrypt || true
  if [ -n "$AUTH_DOMAIN" ]; then
    $ACME_BIN --issue -d "$HOSTNAME_FQDN" -d "$AUTH_DOMAIN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force
  else
    $ACME_BIN --issue -d "$HOSTNAME_FQDN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force
  fi
  $ACME_BIN --install-cert -d "$HOSTNAME_FQDN" \
    --key-file       "/etc/jitsi/meet/$HOSTNAME_FQDN.key" \
    --fullchain-file "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" \
    --reloadcmd "systemctl force-reload nginx.service && /usr/share/jitsi-meet/scripts/coturn-le-update.sh $HOSTNAME_FQDN"
  # Link certs for Prosody and restart XMPP + conferencing services
  install -d /etc/prosody/certs
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/etc/prosody/certs/$HOSTNAME_FQDN.crt"
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.key" "/etc/prosody/certs/$HOSTNAME_FQDN.key"
  if [ -n "$AUTH_DOMAIN" ]; then
    ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/etc/prosody/certs/$AUTH_DOMAIN.crt"
    ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.key" "/etc/prosody/certs/$AUTH_DOMAIN.key"
  fi
  chgrp prosody "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
  chmod 640     "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
  # Refresh system/Java trust to include the new cert
  install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt" || true
  update-ca-certificates || true
  systemctl restart prosody || true
  systemctl restart jicofo || true
  systemctl restart jitsi-videobridge2 || true
fi

# If we installed self-signed because DNS wasn't ready, schedule retries for LE
if [ "$USE_LE" != "1" ]; then
  cat >/usr/local/bin/jitsi-issue-le.sh <<'EOS'
#!/bin/bash
set -e
META="http://metadata.google.internal/computeMetadata/v1"
HOSTNAME_FQDN=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/HOSTNAME_FQDN" || true)
LE_EMAIL=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/LE_EMAIL" || true)
MYIP=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/network-interfaces/0/access-configs/0/external-ip" || true)
DNSIP_HOST=$(dig +short A "$HOSTNAME_FQDN" @1.1.1.1 | head -n1 || true)
AUTH_DOMAIN="auth.$HOSTNAME_FQDN"
DNSIP_AUTH=$(dig +short A "$AUTH_DOMAIN" @1.1.1.1 | head -n1 || true)
if [ -n "$HOSTNAME_FQDN" ] && [ -n "$LE_EMAIL" ] && [ -n "$MYIP" ] && [ "$MYIP" = "$DNSIP_HOST" ] && { [ -z "$AUTH_DOMAIN" ] || [ "$MYIP" = "$DNSIP_AUTH" ]; }; then
  ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
  if [ ! -x "$ACME_BIN" ]; then
    if [ -x "/.acme.sh/acme.sh" ]; then
      mkdir -p /opt/acmesh
      ln -sfn /.acme.sh /opt/acmesh/.acme.sh
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    elif [ -x "/root/.acme.sh/acme.sh" ]; then
      mkdir -p /opt/acmesh
      ln -sfn /root/.acme.sh /opt/acmesh/.acme.sh
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    fi
  fi
  if [ ! -x "$ACME_BIN" ]; then
    curl -fsSL https://get.acme.sh | sh -s email=$LE_EMAIL
    # Try to set up ACME_BIN again after install
    if [ -x "/opt/acmesh/.acme.sh/acme.sh" ]; then
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    elif [ -x "/.acme.sh/acme.sh" ]; then
      mkdir -p /opt/acmesh
      ln -sfn /.acme.sh /opt/acmesh/.acme.sh
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    elif [ -x "/root/.acme.sh/acme.sh" ]; then
      mkdir -p /opt/acmesh
      ln -sfn /root/.acme.sh /opt/acmesh/.acme.sh
      ACME_BIN="/opt/acmesh/.acme.sh/acme.sh"
    fi
  fi
  $ACME_BIN --set-default-ca --server letsencrypt || true
  $ACME_BIN --issue -d "$HOSTNAME_FQDN" -d "$AUTH_DOMAIN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force
  $ACME_BIN --install-cert -d "$HOSTNAME_FQDN" \
    --key-file       "/etc/jitsi/meet/$HOSTNAME_FQDN.key" \
    --fullchain-file "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" \
    --reloadcmd "systemctl force-reload nginx.service && /usr/share/jitsi-meet/scripts/coturn-le-update.sh $HOSTNAME_FQDN"
  install -d /etc/prosody/certs
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/etc/prosody/certs/$HOSTNAME_FQDN.crt"
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.key" "/etc/prosody/certs/$HOSTNAME_FQDN.key"
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/etc/prosody/certs/$AUTH_DOMAIN.crt"
  ln -sf "/etc/jitsi/meet/$HOSTNAME_FQDN.key" "/etc/prosody/certs/$AUTH_DOMAIN.key"
  chgrp prosody "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
  chmod 640     "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
  # Refresh system/Java trust with the new cert
  install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt" || true
  update-ca-certificates || true
  systemctl restart prosody || true
  systemctl restart jicofo || true
  systemctl restart jitsi-videobridge2 || true
  if command -v crontab >/dev/null 2>&1; then
    crontab -l | grep -v 'jitsi-issue-le.sh' | crontab - || true
  fi
fi
EOS
  chmod +x /usr/local/bin/jitsi-issue-le.sh
  if command -v crontab >/dev/null 2>&1; then
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/jitsi-issue-le.sh >/var/log/jitsi-issue-le.log 2>&1") | crontab - || true
  fi
  # Ensure services are up after base config even if LE is pending
  systemctl restart prosody jicofo jitsi-videobridge2 || true
fi

# Firewall
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 10000/udp
# 5222/tcp was already allowed above
ufw --force enable

# Marker file
mkdir -p /var/local
printf '%s\n' "BOOT_DONE=1" > /var/local/jitsi_boot_done

BASH;
    }
}
if (!function_exists('mod_jitsi_gcp_client')) {
    function mod_jitsi_gcp_client(): \Google\Service\Compute {
        $client = new \Google\Client();
        $client->setScopes(['https://www.googleapis.com/auth/cloud-platform']);
        // Try to read Service Account uploaded via settings (File API). Fallback to ADC.
        $fs = get_file_storage();
        $context = context_system::instance();
        $files = $fs->get_area_files($context->id, 'mod_jitsi', 'gcpserviceaccountjson', 0, 'itemid, filepath, filename', false);
        if (!empty($files)) {
            $file = reset($files);
            $content = $file->get_content();
            $json = json_decode($content, true);
            if (is_array($json)) {
                $client->setAuthConfig($json);
            } else {
                $client->useApplicationDefaultCredentials();
            }
        } else {
            $client->useApplicationDefaultCredentials();
        }
        return new \Google\Service\Compute($client);
    }
}

if (!function_exists('mod_jitsi_gcp_create_instance')) {
    /**
     * Creates a bare Compute Engine VM and returns its operation name.
     */
    function mod_jitsi_gcp_create_instance(\Google\Service\Compute $compute, string $project, string $zone, array $opts): string {
        $name = $opts['name'];
        $machineType = sprintf('zones/%s/machineTypes/%s', $zone, $opts['machineType']);
        $diskImage = $opts['image'];
        $network = $opts['network'];

        // Optional metadata: startup-script + variables.
        $metadataItems = [];
        if (!empty($opts['startupScript'])) {
            $metadataItems[] = ['key' => 'startup-script', 'value' => $opts['startupScript']];
        }
        if (!empty($opts['hostname'])) {
            $metadataItems[] = ['key' => 'HOSTNAME_FQDN', 'value' => $opts['hostname']];
        }
        if (!empty($opts['letsencryptEmail'])) {
            $metadataItems[] = ['key' => 'LE_EMAIL', 'value' => $opts['letsencryptEmail']];
        }

        $instanceParams = [
            'name' => $name,
            'machineType' => $machineType,
            'labels' => [ 'app' => 'jitsi', 'plugin' => 'mod-jitsi' ],
            'tags' => ['items' => ['mod-jitsi-web']],
            'networkInterfaces' => [[
                'network' => $network,
                'accessConfigs' => [[ 'name' => 'External NAT', 'type' => 'ONE_TO_ONE_NAT' ]]
            ]],
            'disks' => [[
                'boot' => true,
                'autoDelete' => true,
                'initializeParams' => ['sourceImage' => $diskImage, 'diskSizeGb' => 20],
            ]],
        ];
        if (!empty($metadataItems)) {
            $instanceParams['metadata'] = ['items' => $metadataItems];
        }

        $instance = new \Google\Service\Compute\Instance($instanceParams);
        $op = $compute->instances->insert($project, $zone, $instance);
        return $op->getName();
    }
}

if (!function_exists('mod_jitsi_gcp_wait_zone_op')) {
    function mod_jitsi_gcp_wait_zone_op(\Google\Service\Compute $compute, string $project, string $zone, string $opName, int $timeout=420): void {
        $start = time();
        do {
            $op = $compute->zoneOperations->get($project, $zone, $opName);
            if ($op->getStatus() === 'DONE') {
                if ($op->getError()) {
                    throw new moodle_exception('gcpoperationerror', 'mod_jitsi', '', json_encode($op->getError()));
                }
                return;
            }
            usleep(500000);
        } while (time() - $start < $timeout);
        throw new moodle_exception('gcpoperationtimeout', 'mod_jitsi');
    }
}

// Action: create a bare VM in Google Cloud to test connectivity and permissions.
if ($action === 'creategcpvm') {
    require_sesskey();
    $ajax = optional_param('ajax', 0, PARAM_BOOL);

    // Guard: check if Google API Client classes are available.
    if (!class_exists('Google\\Client') || !class_exists('Google\\Service\\Compute')) {
        if ($ajax) {
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => get_string('gcpapimissing', 'mod_jitsi')]);
            exit;
        }
        \core\notification::add(get_string('gcpapimissing', 'mod_jitsi'), \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    // Read minimal + optional config.
    $project   = trim((string) get_config('mod_jitsi', 'gcp_project'));
    $zone      = trim((string) get_config('mod_jitsi', 'gcp_zone'));
    $mach      = trim((string) get_config('mod_jitsi', 'gcp_machine_type')) ?: 'e2-standard-2';
    $image     = trim((string) get_config('mod_jitsi', 'gcp_image')) ?: 'projects/debian-cloud/global/images/family/debian-12';
    $network   = trim((string) get_config('mod_jitsi', 'gcp_network')) ?: 'global/networks/default';
    $hostname  = trim((string) get_config('mod_jitsi', 'gcp_hostname'));
    $leemail   = trim((string) get_config('mod_jitsi', 'gcp_letsencrypt_email'));
    // If hostname is set, require LE email to avoid interactive prompts later.
    if (!empty($hostname) && empty($leemail)) {
        if ($ajax) {
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Missing Let\'s Encrypt email (gcp_letsencrypt_email) while hostname is set.']);
            exit;
        }
        \core\notification::add('Missing Let\'s Encrypt email (gcp_letsencrypt_email) while hostname is set.', \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }
    $sscript   = mod_jitsi_default_startup_script();

    $missing = [];
    foreach ([['gcp_project',$project], ['gcp_zone',$zone]] as [$k,$v]) { if (empty($v)) { $missing[] = $k; } }
    if ($missing) {
        if ($ajax) {
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Missing GCP settings: '.implode(', ', $missing)]);
            exit;
        }
        \core\notification::add('Missing GCP settings: '.implode(', ', $missing), \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    $instancename = 'jitsi-test-'.date('ymdHi');

    try {
        $compute = mod_jitsi_gcp_client();
        // Derive a short network name for CLI instructions (e.g., "default").
        $networkshort = $network;
        if (strpos($networkshort, '/') !== false) {
            $parts = explode('/', $networkshort);
            $networkshort = end($parts);
        }
        // Ensure VPC firewall rule exists for ports 80/443 (tcp) and 10000 (udp).
        $fwwarn = '';
        $fwwarn_detail = '';
        $fwstatus = mod_jitsi_gcp_ensure_firewall($compute, $project, $network);
        if (strpos($fwstatus, 'error:') === 0) {
            $fwwarn = 'Could not create VPC firewall rule automatically. Please allow TCP 80/443 and UDP 10000 (target tag: mod-jitsi-web).';
            $fwwarn_detail = substr($fwstatus, 6);
            \core\notification::add('Warning: could not create VPC firewall rule automatically. Please allow TCP 80/443 and UDP 10000 to this VM. Details: '.s($fwwarn_detail), \core\output\notification::NOTIFY_WARNING);
        }
        // If status is 'noperms' (e.g., permission denied) or 'exists', do not warn in UI; assume admin-managed firewall or rule already present.
        $opname = mod_jitsi_gcp_create_instance($compute, $project, $zone, [
            'name' => $instancename,
            'machineType' => $mach,
            'image' => $image,
            'network' => $network,
            'hostname' => $hostname,
            'letsencryptEmail' => $leemail,
            'startupScript' => $sscript,
        ]);
        // Save operation info in session for status polling.
        if (!isset($SESSION->mod_jitsi_ops)) { $SESSION->mod_jitsi_ops = []; }
        $SESSION->mod_jitsi_ops[$opname] = [
            'project' => $project,
            'zone' => $zone,
            'instancename' => $instancename,
        ];
        if ($ajax) {
            @header('Content-Type: application/json');
            echo json_encode([
                'status' => 'pending',
                'opname' => $opname,
                'instancename' => $instancename,
                'fwwarn' => $fwwarn,
                'fwwarn_detail' => $fwwarn_detail,
                'network' => $network,
                'networkshort' => $networkshort,
                'fwstatus' => $fwstatus,
            ]);
            exit;
        }
        // Legacy redirect flow (non-AJAX): use previous status page.
        $SESSION->mod_jitsi_gcp_op = [
            'project' => $project,
            'zone' => $zone,
            'opname' => $opname,
            'instancename' => $instancename,
        ];
        redirect(new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpstatus']));
    } catch (Exception $e) {
        if ($ajax) {
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
            exit;
        }
        \core\notification::add('Failed to create GCP VM: '.$e->getMessage(), \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }
}

// Lightweight JSON status endpoint for AJAX polling.
if ($action === 'gcpstatusjson') {
    require_sesskey();
    @header('Content-Type: application/json');
    $opname = required_param('opname', PARAM_TEXT);
    if (empty($SESSION->mod_jitsi_ops[$opname])) {
        echo json_encode(['status' => 'error', 'message' => 'Unknown operation']);
        exit;
    }
    $info = $SESSION->mod_jitsi_ops[$opname];

    if (!class_exists('Google\\Client') || !class_exists('Google\\Service\\Compute')) {
        echo json_encode(['status' => 'error', 'message' => get_string('gcpapimissing', 'mod_jitsi')]);
        exit;
    }

    try {
        $compute = mod_jitsi_gcp_client();
        $op = $compute->zoneOperations->get($info['project'], $info['zone'], $opname);
        if ($op->getStatus() === 'DONE') {
            if ($op->getError()) {
                unset($SESSION->mod_jitsi_ops[$opname]);
                echo json_encode(['status' => 'error', 'message' => json_encode($op->getError())]);
                exit;
            }
            $inst = $compute->instances->get($info['project'], $info['zone'], $info['instancename']);
            $nats = $inst->getNetworkInterfaces()[0]->getAccessConfigs();
            $ip = (!empty($nats) && isset($nats[0])) ? $nats[0]->getNatIP() : '';
            unset($SESSION->mod_jitsi_ops[$opname]);
            echo json_encode(['status' => 'done', 'ip' => $ip]);
            exit;
        } else {
            echo json_encode(['status' => 'pending']);
            exit;
        }
    } catch (Exception $e) {
        unset($SESSION->mod_jitsi_ops[$opname]);
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
        exit;
    }
}

// Action: poll & display status while the VM is being created.
if ($action === 'gcpstatus') {
    // Guard: if no op in session, go back.
    if (empty($SESSION->mod_jitsi_gcp_op)) {
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    $opinfo = $SESSION->mod_jitsi_gcp_op;

    // If Google client not available, show static message and meta refresh.
    $classesok = class_exists('Google\\Client') && class_exists('Google\\Service\\Compute');

    echo $OUTPUT->header();
    echo $OUTPUT->heading(get_string('servermanagement', 'mod_jitsi'));

    // Simple Bootstrap 5 spinner + message.
    echo html_writer::div(
        html_writer::tag('div', '', ['class' => 'spinner-border', 'role' => 'status', 'aria-hidden' => 'true']) .
        html_writer::tag('div', get_string('creatingvm', 'mod_jitsi', s($opinfo['instancename'])), ['class' => 'mt-3']),
        'd-flex flex-column align-items-center my-5'
    );

    // If classes missing, just auto-refresh back to list.
    if (!$classesok) {
        echo html_writer::tag('p', get_string('gcpapimissing', 'mod_jitsi'));
        echo $OUTPUT->footer();
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'), 2);
        exit;
    }

    // Check operation status.
    try {
        $compute = mod_jitsi_gcp_client();
        $op = $compute->zoneOperations->get($opinfo['project'], $opinfo['zone'], $opinfo['opname']);
        if ($op->getStatus() === 'DONE') {
            if ($op->getError()) {
                unset($SESSION->mod_jitsi_gcp_op);
                \core\notification::add(get_string('gcpoperationerror', 'mod_jitsi', json_encode($op->getError())), \core\output\notification::NOTIFY_ERROR);
                redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
            }
            // Fetch public IP and notify success.
            $inst = $compute->instances->get($opinfo['project'], $opinfo['zone'], $opinfo['instancename']);
            $nats = $inst->getNetworkInterfaces()[0]->getAccessConfigs();
            $ip = (!empty($nats) && isset($nats[0])) ? $nats[0]->getNatIP() : '';
            unset($SESSION->mod_jitsi_gcp_op);
            \core\notification::add(get_string('gcpservercreated', 'mod_jitsi', $opinfo['instancename'].' '.$ip), \core\output\notification::NOTIFY_SUCCESS);
            redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
        } else {
            // Not done yet: add meta refresh to poll again in 2s.
            echo html_writer::empty_tag('meta', ['http-equiv' => 'refresh', 'content' => '2']);
            echo $OUTPUT->footer();
            exit;
        }
    } catch (Exception $e) {
        unset($SESSION->mod_jitsi_gcp_op);
        \core\notification::add(get_string('gcpservercreatefail', 'mod_jitsi', $e->getMessage()), \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }
}

if ($action === 'delete' && $id > 0) {
    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid id');
    }

    if ($confirm) {
        $DB->delete_records('jitsi_servers', ['id' => $server->id]);

        \core\notification::add(
            get_string('serverdeleted', 'mod_jitsi', $server->name),
            \core\output\notification::NOTIFY_SUCCESS
        );
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    } else {
        echo $OUTPUT->header();
        echo $OUTPUT->heading(get_string('delete'));
        $msg = get_string('confirmdelete', 'mod_jitsi', format_string($server->name));
        echo $OUTPUT->confirm(
            $msg,
            new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'delete', 'id' => $id, 'confirm' => 1]),
            new moodle_url('/mod/jitsi/servermanagement.php')
        );
        echo $OUTPUT->footer();
        exit;
    }
}

$mform = new servermanagement_form();

if ($action === 'edit' && $id > 0) {
    if ($server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        $mform->set_data($server);
    } else {
        throw new moodle_exception('Invalid id');
    }
}

if ($mform->is_cancelled()) {
    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
} else if ($data = $mform->get_data()) {
    if ($data->id) {
        if (!$server = $DB->get_record('jitsi_servers', ['id' => $data->id])) {
            throw new moodle_exception('Invalid Id');
        }

        $server->name   = $data->name;
        $server->type   = $data->type;
        $server->domain = $data->domain;
        $server->appid                = '';
        $server->secret               = '';
        $server->eightbyeightappid    = '';
        $server->eightbyeightapikeyid = '';
        $server->privatekey           = '';

        if ($data->type == 1) {
            $server->appid  = $data->appid;
            $server->secret = $data->secret;
        } else if ($data->type == 2) {
            $server->eightbyeightappid    = $data->eightbyeightappid;
            $server->eightbyeightapikeyid = $data->eightbyeightapikeyid;
            $server->privatekey           = $data->privatekey;
        }

        $server->timemodified = time();
        $DB->update_record('jitsi_servers', $server);

        \core\notification::add(
            get_string('serverupdated', 'mod_jitsi', $server->name),
            \core\output\notification::NOTIFY_SUCCESS
        );
    } else {
        $server = new stdClass();
        $server->name   = $data->name;
        $server->type   = $data->type;
        $server->domain = $data->domain;
        $server->appid                = '';
        $server->secret               = '';
        $server->eightbyeightappid    = '';
        $server->eightbyeightapikeyid = '';
        $server->privatekey           = '';

        if ($data->type == 1) {
            $server->appid  = $data->appid;
            $server->secret = $data->secret;
        } else if ($data->type == 2) {
            $server->eightbyeightappid    = $data->eightbyeightappid;
            $server->eightbyeightapikeyid = $data->eightbyeightapikeyid;
            $server->privatekey           = $data->privatekey;
        }

        $server->timecreated  = time();
        $server->timemodified = time();

        $DB->insert_record('jitsi_servers', $server);

        \core\notification::add(
            get_string('serveradded', 'mod_jitsi'),
            \core\output\notification::NOTIFY_SUCCESS
        );
    }

    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('servermanagement', 'mod_jitsi'));



$settingsurl = new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']);
$creategcpvmurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'creategcpvm', 'sesskey' => sesskey()]);

echo html_writer::div(
    html_writer::link($settingsurl, get_string('backtosettings', 'mod_jitsi'), ['class' => 'btn btn-secondary me-2']) .
    html_writer::tag('button', 'Create VM in Google Cloud', ['id' => 'btn-creategcpvm', 'type' => 'button', 'class' => 'btn btn-primary'])
);

// Modal markup for progress.
$creating = get_string('creatingvm', 'mod_jitsi', '');
$gcpstatusurl = (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpstatusjson']))->out(false);
$createvmurl  = (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'creategcpvm', 'ajax' => 1]))->out(false);
$listurl      = (new moodle_url('/mod/jitsi/servermanagement.php'))->out(false);
$sesskeyjs    = sesskey();

// Modal markup (HTML only).
echo <<<HTML
<div class="modal fade" id="gcpModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-body text-center">
        <div class="spinner-border" role="status" aria-hidden="true"></div>
        <p id="gcp-modal-text" class="mt-3 mb-0">{$creating}</p>
      </div>
    </div>
  </div>
</div>
HTML;

$init = [
    'sesskey' => $sesskeyjs,
    'statusUrl' => $gcpstatusurl,
    'createUrl' => $createvmurl,
    'listUrl' => $listurl,
    'creatingText' => $creating,
    'hostname' => (string) get_config('mod_jitsi', 'gcp_hostname'),
];
$initjson = json_encode($init, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);
$PAGE->requires->js_init_code(
    "(function(){\n".
    "  var cfg = ".$initjson.";\n".
    "  var btn = document.getElementById('btn-creategcpvm');\n".
    "  if (!btn) return;\n".
    "  var modalEl = document.getElementById('gcpModal');\n".
    "  var textEl = document.getElementById('gcp-modal-text');\n".
    "  var backdrop;\n".
    "  var lastWarnHTML = '';\n".
    "  function showModal(){\n".
    "    if (!modalEl) return;\n".
    "    modalEl.classList.add('show');\n".
    "    modalEl.style.display = 'block';\n".
    "    modalEl.removeAttribute('aria-hidden');\n".
    "    backdrop = document.createElement('div');\n".
    "    backdrop.className = 'modal-backdrop fade show';\n".
    "    document.body.appendChild(backdrop);\n".
    "  }\n".
    "  function hideModal(){\n".
    "    if (!modalEl) return;\n".
    "    modalEl.classList.remove('show');\n".
    "    modalEl.style.display = 'none';\n".
    "    modalEl.setAttribute('aria-hidden','true');\n".
    "    if (backdrop && backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);\n".
    "  }\n".
    "  async function postJSON(url, data){\n".
    "    var res = await fetch(url, {method: 'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(data)});\n".
    "    if (!res.ok) throw new Error('HTTP ' + res.status);\n".
    "    return await res.json();\n".
    "  }\n".
    "  async function pollStatus(opname){\n".
    "    try {\n".
    "      var data = await postJSON(cfg.statusUrl, {sesskey: cfg.sesskey, opname: opname});\n".
    "      if (data.status === 'pending') {\n".
    "        setTimeout(function(){ pollStatus(opname); }, 1500);\n".
    "        if (data.fwwarn && textEl) {\n".
    "          var warn = document.createElement('div');\n".
    "          warn.className = 'alert alert-warning mt-3';\n".
    "          var net = (data.networkshort || 'default');\n".
    "          var detail = data.fwwarn_detail ? ('<pre class=\"mb-2\"><code>'+ String(data.fwwarn_detail).replace(/[<>]/g, function(c){return ({'<':'&lt;','>':'&gt;'}[c]);}) +'</code></pre>') : '';\n".
    "          var cmd = [\n".
    "            'gcloud compute firewall-rules create mod-jitsi-allow-web \\\\',\n".
    "            '  --network='+ net +' \\\\',\n".
    "            '  --direction=INGRESS --priority=1000 --action=ALLOW \\\\',\n".
    "            '  --rules=tcp:80,tcp:443,udp:10000 \\\\',\n".
    "            '  --source-ranges=0.0.0.0/0 \\\\',\n".
    "            '  --target-tags=mod-jitsi-web'\n".
    "          ].join('\\n');\n".
    "          warn.innerHTML = '<strong>'+ data.fwwarn +'</strong>'+\n".
    "            (detail ? '<div class=\"small text-muted\">Error detail:</div>'+ detail : '')+\n".
    "            '<div class=\"mt-2\">Create it manually with:</div>'+ \n".
    "            '<pre class=\"mt-1\"><code>'+ cmd +'</code></pre>'+ \n".
    "            '<button id=\"copy-fw\" type=\"button\" class=\"btn btn-sm btn-outline-secondary\">Copy command</button>';\n".
    "          textEl.appendChild(warn);\n".
    "          var cbtn = document.getElementById('copy-fw');\n".
    "          if (cbtn && navigator.clipboard) {\n".
    "            cbtn.addEventListener('click', function(){ navigator.clipboard.writeText(cmd); });\n".
    "          }\n".
    "          lastWarnHTML = warn.outerHTML;\n".
    "        }\n".
    "      } else if (data.status === 'done') {\n".
    "        var ip = (data.ip || '');\n".
    "        var host = (cfg.hostname || 'your-hostname.example.com');\n".
    "        if (textEl) {\n".
    "          textEl.innerHTML = (\n".
    "            (lastWarnHTML || '') +\n".
    "            '<h5>✅ VM created</h5>'+ \n".
    "            '<p class=\"text-muted\">Firewall step executed (rule: <code>mod-jitsi-allow-web</code>, tag: <code>mod-jitsi-web</code>).</p>'+ \n".
    "            '<p>Public IP: <strong>'+ ip +'</strong></p>'+\n".
    "            '<p>Add <code>A</code> records in your DNS pointing both hostnames to that IP.'+\n".
    "            ' If you use Cloudflare, make sure the records are <strong>DNS only</strong> (proxy off).</p>'+ \n".
    "            '<pre><code>'+ host + '           A  ' + ip + '\\n' + 'auth.'+ host + '   A  ' + ip + '</code></pre>'+ \n".
    "            '<p>Once both DNS records point to this IP, the server will automatically obtain a multi-domain Let\\'s Encrypt certificate and reload services.</p>'+ \n".
    "            '<div class=\"mt-3\">'+\n".
    "              '<button id=\"copy-ip\" type=\"button\" class=\"btn btn-outline-secondary me-2\">Copy IP</button>'+\n".
    "              '<a href=\"'+ cfg.listUrl +'\" class=\"btn btn-primary\">Close</a>'+\n".
    "            '</div>'\n".
    "          );\n".
    "          var copyBtn = document.getElementById('copy-ip');\n".
    "          if (copyBtn && navigator.clipboard) {\n".
    "            copyBtn.addEventListener('click', function(){ navigator.clipboard.writeText(ip); });\n".
    "          }\n".
    "        }\n".
    "      } else {\n".
    "        if (textEl) textEl.textContent = 'Error: ' + (data.message || 'Unknown');\n".
    "        setTimeout(function(){ window.location.href = cfg.listUrl; }, 2000);\n".
    "      }\n".
    "    } catch(e){\n".
    "      if (textEl) textEl.textContent = 'Error: ' + e.message;\n".
    "      setTimeout(function(){ window.location.href = cfg.listUrl; }, 2000);\n".
    "    }\n".
    "  }\n".
    "  btn.addEventListener('click', async function(){\n".
    "    showModal();\n".
    "    if (textEl) {\n".
    "      textEl.innerHTML = '<h5>⏳ Creating resources…</h5>'+\n".
    "        '<p>Ensuring firewall (TCP 80/443 and UDP 10000) and creating the VM in Google Cloud. This can take a few minutes.</p>'+\n".
    "        '<p>You can close this dialog and come back later; the process continues in the background.</p>'+\n".
    "        '<div class=\"mt-3\"><a href=\"'+ cfg.listUrl +'\" class=\"btn btn-outline-secondary\">Close</a></div>';\n".
    "    }\n".
    "    try {\n".
    "      var data = await postJSON(cfg.createUrl, {sesskey: cfg.sesskey});\n".
    "      if (data && data.status === 'pending' && data.opname){\n".
    "        pollStatus(data.opname);\n".
    "        if (data.fwwarn && textEl) {\n".
    "          var warn = document.createElement('div');\n".
    "          warn.className = 'alert alert-warning mt-3';\n".
    "          var net = (data.networkshort || 'default');\n".
    "          var detail = data.fwwarn_detail ? ('<pre class=\"mb-2\"><code>'+ String(data.fwwarn_detail).replace(/[<>]/g, function(c){return ({'<':'&lt;','>':'&gt;'}[c]);}) +'</code></pre>') : '';\n".
    "          var cmd = [\n".
    "            'gcloud compute firewall-rules create mod-jitsi-allow-web \\\\',\n".
    "            '  --network='+ net +' \\\\',\n".
    "            '  --direction=INGRESS --priority=1000 --action=ALLOW \\\\',\n".
    "            '  --rules=tcp:80,tcp:443,udp:10000 \\\\',\n".
    "            '  --source-ranges=0.0.0.0/0 \\\\',\n".
    "            '  --target-tags=mod-jitsi-web'\n".
    "          ].join('\\n');\n".
    "          warn.innerHTML = '<strong>'+ data.fwwarn +'</strong>'+\n".
    "            (detail ? '<div class=\"small text-muted\">Error detail:</div>'+ detail : '')+\n".
    "            '<div class=\"mt-2\">Create it manually with:</div>'+ \n".
    "            '<pre class=\"mt-1\"><code>'+ cmd +'</code></pre>'+ \n".
    "            '<button id=\"copy-fw\" type=\"button\" class=\"btn btn-sm btn-outline-secondary\">Copy command</button>';\n".
    "          textEl.appendChild(warn);\n".
    "          var cbtn = document.getElementById('copy-fw');\n".
    "          if (cbtn && navigator.clipboard) {\n".
    "            cbtn.addEventListener('click', function(){ navigator.clipboard.writeText(cmd); });\n".
    "          }\n".
    "          lastWarnHTML = warn.outerHTML;\n".
    "        }\n".
    "      } else {\n".
    "        if (textEl) textEl.textContent = 'Error starting VM creation';\n".
    "        setTimeout(function(){ window.location.reload(); }, 1500);\n".
    "      }\n".
    "    } catch(e){\n".
    "      if (textEl) textEl.textContent = 'Error: ' + e.message;\n".
    "      setTimeout(function(){ window.location.reload(); }, 1500);\n".
    "    }\n".
    "  });\n".
    "})();"
);


$servers = $DB->get_records('jitsi_servers', null, 'name ASC');
$table = new html_table();
$table->head = [
    get_string('name'),
    get_string('type', 'mod_jitsi'),
    get_string('domain', 'mod_jitsi'),
    get_string('actions', 'mod_jitsi'),
];

foreach ($servers as $s) {
    switch ($s->type) {
        case 0:
            $typestring = 'Server without token';
            break;
        case 1:
            $typestring = 'Self-hosted (appid & secret)';
            break;
        case 2:
            $typestring = '8x8 server';
            break;
        default:
            $typestring = get_string('unknowntype', 'mod_jitsi');
    }

    $editurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'edit', 'id' => $s->id]);
    $deleteurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'delete', 'id' => $s->id]);

    $links = html_writer::link($editurl, get_string('edit')) . ' | '
           . html_writer::link($deleteurl, get_string('delete'));

    $table->data[] = [
        format_string($s->name),
        $typestring,
        format_string($s->domain),
        $links,
    ];
}
echo html_writer::table($table);

if ($action === 'edit' && $id > 0) {
    echo $OUTPUT->heading(get_string('editserver', 'mod_jitsi'));
} else {
    echo $OUTPUT->heading(get_string('addnewserver', 'mod_jitsi'));
}

$mform->display();

echo $OUTPUT->footer();
