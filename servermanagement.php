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

// ⚠️ IMPORTANTE: Verificar la acción ANTES de cargar config.php
$rawaction = $_GET['action'] ?? $_POST['action'] ?? '';

if ($rawaction === 'jitsiready') {
    // Para este endpoint necesitamos config.php pero SIN require_login
    define('NO_MOODLE_COOKIES', true);
    require_once(__DIR__ . '/../../config.php');
    
    @header('Content-Type: application/json');
    
    $instancename = required_param('instance', PARAM_TEXT);
    $token = required_param('token', PARAM_ALPHANUMEXT);
    $ip = optional_param('ip', '', PARAM_TEXT);
    $hostname = optional_param('hostname', '', PARAM_TEXT);
    $phase = optional_param('phase', 'completed', PARAM_ALPHAEXT);
    $appid = optional_param('appid', '', PARAM_ALPHANUMEXT);
    $secret = optional_param('secret', '', PARAM_ALPHANUMEXT);
    
    // Verificar token
    $tokenkey = 'mod_jitsi_vmtoken_' . clean_param($instancename, PARAM_ALPHANUMEXT);
    $storedtoken = get_config('mod_jitsi', $tokenkey);
    
    if (empty($storedtoken) || $storedtoken !== $token) {
        http_response_code(401);
        echo json_encode(['status' => 'error', 'message' => 'Invalid token']);
        exit;
    }
    
    // Guardar estado
    $statuskey = 'mod_jitsi_vmstatus_' . clean_param($instancename, PARAM_ALPHANUMEXT);
    set_config($statuskey, json_encode([
        'status' => $phase,
        'ip' => $ip,
        'hostname' => $hostname,
        'appid' => $appid,
        'secret' => $secret,
        'timestamp' => time(),
    ]), 'mod_jitsi');
    
    // Registrar servidor cuando se complete
    if ($phase === 'completed' && !empty($hostname) && !empty($appid) && !empty($secret)) {
        global $DB;
        
        try {
            // Verificar si el servidor ya existe
            $existingserver = $DB->get_record('jitsi_servers', ['domain' => $hostname]);
            
            if (!$existingserver) {
                // Insertar nuevo servidor
                $server = new stdClass();
                $server->name = $instancename;
                $server->type = 1; // Self-hosted con JWT
                $server->domain = $hostname;
                $server->appid = $appid;
                $server->secret = $secret;
                $server->eightbyeightappid = '';
                $server->eightbyeightapikeyid = '';
                $server->privatekey = '';
                $server->timecreated = time();
                $server->timemodified = time();
                
                // Insertar y obtener el ID
                $serverid = $DB->insert_record('jitsi_servers', $server);
                
                // Configurar este servidor como activo en el plugin
                set_config('server', $serverid, 'mod_jitsi');
                
                error_log("✅ Jitsi server registered: {$hostname} (ID: {$serverid}, appid: {$appid})");
                
                http_response_code(200);
                echo json_encode([
                    'status' => 'ok',
                    'message' => 'Server registered successfully',
                    'phase' => $phase,
                    'registered' => true,
                    'serverid' => $serverid
                ]);
            } else {
                // Actualizar servidor existente
                $existingserver->appid = $appid;
                $existingserver->secret = $secret;
                $existingserver->timemodified = time();
                $DB->update_record('jitsi_servers', $existingserver);
                
                // Configurar como servidor activo
                set_config('server', $existingserver->id, 'mod_jitsi');
                
                error_log("✅ Jitsi server updated: {$hostname} (ID: {$existingserver->id}, appid: {$appid})");
                
                http_response_code(200);
                echo json_encode([
                    'status' => 'ok',
                    'message' => 'Server updated successfully',
                    'phase' => $phase,
                    'registered' => true,
                    'serverid' => $existingserver->id
                ]);
            }
            
            // Limpiar token usado
            unset_config($tokenkey, 'mod_jitsi');
            
        } catch (Exception $e) {
            error_log("❌ Failed to register Jitsi server: " . $e->getMessage());
            http_response_code(500);
            echo json_encode([
                'status' => 'error',
                'message' => 'Database error: ' . $e->getMessage(),
                'phase' => $phase,
                'registered' => false
            ]);
        }
    } else {
        // Fases intermedias (waiting_dns, dns_ready, etc.)
        http_response_code(200);
        echo json_encode([
            'status' => 'ok',
            'message' => 'Status updated',
            'phase' => $phase,
            'registered' => false
        ]);
    }
    exit;
}

// Para el resto de acciones: cargar Moodle normalmente
require_once(__DIR__ . '/../../config.php');

$action = optional_param('action', '', PARAM_ALPHA);

// Ahora sí requerir login para todas las demás acciones
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
    CALLBACK_URL=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/CALLBACK_URL" || true)

    AUTH_DOMAIN=""
    if [ -n "$HOSTNAME_FQDN" ]; then
      AUTH_DOMAIN="auth.$HOSTNAME_FQDN"
    fi

    # Get public IP early
    MYIP=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/network-interfaces/0/access-configs/0/external-ip" || true)

    # Notify Moodle that VM is created and waiting for DNS
    if [ -n "$CALLBACK_URL" ]; then
      curl -X POST "${CALLBACK_URL}&ip=${MYIP}&hostname=${HOSTNAME_FQDN}&phase=waiting_dns" \
        --max-time 10 --retry 2 --retry-delay 3 || true
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
    LOCALIP=$(ip route get 1.1.1.1 | awk '{print $7; exit}' || echo "")
    DNSIP_HOST=""
    DNSIP_AUTH=""
    WAIT_SECS=0

    if [ -n "$HOSTNAME_FQDN" ]; then
      while [ $WAIT_SECS -lt 900 ]; do
        DNSIP_HOST=$(dig +short A "$HOSTNAME_FQDN" @1.1.1.1 | head -n1 || true)
        if [ -n "$AUTH_DOMAIN" ]; then
          DNSIP_AUTH=$(dig +short A "$AUTH_DOMAIN" @1.1.1.1 | head -n1 || true)
        fi
        
        # Check if IPs match
        if [ -n "$MYIP" ] && [ -n "$DNSIP_HOST" ] && [ "$MYIP" = "$DNSIP_HOST" ]; then
          if [ -z "$AUTH_DOMAIN" ]; then
            # DNS ready, notify Moodle
            if [ -n "$CALLBACK_URL" ]; then
              curl -X POST "${CALLBACK_URL}&ip=${MYIP}&hostname=${HOSTNAME_FQDN}&phase=dns_ready" \
                --max-time 10 --retry 2 --retry-delay 3 || true
            fi
            break
          elif [ -n "$DNSIP_AUTH" ] && [ "$MYIP" = "$DNSIP_AUTH" ]; then
            # DNS ready, notify Moodle
            if [ -n "$CALLBACK_URL" ]; then
              curl -X POST "${CALLBACK_URL}&ip=${MYIP}&hostname=${HOSTNAME_FQDN}&phase=dns_ready" \
                --max-time 10 --retry 2 --retry-delay 3 || true
            fi
            break
          fi
        fi
        
        sleep 15
        WAIT_SECS=$((WAIT_SECS + 15))
      done
    fi

    USE_LE=0
    if [ -n "$HOSTNAME_FQDN" ] && [ -n "$LE_EMAIL" ] && [ -n "$MYIP" ] && [ -n "$DNSIP_HOST" ] && [ "$MYIP" = "$DNSIP_HOST" ]; then
      if [ -z "$AUTH_DOMAIN" ]; then
        USE_LE=1
      elif [ -n "$DNSIP_AUTH" ] && [ "$MYIP" = "$DNSIP_AUTH" ]; then
        USE_LE=1
      fi
    fi

    if [ "$USE_LE" = "1" ]; then
      echo "jitsi-meet-web-config jitsi-meet/cert-choice select Let's Encrypt" | debconf-set-selections
      echo "jitsi-meet-web-config jitsi-meet/cert-email string $LE_EMAIL" | debconf-set-selections
      mkdir -p /etc/letsencrypt
      cat > /etc/letsencrypt/cli.ini << 'EOFLE'
    email = PLACEHOLDER_EMAIL
    agree-tos = true
    non-interactive = true
    EOFLE
      sed -i "s/PLACEHOLDER_EMAIL/$LE_EMAIL/g" /etc/letsencrypt/cli.ini
    else
      echo "jitsi-meet-web-config jitsi-meet/cert-choice select Generate a new self-signed certificate (You will later get a chance to obtain a Let's Encrypt certificate)" | debconf-set-selections
    fi

    # Install Jitsi Meet
    apt-get install -y jitsi-meet

    # Ensure Prosody main config has plugin_paths and correct settings
    cat > /etc/prosody/prosody.cfg.lua << 'EOFPROS'
    -- Prosody Configuration File
    plugin_paths = { "/usr/share/jitsi-meet/prosody-plugins/" }

    -- Network configuration
    c2s_ports = { 5222 }
    s2s_ports = { 5269 }
    component_ports = { 5347 }

    -- Modules
    modules_enabled = {
        "roster";
        "saslauth";
        "tls";
        "dialback";
        "disco";
        "carbons";
        "pep";
        "private";
        "blocklist";
        "vcard4";
        "vcard_legacy";
        "version";
        "uptime";
        "time";
        "ping";
        "admin_adhoc";
        "bosh";
        "websocket";
    }

    modules_disabled = {}

    allow_registration = false
    c2s_require_encryption = false
    s2s_require_encryption = false
    s2s_secure_auth = false

    authentication = "internal_hashed"

    log = {
        info = "/var/log/prosody/prosody.log";
        error = "/var/log/prosody/prosody.err";
        "*syslog";
    }

    certificates = "certs"

    -- Include virtual hosts
    Include "conf.d/*.cfg.lua"
    EOFPROS

    chown root:prosody /etc/prosody/prosody.cfg.lua
    chmod 640 /etc/prosody/prosody.cfg.lua

    # Ensure Prosody cert symlinks for jitsi and auth
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

    # Make the current web cert trusted by the OS/Java
    if [ -n "$HOSTNAME_FQDN" ] && [ -f "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" ]; then
      install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt" || true
      update-ca-certificates || true
    fi

    # Open firewall ports
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 5222/tcp
    ufw allow 10000/udp
    ufw allow 4443/tcp
    ufw --force enable

    # Create XMPP users focus and jvb
    if [ -n "$AUTH_DOMAIN" ]; then
      FOCUS_PASS=$(openssl rand -hex 16)
      JVB_PASS=$(openssl rand -hex 16)
      
      # Restart Prosody to ensure it's running
      systemctl restart prosody || true
      sleep 5
      
      # Register users with retry logic
      for i in {1..5}; do
        if prosodyctl register focus "$AUTH_DOMAIN" "$FOCUS_PASS" 2>/dev/null; then
          echo "User focus registered successfully"
          break
        fi
        echo "Retry $i: Failed to register focus user, retrying..."
        sleep 2
      done
      
      for i in {1..5}; do
        if prosodyctl register jvb "$AUTH_DOMAIN" "$JVB_PASS" 2>/dev/null; then
          echo "User jvb registered successfully"
          break
        fi
        echo "Retry $i: Failed to register jvb user, retrying..."
        sleep 2
      done

      # Configure Jicofo
      cat > /etc/jitsi/jicofo/jicofo.conf << EOFJICO
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
          client-proxy = "focus.${HOSTNAME_FQDN}"
          xmpp-domain = "${HOSTNAME_FQDN}"
        }
      }
      bridge {
        brewery-jid = "JvbBrewery@internal.${AUTH_DOMAIN}"
        selection-strategy = "SplitBridgeSelectionStrategy"
      }
      conference {
        enable-auto-owner = true
      }
    }
    EOFJICO

      # Configure JVB with correct IPs
      JVB_NICKNAME="jvb-$(hostname)-$(openssl rand -hex 3)"
      cat > /etc/jitsi/videobridge/jvb.conf << EOFJVB
    videobridge {
      ice {
        udp {
          port = 10000
        }
        tcp {
          enabled = true
          port = 4443
        }
        publicAddress = "${MYIP}"
        privateAddress = "${LOCALIP}"
      }
      apis {
        xmpp-client {
          configs {
            xmpp-server-1 {
              hostname = "${AUTH_DOMAIN}"
              port = 5222
              domain = "${AUTH_DOMAIN}"
              username = "jvb"
              password = "${JVB_PASS}"
              muc_jids = "JvbBrewery@internal.${AUTH_DOMAIN}"
              muc_nickname = "${JVB_NICKNAME}"
              disable_certificate_verification = true
            }
          }
        }
      }
      stats {
        enabled = true
      }
    }
    EOFJVB

      # Create sip-communicator.properties with IP harvesting configuration
      cat > /etc/jitsi/videobridge/sip-communicator.properties << EOFPROPS
    org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${LOCALIP}
    org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${MYIP}
    org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER=true
    org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES=
    EOFPROPS

      # Add JVB environment variables as backup
      mkdir -p /etc/systemd/system/jitsi-videobridge2.service.d
      cat > /etc/systemd/system/jitsi-videobridge2.service.d/override.conf << EOFSVC
    [Service]
    Environment="JVB_OPTS=-Dorg.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${MYIP} -Dorg.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${MYIP}"
    EOFSVC
      systemctl daemon-reload
    fi

    # Mini vhost for auth domain serving ACME challenge
    if [ -n "$AUTH_DOMAIN" ]; then
      mkdir -p /usr/share/jitsi-meet/.well-known/acme-challenge
      cat > /etc/nginx/sites-available/auth-challenge.conf << EOFNGA
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

    # If DNS was ready, issue LE for both host and auth using acme.sh
    if [ "$USE_LE" = "1" ]; then
      # Ensure acme.sh is present
      if [ ! -x /opt/acmesh/.acme.sh/acme.sh ]; then
        curl -fsSL https://get.acme.sh | sh -s email="$LE_EMAIL"
      fi
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
      
      $ACME_BIN --set-default-ca --server letsencrypt || true
      
      # Issue certificate
      if [ -n "$AUTH_DOMAIN" ]; then
        $ACME_BIN --issue -d "$HOSTNAME_FQDN" -d "$AUTH_DOMAIN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force || true
      else
        $ACME_BIN --issue -d "$HOSTNAME_FQDN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force || true
      fi
      
      # Install certificate
      $ACME_BIN --install-cert -d "$HOSTNAME_FQDN" \
        --key-file       "/etc/jitsi/meet/$HOSTNAME_FQDN.key" \
        --fullchain-file "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" \
        --reloadcmd "systemctl force-reload nginx.service && /usr/share/jitsi-meet/scripts/coturn-le-update.sh $HOSTNAME_FQDN || true"
      
      # Update cert permissions
      chgrp prosody "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
      chmod 640     "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
      
      # Refresh system/Java trust
      install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt" || true
      update-ca-certificates || true
    fi

    # If self-signed, schedule retries for LE
    if [ "$USE_LE" != "1" ] && [ -n "$LE_EMAIL" ]; then
      cat > /usr/local/bin/jitsi-issue-le.sh << 'EOSRETRY'
    #!/bin/bash
    set -e

    # Check if LE cert already issued
    if [ -f /var/local/jitsi_le_success ]; then
      exit 0
    fi

    META="http://metadata.google.internal/computeMetadata/v1"
    HOSTNAME_FQDN=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/HOSTNAME_FQDN" || true)
    LE_EMAIL=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/attributes/LE_EMAIL" || true)
    MYIP=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/network-interfaces/0/access-configs/0/external-ip" || true)
    DNSIP_HOST=$(dig +short A "$HOSTNAME_FQDN" @1.1.1.1 | head -n1 || true)
    AUTH_DOMAIN="auth.$HOSTNAME_FQDN"
    DNSIP_AUTH=$(dig +short A "$AUTH_DOMAIN" @1.1.1.1 | head -n1 || true)

    if [ -n "$HOSTNAME_FQDN" ] && [ -n "$LE_EMAIL" ] && [ -n "$MYIP" ] && [ "$MYIP" = "$DNSIP_HOST" ] && [ "$MYIP" = "$DNSIP_AUTH" ]; then
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
        curl -fsSL https://get.acme.sh | sh -s email="$LE_EMAIL"
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
        --reloadcmd "systemctl force-reload nginx.service && /usr/share/jitsi-meet/scripts/coturn-le-update.sh $HOSTNAME_FQDN || true"
      
      chgrp prosody "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
      chmod 640     "/etc/jitsi/meet/$HOSTNAME_FQDN.key" || true
      install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt" || true
      update-ca-certificates || true
      systemctl restart prosody jicofo jitsi-videobridge2 || true
      
      # Remove cron job on success
      touch /var/local/jitsi_le_success
      if command -v crontab >/dev/null 2>&1; then
        crontab -l | grep -v 'jitsi-issue-le.sh' | crontab - || true
      fi
    fi
    EOSRETRY
      chmod +x /usr/local/bin/jitsi-issue-le.sh
      if command -v crontab >/dev/null 2>&1; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/jitsi-issue-le.sh >/var/log/jitsi-issue-le.log 2>&1") | crontab - || true
      fi
    fi

    # Create script to update IPs on boot
    cat > /usr/local/bin/update-jitsi-ips.sh << 'EOFIPUPDATE'
    #!/bin/bash
    set -e

    # Wait for metadata server
    sleep 10

    # Get IPs
    META="http://metadata.google.internal/computeMetadata/v1"
    MYIP=$(curl -s -H "Metadata-Flavor: Google" "$META/instance/network-interfaces/0/access-configs/0/external-ip")
    LOCALIP=$(ip route get 1.1.1.1 | awk '{print $7; exit}')

    echo "$(date): Updating IPs - Public: $MYIP, Local: $LOCALIP" >> /var/log/jitsi-ip-update.log

    # Update sip-communicator.properties
    cat > /etc/jitsi/videobridge/sip-communicator.properties << EOFPROPS
    org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${LOCALIP}
    org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${MYIP}
    org.ice4j.ice.harvest.DISABLE_AWS_HARVESTER=true
    org.ice4j.ice.harvest.STUN_MAPPING_HARVESTER_ADDRESSES=
    EOFPROPS

    # Update jvb.conf
    JVB_CONF="/etc/jitsi/videobridge/jvb.conf"
    sed -i "s/publicAddress = \".*\"/publicAddress = \"${MYIP}\"/" "$JVB_CONF"
    sed -i "s/privateAddress = \".*\"/privateAddress = \"${LOCALIP}\"/" "$JVB_CONF"

    # Update systemd override
    mkdir -p /etc/systemd/system/jitsi-videobridge2.service.d
    cat > /etc/systemd/system/jitsi-videobridge2.service.d/override.conf << EOFSVC
    [Service]
    Environment="JVB_OPTS=-Dorg.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${MYIP} -Dorg.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${MYIP}"
    EOFSVC

    systemctl daemon-reload
    systemctl restart jitsi-videobridge2

    echo "$(date): IPs updated successfully" >> /var/log/jitsi-ip-update.log
    EOFIPUPDATE

    chmod +x /usr/local/bin/update-jitsi-ips.sh

    # Create systemd service for IP updates on boot
    cat > /etc/systemd/system/update-jitsi-ips.service << 'EOFIPSERVICE'
    [Unit]
    Description=Update Jitsi IPs on boot
    After=network-online.target google-network-daemon.service
    Wants=network-online.target
    Before=jitsi-videobridge2.service

    [Service]
    Type=oneshot
    ExecStart=/usr/local/bin/update-jitsi-ips.sh
    RemainAfterExit=yes
    TimeoutStartSec=60

    [Install]
    WantedBy=multi-user.target
    EOFIPSERVICE

    systemctl daemon-reload
    systemctl enable update-jitsi-ips.service

    # Restart all services in correct order
    systemctl restart prosody || true
    sleep 5
    systemctl restart jicofo || true
    sleep 3
    systemctl restart jitsi-videobridge2 || true

    # Marker file
    mkdir -p /var/local
    printf '%s\n' "BOOT_DONE=1" > /var/local/jitsi_boot_done

    echo "Jitsi deployment completed successfully"

    # Generar credenciales JWT
    JWT_APP_ID="jitsi_moodle_$(openssl rand -hex 8)"
    JWT_SECRET=$(openssl rand -hex 32)

    # Configurar JWT en Jitsi
    if [ -n "$HOSTNAME_FQDN" ]; then
      # Configurar prosody para JWT
      cat >> "/etc/prosody/conf.avail/${HOSTNAME_FQDN}.cfg.lua" << EOFJWT

    -- JWT authentication
    authentication = "token"
    app_id = "${JWT_APP_ID}"
    app_secret = "${JWT_SECRET}"
    allow_empty_token = false
    EOFJWT

      # Reiniciar servicios
      systemctl restart prosody jicofo jitsi-videobridge2 || true
    fi

    # Notificar a Moodle con las credenciales
    if [ -n "$CALLBACK_URL" ]; then
      echo "Notifying Moodle with credentials..."
      curl -X POST "${CALLBACK_URL}&ip=$MYIP&hostname=$HOSTNAME_FQDN&phase=completed&appid=${JWT_APP_ID}&secret=${JWT_SECRET}" \
        --max-time 10 \
        --retry 3 \
        --retry-delay 5 \
        || echo "Warning: Could not notify Moodle (callback failed)"
    fi

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
        if (!empty($opts['callbackUrl'])) {
            $metadataItems[] = ['key' => 'CALLBACK_URL', 'value' => $opts['callbackUrl']];
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

    // Generar token único para esta VM
    $vmtoken = bin2hex(random_bytes(32));
    $tokenkey = 'mod_jitsi_vmtoken_' . clean_param($instancename, PARAM_ALPHANUMEXT);
    set_config($tokenkey, $vmtoken, 'mod_jitsi');
    
    // URL del callback (debe ser accesible públicamente)
    $callbackurl = (new moodle_url('/mod/jitsi/servermanagement.php', [
        'action' => 'jitsiready',
        'instance' => $instancename,
        'token' => $vmtoken,
    ]))->out(false);

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
            'callbackUrl' => $callbackurl, // Pasar URL al script
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

if ($action === 'checkjitsiready') {
    require_sesskey();
    @header('Content-Type: application/json');
    $instancename = required_param('instance', PARAM_TEXT);
    
    $statuskey = 'mod_jitsi_vmstatus_' . clean_param($instancename, PARAM_ALPHANUMEXT);
    $statusjson = get_config('mod_jitsi', $statuskey);
    
    if (empty($statusjson)) {
        echo json_encode(['status' => 'installing']);
    } else {
        $status = json_decode($statusjson, true);
        if ($status) {
            // Devolver el estado actual con toda la info
            echo json_encode([
                'status' => $status['status'], // puede ser waiting_dns, dns_ready, completed
                'ip' => $status['ip'] ?? '',
                'hostname' => $status['hostname'] ?? '',
            ]);
            
            // Limpiar después de completado y pasado tiempo
            if ($status['status'] === 'completed' && time() - $status['timestamp'] > 300) {
                unset_config($statuskey, 'mod_jitsi');
            }
        } else {
            echo json_encode(['status' => 'installing']);
        }
    }
    exit;
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

// Modal markup (HTML only) - SIN spinner inicial
echo <<<HTML
<div class="modal fade" id="gcpModal" tabindex="-1" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content">
      <div class="modal-body text-center" id="gcp-modal-body">
        <!-- El contenido se inyectará dinámicamente -->
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
    'checkReadyUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'checkjitsiready']))->out(false),
];
$initjson = json_encode($init, JSON_HEX_TAG|JSON_HEX_APOS|JSON_HEX_AMP|JSON_HEX_QUOT);
$PAGE->requires->js_init_code(
    "(function(){\n".
    "  var cfg = ".$initjson.";\n".
    "  var btn = document.getElementById('btn-creategcpvm');\n".
    "  if (!btn) return;\n".
    "  var modalEl = document.getElementById('gcpModal');\n".
    "  var modalBody = document.getElementById('gcp-modal-body');\n".
    "  var backdrop;\n".
    "  var lastWarnHTML = '';\n".
    "  var vmInfo = {};\n".
    "  var dnsWarningShown = false;\n".
    "  function showModal(){\n".
    "    if (!modalEl) return;\n".
    "    modalEl.classList.add('show');\n".
    "    modalEl.style.display = 'block';\n".
    "    modalEl.removeAttribute('aria-hidden');\n".
    "    backdrop = document.createElement('div');\n".
    "    backdrop.className = 'modal-backdrop fade show';\n".
    "    document.body.appendChild(backdrop);\n".
    "  }\n".
    "  async function postJSON(url, data){\n".
    "    var res = await fetch(url, {method: 'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(data)});\n".
    "    if (!res.ok) throw new Error('HTTP ' + res.status);\n".
    "    return await res.json();\n".
    "  }\n".
    "  async function checkJitsiReady(){\n".
    "    try {\n".
    "      console.log('Checking Jitsi ready status for:', vmInfo.instancename);\n".
    "      var data = await postJSON(cfg.checkReadyUrl, {\n".
    "        sesskey: cfg.sesskey,\n".
    "        instance: vmInfo.instancename\n".
    "      });\n".
    "      console.log('Status received:', data);\n".
    "      if (data.status === 'waiting_dns') {\n".
    "        if (!dnsWarningShown) {\n".
    "          dnsWarningShown = true;\n".
    "          var host = data.hostname || cfg.hostname || 'your-hostname.example.com';\n".
    "          var authHost = 'auth.' + host;\n".
    "          var ip = data.ip || vmInfo.ip || '';\n".
    "          if (modalBody) {\n".
    "            modalBody.innerHTML = (\n".
    "              '<div class=\"alert alert-warning\"><h5>⚠️ Action Required: Configure DNS</h5>'+ \n".
    "              '<p><strong>Public IP: <code>'+ ip +'</code></strong></p>'+\n".
    "              '<p>Please create the following DNS A records:</p>'+\n".
    "              '<ul class=\"text-start\">'+\n".
    "                '<li><code>'+ host +' → '+ ip +'</code></li>'+\n".
    "                '<li><code>'+ authHost +' → '+ ip +'</code></li>'+\n".
    "              '</ul>'+\n".
    "              '<p class=\"text-muted\">The installation will continue automatically once DNS propagates (checking every 15 seconds, timeout 15 minutes).</p>'+\n".
    "              '<div id=\"dns-copy-buttons\" class=\"mt-2\">'+\n".
    "                '<button id=\"copy-ip-dns\" class=\"btn btn-sm btn-outline-primary me-2\">Copy IP</button>'+\n".
    "                '<button id=\"copy-records\" class=\"btn btn-sm btn-outline-secondary\">Copy DNS Records</button>'+\n".
    "              '</div>'+\n".
    "              '</div>'+\n".
    "              '<div class=\"text-center\">'+\n".
    "                '<div class=\"spinner-border spinner-border-sm\" role=\"status\"></div>'+\n".
    "                '<p class=\"mt-2\">Waiting for DNS propagation...</p>'+\n".
    "              '</div>'\n".
    "            );\n".
    "            var copyIpBtn = document.getElementById('copy-ip-dns');\n".
    "            var copyRecordsBtn = document.getElementById('copy-records');\n".
    "            if (copyIpBtn && navigator.clipboard) {\n".
    "              copyIpBtn.addEventListener('click', function(){ \n".
    "                navigator.clipboard.writeText(ip);\n".
    "                copyIpBtn.textContent = '✓ Copied!';\n".
    "                setTimeout(function(){ copyIpBtn.textContent = 'Copy IP'; }, 2000);\n".
    "              });\n".
    "            }\n".
    "            if (copyRecordsBtn && navigator.clipboard) {\n".
    "              copyRecordsBtn.addEventListener('click', function(){ \n".
    "                var records = host + ' A ' + ip + '\\\\n' + authHost + ' A ' + ip;\n".
    "                navigator.clipboard.writeText(records);\n".
    "                copyRecordsBtn.textContent = '✓ Copied!';\n".
    "                setTimeout(function(){ copyRecordsBtn.textContent = 'Copy DNS Records'; }, 2000);\n".
    "              });\n".
    "            }\n".
    "          }\n".
    "        }\n".
    "        setTimeout(checkJitsiReady, 10000);\n".
    "      } else if (data.status === 'dns_ready') {\n".
    "        if (modalBody) {\n".
    "          modalBody.innerHTML = (\n".
    "            '<h5>✅ DNS Configured!</h5>'+ \n".
    "            '<p class=\"text-success\">DNS records detected. Starting Jitsi installation...</p>'+\n".
    "            '<div class=\"text-center\">'+\n".
    "              '<div class=\"spinner-border spinner-border-sm\" role=\"status\"></div>'+\n".
    "            '</div>'\n".
    "          );\n".
    "        }\n".
    "        setTimeout(checkJitsiReady, 5000);\n".
    "      } else if (data.status === 'installing') {\n".
    "        if (modalBody) {\n".
    "          modalBody.innerHTML = (\n".
    "            '<h5>⚙️ Installing Jitsi Meet...</h5>'+ \n".
    "            '<p>The VM is ready. Installing and configuring Jitsi services.</p>'+\n".
    "            '<p class=\"text-muted\">This takes 8-12 minutes. Please wait...</p>'+\n".
    "            '<div class=\"text-center\">'+\n".
    "              '<div class=\"spinner-border spinner-border-sm\" role=\"status\"></div>'+\n".
    "            '</div>'\n".
    "          );\n".
    "        }\n".
    "        setTimeout(checkJitsiReady, 10000);\n".
    "      } else if (data.status === 'completed') {\n".
    "        showSuccessMessage(data.ip, data.hostname);\n".
    "      }\n".
    "    } catch(e){\n".
    "      console.error('Check ready error:', e);\n".
    "      if (modalBody) modalBody.innerHTML = '<p class=\"text-warning\">Cannot verify status. Check the VM console.</p>';\n".
    "    }\n".
    "  }\n".
    "  function showSuccessMessage(ip, hostname){\n".
    "    var host = hostname || cfg.hostname || 'your-hostname.example.com';\n".
    "    if (modalBody) {\n".
    "      modalBody.innerHTML = (\n".
    "        '<h5>✅ Jitsi Server Ready & Registered!</h5>'+ \n".
    "        '<p class=\"text-success\"><strong>Installation completed and server registered in Moodle</strong></p>'+ \n".
    "        '<p>Public IP: <strong>'+ ip +'</strong></p>'+\n".
    "        '<p>Your Jitsi Meet server is ready at: <code>https://'+ host +'</code></p>'+\n".
    "        '<div class=\"mt-3\">'+\n".
    "          '<button id=\"copy-ip\" class=\"btn btn-outline-secondary me-2\">Copy IP</button>'+\n".
    "          '<a href=\"'+ cfg.listUrl +'\" class=\"btn btn-primary\">Close</a>'+\n".
    "        '</div>'\n".
    "      );\n".
    "      var copyBtn = document.getElementById('copy-ip');\n".
    "      if (copyBtn && navigator.clipboard) {\n".
    "        copyBtn.addEventListener('click', function(){ \n".
    "          navigator.clipboard.writeText(ip);\n".
    "          copyBtn.textContent = '✓ Copied!';\n".
    "          setTimeout(function(){ copyBtn.textContent = 'Copy IP'; }, 2000);\n".
    "        });\n".
    "      }\n".
    "    }\n".
    "  }\n".
    "  async function pollStatus(opname){\n".
    "    try {\n".
    "      var data = await postJSON(cfg.statusUrl, {sesskey: cfg.sesskey, opname: opname});\n".
    "      if (data.status === 'pending') {\n".
    "        setTimeout(function(){ pollStatus(opname); }, 1500);\n".
    "      } else if (data.status === 'done') {\n".
    "        vmInfo.ip = (data.ip || '');\n".
    "        if (modalBody) {\n".
    "          modalBody.innerHTML = (\n".
    "            '<h5>⚙️ VM Created - Starting Configuration...</h5>'+ \n".
    "            '<p>Checking installation status...</p>'+\n".
    "            '<div class=\"text-center\">'+\n".
    "              '<div class=\"spinner-border spinner-border-sm\" role=\"status\"></div>'+\n".
    "            '</div>'\n".
    "          );\n".
    "        }\n".
    "        setTimeout(checkJitsiReady, 3000);\n".
    "      } else {\n".
    "        if (modalBody) modalBody.textContent = 'Error: ' + (data.message || 'Unknown');\n".
    "      }\n".
    "    } catch(e){\n".
    "      if (modalBody) modalBody.textContent = 'Error: ' + e.message;\n".
    "    }\n".
    "  }\n".
    "  btn.addEventListener('click', async function(){\n".
    "    showModal();\n".
    "    if (modalBody) {\n".
    "      modalBody.innerHTML = (\n".
    "        '<h5>⏳ Creating VM...</h5>'+\n".
    "        '<p>Setting up infrastructure in Google Cloud.</p>'+\n".
    "        '<div class=\"text-center\">'+\n".
    "          '<div class=\"spinner-border spinner-border-sm\" role=\"status\"></div>'+\n".
    "        '</div>'\n".
    "      );\n".
    "    }\n".
    "    try {\n".
    "      var data = await postJSON(cfg.createUrl, {sesskey: cfg.sesskey});\n".
    "      if (data && data.status === 'pending' && data.opname){\n".
    "               vmInfo.instancename = data.instancename;\n".
    "        console.log('VM instance name:', vmInfo.instancename);\n".
    "        pollStatus(data.opname);\n".
    "      } else {\n".
    "        if (modalBody) modalBody.textContent = 'Error starting VM creation';\n".
    "      }\n".
    "    } catch(e){\n".
    "      if (modalBody) modalBody.textContent = 'Error: ' + e.message;\n".
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
