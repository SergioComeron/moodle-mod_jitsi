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
 * Startup scripts for GCP-provisioned Jitsi and Jibri virtual machines.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\local;

// phpcs:disable moodle.Files.LineLength.MaxExceeded, moodle.Files.LineLength.TooLong

/**
 * Bash startup scripts injected as GCP instance metadata at VM creation time.
 *
 * Extracted verbatim from servermanagement.php — do not reformat the heredoc
 * bodies: their content is executed as-is by cloud-init on Debian 12.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class gcp_scripts {
    /**
     * Built-in startup script that installs Jitsi Meet on Debian 12.
     *
     * Reads HOSTNAME_FQDN and LE_EMAIL from instance metadata. If DNS already
     * points to the VM public IP it uses Let's Encrypt, otherwise it installs
     * a self-signed cert and schedules retries for LE.
     *
     * @return string
     */
    public static function default_startup_script(): string {
        return <<<'BASH'
        #!/bin/bash

        # Skip full provisioning if already done (subsequent reboots)
        if [ -f /var/local/jitsi_boot_done ]; then
            echo "Already provisioned, skipping startup script"
            exit 0
        fi

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

        # Error handler - notify Moodle if script fails
        exit_handler() {
        local exit_code=$?
        if [ $exit_code -ne 0 ]; then
            echo "ERROR: Script exited with code $exit_code"
            if [ -n "$CALLBACK_URL" ]; then
            local error_msg="Installation failed with exit code $exit_code. Check VM logs for details."
            curl -X POST "${CALLBACK_URL}&ip=${MYIP}&hostname=${HOSTNAME_FQDN}&phase=error&error=$(echo "$error_msg" | sed 's/ /%20/g')" \
                --max-time 10 --retry 3 --retry-delay 3 || true
            fi
        fi
        }

        # Set trap to catch all exits (success or failure)
        trap exit_handler EXIT

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
        apt-get install -y curl gnupg2 apt-transport-https ca-certificates ca-certificates-java nginx ufw dnsutils cron luarocks

        # Install Lua inspect library (required for JWT token authentication in Prosody)
        luarocks install inspect

        # Ensure inspect.lua is available for Lua 5.4 (Prosody uses 5.4, but luarocks may install for 5.1)
        mkdir -p /usr/share/lua/5.4/
        # Try to copy from the location where luarocks actually installs it
        if [ -f /usr/share/lua/5.1/inspect.lua ]; then
        cp /usr/share/lua/5.1/inspect.lua /usr/share/lua/5.4/
        elif [ -f /usr/local/share/lua/5.1/inspect.lua ]; then
        cp /usr/local/share/lua/5.1/inspect.lua /usr/share/lua/5.4/
        fi

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
            enable-auto-owner = false
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
        Environment="JVB_OPTS=-Dorg.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${LOCALIP} -Dorg.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${MYIP}"
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

        # Try Let's Encrypt if DNS is ready
        if [ "$USE_LE" = "1" ]; then
        echo "DNS is ready, attempting Let's Encrypt certificate..."

        # Install acme.sh if not present
        # Ensure HOME is set to /root for proper installation
        export HOME=/root

        if [ ! -f "/root/.acme.sh/acme.sh" ] && [ ! -f "/.acme.sh/acme.sh" ]; then
            curl -fsSL https://get.acme.sh | sh -s email="$LE_EMAIL"
            sleep 2
        fi

        # Detect where acme.sh was actually installed
        ACME_PATH="/root/.acme.sh"
        if [ ! -f "$ACME_PATH/acme.sh" ]; then
            if [ -f "/.acme.sh/acme.sh" ]; then
            ACME_PATH="/.acme.sh"
            echo "acme.sh installed at /.acme.sh (moving to /root/.acme.sh)"
            mv /.acme.sh /root/
            ACME_PATH="/root/.acme.sh"
            else
            echo "ERROR: Failed to install acme.sh"
            exit 1
            fi
        fi

        # Set up acme.sh
        export LE_WORKING_DIR="$ACME_PATH"
        $ACME_PATH/acme.sh --set-default-ca --server letsencrypt

        # Issue certificate for both domains
        if [ -n "$AUTH_DOMAIN" ]; then
            $ACME_PATH/acme.sh --issue -d "$HOSTNAME_FQDN" -d "$AUTH_DOMAIN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force
        else
            $ACME_PATH/acme.sh --issue -d "$HOSTNAME_FQDN" --webroot /usr/share/jitsi-meet --keylength ec-256 --force
        fi

        # Install certificate
        $ACME_PATH/acme.sh --install-cert -d "$HOSTNAME_FQDN" \
            --key-file       "/etc/jitsi/meet/$HOSTNAME_FQDN.key" \
            --fullchain-file "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" \
            --reloadcmd "systemctl force-reload nginx.service"

        # Set permissions
        chgrp prosody "/etc/jitsi/meet/$HOSTNAME_FQDN.key"
        chmod 640     "/etc/jitsi/meet/$HOSTNAME_FQDN.key"
        install -D -m 0644 "/etc/jitsi/meet/$HOSTNAME_FQDN.crt" "/usr/local/share/ca-certificates/jitsi-$HOSTNAME_FQDN.crt"
        update-ca-certificates

        echo "Let's Encrypt certificate installed successfully"
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
        Environment="JVB_OPTS=-Dorg.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${LOCALIP} -Dorg.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${MYIP}"
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

        # Ensure Jicofo starts after JVB is registered (race condition fix)
        mkdir -p /etc/systemd/system/jicofo.service.d
        cat > /etc/systemd/system/jicofo.service.d/override.conf << EOFJICOFOD
        [Unit]
        After=jitsi-videobridge2.service

        [Service]
        ExecStartPre=/bin/sleep 30
        EOFJICOFOD
        systemctl daemon-reload

        # Restart all services in correct order
        systemctl restart prosody || true
        sleep 5
        systemctl restart jitsi-videobridge2 || true
        sleep 30
        systemctl restart jicofo || true

        # Marker file
        mkdir -p /var/local
        printf '%s\n' "BOOT_DONE=1" > /var/local/jitsi_boot_done

        echo "Jitsi deployment completed successfully"

        # Generar credenciales JWT
        JWT_APP_ID="jitsi_moodle_$(openssl rand -hex 8)"
        JWT_SECRET=$(openssl rand -hex 32)

        # Configurar JWT en Jitsi (usando Python para modificación fiable del vhost de Prosody)
        if [ -n "$HOSTNAME_FQDN" ] && [ -f "/etc/prosody/conf.avail/${HOSTNAME_FQDN}.cfg.lua" ]; then

        python3 << PYEOF
        import re
        vhost_file = "/etc/prosody/conf.avail/${HOSTNAME_FQDN}.cfg.lua"
        with open(vhost_file, "r") as f:
            content = f.read()
        new_auth = (
            'authentication = "token"\n'
            '    app_id = "${JWT_APP_ID}"\n'
            '    app_secret = "${JWT_SECRET}"\n'
            '    allow_empty_token = false'
        )
        content = re.sub(r'authentication\s*=\s*"jitsi-anonymous"[^\n]*', new_auth, content)
        content = content.replace('--"token_verification"', '"token_verification"')
        if '"token_owner_party"' not in content:
            pattern = r'(Component\s+"conference\.[^"]+"\s+"muc".*?modules_enabled\s*=\s*\{)'
            def add_modules(m):
                return m.group(1) + '\n        "token_verification";\n        "token_owner_party";'
            content = re.sub(pattern, add_modules, content, count=1, flags=re.DOTALL)
        with open(vhost_file, "w") as f:
            f.write(content)
        print("Prosody vhost configurado para JWT con token_owner_party")
        PYEOF

        # Crear mod_token_owner_party.lua si no existe en esta version de jitsi-meet
        MODULE_PATH="/usr/share/jitsi-meet/prosody-plugins/mod_token_owner_party.lua"
        if [ ! -f "$MODULE_PATH" ]; then
        cat > "$MODULE_PATH" << 'EOFLUA'
        -- mod_token_owner_party.lua
        -- Reads context.user.moderator from JWT and assigns owner affiliation.
        -- Replacement for the module missing in newer jitsi-meet versions.
        module:log('info', 'mod_token_owner_party loaded');
        module:hook('muc-occupant-joined', function(event)
            local room, occupant, session = event.room, event.occupant, event.origin;
            if not session or not session.auth_token then return; end
            local context_user = session.jitsi_meet_context_user;
            if context_user then
                local is_mod = context_user['moderator'];
                if is_mod == true or is_mod == 'true' then
                    room:set_affiliation(true, occupant.bare_jid, 'owner');
                end
            end
        end, 2);
        EOFLUA
        echo "mod_token_owner_party.lua created"
        fi

        # Reiniciar servicios con la nueva configuracion
        systemctl restart prosody || true
        sleep 5
        systemctl restart jitsi-videobridge2 || true
        sleep 30
        systemctl restart jicofo || true
        fi

        # Configurar Prosody y Jicofo para Jibri si se ha solicitado
        ENABLE_JIBRI=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/ENABLE_JIBRI" || true)
        JIBRI_XMPP_PASS=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/JIBRI_XMPP_PASS" || true)
        JIBRI_RECORDER_PASS=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/JIBRI_RECORDER_PASS" || true)

        if [ "$ENABLE_JIBRI" = "1" ] && [ -n "$HOSTNAME_FQDN" ] && [ -n "$AUTH_DOMAIN" ]; then
        echo "Configuring Prosody and Jicofo for Jibri..."

        # Register Jibri XMPP users in Prosody
        prosodyctl register jibri "$AUTH_DOMAIN" "$JIBRI_XMPP_PASS" 2>/dev/null || true
        prosodyctl register recorder "recorder.$HOSTNAME_FQDN" "$JIBRI_RECORDER_PASS" 2>/dev/null || true

        # Add recorder virtual host to Prosody config
        RECORDER_VHOST="/etc/prosody/conf.avail/recorder.${HOSTNAME_FQDN}.cfg.lua"
        cat > "$RECORDER_VHOST" << EOFRECVHOST
        VirtualHost "recorder.${HOSTNAME_FQDN}"
          modules_enabled = {
            "ping";
          }
          authentication = "internal_hashed"
        EOFRECVHOST
        ln -sf "$RECORDER_VHOST" "/etc/prosody/conf.d/recorder.${HOSTNAME_FQDN}.cfg.lua" || true

        # Enable token_affiliation and muc_lobby in main vhost if present
        VHOST_FILE="/etc/prosody/conf.avail/${HOSTNAME_FQDN}.cfg.lua"
        if [ -f "$VHOST_FILE" ]; then
            # Add jibri to trusted_senders in main MUC component if not already there
            python3 << PYJIBRI
        import re
        vf = "${VHOST_FILE}"
        with open(vf) as f:
            c = f.read()
        # Add "token_affiliation" module to conference MUC if not present
        if '"token_affiliation"' not in c:
            c = re.sub(
                r'(Component\s+"conference\.[^"]+"\s+"muc".*?modules_enabled\s*=\s*\{)',
                lambda m: m.group(1) + '\n        "token_affiliation";',
                c, count=1, flags=re.DOTALL
            )
        with open(vf, 'w') as f:
            f.write(c)
        print("Prosody vhost updated for Jibri")
        PYJIBRI
        fi

        # Extend Jicofo config to know about Jibri
        JICOFO_CONF="/etc/jitsi/jicofo/jicofo.conf"
        if [ -f "$JICOFO_CONF" ] && ! grep -q "jibri" "$JICOFO_CONF"; then
            # Append Jibri brewery config
            python3 << PYJICOFO
        import re
        with open("${JICOFO_CONF}") as f:
            c = f.read()
        # Inject jibri section before the closing brace of the top-level jicofo { block
        jibri_block = """
          jibri {
            brewery-jid = "JibriBrewery@internal.${AUTH_DOMAIN}"
            pending-timeout = 90 seconds
          }
        """
        # Insert before the last closing brace
        idx = c.rfind('}')
        if idx != -1 and 'JibriBrewery' not in c:
            c = c[:idx] + jibri_block + c[idx:]
        with open("${JICOFO_CONF}", 'w') as f:
            f.write(c)
        print("Jicofo updated with Jibri brewery")
        PYJICOFO
        fi

        # Open XMPP port 5222 for Jibri (already open from ufw allow earlier, but be explicit)
        ufw allow 5222/tcp || true

        # Set hiddenDomain and enable liveStreaming in Jitsi Meet config.
        # Uses Python to avoid sed multiline issues.
        MEET_CONFIG="/etc/jitsi/meet/${HOSTNAME_FQDN}-config.js"
        if [ -f "$MEET_CONFIG" ]; then
            python3 << PYJITSICFG
        import re
        f = '${MEET_CONFIG}'
        with open(f) as fh:
            c = fh.read()
        # hiddenDomain inside hosts{}
        old_muc = "muc: 'conference.' + subdomain + '${HOSTNAME_FQDN}',"
        new_muc = old_muc + "\n        hiddenDomain: 'recorder.${HOSTNAME_FQDN}',"
        if 'hiddenDomain' not in c:
            c = c.replace(old_muc, new_muc, 1)
        # hiddenDomain + liveStreaming at top level (insert before closing }; of config object)
        if 'liveStreaming: { enabled: true }' not in c:
            idx = c.find('\n};')
            if idx != -1:
                insert = "\n    hiddenDomain: 'recorder.${HOSTNAME_FQDN}',\n    liveStreaming: { enabled: true },"
                c = c[:idx] + insert + c[idx:]
        with open(f, 'w') as fh:
            fh.write(c)
        print('Jitsi Meet config updated')
        PYJITSICFG
        fi

        # Restart services to apply Jibri configuration
        systemctl restart prosody || true
        sleep 5
        systemctl restart jicofo || true
        sleep 10

        echo "Jibri Prosody/Jicofo configuration complete"
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

    /**
     * Startup script for the dedicated Jibri recording VM (Debian 12).
     *
     * Reads JITSI_HOSTNAME, JIBRI_XMPP_PASS, JIBRI_RECORDER_PASS and
     * CALLBACK_URL from instance metadata.
     *
     * @return string
     */
    public static function jibri_startup_script(): string {
        return <<<'BASH'
        #!/bin/bash

        # Skip if already fully provisioned
        if [ -f /var/local/jibri_boot_done ]; then
            echo "Jibri already provisioned, skipping"
            exit 0
        fi

        export DEBIAN_FRONTEND=noninteractive

        META="http://metadata.google.internal/computeMetadata/v1"
        CALLBACK_URL=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/CALLBACK_URL" || true)

        # Error handler — defined before set -e so it always runs
        exit_handler() {
            local exit_code=$?
            if [ $exit_code -ne 0 ] && [ -n "$CALLBACK_URL" ]; then
                local err="Jibri installation failed with exit code $exit_code"
                curl -X POST "${CALLBACK_URL}&phase=error&error=$(echo "$err" | sed 's/ /%20/g')" \
                    --max-time 10 --retry 3 --retry-delay 3 || true
            fi
        }
        trap exit_handler EXIT

        set -euxo pipefail

        # Phase 1: install basic packages + generic kernel, then reboot so snd-aloop is available.
        # The GCP startup script re-runs on every boot until the VM is stopped/deleted.
        if [ ! -f /var/local/jibri_phase1_done ]; then
            if [ -n "$CALLBACK_URL" ]; then
                curl -X POST "${CALLBACK_URL}&phase=installing" --max-time 10 --retry 2 || true
            fi

            apt-get update -y
            apt-get install -y curl gnupg2 apt-transport-https ca-certificates ca-certificates-java \
                linux-image-amd64 linux-headers-amd64 alsa-utils unzip nginx

            # Remove the GCP cloud kernel so GRUB boots the generic kernel (which has snd-aloop)
            CLOUD_PKGS=$(dpkg -l 'linux-image-*-cloud-amd64' 2>/dev/null | awk '/^ii/{print $2}' | tr '\n' ' ' || true)
            if [ -n "$CLOUD_PKGS" ]; then
                # shellcheck disable=SC2086
                apt-get remove -y $CLOUD_PKGS || true
                apt-get autoremove -y || true
            fi
            update-grub || true

            # Make snd-aloop load automatically on next boot (generic kernel includes it)
            echo "snd-aloop" >> /etc/modules

            mkdir -p /var/local
            touch /var/local/jibri_phase1_done

            # Reboot into the generic kernel (which includes snd-aloop)
            reboot
            exit 0
        fi

        # Phase 2: running with generic kernel — snd-aloop is now available.
        JITSI_HOSTNAME=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/JITSI_HOSTNAME" || true)
        JITSI_INTERNAL_IP=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/JITSI_INTERNAL_IP" || true)
        JIBRI_XMPP_PASS=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/JIBRI_XMPP_PASS" || true)
        JIBRI_RECORDER_PASS=$(curl -sf -H "Metadata-Flavor: Google" "$META/instance/attributes/JIBRI_RECORDER_PASS" || true)

        AUTH_DOMAIN="auth.${JITSI_HOSTNAME}"
        RECORDER_DOMAIN="recorder.${JITSI_HOSTNAME}"

        # Route Jitsi hostnames to the internal IP to avoid GCP NAT-loopback issues
        # (Jibri must reach Jitsi via VPC, not via its public IP).
        if [ -n "$JITSI_INTERNAL_IP" ]; then
            echo "$JITSI_INTERNAL_IP $JITSI_HOSTNAME $AUTH_DOMAIN $RECORDER_DOMAIN" >> /etc/hosts
        fi

        # Load snd-aloop (succeeds with the generic kernel loaded after phase-1 reboot)
        modprobe snd-aloop

        # Install Java 17 (Jibri requires Java 11+; Java 17 is the available version on Debian 12)
        apt-get install -y openjdk-17-jre-headless

        # Jitsi repository for Jibri
        curl https://download.jitsi.org/jitsi-key.gpg.key | gpg --dearmor > /usr/share/keyrings/jitsi.gpg
        echo 'deb [signed-by=/usr/share/keyrings/jitsi.gpg] https://download.jitsi.org stable/' > /etc/apt/sources.list.d/jitsi-stable.list
        apt-get update -y

        # Install Jibri (no Jitsi Meet, just Jibri)
        apt-get install -y jibri

        # Install Google Chrome — Jibri requires /usr/bin/google-chrome.
        # Chromium from Debian 12 repos has dependency conflicts with jibri packages.
        wget -q -O /tmp/google-chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
        apt-get install -y /tmp/google-chrome.deb
        rm -f /tmp/google-chrome.deb

        # Wrap the real Chrome binary to strip --enable-automation (added by ChromeDriver).
        # ChromeDriver calls /opt/google/chrome/chrome directly (not the /usr/bin symlink),
        # so we must wrap that binary. Without this, a "Chrome is being controlled by
        # automated test software" infobar appears at the top of every Jibri recording.
        mv /opt/google/chrome/chrome /opt/google/chrome/chrome-real
        cat > /opt/google/chrome/chrome << 'EOFCHROMEWRAP'
        #!/bin/bash
        ARGS=()
        for arg in "$@"; do
            [[ "$arg" == "--enable-automation" ]] && continue
            ARGS+=("$arg")
        done
        exec /opt/google/chrome/chrome-real "${ARGS[@]}"
        EOFCHROMEWRAP
        chmod +x /opt/google/chrome/chrome

        # Install matching ChromeDriver (Jibri uses Selenium to drive Chrome).
        CHROME_VER=$(google-chrome --version | grep -oP '\d+\.\d+\.\d+\.\d+')
        wget -q -O /tmp/chromedriver.zip \
            "https://storage.googleapis.com/chrome-for-testing-public/${CHROME_VER}/linux64/chromedriver-linux64.zip"
        unzip -o /tmp/chromedriver.zip -d /tmp/
        mv /tmp/chromedriver-linux64/chromedriver /usr/local/bin/chromedriver
        chmod +x /usr/local/bin/chromedriver
        rm -f /tmp/chromedriver.zip

        # Install ffmpeg and Xvfb (virtual framebuffer for headless Chrome)
        apt-get install -y ffmpeg xvfb x11-xserver-utils

        # Jibri configuration
        mkdir -p /etc/jitsi/jibri /srv/recordings
        chown jibri:jibri /srv/recordings 2>/dev/null || true

        cat > /etc/jitsi/jibri/jibri.conf << EOFJIBRICONF
        jibri {
          id = ""
          single-use-mode = false

          api {
            http {
              host = "127.0.0.1"
              port = 2222
            }
            xmpp {
              environments = [
                {
                  name = "prod"
                  xmpp-server-hosts = ["${JITSI_HOSTNAME}"]
                  xmpp-domain = "${JITSI_HOSTNAME}"

                  control-muc {
                    domain = "internal.${AUTH_DOMAIN}"
                    room-name = "JibriBrewery"
                    nickname = "jibri-$(hostname)"
                  }

                  control-login {
                    domain = "${AUTH_DOMAIN}"
                    username = "jibri"
                    password = "${JIBRI_XMPP_PASS}"
                  }

                  call-login {
                    domain = "${RECORDER_DOMAIN}"
                    username = "recorder"
                    password = "${JIBRI_RECORDER_PASS}"
                  }

                  strip-from-room-domain = "conference."
                  usage-timeout = 0
                  trust-all-xmpp-certs = true
                }
              ]
            }
          }

          recording {
            recordings-directory = "/srv/recordings"
            finalize-script = ""
          }

          streaming {
            rtmp-allow-list = [".*"]
          }

          ffmpeg {
            resolution = "1920x1080"
            audio-source = "alsa"
            audio-device = "plug:bsnoop"
          }

          chrome {
            flags = [
              "--use-fake-ui-for-media-stream",
              "--start-maximized",
              "--kiosk",
              "--enabled",
              "--disable-blink-features=AutomationControlled",
              "--autoplay-policy=no-user-gesture-required",
              "--ignore-certificate-errors"
            ]
          }

          stats {
            enable-stats-d = false
          }
        }
        EOFJIBRICONF

        chown jibri:jibri /etc/jitsi/jibri/jibri.conf 2>/dev/null || true
        chmod 640 /etc/jitsi/jibri/jibri.conf

        # Serve recordings via nginx at /recordings/
        JIBRI_MYIP=$(curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" || true)
        cat > /etc/nginx/sites-available/jibri-recordings.conf << 'EOFNGINX'
        server {
            listen 80 default_server;
            listen [::]:80 default_server;
            server_name _;

            location /recordings/ {
                alias /srv/recordings/;
                autoindex off;
                add_header Content-Disposition "attachment";
            }

            location /delete-recording {
                proxy_pass http://127.0.0.1:8099;
                proxy_read_timeout 10s;
            }

            location / {
                return 404;
            }
        }
        EOFNGINX
        rm -f /etc/nginx/sites-enabled/default
        ln -sf /etc/nginx/sites-available/jibri-recordings.conf /etc/nginx/sites-enabled/jibri-recordings.conf
        nginx -t && systemctl restart nginx || true

        # Create Jibri finalize script to notify Moodle when a recording is ready
        # Re-read metadata for finalize script generation (static values embedded at provision time)
        META_FIN="http://metadata.google.internal/computeMetadata/v1"
        FIN_SERVER_ID=$(curl -sf -H "Metadata-Flavor: Google" "$META_FIN/instance/attributes/JIBRI_SERVER_ID" || echo "0")
        FIN_TOKEN=$(curl -sf -H "Metadata-Flavor: Google" "$META_FIN/instance/attributes/JIBRI_TOKEN" || echo "")
        FIN_MOODLE_URL=$(curl -sf -H "Metadata-Flavor: Google" "$META_FIN/instance/attributes/JIBRI_MOODLE_URL" || echo "")

        cat > /usr/local/bin/jibri-finalize.sh << EOFFINALIZE
        #!/bin/bash
        # Jibri finalize script — called when a recording is complete.
        # Arguments: \$1 = recording directory
        set -e
        RECORDING_DIR="\$1"
        if [ -z "\$RECORDING_DIR" ]; then exit 0; fi

        # Find the latest MP4 in the recording directory
        RECFILE=\$(ls -t "\$RECORDING_DIR"/*.mp4 2>/dev/null | head -1 || true)
        if [ -z "\$RECFILE" ]; then
            echo "No MP4 found in \$RECORDING_DIR"
            exit 0
        fi

        # Move file to /srv/recordings for serving
        FILENAME=\$(basename "\$RECFILE")
        mv "\$RECFILE" "/srv/recordings/\$FILENAME" || cp "\$RECFILE" "/srv/recordings/\$FILENAME"

        # Extract room name from filename (strip trailing _YYYY-MM-DD-HH-MM-SS.mp4)
        ROOM=\$(echo "\$FILENAME" | sed 's/_[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}-[0-9]\{2\}\.mp4\$//')

        # Notify Moodle
        MOODLE_URL="${FIN_MOODLE_URL}"
        SERVERID="${FIN_SERVER_ID}"
        TOKEN="${FIN_TOKEN}"

        # Read pool entry ID from monitor script (set per-VM at boot time)
        POOL_ENTRY_ID=\$(grep "^POOL_ENTRY_ID=" /usr/local/bin/jibri-monitor.sh 2>/dev/null | cut -d'"' -f2 || echo "")

        # Upload to GCS if enabled, otherwise serve from VM disk
        GCS_BUCKET=\$(curl -sf -H "Metadata-Flavor: Google" \
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/GCS_BUCKET" || echo "")
        if [ -n "\$GCS_BUCKET" ]; then
            gsutil cp -a public-read "/srv/recordings/\$FILENAME" "gs://\$GCS_BUCKET/\$FILENAME"
            REC_URL="https://storage.googleapis.com/\$GCS_BUCKET/\$FILENAME"
        else
            # Read own external IP dynamically from GCP metadata so it stays correct after stop/start
            MYIP=\$(curl -sf -H "Metadata-Flavor: Google" \
                "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip" || echo "")
            REC_URL="http://\${MYIP}/recordings/\${FILENAME}"
        fi

        if [ -n "\$MOODLE_URL" ]; then
            curl -X POST "\${MOODLE_URL}" \
                --data-urlencode "serverid=\${SERVERID}" \
                --data-urlencode "token=\${TOKEN}" \
                --data-urlencode "room=\${ROOM}" \
                --data-urlencode "filename=\${FILENAME}" \
                --data-urlencode "url=\${REC_URL}" \
                --data-urlencode "poolentryid=\${POOL_ENTRY_ID}" \
                --max-time 30 --retry 3 --retry-delay 5 \
                || echo "Warning: Could not notify Moodle"
        fi

        echo "Recording finalized: \$REC_URL"
        EOFFINALIZE

        chmod +x /usr/local/bin/jibri-finalize.sh

        # Create delete-recording HTTP service (for physical file removal when Moodle deletes a recording)
        mkdir -p /etc/jibri
        echo "${FIN_TOKEN}" > /etc/jibri/delete-token
        chmod 600 /etc/jibri/delete-token

        cat > /usr/local/bin/jibri-delete-server.py << 'EOFDEL'
        #!/usr/bin/env python3
        import http.server
        import urllib.parse
        import os
        TOKEN_FILE = '/etc/jibri/delete-token'
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != '/delete-recording':
                    self.send_response(404)
                    self.end_headers()
                    return
                try:
                    with open(TOKEN_FILE) as fh:
                        expected = fh.read().strip()
                except Exception:
                    self.send_response(500)
                    self.end_headers()
                    return
                params = urllib.parse.parse_qs(parsed.query)
                token = params.get('token', [''])[0]
                filename = params.get('file', [''])[0]
                if token != expected:
                    self.send_response(403)
                    self.end_headers()
                    return
                filename = os.path.basename(filename)
                if not filename:
                    self.send_response(400)
                    self.end_headers()
                    return
                filepath = '/srv/recordings/' + filename
                if os.path.isfile(filepath):
                    os.remove(filepath)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'OK')
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'Not found')
            def log_message(self, fmt, *args):
                pass
        if __name__ == '__main__':
            http.server.HTTPServer(('127.0.0.1', 8099), Handler).serve_forever()
        EOFDEL
        chmod +x /usr/local/bin/jibri-delete-server.py

        cat > /etc/systemd/system/jibri-delete.service << 'EOFSVC'
        [Unit]
        Description=Jibri Delete Recording Service
        After=network.target

        [Service]
        ExecStart=/usr/bin/python3 /usr/local/bin/jibri-delete-server.py
        Restart=always
        User=root

        [Install]
        WantedBy=multi-user.target
        EOFSVC
        systemctl daemon-reload
        systemctl enable jibri-delete
        systemctl start jibri-delete

        # Ensure gsutil can authenticate as both root and jibri user.
        # New VMs have the default compute SA attached (ADC works automatically).
        # This service handles the jibri user's gcloud config on every boot.
        cat > /etc/systemd/system/gcs-auth.service << 'EOFGCSAUTH'
        [Unit]
        Description=Activate GCS credentials for root and jibri user
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart=/bin/bash -c "gcloud auth application-default print-access-token > /dev/null 2>&1 || true"
        ExecStart=/bin/su -s /bin/bash -c "gcloud auth application-default print-access-token > /dev/null 2>&1 || true" jibri
        RemainAfterExit=yes

        [Install]
        WantedBy=multi-user.target
        EOFGCSAUTH
        systemctl daemon-reload
        systemctl enable gcs-auth
        systemctl start gcs-auth

        # Update Jibri config to use the finalize script
        sed -i 's|finalize-script = ""|finalize-script = "/usr/local/bin/jibri-finalize.sh"|' /etc/jitsi/jibri/jibri.conf || true

        # Enable and start Jibri
        systemctl daemon-reload
        systemctl enable jibri
        systemctl start jibri

        # Install Jibri status monitor — polls local health API and reports recording state to Moodle
        META_MON="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
        MON_SERVER_ID=$(curl -sf -H "Metadata-Flavor: Google" "$META_MON/JIBRI_SERVER_ID" || echo "")
        MON_TOKEN=$(curl -sf -H "Metadata-Flavor: Google" "$META_MON/JIBRI_TOKEN" || echo "")
        MON_POOL_ENTRY=$(curl -sf -H "Metadata-Flavor: Google" "$META_MON/JIBRI_POOL_ENTRY_ID" || echo "")
        MON_MOODLE_URL=$(curl -sf -H "Metadata-Flavor: Google" "$META_MON/JIBRI_MOODLE_URL" || echo "")
        MON_BASE_URL=$(echo "$MON_MOODLE_URL" | grep -oP 'https?://[^/]+')

        cat > /usr/local/bin/jibri-monitor.sh << EOFMON
        #!/bin/bash
        BASE_URL="${MON_BASE_URL}"
        SERVER_ID="${MON_SERVER_ID}"
        TOKEN="${MON_TOKEN}"
        POOL_ENTRY_ID="${MON_POOL_ENTRY}"
        LAST_STATUS=""

        while true; do
            HEALTH=\$(curl -sf http://localhost:2222/jibri/api/v1.0/health 2>/dev/null)
            if [ -n "\$HEALTH" ]; then
                BUSY=\$(echo "\$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',{}).get('busyStatus','IDLE'))" 2>/dev/null || echo "IDLE")
                if [ "\$BUSY" != "\$LAST_STATUS" ]; then
                    LAST_STATUS="\$BUSY"
                    curl -sf "\${BASE_URL}/mod/jitsi/servermanagement.php?action=jibristatus&poolentryid=\${POOL_ENTRY_ID}&token=\${TOKEN}&busyness=\${BUSY}" > /dev/null 2>&1 || true
                fi
            fi
            sleep 2
        done
        EOFMON
        chmod +x /usr/local/bin/jibri-monitor.sh

        cat > /etc/systemd/system/jibri-monitor.service << 'EOFMONITORSVC'
        [Unit]
        Description=Jibri Status Monitor - reports recording state to Moodle
        After=jibri.service

        [Service]
        Type=simple
        ExecStart=/usr/local/bin/jibri-monitor.sh
        Restart=always
        RestartSec=30

        [Install]
        WantedBy=multi-user.target
        EOFMONITORSVC

        systemctl daemon-reload
        systemctl enable jibri-monitor
        systemctl start jibri-monitor

        # Mark provisioning complete
        mkdir -p /var/local
        printf '%s\n' "JIBRI_BOOT_DONE=1" > /var/local/jibri_boot_done

        echo "Jibri installation completed"

        # Notify Moodle: ready
        if [ -n "$CALLBACK_URL" ]; then
            curl -X POST "${CALLBACK_URL}&phase=completed" \
                --max-time 10 --retry 3 --retry-delay 5 \
                || echo "Warning: Could not notify Moodle"
        fi

        BASH;
    }
}
