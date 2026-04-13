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

// phpcs:disable
// IMPORTANTE: Verificar la acción ANTES de cargar config.php.
$rawaction = filter_input(INPUT_GET, 'action', FILTER_UNSAFE_RAW) ??
             filter_input(INPUT_POST, 'action', FILTER_UNSAFE_RAW) ?? '';

// Callbacks from VMs don't need a Moodle session — define NO_MOODLE_COOKIES before config.php.
if ($rawaction === 'jitsiready' || $rawaction === 'jibriready' || $rawaction === 'jibrirecording') {
    define('NO_MOODLE_COOKIES', true);
    require_once(__DIR__ . '/../../config.php');
}

if ($rawaction === 'jitsiready') {

    @header('Content-Type: application/json');

    global $DB;

    $instancename = required_param('instance', PARAM_TEXT);
    $token = required_param('token', PARAM_ALPHANUMEXT);
    $ip = optional_param('ip', '', PARAM_TEXT);
    $hostname = optional_param('hostname', '', PARAM_TEXT);
    $phase = optional_param('phase', 'completed', PARAM_ALPHAEXT);
    $appid = optional_param('appid', '', PARAM_ALPHANUMEXT);
    $secret = optional_param('secret', '', PARAM_ALPHANUMEXT);
    $error = optional_param('error', '', PARAM_TEXT);

    try {
        // Find the server record by instance name.
        $server = $DB->get_record('jitsi_servers', ['gcpinstancename' => $instancename]);

        if (!$server) {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => 'Server not found']);
            exit;
        }

        // Verify token from database.
        if (empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
            http_response_code(401);
            echo json_encode(['status' => 'error', 'message' => 'Invalid token']);
            exit;
        }

        // Update server based on phase.
        $server->timemodified = time();

        if ($phase === 'completed' && !empty($hostname) && !empty($appid) && !empty($secret)) {
            // Successfully completed provisioning.
            $server->provisioningstatus = 'ready';
            $server->domain = $hostname;
            $server->appid = $appid;
            $server->secret = $secret;
            $server->provisioningerror = '';

            $DB->update_record('jitsi_servers', $server);

            debugging("✅ Jitsi GCP server ready: {$hostname} (ID: {$server->id}, instance: {$instancename})", DEBUG_NORMAL);

            // If Jibri is requested, enqueue an ad-hoc task to create the Jibri VM.
            if (!empty($server->jibri_enabled) && empty($server->jibri_gcpinstancename)) {
                $jibrimachtype = !empty($server->jibri_machinetype) ? $server->jibri_machinetype : 'n2-standard-4';
                $task = new \mod_jitsi\task\provision_jibri_vm();
                $task->set_custom_data([
                    'serverid'         => $server->id,
                    'jibrimachinetype' => $jibrimachtype,
                ]);
                \core\task\manager::queue_adhoc_task($task, true);
                debugging("⏳ Queued provision_jibri_vm task for server {$server->id}", DEBUG_NORMAL);
            }

            http_response_code(200);
            echo json_encode([
                'status' => 'ok',
                'message' => 'Server provisioned successfully',
                'phase' => 'ready',
                'registered' => true,
                'serverid' => $server->id,
            ]);
        } else if ($phase === 'error' || !empty($error)) {
            // Provisioning failed.
            $server->provisioningstatus = 'error';
            $server->provisioningerror = $error ?: 'Unknown error during provisioning';

            $DB->update_record('jitsi_servers', $server);

            debugging("❌ Jitsi GCP server error: {$instancename} - {$error}", DEBUG_NORMAL);

            http_response_code(200);
            echo json_encode([
                'status' => 'ok',
                'message' => 'Status updated',
                'phase' => 'error',
                'registered' => false,
            ]);
        } else {
            // Intermediate status update (e.g., 'waiting_dns', 'dns_ready', 'installing', etc.).
            // Update the status to reflect the current phase.
            $server->provisioningstatus = $phase;
            $DB->update_record('jitsi_servers', $server);

            http_response_code(200);
            echo json_encode([
                'status' => 'ok',
                'message' => 'Status updated',
                'phase' => $phase,
                'registered' => false,
            ]);
        }
    } catch (Exception $e) {
        debugging("❌ Callback error: " . $e->getMessage(), DEBUG_NORMAL);
        http_response_code(500);
        echo json_encode([
            'status' => 'error',
            'message' => 'Database error: ' . $e->getMessage(),
        ]);
    }
    exit;
}
// phpcs:enable

// phpcs:disable
if ($rawaction === 'jibriready') {
    // Callback from the Jibri VM — config.php already loaded above without session.
    @header('Content-Type: application/json');

    global $DB;

    $serverid    = filter_input(INPUT_GET, 'serverid', FILTER_VALIDATE_INT) ?:
                   filter_input(INPUT_POST, 'serverid', FILTER_VALIDATE_INT) ?: 0;
    $poolentryid = filter_input(INPUT_GET, 'poolentryid', FILTER_VALIDATE_INT) ?:
                   filter_input(INPUT_POST, 'poolentryid', FILTER_VALIDATE_INT) ?: 0;
    $token       = filter_input(INPUT_GET, 'token', FILTER_UNSAFE_RAW) ?:
                   filter_input(INPUT_POST, 'token', FILTER_UNSAFE_RAW) ?? '';
    $phase       = filter_input(INPUT_GET, 'phase', FILTER_UNSAFE_RAW) ?:
                   filter_input(INPUT_POST, 'phase', FILTER_UNSAFE_RAW) ?? 'completed';
    $error       = filter_input(INPUT_GET, 'error', FILTER_UNSAFE_RAW) ?:
                   filter_input(INPUT_POST, 'error', FILTER_UNSAFE_RAW) ?? '';

    try {
        $server = $DB->get_record('jitsi_servers', ['id' => (int)$serverid]);

        if (!$server) {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => 'Server not found']);
            exit;
        }

        // Reuse the same provisioning token as the Jitsi VM for simplicity.
        if (empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
            http_response_code(401);
            echo json_encode(['status' => 'error', 'message' => 'Invalid token']);
            exit;
        }

        // Update pool entry if provided.
        $poolentry = $poolentryid ? $DB->get_record('jitsi_jibri_pool', ['id' => (int)$poolentryid]) : null;

        $now = time();

        if ($phase === 'completed') {
            // Update pool entry status.
            if ($poolentry) {
                $poolentry->status            = 'idle';
                $poolentry->provisioningerror = '';
                $poolentry->timemodified      = $now;
                $DB->update_record('jitsi_jibri_pool', $poolentry);
            }
            // Keep legacy field updated for the first VM in the pool.
            $firstentry = $DB->get_record_sql(
                'SELECT * FROM {jitsi_jibri_pool} WHERE serverid = ? ORDER BY id ASC LIMIT 1',
                [$server->id]
            );
            if ($firstentry) {
                $DB->set_field('jitsi_servers', 'jibri_gcpinstancename', $firstentry->gcpinstancename, ['id' => $server->id]);
            }
            $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', 'ready', ['id' => $server->id]);
            $DB->set_field('jitsi_servers', 'jibri_provisioningerror', '', ['id' => $server->id]);
            $DB->set_field('jitsi_servers', 'timemodified', $now, ['id' => $server->id]);

            debugging("✅ Jibri VM ready for server ID {$server->id}", DEBUG_NORMAL);

            http_response_code(200);
            echo json_encode(['status' => 'ok', 'phase' => 'ready']);
        } else if ($phase === 'error' || !empty($error)) {
            if ($poolentry) {
                $poolentry->status            = 'error';
                $poolentry->provisioningerror = $error ?: 'Unknown Jibri provisioning error';
                $poolentry->timemodified      = $now;
                $DB->update_record('jitsi_jibri_pool', $poolentry);
            }
            $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', 'error', ['id' => $server->id]);
            $DB->set_field('jitsi_servers', 'jibri_provisioningerror',
                $error ?: 'Unknown Jibri provisioning error', ['id' => $server->id]);
            $DB->set_field('jitsi_servers', 'timemodified', $now, ['id' => $server->id]);

            debugging("❌ Jibri VM error for server ID {$server->id}: {$error}", DEBUG_NORMAL);

            http_response_code(200);
            echo json_encode(['status' => 'ok', 'phase' => 'error']);
        } else {
            if ($poolentry) {
                $poolentry->status       = $phase;
                $poolentry->timemodified = $now;
                $DB->update_record('jitsi_jibri_pool', $poolentry);
            }
            $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', $phase, ['id' => $server->id]);
            $DB->set_field('jitsi_servers', 'timemodified', $now, ['id' => $server->id]);

            http_response_code(200);
            echo json_encode(['status' => 'ok', 'phase' => $phase]);
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
    exit;
}
// phpcs:enable

// phpcs:disable
if ($rawaction === 'jibrirecording') {
    // Callback from the Jibri finalize script when a recording is ready.
    @header('Content-Type: application/json');

    global $DB;

    $serverid = filter_input(INPUT_GET, 'serverid', FILTER_VALIDATE_INT) ?:
                filter_input(INPUT_POST, 'serverid', FILTER_VALIDATE_INT) ?: 0;
    $token    = filter_input(INPUT_GET, 'token', FILTER_UNSAFE_RAW) ?:
                filter_input(INPUT_POST, 'token', FILTER_UNSAFE_RAW) ?? '';
    $roomname = filter_input(INPUT_GET, 'room', FILTER_UNSAFE_RAW) ?:
                filter_input(INPUT_POST, 'room', FILTER_UNSAFE_RAW) ?? '';
    $filename = filter_input(INPUT_GET, 'filename', FILTER_UNSAFE_RAW) ?:
                filter_input(INPUT_POST, 'filename', FILTER_UNSAFE_RAW) ?? '';
    $recurl   = filter_input(INPUT_GET, 'url', FILTER_VALIDATE_URL) ?:
                filter_input(INPUT_POST, 'url', FILTER_VALIDATE_URL) ?: '';

    try {
        $server = $DB->get_record('jitsi_servers', ['id' => (int)$serverid]);

        if (!$server) {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => 'Server not found']);
            exit;
        }

        if (empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
            http_response_code(401);
            echo json_encode(['status' => 'error', 'message' => 'Invalid token']);
            exit;
        }

        if (empty($recurl)) {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Missing recording URL']);
            exit;
        }

        // Find the jitsi activity record matching the room name.
        // The room name is a composite built from course shortname, jitsi id, and jitsi name
        // using the admin settings 'sesionname' and 'separator' — same logic as view.php.
        $jitsi = null;
        if (!empty($roomname)) {
            $separatormap   = ['.', '-', '_', ''];
            $fieldssesname  = (string)get_config('mod_jitsi', 'sesionname');
            $separatorindex = (int)get_config('mod_jitsi', 'separator');
            $sep = $separatormap[$separatorindex] ?? '';

            $alljitsis = $DB->get_records_sql(
                'SELECT j.*, c.shortname AS courseshortname FROM {jitsi} j JOIN {course} c ON c.id = j.course'
            );
            foreach ($alljitsis as $candidate) {
                $allowed = explode(',', $fieldssesname);
                $max = count($allowed);
                $sesparam = '';
                for ($i = 0; $i < $max; $i++) {
                    $part = '';
                    if ($allowed[$i] == 0) {
                        $part = preg_replace('/[^a-zA-Z0-9]/', '', $candidate->courseshortname);
                    } else if ($allowed[$i] == 1) {
                        $part = (string)$candidate->id;
                    } else if ($allowed[$i] == 2) {
                        $part = preg_replace('/[^a-zA-Z0-9]/', '', $candidate->name);
                    }
                    $sesparam .= $part;
                    if ($i < $max - 1) {
                        $sesparam .= preg_replace('/[^a-zA-Z0-9\-_]/', '', $sep);
                    }
                }
                if (strtolower($sesparam) === strtolower($roomname)) {
                    $jitsi = $candidate;
                    break;
                }
            }
        }

        // Create a source record (type=1 = external link).
        $sourcerecord = new stdClass();
        $sourcerecord->link        = $recurl;
        $sourcerecord->name        = !empty($filename) ? $filename : basename(parse_url($recurl, PHP_URL_PATH));
        $sourcerecord->type        = 1;
        $sourcerecord->timeexpires = 0; // Recordings don't expire.
        $sourcerecord->timecreated = time();
        $sourceid = $DB->insert_record('jitsi_source_record', $sourcerecord);

        // Create a jitsi_record to link the source to the activity (required for display in view.php).
        if ($jitsi) {
            $record = new stdClass();
            $record->jitsi   = $jitsi->id;
            $record->source  = $sourceid;
            $record->deleted = 0;
            $record->visible = 1;
            $record->name    = $sourcerecord->name;
            $DB->insert_record('jitsi_record', $record);
        }

        debugging("🎥 Jibri recording imported for server {$server->id}: {$recurl}", DEBUG_NORMAL);

        http_response_code(200);
        echo json_encode(['status' => 'ok', 'message' => 'Recording imported']);
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
    }
    exit;
}
// phpcs:enable

// Para el resto de acciones: cargar Moodle normalmente.
require_once(__DIR__ . '/../../config.php');

$action = optional_param('action', '', PARAM_ALPHA);

// Ahora sí requerir login para todas las demás acciones.
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
    $CFG->dirroot . '/mod/jitsi/api/vendor/autoload.php', // User-provided path.
    $CFG->dirroot . '/mod/jitsi/vendor/autoload.php', // Plugin-level vendor.
    $CFG->dirroot . '/vendor/autoload.php', // Site-level vendor.
];
foreach ($gcpautoloaders as $autoload) {
    if (file_exists($autoload)) {
        require_once($autoload);
        break;
    }
}


$id      = optional_param('id', 0, PARAM_INT);
$confirm = optional_param('confirm', 0, PARAM_BOOL);

// Minimal GCP helpers to create a bare VM (no Jitsi yet).

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
            // Firewall rule doesn't exist or we lack GET permission - proceed to attempt create.
            debugging('Firewall GET failed, attempting create: ' . $e->getMessage(), DEBUG_DEVELOPER);
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
            // 409 Already exists or similar → treat as exists.
            if (
                stripos($msg, 'alreadyexists') !== false || stripos($msg, 'already exists') !== false ||
                stripos($msg, 'duplicate') !== false
            ) {
                return 'exists';
            }
            // Permission errors → assume admin manages firewall; don't warn in UI.
            if (
                stripos($msg, 'permission') !== false || stripos($msg, 'denied') !== false ||
                stripos($msg, 'insufficient') !== false
            ) {
                return 'noperms';
            }
            return 'error:' . $msg;
        }
    }
}
// phpcs:disable
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
}
// phpcs:enable

// phpcs:disable
if (!function_exists('mod_jitsi_jibri_startup_script')) {
    /**
     * Startup script for the dedicated Jibri recording VM (Debian 12).
     * Reads JITSI_HOSTNAME, JIBRI_XMPP_PASS, JIBRI_RECORDER_PASS and CALLBACK_URL from instance metadata.
     */
    function mod_jitsi_jibri_startup_script(): string {
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
                --max-time 30 --retry 3 --retry-delay 5 \
                || echo "Warning: Could not notify Moodle"
        fi

        echo "Recording finalized: \$REC_URL"
        EOFFINALIZE

        chmod +x /usr/local/bin/jibri-finalize.sh

        # Create delete-recording HTTP service (for physical file removal when Moodle deletes a recording)
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
// phpcs:enable

if (!function_exists('mod_jitsi_gcp_client')) {
    /**
     * Creates and returns a configured Google Compute Engine service client.
     *
     * This function initializes a Google API client with appropriate authentication credentials.
     * It first attempts to load a service account JSON file uploaded via the plugin settings.
     * If no file is found, it falls back to Application Default Credentials (ADC).
     *
     * Authentication priority:
     * 1. Service account JSON file stored in mod_jitsi file area
     * 2. Application Default Credentials (environment variable, gcloud CLI, etc.)
     *
     * @return \Google\Service\Compute A configured Google Compute Engine service instance.
     *
     * @throws \Exception If the service account file exists but cannot be properly decoded as JSON.
     *
     * @see https://cloud.google.com/docs/authentication/application-default-credentials
     * @see https://cloud.google.com/docs/authentication/production
     */
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
        $machinetype = sprintf('zones/%s/machineTypes/%s', $zone, $opts['machineType']);
        $diskimage = $opts['image'];
        $network = $opts['network'];

        // Optional metadata: startup-script + variables.
        $metadataitems = [];
        if (!empty($opts['startupScript'])) {
            $metadataitems[] = ['key' => 'startup-script', 'value' => $opts['startupScript']];
        }
        if (!empty($opts['hostname'])) {
            $metadataitems[] = ['key' => 'HOSTNAME_FQDN', 'value' => $opts['hostname']];
        }
        if (!empty($opts['letsencryptEmail'])) {
            $metadataitems[] = ['key' => 'LE_EMAIL', 'value' => $opts['letsencryptEmail']];
        }
        if (!empty($opts['callbackUrl'])) {
            $metadataitems[] = ['key' => 'CALLBACK_URL', 'value' => $opts['callbackUrl']];
        }
        // Allow callers to inject arbitrary extra metadata items.
        if (!empty($opts['extraMetadata']) && is_array($opts['extraMetadata'])) {
            foreach ($opts['extraMetadata'] as $item) {
                if (!empty($item['key'])) {
                    $metadataitems[] = ['key' => $item['key'], 'value' => (string)$item['value']];
                }
            }
        }

        // Configure access config (static IP if provided, otherwise ephemeral).
        $accessconfig = ['name' => 'External NAT', 'type' => 'ONE_TO_ONE_NAT'];
        if (!empty($opts['staticIpAddress'])) {
            // Use the reserved static IP address.
            $accessconfig['natIP'] = $opts['staticIpAddress'];
        }

        $tags = !empty($opts['tags']) ? $opts['tags'] : ['mod-jitsi-web'];
        $instanceparams = [
            'name' => $name,
            'machineType' => $machinetype,
            'labels' => [ 'app' => 'jitsi', 'plugin' => 'mod-jitsi' ],
            'tags' => ['items' => $tags],
            'networkInterfaces' => [[
                'network' => $network,
                'accessConfigs' => [$accessconfig],
            ]],
            'disks' => [[
                'boot' => true,
                'autoDelete' => true,
                'initializeParams' => ['sourceImage' => $diskimage, 'diskSizeGb' => 20],
            ]],
        ];
        // Attach a service account if requested (gives GCP tools like gsutil ADC access).
        if (!empty($opts['serviceAccount'])) {
            $scopes = !empty($opts['serviceAccountScopes'])
                ? $opts['serviceAccountScopes']
                : ['https://www.googleapis.com/auth/cloud-platform'];
            $instanceparams['serviceAccounts'] = [[
                'email' => $opts['serviceAccount'],
                'scopes' => $scopes,
            ]];
        }
        if (!empty($metadataitems)) {
            $instanceparams['metadata'] = ['items' => $metadataitems];
        }

        $instance = new \Google\Service\Compute\Instance($instanceparams);
        $op = $compute->instances->insert($project, $zone, $instance);
        return $op->getName();
    }
}

if (!function_exists('mod_jitsi_gcs_client')) {
    /**
     * Creates and returns a configured Google Cloud Storage service client.
     *
     * @return \Google\Service\Storage
     */
    function mod_jitsi_gcs_client(): \Google\Service\Storage {
        $client = new \Google\Client();
        $client->setScopes(['https://www.googleapis.com/auth/cloud-platform']);
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
        return new \Google\Service\Storage($client);
    }
}

if (!function_exists('mod_jitsi_gcs_ensure_bucket')) {
    /**
     * Creates a GCS bucket if it does not exist. Returns the bucket name.
     *
     * @param \Google\Service\Storage $gcs
     * @param string $project GCP project ID
     * @param string $bucketname Bucket name (must be globally unique)
     * @param string $location GCS location (e.g. 'europe-west1')
     * @return string The bucket name
     */
    function mod_jitsi_gcs_ensure_bucket(\Google\Service\Storage $gcs, string $project, string $bucketname, string $location): string {
        try {
            $gcs->buckets->get($bucketname);
        } catch (\Google\Service\Exception $e) {
            if ($e->getCode() == 404) {
                $bucket = new \Google\Service\Storage\Bucket([
                    'name' => $bucketname,
                    'location' => $location,
                    'storageClass' => 'STANDARD',
                ]);
                $gcs->buckets->insert($project, $bucket);
            } else {
                throw $e;
            }
        }
        return $bucketname;
    }
}

if (!function_exists('mod_jitsi_gcp_update_instance_metadata')) {
    /**
     * Updates specific metadata keys on a GCP instance, preserving existing ones.
     *
     * @param \Google\Service\Compute $compute
     * @param string $project
     * @param string $zone
     * @param string $instancename
     * @param array $updates Key-value pairs to update or add
     */
    function mod_jitsi_gcp_update_instance_metadata(
        \Google\Service\Compute $compute,
        string $project,
        string $zone,
        string $instancename,
        array $updates
    ): void {
        $instance = $compute->instances->get($project, $zone, $instancename);
        $metadata = $instance->getMetadata();
        $items = $metadata->getItems() ?? [];
        foreach ($updates as $key => $value) {
            $found = false;
            foreach ($items as $item) {
                if ($item->getKey() === $key) {
                    $item->setValue($value);
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $newitem = new \Google\Service\Compute\MetadataItems();
                $newitem->setKey($key);
                $newitem->setValue($value);
                $items[] = $newitem;
            }
        }
        $metadata->setItems($items);
        $compute->instances->setMetadata($project, $zone, $instancename, $metadata);
    }
}

if (!function_exists('mod_jitsi_gcs_bucket_name')) {
    /**
     * Derives a globally-unique GCS bucket name for a server.
     *
     * @param string $project GCP project ID
     * @param int $serverid jitsi_servers record ID
     * @return string Bucket name (max 63 chars, lowercase, hyphens only)
     */
    function mod_jitsi_gcs_bucket_name(string $project, int $serverid): string {
        $slug = preg_replace('/[^a-z0-9-]/', '-', strtolower($project));
        $name = 'mod-jitsi-' . $slug . '-s' . $serverid;
        return substr($name, 0, 63);
    }
}

if (!function_exists('mod_jitsi_gcp_wait_zone_op')) {
    /**
     * Wait for a Google Cloud Platform zone operation to complete.
     *
     * This function polls a GCP zone operation until it reaches a 'DONE' status or times out.
     * It checks the operation status at regular intervals and throws an exception if an error
     * occurs during the operation or if the timeout is exceeded.
     *
     * @param \Google\Service\Compute $compute The Google Compute API client instance.
     * @param string $project The GCP project ID.
     * @param string $zone The GCP zone where the operation is being performed.
     * @param string $opName The name of the operation to wait for.
     * @param int $timeout The maximum time in seconds to wait for the operation to complete. Defaults to 420 seconds (7 minutes).
     * @return void
     * @throws moodle_exception If the operation fails (gcpoperationerror) or exceeds the timeout (gcpoperationtimeout).
     */
    function mod_jitsi_gcp_wait_zone_op(
        \Google\Service\Compute $compute,
        string $project,
        string $zone,
        string $opname,
        int $timeout = 420
    ): void {
        $start = time();
        do {
            $op = $compute->zoneOperations->get($project, $zone, $opname);
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

if (!function_exists('mod_jitsi_gcp_wait_region_op')) {
    /**
     * Waits for a regional GCP operation to complete (e.g., address reservation).
     */
    function mod_jitsi_gcp_wait_region_op(
        \Google\Service\Compute $compute,
        string $project,
        string $region,
        string $opname,
        int $timeout = 120
    ): void {
        $start = time();
        do {
            $op = $compute->regionOperations->get($project, $region, $opname);
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

if (!function_exists('mod_jitsi_gcp_find_available_static_ip')) {
    /**
     * Finds an available (unused) static IP in the region.
     *
     * @param \Google\Service\Compute $compute GCP Compute client
     * @param string $project GCP project ID
     * @param string $region GCP region
     * @return array|null Array with ['name' => string, 'address' => string] or null if none available
     */
    function mod_jitsi_gcp_find_available_static_ip(\Google\Service\Compute $compute, string $project, string $region): ?array {
        try {
            $addresses = $compute->addresses->listAddresses($project, $region);

            if ($addresses->getItems()) {
                foreach ($addresses->getItems() as $addr) {
                    // IP is available if it's not assigned to any resource (users array is empty).
                    if (empty($addr->getUsers()) && $addr->getStatus() === 'RESERVED') {
                        return [
                            'name' => $addr->getName(),
                            'address' => $addr->getAddress(),
                        ];
                    }
                }
            }
        } catch (Exception $e) {
            debugging('Failed to list addresses: ' . $e->getMessage(), DEBUG_NORMAL);
        }

        return null;
    }
}

if (!function_exists('mod_jitsi_gcp_reserve_static_ip')) {
    /**
     * Reserves a static IP address in GCP and returns the address name.
     *
     * @param \Google\Service\Compute $compute GCP Compute client
     * @param string $project GCP project ID
     * @param string $region GCP region (e.g., 'europe-west1' from zone 'europe-west1-b')
     * @param string $name Name for the static IP address
     * @return string The reserved static IP address name
     */
    function mod_jitsi_gcp_reserve_static_ip(
        \Google\Service\Compute $compute,
        string $project,
        string $region,
        string $name
    ): string {
        $address = new \Google\Service\Compute\Address();
        $address->setName($name);
        $address->setDescription('Static IP for Jitsi server ' . $name);
        $address->setAddressType('EXTERNAL');

        $op = $compute->addresses->insert($project, $region, $address);
        mod_jitsi_gcp_wait_region_op($compute, $project, $region, $op->getName());

        return $name;
    }
}

if (!function_exists('mod_jitsi_gcp_release_static_ip')) {
    /**
     * Releases a static IP address in GCP.
     *
     * @param \Google\Service\Compute $compute GCP Compute client
     * @param string $project GCP project ID
     * @param string $region GCP region
     * @param string $name Name of the static IP address to release
     */
    function mod_jitsi_gcp_release_static_ip(
        \Google\Service\Compute $compute,
        string $project,
        string $region,
        string $name
    ): void {
        try {
            $op = $compute->addresses->delete($project, $region, $name);
            mod_jitsi_gcp_wait_region_op($compute, $project, $region, $op->getName());
        } catch (Exception $e) {
            // Log error but don't throw - IP might already be deleted.
            debugging('Failed to release static IP ' . $name . ': ' . $e->getMessage(), DEBUG_NORMAL);
        }
    }
}

// Action: create a bare VM in Google Cloud to test connectivity and permissions.
if ($action === 'creategcpvm') {
    $ajax = optional_param('ajax', 0, PARAM_BOOL);
    if ($ajax) {
        // Buffer all output so debugging() messages don't corrupt the JSON response.
        ob_start();
    }
    try {
        require_sesskey();
    } catch (\Throwable $e) {
        if ($ajax) {
            ob_end_clean();
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Invalid session key: ' . $e->getMessage()]);
            exit;
        }
        throw $e;
    }

    // Guard: check if Google API Client classes are available.
    if (!class_exists('Google\\Client') || !class_exists('Google\\Service\\Compute')) {
        if ($ajax) {
            ob_end_clean();
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
    $mach      = trim((string) optional_param('jitsimachinetype', '', PARAM_TEXT));
    if (empty($mach)) {
        $mach = trim((string) get_config('mod_jitsi', 'gcp_machine_type')) ?: 'e2-standard-4';
    }
    $image     = trim((string) get_config('mod_jitsi', 'gcp_image')) ?: 'projects/debian-cloud/global/images/family/debian-12';
    $network   = trim((string) get_config('mod_jitsi', 'gcp_network')) ?: 'global/networks/default';
    $hostname  = trim((string) get_config('mod_jitsi', 'gcp_hostname'));
    $leemail   = trim((string) get_config('mod_jitsi', 'gcp_letsencrypt_email'));
    // If hostname is set, require LE email to avoid interactive prompts later.
    if (!empty($hostname) && empty($leemail)) {
        if ($ajax) {
            ob_end_clean();
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error',
              'message' => 'Missing Let\'s Encrypt email (gcp_letsencrypt_email) while hostname is set.']);
            exit;
        }
        \core\notification::add(
            'Missing Let\'s Encrypt email (gcp_letsencrypt_email) while hostname is set.',
            \core\output\notification::NOTIFY_ERROR
        );
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }
    $sscript       = mod_jitsi_default_startup_script();
    $enablejibri   = (bool) optional_param('enablejibri', 0, PARAM_BOOL);
    $enablegcs     = $enablejibri && (bool) optional_param('enablegcs', 0, PARAM_BOOL);
    $jibrimachtype = trim((string) optional_param('jibrimachinetype', 'n2-standard-4', PARAM_TEXT));
    if (empty($jibrimachtype)) {
        $jibrimachtype = 'n2-standard-4';
    }

    $missing = [];
    foreach ([['gcp_project', $project], ['gcp_zone', $zone]] as [$k, $v]) {
        if (empty($v)) {
            $missing[] = $k;
        }
    }
    if ($missing) {
        if ($ajax) {
            ob_end_clean();
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => 'Missing GCP settings: ' . implode(', ', $missing)]);
            exit;
        }
        \core\notification::add('Missing GCP settings: ' . implode(', ', $missing), \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    $instancename = 'jitsi-' . date('ymdHi');

    // Generar token único para esta VM.
    $vmtoken = bin2hex(random_bytes(32));

    // URL del callback (debe ser accesible públicamente).
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
        $fwwarndetail = '';
        $fwstatus = mod_jitsi_gcp_ensure_firewall($compute, $project, $network);
        if (strpos($fwstatus, 'error:') === 0) {
            $fwwarn = 'Could not create VPC firewall rule automatically. ' .
                      'Please allow TCP 80/443 and UDP 10000 (target tag: mod-jitsi-web).';
            $fwwarndetail = substr($fwstatus, 6);
            $msg = 'Warning: could not create VPC firewall rule automatically. ' .
                   'Please allow TCP 80/443 and UDP 10000 to this VM. Details: ' . s($fwwarndetail);
            \core\notification::add($msg, \core\output\notification::NOTIFY_WARNING);
        }
        // If status is 'noperms' (e.g., permission denied) or 'exists', do not warn in UI;
        // assume admin-managed firewall or rule already present.

        // GET OR RESERVE STATIC IP ADDRESS.
        // Extract region from zone (e.g., 'europe-west1-b' -> 'europe-west1').
        $region = preg_replace('/-[a-z]$/', '', $zone);
        $staticipname = null;
        $staticipaddress = null;
        $ipreused = false;

        try {
            // First, try to find an available (unused) static IP.
            $availableip = mod_jitsi_gcp_find_available_static_ip($compute, $project, $region);

            if ($availableip) {
                // Reuse existing available IP.
                $staticipname = $availableip['name'];
                $staticipaddress = $availableip['address'];
                $ipreused = true;
                debugging("✅ Reusing available static IP: {$staticipname} ({$staticipaddress})", DEBUG_NORMAL);
            } else {
                // No available IP found, create a new one.
                $staticipname = $instancename . '-ip';
                mod_jitsi_gcp_reserve_static_ip($compute, $project, $region, $staticipname);
                // Get the actual IP address from the reserved address.
                $addressobj = $compute->addresses->get($project, $region, $staticipname);
                $staticipaddress = $addressobj->getAddress();
                debugging("✅ Created new static IP: {$staticipname} ({$staticipaddress})", DEBUG_NORMAL);
            }
        } catch (\Throwable $e) {
            if ($ajax) {
                ob_end_clean();
                @header('Content-Type: application/json');
                echo json_encode(['status' => 'error', 'message' => 'Failed to get/reserve static IP: ' . $e->getMessage()]);
                exit;
            }
            \core\notification::add('Failed to get/reserve static IP: ' .
            $e->getMessage(), \core\output\notification::NOTIFY_ERROR);
            redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
        }

        // INSERT SERVER RECORD IMMEDIATELY with 'provisioning' status.
        $server = new stdClass();
        $server->name = $instancename;
        $server->type = 3; // GCP Auto-Managed.
        $server->domain = $hostname ?: $staticipaddress; // Use hostname or fallback to IP.
        $server->appid = ''; // Will be populated by callback.
        $server->secret = ''; // Will be populated by callback.
        $server->eightbyeightappid = '';
        $server->eightbyeightapikeyid = '';
        $server->privatekey = '';
        $server->gcpproject = $project;
        $server->gcpzone = $zone;
        $server->gcpinstancename = $instancename;
        $server->gcpstaticipname = $staticipname;
        $server->gcpstaticipaddress = $staticipaddress; // Save the IP address.
        $server->provisioningstatus = 'provisioning';
        $server->provisioningtoken = $vmtoken;
        $server->provisioningerror = '';
        $server->jibri_enabled = $enablejibri ? 1 : 0;
        $server->jibri_gcpinstancename = '';
        $server->jibri_provisioningstatus = '';
        $server->jibri_provisioningerror = '';

        // Generate Jibri XMPP credentials upfront so both VMs can share them.
        $jibrixmpppass     = $enablejibri ? bin2hex(random_bytes(16)) : '';
        $jibrirecorderpass = $enablejibri ? bin2hex(random_bytes(16)) : '';
        $server->jibri_xmpp_pass     = $jibrixmpppass;
        $server->jibri_recorder_pass = $jibrirecorderpass;
        $server->gcs_enabled = 0;
        $server->gcs_bucket  = '';
        $server->machine_type = $mach;

        $server->timecreated = time();
        $server->timemodified = time();

        $serverid = $DB->insert_record('jitsi_servers', $server);

        // Create GCS bucket if requested.
        if ($enablegcs) {
            try {
                $gcs = mod_jitsi_gcs_client();
                $location = preg_replace('/-[a-z]$/', '', $zone);
                $bucketname = mod_jitsi_gcs_bucket_name($project, $serverid);
                mod_jitsi_gcs_ensure_bucket($gcs, $project, $bucketname, $location);
                $DB->set_field('jitsi_servers', 'gcs_enabled', 1, ['id' => $serverid]);
                $DB->set_field('jitsi_servers', 'gcs_bucket', $bucketname, ['id' => $serverid]);
            } catch (\Throwable $gcse) {
                debugging('Could not create GCS bucket: ' . $gcse->getMessage(), DEBUG_NORMAL);
            }
        }

        // Extra metadata for the Jitsi VM when Jibri is requested.
        $jitsiextrameta = [];
        if ($enablejibri) {
            $jitsiextrameta = [
                ['key' => 'ENABLE_JIBRI', 'value' => '1'],
                ['key' => 'JIBRI_XMPP_PASS', 'value' => $jibrixmpppass],
                ['key' => 'JIBRI_RECORDER_PASS', 'value' => $jibrirecorderpass],
            ];
        }

        $opname = mod_jitsi_gcp_create_instance($compute, $project, $zone, [
            'name'             => $instancename,
            'machineType'      => $mach,
            'image'            => $image,
            'network'          => $network,
            'hostname'         => $hostname,
            'letsencryptEmail' => $leemail,
            'startupScript'    => $sscript,
            'callbackUrl'      => $callbackurl,
            'staticIpAddress'  => $staticipaddress,
            'extraMetadata'    => $jitsiextrameta,
        ]);
        // Save operation info in session for status polling.
        if (!isset($SESSION->mod_jitsi_ops)) {
            $SESSION->mod_jitsi_ops = [];
        }
        $SESSION->mod_jitsi_ops[$opname] = [
            'project' => $project,
            'zone' => $zone,
            'instancename' => $instancename,
            'staticipname' => $staticipname, // Save static IP name.
            'region' => $region, // Save region for IP management.
        ];
        if ($ajax) {
            ob_end_clean();
            @header('Content-Type: application/json');
            echo json_encode([
                'status' => 'pending',
                'opname' => $opname,
                'instancename' => $instancename,
                'fwwarn' => $fwwarn,
                'fwwarn_detail' => $fwwarndetail,
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
            'staticipname' => $staticipname, // Save static IP name.
            'region' => $region, // Save region for IP management.
        ];
        redirect(new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpstatus']));
    } catch (\Throwable $e) {
        if ($ajax) {
            ob_end_clean();
            @header('Content-Type: application/json');
            echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
            exit;
        }
        \core\notification::add('Failed to create GCP VM: ' . $e->getMessage(), \core\output\notification::NOTIFY_ERROR);
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

    try {
        // Read from jitsi_servers table instead of config_plugins.
        $server = $DB->get_record('jitsi_servers', ['gcpinstancename' => $instancename]);

        if (!$server) {
            echo json_encode(['status' => 'error', 'error' => 'Server not found']);
            exit;
        }

        $response = [
            'status' => $server->provisioningstatus ?: 'provisioning',
            'ip' => $server->gcpstaticipaddress ?: $server->domain ?: '',
            'hostname' => $server->domain ?: '',
            'serverid' => $server->id,
        ];

        // Include error message if provisioning failed.
        if (!empty($server->provisioningerror)) {
            $response['error'] = $server->provisioningerror;
        }

        // Map 'ready' status to 'completed' for frontend compatibility.
        if ($response['status'] === 'ready') {
            $response['status'] = 'completed';
        }

        echo json_encode($response);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'error' => $e->getMessage()]);
    }
    exit;
}

if ($action === 'listprovisioningservers') {
    @header('Content-Type: application/json');

    // Return list of servers being provisioned.
    $servers = $DB->get_records_sql(
        "SELECT id, name, gcpinstancename, domain, gcpstaticipaddress, provisioningstatus
         FROM {jitsi_servers}
         WHERE type = 3 AND provisioningstatus IS NOT NULL AND provisioningstatus != '' AND provisioningstatus != 'ready'
         ORDER BY timecreated DESC"
    );

    echo json_encode(array_values($servers));
    exit;
}

if ($action === 'gcpserversstatus') {
    require_sesskey();
    @header('Content-Type: application/json');

    $serverids = required_param('ids', PARAM_TEXT);
    $ids = explode(',', $serverids);

    $statuses = [];

    try {
        $gcpclient = mod_jitsi_gcp_client();

        foreach ($ids as $id) {
            $id = (int)$id;
            if ($server = $DB->get_record('jitsi_servers', ['id' => $id])) {
                if (
                    $server->type == 3 && !empty($server->gcpproject) &&
                    !empty($server->gcpzone) && !empty($server->gcpinstancename)
                ) {
                    try {
                        $instance = $gcpclient->instances->get(
                            $server->gcpproject,
                            $server->gcpzone,
                            $server->gcpinstancename
                        );
                        $status = $instance->getStatus();

                        $statuses[$id] = [
                            'status' => $status,
                            'ip' => '',
                        ];

                        // Obtener IP pública si está corriendo.
                        if ($status === 'RUNNING') {
                            $nats = $instance->getNetworkInterfaces()[0]->getAccessConfigs();
                            if (!empty($nats) && isset($nats[0])) {
                                $statuses[$id]['ip'] = $nats[0]->getNatIP();
                            }
                        }
                    } catch (Exception $e) {
                        if (strpos($e->getMessage(), 'notFound') !== false || strpos($e->getMessage(), '404') !== false) {
                            $statuses[$id] = ['status' => 'NOT_FOUND', 'message' => 'Instance not found'];
                        } else {
                            $statuses[$id] = ['status' => 'ERROR', 'message' => $e->getMessage()];
                        }
                    }
                }
            }
        }
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
        exit;
    }

    echo json_encode($statuses);
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
                \core\notification::add(get_string(
                    'gcpoperationerror',
                    'mod_jitsi',
                    json_encode($op->getError())
                ), \core\output\notification::NOTIFY_ERROR);
                redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
            }
            // Fetch public IP and notify success.
            $inst = $compute->instances->get($opinfo['project'], $opinfo['zone'], $opinfo['instancename']);
            $nats = $inst->getNetworkInterfaces()[0]->getAccessConfigs();
            $ip = (!empty($nats) && isset($nats[0])) ? $nats[0]->getNatIP() : '';
            unset($SESSION->mod_jitsi_gcp_op);
            \core\notification::add(
                get_string('gcpservercreated', 'mod_jitsi', $opinfo['instancename'] . ' ' . $ip),
                \core\output\notification::NOTIFY_SUCCESS
            );
            redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
        } else {
            // Not done yet: add meta refresh to poll again in 2s.
            echo html_writer::empty_tag('meta', ['http-equiv' => 'refresh', 'content' => '2']);
            echo $OUTPUT->footer();
            exit;
        }
    } catch (Exception $e) {
        unset($SESSION->mod_jitsi_gcp_op);
        \core\notification::add(
            get_string('gcpservercreatefail', 'mod_jitsi', $e->getMessage()),
            \core\output\notification::NOTIFY_ERROR
        );
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }
}

// Action: Set default server.
if ($action === 'setdefaultserver' && $id > 0) {
    require_sesskey();

    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid server id');
    }

    // Update the configuration.
    set_config('server', $server->id, 'mod_jitsi');

    \core\notification::add(
        get_string('defaultserverupdated', 'mod_jitsi', $server->name),
        \core\output\notification::NOTIFY_SUCCESS
    );

    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

if ($action === 'delete' && $id > 0) {
    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid id');
    }

    if ($confirm) {
        // Si es servidor GCP (tipo 3), eliminar también la VM.
        if ($server->type == 3 && !empty($server->gcpproject) && !empty($server->gcpzone) && !empty($server->gcpinstancename)) {
            try {
                if (class_exists('Google\\Client') && class_exists('Google\\Service\\Compute')) {
                    $compute = mod_jitsi_gcp_client();

                    // Eliminar la instancia de GCP.
                    $operation = $compute->instances->delete(
                        $server->gcpproject,
                        $server->gcpzone,
                        $server->gcpinstancename
                    );

                    debugging("✅ GCP VM deletion initiated: {$server->gcpinstancename}
                      (Operation: {$operation->getName()})", DEBUG_NORMAL);

                    // NOTE: We do NOT delete the static IP here.
                    // When the VM is deleted, GCP automatically changes the IP status from IN_USE to RESERVED.
                    // This allows the IP to be reused by the next VM created.
                    if (!empty($server->gcpstaticipname)) {
                        debugging("ℹ️ Static IP {$server->gcpstaticipname}
                          will be automatically released by GCP and become available for reuse", DEBUG_NORMAL);
                    }

                    \core\notification::add(
                        "GCP VM '{$server->gcpinstancename}' is being deleted. This may take a few minutes.",
                        \core\output\notification::NOTIFY_INFO
                    );
                } else {
                    \core\notification::add(
                        'Warning: Google Cloud API not available. VM was not deleted from GCP.',
                        \core\output\notification::NOTIFY_WARNING
                    );
                }
            } catch (Exception $e) {
                // Si falla la eliminación en GCP, avisar pero continuar con la BD.
                \core\notification::add(
                    "Warning: Could not delete GCP VM: " . $e->getMessage() . ". Server removed from Moodle database only.",
                    \core\output\notification::NOTIFY_WARNING
                );
                debugging("❌ Failed to delete GCP VM {$server->gcpinstancename}: " . $e->getMessage(), DEBUG_NORMAL);
            }
        }

        // Delete the Jibri VM if one was provisioned.
        if (
            $server->type == 3 && !empty($server->jibri_enabled) && !empty($server->jibri_gcpinstancename)
                && !empty($server->gcpproject) && !empty($server->gcpzone)
        ) {
            try {
                if (class_exists('Google\\Client') && class_exists('Google\\Service\\Compute')) {
                    $compute = mod_jitsi_gcp_client();

                    $operation = $compute->instances->delete(
                        $server->gcpproject,
                        $server->gcpzone,
                        $server->jibri_gcpinstancename
                    );

                    debugging("✅ Jibri VM deletion initiated: {$server->jibri_gcpinstancename}
                      (Operation: {$operation->getName()})", DEBUG_NORMAL);

                    \core\notification::add(
                        "Jibri VM '{$server->jibri_gcpinstancename}' is being deleted. This may take a few minutes.",
                        \core\output\notification::NOTIFY_INFO
                    );
                } else {
                    \core\notification::add(
                        'Warning: Google Cloud API not available. Jibri VM was not deleted from GCP.',
                        \core\output\notification::NOTIFY_WARNING
                    );
                }
            } catch (Exception $e) {
                \core\notification::add(
                    "Warning: Could not delete Jibri VM: " . $e->getMessage() . ". Server removed from Moodle database only.",
                    \core\output\notification::NOTIFY_WARNING
                );
                debugging("❌ Failed to delete Jibri VM {$server->jibri_gcpinstancename}: " . $e->getMessage(), DEBUG_NORMAL);
            }
        }

        // Eliminar de la base de datos.
        $DB->delete_records('jitsi_servers', ['id' => $server->id]);

        // Tras el borrado, verificar si el config apunta a un servidor válido.
        // Esto cubre tanto el caso de que fuera el predeterminado como que el valor
        // fuera 0 o vacío (nunca asignado explícitamente).
        $defaultserver = get_config('mod_jitsi', 'server');
        $defaultvalid = !empty($defaultserver) && $DB->record_exists('jitsi_servers', ['id' => $defaultserver]);
        if (!$defaultvalid) {
            $remaining = $DB->get_records('jitsi_servers', [], 'id ASC', 'id, name', 0, 1);
            if (!empty($remaining)) {
                $nextserver = reset($remaining);
                set_config('server', $nextserver->id, 'mod_jitsi');
                \core\notification::add(
                    get_string('defaultserverupdated', 'mod_jitsi', $nextserver->name),
                    \core\output\notification::NOTIFY_WARNING
                );
            } else {
                set_config('server', '', 'mod_jitsi');
                \core\notification::add(
                    get_string('defaultserverdeleted', 'mod_jitsi'),
                    \core\output\notification::NOTIFY_WARNING
                );
            }
        }

        \core\notification::add(
            get_string('serverdeleted', 'mod_jitsi', $server->name),
            \core\output\notification::NOTIFY_SUCCESS
        );
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    } else {
        echo $OUTPUT->header();
        echo $OUTPUT->heading(get_string('delete'));

        // Mensaje especial para servidores GCP.
        if ($server->type == 3 && !empty($server->gcpinstancename)) {
            $msg = html_writer::div(
                html_writer::tag('strong', 'Warning: This is a GCP Auto-Managed server ') .
                html_writer::tag('span', 'BETA', ['class' => 'badge bg-warning text-dark']) . '<br>' .
                'Deleting this server will:' . '<br>' .
                html_writer::tag(
                    'ul',
                    html_writer::tag('li', '🗑️ Delete the virtual machine from Google Cloud') .
                    html_writer::tag('li', '♻️ Keep the static IP address reserved for reuse') .
                    html_writer::tag('li', '❌ Stop all active Jitsi sessions'),
                    ['class' => 'text-start']
                ) .
                html_writer::tag('p', 'Instance name: <code>' . htmlspecialchars($server->gcpinstancename) . '</code>') .
                html_writer::tag(
                    'p',
                    'Are you sure you want to permanently delete this server?',
                    ['class' => 'text-danger font-weight-bold']
                ),
                'alert alert-warning'
            );
        } else {
            $msg = get_string('confirmdelete', 'mod_jitsi', format_string($server->name));
        }

        echo $OUTPUT->confirm(
            $msg,
            new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'delete', 'id' => $id, 'confirm' => 1]),
            new moodle_url('/mod/jitsi/servermanagement.php')
        );
        echo $OUTPUT->footer();
        exit;
    }
}

// Action: Add Jibri to an existing GCP server.
if ($action === 'addjibri' && $id > 0) {
    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('invalidserverid', 'mod_jitsi');
    }

    if ($server->type != 3 || empty($server->gcpinstancename)) {
        \core\notification::add('Jibri can only be added to GCP Auto-Managed servers.', \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    if (!empty($server->jibri_enabled)) {
        \core\notification::add('This server already has Jibri enabled.', \core\output\notification::NOTIFY_WARNING);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    $confirm = optional_param('confirm', 0, PARAM_BOOL);
    $jibrimachtype = trim((string) optional_param('jibrimachinetype', 'n2-standard-4', PARAM_TEXT));
    if (empty($jibrimachtype)) {
        $jibrimachtype = 'n2-standard-4';
    }

    if ($confirm) {
        require_sesskey();

        // Generate XMPP credentials.
        $jibrixmpppass     = bin2hex(random_bytes(16));
        $jibrirecorderpass = bin2hex(random_bytes(16));

        // Save to DB and enable Jibri.
        $server->jibri_enabled            = 1;
        $server->jibri_xmpp_pass          = $jibrixmpppass;
        $server->jibri_recorder_pass      = $jibrirecorderpass;
        $server->jibri_gcpinstancename    = '';
        $server->jibri_provisioningstatus = '';
        $server->jibri_provisioningerror  = '';
        $server->timemodified             = time();
        $DB->update_record('jitsi_servers', $server);

        // Queue the Jibri VM provisioning task.
        $task = new \mod_jitsi\task\provision_jibri_vm();
        $task->set_custom_data([
            'serverid'         => $server->id,
            'jibrimachinetype' => $jibrimachtype,
        ]);
        \core\task\manager::queue_adhoc_task($task, true);

        \core\notification::add(
            'Jibri VM creation queued. Run the reconfiguration script on the Jitsi VM to complete setup.',
            \core\output\notification::NOTIFY_SUCCESS
        );
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    // Show confirmation page with reconfiguration script.
    $hostname = $server->domain;
    $authdomain = 'auth.' . $hostname;

    // Generate credentials for preview (will be regenerated on confirm).
    // We show placeholder text; actual values are generated on confirm.
    $jibrixmpppass     = bin2hex(random_bytes(16));
    $jibrirecorderpass = bin2hex(random_bytes(16));

    // Build the reconfiguration bash script for the existing Jitsi VM.
    $reconfigscript = <<<SCRIPT
#!/bin/bash
# Run this script on the Jitsi VM ({$hostname}) via SSH to enable Jibri support.
# ssh user@{$hostname} 'sudo bash -s' < this_script.sh
set -euo pipefail
AUTH_DOMAIN="{$authdomain}"
HOSTNAME_FQDN="{$hostname}"
JIBRI_XMPP_PASS="{$jibrixmpppass}"
JIBRI_RECORDER_PASS="{$jibrirecorderpass}"
RECORDER_DOMAIN="recorder.\${HOSTNAME_FQDN}"

echo "Registering Jibri XMPP users..."
prosodyctl register jibri "\$AUTH_DOMAIN" "\$JIBRI_XMPP_PASS" || true
prosodyctl register recorder "\$RECORDER_DOMAIN" "\$JIBRI_RECORDER_PASS" || true

echo "Adding recorder virtual host..."
cat > "/etc/prosody/conf.avail/recorder.\${HOSTNAME_FQDN}.cfg.lua" << 'EOF'
VirtualHost "recorder.HOSTNAME_PLACEHOLDER"
  modules_enabled = { "ping"; }
  authentication = "internal_hashed"
EOF
sed -i "s/HOSTNAME_PLACEHOLDER/\${HOSTNAME_FQDN}/" "/etc/prosody/conf.avail/recorder.\${HOSTNAME_FQDN}.cfg.lua"
ln -sf "/etc/prosody/conf.avail/recorder.\${HOSTNAME_FQDN}.cfg.lua" \\
       "/etc/prosody/conf.d/recorder.\${HOSTNAME_FQDN}.cfg.lua" || true

echo "Updating Jicofo for Jibri brewery..."
JICOFO_CONF="/etc/jitsi/jicofo/jicofo.conf"
if ! grep -q "JibriBrewery" "\$JICOFO_CONF"; then
  python3 -c "
import re
with open('\${JICOFO_CONF}') as f:
    c = f.read()
jibri = '''
  jibri {
    brewery-jid = \"JibriBrewery@internal.\${AUTH_DOMAIN}\"
    pending-timeout = 90 seconds
  }
'''
idx = c.rfind('}')
if idx != -1:
    c = c[:idx] + jibri + c[idx:]
with open('\${JICOFO_CONF}', 'w') as f:
    f.write(c)
print('Jicofo updated')
"
fi

echo "Restarting services..."
systemctl restart prosody
sleep 5
systemctl restart jicofo

echo "Done. Jibri Prosody/Jicofo configuration complete."
SCRIPT;

    echo $OUTPUT->header();
    echo $OUTPUT->heading('Add Jibri recording to: ' . format_string($server->name));

    echo html_writer::div(
        html_writer::tag(
            'p',
            'This will create a dedicated Jibri recording VM alongside your existing Jitsi server. ' .
            'Two steps are required:'
        ) .
        html_writer::tag(
            'ol',
            html_writer::tag(
                'li',
                html_writer::tag('strong', 'Run the script below on your Jitsi VM') .
                ' — reconfigures Prosody and Jicofo to accept Jibri connections.'
            ) .
            html_writer::tag(
                'li',
                html_writer::tag('strong', 'Click "Confirm"') .
                ' — Moodle will create and configure the Jibri VM in GCP automatically.'
            )
        ),
        'alert alert-info mb-3'
    );

    // Script display with copy button.
    $scriptescaped = htmlspecialchars($reconfigscript);
    echo html_writer::div(
        html_writer::tag('h5', 'Reconfiguration script for the Jitsi VM') .
        html_writer::tag(
            'p',
            html_writer::tag('code', 'ssh user@' . s($hostname) . ' \'sudo bash -s\' < script.sh'),
            ['class' => 'text-muted small']
        ) .
        html_writer::tag('pre', $scriptescaped, [
            'id' => 'jibri-reconfig-script',
            'class' => 'bg-dark text-light p-3 rounded',
            'style' => 'max-height:300px; overflow-y:auto; font-size:0.8em;',
        ]) .
        html_writer::tag(
            'button',
            'Copy script',
            ['type' => 'button', 'class' => 'btn btn-sm btn-outline-secondary mb-3', 'id' => 'copy-reconfig-script']
        ),
        'mb-4'
    );

    // Machine type form + confirm.
    $confirmurl = new moodle_url('/mod/jitsi/servermanagement.php', [
        'action'  => 'addjibri',
        'id'      => $id,
        'confirm' => 1,
        'sesskey' => sesskey(),
    ]);
    $cancelurl = new moodle_url('/mod/jitsi/servermanagement.php');

    echo html_writer::start_tag('form', ['method' => 'post', 'action' => $confirmurl->out(false)]);
    echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'sesskey', 'value' => sesskey()]);

    echo html_writer::div(
        html_writer::tag('label', 'Jibri VM machine type', ['class' => 'form-label fw-semibold', 'for' => 'jibri-machine']) .
        html_writer::empty_tag('input', [
            'type'  => 'text',
            'id'    => 'jibri-machine',
            'name'  => 'jibrimachinetype',
            'value' => 'n2-standard-4',
            'class' => 'form-control mb-1',
        ]) .
        html_writer::tag('small', 'Minimum recommended: <code>n2-standard-4</code> (4 vCPUs, 16 GB RAM).', ['class' => 'text-muted']),
        'mb-4'
    );

    echo html_writer::div(
        html_writer::tag('button', 'Confirm — Create Jibri VM', ['type' => 'submit', 'class' => 'btn btn-primary me-2']) .
        html_writer::link($cancelurl, 'Cancel', ['class' => 'btn btn-secondary'])
    );

    echo html_writer::end_tag('form');

    // JS for copy button.
    // phpcs:disable
    $PAGE->requires->js_init_code(
        "(function(){\n".
        "  var btn = document.getElementById('copy-reconfig-script');\n".
        "  var pre = document.getElementById('jibri-reconfig-script');\n".
        "  if (btn && pre && navigator.clipboard) {\n".
        "    btn.addEventListener('click', function(){\n".
        "      navigator.clipboard.writeText(pre.textContent).then(function(){\n".
        "        btn.textContent = '✓ Copied!';\n".
        "        setTimeout(function(){ btn.textContent = 'Copy script'; }, 2000);\n".
        "      });\n".
        "    });\n".
        "  }\n".
        "})();\n"
    );
    // phpcs:enable

    echo $OUTPUT->footer();
    exit;
}

// Action: Start GCP instance.
if ($action === 'gcpstart' && $id > 0) {
    require_sesskey();

    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid server id');
    }

    if ($server->type != 3 || empty($server->gcpproject) || empty($server->gcpzone) || empty($server->gcpinstancename)) {
        \core\notification::add('This server cannot be managed via GCP API', \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    try {
        $compute = mod_jitsi_gcp_client();
        $compute->instances->start($server->gcpproject, $server->gcpzone, $server->gcpinstancename);

        \core\notification::add(
            "Starting GCP instance: {$server->gcpinstancename}",
            \core\output\notification::NOTIFY_SUCCESS
        );

        // Also start the Jibri VM if present.
        if (!empty($server->jibri_enabled) && !empty($server->jibri_gcpinstancename)) {
            try {
                $compute->instances->start($server->gcpproject, $server->gcpzone, $server->jibri_gcpinstancename);
                \core\notification::add(
                    "Starting Jibri GCP instance: {$server->jibri_gcpinstancename}",
                    \core\output\notification::NOTIFY_SUCCESS
                );
            } catch (Exception $ejibri) {
                \core\notification::add(
                    "Failed to start Jibri instance: " . $ejibri->getMessage(),
                    \core\output\notification::NOTIFY_WARNING
                );
            }
        }
    } catch (Exception $e) {
        \core\notification::add(
            "Failed to start instance: " . $e->getMessage(),
            \core\output\notification::NOTIFY_ERROR
        );
    }

    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

// Action: Stop GCP instance.
if ($action === 'gcpstop' && $id > 0) {
    require_sesskey();

    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid server id');
    }

    if ($server->type != 3 || empty($server->gcpproject) || empty($server->gcpzone) || empty($server->gcpinstancename)) {
        \core\notification::add('This server cannot be managed via GCP API', \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    try {
        $compute = mod_jitsi_gcp_client();
        $compute->instances->stop($server->gcpproject, $server->gcpzone, $server->gcpinstancename);

        \core\notification::add(
            "Stopping GCP instance: {$server->gcpinstancename}",
            \core\output\notification::NOTIFY_SUCCESS
        );

        // Also stop the Jibri VM if present.
        if (!empty($server->jibri_enabled) && !empty($server->jibri_gcpinstancename)) {
            try {
                $compute->instances->stop($server->gcpproject, $server->gcpzone, $server->jibri_gcpinstancename);
                \core\notification::add(
                    "Stopping Jibri GCP instance: {$server->jibri_gcpinstancename}",
                    \core\output\notification::NOTIFY_SUCCESS
                );
            } catch (Exception $ejibri) {
                \core\notification::add(
                    "Failed to stop Jibri instance: " . $ejibri->getMessage(),
                    \core\output\notification::NOTIFY_WARNING
                );
            }
        }
    } catch (Exception $e) {
        \core\notification::add(
            "Failed to stop instance: " . $e->getMessage(),
            \core\output\notification::NOTIFY_ERROR
        );
    }

    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

// Action: Enable GCS recordings for a GCP server with Jibri.
if ($action === 'enablegcs' && $id > 0) {
    require_sesskey();

    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid server id');
    }

    if ($server->type != 3 || empty($server->jibri_enabled)) {
        \core\notification::add('GCS is only available for GCP servers with Jibri enabled.', \core\output\notification::NOTIFY_ERROR);
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    try {
        $project = $server->gcpproject;
        $zone = $server->gcpzone;
        $location = preg_replace('/-[a-z]$/', '', $zone);
        $bucketname = !empty($server->gcs_bucket) ? $server->gcs_bucket : mod_jitsi_gcs_bucket_name($project, $server->id);

        $gcs = mod_jitsi_gcs_client();
        mod_jitsi_gcs_ensure_bucket($gcs, $project, $bucketname, $location);

        $server->gcs_enabled = 1;
        $server->gcs_bucket = $bucketname;
        $server->timemodified = time();
        $DB->update_record('jitsi_servers', $server);

        // Update Jibri VM metadata so finalize script uses GCS for new recordings.
        if (!empty($server->jibri_gcpinstancename)) {
            try {
                $compute = mod_jitsi_gcp_client();
                mod_jitsi_gcp_update_instance_metadata($compute, $project, $zone, $server->jibri_gcpinstancename, [
                    'GCS_BUCKET' => $bucketname,
                ]);
            } catch (\Throwable $metaex) {
                debugging('Could not update Jibri VM metadata: ' . $metaex->getMessage(), DEBUG_NORMAL);
                \core\notification::add(
                    'GCS enabled in DB but could not update Jibri VM metadata (VM may be stopped). New recordings will use GCS when VM is next started.',
                    \core\output\notification::NOTIFY_WARNING
                );
            }
        }

        \core\notification::add('GCS recordings enabled. Bucket: ' . $bucketname, \core\output\notification::NOTIFY_SUCCESS);
    } catch (\Throwable $e) {
        \core\notification::add('Failed to enable GCS: ' . $e->getMessage(), \core\output\notification::NOTIFY_ERROR);
    }

    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

// Action: Disable GCS recordings for a GCP server.
if ($action === 'disablegcs' && $id > 0) {
    require_sesskey();

    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('Invalid server id');
    }

    try {
        $server->gcs_enabled = 0;
        $server->timemodified = time();
        $DB->update_record('jitsi_servers', $server);

        // Remove GCS_BUCKET from Jibri VM metadata so finalize script falls back to IP.
        if (!empty($server->jibri_gcpinstancename) && !empty($server->gcpproject) && !empty($server->gcpzone)) {
            try {
                $compute = mod_jitsi_gcp_client();
                mod_jitsi_gcp_update_instance_metadata($compute, $server->gcpproject, $server->gcpzone, $server->jibri_gcpinstancename, [
                    'GCS_BUCKET' => '',
                ]);
            } catch (\Throwable $metaex) {
                debugging('Could not update Jibri VM metadata: ' . $metaex->getMessage(), DEBUG_NORMAL);
            }
        }

        \core\notification::add('GCS recordings disabled. Existing recordings in GCS are preserved.', \core\output\notification::NOTIFY_SUCCESS);
    } catch (\Throwable $e) {
        \core\notification::add('Failed to disable GCS: ' . $e->getMessage(), \core\output\notification::NOTIFY_ERROR);
    }

    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

$mform = new servermanagement_form();

// Verificar si es GCP antes de mostrar formulario de edición.
if ($action === 'edit' && $id > 0) {
    if ($server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        // Bloquear edición de servidores GCP.
        if ($server->type == 3) {
            \core\notification::add(
                'GCP Auto-Managed servers (BETA) cannot be edited manually. Use Start/Stop actions or delete and recreate.',
                \core\output\notification::NOTIFY_WARNING
            );
            redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
        }
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

// Determine if we're in form view (add/edit) or table view (list).
$showform = ($action === 'add' || $action === 'edit');

if ($showform) {
    // FORM VIEW: Show only the form for adding/editing servers.
    if ($action === 'edit' && $id > 0) {
        echo $OUTPUT->heading(get_string('editserver', 'mod_jitsi'));
    } else {
        echo $OUTPUT->heading(get_string('addnewserver', 'mod_jitsi'));
    }

    // Add cancel button before form.
    $cancelurl = new moodle_url('/mod/jitsi/servermanagement.php');
    echo html_writer::div(
        html_writer::link($cancelurl, get_string('cancel'), ['class' => 'btn btn-secondary mb-3']),
        'mb-3'
    );

    $mform->display();
} else {
    // TABLE VIEW: Show server list and management options.
    echo $OUTPUT->heading(get_string('servermanagement', 'mod_jitsi'));

    $settingsurl = new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']);
    $addserverurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'add']);
    $creategcpvmurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'creategcpvm', 'sesskey' => sesskey()]);

    echo html_writer::div(
        html_writer::link($settingsurl, get_string('backtosettings', 'mod_jitsi'), ['class' => 'btn btn-secondary me-2']) .
        html_writer::link($addserverurl, get_string('addnewserver', 'mod_jitsi'), ['class' => 'btn btn-success me-2']) .
        html_writer::tag(
            'button',
            'Create VM in Google Cloud ' . html_writer::tag('span', 'BETA', ['class' => 'badge bg-warning text-dark ms-1']),
            ['id' => 'btn-creategcpvm', 'type' => 'button', 'class' => 'btn btn-primary']
        ),
        'mb-3'
    );

    // Information about GCP servers.
    echo html_writer::div(
        html_writer::div(
            html_writer::tag('strong', get_string('gcpserverinfo', 'mod_jitsi')) . '<br>' .
            get_string('gcpserverinfodetail', 'mod_jitsi'),
            'alert alert-info'
        ),
        'mb-3'
    );

    // Modal markup for progress.
    $creating = get_string('creatingvm', 'mod_jitsi', '');
    $gcpstatusurl = (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpstatusjson']))->out(false);
    $createvmurl  = (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'creategcpvm', 'ajax' => 1]))->out(false);
    $listurl      = (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'listprovisioningservers']))->out(false);
    $redirecturl  = (new moodle_url('/mod/jitsi/servermanagement.php'))->out(false);
    $sesskeyjs    = sesskey();

    // Modal markup (HTML only).
    echo <<<HTML
    <div class="modal fade" id="gcpModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
        <div class="modal-body" id="gcp-modal-body">
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
        'redirectUrl' => $redirecturl,
        'creatingText' => $creating,
        'hostname' => (string) get_config('mod_jitsi', 'gcp_hostname'),
        'checkReadyUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'checkjitsiready']))->out(false),
    ];
    $initjson = json_encode($init, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
    // phpcs:disable 
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
        "  window.closeModal = function closeModal(){\n".
        "    if (modalEl) {\n".
        "      modalEl.classList.remove('show');\n".
        "      modalEl.style.display = 'none';\n".
        "      modalEl.setAttribute('aria-hidden', 'true');\n".
        "    }\n".
        "    if (backdrop && backdrop.parentNode) {\n".
        "      backdrop.parentNode.removeChild(backdrop);\n".
        "    }\n".
        "  };\n".
        "  async function postJSON(url, data){\n".
        "    var res = await fetch(url, {method: 'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams(data)});\n".
        "    if (!res.ok) throw new Error('HTTP ' + res.status);\n".
        "    var text = await res.text();\n".
        "    console.log('[postJSON] Raw response (first 500 chars):', text.substring(0, 500));\n".
        "    return JSON.parse(text);\n".
        "  }\n".
        "  async function checkJitsiReady(){\n".
        "    try {\n".
        "      console.log('[checkJitsiReady] CALLED! vmInfo.instancename:', vmInfo.instancename);\n".
        "      console.log('[checkJitsiReady] Fetching status from:', cfg.checkReadyUrl);\n".
        "      var data = await postJSON(cfg.checkReadyUrl, {\n".
        "        sesskey: cfg.sesskey,\n".
        "        instance: vmInfo.instancename\n".
        "      });\n".
        "      console.log('[checkJitsiReady] Status received:', data);\n".
        "      if (data.status === 'provisioning') {\n".
        "        console.log('[checkJitsiReady] Server is still provisioning, will check again in 5s');\n".
        "        if (modalBody) {\n".
        "          modalBody.innerHTML = (\n".
        "            '<h5>⚙️ VM Initializing...</h5>'+ \n".
        "            '<p>The virtual machine is starting up and running initial setup scripts.</p>'+\n".
        "            '<div class=\"text-center\">'+\n".
        "              '<div class=\"spinner-border spinner-border-sm\" role=\"status\"></div>'+\n".
        "            '</div>'\n".
        "          );\n".
        "        }\n".
        "        setTimeout(checkJitsiReady, 5000);\n".
        "      } else if (data.status === 'waiting_dns') {\n".
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
        "        setTimeout(checkJitsiReady,  10000);\n".
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
        "        showSuccessMessage(data.ip, data.hostname, data.serverid);\n".
        "      } else if (data.status === 'error') {\n".
        "        var errorMsg = data.error || 'Unknown installation error';\n".
        "        if (modalBody) {\n".
        "          modalBody.innerHTML = (\n".
        "            '<div class=\"alert alert-danger\">'+ \n".
        "              '<h5>❌ Installation Failed</h5>'+ \n".
        "              '<p><strong>Error:</strong> ' + errorMsg + '</p>'+ \n".
        "              '<p class=\"text-muted\">Please check the VM console logs in Google Cloud Console for more details.</p>'+\n".
        "            '</div>'+\n".
        "            '<div class=\"mt-3\">'+\n".
        "              '<a href=\"'+ cfg.redirectUrl +'\" class=\"btn btn-primary\">Close</a>'+\n".
        "            '</div>'\n".
        "          );\n".
        "        }\n".
        "      }\n".
        "    } catch(e){\n".
        "      console.error('Check ready error:', e);\n".
        "      if (modalBody) modalBody.innerHTML = '<p class=\"text-warning\">Cannot verify status. Check the VM console.</p>';\n".
        "    }\n".
        "  }\n".
        "  function showSuccessMessage(ip, hostname, serverid){\n".
        "    var host = hostname || cfg.hostname || 'your-hostname.example.com';\n".
        "    if (modalBody) {\n".
        "      modalBody.innerHTML = (\n".
        "        '<h5>✅ Jitsi Server Ready & Registered!</h5>'+ \n".
        "        '<p class=\"text-success\"><strong>Installation completed and server registered in Moodle</strong></p>'+ \n".
        "        '<p>Public IP: <strong>'+ ip +'</strong></p>'+\n".
        "        '<p>Your Jitsi Meet server is ready at: <code>https://'+ host +'</code></p>'+\n".
        "        '<div class=\"mt-3\">'+\n".
        "          '<button id=\"set-default-server\" class=\"btn btn-success me-2\">Set as Default Server</button>'+\n".
        "          '<button id=\"copy-ip\" class=\"btn btn-outline-secondary me-2\">Copy IP</button>'+\n".
        "          '<a href=\"'+ cfg.redirectUrl +'\" class=\"btn btn-primary\">Close</a>'+\n".
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
        "      var setDefaultBtn = document.getElementById('set-default-server');\n".
        "      if (setDefaultBtn && serverid) {\n".
        "        setDefaultBtn.addEventListener('click', function(){ \n".
        "          setDefaultBtn.disabled = true;\n".
        "          setDefaultBtn.textContent = 'Setting...';\n".
        "          var url = cfg.redirectUrl + '?action=setdefaultserver&id=' + serverid + '&sesskey=' + cfg.sesskey;\n".
        "          window.location.href = url;\n".
        "        });\n".
        "      }\n".
        "    }\n".
        "  }\n".
        "  async function pollStatus(opname){\n".
        "    try {\n".
        "      console.log('[pollStatus] Checking operation:', opname);\n".
        "      var data = await postJSON(cfg.statusUrl, {sesskey: cfg.sesskey, opname: opname});\n".
        "      console.log('[pollStatus] Received response:', data);\n".
        "\n".
        "      if (data.status === 'pending') {\n".
        "        console.log('[pollStatus] Status is pending, will poll again in 1.5s');\n".
        "        setTimeout(function(){ pollStatus(opname); }, 1500);\n".
        "      } else if (data.status === 'done') {\n".
        "        console.log('[pollStatus] Status is DONE! VM ready. IP:', data.ip);\n".
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
        "        console.log('[pollStatus] About to schedule checkJitsiReady in 3 seconds...');\n".
        "        console.log('[pollStatus] vmInfo.instancename is:', vmInfo.instancename);\n".
        "        setTimeout(function(){\n".
        "          console.log('[pollStatus setTimeout] Executing checkJitsiReady NOW!');\n".
        "          checkJitsiReady();\n".
        "        }, 3000);\n".
        "        console.log('[pollStatus] setTimeout has been scheduled');\n".
        "      } else {\n".
        "        console.log('[pollStatus] Unexpected status:', data.status);\n".
        "        if (modalBody) modalBody.textContent = 'Error: ' + (data.message || 'Unknown');\n".
        "      }\n".
        "    } catch(e){\n".
        "      console.error('[pollStatus] Exception caught:', e);\n".
        "      if (modalBody) modalBody.textContent = 'Error: ' + e.message;\n".
        "    }\n".
        "  }\n".
        "  async function startVMCreation(enableJibri, jibriMachineType, enableGcs, jitsiMachineType) {\n".
        "    dnsWarningShown = false;\n".
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
        "      console.log('[Button Click] Requesting VM creation... jibri:', enableJibri, 'gcs:', enableGcs, 'jitsiMachine:', jitsiMachineType);\n".
        "      var postData = {sesskey: cfg.sesskey, jitsimachinetype: jitsiMachineType || 'e2-standard-4'};\n".
        "      if (enableJibri) {\n".
        "        postData.enablejibri = '1';\n".
        "        postData.jibrimachinetype = jibriMachineType || 'n2-standard-4';\n".
        "        if (enableGcs) { postData.enablegcs = '1'; }\n".
        "      }\n".
        "      var data = await postJSON(cfg.createUrl, postData);\n".
        "      console.log('[Button Click] Create response:', data);\n".
        "      if (data && data.status === 'pending' && data.opname){\n".
        "        vmInfo.instancename = data.instancename;\n".
        "        console.log('[Button Click] VM instance name saved:', vmInfo.instancename);\n".
        "        console.log('[Button Click] Starting pollStatus for operation:', data.opname);\n".
        "        pollStatus(data.opname);\n".
        "      } else if (data && data.status === 'error') {\n".
        "        var errorMsg = data.message || 'Unknown error occurred';\n".
        "        if (modalBody) {\n".
        "          modalBody.innerHTML = '<div class=\"alert alert-danger\">' +\n".
        "            '<strong>Error starting VM creation:</strong><br>' +\n".
        "            errorMsg +\n".
        "            '</div>' +\n".
        "            '<div class=\"text-center mt-3\">' +\n".
        "            '<button type=\"button\" class=\"btn btn-secondary\" onclick=\"closeModal();\">Close</button>' +\n".
        "            '</div>';\n".
        "        }\n".
        "        console.error('VM creation error:', errorMsg);\n".
        "      } else {\n".
        "        if (modalBody) {\n".
        "          modalBody.innerHTML = '<div class=\"alert alert-danger\">' +\n".
        "            'Error: Unexpected response from server' +\n".
        "            '</div>' +\n".
        "            '<div class=\"text-center mt-3\">' +\n".
        "            '<button type=\"button\" class=\"btn btn-secondary\" onclick=\"closeModal();\">Close</button>' +\n".
        "            '</div>';\n".
        "        }\n".
        "        console.error('Unexpected response:', data);\n".
        "      }\n".
        "    } catch(e){\n".
        "      if (modalBody) {\n".
        "        modalBody.innerHTML = '<div class=\"alert alert-danger\">' +\n".
        "          '<strong>Error:</strong><br>' + e.message +\n".
        "          '</div>' +\n".
        "          '<div class=\"text-center mt-3\">' +\n".
        "          '<button type=\"button\" class=\"btn btn-secondary\" onclick=\"closeModal();\">Close</button>' +\n".
        "          '</div>';\n".
        "      }\n".
        "      console.error('Exception during VM creation:', e);\n".
        "    }\n".
        "  }\n".
        "  function showStep0() {\n".
        "    if (modalBody) {\n".
        "      modalBody.innerHTML =\n".
        "        '<h5 class=\"mb-3\">Create VM in Google Cloud</h5>' +\n".
        "        '<div class=\"mb-3 text-start\">' +\n".
        "          '<label class=\"form-label fw-semibold\" for=\"jitsi-machine-type\">Jitsi server machine type</label>' +\n".
        "          '<select class=\"form-select\" id=\"jitsi-machine-type\">' +\n".
        "            '<option value=\"e2-medium\">e2-medium — 2 vCPU (shared), 4 GB RAM — ~10 concurrent users</option>' +\n".
        "            '<option value=\"e2-standard-2\">e2-standard-2 — 2 vCPU, 8 GB RAM — ~20 concurrent users</option>' +\n".
        "            '<option value=\"e2-standard-4\" selected>e2-standard-4 — 4 vCPU, 16 GB RAM — ~50 concurrent users (recommended)</option>' +\n".
        "            '<option value=\"e2-standard-8\">e2-standard-8 — 8 vCPU, 32 GB RAM — ~100 concurrent users</option>' +\n".
        "            '<option value=\"n2-standard-4\">n2-standard-4 — 4 vCPU, 16 GB RAM — ~60 concurrent users (higher performance)</option>' +\n".
        "            '<option value=\"n2-standard-8\">n2-standard-8 — 8 vCPU, 32 GB RAM — ~120 concurrent users</option>' +\n".
        "          '</select>' +\n".
        "          '<small class=\"text-muted d-block mt-1\">The machine type determines how many simultaneous participants the server can handle.</small>' +\n".
        "        '</div>' +\n".
        "        '<div class=\"mb-3 text-start\">' +\n".
        "          '<div class=\"form-check\">' +\n".
        "            '<input class=\"form-check-input\" type=\"checkbox\" id=\"jibri-enable-check\">' +\n".
        "            '<label class=\"form-check-label fw-semibold\" for=\"jibri-enable-check\">' +\n".
        "              'Enable Jibri recording (dedicated VM)' +\n".
        "            '</label>' +\n".
        "          '</div>' +\n".
        "          '<small class=\"text-muted d-block mt-1 ms-4\">' +\n".
        "            'A second VM will be created as a dedicated Jibri recording server. Requires at least 4 vCPUs / 8 GB RAM.' +\n".
        "          '</small>' +\n".
        "        '</div>' +\n".
        "        '<div class=\"mb-3 text-start\" id=\"jibri-machine-row\" style=\"display:none\">' +\n".
        "          '<label class=\"form-label fw-semibold\" for=\"jibri-machine-type\">Jibri VM machine type</label>' +\n".
        "          '<input type=\"text\" class=\"form-control\" id=\"jibri-machine-type\" value=\"n2-standard-4\">' +\n".
        "          '<small class=\"text-muted\">Minimum recommended: <code>n2-standard-4</code> (4 vCPUs, 16 GB RAM).</small>' +\n".
        "        '</div>' +\n".
        "        '<div class=\"mb-3 text-start\" id=\"gcs-enable-row\" style=\"display:none\">' +\n".
        "          '<div class=\"form-check\">' +\n".
        "            '<input class=\"form-check-input\" type=\"checkbox\" id=\"gcs-enable-check\">' +\n".
        "            '<label class=\"form-check-label fw-semibold\" for=\"gcs-enable-check\">' +\n".
        "              'Upload recordings to Google Cloud Storage' +\n".
        "            '</label>' +\n".
        "          '</div>' +\n".
        "          '<small class=\"text-muted d-block mt-1 ms-4\">' +\n".
        "            'Recordings will be uploaded to a GCS bucket and served via a permanent public URL instead of the Jibri VM disk.' +\n".
        "          '</small>' +\n".
        "        '</div>' +\n".
        "        '<div class=\"d-flex justify-content-end gap-2 mt-3\">' +\n".
        "          '<button type=\"button\" class=\"btn btn-secondary\" onclick=\"closeModal();\">Cancel</button>' +\n".
        "          '<button type=\"button\" class=\"btn btn-primary\" id=\"jibri-confirm-btn\">Create VM</button>' +\n".
        "        '</div>';\n".
        "      var check = document.getElementById('jibri-enable-check');\n".
        "      var machineRow = document.getElementById('jibri-machine-row');\n".
        "      var gcsRow = document.getElementById('gcs-enable-row');\n".
        "      var confirmBtn = document.getElementById('jibri-confirm-btn');\n".
        "      if (check && machineRow) {\n".
        "        check.addEventListener('change', function() {\n".
        "          machineRow.style.display = check.checked ? '' : 'none';\n".
        "          if (gcsRow) gcsRow.style.display = check.checked ? '' : 'none';\n".
        "        });\n".
        "      }\n".
        "      if (confirmBtn) {\n".
        "        confirmBtn.addEventListener('click', function() {\n".
        "          var enableJibri = check && check.checked;\n".
        "          var machineTypeEl = document.getElementById('jibri-machine-type');\n".
        "          var jibriMachine = (machineTypeEl && machineTypeEl.value.trim()) || 'n2-standard-4';\n".
        "          var jitsiMachineEl = document.getElementById('jitsi-machine-type');\n".
        "          var jitsiMachine = (jitsiMachineEl && jitsiMachineEl.value.trim()) || 'e2-standard-4';\n".
        "          var gcsCheck = document.getElementById('gcs-enable-check');\n".
        "          var enableGcs = enableJibri && gcsCheck && gcsCheck.checked;\n".
        "          startVMCreation(enableJibri, jibriMachine, enableGcs, jitsiMachine);\n".
        "        });\n".
        "      }\n".
        "    }\n".
        "  }\n".
        "  btn.addEventListener('click', function(){\n".
        "    showModal();\n".
        "    showStep0();\n".
        "  });\n".
        "\n".
        "  // Check if there's a server in provisioning state on page load\n".
        "  (async function checkOnLoad(){\n".
        "    try {\n".
        "      var response = await fetch(cfg.listUrl);\n".
        "      var servers = await response.json();\n".
        "      if (servers && servers.length > 0) {\n".
        "        for (var i = 0; i < servers.length; i++) {\n".
        "          var srv = servers[i];\n".
        "          if (srv.provisioningstatus && srv.provisioningstatus !== 'ready' && srv.provisioningstatus !== 'error') {\n".
        "            // Found a server being provisioned\n".
        "            vmInfo.instancename = srv.gcpinstancename;\n".
        "            console.log('Found server in provisioning:', vmInfo.instancename, 'status:', srv.provisioningstatus);\n".
        "            showModal();\n".
        "            if (modalBody) {\n".
        "              modalBody.innerHTML = '<h5>⚙️ Resuming provisioning...</h5><div class=\"text-center\"><div class=\"spinner-border spinner-border-sm\" role=\"status\"></div></div>';\n".
        "            }\n".
        "            setTimeout(checkJitsiReady, 2000);\n".
        "            break;\n".
        "          }\n".
        "        }\n".
        "      }\n".
        "    } catch(e) {\n".
        "      console.log('Could not check for provisioning servers:', e);\n".
        "    }\n".
        "  })();\n".
        "})();"
        // phpcs:enable
    );


    $gcpclient = null;
    try {
        if (class_exists('Google\\Client') && class_exists('Google\\Service\\Compute')) {
            $gcpclient = mod_jitsi_gcp_client();
        }
    } catch (Exception $e) {
        // Si falla la autenticación, no mostraremos estados.
        debugging('Failed to initialize GCP client: ' . $e->getMessage(), DEBUG_NORMAL);
    }

    $servers = $DB->get_records('jitsi_servers', null, 'name ASC');
    $table = new html_table();
    $table->head = [
        get_string('name'),
        get_string('type', 'mod_jitsi'),
        get_string('domain', 'mod_jitsi'),
        get_string('status', 'mod_jitsi'), // Nueva columna.
        get_string('actions', 'mod_jitsi'),
    ];

    $gcpserverids = []; // Para recopilar IDs de servidores GCP.

    foreach ($servers as $s) {
        switch ($s->type) {
            case 0:
                $typestring = 'Server without token';
                break;
            case 1:
                $typestring = 'Self-hosted (JWT)';
                break;
            case 2:
                $typestring = '8x8 server';
                break;
            case 3:
                $typestring = '🌩️ GCP Auto-Managed <span class="badge bg-warning text-dark">BETA</span>';
                break;
            default:
                $typestring = get_string('unknowntype', 'mod_jitsi');
        }

        // Obtener estado del servidor GCP y guardarlo para usar en botones.
        $jibribadge = '';
        if (!empty($s->jibri_enabled)) {
            switch ($s->jibri_provisioningstatus ?? '') {
                case 'ready':
                    $jibribadge = ' <span class="badge bg-success ms-1" title="' . s($s->jibri_gcpinstancename) . '">🎥 Jibri ready</span>';
                    break;
                case 'error':
                    $jibribadge = ' <span class="badge bg-danger ms-1" title="' . s($s->jibri_provisioningerror) . '">🎥 Jibri error</span>';
                    break;
                case '':
                    $jibribadge = ' <span class="badge bg-secondary ms-1">🎥 Jibri pending</span>';
                    break;
                default:
                    $jibribadge = ' <span class="badge bg-info ms-1">🎥 Jibri: ' . s($s->jibri_provisioningstatus) . '</span>';
            }
        }
        $statushtml = '<span class="badge bg-secondary" id="gcp-status-' . $s->id . '">N/A</span>';
        $instancestatus = null; // Variable para guardar el estado real.

        if ($s->type == 3 && !empty($s->gcpproject) && !empty($s->gcpzone) && !empty($s->gcpinstancename)) {
            $gcpserverids[] = $s->id;

            if ($gcpclient) {
                try {
                    $instance = $gcpclient->instances->get($s->gcpproject, $s->gcpzone, $s->gcpinstancename);
                    $status = $instance->getStatus();
                    $instancestatus = $status; // Guardar estado para lógica de botones.

                    switch ($status) {
                        case 'RUNNING':
                            $statushtml = '<span class="badge bg-success" id="gcp-status-' . $s->id . '">🟢 Running</span>';
                            break;
                        case 'STOPPED':
                        case 'TERMINATED':
                            $statushtml = '<span class="badge bg-danger" id="gcp-status-' . $s->id . '">🔴 Stopped</span>';
                            break;
                        case 'STOPPING':
                            $statushtml = '<span class="badge bg-warning" id="gcp-status-' . $s->id . '">🟡 Stopping...</span>';
                            break;
                        case 'PROVISIONING':
                        case 'STAGING':
                            $statushtml = '<span class="badge bg-info" id="gcp-status-' . $s->id . '">🔵 Starting...</span>';
                            break;
                        case 'SUSPENDING':
                            $statushtml = '<span class="badge bg-warning" id="gcp-status-' . $s->id . '">🟡 Suspending...</span>';
                            break;
                        case 'SUSPENDED':
                            $statushtml = '<span class="badge bg-secondary" id="gcp-status-' . $s->id . '">⚫ Suspended</span>';
                            break;
                        case 'REPAIRING':
                            $statushtml = '<span class="badge bg-warning" id="gcp-status-' . $s->id . '">🔧 Repairing...</span>';
                            break;
                        default:
                            $statushtml = '<span class="badge bg-secondary" id="gcp-status-' . $s->id . '">' .
                              htmlspecialchars($status) . '</span>';
                    }
                } catch (Exception $e) {
                    if (strpos($e->getMessage(), 'notFound') !== false || strpos($e->getMessage(), '404') !== false) {
                        $statushtml = '<span class="badge bg-dark" id="gcp-status-' . $s->id . '">❌ Not Found</span>';
                        $instancestatus = 'NOT_FOUND';
                    } else {
                        $statushtml = '<span class="badge bg-secondary" id="gcp-status-' . $s->id . '" title="' .
                          htmlspecialchars($e->getMessage()) . '">⚠️ Error</span>';
                        $instancestatus = 'ERROR';
                    }
                }
            }
        }

        $editurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'edit', 'id' => $s->id]);
        $deleteurl = new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'delete', 'id' => $s->id]);

        // Solo mostrar Edit si NO es GCP.
        $links = '';
        if ($s->type != 3) {
            $links = html_writer::link($editurl, get_string('edit'));
        }

        // Agregar acciones de start/stop según el estado real.
        if ($s->type == 3 && !empty($s->gcpproject) && !empty($s->gcpzone) && !empty($s->gcpinstancename)) {
            $starturl = new moodle_url('/mod/jitsi/servermanagement.php', [
                'action' => 'gcpstart',
                'id' => $s->id,
                'sesskey' => sesskey(),
            ]);
            $stopurl = new moodle_url('/mod/jitsi/servermanagement.php', [
                'action' => 'gcpstop',
                'id' => $s->id,
                'sesskey' => sesskey(),
            ]);

            if (!empty($links)) {
                $links .= ' | ';
            }

            // Lógica condicional de botones según estado.
            $buttonshown = false;

            // Mostrar botón START solo si está apagado, suspendido o en error.
            if (in_array($instancestatus, ['STOPPED', 'TERMINATED', 'SUSPENDED', 'NOT_FOUND', 'ERROR', null])) {
                $links .= html_writer::link(
                    $starturl,
                    '▶️ Start',
                    ['class' => 'btn btn-sm btn-success', 'id' => 'gcp-btn-start-' . $s->id],
                );
                $buttonshown = true;
            }

            // Mostrar botón STOP solo si está corriendo o arrancando.
            if (in_array($instancestatus, ['RUNNING', 'PROVISIONING', 'STAGING'])) {
                if ($buttonshown) {
                    $links .= ' | ';
                }
                $links .= html_writer::link(
                    $stopurl,
                    '⏹️ Stop',
                    ['class' => 'btn btn-sm btn-warning', 'id' => 'gcp-btn-stop-' . $s->id],
                );
                $buttonshown = true;
            }

            // Mostrar mensaje de espera si está en transición.
            if (in_array($instancestatus, ['STOPPING', 'SUSPENDING', 'REPAIRING'])) {
                if ($buttonshown) {
                    $links .= ' | ';
                }
                $links .= '<span class="badge bg-secondary" id="gcp-btn-wait-' . $s->id . '">⏳ Please wait...</span>';
                $buttonshown = true;
            }

            // Si no hay estado disponible, mostrar ambos botones deshabilitados.
            if (!$buttonshown) {
                $links .= '<span class="text-muted">Actions unavailable</span>';
            }
        }

        // Show Enable/Disable GCS button for GCP servers with Jibri ready.
        if ($s->type == 3 && !empty($s->jibri_enabled) && ($s->jibri_provisioningstatus ?? '') === 'ready') {
            if (!empty($links)) {
                $links .= ' | ';
            }
            if (empty($s->gcs_enabled)) {
                $enablegcsurl = new moodle_url('/mod/jitsi/servermanagement.php', [
                    'action' => 'enablegcs', 'id' => $s->id, 'sesskey' => sesskey(),
                ]);
                $links .= html_writer::link(
                    $enablegcsurl,
                    get_string('enablegcs', 'jitsi'),
                    ['class' => 'btn btn-sm btn-outline-secondary']
                );
            } else {
                $disablegcsurl = new moodle_url('/mod/jitsi/servermanagement.php', [
                    'action' => 'disablegcs', 'id' => $s->id, 'sesskey' => sesskey(),
                ]);
                $links .= html_writer::link(
                    $disablegcsurl,
                    get_string('disablegcs', 'jitsi'),
                    ['class' => 'btn btn-sm btn-outline-warning']
                );
            }
        }

        // Show "Add Jibri" button for GCP servers that are ready and don't have Jibri yet.
        if ($s->type == 3 && empty($s->jibri_enabled) && ($s->provisioningstatus ?? '') === 'ready') {
            $addjibriurl = new moodle_url('/mod/jitsi/servermanagement.php', [
                'action' => 'addjibri',
                'id'     => $s->id,
            ]);
            if (!empty($links)) {
                $links .= ' | ';
            }
            $links .= html_writer::link($addjibriurl, '🎥 Add Jibri', ['class' => 'btn btn-sm btn-outline-info']);
        }

        // Delete siempre disponible.
        if (!empty($links)) {
            $links .= ' | ';
        }
        $links .= html_writer::link($deleteurl, get_string('delete'));

        $table->data[] = [
            format_string($s->name),
            $typestring,
            format_string($s->domain),
            $statushtml . $jibribadge,
            $links,
        ];
    }
    echo html_writer::table($table);

    // Actualizar JavaScript para también actualizar botones dinámicamente.
    if (!empty($gcpserverids)) {
        $statusurl = (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpserversstatus']))->out(false);
        $gcpidsjs = json_encode($gcpserverids);
        $sesskeyjs = sesskey();
        $wwwroot = $CFG->wwwroot;
        // phpcs:disable
        $PAGE->requires->js_init_code(
            "(function(){\n".
            "  var gcpIds = ".$gcpidsjs.";\n".
            "  if (gcpIds.length === 0) return;\n".
            "  \n".
            "  function updateStatuses(){\n".
            "    fetch('".$statusurl."', {\n".
            "      method: 'POST',\n".
            "      headers: {'Content-Type':'application/x-www-form-urlencoded'},\n".
            "      body: new URLSearchParams({sesskey: '".$sesskeyjs."', ids: gcpIds.join(',')})\n".
            "    })\n".
            "    .then(res => res.json())\n".
            "    .then(data => {\n".
            "      if (data.error) {\n".
            "        console.error('Status update error:', data.error);\n".
            "        return;\n".
            "      }\n".
            "      for (var id in data) {\n".
            "        var badge = document.getElementById('gcp-status-' + id);\n".
            "        if (!badge) continue;\n".
            "        var status = data[id].status;\n".
            "        var badgeClass = 'badge ';\n".
            "        var badgeText = '';\n".
            "        \n".
            "        // ⬅️ Obtener contenedor de botones (celda de la tabla)\n".
            "        var row = badge.closest('tr');\n".
            "        var actionsCell = row ? row.cells[4] : null;\n".
            "        \n".
            "        switch(status) {\n".
            "          case 'RUNNING':\n".
            "            badgeClass += 'bg-success';\n".
            "            badgeText = '🟢 Running';\n".
            "            updateButtons(id, actionsCell, 'running');\n".
            "            break;\n".
            "          case 'STOPPED':\n".
            "          case 'TERMINATED':\n".
            "            badgeClass += 'bg-danger';\n".
            "            badgeText = '🔴 Stopped';\n".
            "            updateButtons(id, actionsCell, 'stopped');\n".
            "            break;\n".
            "          case 'STOPPING':\n".
            "            badgeClass += 'bg-warning';\n".
            "            badgeText = '🟡 Stopping...';\n".
            "            updateButtons(id, actionsCell, 'transition');\n".
            "            break;\n".
            "          case 'PROVISIONING':\n".
            "          case 'STAGING':\n".
            "            badgeClass += 'bg-info';\n".
            "            badgeText = '🔵 Starting...';\n".
            "            updateButtons(id, actionsCell, 'running');\n".
            "            break;\n".
            "          case 'SUSPENDING':\n".
            "            badgeClass += 'bg-warning';\n".
            "            badgeText = '🟡 Suspending...';\n".
            "            updateButtons(id, actionsCell, 'transition');\n".
            "            break;\n".
            "          case 'SUSPENDED':\n".
            "            badgeClass += 'bg-secondary';\n".
            "            badgeText = '⚫ Suspended';\n".
            "            updateButtons(id, actionsCell, 'stopped');\n".
            "            break;\n".
            "          case 'REPAIRING':\n".
            "            badgeClass += 'bg-warning';\n".
            "            badgeText = '🔧 Repairing...';\n".
            "            updateButtons(id, actionsCell, 'transition');\n".
            "            break;\n".
            "          case 'NOT_FOUND':\n".
            "            badgeClass += 'bg-dark';\n".
            "            badgeText = '❌ Not Found';\n".
            "            updateButtons(id, actionsCell, 'stopped');\n".
            "            break;\n".
            "          case 'ERROR':\n".
            "            badgeClass += 'bg-secondary';\n".
            "            badgeText = '⚠️ Error';\n".
            "            if (data[id].message) {\n".
            "              badge.title = data[id].message;\n".
            "            }\n".
            "            updateButtons(id, actionsCell, 'stopped');\n".
            "            break;\n".
            "          default:\n".
            "            badgeClass += 'bg-secondary';\n".
            "            badgeText = status;\n".
            "        }\n".
            "        badge.className = badgeClass;\n".
            "        badge.textContent = badgeText;\n".
            "      }\n".
            "    })\n".
            "    .catch(err => console.error('Status update failed:', err));\n".
            "  }\n".
            "  \n".
            "  function updateButtons(serverId, actionsCell, state) {\n".
            "    if (!actionsCell) return;\n".
            "    \n".
            "    var startBtn = document.getElementById('gcp-btn-start-' + serverId);\n".
            "    var stopBtn = document.getElementById('gcp-btn-stop-' + serverId);\n".
            "    var waitSpan = document.getElementById('gcp-btn-wait-' + serverId);\n".
            "    \n".
            "    // Obtener el contenido de la celda para mantener links estáticos\n".
            "    var cellHTML = actionsCell.innerHTML;\n".
            "    var deleteLink = cellHTML.match(/(<a[^>]*action=delete[^>]*>.*?<\\/a>)/i);\n".
            "    deleteLink = deleteLink ? deleteLink[0] : '';\n".
            "    var jibriLink = cellHTML.match(/(<a[^>]*action=addjibri[^>]*>.*?<\\/a>)/i);\n".
            "    jibriLink = jibriLink ? jibriLink[0] : '';\n".
            "    var gcsLink = cellHTML.match(/(<a[^>]*action=(?:enablegcs|disablegcs)[^>]*>.*?<\\/a>)/i);\n".
            "    gcsLink = gcsLink ? gcsLink[0] : '';\n".
            "    \n".
            "    var startUrl = '".$wwwroot."/mod/jitsi/servermanagement.php?action=gcpstart&id=' + serverId + '&sesskey=".$sesskeyjs."';\n".
            "    var stopUrl = '".$wwwroot."/mod/jitsi/servermanagement.php?action=gcpstop&id=' + serverId + '&sesskey=".$sesskeyjs."';\n".
            "    \n".
            "    var newButtons = '';\n".
            "    \n".
            "    if (state === 'stopped') {\n".
            "      newButtons = '<a href=\"' + startUrl + '\" class=\"btn btn-sm btn-success\" id=\"gcp-btn-start-' + serverId + '\">▶️ Start</a>';\n".
            "    } else if (state === 'running') {\n".
            "      newButtons = '<a href=\"' + stopUrl + '\" class=\"btn btn-sm btn-warning\" id=\"gcp-btn-stop-' + serverId + '\">⏹️ Stop</a>';\n".
            "    } else if (state === 'transition') {\n".
            "      newButtons = '<span class=\"badge bg-secondary\" id=\"gcp-btn-wait-' + serverId + '\">⏳ Please wait...</span>';\n".
            "    }\n".
            "    \n".
            "    var extra = '';\n".
            "    if (jibriLink) { extra += ' | ' + jibriLink; }\n".
            "    if (gcsLink) { extra += ' | ' + gcsLink; }\n".
            "    if (deleteLink) { extra += ' | ' + deleteLink; }\n".
            "    actionsCell.innerHTML = newButtons + extra;\n".
            "  }\n".
            "  \n".
            "  // Actualizar cada 10 segundos\n".
            "  setInterval(updateStatuses, 10000);\n".
            "  // Primera actualización después de 2 segundos\n".
            "  setTimeout(updateStatuses, 2000);\n".
            "})();"
        );
        // phpcs:enable
    }
} // End of TABLE VIEW (else block)

echo $OUTPUT->footer();
