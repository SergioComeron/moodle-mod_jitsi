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
// They authenticate with the per-server provisioning token (see \mod_jitsi\local\vm_callback).
if ($rawaction === 'jitsiready' || $rawaction === 'jibriready'
        || $rawaction === 'jibrirecording' || $rawaction === 'jibristatus') {
    define('NO_MOODLE_COOKIES', true);
    require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php');
    require_once($CFG->dirroot . '/mod/jitsi/lib.php');

    @header('Content-Type: application/json');
    [$httpcode, $payload] = \mod_jitsi\local\vm_callback::dispatch($rawaction);
    http_response_code($httpcode);
    echo json_encode($payload);
    exit;
}
// phpcs:enable

// Para el resto de acciones: cargar Moodle normalmente.
require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php');

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
// Load the Google API PHP Client if available (GCP server management).
\mod_jitsi\local\gcp::load_google_api();

$id      = optional_param('id', 0, PARAM_INT);
$confirm = optional_param('confirm', 0, PARAM_BOOL);

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
    $sscript       = \mod_jitsi\local\gcp_scripts::default_startup_script();
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
        $compute = \mod_jitsi\local\gcp::client();
        // Derive a short network name for CLI instructions (e.g., "default").
        $networkshort = $network;
        if (strpos($networkshort, '/') !== false) {
            $parts = explode('/', $networkshort);
            $networkshort = end($parts);
        }
        // Ensure VPC firewall rule exists for ports 80/443 (tcp) and 10000 (udp).
        $fwwarn = '';
        $fwwarndetail = '';
        $fwstatus = \mod_jitsi\local\gcp::ensure_firewall($compute, $project, $network);
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
            $availableip = \mod_jitsi\local\gcp::find_available_static_ip($compute, $project, $region);

            if ($availableip) {
                // Reuse existing available IP.
                $staticipname = $availableip['name'];
                $staticipaddress = $availableip['address'];
                $ipreused = true;
                debugging("✅ Reusing available static IP: {$staticipname} ({$staticipaddress})", DEBUG_NORMAL);
            } else {
                // No available IP found, create a new one.
                $staticipname = $instancename . '-ip';
                \mod_jitsi\local\gcp::reserve_static_ip($compute, $project, $region, $staticipname);
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
                $gcs = \mod_jitsi\local\gcs::client();
                $location = preg_replace('/-[a-z]$/', '', $zone);
                $bucketname = \mod_jitsi\local\gcs::bucket_name($project, $serverid);
                \mod_jitsi\local\gcs::ensure_bucket($gcs, $project, $bucketname, $location);
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

        $opname = \mod_jitsi\local\gcp::create_instance($compute, $project, $zone, [
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
        $compute = \mod_jitsi\local\gcp::client();
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

    // Return list of servers being provisioned. Ignore runs without activity in the
    // last hour: the longest in-flow waits (DNS propagation, installation) time out
    // at 15 minutes, so anything older is a stale leftover that would otherwise
    // resurrect the provisioning modal forever on every page load.
    $servers = $DB->get_records_sql(
        "SELECT id, name, gcpinstancename, domain, gcpstaticipaddress, provisioningstatus
         FROM {jitsi_servers}
         WHERE type = 3 AND provisioningstatus IS NOT NULL AND provisioningstatus != ''
           AND provisioningstatus NOT IN ('ready', 'error')
           AND timemodified > :cutoff
         ORDER BY timecreated DESC",
        ['cutoff' => time() - HOURSECS]
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
        $gcpclient = \mod_jitsi\local\gcp::client();

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
        $compute = \mod_jitsi\local\gcp::client();
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
                    $compute = \mod_jitsi\local\gcp::client();

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
                    $compute = \mod_jitsi\local\gcp::client();

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

// Action: Add a new Jibri VM to an existing pool.
if ($action === 'addtojibripool' && $id > 0) {
    require_sesskey();
    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('invalidserverid', 'mod_jitsi');
    }
    if ($server->type != 3 || empty($server->jibri_enabled)) {
        \core\notification::add(
            'Jibri pool only available for GCP servers with Jibri enabled.',
            \core\output\notification::NOTIFY_ERROR
        );
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }
    $task = new \mod_jitsi\task\provision_jibri_vm();
    $task->set_custom_data(['serverid' => $server->id]);
    \core\task\manager::queue_adhoc_task($task, true);
    \core\notification::add('New Jibri VM queued for provisioning.', \core\output\notification::NOTIFY_SUCCESS);
    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

// Action: Delete a single Jibri pool entry (and its GCP VM).
if ($action === 'deletejibrientry' && $id > 0) {
    require_sesskey();
    $poolentryid = optional_param('poolentryid', 0, PARAM_INT);
    if (!$server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        throw new moodle_exception('invalidserverid', 'mod_jitsi');
    }
    if ($poolentryid && $entry = $DB->get_record('jitsi_jibri_pool', ['id' => $poolentryid, 'serverid' => $id])) {
        if (!empty($entry->gcpinstancename) && !empty($server->gcpproject) && !empty($server->gcpzone)) {
            try {
                $compute = \mod_jitsi\local\gcp::client();
                $compute->instances->delete($server->gcpproject, $server->gcpzone, $entry->gcpinstancename);
            } catch (\Throwable $e) {
                debugging('Could not delete Jibri VM: ' . $e->getMessage(), DEBUG_NORMAL);
            }
        }
        $DB->delete_records('jitsi_jibri_pool', ['id' => $entry->id]);
        // If no pool entries remain, clear only the legacy gcpinstancename pointer.
        // jibri_provisioningstatus must stay 'ready' so the pool UI and cron keep working.
        if (!$DB->record_exists('jitsi_jibri_pool', ['serverid' => $id])) {
            $DB->set_field('jitsi_servers', 'jibri_gcpinstancename', '', ['id' => $id]);
        }
        \core\notification::add('Jibri VM removed.', \core\output\notification::NOTIFY_SUCCESS);
    }
    redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
}

// Action: Update desired pool size (AJAX).
if ($action === 'updatepoolsize' && $id > 0) {
    require_sesskey();
    @header('Content-Type: application/json');
    $poolsize = optional_param('poolsize', 1, PARAM_INT);
    $poolsize = max(1, min(10, $poolsize));
    if ($server = $DB->get_record('jitsi_servers', ['id' => $id])) {
        $DB->set_field('jitsi_servers', 'jibri_pool_size', $poolsize, ['id' => $id]);
        echo json_encode(['status' => 'ok', 'poolsize' => $poolsize]);
    } else {
        http_response_code(404);
        echo json_encode(['status' => 'error']);
    }
    exit;
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

    echo $OUTPUT->render_from_template('mod_jitsi/addjibri_confirm', [
        'hostname' => $hostname,
        'script' => $reconfigscript,
        'confirmurl' => (new moodle_url('/mod/jitsi/servermanagement.php', [
            'action'  => 'addjibri',
            'id'      => $id,
            'confirm' => 1,
            'sesskey' => sesskey(),
        ]))->out(false),
        'cancelurl' => (new moodle_url('/mod/jitsi/servermanagement.php'))->out(false),
        'sesskey' => sesskey(),
    ]);

    $PAGE->requires->js_call_amd('mod_jitsi/copy_button', 'init', [[
        'buttonId' => 'copy-reconfig-script',
        'sourceId' => 'jibri-reconfig-script',
    ]]);

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
        $compute = \mod_jitsi\local\gcp::client();
        $compute->instances->start($server->gcpproject, $server->gcpzone, $server->gcpinstancename);

        \core\notification::add(
            "Starting GCP instance: {$server->gcpinstancename}",
            \core\output\notification::NOTIFY_SUCCESS
        );

        // Also start all Jibri pool VMs.
        if (!empty($server->jibri_enabled)) {
            $poolentries = $DB->get_records('jitsi_jibri_pool', ['serverid' => $server->id]);
            foreach ($poolentries as $poolentry) {
                if (empty($poolentry->gcpinstancename)) {
                    continue;
                }
                try {
                    $compute->instances->start($server->gcpproject, $server->gcpzone, $poolentry->gcpinstancename);
                    $poolentry->status       = 'provisioning';
                    $poolentry->timemodified = time();
                    $DB->update_record('jitsi_jibri_pool', $poolentry);
                    \core\notification::add(
                        "Starting Jibri GCP instance: {$poolentry->gcpinstancename}",
                        \core\output\notification::NOTIFY_SUCCESS
                    );
                } catch (Exception $ejibri) {
                    \core\notification::add(
                        "Failed to start Jibri instance {$poolentry->gcpinstancename}: " . $ejibri->getMessage(),
                        \core\output\notification::NOTIFY_WARNING
                    );
                }
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
        $compute = \mod_jitsi\local\gcp::client();
        $compute->instances->stop($server->gcpproject, $server->gcpzone, $server->gcpinstancename);

        \core\notification::add(
            "Stopping GCP instance: {$server->gcpinstancename}",
            \core\output\notification::NOTIFY_SUCCESS
        );

        // Also stop all Jibri pool VMs.
        if (!empty($server->jibri_enabled)) {
            $poolentries = $DB->get_records('jitsi_jibri_pool', ['serverid' => $server->id]);
            foreach ($poolentries as $poolentry) {
                if (empty($poolentry->gcpinstancename)) {
                    continue;
                }
                try {
                    $compute->instances->stop($server->gcpproject, $server->gcpzone, $poolentry->gcpinstancename);
                    $poolentry->status       = 'error';
                    $poolentry->timemodified = time();
                    $DB->update_record('jitsi_jibri_pool', $poolentry);
                    \core\notification::add(
                        "Stopping Jibri GCP instance: {$poolentry->gcpinstancename}",
                        \core\output\notification::NOTIFY_SUCCESS
                    );
                } catch (Exception $ejibri) {
                    \core\notification::add(
                        "Failed to stop Jibri instance {$poolentry->gcpinstancename}: " . $ejibri->getMessage(),
                        \core\output\notification::NOTIFY_WARNING
                    );
                }
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
        \core\notification::add('GCS is only available for GCP servers with Jibri enabled.', \core\output\notification::NOTIFY_ERROR); // phpcs:ignore moodle.Files.LineLength.MaxExceeded
        redirect(new moodle_url('/mod/jitsi/servermanagement.php'));
    }

    try {
        $project = $server->gcpproject;
        $zone = $server->gcpzone;
        $location = preg_replace('/-[a-z]$/', '', $zone);
        $bucketname = !empty($server->gcs_bucket) ? $server->gcs_bucket : \mod_jitsi\local\gcs::bucket_name($project, $server->id);

        $gcs = \mod_jitsi\local\gcs::client();
        \mod_jitsi\local\gcs::ensure_bucket($gcs, $project, $bucketname, $location);

        $server->gcs_enabled = 1;
        $server->gcs_bucket = $bucketname;
        $server->timemodified = time();
        $DB->update_record('jitsi_servers', $server);

        // Update Jibri VM metadata so finalize script uses GCS for new recordings.
        if (!empty($server->jibri_gcpinstancename)) {
            try {
                $compute = \mod_jitsi\local\gcp::client();
                \mod_jitsi\local\gcp::update_instance_metadata($compute, $project, $zone, $server->jibri_gcpinstancename, [
                    'GCS_BUCKET' => $bucketname,
                ]);
            } catch (\Throwable $metaex) {
                debugging('Could not update Jibri VM metadata: ' . $metaex->getMessage(), DEBUG_NORMAL);
                \core\notification::add(
                    'GCS enabled in DB but could not update Jibri VM metadata (VM may be stopped). New recordings will use GCS when VM is next started.', // phpcs:ignore moodle.Files.LineLength.MaxExceeded
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
                $compute = \mod_jitsi\local\gcp::client();
                \mod_jitsi\local\gcp::update_instance_metadata($compute, $server->gcpproject, $server->gcpzone, $server->jibri_gcpinstancename, [ // phpcs:ignore moodle.Files.LineLength.MaxExceeded
                    'GCS_BUCKET' => '',
                ]);
            } catch (\Throwable $metaex) {
                debugging('Could not update Jibri VM metadata: ' . $metaex->getMessage(), DEBUG_NORMAL);
            }
        }

        \core\notification::add('GCS recordings disabled. Existing recordings in GCS are preserved.', \core\output\notification::NOTIFY_SUCCESS); // phpcs:ignore moodle.Files.LineLength.MaxExceeded
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

    $PAGE->requires->js_call_amd('mod_jitsi/gcp_wizard', 'init', [[
        'sesskey' => sesskey(),
        'statusUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpstatusjson']))->out(false),
        'createUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'creategcpvm', 'ajax' => 1]))->out(false),
        'listUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'listprovisioningservers']))->out(false),
        'redirectUrl' => (new moodle_url('/mod/jitsi/servermanagement.php'))->out(false),
        'hostname' => (string) get_config('mod_jitsi', 'gcp_hostname'),
        'checkReadyUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'checkjitsiready']))->out(false),
    ]]);

    $gcpclient = null;
    try {
        if (class_exists('Google\\Client') && class_exists('Google\\Service\\Compute')) {
            $gcpclient = \mod_jitsi\local\gcp::client();
        }
    } catch (Exception $e) {
        // Si falla la autenticación, no mostraremos estados.
        debugging('Failed to initialize GCP client: ' . $e->getMessage(), DEBUG_NORMAL);
    }

    $servers = $DB->get_records('jitsi_servers', null, 'name ASC');
    $gcpserverids = []; // Para recopilar IDs de servidores GCP.
    $serverscontext = [];

    foreach ($servers as $s) {
        switch ($s->type) {
            case 0:
                $typelabel = 'Server without token';
                break;
            case 1:
                $typelabel = 'Self-hosted (JWT)';
                break;
            case 2:
                $typelabel = '8x8 server';
                break;
            case 3:
                $typelabel = '🌩️ GCP Auto-Managed';
                break;
            default:
                $typelabel = get_string('unknowntype', 'mod_jitsi');
        }

        // Jibri pool badges (or legacy single badge when no pool rows exist yet).
        $jibripool = null;
        $jibrilegacy = null;
        if (!empty($s->jibri_enabled)) {
            $poolentries = $DB->get_records('jitsi_jibri_pool', ['serverid' => $s->id], 'id ASC');
            if (!empty($poolentries)) {
                $entries = [];
                foreach ($poolentries as $pe) {
                    switch ($pe->status) {
                        case 'idle':
                            $pbadgeclass = 'bg-success';
                            $pbadgetext  = '✅ idle';
                            break;
                        case 'recording':
                            $pbadgeclass = 'bg-primary';
                            $pbadgetext  = '🔴 recording';
                            break;
                        case 'streaming':
                            $pbadgeclass = 'bg-primary';
                            $pbadgetext  = '📡 streaming';
                            break;
                        case 'error':
                            $pbadgeclass = 'bg-danger';
                            $pbadgetext  = '❌ error';
                            break;
                        default:
                            $pbadgeclass = 'bg-info';
                            $pbadgetext  = '⏳ ' . $pe->status;
                    }
                    $entries[] = [
                        'badgeclass' => $pbadgeclass,
                        'badgetext'  => $pbadgetext,
                        'title'      => $pe->gcpinstancename,
                        'deleteurl'  => (new moodle_url('/mod/jitsi/servermanagement.php', [
                            'action'      => 'deletejibrientry',
                            'id'          => $s->id,
                            'poolentryid' => $pe->id,
                            'sesskey'     => sesskey(),
                        ]))->out(false),
                    ];
                }
                $jibripool = [
                    'serverid' => $s->id,
                    'poolsize' => (int)($s->jibri_pool_size ?? 1),
                    'entries'  => $entries,
                    'addurl'   => (new moodle_url('/mod/jitsi/servermanagement.php', [
                        'action'  => 'addtojibripool',
                        'id'      => $s->id,
                        'sesskey' => sesskey(),
                    ]))->out(false),
                ];
            } else {
                switch ($s->jibri_provisioningstatus ?? '') {
                    case 'ready':
                        $jibrilegacy = ['badgeclass' => 'bg-success', 'badgetext' => '🎥 Jibri ready',
                            'title' => $s->jibri_gcpinstancename];
                        break;
                    case 'error':
                        $jibrilegacy = ['badgeclass' => 'bg-danger', 'badgetext' => '🎥 Jibri error',
                            'title' => $s->jibri_provisioningerror];
                        break;
                    case '':
                        $jibrilegacy = ['badgeclass' => 'bg-secondary', 'badgetext' => '🎥 Jibri pending', 'title' => ''];
                        break;
                    default:
                        $jibrilegacy = ['badgeclass' => 'bg-info',
                            'badgetext' => '🎥 Jibri: ' . $s->jibri_provisioningstatus, 'title' => ''];
                }
            }
        }

        // Live GCP instance status badge.
        $statusclass = 'bg-secondary';
        $statustext = 'N/A';
        $statustitle = '';
        $instancestatus = null;

        if ($s->type == 3 && !empty($s->gcpproject) && !empty($s->gcpzone) && !empty($s->gcpinstancename)) {
            $gcpserverids[] = $s->id;

            if ($gcpclient) {
                try {
                    $instance = $gcpclient->instances->get($s->gcpproject, $s->gcpzone, $s->gcpinstancename);
                    $instancestatus = $instance->getStatus();

                    switch ($instancestatus) {
                        case 'RUNNING':
                            $statusclass = 'bg-success';
                            $statustext = '🟢 Running';
                            break;
                        case 'STOPPED':
                        case 'TERMINATED':
                            $statusclass = 'bg-danger';
                            $statustext = '🔴 Stopped';
                            break;
                        case 'STOPPING':
                            $statusclass = 'bg-warning';
                            $statustext = '🟡 Stopping...';
                            break;
                        case 'PROVISIONING':
                        case 'STAGING':
                            $statusclass = 'bg-info';
                            $statustext = '🔵 Starting...';
                            break;
                        case 'SUSPENDING':
                            $statusclass = 'bg-warning';
                            $statustext = '🟡 Suspending...';
                            break;
                        case 'SUSPENDED':
                            $statusclass = 'bg-secondary';
                            $statustext = '⚫ Suspended';
                            break;
                        case 'REPAIRING':
                            $statusclass = 'bg-warning';
                            $statustext = '🔧 Repairing...';
                            break;
                        default:
                            $statusclass = 'bg-secondary';
                            $statustext = $instancestatus;
                    }
                } catch (Exception $e) {
                    if (strpos($e->getMessage(), 'notFound') !== false || strpos($e->getMessage(), '404') !== false) {
                        $statusclass = 'bg-dark';
                        $statustext = '❌ Not Found';
                        $instancestatus = 'NOT_FOUND';
                    } else {
                        $statusclass = 'bg-secondary';
                        $statustext = '⚠️ Error';
                        $statustitle = $e->getMessage();
                        $instancestatus = 'ERROR';
                    }
                }
            }
        }

        // Action links/controls. Start/Stop/wait are always rendered for GCP servers;
        // mod_jitsi/server_status toggles their visibility on each status poll.
        $gcp = null;
        if ($s->type == 3 && !empty($s->gcpproject) && !empty($s->gcpzone) && !empty($s->gcpinstancename)) {
            $gcp = [
                'serverid'  => $s->id,
                'starturl'  => (new moodle_url('/mod/jitsi/servermanagement.php', [
                    'action' => 'gcpstart', 'id' => $s->id, 'sesskey' => sesskey(),
                ]))->out(false),
                'stopurl'   => (new moodle_url('/mod/jitsi/servermanagement.php', [
                    'action' => 'gcpstop', 'id' => $s->id, 'sesskey' => sesskey(),
                ]))->out(false),
                'showstart' => in_array($instancestatus, ['STOPPED', 'TERMINATED', 'SUSPENDED', 'NOT_FOUND', 'ERROR', null]),
                'showstop'  => in_array($instancestatus, ['RUNNING', 'PROVISIONING', 'STAGING']),
                'showwait'  => in_array($instancestatus, ['STOPPING', 'SUSPENDING', 'REPAIRING']),
            ];
        }

        $gcs = null;
        if ($s->type == 3 && !empty($s->jibri_enabled) && ($s->jibri_provisioningstatus ?? '') === 'ready') {
            $gcsenabled = !empty($s->gcs_enabled);
            $gcs = [
                'url' => (new moodle_url('/mod/jitsi/servermanagement.php', [
                    'action' => $gcsenabled ? 'disablegcs' : 'enablegcs', 'id' => $s->id, 'sesskey' => sesskey(),
                ]))->out(false),
                'label' => get_string($gcsenabled ? 'disablegcs' : 'enablegcs', 'jitsi'),
                'buttonclass' => $gcsenabled ? 'btn-outline-warning' : 'btn-outline-secondary',
            ];
        }

        $addjibriurl = null;
        if ($s->type == 3 && empty($s->jibri_enabled) && ($s->provisioningstatus ?? '') === 'ready') {
            $addjibriurl = (new moodle_url('/mod/jitsi/servermanagement.php', [
                'action' => 'addjibri',
                'id'     => $s->id,
            ]))->out(false);
        }

        $serverscontext[] = [
            'id' => $s->id,
            'name' => format_string($s->name),
            'typelabel' => $typelabel,
            'isgcp' => $s->type == 3,
            'domain' => format_string($s->domain),
            'statusclass' => $statusclass,
            'statustext' => $statustext,
            'statustitle' => $statustitle,
            'jibripool' => $jibripool,
            'jibrilegacy' => $jibrilegacy,
            'editurl' => $s->type != 3
                ? (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'edit', 'id' => $s->id]))->out(false)
                : null,
            'gcp' => $gcp,
            'gcs' => $gcs,
            'addjibriurl' => $addjibriurl,
            'deleteurl' => (new moodle_url('/mod/jitsi/servermanagement.php', [
                'action' => 'delete', 'id' => $s->id,
            ]))->out(false),
        ];
    }

    echo $OUTPUT->render_from_template('mod_jitsi/server_table', [
        'settingsurl' => (new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']))->out(false),
        'addserverurl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'add']))->out(false),
        'servers' => $serverscontext,
    ]);

    // Live status badges + Start/Stop visibility + pool size inputs (mod_jitsi/server_status).
    $PAGE->requires->js_call_amd('mod_jitsi/server_status', 'init', [[
        'sesskey' => sesskey(),
        'statusUrl' => (new moodle_url('/mod/jitsi/servermanagement.php', ['action' => 'gcpserversstatus']))->out(false),
        'poolSizeUrl' => (new moodle_url(
            '/mod/jitsi/servermanagement.php',
            ['action' => 'updatepoolsize', 'sesskey' => sesskey()]
        ))->out(false),
        'serverIds' => array_values($gcpserverids),
    ]]);
} // End of TABLE VIEW (else block)

echo $OUTPUT->footer();
