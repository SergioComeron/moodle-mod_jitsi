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
    require_once(__DIR__ . '/../../config.php');
    require_once($CFG->dirroot . '/mod/jitsi/lib.php');

    @header('Content-Type: application/json');
    [$httpcode, $payload] = \mod_jitsi\local\vm_callback::dispatch($rawaction);
    http_response_code($httpcode);
    echo json_encode($payload);
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
        html_writer::tag('small', 'Minimum recommended: <code>n2-standard-4</code> (4 vCPUs, 16 GB RAM).', ['class' => 'text-muted']), // phpcs:ignore moodle.Files.LineLength.MaxExceeded
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
            $gcpclient = \mod_jitsi\local\gcp::client();
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

        // Build Jibri pool badge(s).
        $jibribadge = '';
        if (!empty($s->jibri_enabled)) {
            $poolentries = $DB->get_records('jitsi_jibri_pool', ['serverid' => $s->id], 'id ASC');
            if (!empty($poolentries)) {
                $poolsize = (int)($s->jibri_pool_size ?? 1);
                $jibribadge .= '<div class="mt-1">';
                $jibribadge .= '<small class="text-muted">🎥 Jibri pool (desired: '
                    . '<input type="number" min="1" max="10" value="' . $poolsize . '"'
                    . ' style="width:45px" class="form-control form-control-sm d-inline-block p-0 ps-1"'
                    . ' onchange="updatePoolSize(' . $s->id . ', this.value)"'
                    . '>):</small><br>';
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
                            $pbadgetext  = '⏳ ' . s($pe->status);
                    }
                    $deletejibrientryurl = new moodle_url('/mod/jitsi/servermanagement.php', [
                        'action'      => 'deletejibrientry',
                        'id'          => $s->id,
                        'poolentryid' => $pe->id,
                        'sesskey'     => sesskey(),
                    ]);
                    $jibribadge .= '<span class="badge ' . $pbadgeclass . ' me-1" title="' . s($pe->gcpinstancename) . '">'
                        . $pbadgetext . '</span>';
                    $jibribadge .= html_writer::link(
                        $deletejibrientryurl,
                        '✕',
                        ['class' => 'text-danger small me-1', 'title' => 'Remove this Jibri VM']
                    );
                }
                $addtopoolurl = new moodle_url('/mod/jitsi/servermanagement.php', [
                    'action'  => 'addtojibripool',
                    'id'      => $s->id,
                    'sesskey' => sesskey(),
                ]);
                $jibribadge .= '<br>' . html_writer::link(
                    $addtopoolurl,
                    '+ Add Jibri',
                    ['class' => 'btn btn-xs btn-outline-secondary mt-1', 'style' => 'font-size:0.75rem;padding:1px 6px']
                );
                $jibribadge .= '</div>';
            } else {
                // No pool entries yet — show legacy provisioning status.
                switch ($s->jibri_provisioningstatus ?? '') {
                    case 'ready':
                        $jibribadge = ' <span class="badge bg-success ms-1" title="'
                            . s($s->jibri_gcpinstancename) . '">🎥 Jibri ready</span>';
                        break;
                    case 'error':
                        $jibribadge = ' <span class="badge bg-danger ms-1" title="'
                            . s($s->jibri_provisioningerror) . '">🎥 Jibri error</span>';
                        break;
                    case '':
                        $jibribadge = ' <span class="badge bg-secondary ms-1">🎥 Jibri pending</span>';
                        break;
                    default:
                        $jibribadge = ' <span class="badge bg-info ms-1">🎥 Jibri: '
                            . s($s->jibri_provisioningstatus) . '</span>';
                }
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
        $updatepoolsizeurl = (new moodle_url(
            '/mod/jitsi/servermanagement.php',
            ['action' => 'updatepoolsize', 'sesskey' => sesskey()]
        ))->out(false);
        // phpcs:disable
        $PAGE->requires->js_init_code(
            "window.updatePoolSize = function(serverid, val) {\n".
            "  fetch('" . $updatepoolsizeurl . "&id=' + serverid + '&poolsize=' + val, {method:'POST'})\n".
            "    .then(function(r){return r.json();})\n".
            "    .then(function(d){if(d.status!=='ok') alert('Could not update pool size.');});\n".
            "};\n"
        );
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
