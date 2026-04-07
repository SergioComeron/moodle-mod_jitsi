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
 * Ad-hoc task to create a Jibri recording VM in GCP after the Jitsi VM is ready.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Ad-hoc task: provision a dedicated Jibri recording VM in Google Cloud.
 *
 * Custom data expected:
 *   - serverid (int): ID of the jitsi_servers record
 *
 * @package mod_jitsi
 */
class provision_jibri_vm extends \core\task\adhoc_task {
    /**
     * Returns the component that owns this task.
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Execute the task: create the Jibri VM in GCP and update the server record.
     */
    public function execute(): void {
        global $CFG, $DB;

        $data = $this->get_custom_data();
        if (empty($data->serverid)) {
            mtrace('provision_jibri_vm: missing serverid in custom data');
            return;
        }

        $server = $DB->get_record('jitsi_servers', ['id' => (int)$data->serverid]);
        if (!$server) {
            mtrace("provision_jibri_vm: server {$data->serverid} not found");
            return;
        }

        if (empty($server->jibri_enabled)) {
            mtrace("provision_jibri_vm: server {$server->id} does not have Jibri enabled");
            return;
        }

        if (!empty($server->jibri_gcpinstancename)) {
            mtrace("provision_jibri_vm: Jibri VM already exists for server {$server->id}: {$server->jibri_gcpinstancename}");
            return;
        }

        // Load Google API autoloader.
        $autoloaders = [
            $CFG->dirroot . '/mod/jitsi/api/vendor/autoload.php',
            $CFG->dirroot . '/mod/jitsi/vendor/autoload.php',
            $CFG->dirroot . '/vendor/autoload.php',
        ];
        foreach ($autoloaders as $autoload) {
            if (file_exists($autoload)) {
                require_once($autoload);
                break;
            }
        }

        if (!class_exists('Google\\Client') || !class_exists('Google\\Service\\Compute')) {
            mtrace('provision_jibri_vm: Google API client not available');
            return;
        }

        require_once($CFG->dirroot . '/mod/jitsi/servermanagement.php');

        $project = $server->gcpproject;
        $zone    = $server->gcpzone;
        $image   = trim((string)get_config('mod_jitsi', 'gcp_image')) ?: 'projects/debian-cloud/global/images/family/debian-12';
        $network = trim((string)get_config('mod_jitsi', 'gcp_network')) ?: 'global/networks/default';
        $mach    = !empty($data->jibrimachinetype) ? $data->jibrimachinetype : 'n2-standard-4';

        $jibriinstancename = 'jibri-' . date('ymdHi');

        // Jibri callback URL for provisioning status.
        $callbackurl = (new \moodle_url('/mod/jitsi/servermanagement.php', [
            'action'   => 'jibriready',
            'serverid' => $server->id,
            'token'    => $server->provisioningtoken,
        ]))->out(false);

        // Moodle recording import URL (called by finalize script when recording is done).
        $recordingingesturl = (new \moodle_url('/mod/jitsi/servermanagement.php', [
            'action' => 'jibrirecording',
        ]))->out(false);

        // Jitsi server hostname passed to Jibri so it can connect via XMPP.
        $jitsihostname = $server->domain;

        try {
            $compute = mod_jitsi_gcp_client();

            // Get the Jitsi VM's internal IP so Jibri can connect without going through
            // the public DNS, which GCP does not NAT-loopback between VMs in the same VPC.
            $jitsiinternalip = '';
            if (!empty($server->gcpinstancename)) {
                try {
                    $jitsiinstance = $compute->instances->get($project, $zone, $server->gcpinstancename);
                    $ifaces = $jitsiinstance->getNetworkInterfaces();
                    if (!empty($ifaces[0])) {
                        $jitsiinternalip = $ifaces[0]->getNetworkIP();
                    }
                } catch (\Throwable $ipex) {
                    mtrace("provision_jibri_vm: could not get Jitsi VM internal IP: " . $ipex->getMessage());
                }
            }

            $opname = mod_jitsi_gcp_create_instance($compute, $project, $zone, [
                'name'          => $jibriinstancename,
                'machineType'   => $mach,
                'image'         => $image,
                'network'       => $network,
                'startupScript' => mod_jitsi_jibri_startup_script(),
                'callbackUrl'   => $callbackurl,
                // Extra metadata items read by the Jibri startup script.
                'extraMetadata' => array_merge([
                    ['key' => 'JITSI_HOSTNAME', 'value' => $jitsihostname],
                    ['key' => 'JITSI_INTERNAL_IP', 'value' => $jitsiinternalip],
                    ['key' => 'JIBRI_XMPP_PASS', 'value' => $server->jibri_xmpp_pass],
                    ['key' => 'JIBRI_RECORDER_PASS', 'value' => $server->jibri_recorder_pass],
                    ['key' => 'JIBRI_SERVER_ID', 'value' => (string)$server->id],
                    ['key' => 'JIBRI_TOKEN', 'value' => $server->provisioningtoken],
                    ['key' => 'JIBRI_MOODLE_URL', 'value' => $recordingingesturl],
                ], !empty($server->gcs_enabled) && !empty($server->gcs_bucket) ? [
                    ['key' => 'GCS_BUCKET', 'value' => $server->gcs_bucket],
                ] : []),
                'tags'                 => ['mod-jitsi-web', 'mod-jibri'],
                // Attach default compute SA with cloud-platform scope so gsutil works via ADC.
                'serviceAccount'       => 'default',
            ]);

            $server->jibri_gcpinstancename    = $jibriinstancename;
            $server->jibri_provisioningstatus = 'provisioning';
            $server->jibri_provisioningerror  = '';
            $server->timemodified             = time();
            $DB->update_record('jitsi_servers', $server);

            mtrace("provision_jibri_vm: Jibri VM {$jibriinstancename} creation started (op: {$opname})");
        } catch (\Throwable $e) {
            $server->jibri_provisioningstatus = 'error';
            $server->jibri_provisioningerror  = $e->getMessage();
            $server->timemodified             = time();
            $DB->update_record('jitsi_servers', $server);
            mtrace("provision_jibri_vm: ERROR creating Jibri VM: " . $e->getMessage());
        }
    }
}
