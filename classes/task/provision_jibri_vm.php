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
 * Ad-hoc task: provision a Jibri recording VM in Google Cloud and add it to the pool.
 *
 * Custom data expected:
 *   - serverid (int): ID of the jitsi_servers record
 *   - poolentryid (int, optional): ID of the jitsi_jibri_pool row to update (if pre-created)
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
     * Execute the task: create the Jibri VM in GCP and register it in the pool.
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
        $network = trim((string)get_config('mod_jitsi', 'gcp_network')) ?: 'global/networks/default';
        $mach    = !empty($data->jibrimachinetype) ? $data->jibrimachinetype : 'n2-standard-4';

        // Use custom Jibri image if available (fast boot ~1-2 min), otherwise full Debian image.
        $useimage = !empty($server->jibri_image) ? $server->jibri_image : null;
        $baseimage = trim((string)get_config('mod_jitsi', 'gcp_image'))
            ?: 'projects/debian-cloud/global/images/family/debian-12';

        $jibriinstancename = 'jibri-' . date('ymdHi') . '-' . substr(uniqid(), -4);

        // Create or reuse pool entry.
        $now = time();
        if (!empty($data->poolentryid)) {
            $poolentry = $DB->get_record('jitsi_jibri_pool', ['id' => (int)$data->poolentryid]);
        } else {
            $poolentry = null;
        }
        if (!$poolentry) {
            $poolentry = (object)[
                'serverid'          => $server->id,
                'gcpinstancename'   => '',
                'status'            => 'provisioning',
                'provisioningerror' => '',
                'timecreated'       => $now,
                'timemodified'      => $now,
            ];
            $poolentry->id = $DB->insert_record('jitsi_jibri_pool', $poolentry);
        } else {
            $poolentry->status       = 'provisioning';
            $poolentry->timemodified = $now;
            $DB->update_record('jitsi_jibri_pool', $poolentry);
        }

        // Jibri callback URL: pass pool entry ID so jibriready updates the right row.
        $callbackurl = (new \moodle_url('/mod/jitsi/servermanagement.php', [
            'action'      => 'jibriready',
            'serverid'    => $server->id,
            'poolentryid' => $poolentry->id,
            'token'       => $server->provisioningtoken,
        ]))->out(false);

        // Moodle recording import URL (called by finalize script when recording is done).
        $recordingingesturl = (new \moodle_url('/mod/jitsi/servermanagement.php', [
            'action' => 'jibrirecording',
        ]))->out(false);

        $jitsihostname = $server->domain;

        try {
            $compute = mod_jitsi_gcp_client();

            // Get the Jitsi VM's internal IP for XMPP connectivity.
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

            // If we have a custom Jibri image, boot from it (no startup script needed).
            // The image already has everything installed; only pass metadata for configuration.
            if ($useimage) {
                $imagepath = strpos($useimage, '/') === false
                    ? "projects/{$project}/global/images/{$useimage}"
                    : $useimage;
                $startupscript = '#!/bin/bash' . "\n" .
                    '# Boot from pre-built Jibri image — update per-VM config from metadata.' . "\n" .
                    'META="http://metadata.google.internal/computeMetadata/v1/instance/attributes"' . "\n" .
                    'CALLBACK_URL=$(curl -sf -H "Metadata-Flavor: Google" "$META/CALLBACK_URL" || true)' . "\n" .
                    'POOL_ENTRY_ID=$(curl -sf -H "Metadata-Flavor: Google" "$META/JIBRI_POOL_ENTRY_ID" || true)' . "\n" .
                    '# Update monitor script with this VM\'s pool entry ID, then restart it.' . "\n" .
                    'if [ -n "$POOL_ENTRY_ID" ] && [ -f /usr/local/bin/jibri-monitor.sh ]; then' . "\n" .
                    '    sed -i "s/^POOL_ENTRY_ID=.*/POOL_ENTRY_ID=\"${POOL_ENTRY_ID}\"/" /usr/local/bin/jibri-monitor.sh' . "\n" .
                    '    systemctl restart jibri-monitor 2>/dev/null || true' . "\n" .
                    'fi' . "\n" .
                    '# Wait for Jibri service to be fully up before notifying Moodle.' . "\n" .
                    'sleep 15' . "\n" .
                    'if [ -n "$CALLBACK_URL" ]; then' . "\n" .
                    '    curl -X POST "${CALLBACK_URL}&phase=completed" --max-time 10 --retry 3 --retry-delay 5 || true' . "\n" .
                    'fi';
            } else {
                $imagepath     = $baseimage;
                $startupscript = mod_jitsi_jibri_startup_script();
            }

            $opname = mod_jitsi_gcp_create_instance($compute, $project, $zone, [
                'name'          => $jibriinstancename,
                'machineType'   => $mach,
                'image'         => $imagepath,
                'network'       => $network,
                'startupScript' => $startupscript,
                'callbackUrl'   => $callbackurl,
                'extraMetadata' => array_merge([
                    ['key' => 'JITSI_HOSTNAME', 'value' => $jitsihostname],
                    ['key' => 'JITSI_INTERNAL_IP', 'value' => $jitsiinternalip],
                    ['key' => 'JIBRI_XMPP_PASS', 'value' => $server->jibri_xmpp_pass],
                    ['key' => 'JIBRI_RECORDER_PASS', 'value' => $server->jibri_recorder_pass],
                    ['key' => 'JIBRI_SERVER_ID', 'value' => (string)$server->id],
                    ['key' => 'JIBRI_TOKEN', 'value' => $server->provisioningtoken],
                    ['key' => 'JIBRI_MOODLE_URL', 'value' => $recordingingesturl],
                    ['key' => 'JIBRI_POOL_ENTRY_ID', 'value' => (string)$poolentry->id],
                ], !empty($server->gcs_enabled) && !empty($server->gcs_bucket) ? [
                    ['key' => 'GCS_BUCKET', 'value' => $server->gcs_bucket],
                ] : []),
                'tags'           => ['mod-jitsi-web', 'mod-jibri'],
                'serviceAccount' => 'default',
            ]);

            // Update pool entry with the instance name.
            $poolentry->gcpinstancename  = $jibriinstancename;
            $poolentry->status           = 'provisioning';
            $poolentry->provisioningerror = '';
            $poolentry->timemodified     = time();
            $DB->update_record('jitsi_jibri_pool', $poolentry);

            // Keep jibri_gcpinstancename on the server pointing to the first pool entry
            // for backwards compatibility with existing start/stop/delete code.
            if (empty($server->jibri_gcpinstancename)) {
                $DB->set_field('jitsi_servers', 'jibri_gcpinstancename', $jibriinstancename, ['id' => $server->id]);
                $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', 'provisioning', ['id' => $server->id]);
            }

            mtrace("provision_jibri_vm: Jibri VM {$jibriinstancename} creation started"
                . ($useimage ? " (from image {$useimage})" : " (full install)")
                . " (op: {$opname})");
        } catch (\Throwable $e) {
            $poolentry->status            = 'error';
            $poolentry->provisioningerror = $e->getMessage();
            $poolentry->timemodified      = time();
            $DB->update_record('jitsi_jibri_pool', $poolentry);
            mtrace("provision_jibri_vm: ERROR creating Jibri VM: " . $e->getMessage());
        }
    }
}
