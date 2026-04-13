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
 * Scheduled task to manage the Jibri VM pool.
 *
 * - Polls the Jibri health API to update each VM's status.
 * - Provisions new VMs when idle count is below jibri_pool_size.
 * - Removes idle VMs that exceed the desired pool size after a grace period.
 * - Creates a GCP image from the first ready Jibri if none exists yet.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Scheduled task: keep the Jibri VM pool healthy.
 *
 * @package mod_jitsi
 */
class check_jibri_pool extends \core\task\scheduled_task {
    /** Grace period (seconds) before an excess idle Jibri is deleted. */
    const IDLE_GRACE_SECONDS = 600;

    /** Seconds with no health response before marking a VM as error. */
    const HEALTH_TIMEOUT_SECONDS = 30;

    /** Number of consecutive failed health checks before marking error. */
    const MAX_HEALTH_FAILURES = 3;

    /**
     * Returns the task name shown in Moodle admin.
     */
    public function get_name(): string {
        return get_string('checkjibripool', 'jitsi');
    }

    /**
     * Returns the component that owns this task.
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Execute the pool management logic.
     */
    public function execute(): void {
        global $CFG, $DB;

        $servers = $DB->get_records_select(
            'jitsi_servers',
            "type = 3 AND jibri_enabled = 1 AND provisioningstatus = 'ready'"
        );

        if (empty($servers)) {
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

        require_once($CFG->dirroot . '/mod/jitsi/servermanagement.php');

        foreach ($servers as $server) {
            $this->process_server($server, $DB);
        }
    }

    /**
     * Process the Jibri pool for a single Jitsi server.
     *
     * @param \stdClass $server jitsi_servers record
     * @param \moodle_database $DB
     */
    private function process_server(\stdClass $server, \moodle_database $DB): void {
        $poolsize = (int)($server->jibri_pool_size ?? 1);
        $entries  = $DB->get_records('jitsi_jibri_pool', ['serverid' => $server->id]);

        // 1. Update health status for each VM.
        foreach ($entries as $entry) {
            if (in_array($entry->status, ['provisioning'])) {
                // Still being provisioned — jibriready callback will update it.
                continue;
            }
            $newstatus = $this->check_health($server, $entry);
            if ($newstatus !== $entry->status) {
                mtrace("check_jibri_pool: server {$server->id} VM {$entry->gcpinstancename}"
                    . " status {$entry->status} → {$newstatus}");
                $entry->status       = $newstatus;
                $entry->timemodified = time();
                $DB->update_record('jitsi_jibri_pool', $entry);
            }
        }

        // Refresh entries after health updates.
        $entries = $DB->get_records('jitsi_jibri_pool', ['serverid' => $server->id]);

        $idleentries = array_filter($entries, fn ($e) => $e->status === 'idle');
        $activentries = array_filter($entries, fn ($e) => in_array($e->status, ['recording', 'streaming']));
        $provisioningentries = array_filter($entries, fn ($e) => $e->status === 'provisioning');

        // 2. Auto-create GCP image from the first idle Jibri if none exists yet.
        if (empty($server->jibri_image) && !empty($idleentries)) {
            $this->maybe_create_image($server, reset($idleentries), $DB);
            // Reload server to get updated jibri_image.
            $server = $DB->get_record('jitsi_servers', ['id' => $server->id]);
        }

        // 3. Provision more Jibris if idle count is below pool_size.
        $currentidlecount = count($idleentries) + count($provisioningentries);
        $needed = $poolsize - $currentidlecount;
        for ($i = 0; $i < $needed; $i++) {
            mtrace("check_jibri_pool: server {$server->id} provisioning new Jibri"
                . " ({$currentidlecount} idle/provisioning < {$poolsize} desired)");
            $task = new \mod_jitsi\task\provision_jibri_vm();
            $task->set_custom_data(['serverid' => $server->id]);
            \core\task\manager::queue_adhoc_task($task, true);
            $currentidlecount++;
        }

        // 4. Remove excess idle Jibris (beyond pool_size) after grace period.
        if (count($idleentries) > $poolsize) {
            $now    = time();
            $excess = array_slice(array_values($idleentries), $poolsize);
            foreach ($excess as $entry) {
                $idlefor = $now - $entry->timemodified;
                if ($idlefor >= self::IDLE_GRACE_SECONDS) {
                    mtrace("check_jibri_pool: server {$server->id} removing excess idle VM"
                        . " {$entry->gcpinstancename} (idle for {$idlefor}s)");
                    $this->delete_jibri_vm($server, $entry, $DB);
                }
            }
        }

        // 5. Remove VMs that have been in error state for a long time (>1h).
        foreach ($entries as $entry) {
            if ($entry->status === 'error' && (time() - $entry->timemodified) > 3600) {
                mtrace("check_jibri_pool: server {$server->id} removing stale error VM"
                    . " {$entry->gcpinstancename}");
                $this->delete_jibri_vm($server, $entry, $DB);
            }
        }
    }

    /**
     * Query the Jibri health API and return the new status string.
     *
     * @param \stdClass $server
     * @param \stdClass $entry  jitsi_jibri_pool record
     * @return string  'idle' | 'recording' | 'streaming' | 'error'
     */
    private function check_health(\stdClass $server, \stdClass $entry): string {
        if (empty($entry->gcpinstancename)) {
            return 'error';
        }

        // Resolve VM external IP via GCP API.
        $ip = $this->get_vm_external_ip($server, $entry->gcpinstancename);
        if (empty($ip)) {
            return 'error';
        }

        $url = "http://{$ip}:2222/jibri/api/v1.0/health";
        $ch  = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => self::HEALTH_TIMEOUT_SECONDS,
            CURLOPT_CONNECTTIMEOUT => 10,
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($resp === false || $code !== 200) {
            return 'error';
        }

        $data = json_decode($resp, true);
        $busy = strtolower($data['status']['busyStatus'] ?? 'idle');

        if ($busy === 'idle') {
            return 'idle';
        }
        if ($busy === 'recording') {
            return 'recording';
        }
        if ($busy === 'streaming') {
            return 'streaming';
        }
        return 'recording'; // Any other busy state treated as recording.
    }

    /**
     * Get the external IP of a GCP instance.
     *
     * @param \stdClass $server
     * @param string $instancename
     * @return string|null
     */
    private function get_vm_external_ip(\stdClass $server, string $instancename): ?string {
        try {
            $compute  = mod_jitsi_gcp_client();
            $instance = $compute->instances->get($server->gcpproject, $server->gcpzone, $instancename);
            $ifaces   = $instance->getNetworkInterfaces();
            if (!empty($ifaces[0])) {
                $acs = $ifaces[0]->getAccessConfigs();
                if (!empty($acs[0])) {
                    return $acs[0]->getNatIP();
                }
            }
        } catch (\Throwable $e) {
            mtrace("check_jibri_pool: could not get IP for {$instancename}: " . $e->getMessage());
        }
        return null;
    }

    /**
     * Create a GCP image from a Jibri VM and store the name in jitsi_servers.jibri_image.
     *
     * @param \stdClass $server
     * @param \stdClass $entry  jitsi_jibri_pool record (the source VM)
     * @param \moodle_database $DB
     */
    private function maybe_create_image(\stdClass $server, \stdClass $entry, \moodle_database $DB): void {
        if (empty($entry->gcpinstancename)) {
            return;
        }

        $imagename = 'jibri-image-s' . $server->id . '-' . date('YmdHi');
        mtrace("check_jibri_pool: creating Jibri base image {$imagename}"
            . " from {$entry->gcpinstancename}");

        try {
            $compute = mod_jitsi_gcp_client();

            // Create image from the running VM — no stop needed.
            // Jibri is stateless (config in files, no DB), so a live image boots correctly.
            // GCP marks the image as "READY" once it finishes; the VM keeps running uninterrupted.
            $image = new \Google\Service\Compute\Image([
                'name'       => $imagename,
                'sourceDisk' => "projects/{$server->gcpproject}/zones/{$server->gcpzone}"
                    . "/disks/{$entry->gcpinstancename}",
                'labels'     => ['mod-jitsi' => 'jibri-base'],
            ]);

            $compute->images->insert($server->gcpproject, $image);

            $DB->set_field('jitsi_servers', 'jibri_image', $imagename, ['id' => $server->id]);
            $DB->set_field('jitsi_servers', 'timemodified', time(), ['id' => $server->id]);

            mtrace("check_jibri_pool: image {$imagename} creation requested");
        } catch (\Throwable $e) {
            mtrace("check_jibri_pool: ERROR creating image: " . $e->getMessage());
        }
    }

    /**
     * Delete a Jibri VM from GCP and remove its pool entry.
     *
     * @param \stdClass $server
     * @param \stdClass $entry  jitsi_jibri_pool record
     * @param \moodle_database $DB
     */
    private function delete_jibri_vm(\stdClass $server, \stdClass $entry, \moodle_database $DB): void {
        if (!empty($entry->gcpinstancename)) {
            try {
                $compute = mod_jitsi_gcp_client();
                $compute->instances->delete($server->gcpproject, $server->gcpzone, $entry->gcpinstancename);
            } catch (\Throwable $e) {
                mtrace("check_jibri_pool: ERROR deleting VM {$entry->gcpinstancename}: " . $e->getMessage());
            }
        }
        $DB->delete_records('jitsi_jibri_pool', ['id' => $entry->id]);
    }
}
