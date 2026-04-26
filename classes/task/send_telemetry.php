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
 * Weekly opt-in telemetry ping to the developer's stats endpoint.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\task;

/**
 * Sends anonymous usage data to the developer if the admin has opted in.
 */
class send_telemetry extends \core\task\scheduled_task {
    /**
     * Returns the task name.
     * @return string
     */
    public function get_name() {
        return get_string('task_send_telemetry', 'jitsi');
    }

    /**
     * Executes the task.
     */
    public function execute() {
        global $DB, $CFG;

        $config = get_config('mod_jitsi');

        if (empty($config->telemetry_enabled)) {
            return;
        }

        $endpoint = trim($config->telemetry_endpoint ?? '');
        $secret   = trim($config->telemetry_key ?? '');

        if (!$endpoint || !$secret) {
            mtrace('mod_jitsi send_telemetry: endpoint or key not configured, skipping.');
            return;
        }

        // Build anonymous site hash (SHA-256 of wwwroot — no URL sent).
        $sitehash = hash('sha256', $CFG->wwwroot);

        // Detect active server type (use the first active server found).
        $servertype = -1;
        $servers = $DB->get_records('jitsi_servers', [], 'id ASC');
        foreach ($servers as $s) {
            if (!empty($s->inuse)) {
                $servertype = (int)$s->type;
                break;
            }
        }

        $payload = [
            'site_hash'       => $sitehash,
            'plugin_version'  => (int)($config->version ?? 0),
            'moodle_branch'   => (int)$CFG->branch,
            'server_type'     => $servertype,
            'activity_count'  => (int)$DB->count_records('jitsi'),
            'ai_enabled'      => !empty($config->aienabled),
            'jibri_enabled'   => $DB->record_exists_select('jitsi_servers', "jibri_enabled = 1"),
            'private_sessions' => !empty($config->enableprivatesessions),
            'push_enabled'    => !empty($config->enablepushnotifications),
            'site_timezone'   => $CFG->timezone ?? date_default_timezone_get(),
        ];

        $curl = curl_init($endpoint);
        curl_setopt_array($curl, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => [
                'Content-Type: application/json',
                'X-Jitsi-Key: ' . $secret,
            ],
        ]);

        $response = curl_exec($curl);
        $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if ($httpcode === 200) {
            mtrace('mod_jitsi send_telemetry: ping sent successfully.');
        } else {
            mtrace('mod_jitsi send_telemetry: ping failed (HTTP ' . $httpcode . '): ' . $response);
        }
    }
}
