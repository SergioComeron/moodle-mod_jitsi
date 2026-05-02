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

        // Build anonymous site hash (SHA-256 of wwwroot — no URL sent).
        $sitehash = hash('sha256', $CFG->wwwroot);

        // If no license key yet, try to fetch it from the portal.
        if (empty($config->portal_license_key) && !empty($config->portal_status)) {
            $ch = curl_init('https://portal.sergiocomeron.com/validate.php');
            curl_setopt_array($ch, [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => json_encode(['site_hash' => $sitehash]),
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            ]);
            $vresponse = curl_exec($ch);
            curl_close($ch);
            $vdata = $vresponse !== false ? json_decode($vresponse, true) : null;
            if (!empty($vdata['ok']) && !empty($vdata['license_key'])) {
                set_config('portal_license_key', $vdata['license_key'], 'mod_jitsi');
                set_config('portal_status', 'active', 'mod_jitsi');
                $config->portal_license_key = $vdata['license_key'];
                mtrace('mod_jitsi send_telemetry: license key retrieved from portal.');
            }
        }

        // Only send if registered (license key present).
        if (empty($config->portal_license_key)) {
            return;
        }

        $endpoint = 'https://portal.sergiocomeron.com/collect.php';

        // Detect active server type from plugin config.
        $servertype = -1;
        $activeserverid = (int)($config->server ?? 0);
        if ($activeserverid > 0) {
            $server = $DB->get_record('jitsi_servers', ['id' => $activeserverid], 'type');
            if ($server) {
                $servertype = (int)$server->type;
            }
        }

        // Weekly session stats from jitsi_usage_daily (pre-aggregated, cheap query).
        $sevendaykey = (int)date('Ymd', strtotime('-7 days'));
        $weeklystats = $DB->get_record_sql(
            "SELECT COALESCE(SUM(sessions), 0) AS sessions_week,
                    COALESCE(SUM(minutes), 0) AS minutes_week,
                    COUNT(DISTINCT userid) AS unique_users_week,
                    COUNT(DISTINCT cmid) AS active_activities_week
               FROM {jitsi_usage_daily}
              WHERE daykey >= :daykey",
            ['daykey' => $sevendaykey]
        );

        $recordingstotal = (int)$DB->count_records('jitsi_record', ['deleted' => 0]);
        $maxparticipants = (int)($DB->get_field_sql(
            'SELECT COALESCE(MAX(maxparticipants), 0) FROM {jitsi_source_record}'
        ) ?? 0);

        $payload = [
            'site_hash'              => $sitehash,
            'license_key'            => $config->portal_license_key,
            'plugin_version'         => (int)($config->version ?? 0),
            'moodle_branch'          => (int)$CFG->branch,
            'server_type'            => $servertype,
            'activity_count'         => (int)$DB->count_records('jitsi'),
            'ai_enabled'             => !empty($config->aienabled),
            'jibri_enabled'          => $DB->record_exists_select('jitsi_servers', "jibri_enabled = 1"),
            'private_sessions'       => !empty($config->enableprivatesessions),
            'push_enabled'           => !empty($config->enablepushnotifications),
            'site_timezone'          => $CFG->timezone ?? date_default_timezone_get(),
            'sessions_week'          => (int)($weeklystats->sessions_week ?? 0),
            'minutes_week'           => (int)($weeklystats->minutes_week ?? 0),
            'unique_users_week'      => (int)($weeklystats->unique_users_week ?? 0),
            'active_activities_week' => (int)($weeklystats->active_activities_week ?? 0),
            'recordings_total'       => $recordingstotal,
            'max_participants_peak'  => $maxparticipants,
        ];

        $curl = curl_init($endpoint);
        curl_setopt_array($curl, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);

        $response = curl_exec($curl);
        $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        if ($response === false) {
            mtrace('mod_jitsi send_telemetry: portal unreachable, skipping ping.');
        } else if ($httpcode === 200) {
            $responsedata = json_decode($response, true);
            if (!empty($responsedata['deactivated'])) {
                unset_config('portal_email', 'mod_jitsi');
                unset_config('portal_status', 'mod_jitsi');
                unset_config('portal_license_key', 'mod_jitsi');
                mtrace('mod_jitsi send_telemetry: account deactivated from portal, local config cleared.');
                return;
            }
            mtrace('mod_jitsi send_telemetry: ping sent successfully.');
        } else {
            mtrace('mod_jitsi send_telemetry: ping failed (HTTP ' . $httpcode . '): ' . $response);
        }
    }
}
