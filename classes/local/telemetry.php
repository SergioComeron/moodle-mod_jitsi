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
 * Opt-in telemetry sender for the mod_jitsi Account portal.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\local;

/**
 * Builds and sends the anonymous telemetry ping to the portal.
 *
 * Shared by the weekly scheduled task and the post-registration ad-hoc task
 * (which retries until the first successful ping so activation does not have to
 * wait for the weekly slot). On a successful ping it records the timestamp in
 * the 'portal_lastping' config, used by the settings page to self-diagnose a
 * site that is registered but whose cron is not delivering telemetry.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class telemetry {
    /** Portal base URL. */
    const PORTAL = 'https://portal.sergiocomeron.com';

    /**
     * Fetch the license key (if registered) and send one telemetry ping.
     *
     * @return string One of: 'pinged' | 'deactivated' | 'no_license' | 'unreachable' | 'failed'
     */
    public static function send(): string {
        global $DB, $CFG;

        $config = get_config('mod_jitsi');

        // Build anonymous site hash (SHA-256 of wwwroot — no URL sent).
        $sitehash = hash('sha256', $CFG->wwwroot);

        // If no license key yet, try to fetch it from the portal.
        if (empty($config->portal_license_key) && !empty($config->portal_status)) {
            $vresponse = self::post(self::PORTAL . '/validate.php', ['site_hash' => $sitehash], 5, 10);
            $vdata = $vresponse !== false ? json_decode($vresponse, true) : null;
            if (!empty($vdata['ok']) && !empty($vdata['license_key'])) {
                set_config('portal_license_key', $vdata['license_key'], 'mod_jitsi');
                set_config('portal_status', 'active', 'mod_jitsi');
                $config->portal_license_key = $vdata['license_key'];
            }
        }

        // Only send if registered (license key present).
        if (empty($config->portal_license_key)) {
            return 'no_license';
        }

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

        $nextrunat = self::next_run_time();

        $payload = [
            'site_hash'              => $sitehash,
            'license_key'            => $config->portal_license_key,
            'next_run_at'            => $nextrunat,
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
            // Cron health: a ping proves cron ran, but these flag a flaky/failing one.
            'cron_last_run'          => (int)get_config('tool_task', 'lastcronstart'),
            'failed_tasks'           => (int)$DB->count_records_select('task_scheduled', 'faildelay > 0'),
        ];

        $curl = curl_init(self::PORTAL . '/collect.php');
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
            return 'unreachable';
        }
        if ($httpcode === 200) {
            $responsedata = json_decode($response, true);
            if (!empty($responsedata['deactivated'])) {
                unset_config('portal_email', 'mod_jitsi');
                unset_config('portal_status', 'mod_jitsi');
                unset_config('portal_license_key', 'mod_jitsi');
                return 'deactivated';
            }
            set_config('portal_lastping', time(), 'mod_jitsi');
            return 'pinged';
        }
        return 'failed';
    }

    /**
     * Read the next scheduled run time of the weekly telemetry task.
     *
     * Tries the classname both with and without a leading backslash, as Moodle
     * stores it differently across versions.
     *
     * @return int Unix timestamp, or 0 if unknown.
     */
    protected static function next_run_time(): int {
        global $DB;
        $rec = $DB->get_record('task_scheduled', ['classname' => '\mod_jitsi\task\send_telemetry'], 'nextruntime')
            ?: $DB->get_record('task_scheduled', ['classname' => 'mod_jitsi\task\send_telemetry'], 'nextruntime');
        return $rec ? (int)$rec->nextruntime : 0;
    }

    /**
     * POST a JSON body and return the raw response (or false on transport error).
     *
     * @param string $url
     * @param array $data
     * @param int $connecttimeout
     * @param int $timeout
     * @return string|false
     */
    protected static function post(string $url, array $data, int $connecttimeout, int $timeout) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($data),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => $connecttimeout,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response;
    }
}
