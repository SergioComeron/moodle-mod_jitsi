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
 * Token-authenticated callbacks invoked by GCP-provisioned VMs.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\local;

/**
 * Handlers for the sessionless VM callbacks of servermanagement.php.
 *
 * The Jitsi/Jibri VMs call back into Moodle during provisioning and when
 * recordings finish. These requests carry no Moodle session — they are
 * authenticated by the per-server provisioning token — so the page defines
 * NO_MOODLE_COOKIES and dispatches here. Every handler returns
 * [HTTP status code, JSON-serialisable payload].
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class vm_callback {
    /**
     * Dispatch a VM callback action to its handler.
     *
     * @param string $action One of: jitsiready, jibriready, jibrirecording, jibristatus.
     * @return array [int httpcode, array payload]
     */
    public static function dispatch(string $action): array {
        switch ($action) {
            case 'jitsiready':
                return self::jitsiready();
            case 'jibriready':
                return self::jibriready();
            case 'jibrirecording':
                return self::jibrirecording();
            case 'jibristatus':
                return self::jibristatus();
            default:
                return [400, ['status' => 'error', 'message' => 'Unknown action']];
        }
    }

    /**
     * Read a request parameter accepting GET or POST, unfiltered (token-auth endpoints).
     *
     * @param string $name Parameter name.
     * @param string $default Default value when missing.
     * @return string
     */
    protected static function raw_param(string $name, string $default = ''): string {
        $value = filter_input(INPUT_GET, $name, FILTER_UNSAFE_RAW) ?:
                 filter_input(INPUT_POST, $name, FILTER_UNSAFE_RAW);
        return $value !== null && $value !== false ? $value : $default;
    }

    /**
     * Read an integer request parameter accepting GET or POST.
     *
     * @param string $name Parameter name.
     * @return int
     */
    protected static function int_param(string $name): int {
        return filter_input(INPUT_GET, $name, FILTER_VALIDATE_INT) ?:
               filter_input(INPUT_POST, $name, FILTER_VALIDATE_INT) ?: 0;
    }

    /**
     * Callback from the Jitsi VM startup script reporting provisioning progress.
     *
     * Phases: intermediate statuses (waiting_dns, dns_ready, installing, ...),
     * 'completed' (with hostname/appid/secret) or 'error'.
     *
     * @return array [int httpcode, array payload]
     */
    public static function jitsiready(): array {
        global $DB;

        $instancename = required_param('instance', PARAM_TEXT);
        $token = required_param('token', PARAM_ALPHANUMEXT);
        $hostname = optional_param('hostname', '', PARAM_TEXT);
        $phase = optional_param('phase', 'completed', PARAM_ALPHAEXT);
        $appid = optional_param('appid', '', PARAM_ALPHANUMEXT);
        $secret = optional_param('secret', '', PARAM_ALPHANUMEXT);
        $error = optional_param('error', '', PARAM_TEXT);

        try {
            // Find the server record by instance name.
            $server = $DB->get_record('jitsi_servers', ['gcpinstancename' => $instancename]);

            if (!$server) {
                return [404, ['status' => 'error', 'message' => 'Server not found']];
            }

            // Verify token from database.
            if (empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
                return [401, ['status' => 'error', 'message' => 'Invalid token']];
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

                debugging(
                    "✅ Jitsi GCP server ready: {$hostname} (ID: {$server->id}, instance: {$instancename})",
                    DEBUG_NORMAL
                );

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

                return [200, [
                    'status' => 'ok',
                    'message' => 'Server provisioned successfully',
                    'phase' => 'ready',
                    'registered' => true,
                    'serverid' => $server->id,
                ]];
            } else if ($phase === 'error' || !empty($error)) {
                // Provisioning failed.
                $server->provisioningstatus = 'error';
                $server->provisioningerror = $error ?: 'Unknown error during provisioning';

                $DB->update_record('jitsi_servers', $server);

                debugging("❌ Jitsi GCP server error: {$instancename} - {$error}", DEBUG_NORMAL);

                return [200, [
                    'status' => 'ok',
                    'message' => 'Status updated',
                    'phase' => 'error',
                    'registered' => false,
                ]];
            } else {
                // Intermediate status update (e.g., 'waiting_dns', 'dns_ready', 'installing', etc.).
                $server->provisioningstatus = $phase;
                $DB->update_record('jitsi_servers', $server);

                return [200, [
                    'status' => 'ok',
                    'message' => 'Status updated',
                    'phase' => $phase,
                    'registered' => false,
                ]];
            }
        } catch (\Exception $e) {
            debugging("❌ Callback error: " . $e->getMessage(), DEBUG_NORMAL);
            return [500, [
                'status' => 'error',
                'message' => 'Database error: ' . $e->getMessage(),
            ]];
        }
    }

    /**
     * Callback from the Jibri VM startup script reporting provisioning progress.
     *
     * @return array [int httpcode, array payload]
     */
    public static function jibriready(): array {
        global $DB;

        $serverid    = self::int_param('serverid');
        $poolentryid = self::int_param('poolentryid');
        $token       = self::raw_param('token');
        $phase       = self::raw_param('phase', 'completed');
        $error       = self::raw_param('error');

        try {
            $server = $DB->get_record('jitsi_servers', ['id' => $serverid]);

            if (!$server) {
                return [404, ['status' => 'error', 'message' => 'Server not found']];
            }

            // Reuse the same provisioning token as the Jitsi VM for simplicity.
            if (empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
                return [401, ['status' => 'error', 'message' => 'Invalid token']];
            }

            // Update pool entry if provided.
            $poolentry = $poolentryid ? $DB->get_record('jitsi_jibri_pool', ['id' => $poolentryid]) : null;

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
                    $DB->set_field(
                        'jitsi_servers',
                        'jibri_gcpinstancename',
                        $firstentry->gcpinstancename,
                        ['id' => $server->id]
                    );
                }
                $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', 'ready', ['id' => $server->id]);
                $DB->set_field('jitsi_servers', 'jibri_provisioningerror', '', ['id' => $server->id]);
                $DB->set_field('jitsi_servers', 'timemodified', $now, ['id' => $server->id]);

                debugging("✅ Jibri VM ready for server ID {$server->id}", DEBUG_NORMAL);

                return [200, ['status' => 'ok', 'phase' => 'ready']];
            } else if ($phase === 'error' || !empty($error)) {
                if ($poolentry) {
                    $poolentry->status            = 'error';
                    $poolentry->provisioningerror = $error ?: 'Unknown Jibri provisioning error';
                    $poolentry->timemodified      = $now;
                    $DB->update_record('jitsi_jibri_pool', $poolentry);
                }
                $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', 'error', ['id' => $server->id]);
                $DB->set_field(
                    'jitsi_servers',
                    'jibri_provisioningerror',
                    $error ?: 'Unknown Jibri provisioning error',
                    ['id' => $server->id]
                );
                $DB->set_field('jitsi_servers', 'timemodified', $now, ['id' => $server->id]);

                debugging("❌ Jibri VM error for server ID {$server->id}: {$error}", DEBUG_NORMAL);

                return [200, ['status' => 'ok', 'phase' => 'error']];
            } else {
                if ($poolentry) {
                    $poolentry->status       = $phase;
                    $poolentry->timemodified = $now;
                    $DB->update_record('jitsi_jibri_pool', $poolentry);
                }
                $DB->set_field('jitsi_servers', 'jibri_provisioningstatus', $phase, ['id' => $server->id]);
                $DB->set_field('jitsi_servers', 'timemodified', $now, ['id' => $server->id]);

                return [200, ['status' => 'ok', 'phase' => $phase]];
            }
        } catch (\Exception $e) {
            return [500, ['status' => 'error', 'message' => $e->getMessage()]];
        }
    }

    /**
     * Callback from the Jibri finalize script when a recording is ready.
     *
     * Creates a jitsi_source_record plus — when the room maps to an activity —
     * the jitsi_record linking it (required for display in view.php).
     *
     * @return array [int httpcode, array payload]
     */
    public static function jibrirecording(): array {
        global $DB;

        $serverid    = self::int_param('serverid');
        $token       = self::raw_param('token');
        $roomname    = self::raw_param('room');
        $filename    = self::raw_param('filename');
        $poolentryid = self::int_param('poolentryid');
        $recurl      = filter_input(INPUT_GET, 'url', FILTER_VALIDATE_URL) ?:
                       filter_input(INPUT_POST, 'url', FILTER_VALIDATE_URL) ?: '';

        try {
            $server = $DB->get_record('jitsi_servers', ['id' => $serverid]);

            if (!$server) {
                return [404, ['status' => 'error', 'message' => 'Server not found']];
            }

            if (empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
                return [401, ['status' => 'error', 'message' => 'Invalid token']];
            }

            if (empty($recurl)) {
                return [400, ['status' => 'error', 'message' => 'Missing recording URL']];
            }

            // Find the jitsi activity record matching the room name.
            // The room name is a composite built from course shortname, jitsi id, and jitsi name
            // using the admin settings 'sesionname' and 'separator' — same logic as view.php.
            $jitsi = null;
            if (!empty($roomname)) {
                $sesionname = get_config('mod_jitsi', 'sesionname');
                $separator  = get_config('mod_jitsi', 'separator');
                $alljitsis  = $DB->get_records_sql(
                    'SELECT j.*, c.shortname AS courseshortname FROM {jitsi} j JOIN {course} c ON c.id = j.course'
                );
                $separatormap = ['.', '-', '_', ''];
                $sepchar = $separatormap[(int)$separator] ?? '';
                $roomnamelc = strtolower($roomname);
                foreach ($alljitsis as $candidate) {
                    $sesparam = room::build_name(
                        $candidate->courseshortname,
                        $candidate->id,
                        $candidate->name,
                        $sesionname,
                        $separator
                    );
                    if (strtolower($sesparam) === $roomnamelc) {
                        $jitsi = $candidate;
                        break;
                    }
                    // Fallback: Jibri strips certain separators (e.g. dots) from filenames.
                    if ($sepchar !== '' && strtolower(str_replace($sepchar, '', $sesparam)) === $roomnamelc) {
                        $jitsi = $candidate;
                        break;
                    }
                }
            }

            // Create a source record (type=1 = external link).
            $sourcerecord = new \stdClass();
            $sourcerecord->link        = $recurl;
            $sourcerecord->name        = !empty($filename) ? $filename : basename(parse_url($recurl, PHP_URL_PATH));
            $sourcerecord->type        = 1;
            $sourcerecord->timeexpires = 0; // Recordings don't expire.
            $sourcerecord->timecreated = time();
            $sourceid = $DB->insert_record('jitsi_source_record', $sourcerecord);

            // Create a jitsi_record to link the source to the activity (required for display in view.php).
            if ($jitsi) {
                $record = new \stdClass();
                $record->jitsi   = $jitsi->id;
                $record->source  = $sourceid;
                $record->deleted = 0;
                $record->visible = 1;
                $record->name    = $sourcerecord->name;
                $DB->insert_record('jitsi_record', $record);
            }

            // Mark the pool entry as idle — recording is done.
            if (!empty($poolentryid)) {
                $poolentry = $DB->get_record('jitsi_jibri_pool', ['id' => $poolentryid]);
                if ($poolentry && $poolentry->status === 'recording') {
                    $poolentry->status       = 'idle';
                    $poolentry->timemodified = time();
                    $DB->update_record('jitsi_jibri_pool', $poolentry);
                }
            }

            debugging("🎥 Jibri recording imported for server {$server->id}: {$recurl}", DEBUG_NORMAL);

            return [200, ['status' => 'ok', 'message' => 'Recording imported']];
        } catch (\Exception $e) {
            return [500, ['status' => 'error', 'message' => $e->getMessage()]];
        }
    }

    /**
     * Callback from the Jibri VM status monitor when it flips between IDLE and BUSY.
     *
     * When a Jibri goes BUSY the pool is topped up immediately without waiting
     * for the next cron run.
     *
     * @return array [int httpcode, array payload]
     */
    public static function jibristatus(): array {
        global $DB;

        $poolentryid = self::int_param('poolentryid');
        $token       = self::raw_param('token');
        $busyness    = self::raw_param('busyness');

        $entry = $DB->get_record('jitsi_jibri_pool', ['id' => $poolentryid]);
        if (!$entry) {
            return [404, ['status' => 'error', 'message' => 'Pool entry not found']];
        }

        $server = $DB->get_record('jitsi_servers', ['id' => $entry->serverid]);
        if (!$server || empty($server->provisioningtoken) || $server->provisioningtoken !== $token) {
            return [401, ['status' => 'error', 'message' => 'Invalid token']];
        }

        $newstatus = (strtoupper($busyness) === 'BUSY') ? 'recording' : 'idle';
        if (!in_array($entry->status, ['provisioning', 'error']) && $entry->status !== $newstatus) {
            $entry->status       = $newstatus;
            $entry->timemodified = time();
            $DB->update_record('jitsi_jibri_pool', $entry);

            // When a Jibri goes BUSY, immediately top up the pool without waiting for the next cron run.
            if ($newstatus === 'recording') {
                $poolsize    = (int)($server->jibri_pool_size ?? 1);
                $idlecount   = $DB->count_records_select(
                    'jitsi_jibri_pool',
                    "serverid = ? AND status IN ('idle', 'provisioning')",
                    [$server->id]
                );
                if ($idlecount < $poolsize) {
                    $task = new \mod_jitsi\task\provision_jibri_vm();
                    $task->set_custom_data(['serverid' => $server->id]);
                    \core\task\manager::queue_adhoc_task($task, false);
                }
            }
        }

        return [200, ['status' => 'ok', 'newstatus' => $newstatus]];
    }
}
