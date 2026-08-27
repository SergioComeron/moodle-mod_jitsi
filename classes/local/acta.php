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

namespace mod_jitsi\local;

/**
 * Session minutes (acta) built from existing attendance logs and an optional transcript.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class acta {
    /** Gap in seconds that splits participating pings into separate sessions. */
    public const SESSION_GAP = 1800;

    /** Maximum transcript characters sent to the LLM. */
    public const MAX_TRANSCRIPT_CHARS = 50000;

    /** Existing site Vertex AI setup (gcp_project + service-account JSON). */
    public const PROVIDER_VERTEX = 'vertex';

    /** Site or activity OpenAI-compatible BYOK key. */
    public const PROVIDER_BYOK = 'byok';

    /**
     * Which LLM to use when acta is enabled. Not an admin setting.
     *
     * Vertex wins when the existing site Vertex setup is usable. Otherwise the
     * site or activity BYOK key is used. If neither is available, acta stays off.
     *
     * @param \stdClass $jitsi Jitsi instance
     * @return string|null PROVIDER_VERTEX, PROVIDER_BYOK, or null
     */
    public static function provider(\stdClass $jitsi): ?string {
        if ((string)get_config('mod_jitsi', 'actaenabled') !== '1') {
            return null;
        }
        if (vertex_ai::is_configured()) {
            return self::PROVIDER_VERTEX;
        }
        if (self::credentials($jitsi) !== null) {
            return self::PROVIDER_BYOK;
        }
        return null;
    }

    /**
     * Resolve BYOK credentials for an activity.
     *
     * Requires the site enable toggle. An activity-level key wins over the site
     * key. Used only when Vertex is not configured.
     *
     * @param \stdClass $jitsi Jitsi instance
     * @return array|null {apikey, endpoint, model} or null when unavailable
     */
    public static function credentials(\stdClass $jitsi): ?array {
        if ((string)get_config('mod_jitsi', 'actaenabled') !== '1') {
            return null;
        }
        $activitykey = trim((string)get_config('mod_jitsi', 'acta_apikey_' . $jitsi->id));
        $sitekey = trim((string)get_config('mod_jitsi', 'acta_apikey'));
        $apikey = $activitykey !== '' ? $activitykey : $sitekey;
        if ($apikey === '') {
            return null;
        }

        $endpoint = trim((string)get_config('mod_jitsi', 'acta_api_endpoint'));
        $model = trim((string)get_config('mod_jitsi', 'acta_api_model'));
        return [
            'apikey' => $apikey,
            'endpoint' => $endpoint !== '' ? $endpoint : acta_llm::DEFAULT_ENDPOINT,
            'model' => $model !== '' ? $model : acta_llm::DEFAULT_MODEL,
        ];
    }

    /**
     * Whether minutes can be generated for this activity.
     *
     * @param \stdClass $jitsi Jitsi instance
     * @return bool
     */
    public static function is_available(\stdClass $jitsi): bool {
        return self::provider($jitsi) !== null;
    }

    /**
     * Persist or clear an activity-level BYOK key.
     *
     * @param int $jitsiid Jitsi instance id
     * @param string $apikey New key; empty string leaves the stored key unchanged
     */
    public static function save_activity_key(int $jitsiid, string $apikey): void {
        $apikey = trim($apikey);
        if ($apikey === '') {
            return;
        }
        set_config('acta_apikey_' . $jitsiid, $apikey, 'mod_jitsi');
    }

    /**
     * Remove the activity-level key when the instance is deleted.
     *
     * @param int $jitsiid Jitsi instance id
     */
    public static function delete_activity_key(int $jitsiid): void {
        unset_config('acta_apikey_' . $jitsiid, 'mod_jitsi');
    }

    /**
     * Infer the latest session window from existing participating logs.
     *
     * @param int $cmid Course module id
     * @param int $now Reference time (unix timestamp)
     * @return array {start, end}
     */
    public static function session_window(int $cmid, int $now = 0): array {
        global $DB;

        $now = $now > 0 ? $now : time();
        $sql = 'SELECT timecreated FROM {logstore_standard_log}
                 WHERE contextlevel = :contextlevel
                   AND contextinstanceid = :cmid
                   AND action = :action
                   AND timecreated <= :now
              ORDER BY timecreated DESC';
        $times = $DB->get_fieldset_sql($sql, [
            'contextlevel' => CONTEXT_MODULE,
            'cmid' => $cmid,
            'action' => 'participating',
            'now' => $now,
        ]);

        if (empty($times)) {
            return ['start' => $now - HOURSECS, 'end' => $now];
        }

        $start = (int)reset($times);
        foreach ($times as $timecreated) {
            $timecreated = (int)$timecreated;
            if (($start - $timecreated) > self::SESSION_GAP) {
                break;
            }
            $start = $timecreated;
        }

        return ['start' => $start, 'end' => $now];
    }

    /**
     * Build the attendance list from the existing participating-log counters.
     *
     * @param int $cmid Course module id
     * @param int $start Window start
     * @param int $end Window end
     * @return array List of {userid, name, minutes}
     */
    public static function attendance_for_window(int $cmid, int $start, int $end): array {
        $minutesbyuser = attendance::minutes_between_all($cmid, $start, $end);
        $attendees = [];
        foreach ($minutesbyuser as $userid => $minutes) {
            if ((int)$minutes <= 0) {
                continue;
            }
            $attendees[] = [
                'userid' => (int)$userid,
                'name' => self::display_name((int)$userid),
                'minutes' => (int)$minutes,
            ];
        }
        usort($attendees, static function (array $left, array $right): int {
            return $right['minutes'] <=> $left['minutes'];
        });
        return $attendees;
    }

    /**
     * Latest transcript created for this activity inside the session window.
     *
     * Recordings are never returned — only existing ai_transcription text.
     *
     * @param int $jitsiid Jitsi instance id
     * @param int $start Window start
     * @param int $end Window end
     * @return string Empty when none exists
     */
    public static function transcript_for_window(int $jitsiid, int $start, int $end): string {
        global $DB;

        $sql = 'SELECT s.ai_transcription
                  FROM {jitsi_record} r
                  JOIN {jitsi_source_record} s ON s.id = r.source
                 WHERE r.jitsi = :jitsi
                   AND r.deleted = 0
                   AND s.ai_transcription IS NOT NULL
                   AND s.timecreated >= :start
                   AND s.timecreated <= :end
              ORDER BY s.timecreated DESC';
        $text = $DB->get_field_sql($sql, [
            'jitsi' => $jitsiid,
            'start' => $start,
            'end' => $end,
        ], IGNORE_MULTIPLE);
        $text = trim((string)$text);
        if ($text === '') {
            return '';
        }
        if (\core_text::strlen($text) > self::MAX_TRANSCRIPT_CHARS) {
            $text = \core_text::substr($text, 0, self::MAX_TRANSCRIPT_CHARS);
        }
        return $text;
    }

    /**
     * Build the text sent to the LLM. Never includes recording URLs or keys.
     *
     * @param \stdClass $jitsi Jitsi instance
     * @param array $attendees Attendance rows from attendance_for_window()
     * @param string $transcript Existing transcript or empty
     * @param string $lang Language code for the reply
     * @return array {system, user, source}
     */
    public static function build_prompt(\stdClass $jitsi, array $attendees, string $transcript, string $lang): array {
        $lines = [];
        foreach ($attendees as $attendee) {
            $lines[] = '- ' . $attendee['name'] . ' (' . $attendee['minutes'] . ' min)';
        }
        $attendancetext = $lines ? implode("\n", $lines) : '-';

        $source = $transcript !== '' ? 'transcript' : 'metadata';
        $user = "Session name: {$jitsi->name}\n"
            . "Attendance:\n{$attendancetext}\n";
        if ($transcript !== '') {
            $user .= "Transcript:\n{$transcript}\n";
        } else {
            $user .= "No transcript is available. Do not invent topics, quotes or homework.\n"
                . "Write a one-paragraph factual note that minutes were produced from attendance only.\n"
                . "Leave action_items as an empty array.\n";
        }

        $system = "You write session minutes (acta) for an online class. "
            . "Reply with a JSON object only, using keys summary (string) and action_items (array of strings). "
            . "The summary must be short (3-6 sentences) and based strictly on the provided text. "
            . "action_items are pending follow-ups explicitly present in the transcript; otherwise []. "
            . "Do not mention recordings, API keys or that you are a model. "
            . "Write in language code: {$lang}.";

        return ['system' => $system, 'user' => $user, 'source' => $source];
    }

    /**
     * Queue minutes generation after a teacher hangs up (or a manual request).
     *
     * No-ops when acta has no usable LLM (neither Vertex nor BYOK), the user
     * is not a moderator, or a matching acta already exists (unless $force).
     *
     * @param \stdClass $jitsi Jitsi instance
     * @param int $cmid Course module id
     * @param bool $force Rebuild an existing ready acta for the same window
     * @return int New or reused acta id, or 0 when nothing was queued
     */
    public static function queue_from_session_end(\stdClass $jitsi, int $cmid, bool $force = false): int {
        global $DB, $USER;

        if (!self::is_available($jitsi)) {
            return 0;
        }

        $context = \context_module::instance($cmid);
        if (!isloggedin() || isguestuser() || !has_capability('mod/jitsi:moderation', $context)) {
            return 0;
        }

        $window = self::session_window($cmid);
        $existing = $DB->get_record_select(
            'jitsi_session_acta',
            'jitsi = :jitsi AND sessionstart <= :end AND sessionend >= :start',
            [
                'jitsi' => $jitsi->id,
                'start' => $window['start'],
                'end' => $window['end'],
            ],
            '*',
            IGNORE_MULTIPLE
        );

        if ($existing && !$force) {
            return 0;
        }
        if ($existing && $existing->status === 'pending') {
            return (int)$existing->id;
        }

        $now = time();
        if ($existing && $force) {
            $existing->status = 'pending';
            $existing->error = null;
            $existing->sessionstart = $window['start'];
            $existing->sessionend = $window['end'];
            $existing->userid = (int)$USER->id;
            $existing->timemodified = $now;
            $DB->update_record('jitsi_session_acta', $existing);
            $actaid = (int)$existing->id;
        } else {
            $record = (object)[
                'jitsi' => $jitsi->id,
                'cmid' => $cmid,
                'userid' => (int)$USER->id,
                'sessionstart' => $window['start'],
                'sessionend' => $window['end'],
                'status' => 'pending',
                'timecreated' => $now,
                'timemodified' => $now,
            ];
            $actaid = (int)$DB->insert_record('jitsi_session_acta', $record);
        }

        $task = new \mod_jitsi\task\generate_session_acta();
        $task->set_custom_data(['actaid' => $actaid]);
        \core\task\manager::queue_adhoc_task($task, true);
        return $actaid;
    }

    /**
     * Generate and store the acta. $completer is injectable for tests.
     *
     * @param int $actaid Row id
     * @param callable|null $completer fn(string $system, string $user): string
     */
    public static function generate(int $actaid, ?callable $completer = null): void {
        global $DB;

        $acta = $DB->get_record('jitsi_session_acta', ['id' => $actaid]);
        if (!$acta) {
            return;
        }
        $jitsi = $DB->get_record('jitsi', ['id' => $acta->jitsi]);
        if (!$jitsi) {
            return;
        }

        if ($completer === null && self::provider($jitsi) === null) {
            $acta->status = 'error';
            $acta->error = get_string('actanotavailable', 'jitsi');
            $acta->timemodified = time();
            $DB->update_record('jitsi_session_acta', $acta);
            return;
        }

        $attendees = self::attendance_for_window((int)$acta->cmid, (int)$acta->sessionstart, (int)$acta->sessionend);
        $transcript = self::transcript_for_window((int)$jitsi->id, (int)$acta->sessionstart, (int)$acta->sessionend);
        $prompt = self::build_prompt($jitsi, $attendees, $transcript, current_language());

        $acta->attendancejson = json_encode($attendees);
        $acta->source = $prompt['source'];

        try {
            if ($completer === null) {
                $completer = self::default_completer($jitsi);
            }
            $raw = $completer($prompt['system'], $prompt['user']);
            $parsed = acta_llm::parse_json_object($raw);
            $summary = trim((string)($parsed['summary'] ?? ''));
            $items = $parsed['action_items'] ?? [];
            if (!is_array($items)) {
                $items = [];
            }
            $items = array_values(array_filter(array_map(static function ($item): string {
                return trim((string)$item);
            }, $items), static function (string $item): bool {
                return $item !== '';
            }));

            $acta->summary = $summary !== '' ? $summary : get_string('actasummaryunavailable', 'jitsi');
            $acta->actionitems = json_encode($items);
            $acta->status = 'ready';
            $acta->error = null;
        } catch (\Throwable $e) {
            $acta->status = 'error';
            $acta->error = get_string('actaerror', 'jitsi');
            if (empty($acta->summary)) {
                $acta->summary = get_string('actasummaryunavailable', 'jitsi');
            }
            if ($acta->actionitems === null) {
                $acta->actionitems = json_encode([]);
            }
        }

        $acta->timemodified = time();
        $DB->update_record('jitsi_session_acta', $acta);
    }

    /**
     * Default LLM completer: Vertex when configured, otherwise BYOK.
     *
     * @param \stdClass $jitsi Jitsi instance
     * @return callable
     */
    protected static function default_completer(\stdClass $jitsi): callable {
        $provider = self::provider($jitsi);
        if ($provider === self::PROVIDER_VERTEX) {
            return static function (string $system, string $user): string {
                $text = vertex_ai::generate_from_text($system . "\n\n" . $user);
                if ($text === null || $text === '') {
                    throw new \moodle_exception('actallmempty', 'jitsi');
                }
                return $text;
            };
        }
        $credentials = self::credentials($jitsi);
        if ($credentials === null) {
            throw new \moodle_exception('actanotavailable', 'jitsi');
        }
        return static function (string $system, string $user) use ($credentials): string {
            return acta_llm::complete(
                $credentials['apikey'],
                $credentials['endpoint'],
                $credentials['model'],
                $system,
                $user
            );
        };
    }

    /**
     * Recent actas for the activity view, newest first.
     *
     * @param int $jitsiid Jitsi instance id
     * @param int $limit Maximum rows
     * @return \stdClass[]
     */
    public static function list_for_activity(int $jitsiid, int $limit = 5): array {
        global $DB;
        return $DB->get_records('jitsi_session_acta', ['jitsi' => $jitsiid], 'sessionend DESC, id DESC', '*', 0, $limit);
    }

    /**
     * Mustache context for the activity view section.
     *
     * @param \stdClass $jitsi Jitsi instance
     * @param \stdClass $cm Course module
     * @param \context $context Module context
     * @return array|null Null when the section should be hidden
     */
    public static function export_for_view(\stdClass $jitsi, \stdClass $cm, \context $context): ?array {
        if (!has_capability('mod/jitsi:viewattendance', $context)) {
            return null;
        }
        $records = self::list_for_activity((int)$jitsi->id);
        $available = self::is_available($jitsi);
        if (!$records && !$available) {
            return null;
        }

        $items = [];
        foreach ($records as $record) {
            $attendees = json_decode((string)$record->attendancejson, true) ?: [];
            $actionitems = json_decode((string)$record->actionitems, true) ?: [];
            $attendeerows = [];
            foreach ($attendees as $attendee) {
                $attendeerows[] = [
                    'name' => $attendee['name'] ?? self::display_name((int)($attendee['userid'] ?? 0)),
                    'minutes' => (int)($attendee['minutes'] ?? 0),
                ];
            }
            $actionrows = [];
            foreach ($actionitems as $item) {
                $actionrows[] = ['text' => (string)$item];
            }
            $items[] = [
                'dates' => userdate((int)$record->sessionstart) . ' – ' . userdate((int)$record->sessionend),
                'statuspending' => $record->status === 'pending',
                'statuserror' => $record->status === 'error',
                'statusready' => $record->status === 'ready',
                'summary' => format_text((string)$record->summary, FORMAT_PLAIN),
                'attendees' => $attendeerows,
                'hasattendees' => !empty($attendeerows),
                'actionitems' => $actionrows,
                'hasactionitems' => !empty($actionrows),
                'noactionitems' => empty($actionrows) && $record->status === 'ready',
                'sourcelabel' => $record->source === 'transcript'
                    ? get_string('actasource_transcript', 'jitsi')
                    : get_string('actasource_metadata', 'jitsi'),
                'error' => $record->status === 'error' ? get_string('actaerror', 'jitsi') : '',
            ];
        }

        return [
            'title' => get_string('actatitle', 'jitsi'),
            'items' => $items,
            'hasitems' => !empty($items),
            'empty' => empty($items) && $available,
            'emptylabel' => get_string('actaempty', 'jitsi'),
            'cangenerate' => $available && has_capability('mod/jitsi:moderation', $context),
            'generateurl' => (new \moodle_url('/mod/jitsi/view.php', [
                'id' => $cm->id,
                'generateacta' => 1,
                'sesskey' => sesskey(),
            ]))->out(false),
            'generatelabel' => get_string('actagenerate', 'jitsi'),
            'privacynote' => get_string('actaprivacynote', 'jitsi'),
        ];
    }

    /**
     * Display name for a Moodle user id.
     *
     * @param int $userid User id
     * @return string
     */
    protected static function display_name(int $userid): string {
        global $DB;
        if ($userid <= 0) {
            return get_string('guest');
        }
        $user = $DB->get_record('user', ['id' => $userid], '*');
        if (!$user) {
            return get_string('unknownuser', 'error');
        }
        return fullname($user);
    }
}
