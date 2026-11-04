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

namespace mod_jitsi\external;

use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_value;

/**
 * External API: register a participation in a Jitsi session.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class participating_session extends external_api {
    /** @var int Minimum seconds between two participation rows of the same user in the same activity. */
    const MIN_INTERVAL = 55;

    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Register a participation in a Jitsi session.
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     * @return string 'ok' if the participation was recorded, 'ignored' if it came too soon
     */
    public static function execute($jitsi, $user, $cmid) {
        global $DB, $USER;

        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsi' => $jitsi, 'user' => $user, 'cmid' => $cmid]
        );
        // The 'user' parameter is ignored: the event is always logged for the current user.
        [$jitsiob, $cm, $course, $context] = \mod_jitsi\local\external_access::validate_activity(
            $params['jitsi'],
            $params['cmid']
        );
        // Each row counts as one minute of attendance: accept at most one per user and activity per minute.
        $last = $DB->get_field_sql(
            "SELECT MAX(timecreated) FROM {logstore_standard_log}
              WHERE userid = :userid AND contextlevel = :contextlevel
                AND contextinstanceid = :cmid AND action = 'participating'",
            ['userid' => $USER->id, 'contextlevel' => CONTEXT_MODULE, 'cmid' => $cm->id]
        );
        if ($last && (time() - $last) < self::MIN_INTERVAL) {
            return 'ignored';
        }

        $event = \mod_jitsi\event\jitsi_session_participating::create([
            'objectid' => $jitsiob->id,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
        \mod_jitsi\local\attendance::update_completion($cm);
        return 'ok';
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_TEXT, 'Participating session');
    }
}
