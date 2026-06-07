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
 * Helpers to count connected minutes from the 'participating' log entries.
 *
 * Each 'participating' log row represents roughly one connected minute.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class attendance {
    /**
     * Mark the activity complete for the current user when automatic completion by
     * connected minutes is enabled.
     *
     * @param \stdClass $cm Course module
     */
    public static function update_completion($cm) {
        global $DB;
        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);
        if (! $course = $DB->get_record("course", ["id" => $cm->course])) {
            throw new \Exception("Course is misconfigured");
        }
        $completion = new \completion_info($course);

        if ($completion->is_enabled($cm) == COMPLETION_TRACKING_AUTOMATIC && $jitsi->completionminutes) {
            $completion->update_state($cm, COMPLETION_COMPLETE);
        }
    }

    /**
     * Timestamp of a user's most recent connection (participating/enter) to a course module.
     *
     * @param int $cmid Course module id
     * @param int $userid User id
     * @return int Unix timestamp, or 0 if the user has never connected
     */
    public static function last_connection($cmid, $userid): int {
        global $DB;
        $contextmodule = \context_module::instance($cmid);
        $sql = "SELECT timecreated
                  FROM {logstore_standard_log}
                 WHERE contextid = :ctxid
                   AND (action = 'participating' OR action = 'enter')
                   AND userid = :userid
              ORDER BY timecreated DESC";
        $record = $DB->get_record_sql($sql, ['ctxid' => $contextmodule->id, 'userid' => $userid], IGNORE_MULTIPLE);
        return $record ? (int)$record->timecreated : 0;
    }

    /**
     * Total connected minutes for a user in a course module.
     *
     * @param int $contextinstanceid Course module id (context instance)
     * @param int $userid User id
     * @return int
     */
    public static function minutes($contextinstanceid, $userid) {
        global $DB;

        $cache = \cache::make('mod_jitsi', 'getminutes');
        $cachekey = "getminutes_{$contextinstanceid}_{$userid}";
        $cachedresult = $cache->get($cachekey);

        if ($cachedresult !== false) {
            return $cachedresult;
        }

        // Filter by contextlevel too so PostgreSQL can use the composite index
        // (userid, contextlevel, contextinstanceid, ...) instead of a full table
        // scan, and count in the engine rather than fetching every matching row.
        $sqlminutos = 'SELECT COUNT(*) FROM {logstore_standard_log}
                       WHERE userid = :userid AND contextlevel = :contextlevel
                       AND contextinstanceid = :contextinstanceid AND action = \'participating\'';
        $params = [
            'userid' => $userid,
            'contextlevel' => CONTEXT_MODULE,
            'contextinstanceid' => $contextinstanceid,
        ];
        $result = (int)$DB->get_field_sql($sqlminutos, $params);
        $cache->set($cachekey, $result, 120); // Cache for 2 minutes.

        return $result;
    }

    /**
     * Connected minutes for a user in a course module within a time window.
     *
     * @param int $contextinstanceid Course module id (context instance)
     * @param int $userid User id
     * @param int $init Window start (unix timestamp)
     * @param int $end Window end (unix timestamp)
     * @return int
     */
    public static function minutes_between($contextinstanceid, $userid, $init, $end) {
        global $DB;

        $cache = \cache::make('mod_jitsi', 'getminutesdates');
        $cachekey = "getminutesdates_{$contextinstanceid}_{$userid}_{$init}_{$end}";
        $cachedresult = $cache->get($cachekey);

        if ($cachedresult !== false) {
            return $cachedresult;
        }

        $sqlminutos = 'SELECT COUNT(*) AS minutes FROM {logstore_standard_log}
                       WHERE userid = :userid AND contextlevel = :contextlevel
                       AND contextinstanceid = :contextinstanceid
                       AND action = \'participating\' AND timecreated BETWEEN :init AND :end';
        $params = ['userid' => $userid,
            'contextlevel' => CONTEXT_MODULE,
            'contextinstanceid' => $contextinstanceid,
            'init' => $init,
            'end' => $end,
        ];
        $minutos = $DB->get_record_sql($sqlminutos, $params);

        $cache->set($cachekey, $minutos->minutes, 120); // Cache for 2 minutes.
        return $minutos->minutes;
    }
}
