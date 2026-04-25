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
 * Scheduled task to precompute daily Jitsi usage statistics.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\task;

/**
 * Aggregates logstore_standard_log entries for mod_jitsi into jitsi_usage_daily,
 * processing one day at a time to avoid locking the log table for long periods.
 */
class aggregate_usage_stats extends \core\task\scheduled_task {
    /** Maximum days to process per task run (limits impact on large backlogs). */
    const MAX_DAYS_PER_RUN = 30;

    /**
     * Returns the task name shown in the Moodle admin UI.
     *
     * @return string
     */
    public function get_name() {
        return get_string('task_aggregate_usage_stats', 'jitsi');
    }

    /**
     * Executes the task.
     */
    public function execute() {
        global $DB;

        $lastday = (int)get_config('mod_jitsi', 'usage_stats_last_day');

        if ($lastday === 0) {
            $earliest = $DB->get_field_sql(
                "SELECT MIN(timecreated) FROM {logstore_standard_log} WHERE component = 'mod_jitsi'"
            );
            if (!$earliest) {
                mtrace('mod_jitsi aggregate_usage_stats: no log entries found, skipping.');
                return;
            }
            // Start from the day before the earliest entry so the loop increments to it.
            $lastdayts = mktime(0, 0, 0, (int)date('m', $earliest), (int)date('d', $earliest), (int)date('Y', $earliest));
            $lastdayts -= 86400;
        } else {
            $lastdayts = mktime(
                0,
                0,
                0,
                (int)substr((string)$lastday, 4, 2),
                (int)substr((string)$lastday, 6, 2),
                (int)substr((string)$lastday, 0, 4)
            );
        }

        $yesterdaykey = (int)date('Ymd', time() - 86400);
        $daysprocessed = 0;
        $currentdayts = $lastdayts + 86400;

        while ($daysprocessed < self::MAX_DAYS_PER_RUN) {
            $daykeyint = (int)date('Ymd', $currentdayts);

            if ($daykeyint > $yesterdaykey) {
                mtrace('mod_jitsi aggregate_usage_stats: up to date.');
                break;
            }

            $daystart = mktime(
                0,
                0,
                0,
                (int)date('m', $currentdayts),
                (int)date('d', $currentdayts),
                (int)date('Y', $currentdayts)
            );
            $dayend   = $daystart + 86399;

            // Delete any existing rows for this day (makes the task idempotent).
            $DB->delete_records('jitsi_usage_daily', ['daykey' => $daykeyint]);

            [$insql, $inparams] = $DB->get_in_or_equal(['enter', 'participating'], SQL_PARAMS_NAMED, 'act');
            $sql = "SELECT lsl.contextinstanceid AS cmid,
                           lsl.userid,
                           cm.course AS courseid,
                           c.category AS categoryid,
                           SUM(CASE WHEN lsl.action = 'enter' THEN 1 ELSE 0 END) AS sessions,
                           SUM(CASE WHEN lsl.action = 'participating' THEN 1 ELSE 0 END) AS minutes
                      FROM {logstore_standard_log} lsl
                      JOIN {course_modules} cm ON cm.id = lsl.contextinstanceid
                      JOIN {course} c ON c.id = cm.course
                     WHERE lsl.component = :component
                           AND lsl.action $insql
                           AND lsl.timecreated BETWEEN :daystart AND :dayend
                  GROUP BY lsl.contextinstanceid, lsl.userid, cm.course, c.category";

            $rows = $DB->get_records_sql($sql, array_merge($inparams, [
                'component' => 'mod_jitsi',
                'daystart'  => $daystart,
                'dayend'    => $dayend,
            ]));

            if (!empty($rows)) {
                $records = [];
                foreach ($rows as $row) {
                    $records[] = [
                        'daykey'     => $daykeyint,
                        'userid'     => $row->userid,
                        'cmid'       => $row->cmid,
                        'courseid'   => $row->courseid,
                        'categoryid' => $row->categoryid,
                        'sessions'   => (int)$row->sessions,
                        'minutes'    => (int)$row->minutes,
                    ];
                }
                $DB->insert_records('jitsi_usage_daily', $records);
            }

            set_config('usage_stats_last_day', $daykeyint, 'mod_jitsi');
            mtrace("mod_jitsi aggregate_usage_stats: processed $daykeyint (" . count($rows) . " rows)");

            $currentdayts += 86400;
            $daysprocessed++;

            // Brief pause between days to reduce contention on the log table.
            if ($daysprocessed < self::MAX_DAYS_PER_RUN && $daykeyint < $yesterdaykey) {
                sleep(1);
            }
        }
    }
}
