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
use core_external\external_multiple_structure;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External API: search Jitsi master sessions available to join.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class search_shared_sessions extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'query'        => new external_value(PARAM_TEXT, 'Search string (activity name, course name or shortname)'),
            'excludetoken' => new external_value(
                PARAM_TEXT,
                'tokeninterno to exclude from results (current activity)',
                VALUE_DEFAULT,
                ''
            ),
        ]);
    }

    /**
     * Search for Jitsi master sessions (sessionwithtoken=0) available to join.
     * Site admins search all courses; regular users are filtered to their enrolled courses.
     *
     * @param string $query
     * @param string $excludetoken
     * @return array
     */
    public static function execute($query, $excludetoken = '') {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), [
            'query'        => $query,
            'excludetoken' => $excludetoken,
        ]);
        $query        = trim($params['query']);
        $excludetoken = trim($params['excludetoken']);

        if (\core_text::strlen($query) < 3) {
            return [];
        }

        $like1 = $DB->sql_like('j.name', ':q1', false);
        $like2 = $DB->sql_like('c.fullname', ':q2', false);
        $like3 = $DB->sql_like('c.shortname', ':q3', false);

        $searchparams = [
            'q1' => '%' . $DB->sql_like_escape($query) . '%',
            'q2' => '%' . $DB->sql_like_escape($query) . '%',
            'q3' => '%' . $DB->sql_like_escape($query) . '%',
        ];

        // Exclude the current activity's own token so a session cannot join itself.
        $excludeclause = '';
        if (!empty($excludetoken)) {
            $excludeclause = ' AND j.tokeninterno <> :excludetoken';
            $searchparams['excludetoken'] = $excludetoken;
        }

        // Site admins can see all courses; regular users only their enrolled ones.
        if (is_siteadmin()) {
            $sql = "SELECT j.tokeninterno, j.name AS jname, c.fullname, c.shortname
                      FROM {jitsi} j
                      JOIN {course} c ON c.id = j.course
                     WHERE j.sessionwithtoken = 0
                       AND ($like1 OR $like2 OR $like3)
                       $excludeclause
                  ORDER BY c.shortname, j.name
                     LIMIT 20";
            $inparams = [];
        } else {
            $courses = enrol_get_users_courses($USER->id, true, ['id']);
            if (empty($courses)) {
                return [];
            }
            $courseids = array_keys($courses);
            [$insql, $inparams] = $DB->get_in_or_equal($courseids, SQL_PARAMS_NAMED, 'cid');

            $sql = "SELECT j.tokeninterno, j.name AS jname, c.fullname, c.shortname
                      FROM {jitsi} j
                      JOIN {course} c ON c.id = j.course
                     WHERE j.sessionwithtoken = 0
                       AND j.course $insql
                       AND ($like1 OR $like2 OR $like3)
                       $excludeclause
                  ORDER BY c.shortname, j.name
                     LIMIT 20";
        }

        $records = $DB->get_records_sql($sql, array_merge($inparams, $searchparams));

        // If the query looks like an exact token (64 lowercase hex chars), also search
        // globally by tokeninterno regardless of enrollment, so teachers can use a
        // token shared by a colleague from another course.
        if (preg_match('/^[0-9a-f]{64}$/', $query) && $query !== $excludetoken) {
            $tokensql = "SELECT j.tokeninterno, j.name AS jname, c.fullname, c.shortname
                           FROM {jitsi} j
                           JOIN {course} c ON c.id = j.course
                          WHERE j.sessionwithtoken = 0
                            AND j.tokeninterno = :tok";
            $tokenrec = $DB->get_record_sql($tokensql, ['tok' => $query]);
            if ($tokenrec && !isset($records[$tokenrec->tokeninterno])) {
                $records[$tokenrec->tokeninterno] = $tokenrec;
            }
        }

        $results = [];
        foreach ($records as $rec) {
            $results[] = [
                'value' => $rec->tokeninterno,
                'label' => $rec->jname . ' — ' . $rec->fullname . ' (' . $rec->shortname . ')',
            ];
        }
        return $results;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_multiple_structure
     */
    public static function execute_returns() {
        return new external_multiple_structure(
            new external_single_structure([
                'value' => new external_value(PARAM_TEXT, 'tokeninterno of the Jitsi session'),
                'label' => new external_value(PARAM_TEXT, 'Human-readable label (activity — course)'),
            ])
        );
    }
}
