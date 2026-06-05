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
 * External API: search for users who share at least one course with the current user.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class search_coursemates extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'query' => new external_value(PARAM_TEXT, 'Search string (firstname or lastname)'),
        ]);
    }

    /**
     * Search for users who share at least one course with the current user.
     *
     * @param string $query
     * @return array
     */
    public static function execute($query) {
        global $DB, $USER, $PAGE, $CFG;
        require_once($CFG->dirroot . '/mod/jitsi/lib.php');

        $params = self::validate_parameters(self::execute_parameters(), ['query' => $query]);
        $context = \context_system::instance();
        self::validate_context($context);

        $query = trim($params['query']);
        if (\core_text::strlen($query) < 2) {
            return ['users' => []];
        }

        $searchparam = '%' . $DB->sql_like_escape($query) . '%';

        $sql = "SELECT DISTINCT u.id, u.firstname, u.lastname, u.firstnamephonetic, u.lastnamephonetic,
                       u.middlename, u.alternatename, u.picture, u.imagealt, u.email
                  FROM {user} u
                  JOIN {user_enrolments} ue ON ue.userid = u.id
                  JOIN {enrol} e ON e.id = ue.enrolid
                  JOIN {course} c ON c.id = e.courseid AND c.visible = 1
                 WHERE e.courseid IN (
                           SELECT e2.courseid
                             FROM {enrol} e2
                             JOIN {user_enrolments} ue2 ON ue2.enrolid = e2.id
                             JOIN {course} c2 ON c2.id = e2.courseid AND c2.visible = 1
                            WHERE ue2.userid = :currentuserid
                       )
                   AND u.id != :currentuserid2
                   AND u.deleted = 0
                   AND u.suspended = 0
                   AND (" . $DB->sql_like('u.firstname', ':search1', false) . "
                        OR " . $DB->sql_like('u.lastname', ':search2', false) . ")
              ORDER BY u.firstname, u.lastname";

        $records = $DB->get_records_sql($sql, [
            'currentuserid'  => $USER->id,
            'currentuserid2' => $USER->id,
            'search1'        => $searchparam,
            'search2'        => $searchparam,
        ], 0, 20);

        $users = [];
        foreach ($records as $record) {
            $userpicture = new \user_picture($record);
            $userpicture->size = 1;
            $availability = jitsi_check_tutoring_availability($record->id, $USER->id);
            $users[] = [
                'id'              => (int)$record->id,
                'firstname'       => $record->firstname,
                'lastname'        => $record->lastname,
                'profileimageurl' => $userpicture->get_url($PAGE)->out(false),
                'hasschedule'     => $availability['hasschedule'],
                'available'       => $availability['available'],
                'nextslot'        => $availability['nextslot'] ?? '',
            ];
        }

        return ['users' => $users];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'users' => new external_multiple_structure(
                new external_single_structure([
                    'id'              => new external_value(PARAM_INT, 'User ID'),
                    'firstname'       => new external_value(PARAM_TEXT, 'First name'),
                    'lastname'        => new external_value(PARAM_TEXT, 'Last name'),
                    'profileimageurl' => new external_value(PARAM_URL, 'Profile image URL'),
                    'hasschedule'     => new external_value(PARAM_BOOL, 'Has tutoring schedule'),
                    'available'       => new external_value(PARAM_BOOL, 'Available now'),
                    'nextslot'        => new external_value(PARAM_TEXT, 'Next available slot', VALUE_OPTIONAL),
                ])
            ),
        ]);
    }
}
