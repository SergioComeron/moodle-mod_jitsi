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
 * External API: get a teacher's tutoring schedule visible to the current user.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_teacher_schedule extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'teacherid' => new external_value(PARAM_INT, 'Teacher user ID'),
        ]);
    }

    /**
     * Get tutoring schedule for a teacher visible to the current user (shared courses only).
     *
     * @param int $teacherid
     * @return array
     */
    public static function execute($teacherid) {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), ['teacherid' => $teacherid]);
        $context = \context_system::instance();
        self::validate_context($context);

        $availability = \mod_jitsi\local\tutoring::check_availability($params['teacherid'], $USER->id);

        $slots = [];
        if ($availability['hasschedule']) {
            // Return all slots for shared courses.
            $teacherroles = array_keys(get_archetype_roles('teacher') + get_archetype_roles('editingteacher'));
            $studentroles = array_keys(get_archetype_roles('student'));
            [$trolesql, $troleparams] = $DB->get_in_or_equal($teacherroles, SQL_PARAMS_NAMED, 'trole');
            [$srolesql, $sroleparams] = $DB->get_in_or_equal($studentroles, SQL_PARAMS_NAMED, 'srole');

            $teachercourses = $DB->get_fieldset_sql(
                "SELECT DISTINCT ctx.instanceid
                   FROM {role_assignments} ra
                   JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
                   JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
                  WHERE ra.userid = :teacherid AND ra.roleid $trolesql",
                array_merge(['ctxlevel' => CONTEXT_COURSE, 'teacherid' => $params['teacherid']], $troleparams)
            );

            if (!empty($teachercourses)) {
                [$coursesql, $courseparams] = $DB->get_in_or_equal($teachercourses, SQL_PARAMS_NAMED, 'course');
                $sharedcourses = $DB->get_fieldset_sql(
                    "SELECT DISTINCT ctx.instanceid
                       FROM {role_assignments} ra
                       JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
                       JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
                      WHERE ra.userid = :studentid AND ra.roleid $srolesql AND ctx.instanceid $coursesql",
                    array_merge(['ctxlevel' => CONTEXT_COURSE, 'studentid' => $USER->id], $sroleparams, $courseparams)
                );

                if (!empty($sharedcourses)) {
                    [$csql, $cparams] = $DB->get_in_or_equal($sharedcourses, SQL_PARAMS_NAMED, 'sc');
                    $records = $DB->get_records_select(
                        'jitsi_tutoring_schedule',
                        "userid = :teacherid AND courseid $csql",
                        array_merge(['teacherid' => $params['teacherid']], $cparams),
                        'weekday ASC, timestart ASC'
                    );
                    foreach ($records as $slot) {
                        $h = intdiv((int)$slot->timestart, 3600);
                        $m = intdiv(((int)$slot->timestart % 3600), 60);
                        $hend = intdiv((int)$slot->timeend, 3600);
                        $mend = intdiv(((int)$slot->timeend % 3600), 60);
                        $slots[] = [
                            'weekday'   => (int)$slot->weekday,
                            'timestart' => sprintf('%02d:%02d', $h, $m),
                            'timeend'   => sprintf('%02d:%02d', $hend, $mend),
                        ];
                    }
                }
            }
        }

        return [
            'hasschedule' => $availability['hasschedule'],
            'available'   => $availability['available'],
            'nextslot'    => $availability['nextslot'] ?? '',
            'slots'       => $slots,
        ];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'hasschedule' => new external_value(PARAM_BOOL, 'Has schedule'),
            'available'   => new external_value(PARAM_BOOL, 'Available now'),
            'nextslot'    => new external_value(PARAM_TEXT, 'Next slot label'),
            'slots'       => new external_multiple_structure(
                new external_single_structure([
                    'weekday'   => new external_value(PARAM_INT, 'Day of week'),
                    'timestart' => new external_value(PARAM_TEXT, 'Start HH:MM'),
                    'timeend'   => new external_value(PARAM_TEXT, 'End HH:MM'),
                ])
            ),
        ]);
    }
}
