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
 * External API: get the current user's tutoring schedule grouped by course.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_tutoring_schedule extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([]);
    }

    /**
     * Get the current user's tutoring schedule grouped by course.
     *
     * @return array
     */
    public static function execute() {
        global $DB, $USER;

        $context = \context_system::instance();
        self::validate_context($context);

        $slots = $DB->get_records(
            'jitsi_tutoring_schedule',
            ['userid' => $USER->id],
            'courseid ASC, weekday ASC, timestart ASC'
        );

        $courses = [];
        foreach ($slots as $slot) {
            $courseid = (int)$slot->courseid;
            if (!isset($courses[$courseid])) {
                $course = $DB->get_record('course', ['id' => $courseid], 'id, fullname', IGNORE_MISSING);
                $courses[$courseid] = [
                    'courseid'   => $courseid,
                    'coursename' => $course ? $course->fullname : '?',
                    'slots'      => [],
                ];
            }
            $h = intdiv((int)$slot->timestart, 3600);
            $m = intdiv(((int)$slot->timestart % 3600), 60);
            $hend = intdiv((int)$slot->timeend, 3600);
            $mend = intdiv(((int)$slot->timeend % 3600), 60);
            $courses[$courseid]['slots'][] = [
                'id'        => (int)$slot->id,
                'weekday'   => (int)$slot->weekday,
                'timestart' => sprintf('%02d:%02d', $h, $m),
                'timeend'   => sprintf('%02d:%02d', $hend, $mend),
            ];
        }

        return ['courses' => array_values($courses)];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'courses' => new external_multiple_structure(
                new external_single_structure([
                    'courseid'   => new external_value(PARAM_INT, 'Course ID'),
                    'coursename' => new external_value(PARAM_TEXT, 'Course name'),
                    'slots'      => new external_multiple_structure(
                        new external_single_structure([
                            'id'        => new external_value(PARAM_INT, 'Slot ID'),
                            'weekday'   => new external_value(PARAM_INT, 'Day of week (0=Sun)'),
                            'timestart' => new external_value(PARAM_TEXT, 'Start time HH:MM'),
                            'timeend'   => new external_value(PARAM_TEXT, 'End time HH:MM'),
                        ])
                    ),
                ])
            ),
        ]);
    }
}
