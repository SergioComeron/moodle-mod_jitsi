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
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External API: save a tutoring schedule slot for the current user.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class save_tutoring_slot extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'courseid'  => new external_value(PARAM_INT, 'Course ID'),
            'weekday'   => new external_value(PARAM_INT, 'Day of week 0=Sun, 6=Sat'),
            'timestart' => new external_value(PARAM_TEXT, 'Start time HH:MM'),
            'timeend'   => new external_value(PARAM_TEXT, 'End time HH:MM'),
        ]);
    }

    /**
     * Save a tutoring schedule slot for the current user.
     *
     * @param int $courseid
     * @param int $weekday
     * @param string $timestart HH:MM
     * @param string $timeend HH:MM
     * @return array
     */
    public static function execute($courseid, $weekday, $timestart, $timeend) {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), [
            'courseid'  => $courseid,
            'weekday'   => $weekday,
            'timestart' => $timestart,
            'timeend'   => $timeend,
        ]);

        $context = \context_system::instance();
        self::validate_context($context);

        // Validate course exists, is visible, and user is enrolled as teacher.
        $course = $DB->get_record('course', ['id' => $params['courseid'], 'visible' => 1], 'id', MUST_EXIST);
        $coursecontext = \context_course::instance($course->id);
        if (!has_capability('mod/jitsi:addinstance', $coursecontext)) {
            throw new \moodle_exception('nopermissions', 'error', '', 'save tutoring slot');
        }

        // Parse times.
        [$sh, $sm] = array_map('intval', explode(':', $params['timestart']));
        [$eh, $em] = array_map('intval', explode(':', $params['timeend']));
        $startsecs = $sh * 3600 + $sm * 60;
        $endsecs   = $eh * 3600 + $em * 60;

        if ($endsecs <= $startsecs) {
            throw new \moodle_exception('error', 'mod_jitsi', '', 'End time must be after start time');
        }

        $now = time();
        $record = (object)[
            'userid'       => $USER->id,
            'courseid'     => $params['courseid'],
            'weekday'      => $params['weekday'],
            'timestart'    => $startsecs,
            'timeend'      => $endsecs,
            'timecreated'  => $now,
            'timemodified' => $now,
        ];
        $id = $DB->insert_record('jitsi_tutoring_schedule', $record);

        return ['id' => (int)$id];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'id' => new external_value(PARAM_INT, 'New slot ID'),
        ]);
    }
}
