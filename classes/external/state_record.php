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
 * External API: state session recording.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class state_record extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'state' => new external_value(PARAM_TEXT, 'Ignored, kept for compatibility with existing clients', VALUE_DEFAULT, ''),
        ]);
    }

    /**
     * Returns record state.
     *
     * @param int $jitsi Jitsi session id
     * @param string $state Ignored (kept for compatibility)
     * @return string
     */
    public static function execute($jitsi, $state = '') {
        global $DB;

        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsi' => $jitsi, 'state' => $state]
        );
        // Fired from the Jitsi iframe on every participant's client (including anonymous
        // invitation guests), so this stays login-optional and never throws for them: it only
        // reads the recording flag. The real state is only reported to logged-in users who can
        // view the activity; everybody else gets 'recording0'.
        $notrecording = 'recording0';
        if (!isloggedin() || isguestuser()) {
            return $notrecording;
        }
        $jitsiob = $DB->get_record('jitsi', ['id' => $params['jitsi']], 'id, course, status');
        if (!$jitsiob) {
            return $notrecording;
        }
        $cm = get_coursemodule_from_instance('jitsi', $jitsiob->id, $jitsiob->course, false, IGNORE_MISSING);
        if (!$cm) {
            return $notrecording;
        }
        $context = \context_module::instance($cm->id);
        try {
            self::validate_context($context);
        } catch (\moodle_exception $e) {
            return $notrecording;
        }
        if (!has_capability('mod/jitsi:view', $context)) {
            return $notrecording;
        }
        return $jitsiob->status === 'recording' ? 'recording1' : $notrecording;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_ALPHANUM, 'recording1 while the activity is being recorded, recording0 otherwise');
    }
}
