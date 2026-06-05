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
            'state' => new external_value(PARAM_TEXT, 'State', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Returns record state.
     *
     * @param int $jitsi Jitsi session id
     * @param string $state State
     * @return string
     */
    public static function execute($jitsi, $state) {
        global $USER, $DB;

        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsi' => $jitsi, 'state' => $state]
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $DB->update_record('jitsi', $jitsiob);
        return 'recording' . $jitsiob->recording;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_TEXT, 'State record session');
    }
}
