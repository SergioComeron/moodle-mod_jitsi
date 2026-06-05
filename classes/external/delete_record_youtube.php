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
 * External API: delete a YouTube recording when Jitsi reports an error.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class delete_record_youtube extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters(
            ['idsource' => new external_value(PARAM_INT, 'Record session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED)]
        );
    }

    /**
     * Delete a video from YouTube when Jitsi gets an error.
     *
     * @param int $idsource Source record id
     * @return string
     */
    public static function execute($idsource) {
        global $DB;
        $record = $DB->get_record('jitsi_record', ['source' => $idsource], '*', MUST_EXIST);
        $cm = get_coursemodule_from_instance('jitsi', $record->jitsi, 0, false, MUST_EXIST);
        require_login($cm->course, false, $cm);
        require_capability('mod/jitsi:deleterecord', \context_module::instance($cm->id));
        $record->deleted = 1;
        $DB->update_record('jitsi_record', $record);
        return \mod_jitsi\local\youtube::delete_record($idsource);
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_TEXT, 'Video deleted');
    }
}
