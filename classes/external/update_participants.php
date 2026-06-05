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
 * External API: update the stored number of participants for a session.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class update_participants extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'numberofparticipants' =>
                new external_value(PARAM_INT, 'Number of participants', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Update the number of participants.
     *
     * @param int $jitsi Jitsi session id
     * @param int $numberofparticipants Number of participants
     * @return int Stored number of participants
     */
    public static function execute($jitsi, $numberofparticipants) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsi' => $jitsi, 'numberofparticipants' => $numberofparticipants],
        );
        if ($numberofparticipants >= 0) {
            $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
            if ($numberofparticipants != $jitsiob->numberofparticipants) {
                $jitsiob->numberofparticipants = $numberofparticipants;
                $DB->update_record('jitsi', $jitsiob);
                if ($jitsiob->sourcerecord != null) {
                    $source = $DB->get_record('jitsi_source_record', ['id' => $jitsiob->sourcerecord]);
                    if ($source && $source->maxparticipants < $numberofparticipants) {
                        $source->maxparticipants = $numberofparticipants;
                        $DB->update_record('jitsi_source_record', $source);
                    }
                }
            }
        }
        return $jitsiob->numberofparticipants;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_INT, 'Number of partipants');
    }
}
