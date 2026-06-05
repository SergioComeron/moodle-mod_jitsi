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
 * External API: get names of active participants from the presence table.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_presence_users extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsiid' => new external_value(PARAM_INT, 'Jitsi session id'),
        ]);
    }

    /**
     * Get names of active participants from the presence table.
     *
     * @param int $jitsiid Jitsi session id.
     * @return array List of participant names.
     */
    public static function execute($jitsiid) {
        global $DB;
        $params = self::validate_parameters(self::execute_parameters(), ['jitsiid' => $jitsiid]);
        $threshold = time() - 90;
        $rows = $DB->get_records_select(
            'jitsi_presence',
            'jitsiid = :jitsiid AND timemodified > :threshold',
            ['jitsiid' => $params['jitsiid'], 'threshold' => $threshold],
            'userid DESC'
        );
        $result = [];
        foreach ($rows as $row) {
            if ($row->userid > 0) {
                $fields = 'id,firstname,lastname,firstnamephonetic,lastnamephonetic,middlename,alternatename';
                $user = $DB->get_record('user', ['id' => $row->userid], $fields);
                $name = $user ? fullname($user) : get_string('unknownuser', 'error');
            } else {
                $name = $row->guestname ?: get_string('guest');
            }
            $result[] = ['name' => $name, 'isguest' => (int)($row->userid == 0), 'userid' => (int)$row->userid];
        }
        return $result;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_multiple_structure
     */
    public static function execute_returns() {
        return new external_multiple_structure(
            new external_single_structure([
                'name' => new external_value(PARAM_TEXT, 'Display name'),
                'isguest' => new external_value(PARAM_INT, 'Is guest'),
                'userid' => new external_value(PARAM_INT, 'Moodle user id, 0 for guests'),
            ])
        );
    }
}
