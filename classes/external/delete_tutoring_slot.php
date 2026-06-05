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
 * External API: delete a tutoring schedule slot (only the owner can delete).
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class delete_tutoring_slot extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'slotid' => new external_value(PARAM_INT, 'Slot ID to delete'),
        ]);
    }

    /**
     * Delete a tutoring schedule slot (only the owner can delete).
     *
     * @param int $slotid
     * @return array
     */
    public static function execute($slotid) {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), ['slotid' => $slotid]);
        $context = \context_system::instance();
        self::validate_context($context);

        $slot = $DB->get_record('jitsi_tutoring_schedule', ['id' => $params['slotid']], 'id, userid', MUST_EXIST);
        if ((int)$slot->userid !== (int)$USER->id) {
            throw new \moodle_exception('nopermissions', 'error', '', 'delete tutoring slot');
        }

        $DB->delete_records('jitsi_tutoring_schedule', ['id' => $params['slotid']]);

        return ['success' => true];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether deletion succeeded'),
        ]);
    }
}
