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
use mod_jitsi\local\presence;

/**
 * External API: get active participant count from the presence table.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_presence_count extends external_api {
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
     * Get active participant count from the presence table.
     *
     * @param int $jitsiid Jitsi session id.
     * @return int Total active participants.
     */
    public static function execute($jitsiid) {
        $params = self::validate_parameters(self::execute_parameters(), ['jitsiid' => $jitsiid]);
        $count = presence::count($params['jitsiid']);
        return $count['total'];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_INT, 'Total active participants');
    }
}
