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
 * External API: update presence heartbeat timestamp and clean stale entries.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class presence_heartbeat extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsiid' => new external_value(PARAM_INT, 'Jitsi session id'),
            'sessionhash' => new external_value(PARAM_ALPHANUMEXT, 'Unique session hash'),
            'token' => new external_value(PARAM_RAW, 'Presence token issued by the session page', VALUE_DEFAULT, ''),
        ]);
    }

    /**
     * Update presence heartbeat timestamp and clean stale entries.
     *
     * @param int $jitsiid Jitsi session id.
     * @param string $sessionhash Unique browser session hash.
     * @param string $token Presence token issued by the session page ('' for authenticated clients).
     * @return bool
     */
    public static function execute($jitsiid, $sessionhash, $token = '') {
        global $DB;
        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsiid' => $jitsiid, 'sessionhash' => $sessionhash, 'token' => $token]
        );
        $jitsiid = $params['jitsiid'];
        $sessionhash = $params['sessionhash'];
        $who = presence::authorise($jitsiid, $sessionhash, $params['token']);
        $own = ['jitsiid' => $jitsiid, 'sessionhash' => $sessionhash, 'userid' => $who->userid];
        // Only stale rows of this activity are cleaned up here.
        $DB->delete_records_select(
            'jitsi_presence',
            'jitsiid = :jitsiid AND timemodified < :threshold',
            ['jitsiid' => $jitsiid, 'threshold' => time() - 150]
        );
        $existing = $DB->get_record('jitsi_presence', $own);
        if ($existing) {
            $existing->timemodified = time();
            $DB->update_record('jitsi_presence', $existing);
        }
        return true;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_BOOL, 'Success');
    }
}
