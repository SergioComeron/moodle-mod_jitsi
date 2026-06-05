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
 * External API: stop a YouTube live stream whose author is no longer present.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class stop_stream_noauthor extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Stop a YouTube live stream whose author is no longer present.
     *
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return string
     */
    public static function execute($jitsi, $userid) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsi' => $jitsi, 'userid' => $userid]
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        if ($userid != $jitsiob->sourcerecord) {
            $jitsiob->sourcerecord = null;
            $DB->update_record('jitsi', $jitsiob);
            return 'authordeleted';
        }
        return 'authornotdeleted';
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_TEXT, 'State');
    }
}
