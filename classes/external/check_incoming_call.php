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
 * External API: check for an incoming private session call for the current user.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class check_incoming_call extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'since' => new external_value(PARAM_INT, 'Unix timestamp to check from'),
        ]);
    }

    /**
     * Check if anyone has entered a private session room with the current user recently.
     *
     * @param int $since Unix timestamp
     * @return array
     */
    public static function execute($since) {
        global $DB, $USER, $PAGE;

        $params = self::validate_parameters(self::execute_parameters(), ['since' => $since]);
        $context = \context_system::instance();
        self::validate_context($context);

        $eventname = '\mod_jitsi\event\jitsi_private_session_enter';
        $logs = $DB->get_records_select(
            'logstore_standard_log',
            'eventname = :eventname AND timecreated >= :since AND userid != :userid',
            ['eventname' => $eventname, 'since' => $params['since'], 'userid' => $USER->id],
            'timecreated DESC'
        );

        foreach ($logs as $log) {
            $other = json_decode($log->other, true);
            if (isset($other['peerid']) && (int)$other['peerid'] === (int)$USER->id) {
                $caller = $DB->get_record(
                    'user',
                    ['id' => $log->userid, 'deleted' => 0],
                    'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename, picture, imagealt, email', // phpcs:ignore moodle.Files.LineLength.MaxExceeded
                    IGNORE_MISSING
                );
                if ($caller) {
                    $userpicture = new \user_picture($caller);
                    $userpicture->size = 1;
                    return [
                        'incoming'     => true,
                        'callerid'     => (int)$caller->id,
                        'callername'   => fullname($caller),
                        'calleravatar' => $userpicture->get_url($PAGE)->out(false),
                        'timecreated'  => (int)$log->timecreated,
                    ];
                }
            }
        }

        return [
            'incoming'     => false,
            'callerid'     => 0,
            'callername'   => '',
            'calleravatar' => '',
            'timecreated'  => 0,
        ];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'incoming'     => new external_value(PARAM_BOOL, 'Whether there is an incoming call'),
            'callerid'     => new external_value(PARAM_INT, 'Caller user ID'),
            'callername'   => new external_value(PARAM_TEXT, 'Caller full name'),
            'calleravatar' => new external_value(PARAM_URL, 'Caller avatar URL'),
            'timecreated'  => new external_value(PARAM_INT, 'Event timestamp'),
        ]);
    }
}
