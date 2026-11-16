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
 * External API: register local participant presence on join.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class presence_join extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsiid' => new external_value(PARAM_INT, 'Jitsi session id'),
            'sessionhash' => new external_value(PARAM_ALPHANUMEXT, 'Unique session hash'),
            'guestname' => new external_value(
                PARAM_TEXT,
                'Deprecated and ignored: the guest name is taken from the presence token',
                VALUE_DEFAULT,
                ''
            ),
            'token' => new external_value(PARAM_RAW, 'Presence token issued by the session page', VALUE_DEFAULT, ''),
        ]);
    }

    /**
     * Register local participant presence on join.
     *
     * @param int $jitsiid Jitsi session id.
     * @param string $sessionhash Unique browser session hash.
     * @param string $guestname Deprecated and ignored.
     * @param string $token Presence token issued by the session page ('' for authenticated clients).
     * @return int Total active participants.
     */
    public static function execute($jitsiid, $sessionhash, $guestname = '', $token = '') {
        global $DB;
        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsiid' => $jitsiid, 'sessionhash' => $sessionhash, 'guestname' => $guestname, 'token' => $token]
        );
        $jitsiid = $params['jitsiid'];
        $sessionhash = $params['sessionhash'];
        $who = presence::authorise($jitsiid, $sessionhash, $params['token']);
        $now = time();
        $existing = $DB->get_record('jitsi_presence', ['jitsiid' => $jitsiid, 'sessionhash' => $sessionhash]);
        if ($existing && (int) $existing->userid !== (int) $who->userid) {
            // The session hash belongs to someone else's row: never take it over.
            throw new \moodle_exception('invalidaccess', 'error');
        }
        if ($existing) {
            $existing->timemodified = $now;
            $DB->update_record('jitsi_presence', $existing);
        } else {
            $record = new \stdClass();
            $record->jitsiid = $jitsiid;
            $record->userid = $who->userid;
            $record->sessionhash = $sessionhash;
            $record->guestname = ($who->userid == 0 && $who->guestname !== '') ? $who->guestname : null;
            $record->timecreated = $now;
            $record->timemodified = $now;
            $DB->insert_record('jitsi_presence', $record);
        }
        $count = presence::count($jitsiid);
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsiid]);
        if ($jitsiob && $jitsiob->sourcerecord) {
            $source = $DB->get_record('jitsi_source_record', ['id' => $jitsiob->sourcerecord]);
            if ($source && $source->maxparticipants < $count['total']) {
                $source->maxparticipants = $count['total'];
                $DB->update_record('jitsi_source_record', $source);
            }
        }
        return $count['total'];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_INT, 'Total participants now');
    }
}
