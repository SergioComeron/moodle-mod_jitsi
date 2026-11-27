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
 * External API: report whether a Jitsi session can be joined now, without exposing secrets.
 *
 * Uses the same open/close rule as the mobile pre-session view. Never returns the server
 * secret, the JWT, API tokens or passwords.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_session_state extends external_api {
    /** @var string The session can be joined now. */
    const STATE_OPEN = 'open';
    /** @var string The session has not started yet (before timeopen minus minpretime). */
    const STATE_NOTSTARTED = 'notstarted';
    /** @var string The session has finished (after timeclose). */
    const STATE_CLOSED = 'closed';

    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'cmid' => new external_value(PARAM_INT, 'Course module ID of the jitsi activity'),
        ]);
    }

    /**
     * Return the state of the session.
     *
     * @param int $cmid Course module id.
     * @return array
     */
    public static function execute($cmid) {
        global $DB;
        $params = self::validate_parameters(self::execute_parameters(), ['cmid' => $cmid]);

        $cm = get_coursemodule_from_id('jitsi', $params['cmid'], 0, false, MUST_EXIST);
        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);
        $course = $DB->get_record('course', ['id' => $cm->course], 'id, shortname', MUST_EXIST);

        $now = time();
        $timeopen = (int) $jitsi->timeopen;
        $timeclose = (int) $jitsi->timeclose;
        $minpretime = (int) $jitsi->minpretime;
        $startsat = $timeopen - ($minpretime * 60);

        $minutesbefore = 0;
        if ($timeclose != 0 && $now >= $timeclose) {
            $state = self::STATE_CLOSED;
        } else if ($now <= $startsat) {
            $state = self::STATE_NOTSTARTED;
            $minutesbefore = max(1, (int) ceil(($startsat - $now) / 60));
        } else {
            $state = self::STATE_OPEN;
        }

        $session = \mod_jitsi\local\room::for_activity($jitsi, $course);
        $room = $session === null ? '' : \mod_jitsi\local\room::normalize_session_name($session);

        $domain = 'meet.jit.si';
        $jwtrequired = false;
        $serverid = get_config('mod_jitsi', 'server');
        if (!empty($serverid)) {
            $server = $DB->get_record('jitsi_servers', ['id' => $serverid], 'id, domain, appid, secret');
            if ($server) {
                $domain = (string) $server->domain;
                $jwtrequired = !empty($server->appid) && !empty($server->secret);
            }
        }

        return [
            'state' => $state,
            'timeopen' => $timeopen,
            'timeclose' => $timeclose,
            'minpretime' => $minpretime,
            'minutesbefore' => $minutesbefore,
            'room' => $room,
            'domain' => $domain,
            'jwt_required' => $jwtrequired,
        ];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'state' => new external_value(PARAM_ALPHA, 'Session state: open, notstarted or closed'),
            'timeopen' => new external_value(PARAM_INT, 'Opening time (Unix), 0 if none'),
            'timeclose' => new external_value(PARAM_INT, 'Closing time (Unix), 0 if none'),
            'minpretime' => new external_value(PARAM_INT, 'Minutes before timeopen when users can join'),
            'minutesbefore' => new external_value(PARAM_INT, 'Minutes left until users can join, 0 if open or closed'),
            'room' => new external_value(PARAM_TEXT, 'Normalised room name'),
            'domain' => new external_value(PARAM_TEXT, 'Jitsi server domain'),
            'jwt_required' => new external_value(PARAM_BOOL, 'Whether the server requires a JWT to join'),
        ]);
    }
}
