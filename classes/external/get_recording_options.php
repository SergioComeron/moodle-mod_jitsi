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
use mod_jitsi\local\session;

/**
 * External API: what the current user can record or stream in a Jitsi activity.
 *
 * Same rules as the web session toolbar and record buttons. Returns flags only: no Dropbox
 * app key, YouTube account, stream key or server secret.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_recording_options extends external_api {
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
     * Return the recording options of the current user.
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
        return session::recording_options(session::get_server(), $context, $jitsi);
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        $modes = 'native (Jitsi toolbar / SDK), moodle (Moodle record button) or none';
        return new external_single_structure([
            'canrecord' => new external_value(PARAM_BOOL, 'Whether the user has mod/jitsi:record'),
            'ismoderator' => new external_value(PARAM_BOOL, 'Whether the user has mod/jitsi:moderation (JWT moderator claim)'),
            'filerecording' => new external_value(PARAM_BOOL, 'Whether the user can start a file recording here'),
            'streaming' => new external_value(PARAM_BOOL, 'Whether the user can start a live stream here'),
            'dropbox' => new external_value(PARAM_BOOL, 'Whether recording to Dropbox is offered'),
            'mode' => new external_value(PARAM_ALPHA, 'How file recording is started: ' . $modes),
            'streamingmode' => new external_value(PARAM_ALPHA, 'How live streaming is started: ' . $modes),
        ]);
    }
}
