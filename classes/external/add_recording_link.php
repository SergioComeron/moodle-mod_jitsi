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
 * External API: add an external recording link (type 1) to an activity.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class add_recording_link extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
            'url' => new external_value(PARAM_URL, 'Recording URL'),
            'name' => new external_value(PARAM_TEXT, 'Display name (defaults to current date when empty)', VALUE_DEFAULT, ''),
            'embed' => new external_value(PARAM_INT, 'Whether to embed (only honoured for Dropbox links)', VALUE_DEFAULT, 0),
        ]);
    }

    /**
     * Add an external recording link to an activity.
     *
     * @param int $cmid
     * @param string $url
     * @param string $name
     * @param int $embed
     * @return array
     */
    public static function execute($cmid, $url, $name = '', $embed = 0) {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), [
            'cmid' => $cmid,
            'url' => $url,
            'name' => $name,
            'embed' => $embed,
        ]);

        $cm = get_coursemodule_from_id('jitsi', $params['cmid'], 0, false, MUST_EXIST);
        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:record', $context);

        if (empty($params['url'])) {
            return ['success' => false, 'message' => get_string('error')];
        }

        // Shared sessions store recordings against the master activity.
        $jitsiid = $jitsi->id;
        if ($jitsi->sessionwithtoken && trim($jitsi->tokeninvitacion) !== '') {
            $master = $DB->get_record('jitsi', ['tokeninterno' => trim($jitsi->tokeninvitacion)]);
            if ($master) {
                $jitsiid = $master->id;
            }
        }

        \mod_jitsi\local\recording::add_link($jitsiid, $params['url'], $params['name'], $params['embed'], $USER->id);

        return ['success' => true, 'message' => get_string('recordinglinksaved', 'jitsi')];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the link was added'),
            'message' => new external_value(PARAM_TEXT, 'Result message'),
        ]);
    }
}
