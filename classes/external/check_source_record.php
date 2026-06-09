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
 * External API: report whether an activity currently has an associated source recording.
 *
 * Used by the recording viewer (recordun.php) to poll for a recording appearing or
 * disappearing without reloading the page.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class check_source_record extends external_api {
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
     * Return whether the activity has a source recording and its YouTube link.
     *
     * @param int $cmid
     * @return array
     */
    public static function execute($cmid) {
        global $DB;

        $params = self::validate_parameters(self::execute_parameters(), [
            'cmid' => $cmid,
        ]);

        $cm = get_coursemodule_from_id('jitsi', $params['cmid'], 0, false, MUST_EXIST);
        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $sourcerecord = false;
        if (!empty($jitsi->sourcerecord)) {
            $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $jitsi->sourcerecord]);
        }

        return [
            'found' => (bool)$sourcerecord,
            'link' => $sourcerecord ? $sourcerecord->link : '',
        ];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'found' => new external_value(PARAM_BOOL, 'Whether a source recording is associated with the activity'),
            'link' => new external_value(PARAM_TEXT, 'YouTube video id of the recording, or empty if none'),
        ]);
    }
}
