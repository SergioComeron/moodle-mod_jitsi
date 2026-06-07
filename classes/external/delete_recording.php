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
 * External API: mark a recording for deletion from the activity recordings tab.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class delete_recording extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
            'recordid' => new external_value(PARAM_INT, 'ID of the jitsi_record to delete'),
        ]);
    }

    /**
     * Mark a recording for deletion and log the deletion event.
     *
     * @param int $cmid
     * @param int $recordid
     * @return array
     */
    public static function execute($cmid, $recordid) {
        global $DB;

        $params = self::validate_parameters(self::execute_parameters(), [
            'cmid' => $cmid,
            'recordid' => $recordid,
        ]);

        $cm = get_coursemodule_from_id('jitsi', $params['cmid'], 0, false, MUST_EXIST);
        $course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:deleterecord', $context);

        $record = $DB->get_record('jitsi_record', ['id' => $params['recordid']], '*', MUST_EXIST);
        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);

        \mod_jitsi\local\recording::mark_to_delete($params['recordid'], 1);
        \mod_jitsi\local\recording::log_deletion($cm, $course, $jitsi, $params['recordid'], $source->link);

        return ['success' => true, 'message' => get_string('deleted')];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the recording was deleted'),
            'message' => new external_value(PARAM_TEXT, 'Result message'),
        ]);
    }
}
