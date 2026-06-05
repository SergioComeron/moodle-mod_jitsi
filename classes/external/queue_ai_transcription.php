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
 * External API: queue an ad-hoc task to generate an AI transcription for a GCS recording.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class queue_ai_transcription extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'ID of the jitsi_source_record'),
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
        ]);
    }

    /**
     * Queue an ad-hoc task to generate an AI transcription for a GCS recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @return array
     */
    public static function execute($sourcerecordid, $cmid) {
        global $DB;

        $params = self::validate_parameters(self::execute_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid' => $cmid,
        ]);

        $context = \context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:generateaitranscription', $context);

        if (!get_config('mod_jitsi', 'aienabled')) {
            return ['success' => false, 'message' => get_string('aidisabled', 'jitsi')];
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $params['sourcerecordid']], '*', MUST_EXIST);

        if (strpos($sourcerecord->link, 'storage.googleapis.com') === false) {
            return ['success' => false, 'message' => get_string('aitranscriptionnotavailable', 'jitsi')];
        }

        $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'pending', ['id' => $params['sourcerecordid']]);

        $task = new \mod_jitsi\task\generate_ai_transcription();
        $task->set_custom_data(['sourcerecordid' => $params['sourcerecordid'], 'lang' => current_language()]);
        \core\task\manager::queue_adhoc_task($task, true);

        return ['success' => true, 'message' => get_string('aitranscriptionqueued', 'jitsi')];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the task was queued successfully'),
            'message' => new external_value(PARAM_TEXT, 'Status message'),
        ]);
    }
}
