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
use mod_jitsi\local\vertex_ai;

/**
 * External API: report the generation status of the AI features for a recording.
 *
 * Used by the recordings table to poll while a summary/quiz/transcription is
 * being generated, so the UI can refresh itself when the task finishes.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_ai_status extends external_api {
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
     * Return the AI generation status for a recording.
     *
     * Each feature reports one of: none, pending, done, error.
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
        require_capability('mod/jitsi:view', $context);

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $params['sourcerecordid']], '*', MUST_EXIST);

        // Summary: the task stores an error string in ai_summary on failure.
        $summaryerrorstrs = [
            get_string('aisummaryerror', 'jitsi'),
            get_string('aisummarynotavailable', 'jitsi'),
        ];
        if (!empty($sourcerecord->ai_summary)) {
            $summary = in_array($sourcerecord->ai_summary, $summaryerrorstrs) ? 'error' : 'done';
        } else if (vertex_ai::has_pending_task(\mod_jitsi\task\generate_ai_summary::class, $sourcerecord->id)) {
            $summary = 'pending';
        } else {
            $summary = 'none';
        }

        // Quiz: ai_quiz_id > 0 = cmid of the quiz, -1 = failed, 0 = not generated.
        $quizid = (int)($sourcerecord->ai_quiz_id ?? 0);
        if ($quizid > 0) {
            $quiz = 'done';
        } else if ($quizid < 0) {
            $quiz = 'error';
        } else if (vertex_ai::has_pending_task(\mod_jitsi\task\generate_ai_quiz::class, $sourcerecord->id)) {
            $quiz = 'pending';
        } else {
            $quiz = 'none';
        }

        // Transcription: tracked in its own status field.
        $transcription = $sourcerecord->ai_transcription_status ?: 'none';
        if (!in_array($transcription, ['pending', 'done', 'error'])) {
            $transcription = 'none';
        }

        return [
            'summary' => $summary,
            'quiz' => $quiz,
            'transcription' => $transcription,
        ];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'summary' => new external_value(PARAM_ALPHA, 'Summary status: none, pending, done or error'),
            'quiz' => new external_value(PARAM_ALPHA, 'Quiz status: none, pending, done or error'),
            'transcription' => new external_value(PARAM_ALPHA, 'Transcription status: none, pending, done or error'),
        ]);
    }
}
