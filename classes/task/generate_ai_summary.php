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

/**
 * Ad-hoc task to generate an AI summary for a recording via Vertex AI (Gemini).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

use mod_jitsi\local\vertex_ai;

/**
 * Ad-hoc task: call Vertex AI Gemini to summarise a recording.
 *
 * Custom data expected:
 *   - sourcerecordid (int): ID of the jitsi_source_record row
 *
 * @package mod_jitsi
 */
class generate_ai_summary extends \core\task\adhoc_task {
    /**
     * Returns the component that owns this task.
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Execute the task: call Vertex AI Gemini and store the summary.
     */
    public function execute(): void {
        global $DB;

        $data = $this->get_custom_data();
        if (empty($data->sourcerecordid)) {
            mtrace('generate_ai_summary: missing sourcerecordid in custom data');
            return;
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => (int)$data->sourcerecordid]);
        if (!$sourcerecord) {
            mtrace("generate_ai_summary: source record {$data->sourcerecordid} not found");
            return;
        }

        if (!vertex_ai::supports($sourcerecord)) {
            mtrace("generate_ai_summary: recording not supported for AI: {$sourcerecord->link}");
            $DB->set_field(
                'jitsi_source_record',
                'ai_summary',
                get_string('aisummarynotavailable', 'jitsi'),
                ['id' => $sourcerecord->id]
            );
            return;
        }

        try {
            $lang = !empty($data->lang) ? $data->lang : current_language();
            $prompt = "You are an educational assistant. Please provide a concise summary (3-5 paragraphs) "
                . "of the following video recording from an online class. "
                . "Identify the main topics covered, key concepts explained, and any important conclusions. "
                . "Focus on educational content. "
                . "Write your response in the following language: {$lang}.";

            $summary = vertex_ai::generate_for_record($sourcerecord, $prompt, [
                'temperature' => 0.2,
                'maxOutputTokens' => 1024,
            ], 300);

            $DB->set_field('jitsi_source_record', 'ai_summary', $summary, ['id' => $sourcerecord->id]);
            mtrace("generate_ai_summary: summary saved for source record {$sourcerecord->id}");
        } catch (\Throwable $e) {
            mtrace("generate_ai_summary: ERROR: " . $e->getMessage());
            $DB->set_field(
                'jitsi_source_record',
                'ai_summary',
                get_string('aisummaryerror', 'jitsi'),
                ['id' => $sourcerecord->id]
            );
        }
    }
}
