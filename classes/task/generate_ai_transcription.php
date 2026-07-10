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
 * Ad-hoc task to generate a timestamped AI transcription for a recording via Vertex AI (Gemini).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

use mod_jitsi\local\vertex_ai;

/**
 * Ad-hoc task: call Vertex AI Gemini to transcribe a recording with timestamps.
 *
 * Custom data expected:
 *   - sourcerecordid (int): ID of the jitsi_source_record row
 *   - lang (string): language code for the transcription
 *
 * @package mod_jitsi
 */
class generate_ai_transcription extends \core\task\adhoc_task {
    /**
     * Returns the component that owns this task.
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Execute the task: call Vertex AI Gemini and store the timestamped transcription.
     */
    public function execute(): void {
        global $DB;

        $data = $this->get_custom_data();
        if (empty($data->sourcerecordid)) {
            mtrace('generate_ai_transcription: missing sourcerecordid in custom data');
            return;
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => (int)$data->sourcerecordid]);
        if (!$sourcerecord) {
            mtrace("generate_ai_transcription: source record {$data->sourcerecordid} not found");
            return;
        }

        if (!vertex_ai::supports($sourcerecord)) {
            mtrace("generate_ai_transcription: recording not supported for AI: {$sourcerecord->link}");
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'error', ['id' => $sourcerecord->id]);
            return;
        }

        try {
            $lang = !empty($data->lang) ? $data->lang : 'en';
            $prompt = "Please transcribe this video recording in full. "
                . "Format the transcription as follows:\n"
                . "- When the topic changes significantly, insert a chapter heading on its own line using the format: ### Chapter Title\n" // phpcs:ignore moodle.Files.LineLength.MaxExceeded
                . "- Each spoken line must start with a timestamp in [MM:SS] format "
                . "(or [HH:MM:SS] for recordings longer than one hour), followed by the spoken text.\n"
                . "Example:\n"
                . "### Introduction\n"
                . "[00:00] Welcome to today's class.\n"
                . "[00:15] Today we will cover...\n"
                . "### Exercise 1\n"
                . "[05:30] Let's start with the first exercise.\n"
                . "Include all spoken content. Use chapter headings only at natural topic boundaries. "
                . "Transcribe ONLY speech that actually occurs in the recording; never invent dialogue. "
                . "If there is no discernible speech, output exactly one line with the timestamp [00:00] "
                . "and a brief note (in the requested language) that the recording contains no speech. "
                . "Write everything (including chapter titles) in the following language: {$lang}.";

            $transcription = vertex_ai::generate_for_record($sourcerecord, $prompt, [
                'temperature' => 0.0,
                'maxOutputTokens' => 8192,
            ], 600);

            $DB->set_field('jitsi_source_record', 'ai_transcription', $transcription, ['id' => $sourcerecord->id]);
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'done', ['id' => $sourcerecord->id]);
            mtrace("generate_ai_transcription: transcription saved for source record {$sourcerecord->id}");
        } catch (\Throwable $e) {
            mtrace("generate_ai_transcription: ERROR: " . $e->getMessage());
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'error', ['id' => $sourcerecord->id]);
        }
    }
}
