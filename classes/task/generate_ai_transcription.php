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
 * Ad-hoc task to generate a timestamped AI transcription for a GCS recording via Vertex AI (Gemini).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Ad-hoc task: call Vertex AI Gemini to transcribe a GCS recording with timestamps.
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
        global $CFG, $DB;

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

        // Only GCS recordings are supported.
        if (!preg_match('/^https:\/\/storage\.googleapis\.com\/([^\/]+)\/(.+)$/', $sourcerecord->link, $m)) {
            mtrace("generate_ai_transcription: recording is not a GCS URL: {$sourcerecord->link}");
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'error', ['id' => $sourcerecord->id]);
            return;
        }

        $bucketname = $m[1];
        $objectname = $m[2];
        $gsuri = "gs://{$bucketname}/{$objectname}";

        $server = $DB->get_record('jitsi_servers', ['gcs_bucket' => $bucketname, 'gcs_enabled' => 1]);
        $project = !empty($server->gcpproject) ? $server->gcpproject : '';
        if (empty($project)) {
            mtrace("generate_ai_transcription: could not determine GCP project for bucket {$bucketname}");
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'error', ['id' => $sourcerecord->id]);
            return;
        }

        // Load Google API autoloader.
        $autoloaders = [
            $CFG->dirroot . '/mod/jitsi/api/vendor/autoload.php',
            $CFG->dirroot . '/mod/jitsi/vendor/autoload.php',
            $CFG->dirroot . '/vendor/autoload.php',
        ];
        foreach ($autoloaders as $autoload) {
            if (file_exists($autoload)) {
                require_once($autoload);
                break;
            }
        }

        if (!class_exists('Google\\Client')) {
            mtrace('generate_ai_transcription: Google API client not available');
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'error', ['id' => $sourcerecord->id]);
            return;
        }

        try {
            $client = new \Google\Client();
            $client->addScope('https://www.googleapis.com/auth/cloud-platform');

            $fs = get_file_storage();
            $ctx = \context_system::instance();
            $files = $fs->get_area_files(
                $ctx->id,
                'mod_jitsi',
                'gcpserviceaccountjson',
                0,
                'itemid, filepath, filename',
                false
            );
            if (!empty($files)) {
                $file = reset($files);
                $key = json_decode($file->get_content(), true);
                if (is_array($key)) {
                    $client->setAuthConfig($key);
                } else {
                    $client->useApplicationDefaultCredentials();
                }
            } else {
                $client->useApplicationDefaultCredentials();
            }

            $accesstoken = $client->fetchAccessTokenWithAssertion();
            if (empty($accesstoken['access_token'])) {
                throw new \Exception('Could not obtain access token for Vertex AI');
            }

            $token = $accesstoken['access_token'];
            $location = get_config('mod_jitsi', 'vertexairegion') ?: 'us-central1';
            $model = 'gemini-2.5-flash';
            $endpoint = "https://{$location}-aiplatform.googleapis.com/v1/projects/{$project}"
                . "/locations/{$location}/publishers/google/models/{$model}:generateContent";

            $lang = !empty($data->lang) ? $data->lang : 'en';
            $prompt = "Please transcribe this video recording in full. "
                . "Format the transcription as follows:\n"
                . "- When the topic changes significantly, insert a chapter heading on its own line using the format: ### Chapter Title\n"
                . "- Each spoken line must start with a timestamp in [MM:SS] format "
                . "(or [HH:MM:SS] for recordings longer than one hour), followed by the spoken text.\n"
                . "Example:\n"
                . "### Introduction\n"
                . "[00:00] Welcome to today's class.\n"
                . "[00:15] Today we will cover...\n"
                . "### Exercise 1\n"
                . "[05:30] Let's start with the first exercise.\n"
                . "Include all spoken content. Use chapter headings only at natural topic boundaries. "
                . "Write everything (including chapter titles) in the following language: {$lang}.";

            $body = json_encode([
                'contents' => [
                    [
                        'role' => 'user',
                        'parts' => [
                            ['text' => $prompt],
                            [
                                'fileData' => [
                                    'mimeType' => 'video/mp4',
                                    'fileUri' => $gsuri,
                                ],
                            ],
                        ],
                    ],
                ],
                'generationConfig' => [
                    'temperature' => 0.0,
                    'maxOutputTokens' => 8192,
                ],
            ]);

            $ch = curl_init($endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Authorization: Bearer ' . $token,
                'Content-Type: application/json',
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 600);
            $response = curl_exec($ch);
            $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpcode !== 200) {
                throw new \Exception("Vertex AI returned HTTP {$httpcode}: {$response}");
            }

            $result = json_decode($response, true);
            $transcription = $result['candidates'][0]['content']['parts'][0]['text'] ?? null;

            if (empty($transcription)) {
                throw new \Exception('Empty response from Vertex AI: ' . $response);
            }

            $DB->set_field('jitsi_source_record', 'ai_transcription', $transcription, ['id' => $sourcerecord->id]);
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'done', ['id' => $sourcerecord->id]);
            mtrace("generate_ai_transcription: transcription saved for source record {$sourcerecord->id}");
        } catch (\Throwable $e) {
            mtrace("generate_ai_transcription: ERROR: " . $e->getMessage());
            $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'error', ['id' => $sourcerecord->id]);
        }
    }
}
