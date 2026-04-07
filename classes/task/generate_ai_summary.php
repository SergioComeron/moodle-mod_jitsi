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
 * Ad-hoc task to generate an AI summary for a GCS recording via Vertex AI (Gemini).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Ad-hoc task: call Vertex AI Gemini to summarise a GCS recording.
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
        global $CFG, $DB;

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

        // Only GCS recordings (https://storage.googleapis.com/...) are supported.
        if (!preg_match('/^https:\/\/storage\.googleapis\.com\/([^\/]+)\/(.+)$/', $sourcerecord->link, $m)) {
            mtrace("generate_ai_summary: recording is not a GCS URL: {$sourcerecord->link}");
            $DB->set_field(
                'jitsi_source_record',
                'ai_summary',
                get_string('aisummarynotavailable', 'jitsi'),
                ['id' => $sourcerecord->id]
            );
            return;
        }

        $bucketname = $m[1];
        $objectname = $m[2];
        $gsuri = "gs://{$bucketname}/{$objectname}";

        // Determine which GCP project to use for Vertex AI.
        $server = $DB->get_record('jitsi_servers', ['gcs_bucket' => $bucketname, 'gcs_enabled' => 1]);
        $project = !empty($server->gcpproject) ? $server->gcpproject : '';
        if (empty($project)) {
            mtrace("generate_ai_summary: could not determine GCP project for bucket {$bucketname}");
            $DB->set_field(
                'jitsi_source_record',
                'ai_summary',
                get_string('aisummaryerror', 'jitsi'),
                ['id' => $sourcerecord->id]
            );
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
            mtrace('generate_ai_summary: Google API client not available');
            $DB->set_field(
                'jitsi_source_record',
                'ai_summary',
                get_string('aisummaryerror', 'jitsi'),
                ['id' => $sourcerecord->id]
            );
            return;
        }

        try {
            $client = new \Google\Client();
            $client->addScope('https://www.googleapis.com/auth/cloud-platform');

            // Use service account JSON from Moodle file storage if available.
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
            $location = 'us-central1';
            $model = 'gemini-2.5-flash';
            $endpoint = "https://{$location}-aiplatform.googleapis.com/v1/projects/{$project}"
                . "/locations/{$location}/publishers/google/models/{$model}:generateContent";

            // Use HTTPS URL (public GCS) so Vertex AI can access without SA permissions on the bucket.
            $httpsurl = "https://storage.googleapis.com/{$bucketname}/{$objectname}";

            $prompt = "You are an educational assistant. Please provide a concise summary (3-5 paragraphs) "
                . "of the following video recording from an online class. "
                . "Identify the main topics covered, key concepts explained, and any important conclusions. "
                . "Focus on educational content.";

            $body = json_encode([
                'contents' => [
                    [
                        'role' => 'user',
                        'parts' => [
                            ['text' => $prompt],
                            [
                                'fileData' => [
                                    'mimeType' => 'video/mp4',
                                    'fileUri' => $httpsurl,
                                ],
                            ],
                        ],
                    ],
                ],
                'generationConfig' => [
                    'temperature' => 0.2,
                    'maxOutputTokens' => 1024,
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
            curl_setopt($ch, CURLOPT_TIMEOUT, 120);
            $response = curl_exec($ch);
            $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpcode !== 200) {
                throw new \Exception("Vertex AI returned HTTP {$httpcode}: {$response}");
            }

            $result = json_decode($response, true);
            $summary = $result['candidates'][0]['content']['parts'][0]['text'] ?? null;

            if (empty($summary)) {
                throw new \Exception('Empty response from Vertex AI: ' . $response);
            }

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
