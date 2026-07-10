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

namespace mod_jitsi\local;

/**
 * Shared Vertex AI (Gemini) helper for the AI recording features.
 *
 * Centralises which recordings support AI processing, how their link is
 * turned into a Vertex AI fileUri, which GCP project to bill against and
 * the generateContent REST call itself.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class vertex_ai {
    /** @var string Regex matching a GCS public URL, capturing bucket and object. */
    const GCS_PATTERN = '/^https:\/\/storage\.googleapis\.com\/([^\/]+)\/(.+)$/';

    /** @var string Gemini model used for all AI features. */
    const MODEL = 'gemini-2.5-flash';

    /**
     * Whether a source record can be processed by Vertex AI.
     *
     * Supported: GCS recordings (any type) and external link recordings
     * (type 1) with a non-expired https URL. Vertex AI fetches the media
     * itself, so the URL must be publicly reachable.
     *
     * @param \stdClass $sourcerecord jitsi_source_record row
     * @return bool
     */
    public static function supports(\stdClass $sourcerecord): bool {
        $link = (string)($sourcerecord->link ?? '');
        if (preg_match(self::GCS_PATTERN, $link)) {
            return true;
        }
        if ((int)($sourcerecord->type ?? 0) !== 1) {
            return false;
        }
        if (strpos($link, 'https://') !== 0) {
            return false;
        }
        $expires = (int)($sourcerecord->timeexpires ?? 0);
        if ($expires > 0 && $expires <= time()) {
            return false;
        }
        return true;
    }

    /**
     * Build the Vertex AI fileData part for a source record.
     *
     * @param \stdClass $sourcerecord jitsi_source_record row
     * @return array|null ['fileuri' => string, 'mimetype' => string] or null when unsupported
     */
    public static function media_for(\stdClass $sourcerecord): ?array {
        if (!self::supports($sourcerecord)) {
            return null;
        }
        $link = $sourcerecord->link;
        if (preg_match(self::GCS_PATTERN, $link, $m)) {
            return ['fileuri' => "gs://{$m[1]}/{$m[2]}", 'mimetype' => 'video/mp4'];
        }
        // Dropbox share links serve an HTML page; the dl host serves the raw file.
        $fileuri = str_replace('https://www.dropbox.com/', 'https://dl.dropboxusercontent.com/', $link);
        return ['fileuri' => $fileuri, 'mimetype' => self::guess_mimetype($fileuri)];
    }

    /**
     * Guess the media MIME type from a URL's file extension.
     *
     * @param string $url Media URL
     * @return string MIME type (defaults to video/mp4)
     */
    public static function guess_mimetype(string $url): string {
        $path = parse_url($url, PHP_URL_PATH) ?: '';
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        $map = [
            'mp4'  => 'video/mp4',
            'm4v'  => 'video/mp4',
            'webm' => 'video/webm',
            'mov'  => 'video/quicktime',
            'avi'  => 'video/x-msvideo',
            'mkv'  => 'video/x-matroska',
            'mpg'  => 'video/mpeg',
            'mpeg' => 'video/mpeg',
            'wmv'  => 'video/x-ms-wmv',
            '3gp'  => 'video/3gpp',
            'mp3'  => 'audio/mpeg',
            'm4a'  => 'audio/mp4',
            'wav'  => 'audio/wav',
            'ogg'  => 'audio/ogg',
        ];
        return $map[$ext] ?? 'video/mp4';
    }

    /**
     * Resolve the GCP project to run Vertex AI requests against.
     *
     * GCS recordings use the owning server's project when available; anything
     * else falls back to the global gcp_project setting and finally to any
     * server with a project configured.
     *
     * @param \stdClass $sourcerecord jitsi_source_record row
     * @return string Project id, or '' when none can be determined
     */
    public static function project_for(\stdClass $sourcerecord): string {
        global $DB;
        if (preg_match(self::GCS_PATTERN, (string)($sourcerecord->link ?? ''), $m)) {
            $server = $DB->get_record('jitsi_servers', ['gcs_bucket' => $m[1], 'gcs_enabled' => 1]);
            if (!empty($server->gcpproject)) {
                return $server->gcpproject;
            }
        }
        $project = trim((string)get_config('mod_jitsi', 'gcp_project'));
        if ($project !== '') {
            return $project;
        }
        $servers = $DB->get_records_select(
            'jitsi_servers',
            $DB->sql_isnotempty('jitsi_servers', 'gcpproject', true, false),
            null,
            'id',
            '*',
            0,
            1
        );
        $server = reset($servers);
        return !empty($server->gcpproject) ? $server->gcpproject : '';
    }

    /**
     * Call Vertex AI generateContent with a prompt and a media file and return the text.
     *
     * @param string $project GCP project id
     * @param array $media ['fileuri' => string, 'mimetype' => string] as returned by media_for()
     * @param string $prompt Text prompt sent alongside the media
     * @param array $generationconfig generationConfig payload (temperature, maxOutputTokens, ...)
     * @param int $timeout Request timeout in seconds
     * @return string Generated text
     * @throws \Exception on any auth, transport or response error
     */
    public static function generate_text(
        string $project,
        array $media,
        string $prompt,
        array $generationconfig,
        int $timeout = 300
    ): string {
        global $CFG;

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
            throw new \Exception('Google API client not available');
        }

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

        $location = get_config('mod_jitsi', 'vertexairegion') ?: 'europe-west1';
        $endpoint = "https://{$location}-aiplatform.googleapis.com/v1/projects/{$project}"
            . "/locations/{$location}/publishers/google/models/" . self::MODEL . ':generateContent';

        $body = json_encode([
            'contents' => [
                [
                    'role' => 'user',
                    'parts' => [
                        ['text' => $prompt],
                        [
                            'fileData' => [
                                'mimeType' => $media['mimetype'],
                                'fileUri' => $media['fileuri'],
                            ],
                        ],
                    ],
                ],
            ],
            'generationConfig' => $generationconfig,
        ]);

        $ch = curl_init($endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $accesstoken['access_token'],
            'Content-Type: application/json',
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        $response = curl_exec($ch);
        $curlerror = curl_error($ch);
        $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $httpcode === 0) {
            throw new \Exception("Curl error: {$curlerror}");
        }
        if ($httpcode !== 200) {
            throw new \Exception("Vertex AI returned HTTP {$httpcode}: {$response}");
        }

        $result = json_decode($response, true);
        $text = $result['candidates'][0]['content']['parts'][0]['text'] ?? null;
        if (empty($text)) {
            throw new \Exception('Empty response from Vertex AI: ' . $response);
        }
        return $text;
    }
}
