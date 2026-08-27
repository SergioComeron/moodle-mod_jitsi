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
 * OpenAI-compatible BYOK client used only for session minutes.
 *
 * The API key is never written to logs. Callers must not pass recordings.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class acta_llm {
    /** @var string Default OpenAI-compatible base URL. */
    public const DEFAULT_ENDPOINT = 'https://api.openai.com/v1';

    /** @var string Default chat model. */
    public const DEFAULT_MODEL = 'gpt-4o-mini';

    /**
     * Normalise a configured endpoint to a chat/completions URL.
     *
     * @param string $endpoint Site or activity configured base or full URL
     * @return string
     */
    public static function completions_url(string $endpoint): string {
        $endpoint = trim($endpoint);
        if ($endpoint === '') {
            $endpoint = self::DEFAULT_ENDPOINT;
        }
        $endpoint = rtrim($endpoint, '/');
        if (substr($endpoint, -17) === '/chat/completions') {
            return $endpoint;
        }
        return $endpoint . '/chat/completions';
    }

    /**
     * Call an OpenAI-compatible chat completion and return the assistant text.
     *
     * @param string $apikey Bearer token (never logged)
     * @param string $endpoint Base URL or full chat/completions URL
     * @param string $model Model name
     * @param string $systemprompt System message
     * @param string $userprompt User message
     * @param int $timeout Seconds
     * @return string Assistant content
     * @throws \moodle_exception on transport or response errors
     */
    public static function complete(
        string $apikey,
        string $endpoint,
        string $model,
        string $systemprompt,
        string $userprompt,
        int $timeout = 60
    ): string {
        $url = self::completions_url($endpoint);
        $payload = json_encode([
            'model' => $model !== '' ? $model : self::DEFAULT_MODEL,
            'temperature' => 0.2,
            'messages' => [
                ['role' => 'system', 'content' => $systemprompt],
                ['role' => 'user', 'content' => $userprompt],
            ],
        ]);

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $apikey,
                'Content-Type: application/json',
            ],
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => 15,
        ]);
        $response = curl_exec($ch);
        $httpcode = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $httpcode === 0) {
            throw new \moodle_exception('actallmtransport', 'jitsi');
        }
        if ($httpcode < 200 || $httpcode >= 300) {
            throw new \moodle_exception('actallmhttp', 'jitsi', '', $httpcode);
        }

        $decoded = json_decode($response, true);
        $text = $decoded['choices'][0]['message']['content'] ?? '';
        if (!is_string($text) || trim($text) === '') {
            throw new \moodle_exception('actallmempty', 'jitsi');
        }
        return $text;
    }

    /**
     * Parse a JSON object from an LLM reply, stripping optional markdown fences.
     *
     * @param string $text Raw assistant content
     * @return array Decoded object as an associative array
     * @throws \moodle_exception when the reply is not a JSON object
     */
    public static function parse_json_object(string $text): array {
        $text = trim($text);
        if (preg_match('/^```(?:json)?\s*(.*)\s*```$/s', $text, $matches)) {
            $text = trim($matches[1]);
        }
        $decoded = json_decode($text, true);
        if (!is_array($decoded) || array_is_list($decoded)) {
            throw new \moodle_exception('actallmjson', 'jitsi');
        }
        return $decoded;
    }
}
