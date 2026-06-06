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

namespace mod_jitsi\output;

/**
 * A single user's watched-segments bar for a recording.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class segments_bar {
    /**
     * Build the Mustache context: each watched segment as a left/width percentage.
     *
     * @param array $segments Array of [start, end] pairs in seconds
     * @param float $duration Video duration in seconds
     * @param string $barid Optional id attribute for the bar
     * @return array Template context
     */
    public static function context(array $segments, float $duration, string $barid = ''): array {
        $bars = [];
        if ($duration > 0) {
            foreach ($segments as $seg) {
                if (!is_array($seg) || count($seg) < 2) {
                    continue;
                }
                $left  = max(0, min(100, ($seg[0] / $duration) * 100));
                $width = max(0, min(100 - $left, (($seg[1] - $seg[0]) / $duration) * 100));
                $bars[] = [
                    'left'  => number_format($left, 2, '.', ''),
                    'width' => number_format($width, 2, '.', ''),
                ];
            }
        }
        return [
            'barid'    => $barid,
            'segments' => $bars,
        ];
    }

    /**
     * Render the watched-segments bar.
     *
     * @param array $segments Array of [start, end] pairs in seconds
     * @param float $duration Video duration in seconds
     * @param string $barid Optional id attribute for the bar
     * @return string
     */
    public static function render(array $segments, float $duration, string $barid = ''): string {
        global $OUTPUT;
        return $OUTPUT->render_from_template('mod_jitsi/segments_bar', self::context($segments, $duration, $barid));
    }
}
