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
 * Helper for watched recording segment accounting.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class recording_segments {
    /**
     * Format a number of seconds as a compact human-readable duration (e.g. "1h 5min 3s").
     *
     * @param int $seconds
     * @return string
     */
    public static function format_seconds(int $seconds): string {
        if ($seconds < 60) {
            return $seconds . 's';
        }
        $h   = intdiv($seconds, 3600);
        $m   = intdiv($seconds % 3600, 60);
        $s   = $seconds % 60;
        $out = '';
        if ($h > 0) {
            $out .= $h . 'h ';
        }
        if ($m > 0 || $h > 0) {
            $out .= $m . 'min';
            if ($s > 0) {
                $out .= ' ' . $s . 's';
            }
        } else {
            $out .= $s . 's';
        }
        return trim($out);
    }

    /**
     * Compute the watched percentage (0-100) covered by a set of [start,end] segments.
     *
     * @param array $segments
     * @param float $duration
     * @return int
     */
    public static function watched_pct(array $segments, float $duration): int {
        if ($duration <= 0 || empty($segments)) {
            return 0;
        }
        $watched = 0;
        foreach ($segments as $seg) {
            if (is_array($seg) && count($seg) >= 2) {
                $watched += max(0, (float)$seg[1] - (float)$seg[0]);
            }
        }
        return min(100, (int)round(($watched / $duration) * 100));
    }

    /**
     * Merge and clamp an array of [start,end] segments.
     *
     * @param array $segments
     * @param float $duration
     * @return array
     */
    public static function merge(array $segments, float $duration): array {
        $segments = array_values(array_filter($segments, function ($s) use ($duration) {
            return is_array($s) && count($s) === 2
                && is_numeric($s[0]) && is_numeric($s[1])
                && $s[1] > $s[0] && $s[0] >= 0
                && ($duration <= 0 || $s[1] <= $duration + 2);
        }));
        if (empty($segments)) {
            return [];
        }
        usort($segments, fn($a, $b) => $a[0] <=> $b[0]);
        $merged = [[(float)$segments[0][0], (float)$segments[0][1]]];
        for ($i = 1; $i < count($segments); $i++) {
            $last = &$merged[count($merged) - 1];
            $s0 = (float)$segments[$i][0];
            $s1 = (float)$segments[$i][1];
            if ($s0 <= $last[1]) {
                $last[1] = max($last[1], $s1);
            } else {
                $merged[] = [$s0, $s1];
            }
        }
        return $merged;
    }
}
