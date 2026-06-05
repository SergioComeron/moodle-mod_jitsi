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
 * Helpers for building and sanitising Jitsi room names.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class room {
    /**
     * Sanitise a string for use in a room name: strip punctuation/tags and turn
     * whitespace into hyphens.
     *
     * @param string $string Input string
     * @param bool $forcelowercase Lowercase the result
     * @param bool $anal Strip every non-alphanumeric character
     * @return string
     */
    public static function sanitize($string, $forcelowercase = true, $anal = false) {
        $strip = ['~', chr(96), '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
                '_', '=', '+', '[', '{', ']', '}', '\\', '|', ';', ':', '"',
                "'", '&#8216;', '&#8217;', '&#8220;', '&#8221;', '&#8211;', '&#8212;',
                'â€"', 'â€"', ',', '<', '.', '>', '/', '?',
            ];
        $clean = trim(str_replace($strip, "", strip_tags($string)));
        $clean = preg_replace('/\s+/', "-", $clean);
        $clean = ($anal) ? preg_replace("/[^a-zA-Z0-9]/", "", $clean) : $clean;
        return ($forcelowercase) ?
            (function_exists('mb_strtolower')) ?
                mb_strtolower($clean, 'UTF-8') :
                strtolower($clean) :
            $clean;
    }

    /**
     * Build the Jitsi room name for a given activity using the same algorithm as view.php.
     *
     * Extracted here so that servermanagement.php callbacks and view.php always use
     * identical logic and cannot diverge.
     *
     * @param string $shortname Course shortname
     * @param int $jitsiid Jitsi activity ID
     * @param string $jitsiname Jitsi activity name
     * @param string|false $sesionname Comma-separated field indices (0=shortname,1=id,2=name).
     *                                 Defaults to '0,1,2' when empty/false.
     * @param int|string|false $separator Index into ['.', '-', '_', '']. Defaults to 0 ('.').
     * @return string The room name
     */
    public static function build_name($shortname, $jitsiid, $jitsiname, $sesionname = false, $separator = false) {
        $separatormap = ['.', '-', '_', ''];
        if ($sesionname === false || $sesionname === '' || $sesionname === null) {
            $sesionname = '0,1,2';
        }
        $separatorindex = ($separator === false || $separator === '' || $separator === null) ? 0 : (int)$separator;
        $sep = $separatormap[$separatorindex] ?? '';
        $allowed = explode(',', $sesionname);
        $max = count($allowed);
        $sesparam = '';
        for ($i = 0; $i < $max; $i++) {
            $part = '';
            if ($allowed[$i] == 0) {
                $part = self::sanitize($shortname);
            } else if ($allowed[$i] == 1) {
                $part = (string)$jitsiid;
            } else if ($allowed[$i] == 2) {
                $part = self::sanitize($jitsiname);
            }
            $sesparam .= $part;
            if ($i < $max - 1) {
                $sesparam .= $sep;
            }
        }
        return $sesparam;
    }

    /**
     * Normalise a session name to only alphanumeric, hyphen and underscore characters.
     *
     * @param string $session Input session name
     * @return string
     */
    public static function normalize_session_name($session) {
        $normalized = preg_replace('/[^a-zA-Z0-9\-_]/', '', $session);
        return $normalized;
    }
}
