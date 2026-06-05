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
 * Generic encoding helpers for mod_jitsi.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class util {
    /**
     * URL-safe base64 encode (uses -, _ and , instead of +, / and =).
     *
     * @param string $inputstr
     * @return string
     */
    public static function base64url_encode($inputstr) {
        return strtr(base64_encode($inputstr), '+/=', '-_,');
    }

    /**
     * Decode a URL-safe base64 string produced by base64url_encode().
     *
     * @param string $inputstr
     * @return string
     */
    public static function base64url_decode($inputstr) {
        return base64_decode(strtr($inputstr, '-_,', '+/='));
    }
}
