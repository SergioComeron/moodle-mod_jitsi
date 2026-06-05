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
 * Helpers for Jitsi invitation links: expiry and validation code.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class invitation {
    /**
     * Whether an activity's invitation link has expired.
     *
     * @param \stdClass $jitsi Jitsi activity record (needs validitytime)
     * @return bool
     */
    public static function is_timed_out($jitsi) {
        if (time() > $jitsi->validitytime) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Human-readable message explaining why an invitation link is unavailable.
     *
     * @param \stdClass $jitsi Jitsi activity record (needs validitytime)
     * @return string
     */
    public static function error_time($jitsi) {
        global $CFG;
        if ($jitsi->validitytime == 0 || get_config('mod_jitsi', 'invitebuttons') == 0) {
            return get_string('invitationsnotactivated', 'jitsi');
        } else {
            return get_string('linkexpiredon', 'jitsi', userdate($jitsi->validitytime));
        }
    }

    /**
     * Whether the given code matches the activity's expected invitation code.
     *
     * @param int $code Code supplied by the visitor
     * @param \stdClass $jitsi Jitsi activity record
     * @return bool
     */
    public static function is_original($code, $jitsi) {
        if ($code == ($jitsi->timecreated + $jitsi->id)) {
            $original = true;
        } else {
            $original = false;
        }
        return $original;
    }

    /**
     * Generate the invitation validation code for an activity.
     *
     * @param \stdClass $jitsi Jitsi activity record
     * @return int
     */
    public static function generate_code($jitsi) {
        return $jitsi->timecreated + $jitsi->id;
    }
}
