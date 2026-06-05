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
 * Helper for live participant presence accounting.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class presence {
    /**
     * Count active participants from the presence table.
     *
     * @param int $jitsiid Jitsi session id.
     * @return array With keys moodle, guests, total.
     */
    public static function count($jitsiid) {
        global $DB;
        $threshold = time() - 90;
        $moodle = (int)$DB->count_records_select(
            'jitsi_presence',
            'jitsiid = :jitsiid AND userid > 0 AND timemodified > :threshold',
            ['jitsiid' => $jitsiid, 'threshold' => $threshold]
        );
        $guests = (int)$DB->count_records_select(
            'jitsi_presence',
            'jitsiid = :jitsiid AND userid = 0 AND timemodified > :threshold',
            ['jitsiid' => $jitsiid, 'threshold' => $threshold]
        );
        return ['moodle' => $moodle, 'guests' => $guests, 'total' => $moodle + $guests];
    }
}
