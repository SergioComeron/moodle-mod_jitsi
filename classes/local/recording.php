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
 * Helpers for Jitsi recording lifecycle.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class recording {
    /**
     * Whether a source record can be deleted, i.e. no active (non-deleted)
     * jitsi_record still points at it.
     *
     * @param int $sourcerecordid jitsi_source_record id
     * @return bool
     */
    public static function is_deletable($sourcerecordid) {
        global $DB;
        $records = $DB->get_records('jitsi_record', ['source' => $sourcerecordid, 'deleted' => 0]);
        return empty($records);
    }
}
