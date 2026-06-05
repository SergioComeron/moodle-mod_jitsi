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
 * Helpers for the GCP Jibri recording VM pool.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class jibri {
    /**
     * Returns true if the given GCP server has at least one Jibri VM ready in the pool,
     * or falls back to the legacy jibri_provisioningstatus field for servers not yet
     * migrated to the pool.
     *
     * @param \stdClass $server Server record (needs id, jibri_enabled, jibri_provisioningstatus)
     * @return bool
     */
    public static function is_ready(\stdClass $server): bool {
        global $DB;
        if (empty($server->jibri_enabled)) {
            return false;
        }
        // Check pool table first.
        if (
            $DB->record_exists_select(
                'jitsi_jibri_pool',
                "serverid = ? AND status IN ('idle', 'recording', 'streaming')",
                [$server->id]
            )
        ) {
            return true;
        }
        // If the server already has pool entries (even provisioning), don't fall back to legacy field.
        if ($DB->record_exists('jitsi_jibri_pool', ['serverid' => $server->id])) {
            return false;
        }
        // Fallback: legacy field (servers not yet migrated to pool).
        return ($server->jibri_provisioningstatus ?? '') === 'ready';
    }
}
