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

use core_external\external_api;

/**
 * Shared access checks for the session web services called from the Jitsi page.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class external_access {
    /**
     * Check that the course module belongs to the activity and that the current user can view it.
     *
     * @param int $jitsiid Jitsi activity id
     * @param int $cmid Course module id
     * @return array [$jitsi, $cm, $course, $context]
     */
    public static function validate_activity(int $jitsiid, int $cmid): array {
        global $DB;

        $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST);
        if ((int)$cm->instance !== $jitsiid) {
            throw new \invalid_parameter_exception('The course module does not belong to the Jitsi activity');
        }
        $context = \context_module::instance($cm->id);
        external_api::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $jitsi = $DB->get_record('jitsi', ['id' => $jitsiid], '*', MUST_EXIST);
        $course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
        return [$jitsi, $cm, $course, $context];
    }
}
