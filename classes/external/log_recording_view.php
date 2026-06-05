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

namespace mod_jitsi\external;

use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External API: log that the current user played or reached a milestone in a GCS recording.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class log_recording_view extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'jitsi_source_record id'),
            'cmid'           => new external_value(PARAM_INT, 'Course module id'),
            'milestone'      => new external_value(PARAM_INT, 'Percentage milestone: 0=play, 25, 50, 75, 100', VALUE_DEFAULT, 0),
        ]);
    }

    /**
     * Log that the current user played or reached a milestone in a GCS recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @param int $milestone 0=play start, 25/50/75/100=percentage reached
     * @return array
     */
    public static function execute($sourcerecordid, $cmid, $milestone = 0) {
        global $DB;

        if (!get_config('mod_jitsi', 'portal_license_key')) {
            return ['success' => true];
        }

        $params = self::validate_parameters(self::execute_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid'           => $cmid,
            'milestone'      => $milestone,
        ]);

        if (!in_array($params['milestone'], [0, 25, 50, 75, 100])) {
            return ['success' => false];
        }

        $context = \context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $exists = $DB->record_exists_sql(
            "SELECT 1 FROM {jitsi_source_record} sr
               JOIN {jitsi_record} r ON r.source = sr.id
               JOIN {jitsi} j ON j.id = r.jitsi
               JOIN {course_modules} cm ON cm.instance = j.id
              WHERE sr.id = :srid AND cm.id = :cmid",
            ['srid' => $params['sourcerecordid'], 'cmid' => $params['cmid']]
        );

        if (!$exists) {
            return ['success' => false];
        }

        $event = \mod_jitsi\event\recording_viewed::create([
            'context'  => $context,
            'objectid' => $params['sourcerecordid'],
            'other'    => ['milestone' => $params['milestone']],
        ]);
        $event->trigger();

        return ['success' => true];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the event was logged'),
        ]);
    }
}
