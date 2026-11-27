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
use core_external\external_multiple_structure;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External API: list the recordings of a Jitsi activity that the current user can see.
 *
 * Applies the same rules as the recordings tab: mod/jitsi:viewrecords is required, deleted
 * recordings are never listed and hidden recordings are only listed to users with
 * mod/jitsi:hide. Expired links are left out. AI summaries, transcriptions and account
 * credentials are never returned.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_recordings extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'cmid' => new external_value(PARAM_INT, 'Course module ID of the jitsi activity'),
        ]);
    }

    /**
     * List the recordings visible to the current user.
     *
     * @param int $cmid Course module id.
     * @return array
     */
    public static function execute($cmid) {
        global $DB;
        $params = self::validate_parameters(self::execute_parameters(), ['cmid' => $cmid]);

        $cm = get_coursemodule_from_id('jitsi', $params['cmid'], 0, false, MUST_EXIST);
        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);
        require_capability('mod/jitsi:viewrecords', $context);

        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

        // A session shared by invitation token shows the recordings of the master session.
        $jitsiid = (int) $jitsi->id;
        if (!empty($jitsi->sessionwithtoken) && trim((string) $jitsi->tokeninvitacion) !== '') {
            $masterid = $DB->get_field('jitsi', 'id', ['tokeninterno' => trim($jitsi->tokeninvitacion)]);
            if ($masterid) {
                $jitsiid = (int) $masterid;
            }
        }

        $sql = 'SELECT r.id, r.name, r.visible, s.link, s.timecreated, s.timeexpires, s.type
                  FROM {jitsi_record} r
                  JOIN {jitsi_source_record} s ON s.id = r.source
                 WHERE r.jitsi = :jitsiid
                   AND r.deleted = 0
                   AND (s.timeexpires = 0 OR s.timeexpires > :now)';
        $sqlparams = ['jitsiid' => $jitsiid, 'now' => time()];
        if (!has_capability('mod/jitsi:hide', $context)) {
            $sql .= ' AND r.visible = 1';
        }
        $sql .= ' ORDER BY r.id DESC';

        $result = [];
        foreach ($DB->get_records_sql($sql, $sqlparams) as $record) {
            $result[] = [
                'id' => (int) $record->id,
                'name' => format_string($record->name, true, ['context' => $context]),
                'url' => (string) $record->link,
                'timecreated' => (int) $record->timecreated,
                'timeexpires' => (int) $record->timeexpires,
                'type' => (int) $record->type,
                'visible' => (int) $record->visible,
            ];
        }
        return $result;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_multiple_structure
     */
    public static function execute_returns() {
        return new external_multiple_structure(
            new external_single_structure([
                'id' => new external_value(PARAM_INT, 'Recording id (jitsi_record.id)'),
                'name' => new external_value(PARAM_TEXT, 'Recording name'),
                'url' => new external_value(PARAM_RAW, 'YouTube video id (type 0) or external link (type 1)'),
                'timecreated' => new external_value(PARAM_INT, 'Creation time of the source (Unix)'),
                'timeexpires' => new external_value(PARAM_INT, 'Expiry time of the link (Unix), 0 if it never expires'),
                'type' => new external_value(PARAM_INT, 'Source type: 0 YouTube, 1 external link'),
                'visible' => new external_value(PARAM_INT, '1 visible, 0 hidden (only listed to users with mod/jitsi:hide)'),
            ])
        );
    }
}
