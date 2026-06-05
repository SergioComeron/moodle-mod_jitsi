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
 * External API: list users who watched a specific 10-second bucket of a recording.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class get_bucket_viewers extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'jitsi_source_record id'),
            'cmid'           => new external_value(PARAM_INT, 'Course module id'),
            'bucketindex'    => new external_value(PARAM_INT, 'Zero-based bucket index (10s buckets)'),
        ]);
    }

    /**
     * Get the list of users who watched a specific 10-second bucket of a recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @param int $bucketindex
     * @return array
     */
    public static function execute($sourcerecordid, $cmid, $bucketindex) {
        global $DB;

        $params = self::validate_parameters(self::execute_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid'           => $cmid,
            'bucketindex'    => $bucketindex,
        ]);

        $context = \context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:viewattendance', $context);

        $bucketsize  = 10;
        $bucketstart = $params['bucketindex'] * $bucketsize;
        $bucketend   = $bucketstart + $bucketsize;

        $rows = $DB->get_records('jitsi_recording_segments', [
            'sourcerecordid' => $params['sourcerecordid'],
            'cmid'           => $params['cmid'],
        ]);

        $viewers = [];
        foreach ($rows as $row) {
            $segments = json_decode($row->segments, true);
            if (!is_array($segments)) {
                continue;
            }
            foreach ($segments as $seg) {
                if (!is_array($seg) || count($seg) < 2) {
                    continue;
                }
                if ((float)$seg[0] < $bucketend && (float)$seg[1] > $bucketstart) {
                    $namefields = 'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename';
                    $user = $DB->get_record('user', ['id' => $row->userid], $namefields);
                    if ($user) {
                        $viewers[] = ['userid' => (int)$user->id, 'fullname' => fullname($user)];
                    }
                    break;
                }
            }
        }

        usort($viewers, fn($a, $b) => strcmp($a['fullname'], $b['fullname']));

        return ['viewers' => $viewers, 'bucketstart' => $bucketstart, 'bucketend' => $bucketend];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'viewers'     => new external_multiple_structure(
                new external_single_structure([
                    'userid'   => new external_value(PARAM_INT, 'User id'),
                    'fullname' => new external_value(PARAM_TEXT, 'User full name'),
                ])
            ),
            'bucketstart' => new external_value(PARAM_INT, 'Bucket start in seconds'),
            'bucketend'   => new external_value(PARAM_INT, 'Bucket end in seconds'),
        ]);
    }
}
