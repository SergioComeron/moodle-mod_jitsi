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
use mod_jitsi\local\recording_segments;

/**
 * External API: save and merge watched segments for a GCS recording.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class save_recording_segments extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'sourcerecordid'  => new external_value(PARAM_INT, 'jitsi_source_record id'),
            'cmid'            => new external_value(PARAM_INT, 'Course module id'),
            'segments'        => new external_value(PARAM_TEXT, 'JSON array of [start,end] pairs in seconds'),
            'duration'        => new external_value(PARAM_FLOAT, 'Video duration in seconds'),
            'session_segments' => new external_value(PARAM_TEXT, 'JSON segments from current play session', VALUE_DEFAULT, '[]'),
        ]);
    }

    /**
     * Save and merge watched segments for a GCS recording.
     *
     * @param int    $sourcerecordid
     * @param int    $cmid
     * @param string $segments JSON [[start,end],...]
     * @param float  $duration video duration in seconds
     * @param string $sessionsegments JSON segments from current play session
     * @return array
     */
    public static function execute($sourcerecordid, $cmid, $segments, $duration, $sessionsegments = '[]') {
        global $DB, $USER;

        if (!get_config('mod_jitsi', 'portal_license_key')) {
            return ['success' => true, 'segments' => '[]'];
        }

        $params = self::validate_parameters(self::execute_parameters(), [
            'sourcerecordid'  => $sourcerecordid,
            'cmid'            => $cmid,
            'segments'        => $segments,
            'duration'        => $duration,
            'session_segments' => $sessionsegments,
        ]);

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
            return ['success' => false, 'segments' => '[]'];
        }

        $newsegments = json_decode($params['segments'], true);
        if (!is_array($newsegments)) {
            return ['success' => false, 'segments' => '[]'];
        }

        $existing = $DB->get_record('jitsi_recording_segments', [
            'userid'         => $USER->id,
            'sourcerecordid' => $params['sourcerecordid'],
            'cmid'           => $params['cmid'],
        ]);

        $allsegs = $newsegments;
        if ($existing) {
            $stored = json_decode($existing->segments, true);
            if (is_array($stored)) {
                $allsegs = array_merge($stored, $newsegments);
            }
        }

        $merged     = recording_segments::merge($allsegs, (float)$params['duration']);
        $mergedjson = json_encode($merged);

        // Compute updated playcounts from session_segments.
        $newsessionsegs = json_decode($params['session_segments'], true);
        $duration       = (float)$params['duration'];
        $playcountsjson = null;
        if (is_array($newsessionsegs) && !empty($newsessionsegs) && $duration > 0) {
            $bucketsize  = 10;
            $numbuckets  = max(1, (int)ceil($duration / $bucketsize));
            $existingcounts = [];
            if ($existing && !empty($existing->playcounts)) {
                $existingcounts = json_decode($existing->playcounts, true) ?? [];
            }
            if (count($existingcounts) < $numbuckets) {
                $existingcounts = array_pad($existingcounts, $numbuckets, 0);
            }
            foreach ($newsessionsegs as $seg) {
                if (!is_array($seg) || count($seg) < 2) {
                    continue;
                }
                $startbucket = max(0, (int)floor((float)$seg[0] / $bucketsize));
                $endbucket   = min($numbuckets - 1, (int)floor((float)$seg[1] / $bucketsize));
                for ($b = $startbucket; $b <= $endbucket; $b++) {
                    $existingcounts[$b] = ($existingcounts[$b] ?? 0) + 1;
                }
            }
            $playcountsjson = json_encode(array_values($existingcounts));
        } else if ($existing && !empty($existing->playcounts)) {
            $playcountsjson = $existing->playcounts;
        }

        if ($existing) {
            $existing->segments     = $mergedjson;
            $existing->playcounts   = $playcountsjson;
            $existing->duration     = $duration;
            $existing->timemodified = time();
            $DB->update_record('jitsi_recording_segments', $existing);
        } else {
            $DB->insert_record('jitsi_recording_segments', (object)[
                'userid'         => $USER->id,
                'sourcerecordid' => $params['sourcerecordid'],
                'cmid'           => $params['cmid'],
                'segments'       => $mergedjson,
                'playcounts'     => $playcountsjson,
                'duration'       => $duration,
                'timecreated'    => time(),
                'timemodified'   => time(),
            ]);
        }

        return ['success' => true, 'segments' => $mergedjson];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success'  => new external_value(PARAM_BOOL, 'Whether segments were saved'),
            'segments' => new external_value(PARAM_TEXT, 'Merged segments as JSON'),
        ]);
    }
}
