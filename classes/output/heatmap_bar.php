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

namespace mod_jitsi\output;

use mod_jitsi\local\recording_segments;

/**
 * Aggregate viewing heatmap for a GCS recording (unique viewers + total plays bars).
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class heatmap_bar {
    /** @var int Bucket size in seconds. */
    const BUCKET_SIZE = 10;

    /**
     * Build the Mustache context for the heatmap, or null when there is nothing to show.
     *
     * All the query/aggregation logic lives here; the template only paints the result.
     *
     * @param int $sourcerecordid jitsi_source_record id
     * @param int $cmid Course module id
     * @return array|null Template context, or null if there is no data
     */
    public static function context(int $sourcerecordid, int $cmid): ?array {
        global $DB;

        $rows = $DB->get_records('jitsi_recording_segments', [
            'sourcerecordid' => $sourcerecordid,
            'cmid'           => $cmid,
        ]);
        if (empty($rows)) {
            return null;
        }

        $duration = 0.0;
        foreach ($rows as $row) {
            if ((float)$row->duration > $duration) {
                $duration = (float)$row->duration;
            }
        }
        if ($duration <= 0) {
            return null;
        }

        $totalviewers = count($rows);
        $bucketsize   = self::BUCKET_SIZE;
        $numbuckets   = max(1, (int)ceil($duration / $bucketsize));
        $buckets      = array_fill(0, $numbuckets, 0);

        foreach ($rows as $row) {
            $segments = json_decode($row->segments, true);
            if (!is_array($segments)) {
                continue;
            }
            $covered = array_fill(0, $numbuckets, false);
            foreach ($segments as $seg) {
                if (!is_array($seg) || count($seg) < 2) {
                    continue;
                }
                $startbucket = max(0, (int)floor((float)$seg[0] / $bucketsize));
                $endbucket   = min($numbuckets - 1, (int)floor((float)$seg[1] / $bucketsize));
                for ($b = $startbucket; $b <= $endbucket; $b++) {
                    $covered[$b] = true;
                }
            }
            foreach ($covered as $b => $iscovered) {
                if ($iscovered) {
                    $buckets[$b]++;
                }
            }
        }

        // Aggregate playcounts across all users.
        $playtotals = array_fill(0, $numbuckets, 0);
        $maxplays   = 0;
        foreach ($rows as $row) {
            if (empty($row->playcounts)) {
                continue;
            }
            $counts = json_decode($row->playcounts, true);
            if (!is_array($counts)) {
                continue;
            }
            foreach ($counts as $b => $c) {
                if ($b < $numbuckets) {
                    $playtotals[$b] += (int)$c;
                    if ($playtotals[$b] > $maxplays) {
                        $maxplays = $playtotals[$b];
                    }
                }
            }
        }

        // Build viewers-per-bucket map for inline tooltip data.
        $userids = array_unique(array_map(fn($r) => (int)$r->userid, (array)$rows));
        $usernames = [];
        if (!empty($userids)) {
            [$insql, $inparams] = $DB->get_in_or_equal($userids, SQL_PARAMS_NAMED, 'uid');
            $namefields = 'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename';
            $users = $DB->get_records_sql("SELECT $namefields FROM {user} WHERE id $insql", $inparams);
            foreach ($users as $u) {
                $usernames[$u->id] = fullname($u);
            }
        }

        $viewersperbucket = [];
        foreach ($rows as $row) {
            $segments = json_decode($row->segments, true);
            if (!is_array($segments)) {
                continue;
            }
            $name = $usernames[(int)$row->userid] ?? '';
            if ($name === '') {
                continue;
            }
            $covered = array_fill(0, $numbuckets, false);
            foreach ($segments as $seg) {
                if (!is_array($seg) || count($seg) < 2) {
                    continue;
                }
                $sb = max(0, (int)floor((float)$seg[0] / $bucketsize));
                $eb = min($numbuckets - 1, (int)floor((float)$seg[1] / $bucketsize));
                for ($b = $sb; $b <= $eb; $b++) {
                    $covered[$b] = true;
                }
            }
            foreach ($covered as $b => $c) {
                if ($c) {
                    $viewersperbucket[$b][] = $name;
                }
            }
        }

        $bucketwidth = 100 / $numbuckets;

        // Unique-viewers bar (blue).
        $viewerbuckets = [];
        foreach ($buckets as $i => $count) {
            if ($count === 0) {
                continue;
            }
            $start = $i * $bucketsize;
            $end   = $start + $bucketsize;
            $viewerbuckets[] = [
                'bucket'  => $i,
                'start'   => recording_segments::format_seconds($start),
                'end'     => recording_segments::format_seconds($end),
                'left'    => number_format($i * $bucketwidth, 3, '.', ''),
                'width'   => number_format($bucketwidth + 0.1, 3, '.', ''),
                'opacity' => number_format($count / $totalviewers, 3, '.', ''),
            ];
        }

        // Total-plays bar (orange).
        $playbuckets = [];
        if ($maxplays > 0) {
            foreach ($playtotals as $i => $count) {
                if ($count === 0) {
                    continue;
                }
                $start = $i * $bucketsize;
                $end   = $start + $bucketsize;
                $playbuckets[] = [
                    'title'   => $count . ' plays · '
                        . recording_segments::format_seconds($start) . '–'
                        . recording_segments::format_seconds($end),
                    'left'    => number_format($i * $bucketwidth, 3, '.', ''),
                    'width'   => number_format($bucketwidth + 0.1, 3, '.', ''),
                    'opacity' => number_format($count / $maxplays, 3, '.', ''),
                ];
            }
        }

        return [
            'viewerlabel'  => get_string('recordingheatmap', 'jitsi') . ' — '
                . get_string('recordingheatmapviewers', 'jitsi', $totalviewers),
            'viewersjson'  => json_encode($viewersperbucket),
            'bucketsize'   => $bucketsize,
            'viewerbuckets' => $viewerbuckets,
            'hasplays'     => $maxplays > 0,
            'playslabel'   => get_string('recordingheatmapplays', 'jitsi', $maxplays),
            'playbuckets'  => $playbuckets,
        ];
    }

    /**
     * Render the heatmap HTML, or an empty string when there is no data.
     *
     * @param int $sourcerecordid jitsi_source_record id
     * @param int $cmid Course module id
     * @return string
     */
    public static function render(int $sourcerecordid, int $cmid): string {
        global $OUTPUT;
        $context = self::context($sourcerecordid, $cmid);
        if ($context === null) {
            return '';
        }
        return $OUTPUT->render_from_template('mod_jitsi/heatmap_bar', $context);
    }
}
