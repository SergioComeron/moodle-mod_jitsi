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

/**
 * Attendance report for a Jitsi activity.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/formslib.php');

global $DB, $OUTPUT, $PAGE;

$id = required_param('id', PARAM_INT);

$cm     = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
$course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
$jitsi  = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

require_login($course, true, $cm);
$context = context_module::instance($cm->id);
require_capability('mod/jitsi:viewattendance', $context);

$PAGE->set_url(new moodle_url('/mod/jitsi/attendancereport.php', ['id' => $id]));
$PAGE->set_context($context);
$PAGE->set_title(get_string('attendancereport', 'jitsi') . ': ' . format_string($jitsi->name));
$PAGE->set_heading(format_string($course->fullname));

/**
 * Date filter form for the attendance report.
 *
 * @package   mod_jitsi
 * @copyright 2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class attendancereport_form extends moodleform {
    /**
     * Defines form elements.
     */
    public function definition() {
        $mform = $this->_form;
        $mform->addElement('hidden', 'id', $this->_customdata['id']);
        $mform->setType('id', PARAM_INT);

        $defaulttimestart = [
            'year'   => date('Y'),
            'month'  => 1,
            'day'    => 1,
            'hour'   => 0,
            'minute' => 0,
        ];
        $mform->addElement(
            'date_time_selector',
            'timestart',
            get_string('from', 'jitsi'),
            ['defaulttime' => $defaulttimestart]
        );
        $mform->addElement('date_time_selector', 'timeend', get_string('to', 'jitsi'));

        $buttonarray   = [];
        $buttonarray[] = $mform->createElement('submit', 'submitbutton', get_string('search'));
        $mform->addGroup($buttonarray, 'buttonar', '', ' ', false);
    }

    /**
     * Validate form data.
     *
     * @param array $data  Submitted data.
     * @param array $files Uploaded files.
     * @return array Errors.
     */
    public function validation($data, $files) {
        $errors = [];
        if (!empty($data['timestart']) && !empty($data['timeend']) && $data['timestart'] >= $data['timeend']) {
            $errors['timeend'] = get_string('statsdateerror', 'jitsi');
        }
        return $errors;
    }
}

$mform = new attendancereport_form(null, ['id' => $id]);

// Determine date range.
if ($fromform = $mform->get_data()) {
    $fromdate = $fromform->timestart;
    $todate   = $fromform->timeend;
} else {
    $fromdate = optional_param('fromdate', mktime(0, 0, 0, 1, 1, date('Y')), PARAM_INT);
    $todate   = optional_param(
        'todate',
        mktime(23, 59, 59, (int)date('m'), (int)date('d'), (int)date('Y')),
        PARAM_INT
    );
}

$fromdaykey = (int)date('Ymd', $fromdate);
$todaykey   = (int)date('Ymd', $todate);

// Handle export before any output.
$dataformat = optional_param('dataformat', '', PARAM_ALPHA);
$isdownload = ($dataformat !== '');

// Sort order for the table.
$sort = optional_param('sort', 'name', PARAM_ALPHA);
if (!in_array($sort, ['name', 'minutes'])) {
    $sort = 'name';
}
$orderby = $sort === 'minutes' ? 'minutes DESC' : 'u.lastname ASC, u.firstname ASC';

// Check whether jitsi_usage_daily has any data for this activity at all.
$hasanydata = $DB->record_exists('jitsi_usage_daily', ['cmid' => $cm->id]);

// Whether the teacher has explicitly requested a live logstore query.
$livequery = optional_param('live', 0, PARAM_INT);

if ($hasanydata) {
    // Fast path: read from precomputed table.
    $rows = $DB->get_records_sql(
        "SELECT jud.userid,
                u.firstname,
                u.lastname,
                SUM(jud.sessions) AS sessions,
                SUM(jud.minutes) AS minutes
           FROM {jitsi_usage_daily} jud
           JOIN {user} u ON u.id = jud.userid
          WHERE jud.cmid = :cmid
                AND jud.daykey BETWEEN :fromdaykey AND :todaykey
       GROUP BY jud.userid, u.firstname, u.lastname
       ORDER BY $orderby",
        ['cmid' => $cm->id, 'fromdaykey' => $fromdaykey, 'todaykey' => $todaykey]
    );
    $usinglivedata = false;
} else if ($livequery) {
    // Slow path: query logstore directly (teacher-triggered).
    [$insql, $inparams] = $DB->get_in_or_equal(['enter', 'participating'], SQL_PARAMS_NAMED, 'lact');
    $rows = $DB->get_records_sql(
        "SELECT lsl.userid,
                u.firstname,
                u.lastname,
                SUM(CASE WHEN lsl.action = 'enter' THEN 1 ELSE 0 END) AS sessions,
                SUM(CASE WHEN lsl.action = 'participating' THEN 1 ELSE 0 END) AS minutes
           FROM {logstore_standard_log} lsl
           JOIN {user} u ON u.id = lsl.userid
          WHERE lsl.contextid = :contextid
                AND lsl.action $insql
                AND lsl.timecreated BETWEEN :fromts AND :tots
       GROUP BY lsl.userid, u.firstname, u.lastname
       ORDER BY $orderby",
        array_merge($inparams, [
            'contextid' => $context->id,
            'fromts'    => $fromdate,
            'tots'      => $todate,
        ])
    );
    $usinglivedata = true;
} else {
    $rows        = [];
    $usinglivedata = false;
}

// Handle export.
if ($isdownload) {
    $columns = [
        'name'     => get_string('name'),
        'sessions' => get_string('sessionsentered', 'jitsi'),
        'minutes'  => get_string('totaluserminutes', 'jitsi'),
        'avgtime'  => get_string('averagetimeperuser', 'jitsi'),
    ];
    $exportdata = [];
    foreach ($rows as $row) {
        $avg = $row->sessions > 0 ? round($row->minutes / $row->sessions) : 0;
        $exportdata[] = [
            'name'     => fullname($row),
            'sessions' => (int)$row->sessions,
            'minutes'  => (int)$row->minutes,
            'avgtime'  => $avg,
        ];
    }
    \core\dataformat::download_data(
        'jitsi_attendance_' . $cm->id,
        $dataformat,
        $columns,
        $exportdata
    );
    die;
}

// Build sort toggle URLs.
$baseurl = new moodle_url('/mod/jitsi/attendancereport.php', [
    'id'       => $id,
    'fromdate' => $fromdate,
    'todate'   => $todate,
]);
$urlsortname    = new moodle_url($baseurl, ['sort' => 'name']);
$urlsortminutes = new moodle_url($baseurl, ['sort' => 'minutes']);

// Begin output.
echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('attendancereport', 'jitsi') . ': ' . format_string($jitsi->name), 3);

// Back link to activity.
$activityurl = new moodle_url('/mod/jitsi/view.php', ['id' => $id]);
echo html_writer::link(
    $activityurl,
    '← ' . format_string($jitsi->name),
    ['class' => 'btn btn-secondary mb-4']
);

if (!$hasanydata) {
    echo $OUTPUT->notification(get_string('attendancenodatacron', 'jitsi'), 'warning');
}

// Filter form.
echo html_writer::start_tag('div', ['class' => 'card mb-4']);
echo html_writer::start_tag('div', ['class' => 'card-body']);
$mform->display();
echo html_writer::end_tag('div');
echo html_writer::end_tag('div');

// If no precomputed data and live query not yet triggered, show the generate button.
if (!$hasanydata && !$livequery) {
    $liveurl = new moodle_url('/mod/jitsi/attendancereport.php', [
        'id'       => $id,
        'fromdate' => $fromdate,
        'todate'   => $todate,
        'live'     => 1,
    ]);
    echo $OUTPUT->single_button($liveurl, get_string('attendancegeneratereport', 'jitsi'), 'get');
} else if ($usinglivedata) {
    echo $OUTPUT->notification(get_string('attendancelivedata', 'jitsi'), 'info');
}

if ((!$hasanydata && !$livequery) || empty($rows)) {
    if ($livequery || $hasanydata) {
        echo $OUTPUT->notification(get_string('statsnodata', 'jitsi'), 'info');
    }
} else {
    // Summary row.
    $totalusers    = count($rows);
    $totalsessions = array_sum(array_column((array)$rows, 'sessions'));
    $totalminutes  = array_sum(array_column((array)$rows, 'minutes'));

    echo html_writer::start_tag('div', ['class' => 'row mb-4']);
    $statcards = [
        [get_string('uniqueusers', 'jitsi'), $totalusers],
        [get_string('totalsessionsinperiod', 'jitsi'), $totalsessions],
        [get_string('totaluserminutesinperiod', 'jitsi'), $totalminutes . ' min'],
    ];
    foreach ($statcards as $card) {
        echo html_writer::start_tag('div', ['class' => 'col-md-4 col-sm-6 mb-3']);
        echo html_writer::start_tag('div', ['class' => 'card h-100 text-center border-0 bg-light']);
        echo html_writer::start_tag('div', ['class' => 'card-body py-3']);
        echo html_writer::tag('div', $card[1], ['class' => 'h2 mb-1 fw-bold']);
        echo html_writer::tag('div', $card[0], ['class' => 'text-muted small']);
        echo html_writer::end_tag('div');
        echo html_writer::end_tag('div');
        echo html_writer::end_tag('div');
    }
    echo html_writer::end_tag('div');

    // Attendance table.
    $table                    = new html_table();
    $table->attributes['class'] = 'generaltable';

    $sorticon = $sort === 'name' ? ' ▲' : '';
    $table->head = [
        html_writer::link($urlsortname, get_string('name') . ($sort === 'name' ? ' ▲' : '')),
        get_string('sessionsentered', 'jitsi'),
        html_writer::link($urlsortminutes, get_string('totaluserminutes', 'jitsi') . ($sort === 'minutes' ? ' ▼' : '')),
        get_string('averagetimeperuser', 'jitsi'),
    ];

    foreach ($rows as $row) {
        $userurl = new moodle_url('/user/view.php', ['id' => $row->userid, 'course' => $course->id]);
        $avg     = $row->sessions > 0 ? round($row->minutes / $row->sessions) : 0;
        $table->data[] = [
            html_writer::link($userurl, fullname($row)),
            (int)$row->sessions,
            (int)$row->minutes . ' min',
            $avg . ' min',
        ];
    }

    echo html_writer::table($table);

    // Export selector.
    echo $OUTPUT->download_dataformat_selector(
        get_string('download'),
        'attendancereport.php',
        'dataformat',
        ['id' => $id, 'fromdate' => $fromdate, 'todate' => $todate, 'sort' => $sort]
    );
}

// Recording views section — one card per GCS recording in this activity.
$allrecordings = $DB->get_records_sql(
    "SELECT sr.id, sr.link, sr.timecreated, sr.embed, r.name AS recordname
       FROM {jitsi_source_record} sr
       JOIN {jitsi_record} r ON r.source = sr.id
       JOIN {jitsi} j ON j.id = r.jitsi
       JOIN {course_modules} cm ON cm.instance = j.id
      WHERE cm.id = :cmid AND sr.link IS NOT NULL
      ORDER BY sr.timecreated ASC",
    ['cmid' => $cm->id]
);
// Recordings with an embedded player (GCS or Dropbox-with-embed): full segment tracking.
$gcsrecordings = array_filter(
    $allrecordings,
    fn($r) => strpos($r->link, 'storage.googleapis.com') !== false
        || (!empty($r->embed) && strpos($r->link, 'dropbox.com') !== false)
);
// Link-only recordings (8x8, external, Jibri): track clicks only.
$linkrecordings = array_filter(
    $allrecordings,
    fn($r) => strpos($r->link, 'storage.googleapis.com') === false
        && !(!empty($r->embed) && strpos($r->link, 'dropbox.com') !== false)
);

if (!empty($gcsrecordings)) {
    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header']);
    echo html_writer::tag('h3', get_string('recordingviews', 'jitsi'), ['class' => 'mb-0']);
    echo html_writer::end_tag('div');
    echo html_writer::start_tag('div', ['class' => 'card-body']);

    $eventname = '\\mod_jitsi\\event\\recording_viewed';

    foreach ($gcsrecordings as $idx => $rec) {
        $recnum = $idx + 1;
        $recname = !empty($rec->recordname) ? format_string($rec->recordname) : get_string('recordingnumber', 'jitsi', $recnum);
        $rectitle = $recname . ' — ' . userdate($rec->timecreated, get_string('strftimedatetimeshort', 'langconfig'));

        // Fetch all events for this recording and aggregate per user in PHP.
        $rs = $DB->get_recordset_sql(
            "SELECT userid, other, timecreated
               FROM {logstore_standard_log}
              WHERE contextid = :contextid
                    AND eventname = :eventname
                    AND objectid = :sourcerecordid
                    AND timecreated BETWEEN :fromts AND :tots
           ORDER BY timecreated ASC",
            [
                'contextid'      => $context->id,
                'eventname'      => $eventname,
                'sourcerecordid' => $rec->id,
                'fromts'         => $fromdate,
                'tots'           => $todate,
            ]
        );

        $byuser = [];
        foreach ($rs as $ev) {
            $uid       = $ev->userid;
            $other     = json_decode($ev->other ?? '{}', true);
            $milestone = (int)($other['milestone'] ?? 0);
            if (!isset($byuser[$uid])) {
                $byuser[$uid] = [
                    'userid'    => $uid,
                    'plays'     => 0,
                    'm25'       => 0,
                    'm50'       => 0,
                    'm75'       => 0,
                    'm100'      => 0,
                    'firstview' => $ev->timecreated,
                    'lastview'  => $ev->timecreated,
                ];
            }
            if ($milestone === 0) {
                $byuser[$uid]['plays']++;
            }
            if ($milestone >= 25) {
                $byuser[$uid]['m25'] = 1;
            }
            if ($milestone >= 50) {
                $byuser[$uid]['m50'] = 1;
            }
            if ($milestone >= 75) {
                $byuser[$uid]['m75'] = 1;
            }
            if ($milestone >= 100) {
                $byuser[$uid]['m100'] = 1;
            }
            $byuser[$uid]['firstview'] = min($byuser[$uid]['firstview'], $ev->timecreated);
            $byuser[$uid]['lastview']  = max($byuser[$uid]['lastview'], $ev->timecreated);
        }
        $rs->close();
        $viewrows = array_map(fn($v) => (object)$v, $byuser);

        $totalplays    = array_sum(array_column($byuser, 'plays'));
        $uniqueviewers = count($byuser);

        echo html_writer::start_tag('div', ['class' => 'mb-4']);
        echo html_writer::tag('h5', format_string($rectitle), ['class' => 'mb-2']);

        echo html_writer::start_tag('div', ['class' => 'row mb-2']);
        foreach (
            [
            [get_string('totalplays', 'jitsi'), $totalplays],
            [get_string('uniqueviewers', 'jitsi'), $uniqueviewers],
            ] as $card
        ) {
            echo html_writer::start_tag('div', ['class' => 'col-md-3 col-sm-6 mb-2']);
            echo html_writer::start_tag('div', ['class' => 'card text-center border-0 bg-light']);
            echo html_writer::start_tag('div', ['class' => 'card-body py-2']);
            echo html_writer::tag('div', $card[1], ['class' => 'h3 mb-0 fw-bold']);
            echo html_writer::tag('div', $card[0], ['class' => 'text-muted small']);
            echo html_writer::end_tag('div');
            echo html_writer::end_tag('div');
            echo html_writer::end_tag('div');
        }
        echo html_writer::end_tag('div');

        // Load all segment rows for this recording in one query.
        $segrows = $DB->get_records('jitsi_recording_segments', [
            'sourcerecordid' => $rec->id,
            'cmid'           => $cm->id,
        ], '', 'userid, segments, duration');

        if (!empty($viewrows)) {
            $viewtable                      = new html_table();
            $viewtable->attributes['class'] = 'generaltable table-sm';
            $viewtable->head = [
                get_string('name'),
                get_string('totalplays', 'jitsi'),
                get_string('watchprogress', 'jitsi'),
                get_string('firstview', 'jitsi'),
                get_string('lastview', 'jitsi'),
            ];
            foreach ($viewrows as $vrow) {
                $namefields = 'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename';
                $user = $DB->get_record('user', ['id' => $vrow->userid], $namefields);
                if (!$user) {
                    continue;
                }
                $userurl = new moodle_url('/user/view.php', ['id' => $vrow->userid, 'course' => $course->id]);

                $segrow  = $segrows[$vrow->userid] ?? null;
                $segs    = $segrow ? (json_decode($segrow->segments, true) ?? []) : [];
                $dur     = $segrow ? (float)($segrow->duration ?? 0) : 0;
                $pct     = jitsi_segments_watched_pct($segs, $dur);
                $bar     = jitsi_render_segments_bar($segs, $dur);
                $barcell = $bar . '<small class="text-muted">' . $pct . '%</small>';

                $viewtable->data[] = [
                    html_writer::link($userurl, fullname($user)),
                    (int)$vrow->plays,
                    $barcell,
                    userdate($vrow->firstview, get_string('strftimedatetimeshort', 'langconfig')),
                    userdate($vrow->lastview, get_string('strftimedatetimeshort', 'langconfig')),
                ];
            }
            echo html_writer::table($viewtable);
        } else {
            echo html_writer::tag('p', get_string('recordingnoviews', 'jitsi'), ['class' => 'text-muted']);
        }

        echo html_writer::end_tag('div');

        if ($idx < count($gcsrecordings) - 1) {
            echo html_writer::empty_tag('hr');
        }
    }

    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

if (!empty($linkrecordings)) {
    $eventname = '\\mod_jitsi\\event\\recording_viewed';

    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header']);
    echo html_writer::tag('h3', get_string('recordingaccesslog', 'jitsi'), ['class' => 'mb-0']);
    echo html_writer::end_tag('div');
    echo html_writer::start_tag('div', ['class' => 'card-body']);

    foreach ($linkrecordings as $idx => $rec) {
        $recname  = !empty($rec->recordname) ? format_string($rec->recordname) : get_string('recordingnumber', 'jitsi', $idx + 1);
        $rectitle = $recname . ' — ' . userdate($rec->timecreated, get_string('strftimedatetimeshort', 'langconfig'));

        $rs = $DB->get_recordset_sql(
            "SELECT userid, MIN(timecreated) AS firstaccess
               FROM {logstore_standard_log}
              WHERE contextid  = :contextid
                AND eventname  = :eventname
                AND objectid   = :sourcerecordid
                AND timecreated BETWEEN :fromts AND :tots
           GROUP BY userid",
            [
                'contextid'      => $context->id,
                'eventname'      => $eventname,
                'sourcerecordid' => $rec->id,
                'fromts'         => $fromdate,
                'tots'           => $todate,
            ]
        );

        $accessed = [];
        foreach ($rs as $row) {
            $accessed[$row->userid] = $row->firstaccess;
        }
        $rs->close();

        echo html_writer::start_tag('div', ['class' => 'mb-4']);
        echo html_writer::tag('h5', format_string($rectitle), ['class' => 'mb-2']);

        if (!empty($accessed)) {
            $linktable                      = new html_table();
            $linktable->attributes['class'] = 'generaltable table-sm';
            $linktable->head = [
                get_string('name'),
                get_string('firstview', 'jitsi'),
            ];
            foreach ($accessed as $uid => $ts) {
                $namefields = 'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename';
                $user = $DB->get_record('user', ['id' => $uid], $namefields);
                if (!$user) {
                    continue;
                }
                $userurl = new moodle_url('/user/view.php', ['id' => $uid, 'course' => $course->id]);
                $linktable->data[] = [
                    html_writer::link($userurl, fullname($user)),
                    userdate($ts, get_string('strftimedatetimeshort', 'langconfig')),
                ];
            }
            echo html_writer::table($linktable);
        } else {
            echo html_writer::tag('p', get_string('recordingnoviews', 'jitsi'), ['class' => 'text-muted']);
        }

        echo html_writer::end_tag('div');

        if ($idx < count($linkrecordings) - 1) {
            echo html_writer::empty_tag('hr');
        }
    }

    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

echo $OUTPUT->footer();
