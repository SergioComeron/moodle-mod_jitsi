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

if (!get_config('mod_jitsi', 'portal_license_key')) {
    $PAGE->set_url(new moodle_url('/mod/jitsi/attendancereport.php', ['id' => $id]));
    $PAGE->set_context($context);
    $PAGE->set_title(get_string('attendancereport', 'jitsi'));
    $PAGE->set_heading(get_string('attendancereport', 'jitsi'));
    echo $OUTPUT->header();
    $syscontext = context_system::instance();
    if (has_capability('moodle/site:config', $syscontext)) {
        $notice = get_string('portalrequired', 'jitsi') . ' ' .
            html_writer::link(
                new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']),
                get_string('portalregisterbutton', 'jitsi')
            ) . '.';
    } else {
        $notice = get_string('portalrequiredcontactadmin', 'jitsi');
    }
    echo $OUTPUT->notification($notice, 'warning');
    echo $OUTPUT->footer();
    exit;
}

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

// Course overview queries.
$moduleid = $DB->get_field('modules', 'id', ['name' => 'jitsi']);

$courseactivitiessql = "
    SELECT j.id, j.name, cm.id AS cmid,
           COALESCE(SUM(ud.sessions), 0) AS totalsessions,
           COALESCE(SUM(ud.minutes), 0) AS totalminutes,
           COUNT(DISTINCT ud.userid) AS uniqueparticipants,
           COUNT(DISTINCT r.id) AS recordings
      FROM {jitsi} j
      JOIN {course_modules} cm ON cm.instance = j.id AND cm.module = :moduleid
      LEFT JOIN {jitsi_usage_daily} ud ON ud.cmid = cm.id
      LEFT JOIN {jitsi_record} r ON r.jitsi = j.id AND r.deleted = 0
     WHERE j.course = :courseid
     GROUP BY j.id, j.name, cm.id
     ORDER BY j.name ASC";
$courseactivities = $DB->get_records_sql($courseactivitiessql, [
    'moduleid' => $moduleid,
    'courseid' => $course->id,
]);

$coursestudentssql = "
    SELECT u.id, u.firstname, u.lastname,
           COALESCE(SUM(ud.minutes), 0) AS totalminutes,
           COALESCE(SUM(ud.sessions), 0) AS totalsessions
      FROM {user} u
      JOIN {jitsi_usage_daily} ud ON ud.userid = u.id AND ud.courseid = :courseid
     WHERE u.deleted = 0
     GROUP BY u.id, u.firstname, u.lastname
     ORDER BY totalminutes DESC";
$coursestudents = $DB->get_records_sql($coursestudentssql, ['courseid' => $course->id]);

$courserecviewssql = "
    SELECT rs.userid, COUNT(DISTINCT rs.sourcerecordid) AS recordings_started
      FROM {jitsi_recording_segments} rs
      JOIN {jitsi_record} r ON r.source = rs.sourcerecordid AND r.deleted = 0
      JOIN {jitsi} j ON j.id = r.jitsi AND j.course = :courseid
     GROUP BY rs.userid";
$courserecviews = $DB->get_records_sql($courserecviewssql, ['courseid' => $course->id]);

$toprecordingssql = "
    SELECT sr.id, sr.link, sr.timecreated,
           j.name AS activityname, r.name AS recordingname,
           COUNT(DISTINCT rs.userid) AS viewers
      FROM {jitsi_source_record} sr
      JOIN {jitsi_record} r ON r.source = sr.id AND r.deleted = 0
      JOIN {jitsi} j ON j.id = r.jitsi AND j.course = :courseid
      JOIN {course_modules} cm ON cm.instance = j.id AND cm.module = :moduleid
      JOIN {jitsi_recording_segments} rs ON rs.sourcerecordid = sr.id
     GROUP BY sr.id, sr.link, sr.timecreated, j.name, r.name
     ORDER BY viewers DESC";
$toprecordings = $DB->get_records_sql($toprecordingssql, [
    'courseid' => $course->id,
    'moduleid' => $moduleid,
]);

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

// Dates (and times if available) attended per user — all time, no date filter.
$datesperbuser = [];
if ($hasanydata) {
    $datefmt = get_string('strftimedate', 'langconfig');
    $datetimefmt = get_string('strftimedatetimeshort', 'langconfig');
    $daterset = $DB->get_recordset_sql(
        "SELECT userid, daykey, times
           FROM {jitsi_usage_daily}
          WHERE cmid = :cmid
                AND sessions > 0
          ORDER BY userid, daykey ASC",
        ['cmid' => $cm->id]
    );
    foreach ($daterset as $dr) {
        $timestamps = !empty($dr->times) ? json_decode($dr->times, true) : [];
        if (!empty($timestamps)) {
            foreach ($timestamps as $ts) {
                $datesperbuser[$dr->userid][] = userdate((int)$ts, $datetimefmt);
            }
        } else {
            $y = (int)substr((string)$dr->daykey, 0, 4);
            $m = (int)substr((string)$dr->daykey, 4, 2);
            $d = (int)substr((string)$dr->daykey, 6, 2);
            $datesperbuser[$dr->userid][] = userdate(mktime(0, 0, 0, $m, $d, $y), $datefmt);
        }
    }
    $daterset->close();
}

// Whether the teacher has explicitly requested a live logstore query.
$livequery = optional_param('live', 0, PARAM_INT);

if ($hasanydata) {
    // Fast path: read from precomputed table — all time, no date filter.
    $rows = $DB->get_records_sql(
        "SELECT jud.userid,
                u.firstname,
                u.lastname,
                SUM(jud.sessions) AS sessions,
                SUM(jud.minutes) AS minutes
           FROM {jitsi_usage_daily} jud
           JOIN {user} u ON u.id = jud.userid
          WHERE jud.cmid = :cmid
       GROUP BY jud.userid, u.firstname, u.lastname
       ORDER BY $orderby",
        ['cmid' => $cm->id]
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
        'dates'    => get_string('attendancedates', 'jitsi'),
    ];
    $exportdata = [];
    foreach ($rows as $row) {
        $avg = $row->sessions > 0 ? round($row->minutes / $row->sessions) : 0;
        $exportdata[] = [
            'name'     => fullname($row),
            'sessions' => (int)$row->sessions,
            'minutes'  => (int)$row->minutes,
            'avgtime'  => $avg,
            'dates'    => implode(', ', $datesperbuser[$row->userid] ?? []),
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
$baseurl        = new moodle_url('/mod/jitsi/attendancereport.php', ['id' => $id]);
$urlsortname    = new moodle_url($baseurl, ['sort' => 'name']);
$urlsortminutes = new moodle_url($baseurl, ['sort' => 'minutes']);

// Heatmap hover tooltip.
$PAGE->requires->js_call_amd('mod_jitsi/heatmap_tooltip', 'init');

// Begin output.
echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('attendancereport', 'jitsi') . ': ' . format_string($jitsi->name), 3);

// Tab 1: live sessions — intro notices/button and (when there is data) cards + table.
$sessionintro = [];
if (!$hasanydata) {
    $sessionintro[] = $OUTPUT->notification(get_string('attendancenodatacron', 'jitsi'), 'warning');
}
if (!$hasanydata && !$livequery) {
    $liveurl = new moodle_url('/mod/jitsi/attendancereport.php', ['id' => $id, 'live' => 1]);
    $sessionintro[] = $OUTPUT->single_button($liveurl, get_string('attendancegeneratereport', 'jitsi'), 'get');
} else if ($usinglivedata) {
    $sessionintro[] = $OUTPUT->notification(get_string('attendancelivedata', 'jitsi'), 'info');
}

$sessionsctx = null;
if ((!$hasanydata && !$livequery) || empty($rows)) {
    if ($livequery || $hasanydata) {
        $sessionintro[] = $OUTPUT->notification(get_string('statsnodata', 'jitsi'), 'info');
    }
} else {
    $totalusers    = count($rows);
    $totalsessions = array_sum(array_column((array)$rows, 'sessions'));
    $totalminutes  = array_sum(array_column((array)$rows, 'minutes'));

    $tablerows = [];
    foreach ($rows as $row) {
        $userurl = new moodle_url('/user/view.php', ['id' => $row->userid, 'course' => $course->id]);
        $avg     = $row->sessions > 0 ? round($row->minutes / $row->sessions) : 0;
        $dates   = implode(' · ', $datesperbuser[$row->userid] ?? []);
        $tablerows[] = ['cells' => [
            html_writer::link($userurl, fullname($row)),
            (int)$row->sessions,
            (int)$row->minutes . ' min',
            $avg . ' min',
            $dates ?: '—',
        ]];
    }

    $sessionsctx = [
        'rowclass' => 'mb-4',
        'colclass' => 'col-md-4 col-sm-6 mb-3',
        'smallcards' => false,
        'cards' => [
            ['value' => $totalusers, 'label' => get_string('uniqueusers', 'jitsi')],
            ['value' => $totalsessions, 'label' => get_string('totalsessionsinperiod', 'jitsi')],
            ['value' => $totalminutes . ' min', 'label' => get_string('totaluserminutesinperiod', 'jitsi')],
        ],
        'table' => [
            'tableclass' => null,
            'head' => [
                html_writer::link($urlsortname, get_string('name') . ($sort === 'name' ? ' ▲' : '')),
                get_string('sessionsentered', 'jitsi'),
                html_writer::link(
                    $urlsortminutes,
                    get_string('totaluserminutes', 'jitsi') . ($sort === 'minutes' ? ' ▼' : '')
                ),
                get_string('averagetimeperuser', 'jitsi'),
                get_string('attendancedates', 'jitsi'),
            ],
            'rows' => $tablerows,
        ],
        'downloadhtml' => $OUTPUT->download_dataformat_selector(
            get_string('download'),
            'attendancereport.php',
            'dataformat',
            ['id' => $id, 'sort' => $sort]
        ),
    ];
}

// Tab 2: recordings. GCS/embedded recordings get full segment tracking; plain
// links (8x8, external, Jibri) only first-access logging.
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
$gcsrecordings = array_filter(
    $allrecordings,
    fn($r) => strpos($r->link, 'storage.googleapis.com') !== false
        || (!empty($r->embed) && strpos($r->link, 'dropbox.com') !== false)
);
$linkrecordings = array_filter(
    $allrecordings,
    fn($r) => strpos($r->link, 'storage.googleapis.com') === false
        && !(!empty($r->embed) && strpos($r->link, 'dropbox.com') !== false)
);

$eventname   = '\\mod_jitsi\\event\\recording_viewed';
$namefields  = 'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename';
$datetimefmt = get_string('strftimedatetimeshort', 'langconfig');

$gcsctx = [];
$gcscount = count($gcsrecordings);
$gcsidx = 0;
foreach (array_values($gcsrecordings) as $idx => $rec) {
    $recnum = $idx + 1;
    $recname = !empty($rec->recordname) ? format_string($rec->recordname) : get_string('recordingnumber', 'jitsi', $recnum);
    $rectitle = $recname . ' — ' . userdate($rec->timecreated, $datetimefmt);

    // Fetch all view events for this recording and aggregate per user in PHP.
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
                'firstview' => $ev->timecreated,
                'lastview'  => $ev->timecreated,
            ];
        }
        if ($milestone === 0) {
            $byuser[$uid]['plays']++;
        }
        $byuser[$uid]['firstview'] = min($byuser[$uid]['firstview'], $ev->timecreated);
        $byuser[$uid]['lastview']  = max($byuser[$uid]['lastview'], $ev->timecreated);
    }
    $rs->close();

    $totalplays    = array_sum(array_column($byuser, 'plays'));
    $uniqueviewers = count($byuser);

    // Load all segment rows for this recording in one query.
    $segrows = $DB->get_records('jitsi_recording_segments', [
        'sourcerecordid' => $rec->id,
        'cmid'           => $cm->id,
    ], '', 'userid, segments, duration');

    $viewtable = null;
    if (!empty($byuser)) {
        $tablerows = [];
        foreach ($byuser as $uid => $vrow) {
            $user = $DB->get_record('user', ['id' => $uid], $namefields);
            if (!$user) {
                continue;
            }
            $userurl = new moodle_url('/user/view.php', ['id' => $uid, 'course' => $course->id]);

            $segrow  = $segrows[$uid] ?? null;
            $segs    = $segrow ? (json_decode($segrow->segments, true) ?? []) : [];
            $dur     = $segrow ? (float)($segrow->duration ?? 0) : 0;
            $pct     = \mod_jitsi\local\recording_segments::watched_pct($segs, $dur);
            $bar     = \mod_jitsi\output\segments_bar::render($segs, $dur);
            $barcell = $bar . '<small class="text-muted">' . $pct . '%</small>';

            $tablerows[] = ['cells' => [
                html_writer::link($userurl, fullname($user)),
                (int)$vrow['plays'],
                $barcell,
                userdate($vrow['firstview'], $datetimefmt),
                userdate($vrow['lastview'], $datetimefmt),
            ]];
        }
        $viewtable = [
            'tableclass' => 'table-sm',
            'head' => [
                get_string('name'),
                get_string('totalplays', 'jitsi'),
                get_string('watchprogress', 'jitsi'),
                get_string('firstview', 'jitsi'),
                get_string('lastview', 'jitsi'),
            ],
            'rows' => $tablerows,
        ];
    }

    $gcsidx++;
    $gcsctx[] = [
        'title' => format_string($rectitle),
        'rowclass' => 'mb-2',
        'colclass' => 'col-md-3 col-sm-6 mb-2',
        'smallcards' => true,
        'cards' => [
            ['value' => $totalplays, 'label' => get_string('totalplays', 'jitsi')],
            ['value' => $uniqueviewers, 'label' => get_string('uniqueviewers', 'jitsi')],
        ],
        'heatmaphtml' => \mod_jitsi\output\heatmap_bar::render((int)$rec->id, (int)$cm->id),
        'table' => $viewtable,
        'last' => $gcsidx === $gcscount,
    ];
}

$linkctx = [];
$linkcount = count($linkrecordings);
$linkidx = 0;
foreach (array_values($linkrecordings) as $idx => $rec) {
    $recname  = !empty($rec->recordname)
        ? format_string($rec->recordname)
        : get_string('recordingnumber', 'jitsi', $idx + 1);
    $rectitle = $recname . ' — ' . userdate($rec->timecreated, $datetimefmt);

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

    $linktable = null;
    if (!empty($accessed)) {
        $tablerows = [];
        foreach ($accessed as $uid => $ts) {
            $user = $DB->get_record('user', ['id' => $uid], $namefields);
            if (!$user) {
                continue;
            }
            $userurl = new moodle_url('/user/view.php', ['id' => $uid, 'course' => $course->id]);
            $tablerows[] = ['cells' => [
                html_writer::link($userurl, fullname($user)),
                userdate($ts, $datetimefmt),
            ]];
        }
        $linktable = [
            'tableclass' => 'table-sm',
            'head' => [
                get_string('name'),
                get_string('firstview', 'jitsi'),
            ],
            'rows' => $tablerows,
        ];
    }

    $linkidx++;
    $linkctx[] = [
        'title' => format_string($rectitle),
        'table' => $linktable,
        'last' => $linkidx === $linkcount,
    ];
}

// Tab 3: course overview sections.
$activitiestable = null;
if (!empty($courseactivities)) {
    $tablerows = [];
    foreach ($courseactivities as $act) {
        $acturl = new moodle_url('/mod/jitsi/view.php', ['id' => $act->cmid]);
        $tablerows[] = ['cells' => [
            html_writer::link($acturl, format_string($act->name)),
            (int)$act->totalsessions,
            (int)$act->uniqueparticipants,
            (int)$act->totalminutes . ' min',
            (int)$act->recordings,
        ]];
    }
    $activitiestable = [
        'tableclass' => 'table-sm',
        'head' => [
            get_string('activity'),
            get_string('coursedashboardsessions', 'jitsi'),
            get_string('coursedashboardparticipants', 'jitsi'),
            get_string('coursedashboardminutes', 'jitsi'),
            get_string('coursedashboardrecordings', 'jitsi'),
        ],
        'rows' => $tablerows,
    ];
}

$studentstable = null;
if (!empty($coursestudents)) {
    $tablerows = [];
    foreach ($coursestudents as $student) {
        $profileurl = new moodle_url('/user/view.php', ['id' => $student->id, 'course' => $course->id]);
        $recstarted = isset($courserecviews[$student->id]) ? (int)$courserecviews[$student->id]->recordings_started : 0;
        $tablerows[] = ['cells' => [
            html_writer::link($profileurl, fullname($student)),
            (int)$student->totalsessions,
            (int)$student->totalminutes . ' min',
            $recstarted,
        ]];
    }
    $studentstable = [
        'tableclass' => 'table-sm',
        'head' => [
            get_string('user'),
            get_string('coursedashboardsessions', 'jitsi'),
            get_string('coursedashboardminutes', 'jitsi'),
            get_string('coursedashboardrecordingsstarted', 'jitsi'),
        ],
        'rows' => $tablerows,
    ];
}

$toprecordingstable = null;
if (!empty($toprecordings)) {
    $tablerows = [];
    foreach ($toprecordings as $rec) {
        $recname = !empty($rec->recordingname) ? format_string($rec->recordingname) : userdate($rec->timecreated);
        $tablerows[] = ['cells' => [
            html_writer::link($rec->link, $recname, ['target' => '_blank']),
            format_string($rec->activityname),
            userdate($rec->timecreated),
            (int)$rec->viewers,
        ]];
    }
    $toprecordingstable = [
        'tableclass' => 'table-sm',
        'head' => [
            get_string('coursedashboardrecording', 'jitsi'),
            get_string('activity'),
            get_string('date'),
            get_string('coursedashboardviewers', 'jitsi'),
        ],
        'rows' => $tablerows,
    ];
}

$nodatanotice = $OUTPUT->notification(get_string('coursedashboardnodata', 'jitsi'), 'info');
$coursesections = [
    [
        'first' => true,
        'title' => get_string('coursedashboardactivities', 'jitsi'),
        'table' => $activitiestable,
        'nodatahtml' => $activitiestable ? null : $nodatanotice,
    ],
    [
        'first' => false,
        'title' => get_string('coursedashboardstudents', 'jitsi'),
        'table' => $studentstable,
        'nodatahtml' => $studentstable ? null : $nodatanotice,
    ],
    [
        'first' => false,
        'title' => get_string('coursedashboardtoprecordings', 'jitsi'),
        'table' => $toprecordingstable,
        'nodatahtml' => $toprecordingstable ? null
            : $OUTPUT->notification(get_string('coursedashboardnorecordingdata', 'jitsi'), 'info'),
    ],
];

echo $OUTPUT->render_from_template('mod_jitsi/attendance_report', [
    'backurl' => (new moodle_url('/mod/jitsi/view.php', ['id' => $id]))->out(false),
    'backlabel' => format_string($jitsi->name),
    'sessionintro' => $sessionintro,
    'sessions' => $sessionsctx,
    'formhtml' => $mform->render(),
    'gcs' => !empty($gcsctx) ? ['recordings' => $gcsctx] : null,
    'links' => !empty($linkctx) ? ['recordings' => $linkctx] : null,
    'coursesections' => $coursesections,
]);

echo $OUTPUT->footer();
