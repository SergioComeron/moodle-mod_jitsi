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
 * Session usage statistics for Jitsi.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/formslib.php');
require_once(__DIR__ . '/sessionusagestats_table.php');

global $DB, $OUTPUT, $PAGE;

/**
 * Format minutes into a human-readable time string.
 *
 * @param int $minutes Number of minutes.
 * @return string Formatted time (e.g. "45 min", "2h 30min").
 */
function format_jitsi_time($minutes) {
    $minutes = (int)$minutes;
    if ($minutes < 60) {
        return $minutes . ' min';
    }
    $hours = floor($minutes / 60);
    $remaining = $minutes % 60;
    if ($remaining === 0) {
        return $hours . 'h';
    }
    return $hours . 'h ' . $remaining . 'min';
}

$context = context_system::instance();
require_login();
require_capability('moodle/site:config', $context);

$PAGE->set_url(new moodle_url('/mod/jitsi/sessionusagestats.php'));
$PAGE->set_context($context);
$PAGE->set_title(get_string('sessionusagestats', 'jitsi'));

/**
 * Form for session usage statistics date filter.
 *
 * @package   mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class datesearchsessionstats_form extends moodleform {
    /**
     * Defines forms elements
     */
    public function definition() {
        $mform = $this->_form;
        $defaulttimestart = [
            'year' => date('Y'),
            'month' => 1,
            'day' => 1,
            'hour' => 0,
            'minute' => 0,
        ];
        $mform->addElement('date_time_selector', 'timestart', get_string('from', 'jitsi'), ['defaulttime' => $defaulttimestart]);
        $mform->addElement('date_time_selector', 'timeend', get_string('to', 'jitsi'));

        $buttonarray = [];
        $buttonarray[] = $mform->createElement('submit', 'submitbutton', get_string('search'));
        $mform->addGroup($buttonarray, 'buttonar', '', ' ', false);
    }

    /**
     * Validate data
     *
     * @param array $data Data to validate
     * @param array $files Array of files
     * @return array Errors found
     */
    public function validation($data, $files) {
        return [];
    }
}

$mform = new datesearchsessionstats_form();

// Determine date range.
if ($fromform = $mform->get_data()) {
    $fromdate = $fromform->timestart;
    $todate = $fromform->timeend;
} else {
    $fromdate = optional_param('fromdate', mktime(0, 0, 0, 1, 1, date('Y')), PARAM_INT);
    $todate = optional_param('todate', time(), PARAM_INT);
}

// Build cross-DB month expression from unix timestamp.
$dbfamily = $DB->get_dbfamily();
if ($dbfamily === 'postgres') {
    $monthexpr = "TO_CHAR(TO_TIMESTAMP(timecreated), 'YYYY-MM')";
} else {
    $monthexpr = "DATE_FORMAT(FROM_UNIXTIME(timecreated), '%Y-%m')";
}

// Query 1: Monthly stats — sessions + minutes + unique users in a single pass.
[$insql, $inparams] = $DB->get_in_or_equal(['enter', 'participating'], SQL_PARAMS_NAMED, 'mact');
$sql = "SELECT $monthexpr AS monthkey,
            SUM(CASE WHEN action = 'enter' THEN 1 ELSE 0 END) AS sessions,
            SUM(CASE WHEN action = 'participating' THEN 1 ELSE 0 END) AS minutes,
            COUNT(DISTINCT CASE WHEN action = 'participating' THEN userid END) AS uniqueusers
       FROM {logstore_standard_log}
      WHERE component = :mcomponent
            AND action $insql
            AND timecreated BETWEEN :mfromdate AND :mtodate
   GROUP BY 1
   ORDER BY 1 ASC";
$bymonth = $DB->get_records_sql($sql, array_merge($inparams, [
    'mcomponent' => 'mod_jitsi',
    'mfromdate'  => $fromdate,
    'mtodate'    => $todate,
]));

// Build monthly data array.
$monthlydata = [];
foreach ($bymonth as $row) {
    $monthlydata[$row->monthkey] = [
        'sessions'    => (int)$row->sessions,
        'minutes'     => (int)$row->minutes,
        'uniqueusers' => (int)$row->uniqueusers,
    ];
}

// Total unique users across the whole period (can't be derived from per-month aggregates).
$totaluniqueusers = $DB->count_records_sql(
    "SELECT COUNT(DISTINCT userid)
       FROM {logstore_standard_log}
      WHERE component = :component AND action = :action
            AND timecreated BETWEEN :fromdate AND :todate",
    ['component' => 'mod_jitsi', 'action' => 'participating', 'fromdate' => $fromdate, 'todate' => $todate]
);

// Query 2: Per-activity stats with course/activity info resolved via JOINs — no N+1 in display loops.
[$insql2, $inparams2] = $DB->get_in_or_equal(['enter', 'participating'], SQL_PARAMS_NAMED, 'cact');
$sql = "SELECT lsl.contextinstanceid AS cmid,
               c.id AS courseid,
               c.shortname AS courseshortname,
               j.name AS activityname,
               SUM(CASE WHEN lsl.action = 'enter' THEN 1 ELSE 0 END) AS sessions,
               SUM(CASE WHEN lsl.action = 'participating' THEN 1 ELSE 0 END) AS minutes,
               COUNT(DISTINCT CASE WHEN lsl.action = 'participating' THEN lsl.userid END) AS uniqueusers
          FROM {logstore_standard_log} lsl
          JOIN {course_modules} cm ON cm.id = lsl.contextinstanceid
          JOIN {course} c ON c.id = cm.course
          JOIN {jitsi} j ON j.id = cm.instance
         WHERE lsl.component = :ccomponent
               AND lsl.action $insql2
               AND lsl.timecreated BETWEEN :cfromdate AND :ctodate
      GROUP BY lsl.contextinstanceid, c.id, c.shortname, j.name
      ORDER BY minutes DESC";
$coursedata = $DB->get_records_sql($sql, array_merge($inparams2, [
    'ccomponent' => 'mod_jitsi',
    'cfromdate'  => $fromdate,
    'ctodate'    => $todate,
]));

// Query 3: Per-category stats in a single pass.
[$insql3, $inparams3] = $DB->get_in_or_equal(['enter', 'participating'], SQL_PARAMS_NAMED, 'kaact');
$sql = "SELECT cc.id AS catid,
               cc.name AS catname,
               SUM(CASE WHEN lsl.action = 'enter' THEN 1 ELSE 0 END) AS sessions,
               SUM(CASE WHEN lsl.action = 'participating' THEN 1 ELSE 0 END) AS minutes,
               COUNT(DISTINCT CASE WHEN lsl.action = 'participating' THEN lsl.userid END) AS uniqueusers
          FROM {logstore_standard_log} lsl
          JOIN {course_modules} cm ON cm.id = lsl.contextinstanceid
          JOIN {course} c ON c.id = cm.course
          JOIN {course_categories} cc ON cc.id = c.category
         WHERE lsl.component = :kcomponent
               AND lsl.action $insql3
               AND lsl.timecreated BETWEEN :kfromdate AND :ktodate
      GROUP BY cc.id, cc.name
      ORDER BY minutes DESC";
$categorydata = $DB->get_records_sql($sql, array_merge($inparams3, [
    'kcomponent' => 'mod_jitsi',
    'kfromdate'  => $fromdate,
    'ktodate'    => $todate,
]));

ksort($monthlydata);

// Handle download requests (must be before any output).
$download = optional_param('download', '', PARAM_ALPHA);
$dataformat = optional_param('dataformat', '', PARAM_ALPHA);

if ($dataformat !== '') {
    $columns = [];
    $exportdata = [];

    switch ($download) {
        case 'monthly':
            $columns = [
                'month'       => get_string('month', 'jitsi'),
                'sessions'    => get_string('sessionsentered', 'jitsi'),
                'uniqueusers' => get_string('uniqueusers', 'jitsi'),
                'time'        => get_string('totaluserminutes', 'jitsi'),
                'avgtime'     => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($monthlydata as $month => $data) {
                $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
                $exportdata[] = [
                    'month'       => $month,
                    'sessions'    => $data['sessions'],
                    'uniqueusers' => $data['uniqueusers'],
                    'time'        => format_jitsi_time($data['minutes']),
                    'avgtime'     => format_jitsi_time($avg),
                ];
            }
            $filename = 'jitsi_monthly_usage';
            break;

        case 'courses':
            $columns = [
                'course'      => get_string('course', 'jitsi'),
                'activity'    => get_string('activity', 'jitsi'),
                'sessions'    => get_string('sessionsentered', 'jitsi'),
                'uniqueusers' => get_string('uniqueusers', 'jitsi'),
                'time'        => get_string('totaluserminutes', 'jitsi'),
                'avgtime'     => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($coursedata as $data) {
                $avg = $data->uniqueusers > 0 ? round($data->minutes / $data->uniqueusers) : 0;
                $exportdata[] = [
                    'course'      => $data->courseshortname,
                    'activity'    => $data->activityname,
                    'sessions'    => $data->sessions,
                    'uniqueusers' => $data->uniqueusers,
                    'time'        => format_jitsi_time($data->minutes),
                    'avgtime'     => format_jitsi_time($avg),
                ];
            }
            $filename = 'jitsi_courses_usage';
            break;

        case 'categories':
            $columns = [
                'category'    => get_string('category', 'jitsi'),
                'sessions'    => get_string('sessionsentered', 'jitsi'),
                'uniqueusers' => get_string('uniqueusers', 'jitsi'),
                'time'        => get_string('totaluserminutes', 'jitsi'),
                'avgtime'     => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($categorydata as $data) {
                $avg = $data->uniqueusers > 0 ? round($data->minutes / $data->uniqueusers) : 0;
                $exportdata[] = [
                    'category'    => $data->catname,
                    'sessions'    => $data->sessions,
                    'uniqueusers' => $data->uniqueusers,
                    'time'        => format_jitsi_time($data->minutes),
                    'avgtime'     => format_jitsi_time($avg),
                ];
            }
            $filename = 'jitsi_categories_usage';
            break;

        default:
            $filename = 'jitsi_usage';
            break;
    }

    if (!empty($columns) && !empty($exportdata)) {
        \core\dataformat::download_data($filename, $dataformat, $columns, $exportdata);
        die;
    }
}

// Summary totals.
$totalsessions = array_sum(array_column($monthlydata, 'sessions'));
$totalminutes  = array_sum(array_column($monthlydata, 'minutes'));
$totalavg      = $totaluniqueusers > 0 ? round($totalminutes / $totaluniqueusers) : 0;

// Common download params to preserve date range.
$downloadparams = ['fromdate' => $fromdate, 'todate' => $todate];

// Begin HTML output.
echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('sessionusagestats', 'jitsi'));

// Back to settings button.
$settingsurl = new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']);
echo html_writer::link(
    $settingsurl,
    '← ' . get_string('backtosettings', 'jitsi'),
    ['class' => 'btn btn-secondary mb-4']
);

// Filter form.
echo html_writer::start_tag('div', ['class' => 'card mb-4']);
echo html_writer::start_tag('div', ['class' => 'card-body']);
$mform->display();
echo html_writer::end_tag('div');
echo html_writer::end_tag('div');

// Summary stat cards.
echo html_writer::start_tag('div', ['class' => 'row mb-4']);

$statcards = [
    [get_string('totalsessionsinperiod', 'jitsi'),    $totalsessions],
    [get_string('totaluniqueusersinperiod', 'jitsi'), $totaluniqueusers],
    [get_string('totaluserminutesinperiod', 'jitsi'), format_jitsi_time($totalminutes)],
    [get_string('averagetimeperuserinperiod', 'jitsi'), format_jitsi_time($totalavg)],
];

foreach ($statcards as $card) {
    echo html_writer::start_tag('div', ['class' => 'col-md-3 col-sm-6 mb-3']);
    echo html_writer::start_tag('div', ['class' => 'card h-100 text-center border-0 bg-light']);
    echo html_writer::start_tag('div', ['class' => 'card-body py-3']);
    echo html_writer::tag('div', $card[1], ['class' => 'h2 mb-1 fw-bold']);
    echo html_writer::tag('div', $card[0], ['class' => 'text-muted small']);
    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

echo html_writer::end_tag('div');

// Monthly section.
if (!empty($monthlydata)) {
    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header']);
    echo html_writer::tag('h3', get_string('monthlyusage', 'jitsi'), ['class' => 'mb-0']);
    echo html_writer::end_tag('div');
    echo html_writer::start_tag('div', ['class' => 'card-body']);

    $chartlabels  = [];
    $sessionsdata = [];
    $usersdata    = [];
    $minutesdata  = [];
    $avgdata      = [];

    foreach ($monthlydata as $month => $data) {
        $chartlabels[]  = $month;
        $sessionsdata[] = $data['sessions'];
        $usersdata[]    = $data['uniqueusers'];
        $minutesdata[]  = $data['minutes'];
        $avgdata[]      = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
    }

    $chart = new core\chart_bar();
    $chart->add_series(new core\chart_series(get_string('sessionsentered', 'jitsi'), $sessionsdata));
    $chart->add_series(new core\chart_series(get_string('uniqueusers', 'jitsi'), $usersdata));
    $chart->add_series(new core\chart_series(get_string('totaluserminutes', 'jitsi') . ' (min)', $minutesdata));
    $chart->add_series(new core\chart_series(get_string('averagetimeperuser', 'jitsi') . ' (min)', $avgdata));
    $chart->set_labels($chartlabels);
    echo $OUTPUT->render_chart($chart);

    $table = new html_table();
    $table->head = [
        get_string('month', 'jitsi'),
        get_string('sessionsentered', 'jitsi'),
        get_string('uniqueusers', 'jitsi'),
        get_string('totaluserminutes', 'jitsi'),
        get_string('averagetimeperuser', 'jitsi'),
    ];
    $table->attributes['class'] = 'generaltable mt-3';

    foreach ($monthlydata as $month => $data) {
        $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
        $table->data[] = [
            $month,
            $data['sessions'],
            $data['uniqueusers'],
            format_jitsi_time($data['minutes']),
            format_jitsi_time($avg),
        ];
    }

    echo html_writer::table($table);
    echo $OUTPUT->download_dataformat_selector(
        get_string('download'),
        'sessionusagestats.php',
        'dataformat',
        array_merge($downloadparams, ['download' => 'monthly'])
    );

    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

// Top courses section.
if (!empty($coursedata)) {
    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header']);
    echo html_writer::tag('h3', get_string('topcourses', 'jitsi'), ['class' => 'mb-0']);
    echo html_writer::end_tag('div');
    echo html_writer::start_tag('div', ['class' => 'card-body']);

    $topcourses  = array_slice($coursedata, 0, 10, true);
    $coursetable = new html_table();
    $coursetable->head = [
        get_string('course', 'jitsi'),
        get_string('activity', 'jitsi'),
        get_string('sessionsentered', 'jitsi'),
        get_string('uniqueusers', 'jitsi'),
        get_string('totaluserminutes', 'jitsi'),
        get_string('averagetimeperuser', 'jitsi'),
    ];
    $coursetable->attributes['class'] = 'generaltable';

    foreach ($topcourses as $cmid => $data) {
        $urlcourse    = new moodle_url('/course/view.php', ['id' => $data->courseid]);
        $urlactivity  = new moodle_url('/mod/jitsi/view.php', ['id' => $cmid]);
        $courselink   = '<a href="' . $urlcourse . '">' . format_string($data->courseshortname) . '</a>';
        $activitylink = '<a href="' . $urlactivity . '">' . format_string($data->activityname) . '</a>';
        $avg = $data->uniqueusers > 0 ? round($data->minutes / $data->uniqueusers) : 0;
        $coursetable->data[] = [
            $courselink,
            $activitylink,
            $data->sessions,
            $data->uniqueusers,
            format_jitsi_time($data->minutes),
            format_jitsi_time($avg),
        ];
    }

    echo html_writer::table($coursetable);
    echo $OUTPUT->download_dataformat_selector(
        get_string('download'),
        'sessionusagestats.php',
        'dataformat',
        array_merge($downloadparams, ['download' => 'courses'])
    );

    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

// Top categories section.
if (!empty($categorydata)) {
    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header']);
    echo html_writer::tag('h3', get_string('topcategories', 'jitsi'), ['class' => 'mb-0']);
    echo html_writer::end_tag('div');
    echo html_writer::start_tag('div', ['class' => 'card-body']);

    $cattable = new html_table();
    $cattable->head = [
        get_string('category', 'jitsi'),
        get_string('sessionsentered', 'jitsi'),
        get_string('uniqueusers', 'jitsi'),
        get_string('totaluserminutes', 'jitsi'),
        get_string('averagetimeperuser', 'jitsi'),
    ];
    $cattable->attributes['class'] = 'generaltable';

    foreach ($categorydata as $catid => $data) {
        $urlcat  = new moodle_url('/course/index.php', ['categoryid' => $catid]);
        $catlink = '<a href="' . $urlcat . '">' . format_string($data->catname) . '</a>';
        $avg = $data->uniqueusers > 0 ? round($data->minutes / $data->uniqueusers) : 0;
        $cattable->data[] = [
            $catlink,
            $data->sessions,
            $data->uniqueusers,
            format_jitsi_time($data->minutes),
            format_jitsi_time($avg),
        ];
    }

    echo html_writer::table($cattable);
    echo $OUTPUT->download_dataformat_selector(
        get_string('download'),
        'sessionusagestats.php',
        'dataformat',
        array_merge($downloadparams, ['download' => 'categories'])
    );

    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

echo $OUTPUT->footer();
