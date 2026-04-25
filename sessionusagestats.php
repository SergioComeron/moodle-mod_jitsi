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
$PAGE->set_heading(format_string(get_string('sessionusagestats', 'jitsi')));

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
    $todate = optional_param('todate', mktime(0, 0, 0, (int)date('m'), (int)date('d') - 1, (int)date('Y')), PARAM_INT);
}

// Convert timestamps to YYYYMMDD daykeys for querying the precomputed table.
$fromdaykey = (int)date('Ymd', $fromdate);
$todaykey   = (int)date('Ymd', $todate);

// Detect download intent early to skip cache and adjust limits.
$download   = optional_param('download', '', PARAM_ALPHA);
$dataformat = optional_param('dataformat', '', PARAM_ALPHA);
$isdownload = ($dataformat !== '');

// Try cache for display requests; exports always query fresh.
$cache    = cache::make('mod_jitsi', 'sessionusagestats');
$cachekey = $fromdaykey . '_' . $todaykey;
$cached   = $isdownload ? false : $cache->get($cachekey);

if ($cached !== false) {
    [$monthlydata, $coursedata, $categorydata, $userdata, $totaluniqueusers] = $cached;
} else {
    $limitnum = $isdownload ? 0 : 10;

    // Query 1: Monthly aggregates from precomputed table.
    $bymonth = $DB->get_records_sql(
        "SELECT FLOOR(daykey / 100) AS monthkey,
                SUM(sessions) AS sessions,
                SUM(minutes) AS minutes,
                COUNT(DISTINCT userid) AS uniqueusers
           FROM {jitsi_usage_daily}
          WHERE daykey BETWEEN :fromdaykey AND :todaykey
       GROUP BY FLOOR(daykey / 100)
       ORDER BY FLOOR(daykey / 100) ASC",
        ['fromdaykey' => $fromdaykey, 'todaykey' => $todaykey]
    );

    $monthlydata = [];
    foreach ($bymonth as $row) {
        $mk = (int)$row->monthkey;
        $label = sprintf('%04d-%02d', (int)floor($mk / 100), $mk % 100);
        $monthlydata[$label] = [
            'sessions'    => (int)$row->sessions,
            'minutes'     => (int)$row->minutes,
            'uniqueusers' => (int)$row->uniqueusers,
        ];
    }
    ksort($monthlydata);

    // Total unique users across the whole period.
    $totaluniqueusers = (int)$DB->get_field_sql(
        "SELECT COUNT(DISTINCT userid) FROM {jitsi_usage_daily}
          WHERE daykey BETWEEN :fromdaykey AND :todaykey",
        ['fromdaykey' => $fromdaykey, 'todaykey' => $todaykey]
    );

    // Query 2: Per-activity aggregates.
    $coursedata = $DB->get_records_sql(
        "SELECT jud.cmid,
                jud.courseid,
                c.shortname AS courseshortname,
                j.name AS activityname,
                SUM(jud.sessions) AS sessions,
                SUM(jud.minutes) AS minutes,
                COUNT(DISTINCT jud.userid) AS uniqueusers
           FROM {jitsi_usage_daily} jud
           JOIN {course} c ON c.id = jud.courseid
           JOIN {course_modules} cm ON cm.id = jud.cmid
           JOIN {jitsi} j ON j.id = cm.instance
          WHERE jud.daykey BETWEEN :fromdaykey AND :todaykey
       GROUP BY jud.cmid, jud.courseid, c.shortname, j.name
       ORDER BY minutes DESC",
        ['fromdaykey' => $fromdaykey, 'todaykey' => $todaykey],
        0,
        $limitnum
    );

    // Query 3: Per-category aggregates.
    $categorydata = $DB->get_records_sql(
        "SELECT jud.categoryid AS catid,
                cc.name AS catname,
                SUM(jud.sessions) AS sessions,
                SUM(jud.minutes) AS minutes,
                COUNT(DISTINCT jud.userid) AS uniqueusers
           FROM {jitsi_usage_daily} jud
           JOIN {course_categories} cc ON cc.id = jud.categoryid
          WHERE jud.daykey BETWEEN :fromdaykey AND :todaykey
       GROUP BY jud.categoryid, cc.name
       ORDER BY minutes DESC",
        ['fromdaykey' => $fromdaykey, 'todaykey' => $todaykey],
        0,
        $limitnum
    );

    // Query 4: Per-user aggregates.
    $userdata = $DB->get_records_sql(
        "SELECT jud.userid,
                u.firstname,
                u.lastname,
                SUM(jud.sessions) AS sessions,
                SUM(jud.minutes) AS minutes
           FROM {jitsi_usage_daily} jud
           JOIN {user} u ON u.id = jud.userid
          WHERE jud.daykey BETWEEN :fromdaykey AND :todaykey
       GROUP BY jud.userid, u.firstname, u.lastname
       ORDER BY minutes DESC",
        ['fromdaykey' => $fromdaykey, 'todaykey' => $todaykey],
        0,
        $limitnum
    );

    if (!$isdownload) {
        $cache->set($cachekey, [$monthlydata, $coursedata, $categorydata, $userdata, $totaluniqueusers]);
    }
}

// Handle download requests (must be before any output).
if ($isdownload) {
    $columns    = [];
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

        case 'users':
            $columns = [
                'user'     => get_string('user'),
                'sessions' => get_string('sessionsentered', 'jitsi'),
                'time'     => get_string('totaluserminutes', 'jitsi'),
                'avgtime'  => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($userdata as $data) {
                $avg = $data->sessions > 0 ? round($data->minutes / $data->sessions) : 0;
                $exportdata[] = [
                    'user'     => fullname($data),
                    'sessions' => $data->sessions,
                    'time'     => format_jitsi_time($data->minutes),
                    'avgtime'  => format_jitsi_time($avg),
                ];
            }
            $filename = 'jitsi_users_usage';
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

// Date range covered by the precomputed table.
$tablerange = $DB->get_record_sql(
    "SELECT MIN(daykey) AS firstday, MAX(daykey) AS lastday FROM {jitsi_usage_daily}"
);

// Begin HTML output.
echo $OUTPUT->header();

// Notice that stats are updated nightly, with the covered date range.
if ($tablerange && $tablerange->firstday) {
    $firstdate = userdate(
        mktime(
            0,
            0,
            0,
            (int)substr((string)$tablerange->firstday, 4, 2),
            (int)substr((string)$tablerange->firstday, 6, 2),
            (int)substr((string)$tablerange->firstday, 0, 4)
        ),
        get_string('strftimedate', 'langconfig')
    );
    $lastdate = userdate(
        mktime(
            0,
            0,
            0,
            (int)substr((string)$tablerange->lastday, 4, 2),
            (int)substr((string)$tablerange->lastday, 6, 2),
            (int)substr((string)$tablerange->lastday, 0, 4)
        ),
        get_string('strftimedate', 'langconfig')
    );
    echo $OUTPUT->notification(
        get_string('statsdelayed', 'jitsi') . ' ' .
        get_string('statsdaterange', 'jitsi', (object)['first' => $firstdate, 'last' => $lastdate]),
        'info'
    );
} else {
    echo $OUTPUT->notification(get_string('statsdelayed', 'jitsi'), 'info');
}

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
    [get_string('totalsessionsinperiod', 'jitsi'), $totalsessions],
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

if (empty($monthlydata) && empty($coursedata) && empty($categorydata) && empty($userdata)) {
    echo $OUTPUT->notification(get_string('statsnodata', 'jitsi'), 'warning');
}

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

    $seriessessions = new core\chart_series(get_string('sessionsentered', 'jitsi'), $sessionsdata);
    $seriessessions->set_yaxis(0);
    $chart->add_series($seriessessions);

    $seriesusers = new core\chart_series(get_string('uniqueusers', 'jitsi'), $usersdata);
    $seriesusers->set_yaxis(0);
    $chart->add_series($seriesusers);

    $seriesminutes = new core\chart_series(get_string('totaluserminutes', 'jitsi') . ' (min)', $minutesdata);
    $seriesminutes->set_yaxis(1);
    $chart->add_series($seriesminutes);

    $seriesavg = new core\chart_series(get_string('averagetimeperuser', 'jitsi') . ' (min)', $avgdata);
    $seriesavg->set_yaxis(1);
    $chart->add_series($seriesavg);

    $yaxisleft = new core\chart_axis();
    $yaxisleft->set_label(get_string('sessionsentered', 'jitsi') . ' / ' . get_string('uniqueusers', 'jitsi'));
    $yaxisright = new core\chart_axis();
    $yaxisright->set_label(get_string('totaluserminutes', 'jitsi'));
    $yaxisright->set_position(core\chart_axis::POS_RIGHT);
    $chart->set_yaxis($yaxisleft, 0);
    $chart->set_yaxis($yaxisright, 1);

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

    foreach ($coursedata as $cmid => $data) {
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

// Top users section.
if (!empty($userdata)) {
    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header']);
    echo html_writer::tag('h3', get_string('topusers', 'jitsi'), ['class' => 'mb-0']);
    echo html_writer::end_tag('div');
    echo html_writer::start_tag('div', ['class' => 'card-body']);

    $usertable = new html_table();
    $usertable->head = [
        get_string('user'),
        get_string('sessionsentered', 'jitsi'),
        get_string('totaluserminutes', 'jitsi'),
        get_string('averagetimeperuser', 'jitsi'),
    ];
    $usertable->attributes['class'] = 'generaltable';

    foreach ($userdata as $data) {
        $urluser  = new moodle_url('/user/view.php', ['id' => $data->userid]);
        $userlink = '<a href="' . $urluser . '">' . format_string(fullname($data)) . '</a>';
        $avg = $data->sessions > 0 ? round($data->minutes / $data->sessions) : 0;
        $usertable->data[] = [
            $userlink,
            $data->sessions,
            format_jitsi_time($data->minutes),
            format_jitsi_time($avg),
        ];
    }

    echo html_writer::table($usertable);
    echo $OUTPUT->download_dataformat_selector(
        get_string('download'),
        'sessionusagestats.php',
        'dataformat',
        array_merge($downloadparams, ['download' => 'users'])
    );

    echo html_writer::end_tag('div');
    echo html_writer::end_tag('div');
}

echo $OUTPUT->footer();
