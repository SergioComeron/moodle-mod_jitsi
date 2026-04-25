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
        $mform->addElement('checkbox', 'includetoday', get_string('statsincludetoday', 'jitsi'));
        $mform->addHelpButton('includetoday', 'statsincludetoday', 'jitsi');

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
$includetoday = false;
if ($fromform = $mform->get_data()) {
    $fromdate     = $fromform->timestart;
    $todate       = $fromform->timeend;
    $includetoday = !empty($fromform->includetoday);
} else {
    $fromdate     = optional_param('fromdate', mktime(0, 0, 0, 1, 1, date('Y')), PARAM_INT);
    $todate       = optional_param('todate', mktime(0, 0, 0, (int)date('m'), (int)date('d') - 1, (int)date('Y')), PARAM_INT);
    $includetoday = (bool)optional_param('includetoday', 0, PARAM_INT);
}

// Configurable top-N limit for display sections (not exports).
$toplimit = optional_param('toplimit', 10, PARAM_INT);
if (!in_array($toplimit, [10, 25, 50])) {
    $toplimit = 10;
}

// Convert timestamps to YYYYMMDD daykeys for querying the precomputed table.
$fromdaykey   = (int)date('Ymd', $fromdate);
$todaykey     = (int)date('Ymd', $todate);
$todaydaykey  = (int)date('Ymd');

// Detect download intent early to skip cache and adjust limits.
$download   = optional_param('download', '', PARAM_ALPHA);
$dataformat = optional_param('dataformat', '', PARAM_ALPHA);
$isdownload = ($dataformat !== '');

// Try cache for display requests; exports and includetoday always query fresh.
$cache    = cache::make('mod_jitsi', 'sessionusagestats');
$cachekey = $fromdaykey . '_' . $todaykey . '_' . $toplimit;
$cached   = ($isdownload || $includetoday) ? false : $cache->get($cachekey);

if ($cached !== false) {
    [$monthlydata, $coursedata, $categorydata, $userdata, $totaluniqueusers] = $cached;
} else {
    $limitnum = $isdownload ? 0 : $toplimit;

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

// Merge today's live data from logstore when requested.
if ($includetoday && $todaydaykey >= $fromdaykey) {
    $todaystart = mktime(0, 0, 0, (int)date('m'), (int)date('d'), (int)date('Y'));
    $todayend   = time();
    [$insqlt, $inparamst] = $DB->get_in_or_equal(['enter', 'participating'], SQL_PARAMS_NAMED, 'tact');
    $todayrows = $DB->get_records_sql(
        "SELECT lsl.contextinstanceid AS cmid,
                lsl.userid,
                cm.course AS courseid,
                c.category AS categoryid,
                SUM(CASE WHEN lsl.action = 'enter' THEN 1 ELSE 0 END) AS sessions,
                SUM(CASE WHEN lsl.action = 'participating' THEN 1 ELSE 0 END) AS minutes
           FROM {logstore_standard_log} lsl
           JOIN {course_modules} cm ON cm.id = lsl.contextinstanceid
           JOIN {course} c ON c.id = cm.course
          WHERE lsl.component = :tcomponent
                AND lsl.action $insqlt
                AND lsl.timecreated BETWEEN :tdaystart AND :tdayend
       GROUP BY lsl.contextinstanceid, lsl.userid, cm.course, c.category",
        array_merge($inparamst, [
            'tcomponent' => 'mod_jitsi',
            'tdaystart'  => $todaystart,
            'tdayend'    => $todayend,
        ])
    );

    // Merge today's rows into the aggregated data structures.
    $todaymonthkey = date('Y-m');
    $todaycourses  = [];
    $todaycats     = [];
    $todayusers    = [];
    foreach ($todayrows as $row) {
        // Monthly bucket.
        if (!isset($monthlydata[$todaymonthkey])) {
            $monthlydata[$todaymonthkey] = ['sessions' => 0, 'minutes' => 0, 'uniqueusers' => 0];
        }
        $monthlydata[$todaymonthkey]['sessions'] += (int)$row->sessions;
        $monthlydata[$todaymonthkey]['minutes']  += (int)$row->minutes;

        // Course bucket (keyed by cmid).
        $cmid = $row->cmid;
        if (!isset($todaycourses[$cmid])) {
            $todaycourses[$cmid] = ['sessions' => 0, 'minutes' => 0, 'userids' => []];
        }
        $todaycourses[$cmid]['sessions']          += (int)$row->sessions;
        $todaycourses[$cmid]['minutes']           += (int)$row->minutes;
        $todaycourses[$cmid]['userids'][$row->userid] = true;

        // Category bucket.
        $catid = $row->categoryid;
        if (!isset($todaycats[$catid])) {
            $todaycats[$catid] = ['sessions' => 0, 'minutes' => 0, 'userids' => []];
        }
        $todaycats[$catid]['sessions']             += (int)$row->sessions;
        $todaycats[$catid]['minutes']              += (int)$row->minutes;
        $todaycats[$catid]['userids'][$row->userid] = true;

        // User bucket.
        $uid = $row->userid;
        if (!isset($todayusers[$uid])) {
            $todayusers[$uid] = ['sessions' => 0, 'minutes' => 0];
        }
        $todayusers[$uid]['sessions'] += (int)$row->sessions;
        $todayusers[$uid]['minutes']  += (int)$row->minutes;
    }
    ksort($monthlydata);

    // Merge today's courses into $coursedata (update existing or add new entries).
    foreach ($todaycourses as $cmid => $tdata) {
        if (isset($coursedata[$cmid])) {
            $coursedata[$cmid]->sessions   += $tdata['sessions'];
            $coursedata[$cmid]->minutes    += $tdata['minutes'];
            $coursedata[$cmid]->uniqueusers = max($coursedata[$cmid]->uniqueusers, count($tdata['userids']));
        } else {
            $cm = $DB->get_record('course_modules', ['id' => $cmid]);
            if ($cm) {
                $course  = $DB->get_record('course', ['id' => $cm->course]);
                $jitsi   = $DB->get_record('jitsi', ['id' => $cm->instance]);
                if ($course && $jitsi) {
                    $entry = new stdClass();
                    $entry->cmid           = $cmid;
                    $entry->courseid       = $course->id;
                    $entry->courseshortname = $course->shortname;
                    $entry->activityname   = $jitsi->name;
                    $entry->sessions       = $tdata['sessions'];
                    $entry->minutes        = $tdata['minutes'];
                    $entry->uniqueusers    = count($tdata['userids']);
                    $coursedata[$cmid]     = $entry;
                }
            }
        }
    }
    uasort($coursedata, fn($a, $b) => $b->minutes <=> $a->minutes);

    // Merge today's categories.
    foreach ($todaycats as $catid => $tdata) {
        if (isset($categorydata[$catid])) {
            $categorydata[$catid]->sessions   += $tdata['sessions'];
            $categorydata[$catid]->minutes    += $tdata['minutes'];
            $categorydata[$catid]->uniqueusers = max($categorydata[$catid]->uniqueusers, count($tdata['userids']));
        } else {
            $cat = $DB->get_record('course_categories', ['id' => $catid]);
            if ($cat) {
                $entry             = new stdClass();
                $entry->catid      = $catid;
                $entry->catname    = $cat->name;
                $entry->sessions   = $tdata['sessions'];
                $entry->minutes    = $tdata['minutes'];
                $entry->uniqueusers = count($tdata['userids']);
                $categorydata[$catid] = $entry;
            }
        }
    }
    uasort($categorydata, fn($a, $b) => $b->minutes <=> $a->minutes);

    // Merge today's users.
    foreach ($todayusers as $uid => $tdata) {
        if (isset($userdata[$uid])) {
            $userdata[$uid]->sessions += $tdata['sessions'];
            $userdata[$uid]->minutes  += $tdata['minutes'];
        } else {
            $user = $DB->get_record('user', ['id' => $uid]);
            if ($user) {
                $entry            = new stdClass();
                $entry->userid    = $uid;
                $entry->firstname = $user->firstname;
                $entry->lastname  = $user->lastname;
                $entry->sessions  = $tdata['sessions'];
                $entry->minutes   = $tdata['minutes'];
                $userdata[$uid]   = $entry;
            }
        }
    }
    uasort($userdata, fn($a, $b) => $b->minutes <=> $a->minutes);

    // Add today's users that don't appear in the precomputed period.
    $todayuniqueids = array_unique(array_column((array)$todayrows, 'userid'));
    if (!empty($todayuniqueids)) {
        $precomputedids = $DB->get_fieldset_sql(
            "SELECT DISTINCT userid FROM {jitsi_usage_daily}
              WHERE daykey BETWEEN :fromdaykey AND :todaykey",
            ['fromdaykey' => $fromdaykey, 'todaykey' => $todaykey]
        );
        $totaluniqueusers += count(array_diff($todayuniqueids, $precomputedids));
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

// Common params to preserve date range and limit across links.
$downloadparams  = ['fromdate' => $fromdate, 'todate' => $todate];
$limitparams     = ['fromdate' => $fromdate, 'todate' => $todate, 'toplimit' => $toplimit];

// Date range covered by the precomputed table.
$tablerange = $DB->get_record_sql(
    "SELECT MIN(daykey) AS firstday, MAX(daykey) AS lastday FROM {jitsi_usage_daily}"
);

// Begin HTML output.
echo $OUTPUT->header();

// Warn if the selected date range falls outside the available precomputed data.
if ($tablerange && $tablerange->firstday) {
    if ($fromdaykey > $tablerange->lastday || $todaykey < $tablerange->firstday) {
        echo $OUTPUT->notification(get_string('statsrangeoutside', 'jitsi'), 'warning');
    } else if ($fromdaykey < $tablerange->firstday || (!$includetoday && $todaykey > $tablerange->lastday)) {
        echo $OUTPUT->notification(get_string('statsrangepartial', 'jitsi'), 'warning');
    }
}

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

/**
 * Render a top-N limit selector as small links.
 *
 * @param int   $current    Current limit value.
 * @param array $baseurl    Base URL params (fromdate, todate).
 * @return string HTML for the limit selector.
 */
function jitsi_toplimit_selector($current, $baseurl) {
    $links = [];
    foreach ([10, 25, 50] as $n) {
        $url = new moodle_url('/mod/jitsi/sessionusagestats.php', array_merge($baseurl, ['toplimit' => $n]));
        if ($n === $current) {
            $links[] = html_writer::tag('strong', $n);
        } else {
            $links[] = html_writer::link($url, $n);
        }
    }
    $label = get_string('toplimit', 'jitsi') . ': ' . implode(' | ', $links);
    return html_writer::tag('span', $label, ['class' => 'float-end small text-muted mt-1']);
}

// Monthly section.
if (!empty($monthlydata)) {
    echo html_writer::start_tag('div', ['class' => 'card mb-4']);
    echo html_writer::start_tag('div', ['class' => 'card-header d-flex align-items-center justify-content-between']);
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
    echo html_writer::start_tag('div', ['class' => 'card-header d-flex align-items-center justify-content-between']);
    echo html_writer::tag('h3', get_string('topcourses', 'jitsi'), ['class' => 'mb-0']);
    echo jitsi_toplimit_selector($toplimit, $limitparams);
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
    echo html_writer::start_tag('div', ['class' => 'card-header d-flex align-items-center justify-content-between']);
    echo html_writer::tag('h3', get_string('topcategories', 'jitsi'), ['class' => 'mb-0']);
    echo jitsi_toplimit_selector($toplimit, $limitparams);
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
    echo html_writer::start_tag('div', ['class' => 'card-header d-flex align-items-center justify-content-between']);
    echo html_writer::tag('h3', get_string('topusers', 'jitsi'), ['class' => 'mb-0']);
    echo jitsi_toplimit_selector($toplimit, $limitparams);
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
