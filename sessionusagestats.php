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

// Aggregate enter events by month using SQL.
$sql = "SELECT $monthexpr AS monthkey, COUNT(*) AS sessions
       FROM {logstore_standard_log}
      WHERE component = :component AND action = :action
            AND timecreated BETWEEN :fromdate AND :todate
   GROUP BY 1
   ORDER BY 1 ASC";
$entersbymonth = $DB->get_records_sql($sql,
    ['component' => 'mod_jitsi', 'action' => 'enter', 'fromdate' => $fromdate, 'todate' => $todate]);

// Aggregate participating events by month using SQL.
$sql = "SELECT $monthexpr AS monthkey,
            COUNT(*) AS minutes,
            COUNT(DISTINCT userid) AS uniqueusers
       FROM {logstore_standard_log}
      WHERE component = :component AND action = :action
            AND timecreated BETWEEN :fromdate AND :todate
   GROUP BY 1
   ORDER BY 1 ASC";
$participatingbymonth = $DB->get_records_sql($sql,
    ['component' => 'mod_jitsi', 'action' => 'participating', 'fromdate' => $fromdate, 'todate' => $todate]);

// Total unique users across all months.
$totaluniqueusers = $DB->count_records_sql(
    "SELECT COUNT(DISTINCT userid)
       FROM {logstore_standard_log}
      WHERE component = :component AND action = :action
            AND timecreated BETWEEN :fromdate AND :todate",
    ['component' => 'mod_jitsi', 'action' => 'participating', 'fromdate' => $fromdate, 'todate' => $todate]);

// Build monthly data array.
$monthlydata = [];
foreach ($entersbymonth as $row) {
    $monthlydata[$row->monthkey] = ['sessions' => (int)$row->sessions, 'uniqueusers' => 0, 'minutes' => 0];
}
foreach ($participatingbymonth as $row) {
    if (!isset($monthlydata[$row->monthkey])) {
        $monthlydata[$row->monthkey] = ['sessions' => 0, 'uniqueusers' => 0, 'minutes' => 0];
    }
    $monthlydata[$row->monthkey]['uniqueusers'] = (int)$row->uniqueusers;
    $monthlydata[$row->monthkey]['minutes'] = (int)$row->minutes;
}

// Aggregate enter events by course module using SQL.
$sql = "SELECT contextinstanceid AS cmid, COUNT(*) AS sessions
       FROM {logstore_standard_log}
      WHERE component = :component AND action = :action
            AND timecreated BETWEEN :fromdate AND :todate
   GROUP BY contextinstanceid";
$entersbycm = $DB->get_records_sql($sql,
    ['component' => 'mod_jitsi', 'action' => 'enter', 'fromdate' => $fromdate, 'todate' => $todate]);

// Aggregate participating events by course module using SQL.
$sql = "SELECT contextinstanceid AS cmid, COUNT(*) AS minutes, COUNT(DISTINCT userid) AS uniqueusers
       FROM {logstore_standard_log}
      WHERE component = :component AND action = :action
            AND timecreated BETWEEN :fromdate AND :todate
   GROUP BY contextinstanceid";
$participatingbycm = $DB->get_records_sql($sql,
    ['component' => 'mod_jitsi', 'action' => 'participating', 'fromdate' => $fromdate, 'todate' => $todate]);

// Build course data array.
$coursedata = [];
foreach ($entersbycm as $row) {
    $coursedata[$row->cmid] = ['sessions' => (int)$row->sessions, 'uniqueusers' => 0, 'minutes' => 0];
}
foreach ($participatingbycm as $row) {
    if (!isset($coursedata[$row->cmid])) {
        $coursedata[$row->cmid] = ['sessions' => 0, 'uniqueusers' => 0, 'minutes' => 0];
    }
    $coursedata[$row->cmid]['uniqueusers'] = (int)$row->uniqueusers;
    $coursedata[$row->cmid]['minutes'] = (int)$row->minutes;
}

// Aggregate enter events by course category using SQL.
$sql = "SELECT cc.id AS catid, cc.name AS catname, COUNT(*) AS sessions
          FROM {logstore_standard_log} lsl
          JOIN {course_modules} cm ON cm.id = lsl.contextinstanceid
          JOIN {course} c ON c.id = cm.course
          JOIN {course_categories} cc ON cc.id = c.category
         WHERE lsl.component = :component AND lsl.action = :action
               AND lsl.timecreated BETWEEN :fromdate AND :todate
      GROUP BY cc.id, cc.name";
$entersbycategory = $DB->get_records_sql($sql,
    ['component' => 'mod_jitsi', 'action' => 'enter', 'fromdate' => $fromdate, 'todate' => $todate]);

// Aggregate participating events by course category using SQL.
$sql = "SELECT cc.id AS catid, cc.name AS catname,
               COUNT(*) AS minutes, COUNT(DISTINCT lsl.userid) AS uniqueusers
          FROM {logstore_standard_log} lsl
          JOIN {course_modules} cm ON cm.id = lsl.contextinstanceid
          JOIN {course} c ON c.id = cm.course
          JOIN {course_categories} cc ON cc.id = c.category
         WHERE lsl.component = :component AND lsl.action = :action
               AND lsl.timecreated BETWEEN :fromdate AND :todate
      GROUP BY cc.id, cc.name";
$participatingbycategory = $DB->get_records_sql($sql,
    ['component' => 'mod_jitsi', 'action' => 'participating', 'fromdate' => $fromdate, 'todate' => $todate]);

// Build category data array.
$categorydata = [];
foreach ($entersbycategory as $row) {
    $categorydata[$row->catid] = [
        'name' => $row->catname,
        'sessions' => (int)$row->sessions,
        'uniqueusers' => 0,
        'minutes' => 0,
    ];
}
foreach ($participatingbycategory as $row) {
    if (!isset($categorydata[$row->catid])) {
        $categorydata[$row->catid] = [
            'name' => $row->catname,
            'sessions' => 0,
            'uniqueusers' => 0,
            'minutes' => 0,
        ];
    }
    $categorydata[$row->catid]['uniqueusers'] = (int)$row->uniqueusers;
    $categorydata[$row->catid]['minutes'] = (int)$row->minutes;
}

ksort($monthlydata);

// Sort course data by minutes descending.
uasort($coursedata, function($a, $b) {
    return $b['minutes'] - $a['minutes'];
});

// Sort category data by minutes descending.
uasort($categorydata, function($a, $b) {
    return $b['minutes'] - $a['minutes'];
});

// Handle download requests (must be before any output).
$download = optional_param('download', '', PARAM_ALPHA);
$dataformat = optional_param('dataformat', '', PARAM_ALPHA);

if ($dataformat !== '') {
    $columns = [];
    $exportdata = [];

    switch ($download) {
        case 'monthly':
            $columns = [
                'month' => get_string('month', 'jitsi'),
                'sessions' => get_string('sessionsentered', 'jitsi'),
                'uniqueusers' => get_string('uniqueusers', 'jitsi'),
                'time' => get_string('totaluserminutes', 'jitsi'),
                'avgtime' => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($monthlydata as $month => $data) {
                $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
                $exportdata[] = [
                    'month' => $month,
                    'sessions' => $data['sessions'],
                    'uniqueusers' => $data['uniqueusers'],
                    'time' => format_jitsi_time($data['minutes']),
                    'avgtime' => format_jitsi_time($avg),
                ];
            }
            $filename = 'jitsi_monthly_usage';
            break;

        case 'courses':
            $columns = [
                'course' => get_string('course', 'jitsi'),
                'activity' => get_string('activity', 'jitsi'),
                'sessions' => get_string('sessionsentered', 'jitsi'),
                'uniqueusers' => get_string('uniqueusers', 'jitsi'),
                'time' => get_string('totaluserminutes', 'jitsi'),
                'avgtime' => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($coursedata as $cmid => $data) {
                $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, IGNORE_MISSING);
                if (!$cm) {
                    continue;
                }
                $course = $DB->get_record('course', ['id' => $cm->course], 'id, shortname, fullname', IGNORE_MISSING);
                if (!$course) {
                    continue;
                }
                $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], 'id, name', IGNORE_MISSING);
                $activityname = $jitsi ? $jitsi->name : $cm->name;

                $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
                $exportdata[] = [
                    'course' => $course->shortname,
                    'activity' => $activityname,
                    'sessions' => $data['sessions'],
                    'uniqueusers' => $data['uniqueusers'],
                    'time' => format_jitsi_time($data['minutes']),
                    'avgtime' => format_jitsi_time($avg),
                ];
            }
            $filename = 'jitsi_courses_usage';
            break;

        case 'categories':
            $columns = [
                'category' => get_string('category', 'jitsi'),
                'sessions' => get_string('sessionsentered', 'jitsi'),
                'uniqueusers' => get_string('uniqueusers', 'jitsi'),
                'time' => get_string('totaluserminutes', 'jitsi'),
                'avgtime' => get_string('averagetimeperuser', 'jitsi'),
            ];
            foreach ($categorydata as $catid => $data) {
                $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
                $exportdata[] = [
                    'category' => $data['name'],
                    'sessions' => $data['sessions'],
                    'uniqueusers' => $data['uniqueusers'],
                    'time' => format_jitsi_time($data['minutes']),
                    'avgtime' => format_jitsi_time($avg),
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
$totalminutes = array_sum(array_column($monthlydata, 'minutes'));

// Begin HTML output.
echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('sessionusagestats', 'jitsi'));

$summaryhtml = html_writer::start_tag('div', ['class' => 'general-stats mb-3']);
$summaryhtml .= html_writer::tag('p', get_string('totalsessionsinperiod', 'jitsi') . ': '
    . html_writer::tag('strong', $totalsessions));
$summaryhtml .= html_writer::tag('p', get_string('totaluniqueusersinperiod', 'jitsi') . ': '
    . html_writer::tag('strong', $totaluniqueusers));
$summaryhtml .= html_writer::tag('p', get_string('totaluserminutesinperiod', 'jitsi') . ': '
    . html_writer::tag('strong', format_jitsi_time($totalminutes)));
$totalavg = $totaluniqueusers > 0 ? round($totalminutes / $totaluniqueusers) : 0;
$summaryhtml .= html_writer::tag('p', get_string('averagetimeperuserinperiod', 'jitsi') . ': '
    . html_writer::tag('strong', format_jitsi_time($totalavg)));
$summaryhtml .= html_writer::end_tag('div');

echo $summaryhtml;

// Common download params to preserve date range.
$downloadparams = ['fromdate' => $fromdate, 'todate' => $todate];

// Bar chart with monthly data.
if (!empty($monthlydata)) {
    $chartlabels = [];
    $sessionsdata = [];
    $usersdata = [];
    $minutesdata = [];

    foreach ($monthlydata as $month => $data) {
        $chartlabels[] = $month;
        $sessionsdata[] = $data['sessions'];
        $usersdata[] = $data['uniqueusers'];
        $minutesdata[] = $data['minutes'];
    }

    $chart = new core\chart_bar();
    $seriessessions = new core\chart_series(get_string('sessionsentered', 'jitsi'), $sessionsdata);
    $seriesusers = new core\chart_series(get_string('uniqueusers', 'jitsi'), $usersdata);
    $seriesminutes = new core\chart_series(get_string('totaluserminutes', 'jitsi') . ' (min)', $minutesdata);
    $avgdata = [];
    foreach ($monthlydata as $data) {
        $avgdata[] = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
    }
    $seriesavg = new core\chart_series(get_string('averagetimeperuser', 'jitsi') . ' (min)', $avgdata);
    $chart->add_series($seriessessions);
    $chart->add_series($seriesusers);
    $chart->add_series($seriesminutes);
    $chart->add_series($seriesavg);
    $chart->set_labels($chartlabels);

    echo $OUTPUT->render_chart($chart);

    // Monthly detail table.
    echo html_writer::start_tag('div', ['class' => 'mt-4']);
    echo $OUTPUT->heading(get_string('monthlyusage', 'jitsi'), 3);

    $table = new html_table();
    $table->head = [
        get_string('month', 'jitsi'),
        get_string('sessionsentered', 'jitsi'),
        get_string('uniqueusers', 'jitsi'),
        get_string('totaluserminutes', 'jitsi'),
        get_string('averagetimeperuser', 'jitsi'),
    ];
    $table->attributes['class'] = 'generaltable';

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
}

// Top courses table.
if (!empty($coursedata)) {
    echo html_writer::start_tag('div', ['class' => 'mt-4']);
    echo $OUTPUT->heading(get_string('topcourses', 'jitsi'), 3);

    $topcourses = array_slice($coursedata, 0, 10, true);

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
        $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, IGNORE_MISSING);
        if (!$cm) {
            continue;
        }
        $course = $DB->get_record('course', ['id' => $cm->course], 'id, shortname, fullname', IGNORE_MISSING);
        if (!$course) {
            continue;
        }
        $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], 'id, name', IGNORE_MISSING);
        $activityname = $jitsi ? $jitsi->name : $cm->name;

        $urlcourse = new moodle_url('/course/view.php', ['id' => $course->id]);
        $urlactivity = new moodle_url('/mod/jitsi/view.php', ['id' => $cmid]);

        $courselink = '<a href="' . $urlcourse . '">' . format_string($course->shortname) . '</a>';
        $activitylink = '<a href="' . $urlactivity . '">' . format_string($activityname) . '</a>';

        $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
        $coursetable->data[] = [
            $courselink,
            $activitylink,
            $data['sessions'],
            $data['uniqueusers'],
            format_jitsi_time($data['minutes']),
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
}

// Top categories table.
if (!empty($categorydata)) {
    echo html_writer::start_tag('div', ['class' => 'mt-4']);
    echo $OUTPUT->heading(get_string('topcategories', 'jitsi'), 3);

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
        $urlcat = new moodle_url('/course/index.php', ['categoryid' => $catid]);
        $catlink = '<a href="' . $urlcat . '">' . format_string($data['name']) . '</a>';

        $avg = $data['uniqueusers'] > 0 ? round($data['minutes'] / $data['uniqueusers']) : 0;
        $cattable->data[] = [
            $catlink,
            $data['sessions'],
            $data['uniqueusers'],
            format_jitsi_time($data['minutes']),
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
}

$mform->display();

echo $OUTPUT->footer();
