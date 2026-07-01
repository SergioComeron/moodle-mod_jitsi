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
 * Prints a particular instance of jitsi
 *
 * You can have a rather longer description of the file as well,
 * if you like, and it can span multiple lines.
 *
 * @package    mod_jitsi
 * @copyright  2024 Sergio Comerón <info@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php');
require_once($CFG->libdir . '/formslib.php');
global $DB, $OUTPUT, $PAGE;

$context = context_system::instance();
require_login();
require_capability('moodle/site:config', $context);

$PAGE->set_url(new moodle_url('/mod/jitsi/stats.php'));
$PAGE->set_context($context);
$PAGE->set_title(get_string('jitsi_recording_statistics', 'jitsi'));

/**
 * Form for stats .
 *
 * @package   mod_jitsi
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <info@sergiocomeron.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class datesearchstats_form extends moodleform {
    /**
     * Defines forms elements
     */
    public function definition() {
        global $DB;
        $mform = $this->_form;
        $defaulttimestart = [
            'year' => date('Y'),
            'month' => date('n'),
            'day' => date('j'),
            'hour' => 0,
            'minute' => 0,
        ];
        $mform->addElement('date_time_selector', 'timestart', get_string('from', 'jitsi'), ['defaulttime' => $defaulttimestart]);
        $mform->addElement('date_time_selector', 'timeend', get_string('to', 'jitsi'));

        $topoptions = [10 => 'Top 10', 100 => 'Top 100', 200 => 'Top 200'];
        $mform->addElement('select', 'toplimit', get_string('toplimit', 'jitsi'), $topoptions);
        $mform->setDefault('toplimit', 10);

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

$mform = new datesearchstats_form();

echo $OUTPUT->header();

echo $OUTPUT->heading(get_string('jitsi_recording_statistics', 'jitsi'));

$totalrecordings = $DB->count_records('jitsi_record');

if ($fromform = $mform->get_data()) {
    $fromdate = $fromform->timestart;
    $todate = $fromform->timeend;
    $toplimit = $fromform->toplimit;
} else {
    $fromdate = 0;
    $todate = time();
    $toplimit = 10;
}

$topteacherssql = "SELECT jsr.userid, COUNT(jr.id) AS recording_count,
                    ROUND(COUNT(jr.id) / GREATEST((MAX(jsr.timecreated) - MIN(jsr.timecreated)) / 86400.0, 1), 2)
                        AS avg_recordings_per_day,
                    ROUND(COUNT(jr.id) / GREATEST((MAX(jsr.timecreated) - MIN(jsr.timecreated)) / (86400.0 * 7), 1), 2)
                        AS avg_recordings_per_week
                    FROM {jitsi_record} jr
                    JOIN {jitsi_source_record} jsr ON jr.source = jsr.id
                    WHERE jsr.timecreated BETWEEN :fromdate AND :todate
                    GROUP BY jsr.userid
                    ORDER BY recording_count DESC";

$params = ['fromdate' => $fromdate, 'todate' => $todate];
$topteachers = $DB->get_records_sql($topteacherssql, $params, 0, $toplimit);

$generalstatshtml = html_writer::start_tag('div', ['class' => 'general-stats']);

$generalstatshtml .= html_writer::tag('p', get_string('total_recordings', 'jitsi') . ': ' . $totalrecordings);

$chartlabels = [];
$chartdata = [];

foreach ($topteachers as $teacher) {
    $user = $DB->get_record('user', ['id' => $teacher->userid], 'firstname, lastname');
    $username = $user->firstname . ' ' . $user->lastname;
    $chartlabels[] = $username;
    $chartdata[] = $teacher->recording_count;
}

$generalstatshtml .= html_writer::end_tag('div');

echo $generalstatshtml;

$chart = new core\chart_bar();
$series = new core\chart_series(get_string('number_of_recordings', 'jitsi'), $chartdata);
$chart->add_series($series);
$chart->set_labels($chartlabels);

echo $OUTPUT->render_chart($chart);

$mform->display();

echo $OUTPUT->footer();
