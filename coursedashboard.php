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
 * Course-level dashboard aggregating all Jitsi activities in a course.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');

global $DB, $OUTPUT, $PAGE;

$id = required_param('id', PARAM_INT);

$cm     = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
$course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);

require_login($course, true, $cm);
$context = context_module::instance($cm->id);
require_capability('mod/jitsi:viewattendance', $context);

if (!get_config('mod_jitsi', 'portal_license_key')) {
    $PAGE->set_url(new moodle_url('/mod/jitsi/coursedashboard.php', ['id' => $id]));
    $PAGE->set_context($context);
    $PAGE->set_title(get_string('coursedashboard', 'jitsi'));
    $PAGE->set_heading(get_string('coursedashboard', 'jitsi'));
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

$PAGE->set_url(new moodle_url('/mod/jitsi/coursedashboard.php', ['id' => $id]));
$PAGE->set_context($context);
$PAGE->set_title(get_string('coursedashboard', 'jitsi'));
$PAGE->set_heading(format_string($course->fullname));

$courseid = $course->id;
$moduleid = $DB->get_field('modules', 'id', ['name' => 'jitsi']);

// Section 1: Activity overview.

$activitiessql = "
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
$activities = $DB->get_records_sql($activitiessql, ['moduleid' => $moduleid, 'courseid' => $courseid]);

// Section 2: Student engagement ranking.

$studentssql = "
    SELECT u.id, u.firstname, u.lastname, u.picture, u.imagealt, u.email,
           COALESCE(SUM(ud.minutes), 0) AS totalminutes,
           COALESCE(SUM(ud.sessions), 0) AS totalsessions
      FROM {user} u
      JOIN {jitsi_usage_daily} ud ON ud.userid = u.id AND ud.courseid = :courseid
     WHERE u.deleted = 0
     GROUP BY u.id, u.firstname, u.lastname, u.picture, u.imagealt, u.email
     ORDER BY totalminutes DESC";
$students = $DB->get_records_sql($studentssql, ['courseid' => $courseid]);

// Recording views per student in this course.
$recviewssql = "
    SELECT rs.userid, COUNT(DISTINCT rs.sourcerecordid) AS recordings_started
      FROM {jitsi_recording_segments} rs
      JOIN {jitsi_record} r ON r.source = rs.sourcerecordid AND r.deleted = 0
      JOIN {jitsi} j ON j.id = r.jitsi AND j.course = :courseid
     GROUP BY rs.userid";
$recviews = $DB->get_records_sql($recviewssql, ['courseid' => $courseid]);

// Section 3: Top recordings by unique viewers.

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
$toprecordings = $DB->get_records_sql($toprecordingssql, ['courseid' => $courseid, 'moduleid' => $moduleid]);

echo $OUTPUT->header();
echo html_writer::tag('h4', get_string('coursedashboard', 'jitsi'));

// Render Section 1: Activity overview.

echo html_writer::tag('h5', get_string('coursedashboardactivities', 'jitsi'), ['class' => 'mt-4 mb-2']);

if (empty($activities)) {
    echo $OUTPUT->notification(get_string('coursedashboardnodata', 'jitsi'), 'info');
} else {
    $table = new html_table();
    $table->head = [
        get_string('activity'),
        get_string('coursedashboardsessions', 'jitsi'),
        get_string('coursedashboardparticipants', 'jitsi'),
        get_string('coursedashboardminutes', 'jitsi'),
        get_string('coursedashboardrecordings', 'jitsi'),
    ];
    $table->attributes['class'] = 'table table-sm table-bordered';
    foreach ($activities as $act) {
        $acturl = new moodle_url('/mod/jitsi/view.php', ['id' => $act->cmid]);
        $table->data[] = [
            html_writer::link($acturl, format_string($act->name)),
            (int)$act->totalsessions,
            (int)$act->uniqueparticipants,
            (int)$act->totalminutes . ' min',
            (int)$act->recordings,
        ];
    }
    echo html_writer::table($table);
}

// Render Section 2: Student engagement.

echo html_writer::tag('h5', get_string('coursedashboardstudents', 'jitsi'), ['class' => 'mt-4 mb-2']);

if (empty($students)) {
    echo $OUTPUT->notification(get_string('coursedashboardnodata', 'jitsi'), 'info');
} else {
    $table = new html_table();
    $table->head = [
        get_string('user'),
        get_string('coursedashboardsessions', 'jitsi'),
        get_string('coursedashboardminutes', 'jitsi'),
        get_string('coursedashboardrecordingsstarted', 'jitsi'),
    ];
    $table->attributes['class'] = 'table table-sm table-bordered';
    foreach ($students as $student) {
        $profileurl = new moodle_url('/user/view.php', ['id' => $student->id, 'course' => $courseid]);
        $recstarted = isset($recviews[$student->id]) ? (int)$recviews[$student->id]->recordings_started : 0;
        $table->data[] = [
            html_writer::link($profileurl, fullname($student)),
            (int)$student->totalsessions,
            (int)$student->totalminutes . ' min',
            $recstarted,
        ];
    }
    echo html_writer::table($table);
}

// Render Section 3: Top recordings.

echo html_writer::tag('h5', get_string('coursedashboardtoprecordings', 'jitsi'), ['class' => 'mt-4 mb-2']);

if (empty($toprecordings)) {
    echo $OUTPUT->notification(get_string('coursedashboardnorecordingdata', 'jitsi'), 'info');
} else {
    $table = new html_table();
    $table->head = [
        get_string('coursedashboardrecording', 'jitsi'),
        get_string('activity'),
        get_string('date'),
        get_string('coursedashboardviewers', 'jitsi'),
    ];
    $table->attributes['class'] = 'table table-sm table-bordered';
    foreach ($toprecordings as $rec) {
        $recname = !empty($rec->recordingname) ? format_string($rec->recordingname) : userdate($rec->timecreated);
        $table->data[] = [
            html_writer::link($rec->link, $recname, ['target' => '_blank']),
            format_string($rec->activityname),
            userdate($rec->timecreated),
            (int)$rec->viewers,
        ];
    }
    echo html_writer::table($table);
}

echo $OUTPUT->footer();
