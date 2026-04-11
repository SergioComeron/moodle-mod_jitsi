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
 * Tutoring schedule management for private sessions.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');

$PAGE->set_url('/mod/jitsi/tutoringschedule.php');
$PAGE->set_context(context_system::instance());
require_login();

if (!get_config('mod_jitsi', 'privatesessions')) {
    redirect($CFG->wwwroot, get_string('privatesessiondisabled', 'jitsi'));
}

$PAGE->set_title(get_string('tutoringschedule', 'jitsi'));
$PAGE->set_heading(get_string('tutoringschedule', 'jitsi'));

// Get courses where the current user is a teacher, visible only.
$teacherroles = array_keys(get_archetype_roles('teacher') + get_archetype_roles('editingteacher'));
$teachercourses = [];
if (!empty($teacherroles)) {
    [$trolesql, $troleparams] = $DB->get_in_or_equal($teacherroles, SQL_PARAMS_NAMED, 'trole');
    $courseids = $DB->get_fieldset_sql(
        "SELECT DISTINCT ctx.instanceid
           FROM {role_assignments} ra
           JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
           JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
          WHERE ra.userid = :userid AND ra.roleid $trolesql",
        array_merge(['ctxlevel' => CONTEXT_COURSE, 'userid' => $USER->id], $troleparams)
    );
    if (!empty($courseids)) {
        [$csql, $cparams] = $DB->get_in_or_equal($courseids);
        $teachercourses = $DB->get_records_select('course', "id $csql", $cparams, 'fullname ASC', 'id, fullname');
    }
}

if (empty($teachercourses)) {
    redirect(new moodle_url('/mod/jitsi/call.php'), get_string('notateacher', 'mod_jitsi'));
}

// Weekday names.
$weekdaynames = [];
for ($i = 0; $i <= 6; $i++) {
    $weekdaynames[$i] = get_string('weekday' . $i, 'jitsi');
}

echo $OUTPUT->header();

echo $OUTPUT->single_button(
    new moodle_url('/mod/jitsi/call.php'),
    get_string('back'),
    'get'
);

echo html_writer::tag('p', get_string('tutoringschedulehelp', 'jitsi'));

// Existing slots grouped by course.
$slots = $DB->get_records(
    'jitsi_tutoring_schedule',
    ['userid' => $USER->id],
    'courseid ASC, weekday ASC, timestart ASC'
);
$slotsbycourse = [];
foreach ($slots as $slot) {
    $slotsbycourse[$slot->courseid][] = $slot;
}

foreach ($teachercourses as $course) {
    echo $OUTPUT->heading($course->fullname, 4);

    if (!empty($slotsbycourse[$course->id])) {
        echo html_writer::start_tag('ul', ['class' => 'list-group mb-3']);
        foreach ($slotsbycourse[$course->id] as $slot) {
            $h = intdiv((int)$slot->timestart, 3600);
            $m = intdiv(((int)$slot->timestart % 3600), 60);
            $hend = intdiv((int)$slot->timeend, 3600);
            $mend = intdiv(((int)$slot->timeend % 3600), 60);
            $label = $weekdaynames[$slot->weekday] . ' '
                . sprintf('%02d:%02d', $h, $m) . ' – ' . sprintf('%02d:%02d', $hend, $mend);
            $deletebtn = html_writer::tag('button', get_string('deleteslot', 'jitsi'), [
                'class'       => 'btn btn-sm btn-danger jitsi-delete-slot',
                'data-slotid' => $slot->id,
            ]);
            $liattrs = ['class' => 'list-group-item d-flex align-items-center justify-content-between'];
            $licontent = html_writer::tag('span', $label) . $deletebtn;
            echo html_writer::tag('li', $licontent, $liattrs);
        }
        echo html_writer::end_tag('ul');
    } else {
        echo html_writer::tag('p', get_string('tutoringnoscheduledslots', 'jitsi'), ['class' => 'text-muted']);
    }

    // Add slot form.
    echo html_writer::start_tag('form', [
        'class'         => 'form-inline mb-4 jitsi-add-slot-form',
        'data-courseid' => $course->id,
    ]);
    $options = '';
    foreach ($weekdaynames as $val => $dayname) {
        $options .= html_writer::tag('option', $dayname, ['value' => $val]);
    }
    echo html_writer::tag('select', $options, [
        'name'  => 'weekday',
        'class' => 'form-control mr-2 mb-2',
    ]);
    echo html_writer::tag('input', '', [
        'type'     => 'time',
        'name'     => 'timestart',
        'class'    => 'form-control mr-2 mb-2',
        'value'    => '09:00',
        'required' => 'required',
    ]);
    echo html_writer::tag('span', '–', ['class' => 'mr-2 mb-2']);
    echo html_writer::tag('input', '', [
        'type'     => 'time',
        'name'     => 'timeend',
        'class'    => 'form-control mr-2 mb-2',
        'value'    => '10:00',
        'required' => 'required',
    ]);
    echo html_writer::tag('button', get_string('addslot', 'jitsi'), [
        'type'  => 'submit',
        'class' => 'btn btn-primary mb-2',
    ]);
    echo html_writer::end_tag('form');
}

$jsweekdays = json_encode($weekdaynames);
echo html_writer::tag('script', "
require(['core/ajax', 'core/notification'], function(Ajax, Notification) {
    document.querySelectorAll('.jitsi-add-slot-form').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            var courseid  = parseInt(form.dataset.courseid);
            var weekday   = parseInt(form.querySelector('[name=weekday]').value);
            var timestart = form.querySelector('[name=timestart]').value;
            var timeend   = form.querySelector('[name=timeend]').value;
            Ajax.call([{
                methodname: 'mod_jitsi_save_tutoring_slot',
                args: {courseid: courseid, weekday: weekday, timestart: timestart, timeend: timeend}
            }])[0].then(function() {
                location.reload();
            }).catch(Notification.exception);
        });
    });

    document.querySelectorAll('.jitsi-delete-slot').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var slotid = parseInt(btn.dataset.slotid);
            Ajax.call([{
                methodname: 'mod_jitsi_delete_tutoring_slot',
                args: {slotid: slotid}
            }])[0].then(function() {
                location.reload();
            }).catch(Notification.exception);
        });
    });
});
");

echo $OUTPUT->footer();
