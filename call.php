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
 * Search coursemates and start a private video call.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');

$PAGE->set_url('/mod/jitsi/call.php');
$PAGE->set_context(context_system::instance());
require_login();

if (!get_config('mod_jitsi', 'privatesessions')) {
    redirect($CFG->wwwroot, get_string('privatesessiondisabled', 'jitsi'));
}

$PAGE->set_title(get_string('callsomeone', 'jitsi'));
$PAGE->set_heading(get_string('callsomeone', 'jitsi'));

$PAGE->requires->js_call_amd('mod_jitsi/call', 'init', [
    $CFG->wwwroot . '/mod/jitsi/sessionpriv.php',
]);

// Build call history: most recent entry per peer, ordered by time descending.
$eventname = '\mod_jitsi\event\jitsi_private_session_enter';
$logs = $DB->get_records_select(
    'logstore_standard_log',
    'userid = :userid AND eventname = :eventname',
    ['userid' => $USER->id, 'eventname' => $eventname],
    'timecreated DESC',
    'id, other, timecreated',
    0,
    200
);

$history = [];
foreach ($logs as $log) {
    $other = json_decode($log->other, true);
    $peerid = isset($other['peerid']) ? (int)$other['peerid'] : null;
    if ($peerid && !isset($history[$peerid])) {
        $history[$peerid] = $log->timecreated;
    }
}

$peers = [];
if (!empty($history)) {
    [$insql, $inparams] = $DB->get_in_or_equal(array_keys($history));
    $peers = $DB->get_records_select('user', "id $insql AND deleted = 0", $inparams);
    uasort($peers, function ($a, $b) use ($history) {
        return $history[$b->id] <=> $history[$a->id];
    });
}

// Detect if the current user is a teacher in any visible course.
$teacherroles = array_keys(get_archetype_roles('teacher') + get_archetype_roles('editingteacher'));
$isteacher = false;
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
    $isteacher = !empty($courseids);
}

echo $OUTPUT->header();

// Link to tutoring schedule management for teachers.
if ($isteacher) {
    echo html_writer::link(
        new moodle_url('/mod/jitsi/tutoringschedule.php'),
        get_string('managetutoringschedule', 'jitsi'),
        ['class' => 'btn btn-outline-secondary btn-sm mb-3']
    );
}

echo html_writer::start_div('row');

// Left column: search.
echo html_writer::start_div('col-12 col-md-5');
echo html_writer::tag('p', get_string('callsomeonehelp', 'jitsi'));
echo html_writer::tag('input', '', [
    'type'         => 'text',
    'id'           => 'jitsi-call-search',
    'class'        => 'form-control mb-2',
    'placeholder'  => get_string('callsearchplaceholder', 'jitsi'),
    'autocomplete' => 'off',
]);
echo html_writer::start_div('list-group', ['id' => 'jitsi-call-results']);
echo html_writer::end_div();
echo html_writer::end_div();

// Right column: call history.
echo html_writer::start_div('col-12 col-md-7 mt-4 mt-md-0');
if (!empty($peers)) {
    echo $OUTPUT->heading(get_string('callhistory', 'jitsi'), 4);
    echo html_writer::start_div('list-group');
    foreach ($peers as $peer) {
        $userpicture = new user_picture($peer);
        $userpicture->size = 1;
        $avatarurl = $userpicture->get_url($PAGE)->out(false);
        $sessionurl = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $peer->id]);
        $timeago = userdate($history[$peer->id], get_string('strftimedatetimeshort', 'langconfig'));

        // Show availability badge for teachers with a schedule.
        $availability = jitsi_check_tutoring_availability($peer->id, $USER->id);
        $badge = '';
        if ($availability['hasschedule']) {
            if ($availability['available']) {
                $badge = html_writer::tag('span', get_string('tutoringavailable', 'jitsi'), [
                    'class' => 'badge badge-success ml-2',
                ]);
            } else {
                $badgelabel = $availability['nextslot']
                    ? get_string('tutoringnextslot', 'jitsi', $availability['nextslot'])
                    : get_string('tutoringnotavailable', 'jitsi');
                $badge = html_writer::tag('span', $badgelabel, [
                    'class' => 'badge badge-warning ml-2',
                ]);
            }
        }

        $avatar = html_writer::img($avatarurl, '', [
            'width'  => 32,
            'height' => 32,
            'class'  => 'rounded-circle mr-2',
        ]);
        $name = html_writer::tag('span', fullname($peer), ['class' => 'flex-grow-1']);
        $time = html_writer::tag('small', $timeago, ['class' => 'text-muted ml-2']);

        echo html_writer::link(
            $sessionurl,
            $avatar . $name . $time . $badge,
            ['class' => 'list-group-item list-group-item-action d-flex align-items-center']
        );
    }
    echo html_writer::end_div();
} else {
    echo html_writer::start_div('col-12 col-md-7 mt-4 mt-md-0');
    echo html_writer::end_div();
}
echo html_writer::end_div();

echo html_writer::end_div(); // .row

echo $OUTPUT->footer();
