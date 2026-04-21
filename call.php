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

// Generate VAPID keys if not yet created.
$vapidpublickey = get_config('mod_jitsi', 'vapid_public_key');
if (!$vapidpublickey) {
    $autoloader = __DIR__ . '/api/vendor/autoload.php';
    if (file_exists($autoloader)) {
        require_once($autoloader);
        $keys = \Minishlink\WebPush\VAPID::createVapidKeys();
        set_config('vapid_public_key', $keys['publicKey'], 'mod_jitsi');
        set_config('vapid_private_key', $keys['privateKey'], 'mod_jitsi');
        $vapidpublickey = $keys['publicKey'];
    }
}

$PAGE->requires->js_call_amd('mod_jitsi/call', 'init', [
    $CFG->wwwroot . '/mod/jitsi/sessionpriv.php',
    $CFG->wwwroot . '/mod/jitsi/push-sw.js',
    $vapidpublickey ?: '',
]);

// Build call history: last 10 outgoing calls in chronological order (duplicates allowed).
$eventname = '\mod_jitsi\event\jitsi_private_session_enter';
$outlogs = $DB->get_records_select(
    'logstore_standard_log',
    'userid = :userid AND eventname = :eventname',
    ['userid' => $USER->id, 'eventname' => $eventname],
    'timecreated DESC',
    'id, other, timecreated',
    0,
    50
);

$calllist = []; // List of call entries with peerid and time keys.
foreach ($outlogs as $log) {
    $other = json_decode($log->other, true);
    $peerid = isset($other['peerid']) ? (int)$other['peerid'] : null;
    if ($peerid) {
        $calllist[] = ['peerid' => $peerid, 'time' => (int)$log->timecreated];
    }
    if (count($calllist) >= 10) {
        break;
    }
}

// Fetch user records for call list.
$callpeers = [];
if (!empty($calllist)) {
    $peerids = array_unique(array_column($calllist, 'peerid'));
    [$insql, $inparams] = $DB->get_in_or_equal($peerids);
    $callpeers = $DB->get_records_select('user', "id $insql AND deleted = 0", $inparams);
}

// Build missed calls: incoming events in the last 7 days where we did not answer.
$since7days = time() - 7 * 24 * 3600;
$inlogs = $DB->get_records_select(
    'logstore_standard_log',
    'userid != :userid AND eventname = :eventname AND timecreated >= :since',
    ['userid' => $USER->id, 'eventname' => $eventname, 'since' => $since7days],
    'timecreated DESC',
    'id, userid, other, timecreated',
    0,
    200
);

// Build a set of our outgoing call times per peer for cross-reference.
$ourtimes = []; // Map of peerid to list of timecreated values.
foreach ($outlogs as $log) {
    $other = json_decode($log->other, true);
    $pid = isset($other['peerid']) ? (int)$other['peerid'] : null;
    if ($pid) {
        $ourtimes[$pid][] = (int)$log->timecreated;
    }
}

$missedlist = []; // List of missed call entries with callerid and time keys.
foreach ($inlogs as $log) {
    $other = json_decode($log->other, true);
    if (!isset($other['peerid']) || (int)$other['peerid'] !== (int)$USER->id) {
        continue;
    }
    $callerid = (int)$log->userid;
    $calltime = (int)$log->timecreated;
    // Missed if we have no outgoing event to this caller within 5 minutes after.
    $answered = false;
    if (isset($ourtimes[$callerid])) {
        foreach ($ourtimes[$callerid] as $t) {
            if ($t >= $calltime && $t <= $calltime + 300) {
                $answered = true;
                break;
            }
        }
    }
    if (!$answered) {
        $missedlist[] = ['callerid' => $callerid, 'time' => $calltime];
        if (count($missedlist) >= 10) {
            break;
        }
    }
}

// Fetch user records for missed calls.
$missedpeers = [];
if (!empty($missedlist)) {
    $missedids = array_unique(array_column($missedlist, 'callerid'));
    [$insql2, $inparams2] = $DB->get_in_or_equal($missedids);
    $missedpeers = $DB->get_records_select('user', "id $insql2 AND deleted = 0", $inparams2);
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
    echo $OUTPUT->single_button(
        new moodle_url('/mod/jitsi/tutoringschedule.php'),
        get_string('managetutoringschedule', 'jitsi'),
        'get'
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

// Right column: call history + missed calls.
echo html_writer::start_div('col-12 col-md-7 mt-4 mt-md-0');

// Missed calls section.
if (!empty($missedlist)) {
    echo $OUTPUT->heading(get_string('missedcalls', 'jitsi'), 4);
    echo html_writer::start_div('list-group mb-3');
    foreach ($missedlist as $entry) {
        $caller = isset($missedpeers[$entry['callerid']]) ? $missedpeers[$entry['callerid']] : null;
        if (!$caller) {
            continue;
        }
        $userpicture = new user_picture($caller);
        $userpicture->size = 1;
        $avatarurl = $userpicture->get_url($PAGE)->out(false);
        $sessionurl = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $caller->id]);
        $timeago = userdate($entry['time'], get_string('strftimedatetimeshort', 'langconfig'));

        $avatar = html_writer::img($avatarurl, '', [
            'width'  => 32,
            'height' => 32,
            'class'  => 'rounded-circle mr-2',
        ]);
        $missedicon = html_writer::tag('span', '&#8601;', [
            'class' => 'text-danger mr-1',
            'title' => get_string('missedcall', 'jitsi'),
        ]);
        $name = html_writer::tag('span', fullname($caller), ['class' => 'flex-grow-1']);
        $time = html_writer::tag('small', $timeago, ['class' => 'text-muted ml-2']);

        echo html_writer::link(
            $sessionurl,
            $avatar . $missedicon . $name . $time,
            ['class' => 'list-group-item list-group-item-action d-flex align-items-center list-group-item-danger']
        );
    }
    echo html_writer::end_div();
}

// Recent calls section.
if (!empty($calllist)) {
    echo $OUTPUT->heading(get_string('callhistory', 'jitsi'), 4);
    echo html_writer::start_div('list-group');
    foreach ($calllist as $entry) {
        $peer = isset($callpeers[$entry['peerid']]) ? $callpeers[$entry['peerid']] : null;
        if (!$peer) {
            continue;
        }
        $userpicture = new user_picture($peer);
        $userpicture->size = 1;
        $avatarurl = $userpicture->get_url($PAGE)->out(false);
        $sessionurl = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $peer->id]);
        $timeago = userdate($entry['time'], get_string('strftimedatetimeshort', 'langconfig'));

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
        $outicon = html_writer::tag('span', '&#8599;', [
            'class' => 'text-success mr-1',
            'title' => get_string('outgoingcall', 'jitsi'),
        ]);
        $name = html_writer::tag('span', fullname($peer), ['class' => 'flex-grow-1']);
        $time = html_writer::tag('small', $timeago, ['class' => 'text-muted ml-2']);

        echo html_writer::link(
            $sessionurl,
            $avatar . $outicon . $name . $time . $badge,
            ['class' => 'list-group-item list-group-item-action d-flex align-items-center']
        );
    }
    echo html_writer::end_div();
}

echo html_writer::end_div();

echo html_writer::end_div(); // End of row container.

// Push notification enable/disable button.
echo html_writer::start_div('mt-3');
echo html_writer::tag('button', get_string('enablepushnotifications', 'jitsi'), [
    'id'    => 'jitsi-push-btn',
    'class' => 'btn btn-secondary btn-sm',
    'style' => 'display:none',
]);
echo html_writer::tag('small', '', [
    'id'    => 'jitsi-push-status',
    'class' => 'ml-2 text-muted',
]);
echo html_writer::end_div();

// Incoming call modal.
echo html_writer::start_div('modal fade', [
    'id'          => 'jitsi-incoming-modal',
    'tabindex'    => '-1',
    'role'        => 'dialog',
    'aria-hidden' => 'true',
]);
echo html_writer::start_div('modal-dialog modal-dialog-centered', ['role' => 'document']);
echo html_writer::start_div('modal-content');
echo html_writer::start_div('modal-header');
echo html_writer::tag('h5', get_string('incomingcall', 'jitsi'), ['class' => 'modal-title']);
echo html_writer::end_div();
echo html_writer::start_div('modal-body text-center');
echo html_writer::img('', '', ['id' => 'jitsi-caller-avatar', 'width' => 64, 'height' => 64, 'class' => 'rounded-circle mb-2']);
echo html_writer::tag('p', '', ['id' => 'jitsi-caller-name', 'class' => 'font-weight-bold']);
echo html_writer::end_div();
echo html_writer::start_div('modal-footer justify-content-center');
echo html_writer::tag('a', get_string('joincall', 'jitsi'), [
    'id'    => 'jitsi-join-btn',
    'href'  => '#',
    'class' => 'btn btn-success btn-lg',
]);
echo html_writer::tag('button', get_string('dismisscall', 'jitsi'), [
    'class'             => 'btn btn-secondary btn-lg',
    'data-bs-dismiss'   => 'modal',
]);
echo html_writer::end_div();
echo html_writer::end_div();
echo html_writer::end_div();
echo html_writer::end_div();

echo $OUTPUT->footer();
