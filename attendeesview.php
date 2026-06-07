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
 * @copyright  2024 Sergio Comerón <jitsi@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');

// Allow CORS requests.
header('Access-Control-Allow-Origin: *');

global $USER;

$id = optional_param('id', 0, PARAM_INT);
$n = optional_param('n', 0, PARAM_INT);
$state = optional_param('state', null, PARAM_TEXT);
$deletejitsirecordid = optional_param('deletejitsirecordid', 0, PARAM_INT);
$hidejitsirecordid = optional_param('hidejitsirecordid', 0, PARAM_INT);
$showjitsirecordid = optional_param('showjitsirecordid', 0, PARAM_INT);

if ($id) {
    $cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
    $course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
    $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);
    $sesskey = optional_param('sesskey', null, PARAM_TEXT);
} else {
    throw new \moodle_exception('Unable to find jitsi');
}

require_login($course, true, $cm);
$PAGE->set_url('/mod/jitsi/attendessview.php', ['id' => $cm->id]);
$PAGE->set_title(format_string($jitsi->name));
$PAGE->set_heading(format_string($course->fullname));

echo $OUTPUT->header();
$backurl = new moodle_url('/mod/jitsi/view.php', ['id' => $cm->id]);
echo html_writer::link($backurl, get_string('back'));

$cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
$contextmodule = context_module::instance($cm->id);
$sqlusersconnected = 'SELECT DISTINCT userid FROM {logstore_standard_log}
    WHERE contextid = :contextid AND action = \'participating\'';
$params = ['contextid' => $contextmodule->id];
$usersconnected = $DB->get_records_sql($sqlusersconnected, $params);

$table = new html_table();
$table->head = [get_string('name'), get_string('minutestoday', 'jitsi') .
    ': ' . date('d/m', strtotime('today midnight')), get_string('totalminutes', 'jitsi')];
$table->data = [];
$userids = [];
foreach ($usersconnected as $userconnected) {
    if ($userconnected->userid != 0) {
        $userids[] = $userconnected->userid;
    }
}

$users = $DB->get_records_list('user', 'id', $userids);

// Fetch minutes for all users in two aggregate queries instead of two per user.
$todayminutes = \mod_jitsi\local\attendance::minutes_between_all(
    $id,
    strtotime('today midnight'),
    strtotime('today midnight +1 day')
);
$totalminutes = \mod_jitsi\local\attendance::minutes_all($id);

foreach ($users as $user) {
    $urluser = new moodle_url('/user/profile.php', ['id' => $user->id]);
    $table->data[] = [
        html_writer::link($urluser, fullname($user), ['data-toggle' =>
             'tooltip', 'data-placement' => 'top', 'title' => $user->username]),
        $todayminutes[$user->id] ?? 0,
        $totalminutes[$user->id] ?? 0];
}
echo html_writer::table($table);
echo $OUTPUT->footer();
