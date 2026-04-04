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
 * @copyright  2021 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(dirname(dirname(__FILE__))) . '/lib/moodlelib.php');
require_once(dirname(__FILE__) . '/lib.php');

$PAGE->set_url($CFG->wwwroot . '/mod/jitsi/session.php');

$state = optional_param('state', null, PARAM_TEXT);

if ($state == null) {
    $courseid = required_param('courseid', PARAM_INT);
    $cmid = required_param('cmid', PARAM_INT);
    $nombre = required_param('nom', PARAM_TEXT);
    $session = required_param('ses', PARAM_TEXT);
    $avatar = get_config('mod_jitsi', 'showavatars') == true ? required_param('avatar', PARAM_TEXT) : null;
    $teacher = required_param('t', PARAM_BOOL);
} else {
    $paramdecode = base64urldecode($state);
    $parametrosarray = explode("&", $paramdecode);
    $avatararray = $parametrosarray[0];
    $nomarray = $parametrosarray[1];
    $sessionarray = $parametrosarray[2];
    $coursearray = $parametrosarray[3];
    $cmidarray = $parametrosarray[4];
    $tarray = $parametrosarray[5];
    $statesesarray = $parametrosarray[6];
    $avatara = explode("=", $avatararray);
    $nombrea = explode("=", $nomarray);
    $sessiona = explode("=", $sessionarray);
    $courseida = explode("=", $coursearray);
    $cmida = explode("=", $cmidarray);
    $teachera = explode("=", $tarray);
    $statesesa = explode("=", $statesesarray);
    $avatar = $avatara[1];
    $nombre = $nombrea[1];
    $session = $sessiona[1];
    $courseid = $courseida[1];
    $cmid = $cmida[1];
    $teacher = $teachera[1];
    $stateses = $statesesa[1];
}

$cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST);
$course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
require_login($course, true, $cm);

$module = $DB->get_record('modules', ['name' => 'jitsi']);

$jitsi = $DB->get_record('jitsi', ['id' => $cm->instance]);

$PAGE->set_title($jitsi->name);
$PAGE->set_heading($jitsi->name);
echo $OUTPUT->header();

$PAGE->set_context(context_module::instance($cm->id));

if ($jitsi->sourcerecord != null) {
    $contextmodule = context_module::instance($cm->id);

    $sqllastparticipating = 'select timecreated from {logstore_standard_log} where contextid = '
    . $contextmodule->id . ' and (action = \'participating\' or action = \'enter\') order by timecreated DESC limit 1';
    $usersconnected = $DB->get_record_sql($sqllastparticipating);

    if (
        ($jitsi->numberofparticipants == 1 ||
        $jitsi->numberofparticipants == 0) &&
        (getdate()[0] - $usersconnected->timecreated) > 72
    ) {
        $jitsi->sourcerecord = null;
        $DB->update_record('jitsi', $jitsi);
    }
}
if (
    get_config('mod_jitsi', 'id') == 'username' && $nombre != $USER->username ||
    get_config('mod_jitsi', 'id') == 'nameandsurname' && $nombre != $USER->firstname . ' ' . $USER->lastname ||
    get_config('mod_jitsi', 'id') == 'alias' && $nombre != ""
) {
    echo $OUTPUT->notification(get_string('urlerror', 'jitsi'), 'error');
} else {
    $nombre = str_replace("'", "\\'", $nombre);
    $mail = get_config('mod_jitsi', 'sendemail') ? $USER->email : null;
    createsession($teacher, $cmid, $avatar, $nombre, $session, $mail, $jitsi);
}

echo $OUTPUT->footer();
