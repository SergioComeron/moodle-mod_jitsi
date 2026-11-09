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

require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php'); // phpcs:ignore moodle.Files.RequireLogin.Missing
require_once(dirname(dirname(dirname(__FILE__))) . '/lib/moodlelib.php');
require_once(dirname(__FILE__) . '/lib.php');

// This page is accessible to external guests via invitation link — require_login is intentionally omitted.
// Logged-in Moodle users are handled normally; unauthenticated guests access directly.
if (isloggedin() && !isguestuser()) {
    require_login(0, false);
}

// The invitation token is the only proof that the guest received the link: the activity is
// resolved from it, never from enumerable ids.
$token = required_param('t', PARAM_ALPHANUMEXT);
$name = required_param('name', PARAM_TEXT);

global $DB, $CFG;
$PAGE->set_url($CFG->wwwroot . '/mod/jitsi/universal.php');
if ($token === '' || !$sesion = $DB->get_record('jitsi', ['token' => $token])) {
    throw new moodle_exception('invalidaccess', 'error');
}
$course = $DB->get_record('course', ['id' => $sesion->course], '*', MUST_EXIST);
$cm = get_coursemodule_from_instance('jitsi', $sesion->id, $course->id, false, MUST_EXIST);
$id = $cm->id;
$sessionid = $sesion->id;
$avatar = null;
if (isloggedin() && !isguestuser()) {
    $avatar = $CFG->wwwroot . '/user/pix.php/' . $USER->id . '/f1.jpg';
}
$PAGE->set_cm($cm);

$PAGE->set_context(context_module::instance($cm->id));

$accesserror = \mod_jitsi\local\invitation::get_access_error($sesion);
if ($accesserror !== null) {
    $PAGE->set_title($sesion->name);
    echo $OUTPUT->header();
    echo $OUTPUT->notification($accesserror, 'error');
    echo $OUTPUT->footer();
    die();
}

$navigator = $_SERVER['HTTP_USER_AGENT'];

$event = \mod_jitsi\event\jitsi_session_enter::create([
  'objectid' => $PAGE->cm->instance,
  'context' => $PAGE->context,
  'other' => ['navigator' => $navigator],
]);
$event->add_record_snapshot('course', $PAGE->course);
$event->add_record_snapshot($PAGE->cm->modname, $sesion);

$event->trigger();
$jitsi = $DB->get_record('jitsi', ['id' => $cm->instance]);
echo "<script>";
echo "function participating () {";
echo "  console.log(\"RUNNING\");";
echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
echo "       var respuesta = ajax.call([{\n";
echo "            methodname: 'mod_jitsi_participating_session',\n";
echo "            args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cm->id . "'},\n";
echo "       }]);\n";
echo "        console.log(respuesta[0]);";
echo "})\n";
echo "}";
echo "setInterval(participating, 60000);\n";
echo "</script>";

$fieldssessionname = get_config('mod_jitsi', 'sesionname');
$allowed = explode(',', $fieldssessionname);
$max = count($allowed);

$sesparam = '';
$optionsseparator = ['.', '-', '_', ''];
for ($i = 0; $i < $max; $i++) {
    if ($i != $max - 1) {
        if ($allowed[$i] == 0) {
            $sesparam .= \mod_jitsi\local\room::sanitize($course->shortname)
                . $optionsseparator[get_config('mod_jitsi', 'separator')];
        } else if ($allowed[$i] == 1) {
            $sesparam .= $sesion->id . $optionsseparator[get_config('mod_jitsi', 'separator')];
        } else if ($allowed[$i] == 2) {
            $sesparam .= \mod_jitsi\local\room::sanitize($sesion->name) . $optionsseparator[get_config('mod_jitsi', 'separator')];
        }
    } else {
        if ($allowed[$i] == 0) {
            $sesparam .= \mod_jitsi\local\room::sanitize($course->shortname);
        } else if ($allowed[$i] == 1) {
            $sesparam .= $sessionid;
        } else if ($allowed[$i] == 2) {
            $sesparam .= \mod_jitsi\local\room::sanitize($sesion->name);
        }
    }
}

$PAGE->set_title($sesion->name);
$PAGE->set_heading($sesion->name);

echo $OUTPUT->header();
\mod_jitsi\local\session::create(0, $id, $avatar, $name, $sesparam, null, $sesion, true, null);
if (isloggedin()) {
    echo $OUTPUT->footer();
}
