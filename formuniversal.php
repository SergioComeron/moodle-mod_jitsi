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

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php'); // phpcs:ignore moodle.Files.RequireLogin.Missing
require_once(dirname(dirname(dirname(__FILE__))) . '/lib/moodlelib.php');
require_once(dirname(__FILE__) . '/lib.php');
require_once("$CFG->libdir/formslib.php");
global $DB;

$token = required_param('t', PARAM_TEXT);

$jitsi  = $DB->get_record('jitsi', ['token' => $token], '*', MUST_EXIST);
$module = $DB->get_record('modules', ['name' => 'jitsi']);
$cm     = $DB->get_record('course_modules', ['instance' => $jitsi->id, 'module' => $module->id]);
$id     = $cm->id;

$sessionid = $cm->instance;

$PAGE->set_url($CFG->wwwroot . '/mod/jitsi/formuniversal.php');
$sesion = $DB->get_record('jitsi', ['id' => $sessionid]);

$modulecontext = context_module::instance($id);
if (isloggedin()) {
    $PAGE->set_cm($cm);
    $PAGE->set_context($modulecontext);
} else {
    $PAGE->set_context(context_system::instance());
}

$PAGE->set_title(get_string('accesstotitle', 'jitsi', $sesion->name));
$PAGE->set_heading(get_string('accesstotitle', 'jitsi', $sesion->name));

echo $OUTPUT->header();

if ($jitsi->intro && $CFG->branch < 40) {
    echo $jitsi->intro;
}

$course = $DB->get_record('course', ['id' => $cm->course]);
$event = \mod_jitsi\event\jitsi_session_guest_form::create([
  'objectid' => $cm->instance,
  'context' => $modulecontext,
]);
$event->add_record_snapshot('course', $course);
$event->add_record_snapshot('jitsi', $sesion);

$event->trigger();
if (!istimedout($sesion)) {
    if (get_config('mod_jitsi', 'invitebuttons') == 1) {
        if (!isloggedin()) {
            $today = getdate();
            if ($today[0] < $sesion->timeclose || $sesion->timeclose == 0) {
                if ($today[0] > (($sesion->timeopen) - ($sesion->minpretime * 60))) {
                    $actionurl = (new moodle_url('/mod/jitsi/universal.php', [
                        'ses' => $sessionid,
                        'id'  => $id,
                    ]))->out(false);
                    echo html_writer::start_div('d-flex justify-content-center mt-4');
                    echo html_writer::start_div('card shadow-sm', ['style' => 'max-width:420px;width:100%']);
                    echo html_writer::start_div('card-body p-4 text-center');
                    echo html_writer::tag('h4', s($sesion->name), ['class' => 'card-title mb-1']);
                    echo html_writer::tag('p', s($course->fullname), ['class' => 'text-muted small mb-4']);
                    echo html_writer::start_tag('form', ['method' => 'post', 'action' => $actionurl]);
                    echo html_writer::start_div('mb-3 text-start');
                    $labelattrs = ['for' => 'guestname', 'class' => 'form-label fw-semibold'];
                    echo html_writer::tag('label', get_string('guestname', 'jitsi'), $labelattrs);
                    $inputattrs = [
                        'type'        => 'text',
                        'name'        => 'name',
                        'id'          => 'guestname',
                        'class'       => 'form-control form-control-lg',
                        'placeholder' => get_string('guestnamePlaceholder', 'jitsi'),
                        'required'    => 'required',
                        'autofocus'   => 'autofocus',
                    ];
                    echo html_writer::empty_tag('input', $inputattrs);
                    echo html_writer::end_div();
                    $btnattrs = ['type' => 'submit', 'class' => 'btn btn-primary btn-lg w-100'];
                    echo html_writer::tag('button', get_string('guestjoin', 'jitsi'), $btnattrs);
                    echo html_writer::end_tag('form');
                    echo html_writer::end_div();
                    echo html_writer::end_div();
                    echo html_writer::end_div();
                } else {
                    $nostart = get_string(
                        'nostart',
                        'jitsi',
                        date("d-m-Y H:i", ($sesion->timeopen - ($sesion->minpretime * 60)))
                    );
                    echo $OUTPUT->notification($nostart, 'info');
                }
            } else {
                echo $OUTPUT->notification(get_string('finish', 'jitsi'), 'warning');
            }
        } else {
            $today = getdate();
            if ($today[0] > (($sesion->timeopen) - ($sesion->minpretime * 60))) {
                $nom = null;
                switch (get_config('mod_jitsi', 'jitsi_id')) {
                    case 'username':
                        $nom = $USER->username;
                        break;
                    case 'nameandsurname':
                        $nom = $USER->firstname . ' ' . $USER->lastname;
                        break;
                    case 'alias':
                        break;
                }
                $avatar = $CFG->wwwroot . '/user/pix.php/' . $USER->id . '/f1.jpg';
                $urlparams = [
                    'avatar' => $avatar,
                    'name'   => $nom,
                    'ses'    => $sessionid,
                    'mail'   => '',
                    'id'     => $id,
                ];
                $joinurl = (new moodle_url('/mod/jitsi/universal.php', $urlparams))->out(false);

                echo html_writer::start_div('d-flex justify-content-center mt-4');
                echo html_writer::start_div('card shadow-sm', ['style' => 'max-width:420px;width:100%']);
                echo html_writer::start_div('card-body p-4 text-center');
                echo html_writer::tag('h4', s($sesion->name), ['class' => 'card-title mb-1']);
                echo html_writer::tag('p', s($course->fullname), ['class' => 'text-muted small mb-3']);
                echo html_writer::empty_tag('img', [
                    'src'   => s($avatar),
                    'class' => 'rounded-circle mb-2',
                    'style' => 'width:56px;height:56px;object-fit:cover',
                    'alt'   => s($nom),
                ]);
                echo html_writer::tag('p', s($nom), ['class' => 'fw-semibold mb-3']);
                echo html_writer::start_tag('form', ['method' => 'post', 'action' => $joinurl]);
                $btnattrs = ['type' => 'submit', 'class' => 'btn btn-primary btn-lg w-100'];
                echo html_writer::tag('button', get_string('guestjoin', 'jitsi'), $btnattrs);
                echo html_writer::end_tag('form');
                echo html_writer::end_div();
                echo html_writer::end_div();
                echo html_writer::end_div();
            } else {
                $nostart = get_string(
                    'nostart',
                    'jitsi',
                    date("d-m-Y H:i", ($sesion->timeopen - ($sesion->minpretime * 60)))
                );
                echo $OUTPUT->notification($nostart, 'info');
            }
        }
    } else {
        echo get_string('noinviteaccess', 'jitsi');
    }
} else {
    echo "<div class=\"alert alert-danger\" role=\"alert\">";
    echo generateerrortime($sesion);
    echo "</div>";
}
echo '<p></p>';
echo get_config('mod_jitsi', 'help');

if (isloggedin()) {
    echo $OUTPUT->footer();
}
