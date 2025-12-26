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
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');
require_once('view_table.php');
require_once($CFG->libdir . '/formslib.php');

/**
 * Form to Search for an Attendee’s Minutes on a Specific Day .
 *
 * @package   mod_jitsi
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <info@sergiocomeron.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class datesearchattendees_form extends moodleform {
    /**
     * Defines forms elements
     */
    public function definition() {
        $mform = $this->_form;

        // Campo oculto para el ID del curso.
        $mform->addElement('hidden', 'id', $this->_customdata['id']);
        $mform->setType('id', PARAM_INT);
        $mform->addElement('hidden', 'sesskey', sesskey());
        $mform->setType('sesskey', PARAM_RAW);
        $mform->addElement('hidden', 'generateusersconnected', 1);
        $mform->setType('generateusersconnected', PARAM_BOOL);
        $mform->addElement('hidden', 'tab', 'attendees');
        $mform->setType('tab', PARAM_TEXT);

        // Selector de fecha (solo día) para la búsqueda.
        $defaultdate = [
            'year' => date('Y'),
            'month' => date('n'),
            'day' => date('j'),
        ];
        $mform->addElement('date_selector', 'selecteddate', get_string('selectdate', 'jitsi'), [
            'defaulttime' => $defaultdate,
        ]);
        $mform->setType('selecteddate', PARAM_INT);

        // Botón de envío.
        $buttonarray = [];
        $buttonarray[] = $mform->createElement('submit', 'submitbutton', get_string('search', 'jitsi'));
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
        // Validación personalizada si se necesita.
        return [];
    }
}
// Allow CORS requests.
header('Access-Control-Allow-Origin: *');

global $USER;

$id = optional_param('id', 0, PARAM_INT);
$n = optional_param('n', 0, PARAM_INT);
$state = optional_param('state', null, PARAM_TEXT);
$deletejitsirecordid = optional_param('deletejitsirecordid', 0, PARAM_INT);
$hidejitsirecordid = optional_param('hidejitsirecordid', 0, PARAM_INT);
$showjitsirecordid = optional_param('showjitsirecordid', 0, PARAM_INT);
$selecteddate = optional_param_array('selecteddate', 0, PARAM_INT);
$tab = optional_param('tab', 'help', PARAM_TEXT);
$activetab = $tab;

if (is_array($selecteddate) &&
    isset($selecteddate['year']) && isset($selecteddate['month']) && isset($selecteddate['day']) &&
    $selecteddate['year'] > 0 && $selecteddate['month'] > 0 && $selecteddate['day'] > 0) {
    $selecteddate = make_timestamp(
        $selecteddate['year'],
        $selecteddate['month'],
        $selecteddate['day']
    );
} else {
    $selecteddate = time();
}
if ($id) {
    $cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
    $course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
    $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);
    $sesskey = optional_param('sesskey', null, PARAM_TEXT);
} else if ($n) {
    $jitsi = $DB->get_record('jitsi', ['id' => $n], '*', MUST_EXIST);
    $course = $DB->get_record('course', ['id' => $jitsi->course], '*', MUST_EXIST);
    $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
} else if ($state) {
    $paramdecode = base64urldecode($state);
    $parametrosarray = explode("&", $paramdecode);
    $idarray = $parametrosarray[0];
    $deletejitsirecordidarray = $parametrosarray[1];
    $hidejitsirecordidarray = $parametrosarray[2];
    $showjitsirecordidarray = $parametrosarray[3];
    $sesskeyarray = $parametrosarray[4];
    $statesesarray = $parametrosarray[5];
    $ida = explode("=", $idarray);
    $deletejitsirecordida = explode("=", $deletejitsirecordidarray);
    $hidejitsirecordida = explode("=", $hidejitsirecordidarray);
    $showjitsirecordida = explode("=", $showjitsirecordidarray);
    $sesskeya = explode("=", $sesskeyarray);
    $statesesa = explode("=", $statesesarray);
    $id = $ida[1];
    $deletejitsirecordid = $deletejitsirecordida[1];
    $hidejitsirecordid = $hidejitsirecordida[1];
    $showjitsirecordid = $showjitsirecordida[1];
    $sesskey = $sesskeya[1];
    $stateses = $statesesa[1];
    $cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
    $course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
    $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);
} else {
    throw new \moodle_exception('Unable to find jitsi');
}

require_login($course, true, $cm);
$event = \mod_jitsi\event\course_module_viewed::create([
  'objectid' => $PAGE->cm->instance,
  'context' => $PAGE->context,
]);

$event->add_record_snapshot('course', $PAGE->course);
$event->add_record_snapshot($PAGE->cm->modname, $jitsi);
$event->trigger();
$PAGE->set_url('/mod/jitsi/view.php', ['id' => $cm->id]);

$PAGE->set_title(format_string($jitsi->name));
$PAGE->set_heading(format_string($course->fullname));

if ($deletejitsirecordid && confirm_sesskey($sesskey)) {
    marktodelete($deletejitsirecordid, 1);
    $record = $DB->get_record('jitsi_record', ['id' => $deletejitsirecordid]);
    $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
    $event = \mod_jitsi\event\jitsi_delete_record::create([
        'objectid' => $PAGE->cm->instance,
        'context' => $PAGE->context,
        'other' => ['record' => $deletejitsirecordid, 'link' => $source->link],
    ]);
    $event->add_record_snapshot('course', $PAGE->course);
    $event->add_record_snapshot($PAGE->cm->modname, $jitsi);
    $event->trigger();

    redirect($PAGE->url, get_string('deleted'));
}

if ($hidejitsirecordid && confirm_sesskey($sesskey)) {
    $record = $DB->get_record('jitsi_record', ['id' => $hidejitsirecordid]);
    $record->visible = 0;
    $DB->update_record('jitsi_record', $record);
    redirect($PAGE->url, get_string('updated', 'jitsi'));
}

if ($showjitsirecordid && confirm_sesskey($sesskey)) {
    $record = $DB->get_record('jitsi_record', ['id' => $showjitsirecordid]);
    $record->visible = 1;
    $DB->update_record('jitsi_record', $record);
    redirect($PAGE->url, get_string('updated', 'jitsi'));
}

$context = context_module::instance($cm->id);

$cm = get_coursemodule_from_id('jitsi', $id);
$cminfo = \cm_info::create($cm);

if (!has_capability('mod/jitsi:view', $context)) {
    notice(get_string('noviewpermission', 'jitsi'));
}
$courseid = $course->id;
$context = context_course::instance($courseid);
$roles = get_user_roles($context, $USER->id);

$rolestr[] = null;
foreach ($roles as $role) {
    $rolestr[] = $role->shortname;
}

$moderation = false;
if (has_capability('mod/jitsi:moderation', $context)) {
    $moderation = true;
}

$nom = null;
switch (get_config('mod_jitsi', 'id')) {
    case 'username':
        $nom = $USER->username;
        break;
    case 'nameandsurname':
        $nom = $USER->firstname . ' ' . $USER->lastname;
        break;
    case 'alias':
        break;
}
$sessionoptionsparam = ['$course->shortname', '$jitsi->id', '$jitsi->name'];
$fieldssessionname = get_config('mod_jitsi', 'sesionname');

$allowed = explode(',', $fieldssessionname);
$max = count($allowed);

$sesparam = '';

$errorborrado = false;
if ($jitsi->sessionwithtoken == 0) {
    $courseshortname = $course->shortname;
    $jitsiid = $jitsi->id;
    $jitsiname = $jitsi->name;
} else {
    $sql = "select * from {jitsi} where tokeninterno = '" . $jitsi->tokeninvitacion . "'";
    $jitsiinvitado = $DB->get_record_sql($sql);
    if ($jitsiinvitado != null) {
        $courseinvitado = $DB->get_record('course', ['id' => $jitsiinvitado->course]);
        $courseshortname = $courseinvitado->shortname;
        $jitsiid = $jitsiinvitado->id;
        $jitsiname = $jitsiinvitado->name;
    } else {
        $errorborrado = true;
    }
}

if ($errorborrado == false) {
    $optionsseparator = ['.', '-', '_', ''];
    for ($i = 0; $i < $max; $i++) {
        if ($i != $max - 1) {
            if ($allowed[$i] == 0) {
                $sesparam .= string_sanitize($courseshortname) . $optionsseparator[get_config('mod_jitsi', 'separator')];
            } else if ($allowed[$i] == 1) {
                $sesparam .= $jitsiid . $optionsseparator[get_config('mod_jitsi', 'separator')];
            } else if ($allowed[$i] == 2) {
                $sesparam .= string_sanitize($jitsiname) . $optionsseparator[get_config('mod_jitsi', 'separator')];
            }
        } else {
            if ($allowed[$i] == 0) {
                $sesparam .= string_sanitize($courseshortname);
            } else if ($allowed[$i] == 1) {
                $sesparam .= $jitsiid;
            } else if ($allowed[$i] == 2) {
                $sesparam .= string_sanitize($jitsiname);
            }
        }
    }
    $avatar = $CFG->wwwroot . '/user/pix.php/' . $USER->id . '/f1.jpg';
    $urlparams = [
        'avatar' => $avatar,
        'nom' => $nom,
        'ses' => $sesparam,
        'courseid' => $course->id,
        'cmid' => $id,
        't' => $moderation,
    ];
    $today = getdate();
}

if (!$deletejitsirecordid) {
    echo $OUTPUT->header();
}

$cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
update_completition($cm);
if ($CFG->branch == 311) {
    if (!$deletejitsirecordid) {
        echo $OUTPUT->heading($jitsi->name);
    }
    $completiondetails = \core_completion\cm_completion_details::get_instance($cminfo, $USER->id);
    $activitydates = \core\activity_dates::get_dates_for_module($cminfo, $USER->id);
    echo $OUTPUT->activity_information($cminfo, $completiondetails, $activitydates);
}

$contextmodule = context_module::instance($cm->id);

$sqllastparticipating = 'select timecreated from {logstore_standard_log} where contextid = '
    . $contextmodule->id . ' and (action = \'participating\' or action = \'enter\') order by timecreated DESC limit 1';
$usersconnected = $DB->get_record_sql($sqllastparticipating);
if ($usersconnected != null) {
    if ((getdate()[0] - $usersconnected->timecreated) > 72) {
        $jitsi->numberofparticipants = 0;
        $DB->update_record('jitsi', $jitsi);
    }
}
if ($usersconnected != null) {
    if ($jitsi->numberofparticipants == 0 && (getdate()[0] - $usersconnected->timecreated) > 72) {
        $jitsi->sourcerecord = null;
        $DB->update_record('jitsi', $jitsi);
    }
}
if ($errorborrado) {
    echo "<div class=\"alert alert-danger\" role=\"alert\">";

    echo get_string('sessiondeleted', 'jitsi');
    echo "</div>";
    echo $OUTPUT->footer();
    die();
}
echo " ";
echo "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" fill=\"currentColor\"
     class=\"bi bi-person-workspace\" viewBox=\"0 0 16 16\">";
echo "<path d=\"M4 16s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1H4Zm4-5.95a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z\"/>";
echo "<path d=\"M2 1a2 2 0 0 0-2 2v9.5A1.5 1.5 0 0 0 1.5 14h.653a5.373 5.373 0 0 1 1.066-2H1V3a1 1 0 0 1 1-1h12a1 1 0 0 1
     1 1v9h-2.219c.554.654.89 1.373 1.066 2h.653a1.5 1.5 0 0 0 1.5-1.5V3a2 2 0 0 0-2-2H2Z\"/>";
echo "</svg>";
echo (" " . $jitsi->numberofparticipants . " " . get_string('connectedattendeesnow', 'jitsi'));
echo "<p></p>";
if ($jitsi->sessionwithtoken) {
    echo "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" fill=\"currentColor\"
        class=\"bi bi-share\" viewBox=\"0 0 16 16\">";
    echo "<path d=\"M13.5 1a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zM11 2.5a2.5 2.5 0 1 1 .603 1.628l-6.718 3.12a2.499 2.499 0 0 1
        0 1.504l6.718 3.12a2.5 2.5 0 1 1-.488.876l-6.718-3.12a2.5 2.5 0 1 1 0-3.256l6.718-3.12A2.5 2.5 0 0 1 11 2.5zm-8.5 4a1.5
        1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3zm11 5.5a1.5 1.5 0 1 0 0 3 1.5 1.5 0 0 0 0-3z\"/>";
    echo "</svg> ";
    $sql = "select * from {jitsi} where tokeninterno = '" . $jitsi->tokeninvitacion . "'";
    $jitsimaster = $DB->get_record_sql($sql);
    $coursemaster = $DB->get_record('course', ['id' => $jitsimaster->course]);
    echo get_string('sessionshared', 'jitsi', $coursemaster->shortname);
    echo "<p></p>";
}

if ($jitsi->sourcerecord != null) {
    $source = $DB->get_record('jitsi_source_record', ['id' => $jitsi->sourcerecord]);
    if ($source) {
        $author = $DB->get_record('user', ['id' => $source->userid]);
        if ($author) {
            echo "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"16\" height=\"16\" fill=\"red\"
                class=\"bi bi-record-circle\" viewBox=\"0 0 16 16\">";
            echo "<path d=\"M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z\"/>";
            echo "<path d=\"M11 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0z\"/>";
            echo "</svg> ";
            echo addslashes(get_string('sessionisbeingrecordingby', 'jitsi', $author->firstname . " " . $author->lastname));
        } else {
            // Source exists but author doesn't, clean up the reference.
            $jitsi->sourcerecord = null;
            $DB->update_record('jitsi', $jitsi);
        }
    } else {
        // Source record doesn't exist, clean up the reference.
        $jitsi->sourcerecord = null;
        $DB->update_record('jitsi', $jitsi);
    }
}
echo "<p></p>";
echo get_string('minutesconnected', 'jitsi', getminutes($id, $USER->id));

if ($CFG->branch <= 311) {
    if ($jitsi->intro) {
        echo $OUTPUT->box(format_module_intro('jitsi', $jitsi, $cm->id), 'generalbox mod_introbox', 'jitsiintro');
    }
}

$fechacierre = $jitsi->timeclose;
$fechainicio = $jitsi->timeopen;

if ($jitsi->sessionwithtoken == 1) {
    $fechacierre = $jitsiinvitado->timeclose;
    $fechainicio = $jitsiinvitado->timeopen;
}

if ($today[0] < $fechacierre || $fechacierre == 0) {
    if (
        $today[0] > (($fechainicio)) ||
        has_capability('mod/jitsi:moderation', $context) && $today[0] > (($jitsi->timeopen) - ($jitsi->minpretime * 60))
    ) {
        echo "<br><br>";
        $button = new moodle_url('/mod/jitsi/session.php', $urlparams);
        $options = [
            'class' => 'btn btn-primary',
            'title' => get_string('access', 'jitsi'),
        ];
        $boton = \html_writer::link($button, get_string('access', 'jitsi'), $options);
        echo $boton;
    } else {
        echo $OUTPUT->box(get_string('nostart', 'jitsi', userdate($jitsi->timeopen)));
    }
} else {
    echo $OUTPUT->box(get_string('finish', 'jitsi'));
}

echo "<br><br>";

$sql = 'select * from {jitsi_record} where jitsi = ' . $jitsiid . ' and deleted = 0 order by id desc';
$records = $DB->get_records_sql($sql);

if (has_capability('mod/jitsi:viewusersonsession', $PAGE->context)) {
    $sqlusersconnected = 'SELECT DISTINCT userid FROM {logstore_standard_log}
    WHERE contextid = :contextid AND action = \'participating\'';
    $params = ['contextid' => $contextmodule->id];
    $usersconnected = $DB->get_records_sql($sqlusersconnected, $params);
}

echo "<ul class=\"nav nav-tabs\" id=\"myTab\" role=\"tablist\">";

    echo "  <li class=\"nav-item\">";
    echo "    <a class=\"nav-link " . ($activetab == 'help' ? 'active' : '') .
        "\" id=\"help-tab\" " . ($CFG->branch >= 500 ? 'data-bs-toggle' : 'data-toggle') . "=\"tab\" href=\"#help\"
         role=\"tab\" aria-controls=\"help\" aria-selected=\"" .
         ($activetab == 'help' ? 'true' : 'false') . "\">" . get_string('help') . "</a>";
    echo "  </li>";

if (has_capability('mod/jitsi:viewrecords', $PAGE->context)) {
    if (
        ($records && isallvisible($records)) ||
        (has_capability('mod/jitsi:record', $PAGE->context) && $records) ||
        get_config('mod_jitsi', 'streamingoption') == 1
    ) {
        echo "  <li class=\"nav-item\">";
        echo "    <a class=\"nav-link " . ($activetab == 'record' ? 'active' : '') .
            "\" id=\"record-tab\" " . ($CFG->branch >= 500 ? 'data-bs-toggle' : 'data-toggle') . "=\"tab\" href=\"#record\"
            role=\"tab\" aria-controls=\"record\" aria-selected=\"" .
            ($activetab == 'record' ? 'true' : 'false') . "\">" . get_string('records', 'jitsi') . "</a>";
        echo "  </li>";
    }
}

if (has_capability('mod/jitsi:viewusersonsession', $PAGE->context)) {
    if ($usersconnected) {
        echo "  <li class=\"nav-item\">";
        echo "    <a class=\"nav-link " . ($activetab == 'attendees' ? 'active' : '') .
            "\" id=\"attendees-tab\" " . ($CFG->branch >= 500 ? 'data-bs-toggle' : 'data-toggle') . "=\"tab\" href=\"#attendees\"
            role=\"tab\" aria-controls=\"attendees\" aria-selected=\"" .
            ($activetab == 'attendees' ? 'true' : 'false') . "\">" .
            get_string('attendeesreport', 'jitsi') . "</a>";
        echo "  </li>";
    }
}

echo "</ul>";

echo "<div class=\"tab-content\" id=\"myTabContent\">";
    echo "  <div class=\"tab-pane fade " .
    ($activetab == 'help' ? 'show active' : '') .
    "\" id=\"help\" role=\"tabpanel\" aria-labelledby=\"help-tab\">";
if (get_config('mod_jitsi', 'help') != null) {
    echo "  <br>";
    echo get_config('mod_jitsi', 'help');
} else {
    echo "  <br>";
    echo $OUTPUT->box(get_string('instruction', 'jitsi'));
}
echo "  </div>";

if (has_capability('mod/jitsi:viewrecords', $PAGE->context)) {
    echo "  <div class=\"tab-pane fade " . ($activetab == 'record' ? 'show active' : '') .
        "\" id=\"record\" role=\"tabpanel\" aria-labelledby=\"record-tab\">";
    if ($records) {
        $table = new mod_view_table('search');
        $fields = '{jitsi_record}.id,
                   {jitsi_source_record}.link,
                   {jitsi_record}.jitsi,
                   {jitsi_record}.name,
                   {jitsi_source_record}.timecreated';
        $from = '{jitsi_record}, {jitsi_source_record}';
        $where = '{jitsi_record}.source = {jitsi_source_record}.id AND
                  {jitsi_record}.jitsi = ' . $jitsiid . ' and
                  {jitsi_record}.deleted = 0';
        if (!has_capability('mod/jitsi:hide', $context)) {
            $where .= ' AND {jitsi_record}.visible = 1';
        }
        $params = ['jitsiid' => $jitsi->id];
        $table->set_sql($fields, $from, $where, $params);
        $table->sortable(true, 'id', SORT_DESC);
        $table->define_baseurl('/mod/jitsi/view.php?id=' . $id . '&tab=record');
        $table->out(5, true);
    } else {
        echo "<br>";
        echo get_string('norecords', 'jitsi');
    }
    echo "  </div>";
}

    echo "  <div class=\"tab-pane fade " . ($activetab == 'attendees' ? 'show active' : '') .
        "\" id=\"attendees\" role=\"tabpanel\" aria-labelledby=\"attendees-tab\">";
    echo "<br>";

    $form = new datesearchattendees_form(null, ['id' => $id]);
    $form->display();

if (has_capability('mod/jitsi:viewusersonsession', $PAGE->context)) {
    $generateusersconnected = optional_param('generateusersconnected', 0, PARAM_BOOL);
    if ($generateusersconnected && confirm_sesskey()) {
        require_sesskey();
        $sqlusersconnected = 'SELECT DISTINCT userid FROM {logstore_standard_log}
                              WHERE contextid = :contextid AND action = \'participating\'';
        $params = ['contextid' => $contextmodule->id];
        $usersconnected = $DB->get_records_sql($sqlusersconnected, $params);

        $table = new html_table();
        $table->head = [
            get_string('name'),
            get_string('minutesday', 'jitsi') . ': ' . userdate($selecteddate, '%A %d %B %Y'),
            get_string('totalminutes', 'jitsi'),
        ];
        $table->data = [];

        if ($usersconnected) {
            $userids = [];
            foreach ($usersconnected as $userconnected) {
                if ($userconnected->userid != 0) {
                    $userids[] = $userconnected->userid;
                }
            }

            $users = $DB->get_records_list('user', 'id', $userids);
            foreach ($users as $user) {
                $urluser = new moodle_url('/user/profile.php', ['id' => $user->id]);
                $table->data[] = [
                    html_writer::link(
                        $urluser,
                        fullname($user),
                        [
                            'data-toggle' => 'tooltip',
                            'data-placement' => 'top',
                            'title' => $user->username,
                        ]
                    ),
                        getminutesdates($id, $user->id, $selecteddate, $selecteddate + DAYSECS),
                        getminutes($id, $user->id),
                ];
            }

            echo html_writer::table($table);
        }
    }
}

    echo "  </div>";

echo "</div>";

echo "<hr>";
echo $OUTPUT->footer();
