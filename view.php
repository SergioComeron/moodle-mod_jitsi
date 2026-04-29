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

// Allow CORS requests.
header('Access-Control-Allow-Origin: *');

global $USER;

$id = optional_param('id', 0, PARAM_INT);
$n = optional_param('n', 0, PARAM_INT);
$state = optional_param('state', null, PARAM_TEXT);
$deletejitsirecordid = optional_param('deletejitsirecordid', 0, PARAM_INT);
$hidejitsirecordid = optional_param('hidejitsirecordid', 0, PARAM_INT);
$showjitsirecordid = optional_param('showjitsirecordid', 0, PARAM_INT);
$addrecordlink = optional_param('addrecordlink', 0, PARAM_INT);
$editrecordid = optional_param('editrecordid', 0, PARAM_INT);
$saverecordedit = optional_param('saverecordedit', 0, PARAM_INT);
$selecteddate = optional_param_array('selecteddate', 0, PARAM_INT);
$tab = optional_param('tab', 'help', PARAM_TEXT);
$activetab = $tab;

if (
    is_array($selecteddate) &&
    isset($selecteddate['year']) && isset($selecteddate['month']) && isset($selecteddate['day']) &&
    $selecteddate['year'] > 0 && $selecteddate['month'] > 0 && $selecteddate['day'] > 0
) {
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
    $sesparam = jitsi_build_room_name(
        $courseshortname,
        $jitsiid,
        $jitsiname,
        get_config('mod_jitsi', 'sesionname'),
        get_config('mod_jitsi', 'separator')
    );
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

if ($addrecordlink && !$errorborrado && confirm_sesskey()) {
    require_capability('mod/jitsi:record', context_module::instance($cm->id));
    $recordingurl = optional_param('recordingurl', '', PARAM_URL);
    $recordingname = optional_param('recordingname', '', PARAM_TEXT);
    $embedrecording = optional_param('embedrecording', 0, PARAM_INT);
    if (!empty($recordingurl)) {
        $sourcerecord = new stdClass();
        $sourcerecord->link = $recordingurl;
        $sourcerecord->account = null;
        $sourcerecord->timecreated = time();
        $sourcerecord->userid = $USER->id;
        $sourcerecord->embed = (strpos($recordingurl, 'dropbox.com') !== false) ? $embedrecording : 0;
        $sourcerecord->maxparticipants = 0;
        $sourcerecord->type = 1;
        $sourcerecord->id = $DB->insert_record('jitsi_source_record', $sourcerecord);

        $record = new stdClass();
        $record->jitsi = $jitsiid;
        $record->deleted = 0;
        $record->source = $sourcerecord->id;
        $record->visible = 1;
        $record->name = empty($recordingname) ? userdate(time()) : $recordingname;
        $DB->insert_record('jitsi_record', $record);

        $redirecturl = new moodle_url('/mod/jitsi/view.php', ['id' => $id, 'tab' => 'record']);
        redirect($redirecturl, get_string('recordinglinksaved', 'jitsi'));
    }
}

if ($saverecordedit && !$errorborrado && confirm_sesskey()) {
    require_capability('mod/jitsi:record', context_module::instance($cm->id));
    $editingrecordid = optional_param('editingrecordid', 0, PARAM_INT);
    $recordingurl = optional_param('recordingurl', '', PARAM_URL);
    $recordingname = optional_param('recordingname', '', PARAM_TEXT);
    $embedrecording = optional_param('embedrecording', 0, PARAM_INT);
    if ($editingrecordid && !empty($recordingurl)) {
        $record = $DB->get_record('jitsi_record', ['id' => $editingrecordid], '*', MUST_EXIST);
        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        if ($sourcerecord->type == 1) {
            $sourcerecord->link = $recordingurl;
            $sourcerecord->embed = (strpos($recordingurl, 'dropbox.com') !== false) ? $embedrecording : 0;
            $DB->update_record('jitsi_source_record', $sourcerecord);
            $record->name = empty($recordingname) ? userdate($sourcerecord->timecreated) : $recordingname;
            $DB->update_record('jitsi_record', $record);
        }
        $redirecturl = new moodle_url('/mod/jitsi/view.php', ['id' => $id, 'tab' => 'record']);
        redirect($redirecturl, get_string('updated', 'jitsi'));
    }
}

if (has_capability('mod/jitsi:viewattendance', $PAGE->context)) {
    $reporturl = new moodle_url('/mod/jitsi/attendancereport.php', ['id' => $id]);
    $PAGE->secondarynav->add(
        get_string('attendancereport', 'jitsi'),
        $reporturl,
        \core\navigation\views\secondary::TYPE_SETTING
    );
    $dashboardurl = new moodle_url('/mod/jitsi/coursedashboard.php', ['id' => $id]);
    $PAGE->secondarynav->add(
        get_string('coursedashboard', 'jitsi'),
        $dashboardurl,
        \core\navigation\views\secondary::TYPE_SETTING
    );
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

$sqlrecords = 'SELECT r.id FROM {jitsi_record} r
    JOIN {jitsi_source_record} s ON s.id = r.source
    WHERE r.jitsi = :jitsiid AND r.deleted = 0
    AND (s.timeexpires = 0 OR s.timeexpires > :now)';
$recordsparams = ['jitsiid' => $jitsiid, 'now' => time()];
$records = $DB->record_exists_sql($sqlrecords, $recordsparams);
$hasvisiblerecords = $DB->record_exists_sql($sqlrecords . ' AND r.visible = 1', $recordsparams);

echo "<ul class=\"nav nav-tabs\" id=\"myTab\" role=\"tablist\">";

    echo "  <li class=\"nav-item\">";
    echo "    <a class=\"nav-link " . ($activetab == 'help' ? 'active' : '') .
        "\" id=\"help-tab\" " . ($CFG->branch >= 500 ? 'data-bs-toggle' : 'data-toggle') . "=\"tab\" href=\"#help\"
         role=\"tab\" aria-controls=\"help\" aria-selected=\"" .
         ($activetab == 'help' ? 'true' : 'false') . "\">" . get_string('help') . "</a>";
    echo "  </li>";

if (has_capability('mod/jitsi:viewrecords', $PAGE->context) || has_capability('mod/jitsi:record', $PAGE->context)) {
    if (
        $hasvisiblerecords ||
        has_capability('mod/jitsi:record', $PAGE->context) ||
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

if (has_capability('mod/jitsi:viewrecords', $PAGE->context) || has_capability('mod/jitsi:record', $PAGE->context)) {
    echo "  <div class=\"tab-pane fade " . ($activetab == 'record' ? 'show active' : '') .
        "\" id=\"record\" role=\"tabpanel\" aria-labelledby=\"record-tab\">";
    echo "<div id=\"jitsi-recordings-content\"></div>";
    echo "  </div>";

    $recordingstaburl = (new moodle_url('/mod/jitsi/recordingstab.php', [
        'id'           => $id,
        'editrecordid' => $editrecordid,
    ]))->out(false);

    $PAGE->requires->js_amd_inline("
        require(['core/first'], function() {
            var container = document.getElementById('jitsi-recordings-content');
            var loaded = false;

            function initDropboxToggle() {
                var urlInput = document.getElementById('recordingurl');
                if (!urlInput) { return; }
                urlInput.addEventListener('input', function() {
                    var isDropbox = this.value.indexOf('dropbox.com') !== -1;
                    var embedOpt = document.getElementById('dropboxembedoption');
                    if (embedOpt) { embedOpt.style.display = isDropbox ? 'block' : 'none'; }
                    var embedChk = document.getElementById('embedrecording');
                    if (embedChk && !isDropbox) { embedChk.checked = false; }
                });
            }

            function loadRecordings() {
                if (loaded) { return; }
                loaded = true;
                container.innerHTML = '<div class=\"text-center p-3\">' +
                    '<div class=\"spinner-border\" role=\"status\"></div></div>';
                var params = new URLSearchParams(window.location.search);
                params.delete('tab');
                var url = " . json_encode($recordingstaburl) . ";
                var sep = url.indexOf('?') === -1 ? '?' : '&';
                var extra = params.toString();
                if (extra) { url += sep + extra; }
                fetch(url, {credentials: 'same-origin'})
                    .then(function(r) { return r.text(); })
                    .then(function(html) {
                        container.innerHTML = html;
                        initDropboxToggle();
                        // Notify Moodle that new content has been added so
                        // components like inplace_editable can re-initialise.
                        require(['core/inplace_editable'], function() {});
                    });
            }

            var recordPane = document.getElementById('record');
            if (recordPane && recordPane.classList.contains('active')) {
                loadRecordings();
            }

            var tab = document.getElementById('record-tab');
            if (tab) {
                tab.addEventListener('shown.bs.tab', loadRecordings);
            }
        });
    ");
}


echo "</div>";

echo "<hr>";

// JS for AI dropdown + transcript timestamps.
$PAGE->requires->strings_for_js(
    ['aisummaryqueued', 'aiquizqueued', 'aitranscriptionqueued', 'aigdprnoticetitle'],
    'mod_jitsi'
);
if (get_config('mod_jitsi', 'aienabled')) {
    $gdprregion = get_config('mod_jitsi', 'vertexairegion') ?: 'us-central1';
    $gdprbody   = json_encode('<p>' . get_string('aigdprnotice', 'jitsi', s($gdprregion)) . '</p>');
    $PAGE->requires->js_amd_inline("
require(['core/ajax', 'core/notification'], function(Ajax, Notification) {

    var gdprBody = $gdprbody;
    var queuedMap = {
        'mod_jitsi_queue_ai_summary':       'aisummaryqueued',
        'mod_jitsi_queue_ai_quiz':          'aiquizqueued',
        'mod_jitsi_queue_ai_transcription': 'aitranscriptionqueued'
    };

    function executeAction(action) {
        action.el.classList.add('disabled');
        Ajax.call([{
            methodname: action.methodname,
            args: {sourcerecordid: action.sourcerecordid, cmid: action.cmid},
            done: function(result) {
                if (result.success) {
                    action.el.textContent =
                        M.util.get_string(queuedMap[action.methodname], 'mod_jitsi');
                } else {
                    action.el.classList.remove('disabled');
                }
            },
            fail: function(ex) {
                Notification.exception(ex);
                action.el.classList.remove('disabled');
            }
        }]);
    }

    function showGdprModal(action) {
        // Load modal modules lazily so a load error doesn't break the click handler.
        require(['core/modal_factory', 'core/modal_events'],
            function(ModalFactory, ModalEvents) {
                ModalFactory.create({
                    type:  ModalFactory.types.SAVE_CANCEL,
                    title: M.util.get_string('aigdprnoticetitle', 'mod_jitsi'),
                    body:  gdprBody
                }).done(function(modal) {
                    modal.setSaveButtonText(M.util.get_string('confirm', 'core'));
                    var root = modal.getRoot();
                    root.on(ModalEvents.save, function() {
                        modal.destroy();
                        executeAction(action);
                    });
                    root.on(ModalEvents.cancel, function() { modal.destroy(); });
                    modal.show();
                });
            },
            function() {
                // Fallback: native browser confirm if modal modules unavailable.
                var plainText = gdprBody.replace(/<[^>]+>/g, '');
                if (window.confirm(plainText)) {
                    executeAction(action);
                }
            }
        );
    }

    document.addEventListener('click', function(e) {
        var generateItem = e.target.closest('.jitsi-ai-generate');
        if (generateItem) {
            e.preventDefault();
            showGdprModal({
                methodname:     generateItem.dataset.method,
                sourcerecordid: parseInt(generateItem.dataset.sourcerecordid, 10),
                cmid:           parseInt(generateItem.dataset.cmid, 10),
                el:             generateItem
            });
            return;
        }

        var tsLink = e.target.closest('.jitsi-transcript-ts');
        if (tsLink) {
            e.preventDefault();
            var videoId = tsLink.dataset.video;
            var seconds = parseFloat(tsLink.dataset.seconds);
            var video = document.getElementById(videoId);
            if (video) {
                video.currentTime = seconds;
                video.play();
                video.scrollIntoView({behavior: 'smooth', block: 'center'});
            }
        }
    });
});
");
}

// Track GCS recording views with real segment tracking.
$PAGE->requires->js_amd_inline("
require(['core/ajax'], function(Ajax) {
    var trackers     = {};
    var linkClicked  = {};

    function mergeSegments(segs) {
        if (!segs.length) { return []; }
        var sorted = segs.slice().sort(function(a, b) { return a[0] - b[0]; });
        var merged = [sorted[0].slice()];
        for (var i = 1; i < sorted.length; i++) {
            var last = merged[merged.length - 1];
            if (sorted[i][0] <= last[1]) {
                last[1] = Math.max(last[1], sorted[i][1]);
            } else {
                merged.push(sorted[i].slice());
            }
        }
        return merged;
    }

    function updateBar(sourcerecordid, segments, duration) {
        var bar   = document.getElementById('jitsi-segbar-' + sourcerecordid);
        var label = document.getElementById('jitsi-segbar-pct-' + sourcerecordid);
        if (!bar || !duration) { return; }
        var html = '';
        var watched = 0;
        segments.forEach(function(seg) {
            var left  = (seg[0] / duration) * 100;
            var width = ((seg[1] - seg[0]) / duration) * 100;
            watched  += seg[1] - seg[0];
            html += '<div style=\"position:absolute;left:' + left.toFixed(2)
                + '%;width:' + width.toFixed(2)
                + '%;height:100%;background:#0d6efd\"></div>';
        });
        bar.innerHTML = html;
        if (label) {
            label.textContent = Math.min(100, Math.round((watched / duration) * 100)) + '%';
        }
    }

    function getDuration(video, t) {
        var d = video.duration;
        return (d && isFinite(d)) ? d : (t.duration || 0);
    }

    function saveSegments(video) {
        var key = video.dataset.sourcerecordid + '_' + video.dataset.cmid;
        var t = trackers[key];
        var dur = getDuration(video, t);
        if (!t || !t.segments.length || !dur) { return; }
        var merged = mergeSegments(t.segments.slice());
        Ajax.call([{
            methodname: 'mod_jitsi_save_recording_segments',
            args: {
                sourcerecordid: parseInt(video.dataset.sourcerecordid, 10),
                cmid:           parseInt(video.dataset.cmid, 10),
                segments:       JSON.stringify(merged),
                duration:       dur
            }
        }])[0].then(function(result) {
            if (result.success && result.segments) {
                t.segments = JSON.parse(result.segments);
                updateBar(video.dataset.sourcerecordid, t.segments, getDuration(video, t));
            }
        });
    }

    function setupTracking(video) {
        var key = video.dataset.sourcerecordid + '_' + video.dataset.cmid;
        if (trackers[key]) { return; }
        // Seed existing segments from the server-rendered bar so the bar
        // stays accurate during playback without waiting for the next save.
        var wrap = document.getElementById('jitsi-segbar-wrap-' + video.dataset.sourcerecordid);
        var seedSegs = (wrap && wrap.dataset.segments) ? JSON.parse(wrap.dataset.segments) : [];
        var seedDur  = (wrap && wrap.dataset.duration) ? parseFloat(wrap.dataset.duration) : 0;
        trackers[key] = {segments: seedSegs, segStart: null, lastTime: 0, saveTimer: null, played: false, duration: seedDur};
        var t = trackers[key];

        // Capture duration from metadata and update the bar immediately —
        // this fixes the case where duration was stored as 0 in the DB.
        video.addEventListener('loadedmetadata', function() {
            if (video.duration && isFinite(video.duration)) {
                t.duration = video.duration;
                if (t.segments.length) {
                    updateBar(video.dataset.sourcerecordid, mergeSegments(t.segments), t.duration);
                }
            }
        });
        // If metadata is already loaded (video cached), trigger the update now.
        if (video.readyState >= 1 && video.duration && isFinite(video.duration)) {
            t.duration = video.duration;
            if (seedSegs.length) {
                updateBar(video.dataset.sourcerecordid, mergeSegments(seedSegs), t.duration);
            }
        } else if (seedSegs.length && seedDur) {
            updateBar(video.dataset.sourcerecordid, seedSegs, seedDur);
        }

        // Detect seeks via delta in timeupdate instead of seeking/seeked events,
        // which have a timing race where timeupdate can update lastTime to the
        // new seek position before seeking fires.
        video.addEventListener('timeupdate', function() {
            if (video.paused || video.ended || t.segStart === null) { return; }
            var ct    = video.currentTime;
            var delta = ct - t.lastTime;
            var dur   = getDuration(video, t);
            if (delta > 0 && delta < 2) {
                t.lastTime = ct;
                updateBar(video.dataset.sourcerecordid,
                    mergeSegments(t.segments.concat([[t.segStart, ct]])), dur);
            } else if (delta >= 2 || delta < 0) {
                if (t.lastTime > t.segStart) {
                    t.segments.push([t.segStart, t.lastTime]);
                }
                t.segStart = ct;
                t.lastTime = ct;
            }
        });

        video.addEventListener('pause', function() {
            if (t.segStart !== null) {
                if (t.lastTime > t.segStart) {
                    t.segments.push([t.segStart, t.lastTime]);
                }
                t.segStart = null;
            }
            clearInterval(t.saveTimer);
            t.saveTimer = null;
            updateBar(video.dataset.sourcerecordid, mergeSegments(t.segments), getDuration(video, t));
            saveSegments(video);
        });

        video.addEventListener('ended', function() {
            var dur = getDuration(video, t);
            if (t.segStart !== null) {
                t.segments.push([t.segStart, dur || t.lastTime]);
                t.segStart = null;
            }
            clearInterval(t.saveTimer);
            t.saveTimer = null;
            updateBar(video.dataset.sourcerecordid, mergeSegments(t.segments), dur);
            saveSegments(video);
        });
    }

    // Capture-phase delegation: handles play for lazy-loaded videos.
    document.addEventListener('play', function(e) {
        var video = e.target;
        if (video.tagName !== 'VIDEO' || !video.dataset.sourcerecordid) { return; }
        setupTracking(video);
        var key = video.dataset.sourcerecordid + '_' + video.dataset.cmid;
        var t = trackers[key];
        t.segStart = video.currentTime;
        t.lastTime = video.currentTime;
        if (!t.saveTimer) {
            t.saveTimer = setInterval(function() { saveSegments(video); }, 30000);
        }
        if (!t.played) {
            t.played = true;
            Ajax.call([{
                methodname: 'mod_jitsi_log_recording_view',
                args: {
                    sourcerecordid: parseInt(video.dataset.sourcerecordid, 10),
                    cmid:           parseInt(video.dataset.cmid, 10),
                    milestone:      0
                }
            }]);
        }
    }, true);

    document.querySelectorAll('video[data-sourcerecordid]').forEach(setupTracking);

    // Track clicks on non-embeddable recording links (8x8, external, Jibri).
    document.addEventListener('click', function(e) {
        var link = e.target.closest('.jitsi-recording-link');
        if (!link || !link.dataset.sourcerecordid) { return; }
        var key = link.dataset.sourcerecordid + '_' + link.dataset.cmid;
        if (linkClicked[key]) { return; }
        linkClicked[key] = true;
        Ajax.call([{
            methodname: 'mod_jitsi_log_recording_view',
            args: {
                sourcerecordid: parseInt(link.dataset.sourcerecordid, 10),
                cmid:           parseInt(link.dataset.cmid, 10),
                milestone:      0
            }
        }]);
    });
});
");

echo $OUTPUT->footer();
