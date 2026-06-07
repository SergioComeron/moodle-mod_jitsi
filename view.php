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
require_once(__DIR__ . '/view_table.php');
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
$tab = optional_param('tab', 'session', PARAM_TEXT);
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
    $paramdecode = \mod_jitsi\local\util::base64url_decode($state);
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
    \mod_jitsi\local\recording::mark_to_delete($deletejitsirecordid, 1);
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
    $jitsiinvitado = $DB->get_record('jitsi', ['tokeninterno' => $jitsi->tokeninvitacion]);
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
    $sesparam = \mod_jitsi\local\room::build_name(
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
}

if (!$deletejitsirecordid) {
    echo $OUTPUT->header();
}

$cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
\mod_jitsi\local\attendance::update_completion($cm);
if ($CFG->branch == 311) {
    if (!$deletejitsirecordid) {
        echo $OUTPUT->heading($jitsi->name);
    }
    $completiondetails = \core_completion\cm_completion_details::get_instance($cminfo, $USER->id);
    $activitydates = \core\activity_dates::get_dates_for_module($cminfo, $USER->id);
    echo $OUTPUT->activity_information($cminfo, $completiondetails, $activitydates);
}

$contextmodule = context_module::instance($cm->id);

$presencethreshold = time() - 90;
$presencecount = (int)$DB->count_records_select(
    'jitsi_presence',
    'jitsiid = :jitsiid AND timemodified > :threshold',
    ['jitsiid' => $jitsi->id, 'threshold' => $presencethreshold]
);
if ($errorborrado) {
    echo "<div class=\"alert alert-danger\" role=\"alert\">";

    echo get_string('sessiondeleted', 'jitsi');
    echo "</div>";
    echo $OUTPUT->footer();
    die();
}
$sqlrecords = 'SELECT r.id FROM {jitsi_record} r
    JOIN {jitsi_source_record} s ON s.id = r.source
    WHERE r.jitsi = :jitsiid AND r.deleted = 0
    AND (s.timeexpires = 0 OR s.timeexpires > :now)';
$recordsparams = ['jitsiid' => $jitsiid, 'now' => time()];
$records = $DB->record_exists_sql($sqlrecords, $recordsparams);
$hasvisiblerecords = $DB->record_exists_sql($sqlrecords . ' AND r.visible = 1', $recordsparams);

$bstoggle = ($CFG->branch >= 500) ? 'data-bs-toggle' : 'data-toggle';

echo '<ul class="nav nav-tabs" id="myTab" role="tablist">';
echo '<li class="nav-item">';
echo '<a class="nav-link ' . ($activetab == 'session' ? 'active' : '') . '" id="session-tab"'
    . ' ' . $bstoggle . '="tab" href="#session" role="tab" aria-controls="session"'
    . ' aria-selected="' . ($activetab == 'session' ? 'true' : 'false') . '">'
    . get_string('session', 'jitsi') . '</a>';
echo '</li>';

if (has_capability('mod/jitsi:viewrecords', $PAGE->context) || has_capability('mod/jitsi:record', $PAGE->context)) {
    if (
        $hasvisiblerecords ||
        has_capability('mod/jitsi:record', $PAGE->context) ||
        get_config('mod_jitsi', 'streamingoption') == 1
    ) {
        echo '<li class="nav-item">';
        echo '<a class="nav-link ' . ($activetab == 'record' ? 'active' : '') . '" id="record-tab"'
            . ' ' . $bstoggle . '="tab" href="#record" role="tab" aria-controls="record"'
            . ' aria-selected="' . ($activetab == 'record' ? 'true' : 'false') . '">'
            . get_string('records', 'jitsi') . '</a>';
        echo '</li>';
    }
}
echo '</ul>';

echo '<div class="tab-content" id="myTabContent">';
echo '<div class="tab-pane fade ' . ($activetab == 'session' ? 'show active' : '')
    . '" id="session" role="tabpanel" aria-labelledby="session-tab">';

// Build initial presence user list from DB.
$presenceusers = [];
if ($presencecount > 0) {
    $presencerows = $DB->get_records_select(
        'jitsi_presence',
        'jitsiid = :jitsiid AND timemodified > :threshold',
        ['jitsiid' => $jitsi->id, 'threshold' => $presencethreshold],
        'userid DESC'
    );
    foreach ($presencerows as $presencerow) {
        if ($presencerow->userid > 0) {
            $userfields = 'id,firstname,lastname,firstnamephonetic,lastnamephonetic,middlename,alternatename';
            $presenceuser = $DB->get_record('user', ['id' => $presencerow->userid], $userfields);
            $presenceusers[] = [
                'name' => $presenceuser ? fullname($presenceuser) : get_string('unknownuser', 'error'),
                'userid' => (int)$presencerow->userid,
                'isguest' => 0,
            ];
        } else {
            $presenceusers[] = [
                'name' => $presencerow->guestname ?: get_string('guest'),
                'userid' => 0,
                'isguest' => 1,
            ];
        }
    }
}

// Metrics — centered, above card.
echo html_writer::start_div('d-flex justify-content-center gap-5 mt-3 mb-3');
echo html_writer::start_div('text-center');
echo '<div class="dropdown d-inline-block">';
echo '<button class="border-0 bg-transparent p-0 dropdown-toggle" id="jitsi-presence-btn"'
    . ' ' . $bstoggle . '="dropdown" aria-expanded="false"'
    . ' aria-label="' . s(get_string('connectedattendeesnow', 'jitsi')) . '">';
echo '<span id="jitsi-presence-count" class="h4 mb-0 fw-bold">' . $presencecount . '</span>';
echo '</button>';
echo '<ul class="dropdown-menu" id="jitsi-presence-list" aria-labelledby="jitsi-presence-btn">';
if (empty($presenceusers)) {
    echo '<li><span class="dropdown-item-text text-muted">' . get_string('noconnectedusers', 'jitsi') . '</span></li>';
} else {
    foreach ($presenceusers as $presenceitem) {
        if ($presenceitem['isguest']) {
            echo '<li><span class="dropdown-item-text">'
                . '<i class="fa fa-user-secret text-muted me-1" aria-hidden="true"></i>'
                . s($presenceitem['name'])
                . '</span></li>';
        } else {
            $profileurl = new moodle_url('/user/view.php', ['id' => $presenceitem['userid'], 'course' => $jitsi->course]);
            echo '<li><a class="dropdown-item" href="' . $profileurl . '" target="_blank" rel="noopener">'
                . s($presenceitem['name'])
                . '</a></li>';
        }
    }
}
echo '</ul>';
echo '</div>';
echo html_writer::tag('div', get_string('connectedattendeesnow', 'jitsi'), ['class' => 'text-muted small']);
echo html_writer::end_div();
echo html_writer::start_div('text-center');
echo html_writer::tag(
    'div',
    \mod_jitsi\local\attendance::minutes($id, $USER->id),
    ['class' => 'h4 mb-0 fw-bold', 'id' => 'jitsi-user-minutes']
);
echo html_writer::tag('div', get_string('totaluserminutes', 'jitsi'), ['class' => 'text-muted small']);
echo html_writer::end_div();
echo html_writer::end_div();

$courseid = (int)$jitsi->course;

// Badges — centered, above card.
echo html_writer::start_div('text-center mb-2');
if ($jitsi->sessionwithtoken) {
    $jitsimaster = $DB->get_record('jitsi', ['tokeninterno' => $jitsi->tokeninvitacion]);
    $coursemaster = $DB->get_record('course', ['id' => $jitsimaster->course]);
    echo html_writer::tag(
        'span',
        '🔗 ' . get_string('sessionshared', 'jitsi', $coursemaster->shortname),
        ['class' => 'badge bg-secondary me-2']
    );
}
if ($jitsi->sourcerecord != null) {
    $source = $DB->get_record('jitsi_source_record', ['id' => $jitsi->sourcerecord]);
    if ($source) {
        $author = $DB->get_record('user', ['id' => $source->userid]);
        if ($author) {
            echo html_writer::tag(
                'span',
                '<i class="fa fa-circle me-1" aria-hidden="true"></i>'
                    . get_string('sessionisbeingrecordingby', 'jitsi', fullname($author)),
                ['class' => 'badge bg-danger me-1']
            );
        } else {
            $jitsi->sourcerecord = null;
            $DB->update_record('jitsi', $jitsi);
        }
    } else {
        $jitsi->sourcerecord = null;
        $DB->update_record('jitsi', $jitsi);
    }
}
$jibrirecording = ($jitsi->status === 'recording');
$jibribadgeclass = 'badge bg-danger me-1' . ($jibrirecording ? '' : ' d-none');
echo html_writer::tag(
    'span',
    '<i class="fa fa-circle me-1" aria-hidden="true"></i>' . get_string('sessionisbeingrecorded', 'jitsi'),
    ['class' => $jibribadgeclass, 'id' => 'jitsi-jibri-badge']
);
echo html_writer::end_div();

$PAGE->requires->js_call_amd('mod_jitsi/view_indicators', 'init', [[
    'jitsiid' => (int)$jitsi->id,
    'courseid' => $courseid,
    'cmid' => (int)$cm->id,
]]);

if ($CFG->branch <= 311 && $jitsi->intro) {
    echo html_writer::div(
        format_module_intro('jitsi', $jitsi, $cm->id),
        'generalbox mod_introbox mb-3',
        ['id' => 'jitsiintro']
    );
}

// Centered card with avatar, name and join button.
$fechacierre = $jitsi->timeclose;
$fechainicio = $jitsi->timeopen;
if ($jitsi->sessionwithtoken == 1) {
    $fechacierre = $jitsiinvitado->timeclose;
    $fechainicio = $jitsiinvitado->timeopen;
}

echo html_writer::start_div('d-flex justify-content-center mb-4');
echo html_writer::start_div('card shadow-sm', ['style' => 'max-width:420px;width:100%']);
echo html_writer::start_div('card-body p-4 text-center');
$avatar = $CFG->wwwroot . '/user/pix.php/' . $USER->id . '/f1.jpg';
echo html_writer::empty_tag('img', [
    'src'   => s($avatar),
    'class' => 'rounded-circle mb-2',
    'style' => 'width:64px;height:64px;object-fit:cover',
    'alt'   => s(fullname($USER)),
]);
echo html_writer::tag('p', s(fullname($USER)), ['class' => 'fw-semibold mb-3']);
if (time() < $fechacierre || $fechacierre == 0) {
    if (
        time() > $fechainicio ||
        has_capability('mod/jitsi:moderation', $context) && time() > ($jitsi->timeopen - ($jitsi->minpretime * 60))
    ) {
        $button = new moodle_url('/mod/jitsi/session.php', $urlparams);
        echo html_writer::link(
            $button,
            get_string('access', 'jitsi'),
            [
                'class'      => 'btn btn-primary btn-lg w-100',
                'aria-label' => get_string('accesssessionlabel', 'jitsi', $jitsi->name),
            ]
        );
    } else {
        echo $OUTPUT->notification(get_string('nostart', 'jitsi', userdate($jitsi->timeopen)), 'info');
    }
} else {
    echo $OUTPUT->notification(get_string('finish', 'jitsi'), 'warning');
}
echo html_writer::end_div();
echo html_writer::end_div();
echo html_writer::end_div();

// Help text below the card.
if (get_config('mod_jitsi', 'help') != null) {
    echo '<br>';
    echo get_config('mod_jitsi', 'help');
} else {
    echo '<br>';
    echo $OUTPUT->box(get_string('instruction', 'jitsi'));
}

if (get_config('mod_jitsi', 'inviteemail') == 1 && has_capability('mod/jitsi:createlink', $context)) {
    $sendinvurl = new moodle_url('/mod/jitsi/sendinvitation.php', ['id' => $id]);
    echo html_writer::start_div('text-center mt-3');
    echo html_writer::link(
        $sendinvurl,
        '<i class="fa fa-envelope mr-1" aria-hidden="true"></i>' . get_string('sendinvitation', 'jitsi'),
        ['class' => 'btn btn-outline-secondary btn-sm']
    );
    echo html_writer::end_div();
}

echo '</div>';

if (has_capability('mod/jitsi:viewrecords', $PAGE->context) || has_capability('mod/jitsi:record', $PAGE->context)) {
    echo "  <div class=\"tab-pane fade " . ($activetab == 'record' ? 'show active' : '') .
        "\" id=\"record\" role=\"tabpanel\" aria-labelledby=\"record-tab\">";
    echo "<div id=\"jitsi-recordings-content\"></div>";
    echo "  </div>";

    $recordingstaburl = (new moodle_url('/mod/jitsi/recordingstab.php', [
        'id'           => $id,
        'editrecordid' => $editrecordid,
    ]))->out(false);

    $PAGE->requires->js_call_amd('mod_jitsi/recordings_lazyload', 'init', [[
        'recordingsUrl' => $recordingstaburl,
    ]]);
}


echo "</div>";

echo "<hr>";

// AI dropdown + transcript timestamps.
if (get_config('mod_jitsi', 'aienabled')) {
    $gdprregion = get_config('mod_jitsi', 'vertexairegion') ?: 'us-central1';
    $gdprbody = '<p>' . get_string('aigdprnotice', 'jitsi', s($gdprregion)) . '</p>';
    $PAGE->requires->js_call_amd('mod_jitsi/ai_actions', 'init', [[
        'gdprBody' => $gdprbody,
    ]]);
}

// Track GCS recording views with real segment tracking.
$PAGE->requires->js_call_amd('mod_jitsi/recording_tracker', 'init');

echo $OUTPUT->footer();
