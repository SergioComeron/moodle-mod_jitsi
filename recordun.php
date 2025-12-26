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
require_login(0, true);

$token = required_param('t', PARAM_TEXT);

$sql = "select * from {jitsi} where token = '" . $token . "'";
$jitsi = $DB->get_record_sql($sql);
$module = $DB->get_record('modules', ['name' => 'jitsi']);
$cm = $DB->get_record('course_modules', ['instance' => $jitsi->id, 'module' => $module->id]);
$id = $cm->id;

global $DB, $CFG;
$PAGE->set_url($CFG->wwwroot . '/mod/jitsi/recordun.php');
$course = $DB->get_record('course', ['id' => $jitsi->course]);
$cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
$PAGE->set_cm($cm);

$PAGE->set_context(context_module::instance($cm->id));

$navigator = $_SERVER['HTTP_USER_AGENT'];

$event = \mod_jitsi\event\jitsi_session_enter::create([
  'objectid' => $PAGE->cm->instance,
  'context' => $PAGE->context,
  'other' => ['navigator' => $navigator],
]);
$event->add_record_snapshot('course', $PAGE->course);
$event->add_record_snapshot($PAGE->cm->modname, $jitsi);

$event->trigger();
$jitsi = $DB->get_record('jitsi', ['id' => $cm->instance]);

$fieldssessionname = get_config('mod_jitsi', 'sesionname');
$allowed = explode(',', $fieldssessionname);
$max = count($allowed);

$sesparam = '';
$optionsseparator = ['.', '-', '_', ''];
for ($i = 0; $i < $max; $i++) {
    if ($i != $max - 1) {
        if ($allowed[$i] == 0) {
            $sesparam .= string_sanitize($course->shortname) . $optionsseparator[get_config('mod_jitsi', 'separator')];
        } else if ($allowed[$i] == 1) {
            $sesparam .= $jitsi->id . $optionsseparator[get_config('mod_jitsi', 'separator')];
        } else if ($allowed[$i] == 2) {
            $sesparam .= string_sanitize($jitsi->name) . $optionsseparator[get_config('mod_jitsi', 'separator')];
        }
    } else {
        if ($allowed[$i] == 0) {
            $sesparam .= string_sanitize($course->shortname);
        } else if ($allowed[$i] == 1) {
            $sesparam .= $sessionid;
        } else if ($allowed[$i] == 2) {
            $sesparam .= string_sanitize($jitsi->name);
        }
    }
}

$PAGE->set_title($jitsi->name);
$PAGE->set_heading($jitsi->name);
echo $OUTPUT->header();

echo "<div id=\"videoContainer\">";
if (!istimedout($jitsi)) {
    $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $jitsi->sourcerecord]);
    if ($sourcerecord) {
        echo "<div class=\"embed-responsive embed-responsive-16by9\">
            <iframe class=\"embed-responsive-item\" src=\"https://youtube.com/embed/" . $sourcerecord->link . "\" allowfullscreen>
            </iframe></div>";
    } else {
        echo '<div class="alert alert-warning text-center" role="alert">' . get_string('norecording', 'jitsi') . '</div>';
    }
} else {
    echo generateerrortime($jitsi);
}

echo "</div>";
echo "<script>\n";
echo "var checkInterval;\n";
echo "var hayVideo = document.getElementById('videoContainer').innerHTML.includes('embed-responsive-item');\n";

echo "function checkSourceRecord(jitsiId) {\n";
echo "    var xhr = new XMLHttpRequest();\n";
echo "    xhr.open('GET', 'check_sourcerecord.php?jitsiId=' + jitsiId, true);\n";
echo "    xhr.onreadystatechange = function() {\n";
echo "        if (xhr.readyState == 4 && xhr.status == 200) {\n";
echo "            var response = JSON.parse(xhr.responseText);\n";
echo "            var container = document.getElementById('videoContainer');\n";
echo "            var currentContent = container.innerHTML.trim();\n";

echo "            if (response.found && hayVideo) {\n";

echo "            } else {\n";
echo "                if (response.found) {\n";
echo "                    waitTenSeconds(response);\n";
echo "                } else if (!response.found && currentContent !== 'No hay grabación') {\n";
echo "                    waitTenSecondsForDelete();\n";
echo "                }\n";
echo "            }\n";
echo "        }\n";
echo "    };\n";
echo "    xhr.send();\n";
echo "};\n";

// Función que retorna una promesa que se resuelve después de un periodo de tiempo.
echo "function wait(ms) {\n";
echo "    return new Promise(resolve => setTimeout(resolve, ms));\n";
echo "};\n";

// Función asíncrona que espera 10 segundos antes de continuar.
echo "async function waitTenSeconds(response) {\n";
echo "    document.getElementById('videoContainer').innerHTML = ";
echo "    '<div class=\"d-flex flex-column align-items-center justify-content-center\" style=\"height: 100vh;\">";
echo "     <div class=\"spinner-border\" role=\"status\">";
echo "     <span class=\"sr-only\">" . get_string('loadingvideo', 'jitsi') . "</span></div><br>"
    . get_string('loadingvideo', 'jitsi') . "</div>';\n";

echo "    await wait(10000); // Esperar 10,000 milisegundos (10 segundos)\n";
echo "    document.getElementById('videoContainer').innerHTML = ";
echo "    '<div class=\"embed-responsive embed-responsive-16by9\">";
echo "    <iframe class=\"embed-responsive-item\" src=\"https://youtube.com/embed/' + response.link + '\" allowfullscreen>";
echo "    </iframe></div>';\n";
echo "    hayVideo = true;\n";
echo "}\n";

echo "async function waitTenSecondsForDelete() {";
echo "    await wait(10000);";
echo "    document.getElementById('videoContainer').innerHTML = '<div class=\"alert alert-warning text-center\" role=\"alert\">"
    . get_string('norecording', 'jitsi') . "</div>';\n";
echo "    hayVideo = false;\n";
echo "};\n";

// Llama a la función cada 5 segundos.
echo "checkInterval = setInterval(function() {\n";
echo "    checkSourceRecord(" . $jitsi->id . ");\n";
echo "}, 10000);\n";
echo "</script>\n";
if (isloggedin()) {
    echo $OUTPUT->footer();
}
