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
 * Lazy-loaded fragment for the recordings tab in view.php.
 *
 * @package    mod_jitsi
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once($CFG->dirroot . '/mod/jitsi/lib.php');
require_once($CFG->dirroot . '/mod/jitsi/view_table.php');

$id          = required_param('id', PARAM_INT);
$editrecordid = optional_param('editrecordid', 0, PARAM_INT);

$cm     = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
$course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
$jitsi  = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

require_login($course, true, $cm);

$context = context_module::instance($cm->id);
$PAGE->set_context($context);
$PAGE->set_cm($cm, $course);

if (!has_capability('mod/jitsi:viewrecords', $context) && !has_capability('mod/jitsi:record', $context)) {
    http_response_code(403);
    die();
}

$jitsiid = $jitsi->id;
if (!empty($jitsi->sessionwithtoken) && !empty($jitsi->tokeninvitacion)) {
    $master = $DB->get_record_sql(
        "SELECT id FROM {jitsi} WHERE tokeninterno = :token",
        ['token' => $jitsi->tokeninvitacion]
    );
    if ($master) {
        $jitsiid = $master->id;
    }
}

if (has_capability('mod/jitsi:viewrecords', $context)) {
    $sqlrecords = 'SELECT r.id FROM {jitsi_record} r
        JOIN {jitsi_source_record} s ON s.id = r.source
        WHERE r.jitsi = :jitsiid AND r.deleted = 0
        AND (s.timeexpires = 0 OR s.timeexpires > :now)';
    $hasrecords = $DB->record_exists_sql($sqlrecords, ['jitsiid' => $jitsiid, 'now' => time()]);

    if ($hasrecords) {
        $table = new mod_view_table('jitsirecords');
        $fields = '{jitsi_record}.id,
                   {jitsi_source_record}.link,
                   {jitsi_source_record}.type,
                   {jitsi_record}.jitsi,
                   {jitsi_record}.name,
                   {jitsi_source_record}.timecreated';
        $from  = '{jitsi_record}, {jitsi_source_record}';
        $where = '{jitsi_record}.source = {jitsi_source_record}.id AND
                  {jitsi_record}.jitsi = ' . $jitsiid . ' AND
                  {jitsi_record}.deleted = 0';
        if (!has_capability('mod/jitsi:hide', $context)) {
            $where .= ' AND {jitsi_record}.visible = 1';
        }
        $table->set_sql($fields, $from, $where, []);
        $table->sortable(true, 'id', SORT_DESC);
        $table->define_baseurl(new moodle_url('/mod/jitsi/view.php', ['id' => $id, 'tab' => 'record']));
        $table->out(5, true);
    } else {
        echo "<br>";
        echo get_string('norecords', 'jitsi');
    }
}

if (has_capability('mod/jitsi:record', $context)) {
    echo "<br><hr>";
    if ($editrecordid) {
        $editrecord = $DB->get_record('jitsi_record', ['id' => $editrecordid]);
        $editsource = $editrecord ? $DB->get_record('jitsi_source_record', ['id' => $editrecord->source]) : null;
    }
    if ($editrecordid && !empty($editrecord) && !empty($editsource) && $editsource->type == 1) {
        echo "<h5>" . get_string('editrecordinglink', 'jitsi') . "</h5>";
        echo "<form method=\"post\" action=\"" . (new moodle_url('/mod/jitsi/view.php', ['id' => $id]))->out(false) . "\">";
        echo "<input type=\"hidden\" name=\"sesskey\" value=\"" . sesskey() . "\">";
        echo "<input type=\"hidden\" name=\"tab\" value=\"record\">";
        echo "<input type=\"hidden\" name=\"editingrecordid\" value=\"" . $editrecordid . "\">";
        echo "<div class=\"mb-3\">";
        echo "<label for=\"recordingurl\" class=\"form-label\">" . get_string('recordingurl', 'jitsi') . "</label>";
        echo "<input type=\"url\" class=\"form-control\" id=\"recordingurl\" name=\"recordingurl\""
            . " value=\"" . s($editsource->link) . "\" required data-is-dropbox=\""
            . (strpos($editsource->link, 'dropbox.com') !== false ? '1' : '0') . "\">";
        echo "</div>";
        echo "<div class=\"mb-3\" id=\"dropboxembedoption\""
            . (strpos($editsource->link, 'dropbox.com') !== false ? '' : ' style="display:none"') . ">";
        echo "<div class=\"form-check\">";
        echo "<input class=\"form-check-input\" type=\"checkbox\" id=\"embedrecording\" name=\"embedrecording\" value=\"1\""
            . (!empty($editsource->embed) ? ' checked' : '') . ">";
        echo "<label class=\"form-check-label\" for=\"embedrecording\">"
            . get_string('dropboxembedrecording', 'jitsi') . "</label>";
        echo "</div>";
        echo "<div class=\"form-text text-warning mt-1\">" . get_string('dropboxembedwarning', 'jitsi') . "</div>";
        echo "</div>";
        echo "<div class=\"mb-3\">";
        echo "<label for=\"recordingname\" class=\"form-label\">" . get_string('recordingname', 'jitsi') . "</label>";
        echo "<input type=\"text\" class=\"form-control\" id=\"recordingname\" name=\"recordingname\""
            . " value=\"" . s($editrecord->name) . "\">";
        echo "</div>";
        echo "<button type=\"submit\" name=\"saverecordedit\" value=\"1\" class=\"btn btn-primary\">";
        echo get_string('savechanges');
        echo "</button> ";
        $cancelurl = new moodle_url('/mod/jitsi/view.php', ['id' => $id, 'tab' => 'record']);
        echo "<a href=\"" . $cancelurl->out(false) . "\" class=\"btn btn-secondary\">" . get_string('cancel') . "</a>";
        echo "</form><br>";
    } else {
        echo "<h5>" . get_string('addrecordinglink', 'jitsi') . "</h5>";
        echo "<form method=\"post\" action=\"" . (new moodle_url('/mod/jitsi/view.php', ['id' => $id]))->out(false) . "\">";
        echo "<input type=\"hidden\" name=\"sesskey\" value=\"" . sesskey() . "\">";
        echo "<input type=\"hidden\" name=\"tab\" value=\"record\">";
        echo "<div class=\"mb-3\">";
        echo "<label for=\"recordingurl\" class=\"form-label\">" . get_string('recordingurl', 'jitsi') . "</label>";
        echo "<input type=\"url\" class=\"form-control\" id=\"recordingurl\" name=\"recordingurl\" required>";
        echo "</div>";
        echo "<div class=\"mb-3\" id=\"dropboxembedoption\" style=\"display:none\">";
        echo "<div class=\"form-check\">";
        echo "<input class=\"form-check-input\" type=\"checkbox\" id=\"embedrecording\" name=\"embedrecording\" value=\"1\">";
        echo "<label class=\"form-check-label\" for=\"embedrecording\">"
            . get_string('dropboxembedrecording', 'jitsi') . "</label>";
        echo "</div>";
        echo "<div class=\"form-text text-warning mt-1\">" . get_string('dropboxembedwarning', 'jitsi') . "</div>";
        echo "</div>";
        echo "<div class=\"mb-3\">";
        echo "<label for=\"recordingname\" class=\"form-label\">" . get_string('recordingname', 'jitsi') . "</label>";
        echo "<input type=\"text\" class=\"form-control\" id=\"recordingname\" name=\"recordingname\">";
        echo "</div>";
        echo "<button type=\"submit\" name=\"addrecordlink\" value=\"1\" class=\"btn btn-secondary\">";
        echo get_string('addrecordinglink', 'jitsi');
        echo "</button>";
        echo "</form><br>";
    }
}
