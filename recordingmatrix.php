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
 * Library of interface functions and constants for module jitsi
 *
 * All the core Moodle functions, neeeded to allow the module to work
 * integrated in Moodle should be placed here.
 *
 * All the jitsi specific functions, needed to implement all the module
 * logic, should go to locallib.php. This will help to save some memory when
 * Moodle is performing actions across all modules.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once("$CFG->libdir/formslib.php");
require_once(dirname(__FILE__) . '/lib.php');
require_once($CFG->libdir . '/tablelib.php');
require_once('adminrecords_table.php');

global $DB;

$deletejitsisourceid = optional_param('deletejitsisourceid', 0, PARAM_INT);
$sesskey = optional_param('sesskey', null, PARAM_TEXT);

$PAGE->set_context(context_system::instance());

$PAGE->set_url('/mod/jitsi/recordingmatrix.php');
require_login();

if ($deletejitsisourceid && confirm_sesskey($sesskey)) {
    if (deleterecordyoutube($deletejitsisourceid) == true) {
        redirect($PAGE->url, get_string('deleted'));
    } else {
        redirect($PAGE->url, get_string('errordeleting', 'jitsi'));
    }
}

$PAGE->set_title(format_string(get_string('recordsonair', 'jitsi')));
$PAGE->set_heading(format_string(get_string('recordsonair', 'jitsi')));

echo $OUTPUT->header();

if (is_siteadmin()) {
    $sqljitsilive = 'select {jitsi}.id,
                    {jitsi}.sourcerecord,
                    {jitsi}.course,
                    {jitsi}.numberofparticipants
                    from {jitsi}, {jitsi_source_record}
                    where {jitsi}.sourcerecord > 0 and
                    {jitsi}.sourcerecord = {jitsi_source_record}.id
                    order by {jitsi_source_record}.timecreated desc';
    $jitsilives = $DB->get_records_sql($sqljitsilive);
    if ($jitsilives) {
        echo "<div class=\"container-fluid\">";
        echo "<div class=\"row\">";
        foreach ($jitsilives as $jitsilive) {
            $sqlsourcelive = 'select {jitsi_source_record}.id,
                                {jitsi_source_record}.timecreated,
                                {jitsi_record}.name,
                                {jitsi_source_record}.link,
                                {jitsi_source_record}.userid,
                                {jitsi_source_record}.embed
                            from {jitsi_source_record},
                                {jitsi_record}
                            where ' . $jitsilive->sourcerecord . ' = {jitsi_source_record}.id and
                                {jitsi_record}.source = {jitsi_source_record}.id';
            $sourcelives = $DB->get_records_sql($sqlsourcelive);
            foreach ($sourcelives as $sourcelive) {
                $cm = get_coursemodule_from_instance('jitsi', $jitsilive->id, $jitsilive->course, false, MUST_EXIST);
                $contextmodule = context_module::instance($cm->id);
                $sqllastparticipating = 'select timecreated from {logstore_standard_log} where contextid = '
                    . $contextmodule->id . ' and (action = \'participating\'
                    or action = \'enter\') order by timecreated DESC limit 1';
                $usersconnected = $DB->get_record_sql($sqllastparticipating);
                if ($usersconnected != null) {
                    if ((getdate()[0] - $usersconnected->timecreated) > 72) {
                        $jitsilive->numberofparticipants = 0;
                        $DB->update_record('jitsi', $jitsilive);
                    }
                }
                if ($usersconnected != null) {
                    if ($jitsilive->numberofparticipants == 0 && (getdate()[0] - $usersconnected->timecreated) > 72) {
                        $jitsilive->sourcerecord = null;
                        $DB->update_record('jitsi', $jitsilive);
                    }
                }

                if ($sourcelive->link != null) {
                    $coursemodule = get_coursemodule_from_instance('jitsi', $jitsilive->id);
                    $urljitsiparams = ['id' => $coursemodule->id];
                    $urljitsi = new moodle_url('/mod/jitsi/view.php', $urljitsiparams);
                    $urlcourse = new moodle_url('/course/view.php', ['id' => $coursemodule->course]);
                    $course = $DB->get_record('course', ['id' => $coursemodule->course]);
                    echo "<div class=\"col-sm-4\">";
                    echo "<div class=\"card\" >";
                    echo "<div class=\"card-body\">";
                    echo "<h5 class=\"card-title\">";
                    echo "<a href=" . $urljitsi . " >" . $sourcelive->name . "</a> (" . $jitsilive->numberofparticipants . ")";
                    echo "</h5>";
                    echo "<h6 class=\"card-subtitle mb-2 text-muted\"><a href=" . $urljitsi . "
                        data-toggle=\"tooltip\" data-placement=\"top\" title=\"" . $course->fullname . "\">" .
                        $course->shortname . "</a></h6>";
                    echo "<h6 class=\"card-subtitle mb-2 text-muted\">" . userdate($sourcelive->timecreated) . "</h6>";
                    if ($sourcelive->embed == 0) {
                        doembedable($sourcelive->link);
                        sleep(1);
                    }
                    echo "<div class=\"embed-responsive embed-responsive-16by9\">";
                    echo "<iframe class=\"embed-responsive-item\" src=\"https://youtube.com/embed/"
                        . $sourcelive->link . "\"allowfullscreen></iframe>";
                    echo "</div>";
                    $author = $DB->get_record('user', ['id' => $sourcelive->userid]);
                    $authorurl = new moodle_url('/user/view.php', ['id' => $sourcelive->userid]);
                    echo "<a href=" . $authorurl . " target=\"_blank\"><h6 class=\"card-subtitle mb-2 text-muted\">"
                        . $author->firstname . " " . $author->lastname . "</h6></a>";
                    echo "</div>";
                    echo "</div>";
                    echo "</div>";
                }
            }
        }
        echo "</div>";
        echo "</div>";
    } else {
        echo "<div class=\"alert alert-info\" role=\"alert\">";
        echo get_string('norecords', 'jitsi');
        echo "</div>";
    }
}
echo $OUTPUT->footer();

/**
 * Get true if the source is on array.
 * @param array $sources array of sources
 * @param stdClass $sourceelement source element to search
 * @return bool
 */
function isincluded($sources, $sourceelement) {
    foreach ($sources as $source) {
        if ($source->id == $sourceelement->id) {
            return true;
        }
    }
    return false;
}
