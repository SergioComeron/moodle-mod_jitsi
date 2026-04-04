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

$PAGE->set_url('/mod/jitsi/adminrecord.php');
require_login();

if ($deletejitsisourceid && confirm_sesskey($sesskey)) {
    if (deleterecordyoutube($deletejitsisourceid) == true) {
        redirect($PAGE->url, get_string('deleted'));
    } else {
        redirect($PAGE->url, get_string('errordeleting', 'jitsi'));
    }
}

$PAGE->set_title(format_string(get_string('records', 'jitsi')));
$PAGE->set_heading(format_string(get_string('records', 'jitsi')));

echo $OUTPUT->header();

$settingsurl = new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']);
echo html_writer::div(
    html_writer::link($settingsurl, '&laquo; ' . get_string('settings'), ['class' => 'btn btn-secondary mb-3']),
    'mb-2'
);

echo $OUTPUT->box(get_string('tablelistjitsis', 'jitsi'));

if (is_siteadmin()) {
    $table = new mod_adminrecords_table('records_to_delete');
    $fields = '{jitsi_source_record}.id,
                {jitsi_source_record}.link,
                {jitsi_source_record}.account,
                {jitsi_source_record}.userid,
                {jitsi_source_record}.timecreated';
    $from = '{jitsi_source_record}, {jitsi_record}';
    $where = '{jitsi_record}.source = {jitsi_source_record}.id and
                {jitsi_record}.deleted = 1';
    $table->set_sql($fields, $from, $where, ['1']);
    $table->define_baseurl('/mod/jitsi/adminrecord.php');
    $table->out(10, true);
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
