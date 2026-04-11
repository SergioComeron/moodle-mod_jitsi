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
 * Search coursemates and start a private video call.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(__FILE__) . '/lib.php');

$PAGE->set_url('/mod/jitsi/call.php');
$PAGE->set_context(context_system::instance());
require_login();

if (!get_config('mod_jitsi', 'privatesessions')) {
    redirect($CFG->wwwroot, get_string('privatesessiondisabled', 'jitsi'));
}

$PAGE->set_title(get_string('callsomeone', 'jitsi'));
$PAGE->set_heading(get_string('callsomeone', 'jitsi'));

$PAGE->requires->js_call_amd('mod_jitsi/call', 'init', [
    $CFG->wwwroot . '/mod/jitsi/sessionpriv.php',
]);

echo $OUTPUT->header();

echo html_writer::tag('p', get_string('callsomeonehelp', 'jitsi'));

echo html_writer::start_div('', ['id' => 'jitsi-call-wrapper', 'style' => 'max-width:480px']);

echo html_writer::tag('input', '', [
    'type'        => 'text',
    'id'          => 'jitsi-call-search',
    'class'       => 'form-control mb-2',
    'placeholder' => get_string('callsearchplaceholder', 'jitsi'),
    'autocomplete' => 'off',
]);

echo html_writer::start_div('list-group', ['id' => 'jitsi-call-results']);
echo html_writer::end_div();

echo html_writer::end_div();

echo $OUTPUT->footer();
