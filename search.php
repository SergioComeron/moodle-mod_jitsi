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

require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php');
require_once("$CFG->libdir/formslib.php");
require_once('search_table.php');
require_once($CFG->dirroot . '/user/selector/lib.php');

/**
 * Guest access form.
 *
 * @package   mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class datesearch_form extends moodleform {
    /**
     * Defines forms elements
     */
    public function definition() {
        global $CFG, $DB;
        $mform = $this->_form; // Don't forget the underscore!.
        $defaulttimestart = [
            'year' => date('Y'),
            'month' => date('n'),
            'day' => date('j'),
            'hour' => 0,
            'minute' => 0,
        ];
        $mform->addElement(
            'date_time_selector',
            'timestart',
            get_string('from'),
            ['defaulttime' => $defaulttimestart]
        );
        $mform->addElement('date_time_selector', 'timeend', get_string('to'));

        $usersid = $DB->get_records_sql('SELECT DISTINCT userid FROM {jitsi_source_record}');
        $users = [];
        foreach ($usersid as $userid) {
            $user = $DB->get_record('user', ['id' => $userid->userid]);
            $users[$user->id] = $user->firstname . ' ' . $user->lastname;
        }
        $options = [
            'multiple' => true,
            'noselectionstring' => 'Todos los usuarios',
            'casesensitive' => false,
        ];
        $mform->addElement('autocomplete', 'userselected', 'Usuario', $users, $options);

        $mform->setType('userselected', PARAM_INT);

        $recorders = $DB->get_records('jitsi_record_account', null, '', 'id, name');
        $recordersidnombre = [];
        foreach ($recorders as $recorder) {
            $recordersidnombre[$recorder->id] = $recorder->name;
        }

        $mform->addElement('select', 'recorder', get_string('recorders', 'jitsi'), $recordersidnombre);

        $mform->getElement('recorder')->setMultiple(true);
        $mform->addRule('recorder', null, 'required', null, 'client');

        $indices = array_column($recorders, 'id');
        $mform->getElement('recorder')->setSelected($indices);

        $buttonarray = [];
        $buttonarray[] = $mform->createElement('submit', 'submitbutton', get_string('search'));

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
        return [];
    }
}

$PAGE->set_context(context_system::instance());

$PAGE->set_url('/mod/jitsi/search.php');
require_login();

$timestart = optional_param_array('timestart', 0, PARAM_INT);
$timeend = optional_param_array('timeend', 0, PARAM_INT);
$recorder = optional_param_array('recorder', [], PARAM_INT);
if (isset($_POST['userselected']) && is_array($_POST['userselected'])) {
    $userselected = optional_param_array('userselected', [], PARAM_INT);
} else {
    $userselected = [];
}

$recorders = $DB->get_records('jitsi_record_account');

if ($timestart == 0) {
    $timestart = ['year' => 2021, 'month' => 1, 'day' => 1, 'hour' => 0, 'minute' => 0];
    $timeend = ['year' => 2021, 'month' => 12, 'day' => 31, 'hour' => 23, 'minute' => 59];
}
$timestarttimestamp = make_timestamp(
    $timestart['year'],
    $timestart['month'],
    $timestart['day'],
    $timestart['hour'],
    $timestart['minute']
);
$timeendtimestamp = make_timestamp(
    $timeend['year'],
    $timeend['month'],
    $timeend['day'],
    $timeend['hour'],
    $timeend['minute']
);

$PAGE->set_title(format_string(get_string('search')));
$PAGE->set_heading(format_string(get_string('search')));
echo $OUTPUT->header();

if (is_siteadmin()) {
    $mform = new datesearch_form();
    $mform->display();
    $table = new mod_search_table('search');
    $fields = '{jitsi_source_record}.id,
                {jitsi_source_record}.link,
                {jitsi_record}.jitsi,
                {jitsi_source_record}.account,
                {jitsi_source_record}.userid,
                {jitsi_source_record}.timecreated,
                {jitsi_source_record}.maxparticipants,
                {jitsi_record}.deleted';
    $from = '{jitsi_source_record}, {jitsi_record}';
    $where = '{jitsi_record}.source = {jitsi_source_record}.id and
                {jitsi_source_record}.timecreated > ' . $timestarttimestamp . ' and
                {jitsi_source_record}.timecreated < ' . $timeendtimestamp;

    if (!empty($recorder)) {
        $recorderlist = implode(',', $recorder);
        $where .= ' AND {jitsi_source_record}.account IN (' . $recorderlist . ')';
    }
    if (!empty($userselected)) {
        $userlist = implode(',', $userselected);
        $where .= ' AND {jitsi_source_record}.userid IN (' . $userlist . ')';
    }
    $table->set_sql($fields, $from, $where, ['1']);
    $table->define_baseurl('/mod/jitsi/search.php?' .
        http_build_query(['timestart' => $timestart, 'timeend' => $timeend,
            'recorder' => $recorder, 'userselected' => $userselected]));
    $table->out(10, true);
} else {
    redirect($CFG->wwwroot, 'Acceso a busquedas no permitido. Solo administradores');
}
echo $OUTPUT->footer();
