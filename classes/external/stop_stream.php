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

namespace mod_jitsi\external;

use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External API: stop a YouTube live stream.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class stop_stream extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_TEXT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Stop a YouTube live stream.
     *
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return array result
     */
    public static function execute($jitsi, $userid) {
        global $CFG, $DB;
        require_once($CFG->dirroot . '/mod/jitsi/lib.php');

        $params = self::validate_parameters(
            self::execute_parameters(),
            ['jitsi' => $jitsi, 'userid' => $userid]
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $sourcealmacenada = $DB->get_record('jitsi_source_record', ['id' => $jitsiob->sourcerecord]);
        $author = $DB->get_record('user', ['id' => $sourcealmacenada->userid]);

        if ($sourcealmacenada->userid != $userid && $jitsiob->sourcerecord != null) {
            $result = [];
            $result['error'] = 'errorauthor';
            $result['user'] = $author->id;
            $result['usercomplete'] = $author->firstname . ' ' . $author->lastname;
            return $result;
        }
        $jitsiob->sourcerecord = null;
        $DB->update_record('jitsi', $jitsiob);
        $result = [];

        $result['error'] = '';
        $result['user'] = $author->id;
        $result['usercomplete'] = $author->firstname . ' ' . $author->lastname;
        doembedable($sourcealmacenada->link);
        return $result;
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
                'error' => new external_value(PARAM_TEXT, 'error'),
                'user' => new external_value(PARAM_INT, 'user id'),
                'usercomplete' => new external_value(PARAM_TEXT, 'user complete name'),
            ]);
    }
}
