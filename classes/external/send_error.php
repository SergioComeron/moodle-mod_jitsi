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
use core_external\external_value;

/**
 * External API: email site admins about a Jitsi recording error and log the event.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class send_error extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'user'  => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'error' => new external_value(PARAM_TEXT, 'Error', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'cmid'  => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Email site admins about a recording error and trigger the error event.
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param string $error Error message
     * @param int $cmid Course Module id
     */
    public static function execute($jitsi, $user, $error, $cmid) {
        global $DB, $CFG;

        $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST);
        $context = \context_module::instance($cmid);
        $admins = get_admins();

        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $course = $DB->get_record('course', ['id' => $jitsiob->course]);
        $userob = $DB->get_record('user', ['id' => $user]);
        $safeerror = substr(strip_tags($error), 0, 500);
        $mensaje = "El usuario " . $userob->firstname . " " . $userob->lastname .
            " ha tenido un error al intentar grabar la sesión de jitsi con id " . $jitsi . "\nInfo:\n" . $safeerror . "\n
        Para más información, accede a la sesión de jitsi y mira el log.\n
        URL: " . $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid . "\n
        Nombre de la sesión: " . $jitsiob->name . "\n
        Curso: " . $course->fullname . "\n
        Usuario: " . $userob->username . "\n";
        foreach ($admins as $admin) {
            email_to_user($admin, $admin, "ERROR JITSI! el usuario: "
                . $userob->username . " ha tenido un error en el jitsi: " . $jitsi, $mensaje);
        }

        $event = \mod_jitsi\event\jitsi_error::create([
            'objectid' => $cm->instance,
            'context' => $context,
            'other' => ['error' => $error, 'account' => '-'],
        ]);
        $event->add_record_snapshot('course', $course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Returns description of method return value.
     *
     * @return external_value
     */
    public static function execute_returns() {
        return new external_value(PARAM_TEXT, 'Error sent');
    }
}
