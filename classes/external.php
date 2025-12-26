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
 * Jitsi module external API
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

require_once($CFG->libdir . '/externallib.php');
require_once($CFG->dirroot . '/mod/jitsi/lib.php');

/**
 * Jitsi module external API
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class mod_jitsi_external extends external_api {
    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function view_jitsi_parameters() {
        return new external_function_parameters(
            [
                'cmid' => new external_value(PARAM_INT, 'course module instance id'),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function state_record_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'state' => new external_value(PARAM_TEXT, 'State', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function create_stream_parameters() {
        return new external_function_parameters(
            ['session' => new external_value(PARAM_TEXT, 'Session object from google', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function enter_session_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function press_record_button_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function delete_record_youtube_parameters() {
        return new external_function_parameters(
            ['idsource' => new external_value(PARAM_INT, 'Record session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED)]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function stop_stream_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_TEXT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function stop_stream_byerror_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function stop_stream_noauthor_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function getminutesfromlastconexion_parameters() {
        return new external_function_parameters(
            ['cmid' => new external_value(PARAM_INT, 'Cm id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                  'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method result value
     *
     * @return external_description
     * @param int $cmid Course module id
     * @param int $user User id
     */
    public static function getminutesfromlastconexion($cmid, $user) {
        return getminutesfromlastconexion($cmid, $user);
    }

    /**
     * Delete Video from youtube when jitsi get an error
     *
     * @param int $idsource Source record id
     * @return external_function_parameters
     */
    public static function delete_record_youtube($idsource) {
        global $DB;
        $record = $DB->get_record('jitsi_record', ['source' => $idsource]);
        $record->deleted = 1;
        $DB->update_record('jitsi_record', $record);
        return deleterecordyoutube($idsource);
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     */
    public static function enter_session($jitsi, $user) {
        global $DB;
        $event = \mod_jitsi\event\jitsi_session_enter::create([
            'objectid' => $PAGE->cm->instance,
            'context' => $PAGE->context,
          ]);
          $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
          $event->add_record_snapshot('course', $jitsi->course);
          $event->add_record_snapshot('jitsi', $jitsiob);
          $event->trigger();
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function press_record_button($jitsi, $user, $cmid) {
          global $DB;
          $context = context_module::instance($cmid);
          $event = \mod_jitsi\event\jitsi_press_record_button::create([
              'objectid' => $jitsi,
              'context' => $context,
          ]);
          $event->add_record_snapshot('course', $jitsi->course);
          $event->add_record_snapshot('jitsi', $jitsiob);
          $event->trigger();
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function press_button_cam_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function press_button_cam($jitsi, $user, $cmid) {
        global $DB;
        $context = context_module::instance($cmid);
        $event = \mod_jitsi\event\jitsi_press_button_cam::create([
            'objectid' => $jitsi,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $jitsi->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function press_button_cam_returns() {
        return new external_value(PARAM_TEXT, 'Press cam button');
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function press_button_desktop_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return send_error_parameters
     */
    public static function send_error_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'error' => new external_value(PARAM_TEXT, 'Error', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param string $error Error message
     * @param int $cmid Course Module id
     */
    public static function send_error($jitsi, $user, $error, $cmid) {
        global $PAGE, $DB, $CFG;

        $PAGE->set_context(context_module::instance($cmid));
        $admins = get_admins();

        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $DB->update_record('jitsi', $jitsiob);

        $user = $DB->get_record('user', ['id' => $user]);
        $mensaje = "El usuario " . $user->firstname . " " . $user->lastname .
            " ha tenido un error al intentar grabar la sesión de jitsi con id " . $jitsi . "\nInfo:\n" . $error . "\n
        Para más información, accede a la sesión de jitsi y mira el log.\n
        URL: " . $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid . "\n
        Nombre de la sesión: " . $DB->get_record('jitsi', ['id' => $jitsi])->name . "\n
        Curso: " . $DB->get_record('course', ['id' => $DB->get_record('jitsi', ['id' => $jitsi])->course])->fullname . "\n
        Usuario: " . $user->username . "\n";
        foreach ($admins as $admin) {
            email_to_user($admin, $admin, "ERROR JITSI! el usuario: "
                . $user->username . " ha tenido un error en el jitsi: " . $jitsi, $mensaje);
        }

        $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST);
        $event = \mod_jitsi\event\jitsi_error::create([
            'objectid' => $PAGE->cm->instance,
            'context' => $PAGE->context,
            'other' => ['error' => $error, 'account' => '-'],
        ]);
        $event->add_record_snapshot('course', $PAGE->course);
        $event->add_record_snapshot('jitsi', $jitsi);
        $event->trigger();
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function press_button_desktop($jitsi, $user, $cmid) {
        global $DB;
        $context = context_module::instance($cmid);
        $event = \mod_jitsi\event\jitsi_press_button_desktop::create([
            'objectid' => $jitsi,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $jitsi->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function press_button_desktop_returns() {
        return new external_value(PARAM_TEXT, 'Press desktop button');
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function press_button_end_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function log_error_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function press_button_end($jitsi, $user, $cmid) {
        global $DB;
        $context = context_module::instance($cmid);
        $event = \mod_jitsi\event\jitsi_press_button_end::create([
            'objectid' => $jitsi,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $jitsi->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function log_error($jitsi, $user, $cmid) {
        global $DB;
        $context = context_module::instance($cmid);
        $event = \mod_jitsi\event\jitsi_error::create([
            'objectid' => $jitsi,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $jitsi->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function press_button_microphone_returns() {
        return new external_value(PARAM_TEXT, 'Press microphone button');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function log_error_returns() {
        return new external_value(PARAM_TEXT, 'Log error');
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function press_button_microphone_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function update_participants_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'numberofparticipants' =>
                        new external_value(PARAM_INT, 'Number of participants', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @return external_function_parameters
     */
    public static function get_participants_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED)]
        );
    }

    /**
     * Returns description of method parameters
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function press_button_microphone($jitsi, $user, $cmid) {
        global $DB;
        $context = context_module::instance($cmid);
        $event = \mod_jitsi\event\jitsi_press_button_microphone::create([
            'objectid' => $jitsi,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $jitsi->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function press_button_end_returns() {
        return new external_value(PARAM_TEXT, 'Press end button');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function enter_session_returns() {
        return new external_value(PARAM_TEXT, 'Enter session');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function press_record_button_returns() {
        return new external_value(PARAM_TEXT, 'Press record button');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function participating_session_parameters() {
        return new external_function_parameters(
            ['jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'user' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
                    'cmid' => new external_value(PARAM_INT, 'Course Module id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            ]
        );
    }

    /**
     * Register a participation in a Jitsi session
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param int $cmid Course Module id
     */
    public static function participating_session($jitsi, $user, $cmid) {
        global $DB;
        $context = context_module::instance($cmid);
        $event = \mod_jitsi\event\jitsi_session_participating::create([
            'objectid' => $jitsi,
            'context' => $context,
        ]);
        $event->add_record_snapshot('course', $jitsi->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
        update_completition(get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST));
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function participating_session_returns() {
        return new external_value(PARAM_TEXT, 'Participating session');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function delete_record_youtube_returns() {
        return new external_value(PARAM_TEXT, 'Video deleted');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function send_error_returns() {
        return new external_value(PARAM_TEXT, 'Error sent');
    }

    /**
     * Trigger the course module viewed event.
     *
     * @param int $cmid the course module instance id
     * @return array of warnings and status result
     * @throws moodle_exception
     */
    public static function view_jitsi($cmid) {
        global $DB;

        $params = self::validate_parameters(
            self::view_jitsi_parameters(),
            ['cmid' => $cmid]
        );
        $warnings = [];

        $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST);

        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $event = \mod_jitsi\event\course_module_viewed::create([
                'objectid' => $cm->instance,
                'context' => $context,
            ]);
        $event->add_record_snapshot('course', $course);
        $event->add_record_snapshot($cm->modname, $jitsi);
        $event->trigger();

        $result = [];
        $result['status'] = true;
        $result['warnings'] = $warnings;
        return $result;
    }

    /**
     * Returns record state
     * @param int $jitsi Jitsi session id
     * @param string $state State
     * @return array
     */
    public static function state_record($jitsi, $state) {
        global $USER, $DB;

        $params = self::validate_parameters(
            self::state_record_parameters(),
            ['jitsi' => $jitsi, 'state' => $state]
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $DB->update_record('jitsi', $jitsiob);
        return 'recording' . $jitsiob->recording;
    }

    /**
     * Stop stream with youtube
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return array result
     */
    public static function stop_stream($jitsi, $userid) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::stop_stream_parameters(),
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
     * Stop stream with youtube by error
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return array result
     */
    public static function stop_stream_byerror($jitsi, $userid) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::stop_stream_byerror_parameters(),
            ['jitsi' => $jitsi, 'userid' => $userid]
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        if ($userid != $jitsiob->sourcerecord) {
            $jitsiob->sourcerecord = null;
            $DB->update_record('jitsi', $jitsiob);
            return 'authordeleted';
        }
        return 'authornotdeleted';
    }

    /**
     * Stop stream with youtube by error
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return array result
     */
    public static function stop_stream_noauthor($jitsi, $userid) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::stop_stream_byerror_parameters(),
            ['jitsi' => $jitsi, 'userid' => $userid]
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        if ($userid != $jitsiob->sourcerecord) {
            $jitsiob->sourcerecord = null;
            $DB->update_record('jitsi', $jitsiob);
            return 'authordeleted';
        }
        return 'authornotdeleted';
    }

    /**
     * Start stream with youtube
     * @param int $session session
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return array result
     */
    public static function create_stream($session, $jitsi, $userid) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::create_stream_parameters(),
            ['session' => $session, 'jitsi' => $jitsi, 'userid' => $userid]
        );

        $author = $DB->get_record('user', ['id' => $userid]);
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        if ($jitsiob->sourcerecord != null) {
            $sourcealmacenada = $DB->get_record('jitsi_source_record', ['id' => $jitsiob->sourcerecord]);
            if ($sourcealmacenada->userid != $userid) {
                $result = [];
                $result['stream'] = 'nodata';
                $result['idsource'] = 0;
                $result['error'] = 'errorauthor';
                $result['user'] = $sourcealmacenada->userid;
                $authoralmacenada = $DB->get_record('user', ['id' => $sourcealmacenada->userid]);
                $result['usercomplete'] = $authoralmacenada->firstname . ' ' . $authoralmacenada->lastname;
                $result['errorinfo'] = '';
                $result['link'] = '';
                return $result;
            }
        }

        $client = getclientgoogleapi();
        $youtube = new Google_Service_YouTube($client);

        $account = $DB->get_record('jitsi_record_account', ['inuse' => 1]);
        $source = new stdClass();
        $source->account = $account->id;
        $source->timecreated = time();
        $source->userid = $userid;
        $source->link = $broadcastsresponse['id'];

        $record = new stdClass();
        $record->jitsi = $jitsi;
        $record->source = $DB->insert_record('jitsi_source_record', $source);
        $record->deleted = 0;
        $record->visible = 1;
        $record->name = get_string('recordtitle', 'jitsi') . ' ' . mb_substr($jitsiob->name, 0, 30);

        $DB->insert_record('jitsi_record', $record);
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $jitsiob->sourcerecord = $record->source;
        $DB->update_record('jitsi', $jitsiob);

        try {
            $broadcastsnippet = new Google_Service_YouTube_LiveBroadcastSnippet();
            $testdate = time();

            $broadcastsnippet->setTitle("Record " . date('Y-m-d\T H:i A', $testdate));
            $broadcastsnippet->setScheduledStartTime(date('Y-m-d\TH:i:s', $testdate));

            $status = new Google_Service_YouTube_LiveBroadcastStatus();
            $status->setPrivacyStatus('unlisted');
            if (get_config('mod_jitsi', 'selfdeclaredmadeforkids') == 0) {
                $status->setSelfDeclaredMadeForKids('false');
            } else {
                $status->setSelfDeclaredMadeForKids('true');
            }
            $contentdetails = new Google_Service_YouTube_LiveBroadcastContentDetails();
            $contentdetails->setEnableAutoStart(true);
            $contentdetails->setEnableAutoStop(true);
            if (get_config('mod_jitsi', 'latency') == 0) {
                $contentdetails->setLatencyPreference("normal");
            } else if (get_config('mod_jitsi', 'latency') == 1) {
                $contentdetails->setLatencyPreference("low");
            } else if (get_config('mod_jitsi', 'latency') == 2) {
                $contentdetails->setLatencyPreference("ultralow");
            }

            $broadcastinsert = new Google_Service_YouTube_LiveBroadcast();
            $broadcastinsert->setSnippet($broadcastsnippet);
            $broadcastinsert->setStatus($status);
            $broadcastinsert->setKind('youtube#liveBroadcast');
            $broadcastinsert->setContentDetails($contentdetails);
            sleep(rand(1, 2));
            $broadcastsresponse = $youtube->liveBroadcasts->insert(
                'snippet,status,contentDetails',
                $broadcastinsert,
                [],
            );

            $streamsnippet = new Google_Service_YouTube_LiveStreamSnippet();
            $streamsnippet->setTitle("Record " . date('l jS \of F', $testdate));

            $cdn = new Google_Service_YouTube_CdnSettings();
            $cdn->setIngestionType('rtmp');
            $cdn->setResolution("variable");
            $cdn->setFrameRate("variable");

            $streaminsert = new Google_Service_YouTube_LiveStream();
            $streaminsert->setSnippet($streamsnippet);
            $streaminsert->setCdn($cdn);
            $streaminsert->setKind('youtube#liveStream');
            sleep(rand(1, 2));
            $streamsresponse = $youtube->liveStreams->insert('snippet,cdn', $streaminsert, []);
            sleep(rand(1, 2));
            $bindbroadcastresponse = $youtube->liveBroadcasts->bind(
                $broadcastsresponse['id'],
                'id,contentDetails',
                ['streamId' => $streamsresponse['id']],
            );
        } catch (Google_Service_Exception $e) {
            $result = [];
            $result['stream'] = $streamsresponse['cdn']['ingestionInfo']['streamName'];
            $result['idsource'] = $record->source;
            $result['error'] = 'erroryoutube';
            $result['user'] = $jitsiob->sourcerecord;
            $result['usercomplete'] = $author->firstname . ' ' . $author->lastname;
            $result['errorinfo'] = $e->getMessage();
            $result['link'] = '';
            senderror($jitsi, $userid, 'ERROR DE YOUTUBE: ' . $e->getMessage(), $source);
            changeaccount();
            return $result;
        } catch (Google_Exception $e) {
            $result = [];
            $result['stream'] = $streamsresponse['cdn']['ingestionInfo']['streamName'];
            $result['idsource'] = $record->source;
            $result['error'] = 'erroryoutube';
            $result['user'] = $jitsiob->sourcerecord;
            $result['usercomplete'] = $author->firstname . ' ' . $author->lastname;
            $result['errorinfo'] = $e->getMessage();
            $result['link'] = '';
            senderror($jitsi, $userid, 'ERROR DE YOUTUBE: ' . $e->getMessage(), $source);
            changeaccount();
            return $result;
        }

        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
        $source->link = $broadcastsresponse['id'];
        $source->maxparticipants = $jitsiob->numberofparticipants;
        $DB->update_record('jitsi_source_record', $source);

        $result = [];
        $result['stream'] = $streamsresponse['cdn']['ingestionInfo']['streamName'];
        $result['idsource'] = $record->source;
        $result['error'] = '';
        $result['user'] = $author->id;
        $result['usercomplete'] = $author->firstname . ' ' . $author->lastname;
        $result['errorinfo'] = '';
        $result['link'] = $broadcastsresponse['id'];
        changeaccount();
        return $result;
    }

    /**
     * Update Number of Participants
     * @param int $jitsi Jitsi session id
     * @param int $numberofparticipants Number of participants
     * @return array result
     */
    public static function update_participants($jitsi, $numberofparticipants) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::update_participants_parameters(),
            ['jitsi' => $jitsi, 'numberofparticipants' => $numberofparticipants],
        );
        if ($numberofparticipants >= 0) {
            $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
            if ($numberofparticipants != $jitsiob->numberofparticipants) {
                $jitsiob->numberofparticipants = $numberofparticipants;
                $DB->update_record('jitsi', $jitsiob);
                if ($jitsiob->sourcerecord != null) {
                    $source = $DB->get_record('jitsi_source_record', ['id' => $jitsiob->sourcerecord]);
                    if ($source && $source->maxparticipants < $numberofparticipants) {
                        $source->maxparticipants = $numberofparticipants;
                        $DB->update_record('jitsi_source_record', $source);
                    }
                }
            }
        }
        return $jitsiob->numberofparticipants;
    }

    /**
     * Get Number of Participants
     * @param int $jitsi Jitsi session id
     * @return array result
     */
    public static function get_participants($jitsi) {
        global $CFG, $DB;

        $params = self::validate_parameters(
            self::update_participants_parameters(),
            ['jitsi' => $jitsi],
        );
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $jitsiob->name = 'modificado';
        $DB->update_record('jitsi', $jitsiob);
        return $jitsiob->numberofparticipants;
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function state_record_returns() {
        return new external_value(PARAM_TEXT, 'State record session');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function stop_stream_returns() {
        return new external_single_structure([
                'error' => new external_value(PARAM_TEXT, 'error'),
                'user' => new external_value(PARAM_INT, 'user id'),
                'usercomplete' => new external_value(PARAM_TEXT, 'user complete name'),
            ]);
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function stop_stream_byerror_returns() {
        return new external_value(PARAM_TEXT, 'State');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function stop_stream_noauthor_returns() {
        return new external_value(PARAM_TEXT, 'State');
    }

    /**
     * Returns description of method result value
     *
     * @return external_description
     */
    public static function view_jitsi_returns() {
        return new external_single_structure([
                'status' => new external_value(PARAM_BOOL, 'status: true if success'),
                'warnings' => new external_warnings(),
            ]);
    }

    /**
     * Returns description of method result value
     *
     * @return external_description
     */
    public static function create_stream_returns() {
        return new external_single_structure([
                'stream' => new external_value(PARAM_TEXT, 'stream'),
                'idsource' => new external_value(PARAM_INT, 'source instance id'),
                'error' => new external_value(PARAM_TEXT, 'error'),
                'user' => new external_value(PARAM_INT, 'user id'),
                'usercomplete' => new external_value(PARAM_TEXT, 'user complete name'),
                'errorinfo' => new external_value(PARAM_TEXT, 'error info'),
                'link' => new external_value(PARAM_TEXT, 'link'),
            ]);
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function update_participants_returns() {
        return new external_value(PARAM_INT, 'Number of partipants');
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function get_participants_returns() {
        return new external_value(PARAM_INT, 'Number of partipants');
    }

    /**
     * Returns description of method parameters
     * @return external_function_parameters
     */
    public static function getminutesfromlastconexion_returns() {
        return new external_value(PARAM_INT, 'Last conexion timestamp');
    }
}
