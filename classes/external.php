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

    /**
     * Returns description of method parameters for save_recording_link
     * @return external_function_parameters
     */
    public static function save_recording_link_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED),
            'link'  => new external_value(PARAM_URL, 'Recording link URL provided by recordingLinkAvailable event', VALUE_REQUIRED),
            'ttl'   => new external_value(PARAM_INT, 'Time to live in seconds (0 = no expiry)', VALUE_DEFAULT, 0),
        ]);
    }

    /**
     * Saves a recording link received from the Jitsi recordingLinkAvailable iframe event.
     * Creates entries in jitsi_source_record (type=1) and jitsi_record so the recording
     * appears automatically in the activity's recordings tab.
     *
     * @param int    $jitsi Jitsi session id
     * @param string $link  Full URL of the recording
     * @param int    $ttl   Time-to-live in seconds reported by Jitsi (0 = unknown/no expiry)
     * @return array
     */
    public static function save_recording_link($jitsi, $link, $ttl = 0) {
        global $DB, $USER;

        $params = self::validate_parameters(self::save_recording_link_parameters(), [
            'jitsi' => $jitsi,
            'link'  => $link,
            'ttl'   => $ttl,
        ]);

        // Make sure the jitsi session exists.
        $jitsirecord = $DB->get_record('jitsi', ['id' => $params['jitsi']], '*', MUST_EXIST);

        // Avoid saving the same link twice for the same session.
        $existingsource = $DB->get_record_sql(
            'SELECT s.id FROM {jitsi_source_record} s
             JOIN {jitsi_record} r ON r.source = s.id
             WHERE s.link = :link AND r.jitsi = :jitsi AND r.deleted = 0',
            ['link' => $params['link'], 'jitsi' => $params['jitsi']]
        );
        if ($existingsource) {
            // If the existing record has no expiry, try to set it now.
            $existingfull = $DB->get_record('jitsi_source_record', ['id' => $existingsource->id]);
            if ($existingfull && empty($existingfull->timeexpires)) {
                $is8x8link = strpos($params['link'], '8x8.vc') !== false;
                if ($params['ttl'] > 0) {
                    $existingfull->timeexpires = $existingfull->timecreated + $params['ttl'];
                    $DB->update_record('jitsi_source_record', $existingfull);
                } else if ($is8x8link) {
                    $existingfull->timeexpires = $existingfull->timecreated + 86400;
                    $DB->update_record('jitsi_source_record', $existingfull);
                }
            }
            return ['idsource' => $existingsource->id];
        }

        // Create the source record with type = 1 (external link).
        $sourcerecord = new stdClass();
        $sourcerecord->link            = $params['link'];
        $sourcerecord->account         = null;
        $sourcerecord->timecreated     = time();
        $sourcerecord->userid          = $USER->id;
        $sourcerecord->embed           = 0;
        $sourcerecord->maxparticipants = 0;
        $sourcerecord->type            = 1;
        $jaasttl = 86400; // JaaS recordings expire after 24 hours if no TTL is provided.
        $is8x8link = strpos($params['link'], '8x8.vc') !== false;
        if ($params['ttl'] > 0) {
            $sourcerecord->timeexpires = time() + $params['ttl'];
        } else if ($is8x8link) {
            $sourcerecord->timeexpires = time() + $jaasttl;
        } else {
            $sourcerecord->timeexpires = 0;
        }
        $idsource = $DB->insert_record('jitsi_source_record', $sourcerecord);

        // Create the jitsi_record linking the source to the session.
        $record = new stdClass();
        $record->jitsi   = $params['jitsi'];
        $record->deleted = 0;
        $record->source  = $idsource;
        $record->visible = 1;
        $record->name    = userdate(time());
        $DB->insert_record('jitsi_record', $record);

        return ['idsource' => $idsource];
    }

    /**
     * Returns description of method result value for save_recording_link
     * @return external_description
     */
    public static function save_recording_link_returns() {
        return new external_single_structure([
            'idsource' => new external_value(PARAM_INT, 'Id of the created jitsi_source_record'),
        ]);
    }

    /**
     * Returns description of search_shared_sessions parameters
     * @return external_function_parameters
     */
    public static function search_shared_sessions_parameters() {
        return new external_function_parameters([
            'query'        => new external_value(PARAM_TEXT, 'Search string (activity name, course name or shortname)'),
            'excludetoken' => new external_value(
                PARAM_TEXT,
                'tokeninterno to exclude from results (current activity)',
                VALUE_DEFAULT,
                ''
            ),
        ]);
    }

    /**
     * Search for Jitsi master sessions (sessionwithtoken=0) available to join.
     * Site admins search all courses; regular users are filtered to their enrolled courses.
     *
     * @param string $query Search string
     * @param string $excludetoken Token to exclude from results
     * @return array List of matching sessions [{value, label}]
     */
    public static function search_shared_sessions($query, $excludetoken = '') {
        global $DB, $USER;

        $params = self::validate_parameters(self::search_shared_sessions_parameters(), [
            'query'        => $query,
            'excludetoken' => $excludetoken,
        ]);
        $query        = trim($params['query']);
        $excludetoken = trim($params['excludetoken']);

        if (core_text::strlen($query) < 3) {
            return [];
        }

        $like1 = $DB->sql_like('j.name', ':q1', false);
        $like2 = $DB->sql_like('c.fullname', ':q2', false);
        $like3 = $DB->sql_like('c.shortname', ':q3', false);

        $searchparams = [
            'q1' => '%' . $DB->sql_like_escape($query) . '%',
            'q2' => '%' . $DB->sql_like_escape($query) . '%',
            'q3' => '%' . $DB->sql_like_escape($query) . '%',
        ];

        // Exclude the current activity's own token so a session cannot join itself.
        $excludeclause = '';
        if (!empty($excludetoken)) {
            $excludeclause = ' AND j.tokeninterno <> :excludetoken';
            $searchparams['excludetoken'] = $excludetoken;
        }

        // Site admins can see all courses; regular users only their enrolled ones.
        if (is_siteadmin()) {
            $sql = "SELECT j.tokeninterno, j.name AS jname, c.fullname, c.shortname
                      FROM {jitsi} j
                      JOIN {course} c ON c.id = j.course
                     WHERE j.sessionwithtoken = 0
                       AND ($like1 OR $like2 OR $like3)
                       $excludeclause
                  ORDER BY c.shortname, j.name
                     LIMIT 20";
            $inparams = [];
        } else {
            $courses = enrol_get_users_courses($USER->id, true, ['id']);
            if (empty($courses)) {
                return [];
            }
            $courseids = array_keys($courses);
            [$insql, $inparams] = $DB->get_in_or_equal($courseids, SQL_PARAMS_NAMED, 'cid');

            $sql = "SELECT j.tokeninterno, j.name AS jname, c.fullname, c.shortname
                      FROM {jitsi} j
                      JOIN {course} c ON c.id = j.course
                     WHERE j.sessionwithtoken = 0
                       AND j.course $insql
                       AND ($like1 OR $like2 OR $like3)
                       $excludeclause
                  ORDER BY c.shortname, j.name
                     LIMIT 20";
        }

        $records = $DB->get_records_sql($sql, array_merge($inparams, $searchparams));

        // If the query looks like an exact token (64 lowercase hex chars), also search
        // globally by tokeninterno regardless of enrollment, so teachers can use a
        // token shared by a colleague from another course.
        if (preg_match('/^[0-9a-f]{64}$/', $query) && $query !== $excludetoken) {
            $tokensql = "SELECT j.tokeninterno, j.name AS jname, c.fullname, c.shortname
                           FROM {jitsi} j
                           JOIN {course} c ON c.id = j.course
                          WHERE j.sessionwithtoken = 0
                            AND j.tokeninterno = :tok";
            $tokenrec = $DB->get_record_sql($tokensql, ['tok' => $query]);
            if ($tokenrec && !isset($records[$tokenrec->tokeninterno])) {
                $records[$tokenrec->tokeninterno] = $tokenrec;
            }
        }

        $results = [];
        foreach ($records as $rec) {
            $results[] = [
                'value' => $rec->tokeninterno,
                'label' => $rec->jname . ' — ' . $rec->fullname . ' (' . $rec->shortname . ')',
            ];
        }
        return $results;
    }

    /**
     * Returns description of search_shared_sessions return value
     * @return external_description
     */
    public static function search_shared_sessions_returns() {
        return new external_multiple_structure(
            new external_single_structure([
                'value' => new external_value(PARAM_TEXT, 'tokeninterno of the Jitsi session'),
                'label' => new external_value(PARAM_TEXT, 'Human-readable label (activity — course)'),
            ])
        );
    }

    /**
     * Returns description of queue_ai_summary parameters
     * @return external_function_parameters
     */
    public static function queue_ai_summary_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'ID of the jitsi_source_record'),
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
        ]);
    }

    /**
     * Queue an ad-hoc task to generate an AI summary for a GCS recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @return array
     */
    public static function queue_ai_summary($sourcerecordid, $cmid) {
        global $DB;

        $params = self::validate_parameters(self::queue_ai_summary_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid' => $cmid,
        ]);

        $context = context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:generateaisummary', $context);

        if (!get_config('mod_jitsi', 'aienabled')) {
            return ['success' => false, 'message' => get_string('aidisabled', 'jitsi')];
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $params['sourcerecordid']], '*', MUST_EXIST);

        // Only GCS recordings are supported.
        if (strpos($sourcerecord->link, 'storage.googleapis.com') === false) {
            return ['success' => false, 'message' => get_string('aisummarynotavailable', 'jitsi')];
        }

        // Enqueue the ad-hoc task.
        $task = new \mod_jitsi\task\generate_ai_summary();
        $task->set_custom_data(['sourcerecordid' => $params['sourcerecordid'], 'lang' => current_language()]);
        \core\task\manager::queue_adhoc_task($task, true);

        return ['success' => true, 'message' => get_string('aisummaryqueued', 'jitsi')];
    }

    /**
     * Returns description of queue_ai_summary return value
     * @return external_description
     */
    public static function queue_ai_summary_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the task was queued successfully'),
            'message' => new external_value(PARAM_TEXT, 'Status message'),
        ]);
    }

    /**
     * Returns description of queue_ai_transcription parameters
     * @return external_function_parameters
     */
    public static function queue_ai_transcription_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'ID of the jitsi_source_record'),
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
        ]);
    }

    /**
     * Queue an ad-hoc task to generate an AI transcription for a GCS recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @return array
     */
    public static function queue_ai_transcription($sourcerecordid, $cmid) {
        global $DB;

        $params = self::validate_parameters(self::queue_ai_transcription_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid' => $cmid,
        ]);

        $context = context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:generateaitranscription', $context);

        if (!get_config('mod_jitsi', 'aienabled')) {
            return ['success' => false, 'message' => get_string('aidisabled', 'jitsi')];
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $params['sourcerecordid']], '*', MUST_EXIST);

        if (strpos($sourcerecord->link, 'storage.googleapis.com') === false) {
            return ['success' => false, 'message' => get_string('aitranscriptionnotavailable', 'jitsi')];
        }

        $DB->set_field('jitsi_source_record', 'ai_transcription_status', 'pending', ['id' => $params['sourcerecordid']]);

        $task = new \mod_jitsi\task\generate_ai_transcription();
        $task->set_custom_data(['sourcerecordid' => $params['sourcerecordid'], 'lang' => current_language()]);
        \core\task\manager::queue_adhoc_task($task, true);

        return ['success' => true, 'message' => get_string('aitranscriptionqueued', 'jitsi')];
    }

    /**
     * Returns description of queue_ai_transcription return value
     * @return external_description
     */
    public static function queue_ai_transcription_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the task was queued successfully'),
            'message' => new external_value(PARAM_TEXT, 'Status message'),
        ]);
    }

    /**
     * Returns description of queue_ai_quiz parameters
     * @return external_function_parameters
     */
    public static function queue_ai_quiz_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'ID of the jitsi_source_record'),
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
        ]);
    }

    /**
     * Queue an ad-hoc task to generate a true/false quiz from a GCS recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @return array
     */
    public static function queue_ai_quiz($sourcerecordid, $cmid) {
        global $DB;

        $params = self::validate_parameters(self::queue_ai_quiz_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid' => $cmid,
        ]);

        $context = context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:generateaiquiz', $context);

        if (!get_config('mod_jitsi', 'aienabled')) {
            return ['success' => false, 'message' => get_string('aidisabled', 'jitsi')];
        }

        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $params['sourcerecordid']], '*', MUST_EXIST);

        if (strpos($sourcerecord->link, 'storage.googleapis.com') === false) {
            return ['success' => false, 'message' => get_string('aiquizerror', 'jitsi')];
        }

        $task = new \mod_jitsi\task\generate_ai_quiz();
        $task->set_custom_data([
            'sourcerecordid' => $params['sourcerecordid'],
            'cmid' => $params['cmid'],
            'lang' => current_language(),
        ]);
        \core\task\manager::queue_adhoc_task($task, true);

        return ['success' => true, 'message' => get_string('aiquizqueued', 'jitsi')];
    }

    /**
     * Returns description of queue_ai_quiz return value
     * @return external_description
     */
    public static function queue_ai_quiz_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the task was queued successfully'),
            'message' => new external_value(PARAM_TEXT, 'Status message'),
        ]);
    }

    /**
     * Returns description of search_coursemates parameters
     * @return external_function_parameters
     */
    public static function search_coursemates_parameters() {
        return new external_function_parameters([
            'query' => new external_value(PARAM_TEXT, 'Search string (firstname or lastname)'),
        ]);
    }

    /**
     * Search for users who share at least one course with the current user.
     *
     * @param string $query
     * @return array
     */
    public static function search_coursemates($query) {
        global $DB, $USER, $PAGE;

        $params = self::validate_parameters(self::search_coursemates_parameters(), ['query' => $query]);
        $context = context_system::instance();
        self::validate_context($context);

        $query = trim($params['query']);
        if (core_text::strlen($query) < 2) {
            return ['users' => []];
        }

        $searchparam = '%' . $DB->sql_like_escape($query) . '%';

        $sql = "SELECT DISTINCT u.id, u.firstname, u.lastname, u.picture, u.imagealt, u.email
                  FROM {user} u
                  JOIN {user_enrolments} ue ON ue.userid = u.id
                  JOIN {enrol} e ON e.id = ue.enrolid
                  JOIN {course} c ON c.id = e.courseid AND c.visible = 1
                 WHERE e.courseid IN (
                           SELECT e2.courseid
                             FROM {enrol} e2
                             JOIN {user_enrolments} ue2 ON ue2.enrolid = e2.id
                             JOIN {course} c2 ON c2.id = e2.courseid AND c2.visible = 1
                            WHERE ue2.userid = :currentuserid
                       )
                   AND u.id != :currentuserid2
                   AND u.deleted = 0
                   AND u.suspended = 0
                   AND (" . $DB->sql_like('u.firstname', ':search1', false) . "
                        OR " . $DB->sql_like('u.lastname', ':search2', false) . ")
              ORDER BY u.firstname, u.lastname";

        $records = $DB->get_records_sql($sql, [
            'currentuserid'  => $USER->id,
            'currentuserid2' => $USER->id,
            'search1'        => $searchparam,
            'search2'        => $searchparam,
        ], 0, 20);

        $users = [];
        foreach ($records as $record) {
            $userpicture = new user_picture($record);
            $userpicture->size = 1;
            $availability = jitsi_check_tutoring_availability($record->id, $USER->id);
            $users[] = [
                'id'              => (int)$record->id,
                'firstname'       => $record->firstname,
                'lastname'        => $record->lastname,
                'profileimageurl' => $userpicture->get_url($PAGE)->out(false),
                'hasschedule'     => $availability['hasschedule'],
                'available'       => $availability['available'],
                'nextslot'        => $availability['nextslot'] ?? '',
            ];
        }

        return ['users' => $users];
    }

    /**
     * Returns description of search_coursemates return value
     * @return external_description
     */
    public static function search_coursemates_returns() {
        return new external_single_structure([
            'users' => new external_multiple_structure(
                new external_single_structure([
                    'id'              => new external_value(PARAM_INT, 'User ID'),
                    'firstname'       => new external_value(PARAM_TEXT, 'First name'),
                    'lastname'        => new external_value(PARAM_TEXT, 'Last name'),
                    'profileimageurl' => new external_value(PARAM_URL, 'Profile image URL'),
                    'hasschedule'     => new external_value(PARAM_BOOL, 'Has tutoring schedule'),
                    'available'       => new external_value(PARAM_BOOL, 'Available now'),
                    'nextslot'        => new external_value(PARAM_TEXT, 'Next available slot', VALUE_OPTIONAL),
                ])
            ),
        ]);
    }

    /**
     * Returns description of register_push_subscription parameters
     * @return external_function_parameters
     */
    public static function register_push_subscription_parameters() {
        return new external_function_parameters([
            'endpoint'  => new external_value(PARAM_URL, 'Push endpoint URL'),
            'authkey'   => new external_value(PARAM_TEXT, 'Auth key base64url'),
            'p256dhkey' => new external_value(PARAM_TEXT, 'p256dh key base64url'),
        ]);
    }

    /**
     * Register a Web Push subscription for the current user.
     *
     * @param string $endpoint
     * @param string $authkey
     * @param string $p256dhkey
     * @return array
     */
    public static function register_push_subscription($endpoint, $authkey, $p256dhkey) {
        global $DB, $USER;

        $params = self::validate_parameters(self::register_push_subscription_parameters(), [
            'endpoint'  => $endpoint,
            'authkey'   => $authkey,
            'p256dhkey' => $p256dhkey,
        ]);

        $context = context_system::instance();
        self::validate_context($context);

        $now = time();
        $existing = $DB->get_record_sql(
            'SELECT id FROM {jitsi_push_subscriptions} WHERE userid = :userid AND ' . $DB->sql_compare_text('endpoint') . ' = ' . $DB->sql_compare_text(':endpoint'), // phpcs:ignore moodle.Files.LineLength.MaxExceeded
            ['userid' => $USER->id, 'endpoint' => $params['endpoint']]
        );

        if ($existing) {
            $DB->update_record('jitsi_push_subscriptions', (object)[
                'id'           => $existing->id,
                'authkey'      => $params['authkey'],
                'p256dhkey'    => $params['p256dhkey'],
                'timemodified' => $now,
            ]);
        } else {
            $DB->insert_record('jitsi_push_subscriptions', (object)[
                'userid'       => $USER->id,
                'endpoint'     => $params['endpoint'],
                'authkey'      => $params['authkey'],
                'p256dhkey'    => $params['p256dhkey'],
                'timecreated'  => $now,
                'timemodified' => $now,
            ]);
        }

        return ['success' => true];
    }

    /**
     * Returns description of register_push_subscription return value
     * @return external_description
     */
    public static function register_push_subscription_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether registration succeeded'),
        ]);
    }

    /**
     * Returns description of unregister_push_subscription parameters
     * @return external_function_parameters
     */
    public static function unregister_push_subscription_parameters() {
        return new external_function_parameters([
            'endpoint' => new external_value(PARAM_URL, 'Push endpoint URL'),
        ]);
    }

    /**
     * Unregister a Web Push subscription.
     *
     * @param string $endpoint
     * @return array
     */
    public static function unregister_push_subscription($endpoint) {
        global $DB, $USER;

        $params = self::validate_parameters(self::unregister_push_subscription_parameters(), [
            'endpoint' => $endpoint,
        ]);

        $context = context_system::instance();
        self::validate_context($context);

        $DB->delete_records_select(
            'jitsi_push_subscriptions',
            'userid = :userid AND ' . $DB->sql_compare_text('endpoint') . ' = ' . $DB->sql_compare_text(':endpoint'),
            ['userid' => $USER->id, 'endpoint' => $params['endpoint']]
        );

        return ['success' => true];
    }

    /**
     * Returns description of unregister_push_subscription return value
     * @return external_description
     */
    public static function unregister_push_subscription_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether unregistration succeeded'),
        ]);
    }

    /**
     * Returns description of check_incoming_call parameters
     * @return external_function_parameters
     */
    public static function check_incoming_call_parameters() {
        return new external_function_parameters([
            'since' => new external_value(PARAM_INT, 'Unix timestamp to check from'),
        ]);
    }

    /**
     * Check if anyone has entered a private session room with the current user recently.
     *
     * @param int $since Unix timestamp
     * @return array
     */
    public static function check_incoming_call($since) {
        global $DB, $USER, $PAGE;

        $params = self::validate_parameters(self::check_incoming_call_parameters(), ['since' => $since]);
        $context = context_system::instance();
        self::validate_context($context);

        $eventname = '\mod_jitsi\event\jitsi_private_session_enter';
        $logs = $DB->get_records_select(
            'logstore_standard_log',
            'eventname = :eventname AND timecreated >= :since AND userid != :userid',
            ['eventname' => $eventname, 'since' => $params['since'], 'userid' => $USER->id],
            'timecreated DESC'
        );

        foreach ($logs as $log) {
            $other = json_decode($log->other, true);
            if (isset($other['peerid']) && (int)$other['peerid'] === (int)$USER->id) {
                $caller = $DB->get_record(
                    'user',
                    ['id' => $log->userid, 'deleted' => 0],
                    'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename, picture, imagealt, email', // phpcs:ignore moodle.Files.LineLength.MaxExceeded
                    IGNORE_MISSING
                );
                if ($caller) {
                    $userpicture = new user_picture($caller);
                    $userpicture->size = 1;
                    return [
                        'incoming'     => true,
                        'callerid'     => (int)$caller->id,
                        'callername'   => fullname($caller),
                        'calleravatar' => $userpicture->get_url($PAGE)->out(false),
                        'timecreated'  => (int)$log->timecreated,
                    ];
                }
            }
        }

        return [
            'incoming'     => false,
            'callerid'     => 0,
            'callername'   => '',
            'calleravatar' => '',
            'timecreated'  => 0,
        ];
    }

    /**
     * Returns description of check_incoming_call return value
     * @return external_description
     */
    public static function check_incoming_call_returns() {
        return new external_single_structure([
            'incoming'     => new external_value(PARAM_BOOL, 'Whether there is an incoming call'),
            'callerid'     => new external_value(PARAM_INT, 'Caller user ID'),
            'callername'   => new external_value(PARAM_TEXT, 'Caller full name'),
            'calleravatar' => new external_value(PARAM_URL, 'Caller avatar URL'),
            'timecreated'  => new external_value(PARAM_INT, 'Event timestamp'),
        ]);
    }

    /**
     * Returns description of get_tutoring_schedule parameters
     * @return external_function_parameters
     */
    public static function get_tutoring_schedule_parameters() {
        return new external_function_parameters([]);
    }

    /**
     * Get the current user's tutoring schedule grouped by course.
     *
     * @return array
     */
    public static function get_tutoring_schedule() {
        global $DB, $USER;

        $context = context_system::instance();
        self::validate_context($context);

        $slots = $DB->get_records(
            'jitsi_tutoring_schedule',
            ['userid' => $USER->id],
            'courseid ASC, weekday ASC, timestart ASC'
        );

        $courses = [];
        foreach ($slots as $slot) {
            $courseid = (int)$slot->courseid;
            if (!isset($courses[$courseid])) {
                $course = $DB->get_record('course', ['id' => $courseid], 'id, fullname', IGNORE_MISSING);
                $courses[$courseid] = [
                    'courseid'   => $courseid,
                    'coursename' => $course ? $course->fullname : '?',
                    'slots'      => [],
                ];
            }
            $h = intdiv((int)$slot->timestart, 3600);
            $m = intdiv(((int)$slot->timestart % 3600), 60);
            $hend = intdiv((int)$slot->timeend, 3600);
            $mend = intdiv(((int)$slot->timeend % 3600), 60);
            $courses[$courseid]['slots'][] = [
                'id'        => (int)$slot->id,
                'weekday'   => (int)$slot->weekday,
                'timestart' => sprintf('%02d:%02d', $h, $m),
                'timeend'   => sprintf('%02d:%02d', $hend, $mend),
            ];
        }

        return ['courses' => array_values($courses)];
    }

    /**
     * Returns description of get_tutoring_schedule return value
     * @return external_description
     */
    public static function get_tutoring_schedule_returns() {
        return new external_single_structure([
            'courses' => new external_multiple_structure(
                new external_single_structure([
                    'courseid'   => new external_value(PARAM_INT, 'Course ID'),
                    'coursename' => new external_value(PARAM_TEXT, 'Course name'),
                    'slots'      => new external_multiple_structure(
                        new external_single_structure([
                            'id'        => new external_value(PARAM_INT, 'Slot ID'),
                            'weekday'   => new external_value(PARAM_INT, 'Day of week (0=Sun)'),
                            'timestart' => new external_value(PARAM_TEXT, 'Start time HH:MM'),
                            'timeend'   => new external_value(PARAM_TEXT, 'End time HH:MM'),
                        ])
                    ),
                ])
            ),
        ]);
    }

    /**
     * Returns description of save_tutoring_slot parameters
     * @return external_function_parameters
     */
    public static function save_tutoring_slot_parameters() {
        return new external_function_parameters([
            'courseid'  => new external_value(PARAM_INT, 'Course ID'),
            'weekday'   => new external_value(PARAM_INT, 'Day of week 0=Sun, 6=Sat'),
            'timestart' => new external_value(PARAM_TEXT, 'Start time HH:MM'),
            'timeend'   => new external_value(PARAM_TEXT, 'End time HH:MM'),
        ]);
    }

    /**
     * Save a tutoring schedule slot for the current user.
     *
     * @param int $courseid
     * @param int $weekday
     * @param string $timestart HH:MM
     * @param string $timeend HH:MM
     * @return array
     */
    public static function save_tutoring_slot($courseid, $weekday, $timestart, $timeend) {
        global $DB, $USER;

        $params = self::validate_parameters(self::save_tutoring_slot_parameters(), [
            'courseid'  => $courseid,
            'weekday'   => $weekday,
            'timestart' => $timestart,
            'timeend'   => $timeend,
        ]);

        $context = context_system::instance();
        self::validate_context($context);

        // Validate course exists, is visible, and user is enrolled as teacher.
        $course = $DB->get_record('course', ['id' => $params['courseid'], 'visible' => 1], 'id', MUST_EXIST);
        $coursecontext = context_course::instance($course->id);
        if (!has_capability('mod/jitsi:addinstance', $coursecontext)) {
            throw new moodle_exception('nopermissions', 'error', '', 'save tutoring slot');
        }

        // Parse times.
        [$sh, $sm] = array_map('intval', explode(':', $params['timestart']));
        [$eh, $em] = array_map('intval', explode(':', $params['timeend']));
        $startsecs = $sh * 3600 + $sm * 60;
        $endsecs   = $eh * 3600 + $em * 60;

        if ($endsecs <= $startsecs) {
            throw new moodle_exception('error', 'mod_jitsi', '', 'End time must be after start time');
        }

        $now = time();
        $record = (object)[
            'userid'       => $USER->id,
            'courseid'     => $params['courseid'],
            'weekday'      => $params['weekday'],
            'timestart'    => $startsecs,
            'timeend'      => $endsecs,
            'timecreated'  => $now,
            'timemodified' => $now,
        ];
        $id = $DB->insert_record('jitsi_tutoring_schedule', $record);

        return ['id' => (int)$id];
    }

    /**
     * Returns description of save_tutoring_slot return value
     * @return external_description
     */
    public static function save_tutoring_slot_returns() {
        return new external_single_structure([
            'id' => new external_value(PARAM_INT, 'New slot ID'),
        ]);
    }

    /**
     * Returns description of delete_tutoring_slot parameters
     * @return external_function_parameters
     */
    public static function delete_tutoring_slot_parameters() {
        return new external_function_parameters([
            'slotid' => new external_value(PARAM_INT, 'Slot ID to delete'),
        ]);
    }

    /**
     * Delete a tutoring schedule slot (only the owner can delete).
     *
     * @param int $slotid
     * @return array
     */
    public static function delete_tutoring_slot($slotid) {
        global $DB, $USER;

        $params = self::validate_parameters(self::delete_tutoring_slot_parameters(), ['slotid' => $slotid]);
        $context = context_system::instance();
        self::validate_context($context);

        $slot = $DB->get_record('jitsi_tutoring_schedule', ['id' => $params['slotid']], 'id, userid', MUST_EXIST);
        if ((int)$slot->userid !== (int)$USER->id) {
            throw new moodle_exception('nopermissions', 'error', '', 'delete tutoring slot');
        }

        $DB->delete_records('jitsi_tutoring_schedule', ['id' => $params['slotid']]);

        return ['success' => true];
    }

    /**
     * Returns description of delete_tutoring_slot return value
     * @return external_description
     */
    public static function delete_tutoring_slot_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether deletion succeeded'),
        ]);
    }

    /**
     * Returns description of get_teacher_schedule parameters
     * @return external_function_parameters
     */
    public static function get_teacher_schedule_parameters() {
        return new external_function_parameters([
            'teacherid' => new external_value(PARAM_INT, 'Teacher user ID'),
        ]);
    }

    /**
     * Get tutoring schedule for a teacher visible to the current user (shared courses only).
     *
     * @param int $teacherid
     * @return array
     */
    public static function get_teacher_schedule($teacherid) {
        global $DB, $USER;

        $params = self::validate_parameters(self::get_teacher_schedule_parameters(), ['teacherid' => $teacherid]);
        $context = context_system::instance();
        self::validate_context($context);

        $availability = jitsi_check_tutoring_availability($params['teacherid'], $USER->id);

        $slots = [];
        if ($availability['hasschedule']) {
            // Return all slots for shared courses.
            $teacherroles = array_keys(get_archetype_roles('teacher') + get_archetype_roles('editingteacher'));
            $studentroles = array_keys(get_archetype_roles('student'));
            [$trolesql, $troleparams] = $DB->get_in_or_equal($teacherroles, SQL_PARAMS_NAMED, 'trole');
            [$srolesql, $sroleparams] = $DB->get_in_or_equal($studentroles, SQL_PARAMS_NAMED, 'srole');

            $teachercourses = $DB->get_fieldset_sql(
                "SELECT DISTINCT ctx.instanceid
                   FROM {role_assignments} ra
                   JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
                   JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
                  WHERE ra.userid = :teacherid AND ra.roleid $trolesql",
                array_merge(['ctxlevel' => CONTEXT_COURSE, 'teacherid' => $params['teacherid']], $troleparams)
            );

            if (!empty($teachercourses)) {
                [$coursesql, $courseparams] = $DB->get_in_or_equal($teachercourses, SQL_PARAMS_NAMED, 'course');
                $sharedcourses = $DB->get_fieldset_sql(
                    "SELECT DISTINCT ctx.instanceid
                       FROM {role_assignments} ra
                       JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
                       JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
                      WHERE ra.userid = :studentid AND ra.roleid $srolesql AND ctx.instanceid $coursesql",
                    array_merge(['ctxlevel' => CONTEXT_COURSE, 'studentid' => $USER->id], $sroleparams, $courseparams)
                );

                if (!empty($sharedcourses)) {
                    [$csql, $cparams] = $DB->get_in_or_equal($sharedcourses, SQL_PARAMS_NAMED, 'sc');
                    $records = $DB->get_records_select(
                        'jitsi_tutoring_schedule',
                        "userid = :teacherid AND courseid $csql",
                        array_merge(['teacherid' => $params['teacherid']], $cparams),
                        'weekday ASC, timestart ASC'
                    );
                    foreach ($records as $slot) {
                        $h = intdiv((int)$slot->timestart, 3600);
                        $m = intdiv(((int)$slot->timestart % 3600), 60);
                        $hend = intdiv((int)$slot->timeend, 3600);
                        $mend = intdiv(((int)$slot->timeend % 3600), 60);
                        $slots[] = [
                            'weekday'   => (int)$slot->weekday,
                            'timestart' => sprintf('%02d:%02d', $h, $m),
                            'timeend'   => sprintf('%02d:%02d', $hend, $mend),
                        ];
                    }
                }
            }
        }

        return [
            'hasschedule' => $availability['hasschedule'],
            'available'   => $availability['available'],
            'nextslot'    => $availability['nextslot'] ?? '',
            'slots'       => $slots,
        ];
    }

    /**
     * Returns description of get_teacher_schedule return value
     * @return external_description
     */
    public static function get_teacher_schedule_returns() {
        return new external_single_structure([
            'hasschedule' => new external_value(PARAM_BOOL, 'Has schedule'),
            'available'   => new external_value(PARAM_BOOL, 'Available now'),
            'nextslot'    => new external_value(PARAM_TEXT, 'Next slot label'),
            'slots'       => new external_multiple_structure(
                new external_single_structure([
                    'weekday'   => new external_value(PARAM_INT, 'Day of week'),
                    'timestart' => new external_value(PARAM_TEXT, 'Start HH:MM'),
                    'timeend'   => new external_value(PARAM_TEXT, 'End HH:MM'),
                ])
            ),
        ]);
    }

    /**
     * Parameters for log_recording_view.
     * @return external_function_parameters
     */
    public static function log_recording_view_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'jitsi_source_record id'),
            'cmid'           => new external_value(PARAM_INT, 'Course module id'),
            'milestone'      => new external_value(PARAM_INT, 'Percentage milestone: 0=play, 25, 50, 75, 100', VALUE_DEFAULT, 0),
        ]);
    }

    /**
     * Log that the current user played or reached a milestone in a GCS recording.
     *
     * @param int $sourcerecordid
     * @param int $cmid
     * @param int $milestone 0=play start, 25/50/75/100=percentage reached
     * @return array
     */
    public static function log_recording_view($sourcerecordid, $cmid, $milestone = 0) {
        global $DB;

        $params = self::validate_parameters(self::log_recording_view_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid'           => $cmid,
            'milestone'      => $milestone,
        ]);

        if (!in_array($params['milestone'], [0, 25, 50, 75, 100])) {
            return ['success' => false];
        }

        $context = context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $exists = $DB->record_exists_sql(
            "SELECT 1 FROM {jitsi_source_record} sr
               JOIN {jitsi_record} r ON r.source = sr.id
               JOIN {jitsi} j ON j.id = r.jitsi
               JOIN {course_modules} cm ON cm.instance = j.id
              WHERE sr.id = :srid AND cm.id = :cmid",
            ['srid' => $params['sourcerecordid'], 'cmid' => $params['cmid']]
        );

        if (!$exists) {
            return ['success' => false];
        }

        $event = \mod_jitsi\event\recording_viewed::create([
            'context'  => $context,
            'objectid' => $params['sourcerecordid'],
            'other'    => ['milestone' => $params['milestone']],
        ]);
        $event->trigger();

        return ['success' => true];
    }

    /**
     * Returns for log_recording_view.
     * @return external_description
     */
    public static function log_recording_view_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the event was logged'),
        ]);
    }

    /**
     * Parameters for save_recording_segments.
     * @return external_function_parameters
     */
    public static function save_recording_segments_parameters() {
        return new external_function_parameters([
            'sourcerecordid' => new external_value(PARAM_INT, 'jitsi_source_record id'),
            'cmid'           => new external_value(PARAM_INT, 'Course module id'),
            'segments'       => new external_value(PARAM_TEXT, 'JSON array of [start,end] pairs in seconds'),
            'duration'       => new external_value(PARAM_FLOAT, 'Video duration in seconds'),
        ]);
    }

    /**
     * Save and merge watched segments for a GCS recording.
     *
     * @param int    $sourcerecordid
     * @param int    $cmid
     * @param string $segments JSON [[start,end],...]
     * @param float  $duration video duration in seconds
     * @return array
     */
    public static function save_recording_segments($sourcerecordid, $cmid, $segments, $duration) {
        global $DB, $USER;

        $params = self::validate_parameters(self::save_recording_segments_parameters(), [
            'sourcerecordid' => $sourcerecordid,
            'cmid'           => $cmid,
            'segments'       => $segments,
            'duration'       => $duration,
        ]);

        $context = context_module::instance($params['cmid']);
        self::validate_context($context);
        require_capability('mod/jitsi:view', $context);

        $exists = $DB->record_exists_sql(
            "SELECT 1 FROM {jitsi_source_record} sr
               JOIN {jitsi_record} r ON r.source = sr.id
               JOIN {jitsi} j ON j.id = r.jitsi
               JOIN {course_modules} cm ON cm.instance = j.id
              WHERE sr.id = :srid AND cm.id = :cmid",
            ['srid' => $params['sourcerecordid'], 'cmid' => $params['cmid']]
        );
        if (!$exists) {
            return ['success' => false, 'segments' => '[]'];
        }

        $newsegments = json_decode($params['segments'], true);
        if (!is_array($newsegments)) {
            return ['success' => false, 'segments' => '[]'];
        }

        $existing = $DB->get_record('jitsi_recording_segments', [
            'userid'         => $USER->id,
            'sourcerecordid' => $params['sourcerecordid'],
            'cmid'           => $params['cmid'],
        ]);

        $allsegs = $newsegments;
        if ($existing) {
            $stored = json_decode($existing->segments, true);
            if (is_array($stored)) {
                $allsegs = array_merge($stored, $newsegments);
            }
        }

        $merged     = self::merge_segments($allsegs, (float)$params['duration']);
        $mergedjson = json_encode($merged);

        if ($existing) {
            $existing->segments     = $mergedjson;
            $existing->duration     = (float)$params['duration'];
            $existing->timemodified = time();
            $DB->update_record('jitsi_recording_segments', $existing);
        } else {
            $DB->insert_record('jitsi_recording_segments', (object)[
                'userid'         => $USER->id,
                'sourcerecordid' => $params['sourcerecordid'],
                'cmid'           => $params['cmid'],
                'segments'       => $mergedjson,
                'duration'       => (float)$params['duration'],
                'timecreated'    => time(),
                'timemodified'   => time(),
            ]);
        }

        return ['success' => true, 'segments' => $mergedjson];
    }

    /**
     * Merge and clamp an array of [start,end] segments.
     *
     * @param array $segments
     * @param float $duration
     * @return array
     */
    private static function merge_segments(array $segments, float $duration): array {
        $segments = array_values(array_filter($segments, function($s) use ($duration) {
            return is_array($s) && count($s) === 2
                && is_numeric($s[0]) && is_numeric($s[1])
                && $s[1] > $s[0] && $s[0] >= 0
                && ($duration <= 0 || $s[1] <= $duration + 2);
        }));
        if (empty($segments)) {
            return [];
        }
        usort($segments, fn($a, $b) => $a[0] <=> $b[0]);
        $merged = [[(float)$segments[0][0], (float)$segments[0][1]]];
        for ($i = 1; $i < count($segments); $i++) {
            $last = &$merged[count($merged) - 1];
            $s0 = (float)$segments[$i][0];
            $s1 = (float)$segments[$i][1];
            if ($s0 <= $last[1]) {
                $last[1] = max($last[1], $s1);
            } else {
                $merged[] = [$s0, $s1];
            }
        }
        return $merged;
    }

    /**
     * Returns for save_recording_segments.
     * @return external_description
     */
    public static function save_recording_segments_returns() {
        return new external_single_structure([
            'success'  => new external_value(PARAM_BOOL, 'Whether segments were saved'),
            'segments' => new external_value(PARAM_TEXT, 'Merged segments as JSON'),
        ]);
    }
}
