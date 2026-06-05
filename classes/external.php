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
        $record = $DB->get_record('jitsi_record', ['source' => $idsource], '*', MUST_EXIST);
        $cm = get_coursemodule_from_instance('jitsi', $record->jitsi, 0, false, MUST_EXIST);
        require_login($cm->course, false, $cm);
        require_capability('mod/jitsi:deleterecord', context_module::instance($cm->id));
        $record->deleted = 1;
        $DB->update_record('jitsi_record', $record);
        return deleterecordyoutube($idsource);
    }

    /**
     * Returns description of method result value
     * @return external_description
     */
    public static function delete_record_youtube_returns() {
        return new external_value(PARAM_TEXT, 'Video deleted');
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

        // Validate there is an active streaming account before creating any record.
        $account = $DB->get_record('jitsi_record_account', ['inuse' => 1]);
        if (empty($account)) {
            return [
                'stream' => 'nodata',
                'idsource' => 0,
                'error' => 'erroraccount',
                'user' => $userid,
                'usercomplete' => $author->firstname . ' ' . $author->lastname,
                'errorinfo' => 'No active YouTube streaming account is configured. '
                    . 'Add or re-authorise an account in Site administration > Plugins > '
                    . 'Activity modules > Jitsi > Streaming/Recording accounts.',
                'link' => '',
            ];
        }

        // Obtain the Google client. getclientgoogleapi() returns false (or throws)
        // when the account token expired and could not be refreshed, i.e. the
        // account needs to be re-authorised. Handle it cleanly instead of letting
        // a fatal error surface to the user as a generic "Internal error".
        try {
            $client = getclientgoogleapi();
        } catch (\Exception $e) {
            return [
                'stream' => 'nodata',
                'idsource' => 0,
                'error' => 'erroraccount',
                'user' => $userid,
                'usercomplete' => $author->firstname . ' ' . $author->lastname,
                'errorinfo' => $e->getMessage(),
                'link' => '',
            ];
        }
        if ($client === false) {
            return [
                'stream' => 'nodata',
                'idsource' => 0,
                'error' => 'erroraccount',
                'user' => $userid,
                'usercomplete' => $author->firstname . ' ' . $author->lastname,
                'errorinfo' => 'The YouTube account "' . $account->name . '" needs to be '
                    . 're-authorised. Delete and re-add it in Site administration > Plugins > '
                    . 'Activity modules > Jitsi > Streaming/Recording accounts.',
                'link' => '',
            ];
        }
        $youtube = new Google_Service_YouTube($client);

        $source = new stdClass();
        $source->account = $account->id;
        $source->timecreated = time();
        $source->userid = $userid;
        $source->link = '';

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
            $result['stream'] = isset($streamsresponse['cdn']['ingestionInfo']['streamName'])
                ? $streamsresponse['cdn']['ingestionInfo']['streamName']
                : 'nodata';
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
            $result['stream'] = isset($streamsresponse['cdn']['ingestionInfo']['streamName'])
                ? $streamsresponse['cdn']['ingestionInfo']['streamName']
                : 'nodata';
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
     * Returns description of method parameters
     * @return external_function_parameters
     */
    public static function getminutesfromlastconexion_returns() {
        return new external_value(PARAM_INT, 'Last conexion timestamp');
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
}
