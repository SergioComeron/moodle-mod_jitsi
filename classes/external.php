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
}
