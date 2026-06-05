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
 * External API: start a YouTube live stream for a Jitsi session.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class create_stream extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'session' => new external_value(PARAM_TEXT, 'Session object from google', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
            'userid' => new external_value(PARAM_INT, 'User id', VALUE_REQUIRED, '', NULL_NOT_ALLOWED),
        ]);
    }

    /**
     * Start a YouTube live stream.
     *
     * @param string $session session
     * @param int $jitsi Jitsi session id
     * @param int $userid User id
     * @return array result
     */
    public static function execute($session, $jitsi, $userid) {
        global $CFG, $DB;
        require_once($CFG->dirroot . '/mod/jitsi/lib.php');

        $params = self::validate_parameters(
            self::execute_parameters(),
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
        $youtube = new \Google_Service_YouTube($client);

        $source = new \stdClass();
        $source->account = $account->id;
        $source->timecreated = time();
        $source->userid = $userid;
        $source->link = '';

        $record = new \stdClass();
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
            $broadcastsnippet = new \Google_Service_YouTube_LiveBroadcastSnippet();
            $testdate = time();

            $broadcastsnippet->setTitle("Record " . date('Y-m-d\T H:i A', $testdate));
            $broadcastsnippet->setScheduledStartTime(date('Y-m-d\TH:i:s', $testdate));

            $status = new \Google_Service_YouTube_LiveBroadcastStatus();
            $status->setPrivacyStatus('unlisted');
            if (get_config('mod_jitsi', 'selfdeclaredmadeforkids') == 0) {
                $status->setSelfDeclaredMadeForKids('false');
            } else {
                $status->setSelfDeclaredMadeForKids('true');
            }
            $contentdetails = new \Google_Service_YouTube_LiveBroadcastContentDetails();
            $contentdetails->setEnableAutoStart(true);
            $contentdetails->setEnableAutoStop(true);
            if (get_config('mod_jitsi', 'latency') == 0) {
                $contentdetails->setLatencyPreference("normal");
            } else if (get_config('mod_jitsi', 'latency') == 1) {
                $contentdetails->setLatencyPreference("low");
            } else if (get_config('mod_jitsi', 'latency') == 2) {
                $contentdetails->setLatencyPreference("ultralow");
            }

            $broadcastinsert = new \Google_Service_YouTube_LiveBroadcast();
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

            $streamsnippet = new \Google_Service_YouTube_LiveStreamSnippet();
            $streamsnippet->setTitle("Record " . date('l jS \of F', $testdate));

            $cdn = new \Google_Service_YouTube_CdnSettings();
            $cdn->setIngestionType('rtmp');
            $cdn->setResolution("variable");
            $cdn->setFrameRate("variable");

            $streaminsert = new \Google_Service_YouTube_LiveStream();
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
        } catch (\Google_Service_Exception $e) {
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
        } catch (\Google_Exception $e) {
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
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
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
}
