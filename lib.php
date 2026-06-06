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
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/* Moodle core API */
defined('MOODLE_INTERNAL') || die();
require_once(__DIR__ . '/deprecatedlib.php');


/**
 * Returns the information on whether the module supports a feature
 *
 * See plugin_supports() for more info.
 *
 * @param string $feature FEATURE_xx constant for requested feature
 * @return mixed true if the feature is supported, null if unknown
 */
function jitsi_supports($feature) {
    global $CFG;
    if ($CFG->branch >= 400) {
        switch ($feature) {
            case FEATURE_MOD_INTRO:
                return true;
            case FEATURE_SHOW_DESCRIPTION:
                return true;
            case FEATURE_BACKUP_MOODLE2:
                return true;
            case FEATURE_COMPLETION_HAS_RULES:
                return true;
            case FEATURE_MOD_PURPOSE:
                return MOD_PURPOSE_COMMUNICATION;
            default:
                return null;
        }
    } else {
        switch ($feature) {
            case FEATURE_MOD_INTRO:
                return true;
            case FEATURE_SHOW_DESCRIPTION:
                return true;
            case FEATURE_BACKUP_MOODLE2:
                return true;
            case FEATURE_COMPLETION_HAS_RULES:
                return true;
            default:
                return null;
        }
    }
}

/**
 * Check if a GCP server instance is running
 *
 * @param stdClass $server Server record from jitsi_servers table
 * @return array Array with 'status' ('running'|'stopped'|'error') and optional 'message'
 */
function jitsi_check_gcp_server_status($server) {
    // Only check GCP servers (type 3).
    if ($server->type != 3) {
        return ['status' => 'running']; // Non-GCP servers are always considered "running".
    }

    // Check if server is still provisioning.
    if ($server->provisioningstatus === 'provisioning' || $server->provisioningstatus === 'error') {
        return [
            'status' => 'error',
            'message' => 'Server is still being provisioned or has an error',
        ];
    }

    // If no GCP instance name, assume it's not a GCP-managed server.
    if (empty($server->gcpinstancename) || empty($server->gcpproject) || empty($server->gcpzone)) {
        return ['status' => 'running'];
    }

    // Check if Google API client is available.
    $autoloader = __DIR__ . '/api/vendor/autoload.php';
    if (!file_exists($autoloader)) {
        return [
            'status' => 'error',
            'message' => 'Google API client not installed',
        ];
    }

    try {
        require_once($autoloader);

        // Initialize Google Client.
        $client = new \Google\Client();
        $client->setScopes(['https://www.googleapis.com/auth/cloud-platform']);

        // Try to read Service Account uploaded via settings.
        $fs = get_file_storage();
        $context = context_system::instance();
        $files = $fs->get_area_files($context->id, 'mod_jitsi', 'gcpserviceaccountjson', 0, 'itemid, filepath, filename', false);

        if (!empty($files)) {
            $file = reset($files);
            $jsoncontent = $file->get_content();
            $client->setAuthConfig(json_decode($jsoncontent, true));
        } else {
            // Fallback to Application Default Credentials.
            $client->useApplicationDefaultCredentials();
        }

        $compute = new \Google\Service\Compute($client);

        // Get instance status.
        $instance = $compute->instances->get(
            $server->gcpproject,
            $server->gcpzone,
            $server->gcpinstancename
        );

        $status = $instance->getStatus();

        // Possible statuses: PROVISIONING, STAGING, RUNNING, STOPPING, STOPPED, SUSPENDING, SUSPENDED, TERMINATED.
        if ($status === 'RUNNING') {
            return ['status' => 'running'];
        } else if ($status === 'STOPPED' || $status === 'TERMINATED' || $status === 'SUSPENDED') {
            return [
                'status' => 'stopped',
                'message' => 'Instance status: ' . $status,
            ];
        } else {
            return [
                'status' => 'transitioning',
                'message' => 'Instance status: ' . $status,
            ];
        }
    } catch (Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage(),
        ];
    }
}

/**
 * Saves a new instance of the jitsi into the database
 *
 * Given an object containing all the necessary data,
 * (defined by the form in mod_form.php) this function
 * will create a new instance and return the id number
 * of the new instance.
 *
 * @param stdClass $jitsi Submitted data from the form in mod_form.php
 * @param mod_jitsi_mod_form $mform The form instance itself (if needed)
 * @return int The id of the newly inserted jitsi record
 */
function jitsi_add_instance($jitsi, $mform = null) {
    global $CFG, $DB;
    require_once($CFG->dirroot . '/mod/jitsi/locallib.php');
    $time = time();
    $jitsi->timecreated = $time;
    $cmid = $jitsi->coursemodule;
    $jitsi->id = $DB->insert_record('jitsi', $jitsi);
    jitsi_update_calendar($jitsi, $cmid);
    return $jitsi->id;
}

/**
 * Updates an instance of the jitsi in the database
 *
 * Given an object containing all the necessary data,
 * (defined by the form in mod_form.php) this function
 * will update an existing instance with new data.
 *
 * @param stdClass $jitsi An object from the form in mod_form.php
 * @param mod_jitsi_mod_form $mform The form instance itself (if needed)
 * @return boolean Success/Fail
 */
function jitsi_update_instance($jitsi, $mform = null) {
    global $CFG, $DB;
    require_once($CFG->dirroot . '/mod/jitsi/locallib.php');

    $jitsi->timemodified = time();
    $jitsi->id = $jitsi->instance;
    $cmid = $jitsi->coursemodule;

    $result = $DB->update_record('jitsi', $jitsi);
    jitsi_update_calendar($jitsi, $cmid);

    return $result;
}

/**
 * This standard function will check all instances of this module
 * and make sure there are up-to-date events created for each of them.
 * If courseid = 0, then every assignment event in the site is checked, else
 * only assignment events belonging to the course specified are checked.
 *
 * @param int $courseid
 * @param int|stdClass $instance Jitsi module instance or ID.
 * @param int|stdClass $cm Course module object or ID.
 * @return bool
 */
function jitsi_refresh_events($courseid = 0, $instance = null, $cm = null) {
    global $CFG, $DB;
    require_once($CFG->dirroot . '/mod/jitsi/locallib.php');

    if (isset($instance)) {
        if (!is_object($instance)) {
            $instance = $DB->get_record('jitsi', ['id' => $instance], '*', MUST_EXIST);
        }
        if (isset($cm)) {
            if (!is_object($cm)) {
                $cm = (object) ['id' => $cm];
            }
        } else {
            $cm = get_coursemodule_from_instance('jitsi', $instance->id);
        }
        jitsi_update_calendar($instance, $cm->id);
        return true;
    }

    if ($courseid) {
        if (!is_numeric($courseid)) {
            return false;
        }
        if (!$jitsis = $DB->get_records('jitsi', ['course' => $courseid])) {
            return true;
        }
    } else {
        return true;
    }

    foreach ($jitsis as $jitsi) {
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id);
        jitsi_update_calendar($jitsi, $cm->id);
    }

    return true;
}

/**
 * Removes an instance of the jitsi from the database
 *
 * Given an ID of an instance of this module,
 * this function will permanently delete the instance
 * and any data that depends on it.
 *
 * @param int $id Id of the module instance
 * @return boolean Success/Failure
 */
function jitsi_delete_instance($id) {
    global $CFG, $DB;

    if (! $jitsi = $DB->get_record('jitsi', ['id' => $id])) {
        return false;
    }

    $result = true;
    $DB->delete_records('jitsi_record', ['jitsi' => $jitsi->id]);

    if (! $DB->delete_records('jitsi', ['id' => $jitsi->id])) {
        $result = false;
    }

    return $result;
}

/**
 * Jitsi private sessions on profile user
 *
 * @param tree $tree tree
 * @param stdClass $user user
 * @param int $iscurrentuser iscurrentuser
 */
function jitsi_myprofile_navigation(core_user\output\myprofile\tree $tree, $user, $iscurrentuser) {
    global $DB, $CFG, $USER;
    if (get_config('mod_jitsi', 'privatesessions') == 1) {
        $category = new core_user\output\myprofile\category(
            'jitsi',
            get_string('jitsi', 'jitsi'),
            null,
        );
        $tree->add_category($category);
        if ($iscurrentuser == 0) {
            // Only show the call link if both users share at least one course.
            $sharedcourses = enrol_get_shared_courses($USER->id, $user->id, true);
            if (!empty($sharedcourses)) {
                $url = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $user->id]);
                $node = new core_user\output\myprofile\node(
                    'jitsi',
                    'jitsi',
                    get_string('startprivatesession', 'jitsi', $user->firstname),
                    null,
                    $url,
                );
                $tree->add_node($node);
            }
        } else {
            $url = new moodle_url('/mod/jitsi/call.php');
            $node = new core_user\output\myprofile\node(
                'jitsi',
                'jitsi',
                get_string('callsomeone', 'jitsi'),
                null,
                $url,
            );
            $tree->add_node($node);
        }
    }
    return true;
}

/**
 * Create privatesession
 * @param int $teacher - Moderation
 * @param int $cmid - Course module
 * @param string $avatar - Avatar
 * @param string $nombre - Name
 * @param string $session - sesssion name
 * @param string $mail - mail
 * @param stdClass $jitsi - Jitsi session
 * @param bool $universal - Say if is universal session
 * @param stdClass $user - User object
 */
function createsessionpriv(
    $teacher,
    $cmid,
    $avatar,
    $nombre,
    $session,
    $mail,
    $jitsi,
    $universal = false,
    $user = null
) {
    global $CFG, $DB, $PAGE, $USER, $OUTPUT;
    $serverid = get_config('mod_jitsi', 'server');
    $server = $DB->get_record('jitsi_servers', ['id' => $serverid]);

    if (!$server) {
        echo $OUTPUT->notification(get_string('nodefaultserver', 'jitsi'), 'error');
        return;
    }

    // Check if GCP server is running.
    $serverstatus = jitsi_check_gcp_server_status($server);
    if ($serverstatus['status'] === 'stopped') {
        echo $OUTPUT->notification(get_string('gcpserverstopped', 'jitsi'), 'error');
        return;
    } else if ($serverstatus['status'] === 'error') {
        $errormsg = isset($serverstatus['message']) ? $serverstatus['message'] : 'Unknown error';
        echo $OUTPUT->notification(get_string('gcpservererror', 'jitsi', $errormsg), 'error');
        return;
    }

    $servertype = $server->type;
    $appid = $server->appid;
    $domain = $server->domain;
    $secret = $server->secret;
    $eightbyeightappid = $server->eightbyeightappid;
    $eightbyeightapikeyid = $server->eightbyeightapikeyid;
    $privatykey = $server->privatekey;

    $sessionnorm = \mod_jitsi\local\room::normalize_session_name($session);
    if ($teacher == 1) {
        $teacher = true;
        $affiliation = "owner";
    } else {
        $teacher = false;
        $affiliation = "member";
    }
    if ($user != null) {
        $context = context_system::instance();
    } else {
        $context = context_module::instance($cmid);
    }

    if ($universal == false) {
        if (!has_capability('mod/jitsi:view', $context)) {
            notice(get_string('noviewpermission', 'jitsi'));
        }
    }

    echo '<style>
    .cuadrado-wrapper {
        position: relative;
        display: flex;
        justify-content: center;
        align-items: center;
        overflow: hidden;
    }
    .jitsi-container {
        width: calc(90vw);
        height: calc(90vw * 9 / 16);
        max-width: calc(90vh * 16 / 9);
        max-height: calc(90vh);
    }
    </style>';
    echo '<div class="cuadrado-wrapper"><div class="jitsi-container" id="jitsi-container"></div></div>';

    echo "<script src=\"//ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js\"></script>";
    echo "<script src=\"https://" . $domain . "/external_api.js\"></script>\n";

    // Recording and live streaming are disabled in private sessions — they have no
    // associated jitsi activity, so recordings cannot be stored or displayed.
    $streamingoption = '';
    $record = '';

    $youtubeoption = '';
    if (get_config('mod_jitsi', 'shareyoutube') == 1) {
        $youtubeoption = 'sharedvideo';
    }
    $bluroption = '';
    if (get_config('mod_jitsi', 'blurbutton') == 1) {
        $bluroption = 'select-background';
    }
    $security = '';
    if (get_config('mod_jitsi', 'securitybutton') == 1) {
        $security = 'security';
    }
    $invite = '';
    $muteeveryone = '';
    $mutevideoeveryone = '';
    if (has_capability('mod/jitsi:moderation', $PAGE->context)) {
        $muteeveryone = 'mute-everyone';
        $mutevideoeveryone = 'mute-video-everyone';
    }

    $participantspane = '';
    if (
        has_capability('mod/jitsi:moderation', $PAGE->context) ||
        get_config('mod_jitsi', 'participantspane') == 1
    ) {
        $participantspane = 'participants-pane';
    }

    $raisehand = '';
    if (get_config('mod_jitsi', 'raisehand') == 1) {
        $raisehand = 'raisehand';
    }

    $whiteboard = '';
    if (get_config('mod_jitsi', 'whiteboard') == 1) {
        $whiteboard = 'whiteboard';
    }

    $buttons = "['microphone', 'camera', 'closedcaptions', 'desktop', 'fullscreen',
        'fodeviceselection', 'hangup', 'chat', '" . $record . "', 'etherpad', '" . $youtubeoption . "',
        'settings', '" . $raisehand . "', 'videoquality', '" . $streamingoption . "', 'filmstrip', '" . $invite . "', 'stats',
        'shortcuts', 'tileview', '" . $bluroption . "', 'download', 'help', '" . $muteeveryone . "',
        '" . $mutevideoeveryone . "', '" . $security . "', '" . $participantspane . "', '" . $whiteboard . "']";

    echo "<div class=\"row\">";
    echo "<div class=\"col-sm\">";

    $account = $DB->get_record('jitsi_record_account', ['inuse' => 1]);

    echo "<div class=\"row\">";
    echo "<div class=\"col-sm-9\">";
    echo "<div id=\"state\"><div class=\"alert alert-light\" role=\"alert\"></div></div>";
    echo "</div>";
    if ($CFG->branch >= 500) {
        echo "<div class=\"col-sm-3 text-end\">";
    } else {
        echo "<div class=\"col-sm-3 text-right\">";
    }

    echo "</div>";
    echo "</div>";

    echo "</div></div>";
    echo "<hr>";

    echo "<script>\n";
    echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
    echo "  document.getElementById(\"recordSwitch\").disabled = true;\n";
    echo "  setTimeout(function() { document.getElementById(\"recordSwitch\").disabled = false; }, 5000);\n";
    echo "}\n";

    echo "const domain = \"" . $domain . "\";\n";
    echo "const options = {\n";
    echo "configOverwrite: {\n";

    echo "breakoutRooms: {";
    if (get_config('mod_jitsi', 'allowbreakoutrooms') == '1') {
        echo "    hideAddRoomButton: false,";
        echo "    hideAutoAssignButton: false,";
        echo "    hideJoinRoomButton: false,";
    } else {
        echo "    hideAddRoomButton: true,";
        echo "    hideAutoAssignButton: true,";
        echo "    hideJoinRoomButton: true,";
    }
    echo "},";

    echo "subject: '" . $jitsi->name . "',\n";
    echo "disableSelfView: false,\n";
    echo "defaultLanguage: '" . current_language() . "',\n";
    echo "disableInviteFunctions: true,\n";
    echo "recordingService: {\n";
    if (get_config('mod_jitsi', 'livebutton') == 1) {
        echo "enabled: true,\n";
    } else {
        echo "enabled: false,\n";
    }
    echo "},\n";
    // Private sessions never allow recording or live streaming.
    echo "fileRecordingsEnabled: false,\n";
    echo "liveStreamingEnabled: false,\n";
    echo "remoteVideoMenu: {\n";
    echo "disableGrantModerator: true, \n";
    echo "},\n";

    echo "buttonsWithNotifyClick: [
           {
                key: 'camera',
                preventExecution: false
           },
           {
                key: 'desktop',
                preventExecution: false
           },
           {
                key: 'tileview',
                preventExecution: false
           },
           {
                key: 'chat',
                preventExecution: false
           },
           {
                key: 'chat',
                preventExecution: false
           },
           {
                key: 'microphone',
                preventExecution: false
           },
           {
                key: '__end',
                preventExecution: true
           }
    ],\n";

    echo "disableDeepLinking: true,\n";

    if (!has_capability('mod/jitsi:moderation', $PAGE->context)) {
        echo "remoteVideoMenu: {\n";
        echo "    disableKick: true,\n";
        echo "    disableGrantModerator: true\n";
        echo "},\n";
        echo "disableRemoteMute: true,\n";
    }

    if (get_config('mod_jitsi', 'reactions') == 0) {
        echo "disableReactions: true,\n";
    }

    if (get_config('mod_jitsi', 'chat') == 0) {
        echo "disableChat: true,\n";
        echo "disablePolls: true,\n";
    } else if (get_config('mod_jitsi', 'polls') == 0) {
        echo "disablePolls: true,\n";
    }

    echo "toolbarButtons: " . $buttons . ",\n";
    echo "disableProfile: true,\n";
    echo "prejoinPageEnabled: false,\n";
    echo "prejoinConfig: { enabled: false },\n";
    echo "channelLastN: " . get_config('mod_jitsi', 'channellastcam') . ",\n";
    if (get_config('mod_jitsi', 'startwithaudiomuted') == '1') {
        echo "startWithAudioMuted: true,\n";
    } else {
        echo "startWithAudioMuted: false,\n";
    }

    if (get_config('mod_jitsi', 'startwithvideomuted') == '1') {
        echo "startWithVideoMuted: true,\n";
    } else {
        echo "startWithVideoMuted: false,\n";
    }
    if ($servertype != 2) {
        $dropboxappkey = get_config('mod_jitsi', 'dropbox_appkey');
        if (!empty($dropboxappkey)) {
            echo "dropbox: {\n";
            echo "    appKey: '" . addslashes($dropboxappkey) . "',\n";
            $dropboxredirecturi = get_config('mod_jitsi', 'dropbox_redirect_uri');
            if (!empty($dropboxredirecturi)) {
                echo "    redirectURI: '" . addslashes($dropboxredirecturi) . "',\n";
            }
            echo "},\n";
        }
    }
    if (get_config('mod_jitsi', 'transcription') == 0) {
        echo "transcription: { enabled: false },\n";
    }
    echo "},\n";

    if ($servertype == '2') {
        $header = json_encode([
            "kid" => $eightbyeightapikeyid,
            "typ" => "JWT",
            "alg" => "RS256",
        ]);

        $payload = json_encode([
            'iss' => 'chat',
            'aud' => 'jitsi',
            'exp' => time() + 24 * 3600,
            'nbf' => time() - 10,
            'room' => '*',
            'sub' => $eightbyeightappid,
            'context' => [
                'user' => [
                    'moderator' => $teacher || has_capability('mod/jitsi:moderation', $PAGE->context),
                    'email' => $mail,
                    'name' => $nombre,
                    'avatar' => $avatar,
                    'id' => "",
                ],
                'features' => [
                    'recording' => false,
                    'livestreaming' => false,
                    'transcription' => $teacher,
                    'outbound-call' => $teacher,
                ],
            ],
        ]);
        echo "roomName: \"" . $eightbyeightappid . "/" . urlencode($sessionnorm) . "\",\n";
        $payloadencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $headerencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        openssl_sign($headerencoded . "." . $payloadencoded, $signature, $privatykey, OPENSSL_ALGO_SHA256);
    } else if (get_config('mod_jitsi', 'tokentype') == '1' || $servertype == '1' || $servertype == '3') {
        $header = json_encode([
            "kid" => "jitsi/custom_key_name",
            "typ" => "JWT",
            "alg" => "HS256",
        ], JSON_UNESCAPED_SLASHES);
        $base64urlheader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $ismoderator = $teacher || has_capability('mod/jitsi:moderation', $PAGE->context);
        $payload = json_encode([
            "context" => [
                "user" => [
                    "affiliation" => $affiliation,
                    "avatar" => $avatar,
                    "name" => $nombre,
                    "email" => $mail,
                    "id" => "",
                    "moderator" => $ismoderator,
                ],
                "group" => "",
            ],
            "aud" => "jitsi",
            "iss" => $appid,
            "sub" => $domain,
            "room" => urlencode($sessionnorm),
            "exp" => time() + 24 * 3600,
            "moderator" => $ismoderator,
        ], JSON_UNESCAPED_SLASHES);
        echo "roomName: \"" . urlencode($sessionnorm) . "\",\n";
        $payloadencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
        $headerencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $signature = hash_hmac('sha256', $headerencoded . "." . $payloadencoded, $secret, true);
    } else {
        echo "roomName: \"" . urlencode($sessionnorm) . "\",\n";
    }

    if (
        ($servertype == '1' && ($appid != null && $secret != null)) ||
        ($servertype == '3' && ($appid != null && $secret != null)) ||
        $servertype == '2'
    ) {
        $signatureencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
        $jwt = $headerencoded . "." . $payloadencoded . "." . $signatureencoded;

        echo "jwt: \"" . $jwt . "\",\n";
    }

    if ($CFG->branch < 36) {
        $themeconfig = theme_config::load($CFG->theme);
        if ($CFG->theme == 'boost' || in_array('boost', $themeconfig->parents)) {
            echo "parentNode: document.querySelector('#region-main .card-body'),\n";
        } else {
            echo "parentNode: document.querySelector('#region-main'),\n";
        }
    } else {
        echo "parentNode: document.querySelector('#jitsi-container'),\n";
    }
    echo "interfaceConfigOverwrite:{\n";
    echo "TOOLBAR_BUTTONS: " . $buttons . ",\n";
    echo "SHOW_JITSI_WATERMARK: true,\n";
    echo "JITSI_WATERMARK_LINK: '" . get_config('mod_jitsi', 'watermarklink') . "',\n";
    echo "},\n";
    echo "width: '100%',\n";
    echo "height: '100%',\n";
    echo "}\n";
    echo "const api = new JitsiMeetExternalAPI(domain, options);\n";

    if (get_config('mod_jitsi', 'finishandreturn') == 1) {
        echo "api.on('readyToClose', () => {\n";
        echo "    api.dispose();\n";
        if ($universal == false && $user == null) {
            echo "    location.href=\"" . $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid . "\";";
        } else if ($universal == true && $user == null) {
            echo "    location.href=\"" . $CFG->wwwroot . "/mod/jitsi/formuniversal.php?t=" . $jitsi->token . "\";";
        } else if ($user != null) {
            echo "    location.href=\"" . $CFG->wwwroot . "/mod/jitsi/call.php\";";
        }
        echo  "});\n";
    }

    if (get_config('mod_jitsi', 'password') != null) {
        echo "api.addEventListener('participantRoleChanged', function(event) {\n";
        echo "    if (event.role === \"moderator\") {\n";
        echo "        api.executeCommand('password', '" . get_config('mod_jitsi', 'password') . "');\n";
        echo "    }\n";
        echo "});\n";
        echo "api.on('passwordRequired', function () {\n";
        echo "    api.executeCommand('password', '" . get_config('mod_jitsi', 'password') . "');\n";
        echo "});\n";
    }
    echo "</script>\n";
}

 /**
  * Get icon mapping for font-awesome.
  */
function mod_jitsi_get_fontawesome_icon_map() {
    return [
        'mod_forum:t/add' => 'share-alt-square',
    ];
}

/**
 * For edit record name
 * @param stdClass $itemtype - Type item
 * @param int $itemid - item id
 * @param string $newvalue - new value
 */
function mod_jitsi_inplace_editable($itemtype, $itemid, $newvalue) {
    if ($itemtype === 'recordname') {
        global $DB, $PAGE;
        $record = $DB->get_record('jitsi_record', ['id' => $itemid], '*', MUST_EXIST);
        // Must call validate_context for either system, or course or course module context.
        // This will both check access and set current context.
        $record  = $DB->get_record('jitsi_record', ['id' => $itemid], '*', MUST_EXIST);
        $jitsi   = $DB->get_record('jitsi', ['id' => $record->jitsi], '*', MUST_EXIST);
        $course  = $DB->get_record('course', ['id' => $jitsi->course], '*', MUST_EXIST);
        $cm      = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $context = context_module::instance($cm->id);
        $PAGE->set_context($context);
        // Clean input and update the record.
        $newvalue = clean_param($newvalue, PARAM_NOTAGS);
        $DB->update_record('jitsi_record', ['id' => $itemid, 'name' => $newvalue]);
        // Prepare the element for the output.
        $record->name = $newvalue;
        return new \core\output\inplace_editable(
            'mod_jitsi',
            'recordname',
            $record->id,
            true,
            format_string($record->name),
            $record->name,
            get_string('editrecordname', 'jitsi'),
            get_string('newvaluefor', 'jitsi') . format_string($record->name),
        );
    }
}

/**
 * Add a get_coursemodule_info function in case any jitsi type wants to add 'extra' information
 * for the course (see resource).
 *
 * Given a course_module object, this function returns any "extra" information that may be needed
 * when printing this activity in a course listing.  See get_array_of_activities() in course/lib.php.
 *
 * @param stdClass $coursemodule The coursemodule object (record).
 * @return cached_cm_info An object on information that the courses
 *                        will know about (most noticeably, an icon).
 */
function jitsi_get_coursemodule_info($coursemodule) {
    global $DB;

    $dbparams = ['id' => $coursemodule->instance];
    $fields = 'id, name, intro, introformat, completionminutes, timeopen, timeclose';
    if (!$jitsi = $DB->get_record('jitsi', $dbparams, $fields)) {
        return false;
    }

    $result = new cached_cm_info();
    $result->name = $jitsi->name;

    if ($coursemodule->showdescription) {
        // Convert intro to html. Do not filter cached version, filters run at display time.
        $result->content = format_module_intro('jitsi', $jitsi, $coursemodule->id, false);
    }

    // Populate the custom completion rules as key => value pairs, but only if the completion mode is 'automatic'.
    if ($coursemodule->completion == COMPLETION_TRACKING_AUTOMATIC) {
        $result->customdata['customcompletionrules']['completionminutes'] = $jitsi->completionminutes;
    }

    if ($jitsi->timeopen) {
        $result->customdata['timeopen'] = $jitsi->timeopen;
    }
    if ($jitsi->timeclose) {
        $result->customdata['timeclose'] = $jitsi->timeclose;
    }

    return $result;
}

/**
 * Callback which returns human-readable strings describing the active completion custom rules for the module instance.
 *
 * @param cm_info|stdClass $cm object with fields ->completion and ->customdata['customcompletionrules']
 * @return array $descriptions the array of descriptions for the custom rules.
 */
function mod_jitsi_get_completion_active_rule_descriptions($cm) {
    // Values will be present in cm_info, and we assume these are up to date.
    if (
        empty($cm->customdata['customcompletionrules']) ||
        $cm->completion != COMPLETION_TRACKING_AUTOMATIC
    ) {
        return [];
    }

    $descriptions = [];
    foreach ($cm->customdata['customcompletionrules'] as $key => $val) {
        switch ($key) {
            case 'completionminutes':
                if (!empty($val)) {
                    $descriptions[] = get_string('completionminutes', 'jitsi', $val);
                }
                break;
            default:
                break;
        }
    }
    return $descriptions;
}

/**
 * Get the last time a user was connected to a jitsi activity
 * @param int $cmid - Course module id
 * @param int $user - User id
 * @return int - Time of last connection
 */
function getminutesfromlastconexion($cmid, $user) {
    global $DB;
    $contextmodule = context_module::instance($cmid);
    $sqllastparticipating = 'select timecreated from {logstore_standard_log} where contextid = '
        . $contextmodule->id . ' and (action = \'participating\' or action = \'enter\') and userid
         = ' . $user . ' order by timecreated DESC limit 1';
    $usersconnected = $DB->get_record_sql($sqllastparticipating);
    return $usersconnected->timecreated;
}

/**
 * Render an HTML progress bar showing watched segments of a GCS recording.
 *
 * @param array  $segments Array of [start, end] pairs in seconds
 * @param float  $duration Video duration in seconds
 * @param string $barid    Optional HTML id for the container div
 * @return string HTML
 */
function jitsi_render_segments_bar(array $segments, float $duration, string $barid = ''): string {
    $idattr = $barid !== '' ? ' id="' . s($barid) . '"' : '';
    $html = '<div' . $idattr . ' class="jitsi-segbar"'
        . ' style="position:relative;height:8px;background:#dee2e6;border-radius:4px;overflow:hidden">';
    if ($duration > 0) {
        foreach ($segments as $seg) {
            if (!is_array($seg) || count($seg) < 2) {
                continue;
            }
            $left  = max(0, min(100, ($seg[0] / $duration) * 100));
            $width = max(0, min(100 - $left, (($seg[1] - $seg[0]) / $duration) * 100));
            $html .= '<div style="position:absolute;left:' . number_format($left, 2, '.', '') . '%;'
                . 'width:' . number_format($width, 2, '.', '') . '%;height:100%;background:#0d6efd"></div>';
        }
    }
    $html .= '</div>';
    return $html;
}
