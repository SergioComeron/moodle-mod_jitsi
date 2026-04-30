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
 * Base 64 encode
 * @param string $inputstr - Input to encode
 */
function base64urlencode($inputstr) {
    return strtr(base64_encode($inputstr), '+/=', '-_,');
}

/**
 * Base 64 decode
 * @param string $inputstr - Input to decode
 */
function base64urldecode($inputstr) {
    return base64_decode(strtr($inputstr, '-_,', '+/='));
}

/**
 * Sanitize strings
 * @param string $string - The string to sanitize.
 * @param boolean $forcelowercase - Force the string to lowercase?
 * @param boolean $anal - If set to *true*, will remove all non-alphanumeric characters.
 */
function string_sanitize($string, $forcelowercase = true, $anal = false) {
    $strip = ['~', chr(96), '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
            '_', '=', '+', '[', '{', ']', '}', '\\', '|', ';', ':', '"',
            "'", '&#8216;', '&#8217;', '&#8220;', '&#8221;', '&#8211;', '&#8212;',
            'â€"', 'â€"', ',', '<', '.', '>', '/', '?',
        ];
    $clean = trim(str_replace($strip, "", strip_tags($string)));
    $clean = preg_replace('/\s+/', "-", $clean);
    $clean = ($anal) ? preg_replace("/[^a-zA-Z0-9]/", "", $clean) : $clean;
    return ($forcelowercase) ?
        (function_exists('mb_strtolower')) ?
            mb_strtolower($clean, 'UTF-8') :
            strtolower($clean) :
        $clean;
}

/**
 * Build the Jitsi room name for a given activity using the same algorithm as view.php.
 *
 * Extracted here so that servermanagement.php callbacks and view.php always use
 * identical logic and cannot diverge.
 *
 * @param string $shortname Course shortname
 * @param int $jitsiid Jitsi activity ID
 * @param string $jitsiname Jitsi activity name
 * @param string|false $sesionname Comma-separated field indices (0=shortname,1=id,2=name).
 *                                 Defaults to '0,1,2' when empty/false.
 * @param int|string|false $separator Index into ['.', '-', '_', '']. Defaults to 0 ('.').
 * @return string The room name
 */
function jitsi_build_room_name($shortname, $jitsiid, $jitsiname, $sesionname = false, $separator = false) {
    $separatormap = ['.', '-', '_', ''];
    if ($sesionname === false || $sesionname === '' || $sesionname === null) {
        $sesionname = '0,1,2';
    }
    $separatorindex = ($separator === false || $separator === '' || $separator === null) ? 0 : (int)$separator;
    $sep = $separatormap[$separatorindex] ?? '';
    $allowed = explode(',', $sesionname);
    $max = count($allowed);
    $sesparam = '';
    for ($i = 0; $i < $max; $i++) {
        $part = '';
        if ($allowed[$i] == 0) {
            $part = string_sanitize($shortname);
        } else if ($allowed[$i] == 1) {
            $part = (string)$jitsiid;
        } else if ($allowed[$i] == 2) {
            $part = string_sanitize($jitsiname);
        }
        $sesparam .= $part;
        if ($i < $max - 1) {
            $sesparam .= $sep;
        }
    }
    return $sesparam;
}

/**
 * Create session
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
function createsession(
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

    $sessionnorm = normalizesessionname($session);
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

    echo "<script src=\"//ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js\"></script>";
    echo "<script src=\"https://" . $domain . "/external_api.js\"></script>\n";

    $streamingoption = '';
    $jibrienabled = ($servertype == 3 && jitsi_is_jibri_ready($server));
    if (
        (get_config('mod_jitsi', 'livebutton') == 1) &&
        (has_capability('mod/jitsi:record', $PAGE->context)) &&
        (get_config('mod_jitsi', 'streamingoption') == 0) &&
        ($servertype != 3 || $jibrienabled)
    ) {
        $streamingoption = 'livestreaming';
    }

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
    $record = '';
    // Enable the Jitsi recording toolbar button when the record setting is on.
    // For GCP servers (type 3), only enable it when at least one Jibri is ready in the pool.
    $jibrienabled = ($servertype == 3 && jitsi_is_jibri_ready($server));
    if (
        get_config('mod_jitsi', 'record') == 1 && has_capability('mod/jitsi:record', $PAGE->context) &&
            ($servertype != 3 || $jibrienabled)
    ) {
        $record = 'recording';
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

    if ($user == null) {
        $showstreaming = (
            get_config('mod_jitsi', 'livebutton') == 1 &&
            has_capability('mod/jitsi:record', $PAGE->context) &&
            $account != null && $universal == false &&
            get_config('mod_jitsi', 'streamingoption') == 1 &&
            $jitsi->sessionwithtoken == 0 &&
            ($servertype != 3 || $jibrienabled)
        );
        $showrecording = (
            has_capability('mod/jitsi:record', $PAGE->context) &&
            $universal == false && $servertype == 3 &&
            $jibrienabled && $jitsi->sessionwithtoken == 0
        );
        if ($showstreaming || $showrecording) {
            echo "<div class=\"d-flex gap-2 justify-content-end flex-wrap\">";
            if ($showstreaming) {
                echo "<button id=\"streamBtn\" class=\"btn btn-sm btn-outline-warning\""
                    . " onclick=\"handleStreamBtn()\" disabled>"
                    . "📡 " . addslashes(get_string('streambtn', 'jitsi')) . "</button>";
            }
            if ($showrecording) {
                echo "<button id=\"recordBtn\" class=\"btn btn-sm btn-outline-danger\""
                    . " onclick=\"handleRecordBtn()\" disabled>"
                    . "🔴 " . addslashes(get_string('recordbtn', 'jitsi')) . "</button>";
            }
            echo "</div>";
        }
    }

    echo "</div>";
    echo "</div>";

    echo "</div></div>";
    echo "<hr>";

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
    if (get_config('mod_jitsi', 'record') == 1) {
        echo "fileRecordingsEnabled: true,\n";
    }
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

    // Disable live streaming if global setting is off, or if GCP (type 3) without Jibri ready.
    $jibrilivestream = ($servertype == 3 && jitsi_is_jibri_ready($server));
    if (get_config('mod_jitsi', 'livebutton') == 0 || ($servertype == 3 && !$jibrilivestream)) {
        echo "liveStreamingEnabled: false,\n";
        echo "liveStreaming: {enabled: false},\n";
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
                    'moderator' => has_capability('mod/jitsi:moderation', $PAGE->context),
                    'email' => $mail,
                    'name' => $nombre,
                    'avatar' => $avatar,
                    'id' => "",
                ],
                'features' => [
                    'recording' => $teacher,
                    'livestreaming' => $teacher,
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
        $ismoderator = has_capability('mod/jitsi:moderation', $PAGE->context);
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
    echo "width: '100%',";
    echo "height: '100%',";
    echo "}\n";
    echo "const api = new JitsiMeetExternalAPI(domain, options);\n";
    echo "api.addListener('videoConferenceJoined', () => {\n";
    echo "api.executeCommand('displayName', '" . $nombre . "');\n";
    echo "api.executeCommand('avatarUrl', '" . $avatar . "');\n";
    echo "});\n";
    $navigator = $_SERVER['HTTP_USER_AGENT'] ?? '';

    $cm = get_coursemodule_from_id('jitsi', $cmid, 0, false, MUST_EXIST);
    $event = \mod_jitsi\event\jitsi_session_enter::create([
        'objectid' => $PAGE->cm->instance,
        'context' => $PAGE->context,
        'other' => ['navigator' => $navigator],
    ]);
    $event->add_record_snapshot('course', $PAGE->course);
    $event->add_record_snapshot($PAGE->cm->modname, $jitsi);
    $event->trigger();

    $isguestjs = (!isloggedin() || isguestuser()) ? 'true' : 'false';
    echo "var jitsiPresenceHash = (Math.random().toString(36).substr(2,9) + Date.now().toString(36));\n";
    echo "var jitsiIsGuest = " . $isguestjs . ";\n";
    echo "var jitsiGuestName = '" . addslashes($nombre) . "';\n";

    echo "let intervalo = 60000;";
    echo "setInterval(function(){myTimer(api)}, intervalo);\n";
    echo "function myTimer(_api) {\n";
    echo "      require(['core/ajax'], function(ajax) {\n";
    echo "          ajax.call([{\n";
    echo "              methodname: 'mod_jitsi_participating_session',\n";
    echo "              args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cm->id . "'},\n";
    echo "          }]);\n";
    echo "      })\n";
    echo "}\n";
    echo "setInterval(function() {\n";
    echo "  require(['core/ajax'], function(ajax) {\n";
    echo "      ajax.call([{\n";
    echo "          methodname: 'mod_jitsi_presence_heartbeat',\n";
    echo "          args: {jitsiid:" . $jitsi->id . ", sessionhash: jitsiPresenceHash},\n";
    echo "      }]);\n";
    echo "  });\n";
    echo "}, 30000);\n";

    if (get_config('mod_jitsi', 'finishandreturn') == 1) {
        echo "api.on('readyToClose', () => {\n";
            echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
                echo "       var respuesta = ajax.call([{\n";
                echo "            methodname: 'mod_jitsi_press_button_end',\n";
                echo "            args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cmid . "'},\n";
                echo "            fail: notification.exception\n";
                echo "       }]);\n";
                echo "    ;});";
        echo "    api.dispose();\n";
        if ($universal == false && $user == null) {
            echo "    location.href=\"" . $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid . "\";";
        } else if ($universal == true && $user == null) {
            echo "    location.href=\"" . $CFG->wwwroot . "/mod/jitsi/formuniversal.php?t=" . $jitsi->token . "\";";
        } else if ($user != null) {
            echo "    location.href=\"" . $CFG->wwwroot . "/mod/jitsi/viewpriv.php?user=" . $user . "\";";
        }
        echo  "});\n";
    }
    echo "setTimeout(function() {\n";
    echo "  var sb = document.getElementById('streamBtn');\n";
    echo "  var rb = document.getElementById('recordBtn');\n";
    echo "  if (sb) { sb.disabled = false; }\n";
    echo "  if (rb) { rb.disabled = false; }\n";
    echo "}, 5000);\n";

    echo "function handleStreamBtn() {\n";
    echo "  var btn = document.getElementById('streamBtn');\n";
    echo "  var recBtn = document.getElementById('recordBtn');\n";
    echo "  if (!btn) { return; }\n";
    echo "  btn.disabled = true;\n";
    echo "  require(['jquery', 'core/ajax', 'core/notification'], function(\$, ajax, notification) {\n";
    echo "    ajax.call([{\n";
    echo "      methodname: 'mod_jitsi_press_record_button',\n";
    echo "      args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cmid . "'},\n";
    echo "      fail: notification.exception\n";
    echo "    }]);\n";
    echo "  });\n";
    echo "  if (btn.classList.contains('btn-warning')) {\n";
    echo "    stopStream();\n";
    echo "  } else {\n";
    echo "    document.getElementById('state').innerHTML ="
        . " '<div class=\"alert alert-light\" role=\"alert\">" . addslashes(get_string('preparing', 'jitsi')) . "</div>';\n";
    echo "    stream();\n";
    echo "  }\n";
    echo "}\n";

    echo "function handleRecordBtn() {\n";
    echo "  var btn = document.getElementById('recordBtn');\n";
    echo "  if (!btn) { return; }\n";
    echo "  btn.disabled = true;\n";
    echo "  if (btn.classList.contains('btn-danger')) {\n";
    echo "    api.stopRecording('file');\n";
    echo "  } else {\n";
    echo "    api.startRecording({mode: 'file'});\n";
    echo "  }\n";
    echo "}\n";

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

    if ($user == null) {
        echo "api.addEventListener('recordingStatusChanged', function(event) {\n";
        echo "  var sb = document.getElementById('streamBtn');\n";
        echo "  var rb = document.getElementById('recordBtn');\n";
        echo "  if (event['mode'] == 'file') {\n";
        echo "    if (event['on']) {\n";
        echo "      if (rb) { rb.classList.remove('btn-outline-danger'); rb.classList.add('btn-danger'); rb.disabled = false; }\n";
        echo "      if (sb) { sb.disabled = true; }\n";
        echo "    } else {\n";
        echo "      if (rb) { rb.classList.remove('btn-danger'); rb.classList.add('btn-outline-danger'); rb.disabled = false; }\n";
        echo "      if (sb) { sb.disabled = false; }\n";
        echo "    }\n";
        echo "    require(['core/ajax'], function(ajax) {\n";
        echo "      ajax.call([{\n";
        echo "        methodname: 'mod_jitsi_set_jibri_recording',\n";
        echo "        args: {jitsiid:" . $jitsi->id . ", recording: event['on'] ? 1 : 0},\n";
        echo "      }]);\n";
        echo "    });\n";
        echo "  }\n";
        echo "  if (event['on'] && event['mode'] == 'stream') {\n";
        echo "    if (sb) { sb.classList.remove('btn-outline-warning'); sb.classList.add('btn-warning'); sb.disabled = false; }\n";
        echo "    if (rb) { rb.disabled = true; }\n";
        echo "    document.getElementById('state').innerHTML = ";
        echo "      '<div class=\"alert alert-primary\" role=\"alert\">";
        echo "      <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" fill=\"currentColor\" ";
        echo "        class=\"bi bi-exclamation-triangle-fill flex-shrink-0 me-2\" viewBox=\"0 0 16 16\" ";
        echo "        role=\"img\" aria-label=\"Warning:\">";
        echo "        <path d=\"M0 5a2 2 0 0 1 2-2h7.5a2 2 0 0 1 1.983 1.738l3.11-1.382A1 1 0 0 1 ";
        echo "        16 4.269v7.462a1 1 0 0 1-1.406.913l-3.111-1.382A2 ";
        echo "        2 0 0 1 9.5 13H2a2 2 0 0 1-2-2V5zm11.5 5.175 3.5 1.556V4.269l-3.5 1.556v4.35zM2 4a1 1 0 0 ";
        echo "        0-1 1v6a1 1 0 0 0 1 1h7.5a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1H2z\"/>";
        echo "      </svg>";
        echo "      " . addslashes(get_string('sessionisbeingrecorded', 'jitsi'));
        echo "      </div>';";
        echo "  } else if (event['on'] == false && event['mode'] == 'stream') {\n";
        echo "    if (sb) { sb.classList.remove('btn-warning'); sb.classList.add('btn-outline-warning'); setTimeout(function(){ sb.disabled = false; }, 2000); }\n";
        echo "    if (rb) { setTimeout(function(){ rb.disabled = false; }, 2000); }\n";
        echo "    document.getElementById('state').innerHTML = '';\n";
        echo "  }\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function(\$, ajax, notification) {\n";
        echo "    ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_state_record',\n";
        echo "      args: {jitsi:" . $jitsi->id . ", state: event['on']},\n";
        echo "      fail: notification.exception\n";
        echo "    }]);\n";
        echo "  })\n";
        echo "});\n";

        echo "var idsource = null;\n";
        echo "var link = null;\n";
        echo "function stream(){\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "  var respuesta = ajax.call([{\n";
        echo "    methodname: 'mod_jitsi_create_stream',\n";
        echo "    args: {session:'" . $session . "', jitsi:'" . $jitsi->id . "', userid: '" . $USER->id . "'},\n";
        echo "  }]);\n";

        echo "  respuesta[0].done(function(response) {\n";
        echo "console.log(\"video creado\");";
        echo "        console.log(response['stream']);";
        echo "        link = response['link'];";
        echo "        idsource = response['idsource'];";
        echo "        console.log(idsource);";

        echo "    if (response['error'] == 'errorauthor'){\n";
        echo "      alert(\"" . addslashes(get_string('recordingbloquedby', 'jitsi')) . "\"+response['usercomplete']);\n";
        echo "      document.getElementById('state').innerHTML = ";
        echo "        '<div class=\"alert alert-light\" role=\"alert\"></div>';";
        echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
        echo "      document.getElementById(\"recordSwitch\").disabled = false;\n";
        echo "      document.getElementById(\"recordSwitch\").checked = false;\n";
        echo "}\n";
        echo "    } else if (response['error'] == 'erroryoutube'){\n";
        echo "      var infoerror = response['errorinfo'];\n";
        echo "      console.log(infoerror);\n";

        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "        ajax.call([{\n";
        echo "            methodname: 'mod_jitsi_delete_record_youtube',\n";
        echo "            args: {idsource: idsource},\n";
        echo "            done: console.log(\"BORRADO VIDEO POR ERROR EN JITSI!\"),\n";
        echo "            fail: notification.exception\n";
        echo "        }]);\n";
        echo "    })\n";

        echo "      document.getElementById('state').innerHTML = ";
        echo "        '<div class=\"alert alert-light\" role=\"alert\">ERROR RECORD ACCOUNT. TRY AGAIN IN A FEW SECONDS</div>';";
        echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
        echo "      document.getElementById(\"recordSwitch\").disabled = false;\n";
        echo "      document.getElementById(\"recordSwitch\").checked = false;\n";
        echo "}\n";
        echo "      require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "        ajax.call([{\n";
        echo "          methodname: 'mod_jitsi_stop_stream_byerror',\n";
        echo "          args: {jitsi: " . $jitsi->id . ", userid : " . $USER->id . "},\n";
        echo "          done: console.log(\"borrado author!\"),\n";
        echo "          fail: notification.exception\n";
        echo "        }]);\n";
        echo "      })\n";
        echo "    } else {\n";
        echo "      if (response['stream'] == 'streaming'){\n";
        echo "        alert(\"" . get_string('streamingisstarting', 'jitsi') . "\");";
        echo "        console.log(\"" . get_string('streamingisstarting', 'jitsi') . "\");  ";
        echo "      } else {\n";
        echo "        api.executeCommand('startRecording', {\n";
        echo "          mode: 'stream',\n";
        echo "          youtubeStreamKey: response['stream'] \n";
        echo "        });\n";

        echo "      }\n";
        echo "    }\n";
        echo "  ;})";
        echo "  .fail(function(ex) {";
        echo "    console.log(ex);";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "      ajax.call([{\n";
        echo "        methodname: 'mod_jitsi_stop_stream_byerror',\n";
        echo "        args: {jitsi: " . $jitsi->id . ", userid : " . $USER->id . "},\n";
        echo "        done: console.log(\"borrado author!\"),\n";
        echo "        fail: notification.exception\n";
        echo "      }]);\n";
        echo "    })\n";
        echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
        echo "    document.getElementById(\"recordSwitch\").checked = false;\n";
        echo "}\n";
        echo "    document.getElementById('state').innerHTML = '';";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "      ajax.call([{\n";
        echo "        methodname: 'mod_jitsi_send_error',\n";
        echo "        args: {jitsi:'" . $jitsi->id . "', user: '" . $USER->id . "',
                      error: ex['backtrace'], cmid:" . $cmid . "},\n";
        echo "        done: console.log(\"MAIL ENVIADO!\"),\n";
        echo "        fail: notification.exception\n";
        echo "      }]);\n";
        echo "    })\n";
        echo "    document.getElementById('state').innerHTML = ";
        echo "      '<div class=\"alert alert-light\" role=\"alert\">"
                    . get_string('internalerror', 'jitsi') . "</div>';";
        echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
        echo "    document.getElementById(\"recordSwitch\").checked = false;\n";
        echo "    document.getElementById(\"recordSwitch\").disabled = false;\n";
        echo "}\n";
        echo "  });";
        echo "})\n";
        echo "console.log('el link: '+link);\n";
        echo "}\n";
        echo "console.log('el link: '+link);\n";
        echo "api.on('participantLeft', function () {\n";
        echo "  console.log('Participant left');\n";
        echo "});\n";

        echo "api.on('participantJoined', function () {\n";
        echo "  console.log('Participant joined');\n";
        echo "});\n";

        echo "api.on('videoConferenceJoined', function () {\n";
        echo "  require(['core/ajax'], function(ajax) {\n";
        echo "      ajax.call([{\n";
        echo "          methodname: 'mod_jitsi_presence_join',\n";
        echo "          args: {jitsiid:" . $jitsi->id . ", sessionhash: jitsiPresenceHash,\n";
        echo "              guestname: jitsiIsGuest ? jitsiGuestName : ''},\n";
        echo "      }]);\n";
        echo "  });\n";
        echo "});\n";

        echo "api.on('videoConferenceLeft', function () {\n";
        echo "  require(['core/ajax'], function(ajax) {\n";
        echo "      ajax.call([{\n";
        echo "          methodname: 'mod_jitsi_presence_leave',\n";
        echo "          args: {jitsiid:" . $jitsi->id . ", sessionhash: jitsiPresenceHash},\n";
        echo "      }]);\n";
        echo "  });\n";
        if ($universal == false && $user == null) {
            $redirecturl = $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid;
            echo "  setTimeout(function() { location.href=\"" . $redirecturl . "\"; }, 2000);\n";
        } else if ($universal == true && $user == null) {
            $redirecturl = $CFG->wwwroot . "/mod/jitsi/formuniversal.php?t=" . $jitsi->token;
            echo "  setTimeout(function() { location.href=\"" . $redirecturl . "\"; }, 2000);\n";
        } else if ($user != null) {
            $redirecturl = $CFG->wwwroot . "/mod/jitsi/call.php";
            echo "  setTimeout(function() { location.href=\"" . $redirecturl . "\"; }, 2000);\n";
        }
        echo "});\n";

        // Registro de los diferentes botones.
        echo "api.addEventListener('toolbarButtonClicked', function(event) {\n";
        echo "if (event.key == 'camera'){\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "    var respuesta = ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_press_button_cam',\n";
        echo "      args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cmid . "'},\n";
        echo "      fail: notification.exception\n";
        echo "    }]);\n";
        echo "  ;});";
        echo "}\n";

        echo "if (event.key == 'desktop'){\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "    var respuesta = ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_press_button_desktop',\n";
        echo "      args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cmid . "'},\n";
        echo "      fail: notification.exception\n";
        echo "    }]);\n";
        echo "  ;});";
        echo "}\n";

        echo "if (event.key == '__end'){\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "    var respuesta = ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_press_button_end',\n";
        echo "      args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cmid . "'},\n";
        echo "      fail: notification.exception\n";
        echo "    }]);\n";
        echo "  ;});";
        echo "}\n";

        echo "if (event.key == 'microphone'){\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "    var respuesta = ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_press_button_microphone',\n";
        echo "      args: {jitsi:'" . $jitsi->id . "', user:'" . $USER->id . "', cmid:'" . $cmid . "'},\n";
        echo "      fail: notification.exception\n";
        echo "    }]);\n";
        echo "  ;});";
        echo "}\n";
        // Fin registro de los diferentes botones.

        echo "    console.log(event['key']);\n";
        echo "});\n";

        echo "api.addEventListener('recordingStatusChanged', function(event) {\n";
        echo "  if (event['error']){\n";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "      ajax.call([{\n";
        echo "        methodname: 'mod_jitsi_delete_record_youtube',\n";
        echo "        args: {idsource: idsource},\n";
        echo "        done: console.log(\"BORRADO VIDEO POR ERROR EN JITSI!\"),\n";
        echo "        fail: notification.exception\n";
        echo "      }]);\n";
        echo "    })\n";
        echo "    console.log('ERROR DE JITSI');\n";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "      ajax.call([{\n";
        echo "        methodname: 'mod_jitsi_send_error',\n";
        echo "        args: {jitsi:'" . $jitsi->id . "', user: '" . $USER->id .
                    "', error: 'Error de servidor jitsi: ' + event['error'], cmid:" . $cmid . "},\n";
        echo "        done: console.log(\"MAIL ENVIADO!\"),\n";
        echo "        fail: notification.exception\n";
        echo "      }]);\n";
        echo "    })\n";
        echo "  }";
        echo "});\n";

        echo "api.addEventListener('recordingLinkAvailable', function(event) {\n";
        echo "  console.log('recordingLinkAvailable: ' + event.link);\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "    ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_save_recording_link',\n";
        echo "      args: {jitsi: " . $jitsi->id . ", link: event.link, ttl: event.ttl || 0},\n";
        echo "      done: function(response) { console.log('Recording link saved, idsource: ' + response.idsource); },\n";
        echo "      fail: notification.exception\n";
        echo "    }]);\n";
        echo "  });\n";
        echo "});\n";
        echo "api.addEventListener('recordingStatusChanged', function(event) {\n";
        echo "  if (!event.on && event.url) {\n";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "      ajax.call([{\n";
        echo "        methodname: 'mod_jitsi_save_recording_link',\n";
        echo "        args: {jitsi: " . $jitsi->id . ", link: event.url, ttl: 0},\n";
        echo "        done: function(response) {\n";
        echo "          console.log('Recording link saved via recordingStatusChanged, idsource: ' + response.idsource);\n";
        echo "        },\n";
        echo "        fail: notification.exception\n";
        echo "      }]);\n";
        echo "    });\n";
        echo "  }\n";
        echo "});\n";

        echo "function stopStream(){\n";
        echo "  var parar = true;\n";
        echo "                console.log(\"parar?: \"+parar);\n";
        echo "  require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "    var respuesta = ajax.call([{\n";
        echo "      methodname: 'mod_jitsi_stop_stream',\n";
        echo "      args: {jitsi:'" . $jitsi->id . "', userid: '" . $USER->id . "'},\n";
        echo "    }]);\n";
        echo "    respuesta[0].done(function(response) {\n";
        echo "      if (response['error'] == 'errorauthor'){\n";
        echo "        require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "          var respuestaminutos = ajax.call([{\n";
        echo "            methodname: 'mod_jitsi_getminutesfromlastconexion',\n";
        echo "            args: {cmid: " . $cmid . ", user: response['user']},\n";
        echo "            fail: notification.exception\n";
        echo "          }]);\n";
        echo "          respuestaminutos[0].done(function(respuestaminutos) {\n";
        echo "            console.log('Los minutos: '+JSON.stringify(respuestaminutos));\n";
        echo "            if ((Date.now() / 1000) - respuestaminutos > 60){\n";
        echo "              console.log(\"Ha pasado 1 minuto\");\n";
        echo "              if (confirm(\"" . addslashes(get_string('recordingwasbloquedby', 'jitsi')) .
                            "\"+response['usercomplete'])) {";
        echo "                console.log(\"Switch cambiado a desactivado\");";
        echo "                document.getElementById('state').innerHTML = '';";
        echo "                require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "                  ajax.call([{\n";
        echo "                    methodname: 'mod_jitsi_stop_stream_noauthor',\n";
        echo "                    args: {jitsi: " . $jitsi->id . ", userid: " . $USER->id . "},\n";
        echo "                    done: console.log(\"borrado author!\"),\n";
        echo "                    fail: notification.exception\n";
        echo "                  }]);\n";
        echo "                })\n";
        echo "                api.executeCommand('stopRecording', 'stream');\n";
        echo "              } else {\n";
        echo "                parar = false;\n";
        echo "                console.log(\"parar?: \"+parar);\n";
        echo "              }";
        echo "            } else {\n";
        echo "              console.log(\" no ha pasado 1 minuto\");\n";
        echo "              alert(\"" . addslashes(get_string('recordingbloquedby', 'jitsi')) . "\"+response['usercomplete']);\n";
        echo "            }\n";
        echo "          });\n";
        echo "        })\n";
        echo "        document.getElementById('state').innerHTML = ";
        echo "          '<div class=\"alert alert-light\" role=\"alert\"></div>';";
        echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
        echo "        document.getElementById(\"recordSwitch\").disabled = false;\n";
        echo "        document.getElementById(\"recordSwitch\").checked = true;\n";
        echo " }\n";
        echo "        document.getElementById('state').innerHTML = ";
        echo "          '<div class=\"alert alert-primary\" role=\"alert\">";
        echo "          <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"24\" height=\"24\" fill=\"currentColor\" ";
        echo "          class=\"bi bi-exclamation-triangle-fill flex-shrink-0 me-2\" viewBox=\"0 0 16 16\" ";
        echo "          role=\"img\" aria-label=\"Warning:\">";
        echo "          <path d=\"M0 5a2 2 0 0 1 2-2h7.5a2 2 0 0 1 1.983 1.738l3.11-1.382A1 1 0 0 1 ";
        echo "          16 4.269v7.462a1 1 0 0 1-1.406.913l-3.111-1.382A2 ";
        echo "          2 0 0 1 9.5 13H2a2 2 0 0 1-2-2V5zm11.5 5.175 3.5 1.556V4.269l-3.5 1.556v4.35zM2 4a1 1 0 0 ";
        echo "          0-1 1v6a1 1 0 0 0 1 1h7.5a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1H2z\"/>";
        echo "          </svg>";
        echo " " . addslashes(get_string('sessionisbeingrecorded', 'jitsi'));
        echo "</div>';";
        echo "      } else if (parar = true) {\n";
        echo "        api.executeCommand('stopRecording', 'stream');\n";
        echo "      }\n";
        echo "    })\n";
        echo "  })\n";
        echo "}\n";

        echo "console.log('el navegador: '+navigator.userAgent);";
        echo "function sendlink(){\n";
        echo "        var nombreform = document.getElementById(\"nombrelink\").value;";
        echo "        var mailform = document.getElementById(\"maillink\").value;";
        echo "    require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
        echo "       var respuesta = ajax.call([{\n";
        echo "            methodname: 'mod_jitsi_create_link',\n";
        echo "            args: {jitsi: " . $jitsi->id . "},\n";
        echo "       }]);\n";
        echo "       respuesta[0].done(function(response) {\n";
        echo "            alert(\"Enviado\");";
        echo ";})";
        echo  ".fail(function(ex) {console.log(ex);});";
        echo "    })\n";
        echo "}\n";
    }
    echo "</script>\n";
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

    $sessionnorm = normalizesessionname($session);
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
 * Check if a date is out of time
 * @param stdClass $jitsi jitsi instance
 */
function istimedout($jitsi) {
    if (time() > $jitsi->validitytime) {
        return true;
    } else {
        return false;
    }
}

/**
 * Generate the time error
 * @param stdClass $jitsi jitsi instance
 */
function generateerrortime($jitsi) {
    global $CFG;
    if ($jitsi->validitytime == 0 || get_config('mod_jitsi', 'invitebuttons') == 0) {
        return get_string('invitationsnotactivated', 'jitsi');
    } else {
        return get_string('linkexpiredon', 'jitsi', userdate($jitsi->validitytime));
    }
}

/**
 * Check if a code is original
 * @param int $code code to check
 * @param stdClass $jitsi jitsi instance
 */
function isoriginal($code, $jitsi) {
    if ($code == ($jitsi->timecreated + $jitsi->id)) {
        $original = true;
    } else {
        $original = false;
    }
    return $original;
}

/**
 * Generate code from a jitsi
 * @param stdClass $jitsi jitsi instance
 */
function generatecode($jitsi) {
    return $jitsi->timecreated + $jitsi->id;
}

/**
 * Send notification when user enter on private session
 * @param stdClass $fromuser - User entering the private session
 * @param stdClass $touser - User session owner
 */
function sendnotificationprivatesession($fromuser, $touser) {
    global $CFG;
    $message = new \core\message\message();
    $message->component = 'mod_jitsi';
    $message->name = 'onprivatesession';
    $message->userfrom = core_user::get_noreply_user();
    $message->userto = $touser;
    $message->subject = get_string('userenter', 'jitsi', $fromuser->firstname);
    $message->fullmessage = get_string('userenter', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
    $message->fullmessageformat = FORMAT_MARKDOWN;
    $message->fullmessagehtml = get_string('user') . ' <a href="' . $CFG->wwwroot . '/user/profile.php?id=' . $fromuser->id . '"> '
    . $fromuser->firstname . ' ' . $fromuser->lastname
    . '</a> ' . get_string('hasentered', 'jitsi') . '. ' . get_string('click', 'jitsi') . '<a href="'
    . new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id])
    . '"> ' . get_string('here', 'jitsi') . '</a> ' . get_string('toenter', 'jitsi');
    $message->smallmessage = get_string('userenter', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
    $message->notification = 1;
    $message->contexturl = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id]);
    $message->contexturlname = 'Private session';
    $content = ['*' => ['header' => '', 'footer' => '']];
    $message->set_additional_content('email', $content);
    $messageid = message_send($message);
}

/**
 * Send notification when user enter on private session
 * @param stdClass $fromuser - User entering the private session
 * @param stdClass $touser - User session owner
 */
function sendcallprivatesession($fromuser, $touser) {
    global $CFG;
    $message = new \core\message\message();
    $message->component = 'mod_jitsi';
    $message->name = 'callprivatesession';
    $message->userfrom = core_user::get_noreply_user();
    $message->userto = $touser;
    $message->subject = get_string('usercall', 'jitsi', $fromuser->firstname);
    $message->fullmessage = get_string('usercall', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
    $message->fullmessageformat = FORMAT_MARKDOWN;
    $message->fullmessagehtml = get_string('user') . ' <a href="' . $CFG->wwwroot . '/user/profile.php?id=' . $fromuser->id . '"> '
    . $fromuser->firstname . ' ' . $fromuser->lastname
    . '</a> ' . get_string('iscalling', 'jitsi') . '. ' . get_string('click', 'jitsi') . '<a href="'
    . new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id])
    . '"> ' . get_string('here', 'jitsi') . '</a> ' . get_string('toenter', 'jitsi');
    $message->smallmessage = get_string('usercall', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
    $message->notification = 1;
    $message->contexturl = new moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id]);
    $message->contexturlname = 'Private session';
    $content = ['*' => ['header' => '', 'footer' => '']];
    $message->set_additional_content('email', $content);
    $messageid = message_send($message);
}

/**
 * Mark Jitsi record to delete
 * @param int $idrecord - Jitsi record to delete
 * @param int $option - Delete option
 */
function marktodelete($idrecord, $option) {
    global $DB;
    $record = $DB->get_record('jitsi_record', ['id' => $idrecord]);
    $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
    if ($option == 1) {
        $record->deleted = 1;
    } else if ($option == 2) {
        $record->deleted = 2;
    }
    $records = $DB->get_records('jitsi_record', ['source' => $record->source]);
    if (count($records) == 1 && $source->type == 0) {
        togglestate($source->link);
    }
    $DB->update_record('jitsi_record', $record);
}

/**
 * Delete physical recording file from Jibri VM or GCS bucket.
 * Best-effort: returns false if URL is not recognised or VM/GCS is unreachable.
 * @param string $link Recording URL (http://<ip>/recordings/<file> or https://storage.googleapis.com/<bucket>/<file>)
 * @return bool True if deletion was accepted, false otherwise.
 */
function delete_jibri_file($link) {
    global $DB;

    // GCS URL format: https://storage.googleapis.com/<bucket>/<filename>.
    if (preg_match('/^https:\/\/storage\.googleapis\.com\/([^\/]+)\/(.+)$/', $link, $m)) {
        $bucketname = $m[1];
        $objectname = $m[2];
        $server = $DB->get_record('jitsi_servers', ['gcs_bucket' => $bucketname, 'gcs_enabled' => 1]);
        if (!$server) {
            return false;
        }
        try {
            require_once(__DIR__ . '/api/vendor/autoload.php');
            $client = new Google\Client();
            $client->addScope(Google\Service\Storage::DEVSTORAGE_FULL_CONTROL);
            // GCP servers store credentials in Moodle file storage, not in privatekey field.
            $fs = get_file_storage();
            $ctx = context_system::instance();
            $files = $fs->get_area_files(
                $ctx->id,
                'mod_jitsi',
                'gcpserviceaccountjson',
                0,
                'itemid, filepath, filename',
                false
            );
            if (!empty($files)) {
                $file = reset($files);
                $key = json_decode($file->get_content(), true);
                if (is_array($key)) {
                    $client->setAuthConfig($key);
                } else {
                    $client->useApplicationDefaultCredentials();
                }
            } else {
                $client->useApplicationDefaultCredentials();
            }
            $storage = new Google\Service\Storage($client);
            $storage->objects->delete($bucketname, $objectname);
            return true;
        } catch (\Exception $e) {
            return false;
        }
    }

    // Jibri VM URL format: http://<ip>/recordings/<filename>.
    if (!preg_match('/^http:\/\/(\d+\.\d+\.\d+\.\d+)\/recordings\/(.+)$/', $link, $m)) {
        return false;
    }
    $ip = $m[1];
    $filename = basename($m[2]);
    $servers = $DB->get_records('jitsi_servers', ['jibri_enabled' => 1]);
    foreach ($servers as $server) {
        if (empty($server->provisioningtoken)) {
            continue;
        }
        $url = 'http://' . $ip . '/delete-recording'
            . '?file=' . rawurlencode($filename)
            . '&token=' . rawurlencode($server->provisioningtoken);
        $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
        $response = @file_get_contents($url, false, $ctx);
        if ($response !== false) {
            return true;
        }
    }
    return false;
}

/**
 * Delete Jitsi record
 * @param int $source - Jitsi source record to delete
 */
function delete_jitsi_record($source) {
    global $DB;
    // Delete the AI-generated quiz course module if one was created.
    $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $source]);
    if ($sourcerecord && !empty($sourcerecord->ai_quiz_id) && (int)$sourcerecord->ai_quiz_id > 0) {
        $cmid = (int)$sourcerecord->ai_quiz_id;
        if ($DB->record_exists('course_modules', ['id' => $cmid])) {
            course_delete_module($cmid);
        }
    }
    $DB->delete_records('jitsi_record', ['source' => $source]);
    $DB->delete_records('jitsi_source_record', ['id' => $source]);
}

/**
 * Return if Jitsi record source is deletable
 * @param int $sourcerecord - Jitsi source record id
 */
function isdeletable($sourcerecord) {
    $res = true;
    global $DB;
    $records = $DB->get_records('jitsi_record', ['source' => $sourcerecord, 'deleted' => 0]);
    if (!$records == null) {
        $res = false;
    }
    return $res;
}

/**
 * Delete Record from youtube
 * @param int $idsource - Jitsi source record to delete
 */
function deleterecordyoutube($idsource) {
    global $CFG, $DB, $PAGE;
    $res = false;
    $source = $DB->get_record('jitsi_source_record', ['id' => $idsource]);
    $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);
    if (isdeletable($idsource)) {
        if ($source->link != null) {
            if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
                throw new \Exception('please run "composer require google/apiclient:~2.0" in "' . __DIR__ . '"');
            }
            require_once(__DIR__ . '/api/vendor/autoload.php');

            $client = new Google_Client();

            $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
            $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

            $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";

            $_SESSION[$tokensessionkey] = $account->clientaccesstoken;
            try {
                $client->setAccessToken($_SESSION[$tokensessionkey]);
            } catch (\Exception $e) {
                $account->clientaccesstoken = null;
                $account->clientrefreshtoken = null;
                $account->tokencreated = 0;
                $DB->update_record('jitsi_record_account', $account);
                return false;
            }
            if ($client->isAccessTokenExpired()) {
                // Validate refresh token exists before attempting to use it.
                if (empty($account->clientrefreshtoken)) {
                    if ($account->inuse == 1) {
                        $account->inuse = 0;
                    }
                    $account->clientaccesstoken = null;
                    $account->tokencreated = 0;
                    $DB->update_record('jitsi_record_account', $account);
                    return false;
                }

                try {
                    $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($account->clientrefreshtoken);
                    $account->clientaccesstoken = $newaccesstoken["access_token"];
                    $newrefreshaccesstoken = $client->getRefreshToken();
                    $newrefreshaccesstoken = $client->getRefreshToken();
                    $account->clientrefreshtoken = $newrefreshaccesstoken;
                    $account->tokencreated = time();
                } catch (Google_Service_Exception $e) {
                    if ($account->inuse == 1) {
                        $account->inuse = 0;
                    }
                    $account->clientaccesstoken = null;
                    $account->clientrefreshtoken = null;
                    $account->tokencreated = 0;
                    $DB->update_record('jitsi_record_account', $account);
                    $client->revokeToken();
                    return false;
                } catch (Google_Exception $e) {
                    if ($account->inuse == 1) {
                        $account->inuse = 0;
                    }
                    $account->clientaccesstoken = null;
                    $account->clientrefreshtoken = null;
                    $account->tokencreated = 0;
                    $DB->update_record('jitsi_record_account', $account);
                    $client->revokeToken();
                    return false;
                }
            }
            $youtube = new Google_Service_YouTube($client);
            try {
                $listresponse = $youtube->videos->listVideos("snippet", ['id' => $source->link]);
            } catch (Google_Service_Exception $e) {
                if ($account->inuse == 1) {
                    $account->inuse = 0;
                }
                $account->clientaccesstoken = null;
                $account->clientrefreshtoken = null;
                $account->tokencreated = 0;
                $DB->update_record('jitsi_record_account', $account);
                $client->revokeToken();
                return false;
                throw new \Exception("exception" . $e->getMessage());
            } catch (Google_Exception $e) {
                if ($account->inuse == 1) {
                    $account->inuse = 0;
                }
                $account->clientaccesstoken = null;
                $account->clientrefreshtoken = null;
                $account->tokencreated = 0;
                $DB->update_record('jitsi_record_account', $account);
                $client->revokeToken();
                return false;
                throw new \Exception("exception" . $e->getMessage());
            }
            if ($listresponse['items'] != []) {
                if ($client->getAccessToken($idsource)) {
                    try {
                        $youtube->videos->delete($source->link);
                        delete_jitsi_record($idsource);
                        return true;
                    } catch (Google_Service_Exception $e) {
                        throw new \Exception("exception" . $e->getMessage());
                    } catch (Google_Exception $e) {
                        throw new \Exception("exception" . $e->getMessage());
                    }
                }
            } else {
                delete_jitsi_record($idsource);
            }
        } else {
            delete_jitsi_record($idsource);
        }
    }
    return $res;
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
 * Counts the minutes of a user in the current session
 * @param id $contextinstanceid - context instance
 * @param id $userid - user id
 */
function getminutes($contextinstanceid, $userid) {
    global $DB, $USER;

    $cache = cache::make('mod_jitsi', 'getminutes');
    $cachekey = "getminutes_{$contextinstanceid}_{$userid}";
    $cachedresult = $cache->get($cachekey);

    if ($cachedresult !== false) {
        return $cachedresult;
    }

    $sqlminutos = 'SELECT * FROM {logstore_standard_log} WHERE userid = :userid
                   AND contextinstanceid = :contextinstanceid AND action = \'participating\'';
    $params = ['userid' => $userid, 'contextinstanceid' => $contextinstanceid];
    $minutos = $DB->get_records_sql($sqlminutos, $params);

    $result = count($minutos);
    $cache->set($cachekey, $result, 120); // Cache for 2 minutes.

    return $result;
}

/**
 * Counts the minutes of a user in the current session
 * @param id $contextinstanceid - context instance
 * @param id $userid - user id
 * @param int $init - initial time
 * @param int $end - end time
 */
function getminutesdates($contextinstanceid, $userid, $init, $end) {
    global $DB, $USER;

    $cache = cache::make('mod_jitsi', 'getminutesdates');
    $cachekey = "getminutesdates_{$contextinstanceid}_{$userid}_{$init}_{$end}";
    $cachedresult = $cache->get($cachekey);

    if ($cachedresult !== false) {
        return $cachedresult;
    }

    $sqlminutos = 'SELECT COUNT(*) AS minutes FROM {logstore_standard_log}
                   WHERE userid = :userid AND contextinstanceid = :contextinstanceid
                   AND action = \'participating\' AND timecreated BETWEEN :init AND :end';
    $params = ['userid' => $userid,
        'contextinstanceid' => $contextinstanceid,
        'init' => $init,
        'end' => $end,
    ];
    $minutos = $DB->get_record_sql($sqlminutos, $params);

    $cache->set($cachekey, $minutos->minutes, 120); // Cache for 2 minutes.
    return $minutos->minutes;
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
 * Update completion.
 * @param stdClass $cm - course module object
 */
function update_completition($cm) {
    global $DB;
    $jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);
    if (! $course = $DB->get_record("course", ["id" => $cm->course])) {
        throw new \Exception("Course is misconfigured");
    }
    $completion = new completion_info($course);

    if ($completion->is_enabled($cm) == COMPLETION_TRACKING_AUTOMATIC && $jitsi->completionminutes) {
        $completion->update_state($cm, COMPLETION_COMPLETE);
    }
}

/**
 * Set embedable a video
 * @param int $idvideo - id of the video
 */
function doembedable($idvideo) {
    global $DB;

    $source = $DB->get_record('jitsi_source_record', ['link' => $idvideo]);
    $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);
    $client = getclientgoogleapibyaccount($account);
    $youtube = new Google_Service_YouTube($client);

    try {
        $listresponse = $youtube->videos->listVideos("status", ['id' => $idvideo]);
        $video = $listresponse[0];

        $videostatus = $video['status'];
        if ($videostatus != null) {
            if ($videostatus['embeddable'] == 0) {
                $videostatus['embeddable'] = 1;
                $updateresponse = $youtube->videos->update("status", $video);
                $source->embed = 1;
                $DB->update_record('jitsi_source_record', $source);
            } else if ($videostatus['embeddable'] == 1) {
                $source->embed = 1;
                $DB->update_record('jitsi_source_record', $source);
                $updateresponse = 'Video already embedable';
            }
        }
    } catch (Google_Service_Exception $e) {
        $record = $DB->get_record('jitsi_record', ['source' => $source->id]);
        $jitsi = $DB->get_record('jitsi', ['id' => $record->jitsi]);
        $source->embed = -1;
        $DB->update_record('jitsi_source_record', $source);
        senderror($jitsi->id, $source->userid, 'ERROR doembedable: ' . $e->getMessage(), $source);
        return false;
    } catch (Google_Exception $e) {
        $record = $DB->get_record('jitsi_record', ['source' => $source->id]);
        $jitsi = $DB->get_record('jitsi', ['id' => $record->jitsi]);
        $source->embed = -1;
        $DB->update_record('jitsi_source_record', $source);
        senderror($jitsi->id, $source->userid, 'ERROR doembedable: ' . $e->getMessage(), $source);
        return false;
    }

    return $updateresponse;
}

/**
 * Set private a video
 * @param int $idvideo - id of the video
 */
function togglestate($idvideo) {
    global $CFG, $DB;
    if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
        throw new \Exception('please run "composer require google/apiclient:~2.0" in "' . __DIR__ . '"');
    }
    require_once(__DIR__ . '/api/vendor/autoload.php');

    $client = new Google_Client();

    $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
    $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

    $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";

    $source = $DB->get_record('jitsi_source_record', ['link' => $idvideo]);
    $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);

    $_SESSION[$tokensessionkey] = $account->clientaccesstoken;
    $client->setAccessToken($_SESSION[$tokensessionkey]);

    if ($client->isAccessTokenExpired()) {
        // Validate refresh token exists before attempting to use it.
        if (empty($account->clientrefreshtoken)) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            return false;
        }

        try {
            $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($account->clientrefreshtoken);
            $account->clientaccesstoken = $newaccesstoken["access_token"];
            $newraccesstfreshaccesstoken = $client->getRefreshToken();
            $newrefreshaccesstoken = $client->getRefreshToken();
            $account->clientrefreshtoken = $newrefreshaccesstoken;
            $account->tokencreated = time();
        } catch (Google_Service_Exception $e) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->clientrefreshtoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            $client->revokeToken();
            return false;
        } catch (Google_Exception $e) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->clientrefreshtoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            $client->revokeToken();
            return false;
        }
    }

    $youtube = new Google_Service_YouTube($client);

    try {
        $listresponse = $youtube->videos->listVideos("status", ['id' => $idvideo]);
        $video = $listresponse[0];

        $videostatus = $video['status'];
        if ($videostatus != null) {
            if ($videostatus['privacyStatus'] == 'unlisted') {
                $videostatus['privacyStatus'] = 'private';
                $updateresponse = $youtube->videos->update("status", $video);
            } else {
                $videostatus['privacyStatus'] = 'unlisted';
                $updateresponse = $youtube->videos->update("status", $video);
            }
        }
    } catch (Google_Service_Exception $e) {
        if ($account->inuse == 1) {
            $account->inuse = 0;
        }
        $account->clientaccesstoken = null;
        $account->clientrefreshtoken = null;
        $account->tokencreated = 0;
        $DB->update_record('jitsi_record_account', $account);
        $client->revokeToken();
        return false;
    } catch (Google_Exception $e) {
        if ($account->inuse == 1) {
            $account->inuse = 0;
        }
        $account->clientaccesstoken = null;
        $account->clientrefreshtoken = null;
        $account->tokencreated = 0;
        $DB->update_record('jitsi_record_account', $account);
        $client->revokeToken();
        return false;
    }
    return $updateresponse;
}

/**
 * Get state of visibility of a video
 * @param array $records - Array of records
 */
function isallvisible($records) {
    $res = false;
    foreach ($records as $record) {
        if ($record->visible == 1) {
            $res = true;
        }
    }
    return $res;
}

/**
 * Get client google api
 * @return Google_Client - Client google api
 */
function getclientgoogleapi() {
    global $CFG, $DB;
    if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
        throw new \Exception('please run "composer require google/apiclient:~2.0" in "' . __DIR__ . '"');
    }
    require_once(__DIR__ . '/api/vendor/autoload.php');

    $client = new Google_Client();

    $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
    $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

    $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";

    $account = $DB->get_record('jitsi_record_account', ['inuse' => 1]);
    $_SESSION[$tokensessionkey] = $account->clientaccesstoken;
    $client->setAccessToken($_SESSION[$tokensessionkey]);

    if ($client->isAccessTokenExpired()) {
        // Validate refresh token exists before attempting to use it.
        if (empty($account->clientrefreshtoken)) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            throw new moodle_exception(
                'error',
                'mod_jitsi',
                '',
                'The YouTube account "' . $account->name . '" is missing a refresh token. ' .
                'Please delete and re-add this account in Site administration > Plugins > Activity modules > ' .
                'Jitsi > Streaming/Recording accounts.'
            );
        }

        try {
            $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($account->clientrefreshtoken);
            $account->clientaccesstoken = $newaccesstoken["access_token"];
            $newrefreshaccesstoken = $client->getRefreshToken();
            $newrefreshaccesstoken = $client->getRefreshToken();
            $account->clientrefreshtoken = $newrefreshaccesstoken;
            $account->tokencreated = time();
        } catch (Google_Service_Exception $e) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->clientrefreshtoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            $client->revokeToken();
            return false;
        } catch (Google_Exception $e) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->clientrefreshtoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            $client->revokeToken();
            return false;
        }
    }
    return $client;
}

/**
 * Get client google api
 * @param stdClass $account - Account to get client
 * @return Google_Client - Client google api
 */
function getclientgoogleapibyaccount($account) {
    global $CFG, $DB;
    if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
        throw new \Exception('please run "composer require google/apiclient:~2.0" in "' . __DIR__ . '"');
    }
    require_once(__DIR__ . '/api/vendor/autoload.php');

    $client = new Google_Client();

    $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
    $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

    $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";

    $_SESSION[$tokensessionkey] = $account->clientaccesstoken;
    $client->setAccessToken($_SESSION[$tokensessionkey]);

    if ($client->isAccessTokenExpired()) {
        // Validate refresh token exists before attempting to use it.
        if (empty($account->clientrefreshtoken)) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            throw new moodle_exception(
                'error',
                'mod_jitsi',
                '',
                'The YouTube account "' . $account->name . '" is missing a refresh token. ' .
                'Please delete and re-add this account in Site administration > Plugins > Activity modules > ' .
                'Jitsi > Streaming/Recording accounts.'
            );
        }

        try {
            $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($account->clientrefreshtoken);
            $account->clientaccesstoken = $newaccesstoken["access_token"];
            $newrefreshaccesstoken = $client->getRefreshToken();
            $newrefreshaccesstoken = $client->getRefreshToken();
            $account->clientrefreshtoken = $newrefreshaccesstoken;
            $account->tokencreated = time();
        } catch (Google_Service_Exception $e) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->clientrefreshtoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            $client->revokeToken();
            return false;
        } catch (Google_Exception $e) {
            if ($account->inuse == 1) {
                $account->inuse = 0;
            }
            $account->clientaccesstoken = null;
            $account->clientrefreshtoken = null;
            $account->tokencreated = 0;
            $DB->update_record('jitsi_record_account', $account);
            $client->revokeToken();
            return false;
        }
    }
    return $client;
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
 * Change account.
 */
function changeaccount() {
    global $DB;

    $sql = 'select * from {jitsi_record_account} where {jitsi_record_account}.inqueue = 1 and
     {jitsi_record_account}.clientaccesstoken != \'\' and {jitsi_record_account}.clientrefreshtoken != \'\' order by id asc';
    $accounts = $DB->get_records_sql($sql);
    $accountinuse = $DB->get_record('jitsi_record_account', ['inuse' => 1]);
    if ($accounts == null) {
        return $accountinuse->id;
    }
    $arrayparaiterar = array_slice($accounts, array_search($accountinuse->id, array_keys($accounts)) + 1);

    if (count($arrayparaiterar) == 0) {
        $arrayparaiterar = array_slice($accounts, 0);
    }
    $newaccountinuse = current($arrayparaiterar);
    $accountinuse->inuse = 0;
    $newaccountinuse->inuse = 1;
    $DB->update_record('jitsi_record_account', $accountinuse);
    $DB->update_record('jitsi_record_account', $newaccountinuse);

    return $newaccountinuse->id;
}

/**
 * Send an error message to a user in a Jitsi session.
 *
 * @param object $jitsi Object representing the Jitsi session.
 * @param object $user Object representing the user to whom the error message will be sent.
 * @param string $error Error message to be sent to the user.
 * @param string $source Source of the error.
 */
function senderror($jitsi, $user, $error, $source) {
    global $PAGE, $DB, $CFG;
    $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
    $cm = get_coursemodule_from_instance('jitsi', $jitsi);
    $cmid = $cm->id;
    $PAGE->set_context(context_module::instance($cmid));

    $admins = get_admins();
    $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);
    $DB->update_record('jitsi', $jitsiob);

    $user = $DB->get_record('user', ['id' => $user]);
    $mensaje = "El usuario " . $user->firstname . " " . $user->lastname .
        " ha tenido un error al intentar grabar la sesión de jitsi con id " . $jitsi . "\nInfo:\n" . $error . " en la cuenta: " .
        $account->name . " (id: " . $account->id . ")\n
    Para más información, mira el log:\n
    LOG: " . $CFG->wwwroot . "/report/log/index.php?chooselog=1&id=" . $jitsiob->course . "&modid=" . $cmid . "\n
    URL: " . $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid . "\n
    Nombre de la sesión: " . $DB->get_record('jitsi', ['id' => $jitsi])->name . "\n
    Curso: " . $DB->get_record('course', ['id' => $DB->get_record('jitsi', ['id' => $jitsi])->course])->fullname . "\n
    Usuario: " . $user->username . "\n";
    foreach ($admins as $admin) {
        email_to_user($admin, $admin, "ERROR JITSI! el usuario: "
            . $user->username . " ha tenido un error en el jitsi: " . $jitsi, $mensaje);
    }

    $event = \mod_jitsi\event\jitsi_error::create([
        'objectid' => $cmid,
        'context' => $PAGE->context,
        'other' => ['error' => $error, 'account' => $account->id],
    ]);
    $event->add_record_snapshot('course', $PAGE->course);
    $event->add_record_snapshot('jitsi', $jitsiob);
    $event->trigger();
}


/**
 * Normalizes the session name by removing any special characters or spaces.
 *
 * @param string $session The session name to be normalized.
 * @return string The normalized session name.
 */
function normalizesessionname($session) {
    $normalized = preg_replace('/[^a-zA-Z0-9\-_]/', '', $session);
    return $normalized;
}

/**
 * Send a Web Push notification to a user.
 *
 * @param int $userid Recipient user ID
 * @param string $title Notification title
 * @param string $body Notification body
 * @param string $url URL to open when notification is clicked
 */
function jitsi_send_push_notification($userid, $title, $body, $url) {
    global $DB, $CFG;

    $autoloader = __DIR__ . '/api/vendor/autoload.php';
    if (!file_exists($autoloader)) {
        return;
    }
    require_once($autoloader);

    $subscriptions = $DB->get_records('jitsi_push_subscriptions', ['userid' => $userid]);
    if (empty($subscriptions)) {
        return;
    }

    // Get or generate VAPID keys.
    $publickey = get_config('mod_jitsi', 'vapid_public_key');
    $privatekey = get_config('mod_jitsi', 'vapid_private_key');

    if (!$publickey || !$privatekey) {
        $keys = \Minishlink\WebPush\VAPID::createVapidKeys();
        set_config('vapid_public_key', $keys['publicKey'], 'mod_jitsi');
        set_config('vapid_private_key', $keys['privateKey'], 'mod_jitsi');
        $publickey = $keys['publicKey'];
        $privatekey = $keys['privateKey'];
    }

    // VAPID subject must be a mailto: URI or https:// URL.
    // mailto: is more reliable across push services.
    $admin = get_admin();
    $vapidsubject = 'mailto:' . $admin->email;

    $auth = [
        'VAPID' => [
            'subject'    => $vapidsubject,
            'publicKey'  => $publickey,
            'privateKey' => $privatekey,
        ],
    ];

    try {
        $webpush = new \Minishlink\WebPush\WebPush($auth);
        $payload = json_encode([
            'title' => $title,
            'body'  => $body,
            'url'   => $url,
            'icon'  => $CFG->wwwroot . '/mod/jitsi/pix/icon.png',
        ]);

        foreach ($subscriptions as $sub) {
            $subscription = \Minishlink\WebPush\Subscription::create([
                'endpoint' => $sub->endpoint,
                'keys'     => [
                    'auth'   => $sub->authkey,
                    'p256dh' => $sub->p256dhkey,
                ],
            ]);
            $webpush->queueNotification($subscription, $payload);
        }

        foreach ($webpush->flush() as $report) {
            debugging('Web Push report for ' . $report->getEndpoint() . ': '
                . ($report->isSuccess() ? 'OK' : $report->getReason()), DEBUG_DEVELOPER);
            if ($report->isSubscriptionExpired()) {
                $DB->delete_records_select(
                    'jitsi_push_subscriptions',
                    'userid = :userid AND ' . $DB->sql_compare_text('endpoint') . ' = ' . $DB->sql_compare_text(':endpoint'),
                    ['userid' => $userid, 'endpoint' => $report->getEndpoint()]
                );
            }
        }
    } catch (\Exception $e) {
        debugging('Web Push error: ' . $e->getMessage(), DEBUG_DEVELOPER);
    }
}

/**
 * Check if a teacher is available for private calls from a given student right now,
 * based on their tutoring schedule for shared courses.
 *
 * Returns an array:
 *   'hasschedule' => bool  — true if the teacher has any slots in shared courses where
 *                            they are teacher and the student is student.
 *   'available'   => bool  — true if current time falls within a slot (or no schedule).
 *   'nextslot'    => string|null — human-readable next available slot (teacher timezone),
 *                                  null if available now or no schedule.
 *
 * @param int $teacherid
 * @param int $studentid
 * @return array
 */
function jitsi_check_tutoring_availability($teacherid, $studentid) {
    global $DB;

    // Find visible courses where teacherid is teacher/editingteacher AND studentid is student.
    $teacherroles = array_keys(get_archetype_roles('teacher') + get_archetype_roles('editingteacher'));
    $studentroles = array_keys(get_archetype_roles('student'));

    if (empty($teacherroles) || empty($studentroles)) {
        return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
    }

    [$trolesql, $troleparams] = $DB->get_in_or_equal($teacherroles, SQL_PARAMS_NAMED, 'trole');
    [$srolesql, $sroleparams] = $DB->get_in_or_equal($studentroles, SQL_PARAMS_NAMED, 'srole');

    // Visible courses where teacherid has a teacher role.
    $teachercourses = $DB->get_fieldset_sql(
        "SELECT DISTINCT ctx.instanceid
           FROM {role_assignments} ra
           JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
           JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
          WHERE ra.userid = :teacherid AND ra.roleid $trolesql",
        array_merge(['ctxlevel' => CONTEXT_COURSE, 'teacherid' => $teacherid], $troleparams)
    );

    if (empty($teachercourses)) {
        return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
    }

    // From those, visible courses where studentid has a student role.
    [$coursesql, $courseparams] = $DB->get_in_or_equal($teachercourses, SQL_PARAMS_NAMED, 'course');
    $sharedcourses = $DB->get_fieldset_sql(
        "SELECT DISTINCT ctx.instanceid
           FROM {role_assignments} ra
           JOIN {context} ctx ON ctx.id = ra.contextid AND ctx.contextlevel = :ctxlevel
           JOIN {course} c ON c.id = ctx.instanceid AND c.visible = 1
          WHERE ra.userid = :studentid AND ra.roleid $srolesql AND ctx.instanceid $coursesql",
        array_merge(['ctxlevel' => CONTEXT_COURSE, 'studentid' => $studentid], $sroleparams, $courseparams)
    );

    if (empty($sharedcourses)) {
        return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
    }

    // Get tutoring schedule slots for those courses.
    [$csql, $cparams] = $DB->get_in_or_equal($sharedcourses, SQL_PARAMS_NAMED, 'sc');
    $slots = $DB->get_records_select(
        'jitsi_tutoring_schedule',
        "userid = :teacherid AND courseid $csql",
        array_merge(['teacherid' => $teacherid], $cparams),
        'weekday ASC, timestart ASC'
    );

    if (empty($slots)) {
        return ['hasschedule' => false, 'available' => true, 'nextslot' => null];
    }

    // Get teacher's timezone and current time in that timezone.
    $teacher = $DB->get_record('user', ['id' => $teacherid], 'timezone');
    $teachertz = core_date::normalise_timezone($teacher->timezone);
    $now = new DateTime('now', new DateTimeZone($teachertz));
    $currentweekday = (int)$now->format('w'); // 0=Sunday to 6=Saturday.
    $currentsecsofday = ((int)$now->format('H')) * 3600 + ((int)$now->format('i')) * 60 + (int)$now->format('s');

    // Check if we are currently within any slot.
    foreach ($slots as $slot) {
        $slotday = (int)$slot->weekday;
        $slotstart = (int)$slot->timestart;
        $slotend = (int)$slot->timeend;
        if ($slotday === $currentweekday && $currentsecsofday >= $slotstart && $currentsecsofday < $slotend) {
            return ['hasschedule' => true, 'available' => true, 'nextslot' => null];
        }
    }

    // Not available now — find next slot within the next 7 days.
    $nextslotstr = null;
    $days = get_string_manager()->get_list_of_translations(); // Not needed, using lang strings differently.
    $weekdays = [
        0 => get_string('weekday0', 'mod_jitsi'),
        1 => get_string('weekday1', 'mod_jitsi'),
        2 => get_string('weekday2', 'mod_jitsi'),
        3 => get_string('weekday3', 'mod_jitsi'),
        4 => get_string('weekday4', 'mod_jitsi'),
        5 => get_string('weekday5', 'mod_jitsi'),
        6 => get_string('weekday6', 'mod_jitsi'),
    ];

    // Build candidate list: remaining slots today, then next 6 days.
    for ($dayoffset = 0; $dayoffset <= 6; $dayoffset++) {
        $checkday = ($currentweekday + $dayoffset) % 7;
        foreach ($slots as $slot) {
            if ((int)$slot->weekday !== $checkday) {
                continue;
            }
            // If same day, only consider future slots.
            if ($dayoffset === 0 && (int)$slot->timestart <= $currentsecsofday) {
                continue;
            }
            $h = intdiv((int)$slot->timestart, 3600);
            $m = intdiv(((int)$slot->timestart % 3600), 60);
            $nextslotstr = $weekdays[$checkday] . ' ' . sprintf('%02d:%02d', $h, $m);
            break 2;
        }
    }

    return ['hasschedule' => true, 'available' => false, 'nextslot' => $nextslotstr];
}

/**
 * Returns true if the given GCP server has at least one Jibri VM ready in the pool,
 * or falls back to the legacy jibri_provisioningstatus field for servers not yet migrated.
 *
 * @param \stdClass $server jitsi_servers record
 * @return bool
 */
function jitsi_is_jibri_ready(\stdClass $server): bool {
    global $DB;
    if (empty($server->jibri_enabled)) {
        return false;
    }
    // Check pool table first.
    if (
        $DB->record_exists_select(
            'jitsi_jibri_pool',
            "serverid = ? AND status IN ('idle', 'recording', 'streaming')",
            [$server->id]
        )
    ) {
        return true;
    }
    // If the server already has pool entries (even provisioning), don't fall back to legacy field.
    if ($DB->record_exists('jitsi_jibri_pool', ['serverid' => $server->id])) {
        return false;
    }
    // Fallback: legacy field (servers not yet migrated to pool).
    return ($server->jibri_provisioningstatus ?? '') === 'ready';
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

/**
 * Compute total watched percentage from segments.
 *
 * @param array $segments Array of [start, end] pairs in seconds
 * @param float $duration Video duration in seconds
 * @return int  0–100
 */
function jitsi_segments_watched_pct(array $segments, float $duration): int {
    if ($duration <= 0 || empty($segments)) {
        return 0;
    }
    $watched = 0;
    foreach ($segments as $seg) {
        if (is_array($seg) && count($seg) >= 2) {
            $watched += max(0, (float)$seg[1] - (float)$seg[0]);
        }
    }
    return min(100, (int)round(($watched / $duration) * 100));
}

/**
 * Render an aggregate heatmap bar showing which parts of a recording each fraction of viewers watched.
 * Color intensity is proportional to the share of viewers who watched each time bucket.
 * Only shown to users with mod/jitsi:viewattendance.
 *
 * @param int $sourcerecordid
 * @param int $cmid
 * @return string HTML, or empty string if no data
 */
/**
 * Format a number of seconds as a video timestamp (MM:SS or H:MM:SS).
 *
 * @param int $seconds
 * @return string
 */
function jitsi_format_video_seconds(int $seconds): string {
    if ($seconds < 60) {
        return $seconds . 's';
    }
    $h   = intdiv($seconds, 3600);
    $m   = intdiv($seconds % 3600, 60);
    $s   = $seconds % 60;
    $out = '';
    if ($h > 0) {
        $out .= $h . 'h ';
    }
    if ($m > 0 || $h > 0) {
        $out .= $m . 'min';
        if ($s > 0) {
            $out .= ' ' . $s . 's';
        }
    } else {
        $out .= $s . 's';
    }
    return trim($out);
}

/**
 * Render an aggregate heatmap bar showing which parts of a recording each fraction of viewers watched.
 * Color intensity is proportional to the share of viewers who watched each time bucket.
 * Only shown to users with mod/jitsi:viewattendance.
 *
 * @param int $sourcerecordid
 * @param int $cmid
 * @return string HTML, or empty string if no data
 */
function jitsi_render_heatmap_bar(int $sourcerecordid, int $cmid): string {
    global $DB;

    $rows = $DB->get_records('jitsi_recording_segments', [
        'sourcerecordid' => $sourcerecordid,
        'cmid'           => $cmid,
    ]);

    if (empty($rows)) {
        return '';
    }

    $duration = 0.0;
    foreach ($rows as $row) {
        if ((float)$row->duration > $duration) {
            $duration = (float)$row->duration;
        }
    }
    if ($duration <= 0) {
        return '';
    }

    $totalviewers = count($rows);
    $bucketsize   = 10;
    $numbuckets   = max(1, (int)ceil($duration / $bucketsize));
    $buckets      = array_fill(0, $numbuckets, 0);

    foreach ($rows as $row) {
        $segments = json_decode($row->segments, true);
        if (!is_array($segments)) {
            continue;
        }
        $covered = array_fill(0, $numbuckets, false);
        foreach ($segments as $seg) {
            if (!is_array($seg) || count($seg) < 2) {
                continue;
            }
            $startbucket = max(0, (int)floor((float)$seg[0] / $bucketsize));
            $endbucket   = min($numbuckets - 1, (int)floor((float)$seg[1] / $bucketsize));
            for ($b = $startbucket; $b <= $endbucket; $b++) {
                $covered[$b] = true;
            }
        }
        foreach ($covered as $b => $iscovered) {
            if ($iscovered) {
                $buckets[$b]++;
            }
        }
    }

    // Aggregate playcounts across all users.
    $playtotals = array_fill(0, $numbuckets, 0);
    $maxplays   = 0;
    foreach ($rows as $row) {
        if (empty($row->playcounts)) {
            continue;
        }
        $counts = json_decode($row->playcounts, true);
        if (!is_array($counts)) {
            continue;
        }
        foreach ($counts as $b => $c) {
            if ($b < $numbuckets) {
                $playtotals[$b] += (int)$c;
                if ($playtotals[$b] > $maxplays) {
                    $maxplays = $playtotals[$b];
                }
            }
        }
    }

    // Build viewers-per-bucket map for inline tooltip data.
    $userids = array_unique(array_map(fn($r) => (int)$r->userid, (array)$rows));
    $usernames = [];
    if (!empty($userids)) {
        [$insql, $inparams] = $DB->get_in_or_equal($userids, SQL_PARAMS_NAMED, 'uid');
        $namefields = 'id, firstname, lastname, firstnamephonetic, lastnamephonetic, middlename, alternatename';
        $users = $DB->get_records_sql("SELECT $namefields FROM {user} WHERE id $insql", $inparams);
        foreach ($users as $u) {
            $usernames[$u->id] = fullname($u);
        }
    }

    $viewersperbucket = [];
    foreach ($rows as $row) {
        $segments = json_decode($row->segments, true);
        if (!is_array($segments)) {
            continue;
        }
        $name = $usernames[(int)$row->userid] ?? '';
        if ($name === '') {
            continue;
        }
        $covered = array_fill(0, $numbuckets, false);
        foreach ($segments as $seg) {
            if (!is_array($seg) || count($seg) < 2) {
                continue;
            }
            $sb = max(0, (int)floor((float)$seg[0] / $bucketsize));
            $eb = min($numbuckets - 1, (int)floor((float)$seg[1] / $bucketsize));
            for ($b = $sb; $b <= $eb; $b++) {
                $covered[$b] = true;
            }
        }
        foreach ($covered as $b => $c) {
            if ($c) {
                $viewersperbucket[$b][] = $name;
            }
        }
    }

    $viewerlabel  = get_string('recordingheatmapviewers', 'jitsi', $totalviewers);
    $viewersjson  = htmlspecialchars(json_encode($viewersperbucket), ENT_QUOTES, 'UTF-8');
    $html  = '<div class="mt-3">';
    $html .= '<small class="text-muted d-block mb-1">'
        . get_string('recordingheatmap', 'jitsi') . ' — ' . $viewerlabel
        . '</small>';

    $bucketwidth = 100 / $numbuckets;

    // Bar 1: unique viewers (blue) — hover tooltip shows viewer names.
    $html .= '<div class="jitsi-heatmap mb-1"'
        . ' data-viewers="' . $viewersjson . '"'
        . ' data-bucketsize="' . $bucketsize . '"'
        . ' style="position:relative;height:8px;background:#dee2e6;border-radius:4px;overflow:hidden;cursor:crosshair">';
    foreach ($buckets as $i => $count) {
        if ($count === 0) {
            continue;
        }
        $opacity   = number_format($count / $totalviewers, 3, '.', '');
        $left      = number_format($i * $bucketwidth, 3, '.', '');
        $width     = number_format($bucketwidth + 0.1, 3, '.', '');
        $start     = $i * $bucketsize;
        $end       = $start + $bucketsize;
        $fmtstart  = jitsi_format_video_seconds($start);
        $fmtend    = jitsi_format_video_seconds($end);
        $html     .= '<div data-bucket="' . $i . '" data-start="' . s($fmtstart) . '" data-end="' . s($fmtend) . '"'
            . ' style="position:absolute;left:' . $left . '%;width:' . $width
            . '%;height:100%;background:rgba(13,110,253,' . $opacity . ')"></div>';
    }
    $html .= '</div>';

    // Bar 2: total plays (orange), only if we have data.
    if ($maxplays > 0) {
        $html .= '<small class="text-muted d-block mb-1">'
            . get_string('recordingheatmapplays', 'jitsi', $maxplays)
            . '</small>';
        $html .= '<div class="jitsi-heatmap" style="position:relative;height:8px;'
            . 'background:#dee2e6;border-radius:4px;overflow:hidden;cursor:default">';
        foreach ($playtotals as $i => $count) {
            if ($count === 0) {
                continue;
            }
            $opacity  = number_format($count / $maxplays, 3, '.', '');
            $left     = number_format($i * $bucketwidth, 3, '.', '');
            $width    = number_format($bucketwidth + 0.1, 3, '.', '');
            $start    = $i * $bucketsize;
            $end      = $start + $bucketsize;
            $tooltip  = s($count . ' plays · ' . jitsi_format_video_seconds($start) . '–' . jitsi_format_video_seconds($end));
            $html    .= '<div title="' . $tooltip . '" style="position:absolute;left:' . $left . '%;width:' . $width
                . '%;height:100%;background:rgba(253,126,20,' . $opacity . ')"></div>';
        }
        $html .= '</div>';
    }

    $html .= '</div>';
    return $html;
}
