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

namespace mod_jitsi\local;

/**
 * Renders a Jitsi videoconference session (HTML + JS) for an activity.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class session {
    /**
     * Create and render a Jitsi session (HTML + JS).
     *
     * @param int $teacher Moderation flag
     * @param int $cmid Course module id
     * @param string $avatar Avatar URL
     * @param string $nombre Display name
     * @param string $session Session/room name
     * @param string $mail Email
     * @param \stdClass $jitsi Jitsi session record
     * @param bool $universal Whether this is a universal (invitation) session
     * @param \stdClass|null $user User object for private sessions
     */
    public static function create(
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
        $serverstatus = \mod_jitsi\local\server::check_gcp_status($server);
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
            $context = \context_system::instance();
        } else {
            $context = \context_module::instance($cmid);
        }

        if ($universal == false) {
            if (!has_capability('mod/jitsi:view', $context)) {
                notice(get_string('noviewpermission', 'jitsi'));
            }
        }

        echo "<script src=\"//ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js\"></script>";
        echo "<script src=\"https://" . $domain . "/external_api.js\"></script>\n";

        $streamingoption = '';
        $jibrienabled = ($servertype == 3 && \mod_jitsi\local\jibri::is_ready($server));
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
        // For GCP servers (type 3) the Moodle-integrated record button is used instead.
        $jibrienabled = ($servertype == 3 && \mod_jitsi\local\jibri::is_ready($server));
        if (
            get_config('mod_jitsi', 'record') == 1 &&
            has_capability('mod/jitsi:record', $PAGE->context) &&
            $servertype != 3
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
                        . "<i class=\"fa fa-rss me-1\" aria-hidden=\"true\"></i>"
                        . addslashes(get_string('streambtn', 'jitsi')) . "</button>";
                }
                if ($showrecording) {
                    echo "<button id=\"recordBtn\" class=\"btn btn-sm btn-outline-danger\""
                        . " onclick=\"handleRecordBtn()\" disabled>"
                        . "<i class=\"fa fa-circle me-1\" aria-hidden=\"true\"></i>"
                        . addslashes(get_string('recordbtn', 'jitsi')) . "</button>";
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
        $jibrilivestream = ($servertype == 3 && \mod_jitsi\local\jibri::is_ready($server));
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
            $themeconfig = \theme_config::load($CFG->theme);
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
        echo "api.executeCommand('displayName', " . json_encode($nombre) . ");\n";
        echo "api.executeCommand('avatarUrl', " . json_encode($avatar) . ");\n";
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
        echo "var jitsiRecordingStateReceived = false;\n";
        echo "setTimeout(function() {\n";
        echo "  if (jitsiRecordingStateReceived) { return; }\n";
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
            echo "  jitsiRecordingStateReceived = true;\n";
            echo "  var sb = document.getElementById('streamBtn');\n";
            echo "  var rb = document.getElementById('recordBtn');\n";
            echo "  if (event['mode'] == 'file') {\n";
            echo "    if (event['on']) {\n";
            echo "      if (rb) { rb.classList.remove('btn-outline-danger');";
            echo " rb.classList.add('btn-danger'); rb.disabled = false; }\n";
            echo "      if (sb) { sb.disabled = true; }\n";
            echo "    } else {\n";
            echo "      if (rb) { rb.classList.remove('btn-danger');";
            echo " rb.classList.add('btn-outline-danger'); rb.disabled = false; }\n";
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
            echo "    if (sb) { sb.classList.remove('btn-outline-warning');";
            echo " sb.classList.add('btn-warning'); sb.disabled = false; }\n";
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
            echo "    if (sb) { sb.classList.remove('btn-warning'); sb.classList.add('btn-outline-warning');\n";
            echo "      setTimeout(function(){ sb.disabled = false; }, 2000); }\n";
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
            echo "        '<div class=\"alert alert-light\" role=\"alert\">";
            echo "ERROR RECORD ACCOUNT. TRY AGAIN IN A FEW SECONDS</div>';";
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
            echo "    } else if (response['error'] == 'erroraccount'){\n";
            echo "      document.getElementById('state').innerHTML = ";
            echo "        '<div class=\"alert alert-warning\" role=\"alert\">' + response['errorinfo'] + '</div>';";
            echo "if (document.getElementById(\"recordSwitch\") != null) {\n";
            echo "      document.getElementById(\"recordSwitch\").disabled = false;\n";
            echo "      document.getElementById(\"recordSwitch\").checked = false;\n";
            echo "}\n";
            echo "      require(['jquery', 'core/ajax', 'core/notification'], function($, ajax, notification) {\n";
            echo "        ajax.call([{\n";
            echo "          methodname: 'mod_jitsi_stop_stream_byerror',\n";
            echo "          args: {jitsi: " . $jitsi->id . ", userid : " . $USER->id . "},\n";
            echo "          done: console.log(\"stream account error cleaned\"),\n";
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
            echo "              alert(\"" . addslashes(get_string('recordingbloquedby', 'jitsi'))
                . "\"+response['usercomplete']);\n";
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
     * Create and render a private (1-to-1) Jitsi session.
     *
     * @param int $teacher Moderation flag
     * @param int $cmid Course module id
     * @param string $avatar Avatar URL
     * @param string $nombre Display name
     * @param string $session Session/room name
     * @param string $mail Email
     * @param \stdClass $jitsi Jitsi session record
     * @param bool $universal Whether this is a universal session
     * @param \stdClass|null $user Peer user
     */
    public static function create_priv(
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
        $serverstatus = \mod_jitsi\local\server::check_gcp_status($server);
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
            $context = \context_system::instance();
        } else {
            $context = \context_module::instance($cmid);
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
            $themeconfig = \theme_config::load($CFG->theme);
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
}
