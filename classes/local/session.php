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
     * Build the room name and (optionally) the signed JWT for a session, per server type.
     *
     * Server types: 0 = public (no token), 1 = self-hosted (HS256), 2 = 8x8 JaaS (RS256),
     * 3 = GCP (HS256). When global tokentype is 1, type-1-style HS256 tokens are also used.
     *
     * @param \stdClass $server Server record from jitsi_servers
     * @param \context $modcontext Context to evaluate the moderation capability against
     * @param string $sessionnorm Normalized session name
     * @param bool $teacher Whether the user is a moderator/owner
     * @param string $affiliation 'owner' or 'member'
     * @param string $nombre Display name
     * @param string $avatar Avatar URL
     * @param string|null $mail Email
     * @return array ['roomname' => string, 'jwt' => string|null]
     */
    public static function build_token($server, $modcontext, $sessionnorm, $teacher, $affiliation, $nombre, $avatar, $mail) {
        $servertype = $server->type;
        $appid = $server->appid;
        $domain = $server->domain;
        $secret = $server->secret;
        $eightbyeightappid = $server->eightbyeightappid;
        $eightbyeightapikeyid = $server->eightbyeightapikeyid;
        $privatykey = $server->privatekey;

        $header = null;
        $payload = null;
        $headerencoded = null;
        $payloadencoded = null;
        $signature = null;

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
                        'moderator' => has_capability('mod/jitsi:moderation', $modcontext),
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
            $roomname = $eightbyeightappid . "/" . urlencode($sessionnorm);
            $payloadencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
            $headerencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
            openssl_sign($headerencoded . "." . $payloadencoded, $signature, $privatykey, OPENSSL_ALGO_SHA256);
        } else if (get_config('mod_jitsi', 'tokentype') == '1' || $servertype == '1' || $servertype == '3') {
            $header = json_encode([
                "kid" => "jitsi/custom_key_name",
                "typ" => "JWT",
                "alg" => "HS256",
            ], JSON_UNESCAPED_SLASHES);
            $ismoderator = has_capability('mod/jitsi:moderation', $modcontext);
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
            $roomname = urlencode($sessionnorm);
            $payloadencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));
            $headerencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
            $signature = hash_hmac('sha256', $headerencoded . "." . $payloadencoded, $secret, true);
        } else {
            $roomname = urlencode($sessionnorm);
        }

        $jwt = null;
        if (
            ($servertype == '1' && ($appid != null && $secret != null)) ||
            ($servertype == '3' && ($appid != null && $secret != null)) ||
            $servertype == '2'
        ) {
            $signatureencoded = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));
            $jwt = $headerencoded . "." . $payloadencoded . "." . $signatureencoded;
        }

        return ['roomname' => $roomname, 'jwt' => $jwt];
    }

    /**
     * Build the ordered list of Jitsi toolbar buttons, honouring plugin settings and capabilities.
     *
     * Conditional buttons collapse to an empty string when disabled (Jitsi ignores empty entries),
     * preserving the exact slot order the front-end expects.
     *
     * @param \stdClass $server Server record from jitsi_servers
     * @param \context $context Context to evaluate capabilities against
     * @param bool $isprivate Whether this is a private (1-to-1) session (no recording/streaming)
     * @param bool $jibrienabled Whether a GCP Jibri recorder is ready
     * @return string[] Ordered toolbar button keys
     */
    public static function build_toolbar_buttons($server, \context $context, bool $isprivate, bool $jibrienabled): array {
        $servertype = $server->type;

        // On GCP (type 3) the Moodle toolbar record button always replaces Jitsi's own;
        // on 8x8/JaaS (type 2) the recordingoption setting picks between the native
        // button (its dialog allows Dropbox) and the Moodle toolbar one.
        $moodlerecordbtn = ($servertype == 3)
            || ($servertype == 2 && get_config('mod_jitsi', 'recordingoption') == 1);
        $record = '';
        if (
            !$isprivate &&
            get_config('mod_jitsi', 'record') == 1 &&
            has_capability('mod/jitsi:record', $context) &&
            !$moodlerecordbtn
        ) {
            $record = 'recording';
        }

        $streamingoption = '';
        if (
            !$isprivate &&
            get_config('mod_jitsi', 'livebutton') == 1 &&
            has_capability('mod/jitsi:record', $context) &&
            get_config('mod_jitsi', 'streamingoption') == 0 &&
            ($servertype != 3 || $jibrienabled)
        ) {
            $streamingoption = 'livestreaming';
        }

        $youtubeoption = (get_config('mod_jitsi', 'shareyoutube') == 1) ? 'sharedvideo' : '';
        $bluroption = (get_config('mod_jitsi', 'blurbutton') == 1) ? 'select-background' : '';
        $security = (get_config('mod_jitsi', 'securitybutton') == 1) ? 'security' : '';
        $invite = '';

        $muteeveryone = '';
        $mutevideoeveryone = '';
        if (has_capability('mod/jitsi:moderation', $context)) {
            $muteeveryone = 'mute-everyone';
            $mutevideoeveryone = 'mute-video-everyone';
        }

        $participantspane = '';
        if (
            has_capability('mod/jitsi:moderation', $context) ||
            get_config('mod_jitsi', 'participantspane') == 1
        ) {
            $participantspane = 'participants-pane';
        }

        $raisehand = (get_config('mod_jitsi', 'raisehand') == 1) ? 'raisehand' : '';
        $whiteboard = (get_config('mod_jitsi', 'whiteboard') == 1) ? 'whiteboard' : '';

        return [
            'microphone', 'camera', 'closedcaptions', 'desktop', 'fullscreen',
            'fodeviceselection', 'hangup', 'chat', $record, 'etherpad', $youtubeoption,
            'settings', $raisehand, 'videoquality', $streamingoption, 'filmstrip', $invite, 'stats',
            'shortcuts', 'tileview', $bluroption, 'download', 'help', $muteeveryone,
            $mutevideoeveryone, $security, $participantspane, $whiteboard,
        ];
    }

    /**
     * Build the JitsiMeetExternalAPI configOverwrite object as a PHP array (ready for json_encode).
     *
     * @param \stdClass $server Server record from jitsi_servers
     * @param \stdClass $jitsi Jitsi session record (uses ->name as the subject)
     * @param \context $context Context to evaluate the moderation capability against
     * @param string[] $buttons Toolbar button keys from build_toolbar_buttons()
     * @param bool $isprivate Whether this is a private (1-to-1) session (recording/streaming forced off)
     * @param bool $jibrienabled Whether a GCP Jibri recorder is ready
     * @return array configOverwrite settings
     */
    public static function build_config_overwrite(
        $server,
        $jitsi,
        \context $context,
        array $buttons,
        bool $isprivate,
        bool $jibrienabled
    ): array {
        $servertype = $server->type;
        $ismoderator = has_capability('mod/jitsi:moderation', $context);

        $config = [];

        $allowbreakout = (get_config('mod_jitsi', 'allowbreakoutrooms') == '1');
        $config['breakoutRooms'] = [
            'hideAddRoomButton' => !$allowbreakout,
            'hideAutoAssignButton' => !$allowbreakout,
            'hideJoinRoomButton' => !$allowbreakout,
        ];

        $config['subject'] = $jitsi->name;
        $config['disableSelfView'] = false;
        $config['defaultLanguage'] = current_language();
        $config['disableInviteFunctions'] = true;
        $config['recordingService'] = ['enabled' => get_config('mod_jitsi', 'livebutton') == 1];

        if ($isprivate) {
            // Private sessions never allow recording or live streaming.
            $config['fileRecordingsEnabled'] = false;
            $config['liveStreamingEnabled'] = false;
        } else if (get_config('mod_jitsi', 'record') == 1) {
            $config['fileRecordingsEnabled'] = true;
        }

        // The original JS emitted two remoteVideoMenu literals; for non-moderators the second
        // (locked-down) one overrode the first. Collapse that here, since a PHP array can't hold
        // duplicate keys, preserving the same runtime behaviour.
        if ($ismoderator) {
            $config['remoteVideoMenu'] = ['disableGrantModerator' => true];
        } else {
            $config['remoteVideoMenu'] = ['disableKick' => true, 'disableGrantModerator' => true];
            $config['disableRemoteMute'] = true;
        }

        $config['buttonsWithNotifyClick'] = [
            ['key' => 'camera', 'preventExecution' => false],
            ['key' => 'desktop', 'preventExecution' => false],
            ['key' => 'tileview', 'preventExecution' => false],
            ['key' => 'chat', 'preventExecution' => false],
            ['key' => 'chat', 'preventExecution' => false],
            ['key' => 'microphone', 'preventExecution' => false],
            ['key' => '__end', 'preventExecution' => true],
        ];

        $config['disableDeepLinking'] = true;

        if (get_config('mod_jitsi', 'reactions') == 0) {
            $config['disableReactions'] = true;
        }

        if (get_config('mod_jitsi', 'chat') == 0) {
            $config['disableChat'] = true;
            $config['disablePolls'] = true;
        } else if (get_config('mod_jitsi', 'polls') == 0) {
            $config['disablePolls'] = true;
        }

        // Disable live streaming if the global setting is off, or on GCP (type 3) without Jibri ready.
        // Both keys are emitted for multi-version Jitsi Meet compatibility.
        if (
            !$isprivate &&
            (get_config('mod_jitsi', 'livebutton') == 0 || ($servertype == 3 && !$jibrienabled))
        ) {
            $config['liveStreamingEnabled'] = false;
            $config['liveStreaming'] = ['enabled' => false];
        }

        $config['toolbarButtons'] = $buttons;
        $config['disableProfile'] = true;
        $config['prejoinPageEnabled'] = false;
        $config['prejoinConfig'] = ['enabled' => false];
        $config['channelLastN'] = (int) get_config('mod_jitsi', 'channellastcam');
        $config['startWithAudioMuted'] = get_config('mod_jitsi', 'startwithaudiomuted') == '1';
        $config['startWithVideoMuted'] = get_config('mod_jitsi', 'startwithvideomuted') == '1';

        if ($servertype != 2) {
            $dropboxappkey = get_config('mod_jitsi', 'dropbox_appkey');
            if (!empty($dropboxappkey)) {
                $dropbox = ['appKey' => $dropboxappkey];
                $dropboxredirecturi = get_config('mod_jitsi', 'dropbox_redirect_uri');
                if (!empty($dropboxredirecturi)) {
                    $dropbox['redirectURI'] = $dropboxredirecturi;
                }
                $config['dropbox'] = $dropbox;
            }
        }

        if (get_config('mod_jitsi', 'transcription') == 0) {
            $config['transcription'] = ['enabled' => false];
        }

        return $config;
    }

    /**
     * Build the JitsiMeetExternalAPI interfaceConfigOverwrite object as a PHP array.
     *
     * @param string[] $buttons Toolbar button keys from build_toolbar_buttons()
     * @return array interfaceConfigOverwrite settings
     */
    public static function build_interface_config_overwrite(array $buttons): array {
        return [
            'TOOLBAR_BUTTONS' => $buttons,
            'SHOW_JITSI_WATERMARK' => true,
            'JITSI_WATERMARK_LINK' => get_config('mod_jitsi', 'watermarklink'),
        ];
    }

    /**
     * Resolve the default server and the per-user session context shared by create()/create_priv().
     *
     * Echoes a notification and returns null when there is no default server or the GCP server is
     * down; halts via notice() when the user lacks view permission.
     *
     * @param int $cmid Course module id
     * @param string $session Session/room name
     * @param int $teacher Moderation flag (1 = moderator)
     * @param bool $universal Whether this is a universal (invitation) session
     * @param \stdClass|null $user Peer user for private sessions
     * @return \stdClass|null {server, sessionnorm, teacher (bool), affiliation, context} or null on error
     */
    private static function resolve_session_context($cmid, $session, $teacher, $universal, $user) {
        global $DB, $OUTPUT;

        $serverid = get_config('mod_jitsi', 'server');
        $server = $DB->get_record('jitsi_servers', ['id' => $serverid]);

        if (!$server) {
            echo $OUTPUT->notification(get_string('nodefaultserver', 'jitsi'), 'error');
            return null;
        }

        // Check if GCP server is running.
        $serverstatus = \mod_jitsi\local\server::check_gcp_status($server);
        if ($serverstatus['status'] === 'stopped') {
            echo $OUTPUT->notification(get_string('gcpserverstopped', 'jitsi'), 'error');
            return null;
        } else if ($serverstatus['status'] === 'error') {
            $errormsg = isset($serverstatus['message']) ? $serverstatus['message'] : 'Unknown error';
            echo $OUTPUT->notification(get_string('gcpservererror', 'jitsi', $errormsg), 'error');
            return null;
        }

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

        return (object)[
            'server' => $server,
            'sessionnorm' => \mod_jitsi\local\room::normalize_session_name($session),
            'teacher' => $teacher,
            'affiliation' => $affiliation,
            'context' => $context,
        ];
    }

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
        global $CFG, $DB, $PAGE, $USER;

        $ctx = self::resolve_session_context($cmid, $session, $teacher, $universal, $user);
        if ($ctx === null) {
            return;
        }
        $server = $ctx->server;
        $servertype = $server->type;
        $domain = $server->domain;
        $sessionnorm = $ctx->sessionnorm;
        $teacher = $ctx->teacher;
        $affiliation = $ctx->affiliation;

        echo "<script src=\"//ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js\"></script>";
        echo "<script src=\"https://" . $domain . "/external_api.js\"></script>\n";

        $jibrienabled = ($servertype == 3 && \mod_jitsi\local\jibri::is_ready($server));
        $buttons = self::build_toolbar_buttons($server, $PAGE->context, false, $jibrienabled);

        $account = $DB->get_record('jitsi_record_account', ['inuse' => 1]);

        $showstreaming = false;
        $showrecording = false;
        if ($user == null) {
            $showstreaming = (
                get_config('mod_jitsi', 'livebutton') == 1 &&
                has_capability('mod/jitsi:record', $PAGE->context) &&
                $account != null && $universal == false &&
                get_config('mod_jitsi', 'streamingoption') == 1 &&
                $jitsi->sessionwithtoken == 0 &&
                ($servertype != 3 || $jibrienabled)
            );
            // GCP needs its Jibri recorder ready; 8x8 records in the JaaS cloud when
            // the recordingoption setting picks the Moodle toolbar button.
            $canrecordhere = ($servertype == 3 && $jibrienabled)
                || (
                    $servertype == 2 &&
                    get_config('mod_jitsi', 'record') == 1 &&
                    get_config('mod_jitsi', 'recordingoption') == 1
                );
            $showrecording = (
                has_capability('mod/jitsi:record', $PAGE->context) &&
                $universal == false && $canrecordhere &&
                $jitsi->sessionwithtoken == 0
            );
        }

        echo \mod_jitsi\output\session_page::render($CFG->branch >= 500, $showstreaming, $showrecording);

        echo "<script>\n";
        echo "const domain = \"" . $domain . "\";\n";

        $configoverwrite = self::build_config_overwrite($server, $jitsi, $PAGE->context, $buttons, false, $jibrienabled);
        $interfaceconfig = self::build_interface_config_overwrite($buttons);
        $token = self::build_token($server, $PAGE->context, $sessionnorm, $teacher, $affiliation, $nombre, $avatar, $mail);

        echo "const options = {\n";
        echo "configOverwrite: " . json_encode($configoverwrite, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ",\n";
        echo "roomName: \"" . $token['roomname'] . "\",\n";
        if ($token['jwt'] !== null) {
            echo "jwt: \"" . $token['jwt'] . "\",\n";
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
        echo "interfaceConfigOverwrite: " . json_encode($interfaceconfig, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ",\n";
        echo "width: '100%',";
        echo "height: '100%',";
        echo "}\n";
        echo "const api = new JitsiMeetExternalAPI(domain, options);\n";
        // Expose the live api so the session_presence AMD module (loaded via js_call_amd in the
        // footer, after RequireJS is ready) can attach its listeners to it.
        echo "window.jitsiSessionApi = api;\n";
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

        // Presence tracking (heartbeats, participating ping, join/leave) lives in the
        // mod_jitsi/session_presence AMD module; hand it the live api instance and its config.
        $trackjoinleave = ($user == null);
        $redirecturl = null;
        if ($user == null) {
            if ($universal == false) {
                $redirecturl = $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid;
            } else {
                $redirecturl = $CFG->wwwroot . "/mod/jitsi/formuniversal.php?t=" . $jitsi->token;
            }
        }
        $presenceconfig = [
            'jitsiid' => (int) $jitsi->id,
            'cmid' => (int) $cm->id,
            'userid' => (int) $USER->id,
            'isGuest' => (!isloggedin() || isguestuser()),
            'guestName' => $nombre,
            'trackJoinLeave' => $trackjoinleave,
            'redirectUrl' => $redirecturl,
        ];
        $PAGE->requires->js_call_amd('mod_jitsi/session_presence', 'init', [$presenceconfig]);

        // Password auto-fill and finish-and-return redirect live in the
        // mod_jitsi/session_controls AMD module (both are settings-gated).
        $password = get_config('mod_jitsi', 'password');
        $finishandreturn = (get_config('mod_jitsi', 'finishandreturn') == 1);
        $closeredirecturl = null;
        if ($finishandreturn) {
            if ($universal == false && $user == null) {
                $closeredirecturl = $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid;
            } else if ($universal == true && $user == null) {
                $closeredirecturl = $CFG->wwwroot . "/mod/jitsi/formuniversal.php?t=" . $jitsi->token;
            } else if ($user != null) {
                $closeredirecturl = $CFG->wwwroot . "/mod/jitsi/viewpriv.php?user=" . $user;
            }
        }
        if (($password != null && $password !== '') || $finishandreturn) {
            $PAGE->requires->js_call_amd('mod_jitsi/session_controls', 'init', [[
                'jitsiid' => (int) $jitsi->id,
                'userid' => (int) $USER->id,
                'cmid' => (int) $cmid,
                'password' => ($password != null && $password !== '') ? $password : null,
                'finishAndReturn' => $finishandreturn,
                'reportEnd' => true,
                'closeRedirectUrl' => $closeredirecturl,
            ]]);
        }

        if ($user == null) {
            // Toolbar-button audit lives in the mod_jitsi/session_buttons AMD module.
            $PAGE->requires->js_call_amd('mod_jitsi/session_buttons', 'init', [[
                'jitsiid' => (int) $jitsi->id,
                'userid' => (int) $USER->id,
                'cmid' => (int) $cmid,
            ]]);
            // Recording / live-streaming controls live in the mod_jitsi/session_recording module.
            $PAGE->requires->js_call_amd('mod_jitsi/session_recording', 'init', [[
                'jitsiid' => (int) $jitsi->id,
                'userid' => (int) $USER->id,
                'cmid' => (int) $cmid,
                'session' => $session,
            ]]);
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
        global $CFG, $PAGE, $USER;

        $ctx = self::resolve_session_context($cmid, $session, $teacher, $universal, $user);
        if ($ctx === null) {
            return;
        }
        $server = $ctx->server;
        $servertype = $server->type;
        $appid = $server->appid;
        $domain = $server->domain;
        $secret = $server->secret;
        $eightbyeightappid = $server->eightbyeightappid;
        $eightbyeightapikeyid = $server->eightbyeightapikeyid;
        $privatykey = $server->privatekey;
        $sessionnorm = $ctx->sessionnorm;
        $teacher = $ctx->teacher;
        $affiliation = $ctx->affiliation;

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
        $buttons = self::build_toolbar_buttons($server, $PAGE->context, true, false);

        echo "<div class=\"row\">";
        echo "<div class=\"col-sm\">";

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
        echo "const domain = \"" . $domain . "\";\n";

        $configoverwrite = self::build_config_overwrite($server, $jitsi, $PAGE->context, $buttons, true, false);

        echo "const options = {\n";
        echo "configOverwrite: " . json_encode($configoverwrite, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ",\n";

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
        echo "interfaceConfigOverwrite: " .
            json_encode(self::build_interface_config_overwrite($buttons), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ",\n";
        echo "width: '100%',\n";
        echo "height: '100%',\n";
        echo "}\n";
        echo "const api = new JitsiMeetExternalAPI(domain, options);\n";
        // Expose the live api so the session_controls AMD module can attach its listeners.
        echo "window.jitsiSessionApi = api;\n";
        echo "</script>\n";

        // Password auto-fill and finish-and-return redirect live in the mod_jitsi/session_controls
        // module. Private sessions never report the session end (no associated activity).
        $password = get_config('mod_jitsi', 'password');
        $finishandreturn = (get_config('mod_jitsi', 'finishandreturn') == 1);
        $closeredirecturl = null;
        if ($finishandreturn) {
            if ($universal == false && $user == null) {
                $closeredirecturl = $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid;
            } else if ($universal == true && $user == null) {
                $closeredirecturl = $CFG->wwwroot . "/mod/jitsi/formuniversal.php?t=" . $jitsi->token;
            } else if ($user != null) {
                $closeredirecturl = $CFG->wwwroot . "/mod/jitsi/call.php";
            }
        }
        if (($password != null && $password !== '') || $finishandreturn) {
            $PAGE->requires->js_call_amd('mod_jitsi/session_controls', 'init', [[
                'jitsiid' => (int) $jitsi->id,
                'userid' => (int) $USER->id,
                'cmid' => (int) $cmid,
                'password' => ($password != null && $password !== '') ? $password : null,
                'finishAndReturn' => $finishandreturn,
                'reportEnd' => false,
                'closeRedirectUrl' => $closeredirecturl,
            ]]);
        }
    }
}
