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
 * Settings for Jitsi instances
 * @package   mod_jitsi
 * @copyright  2019 Sergio Comerón (sergiocomeron@icloud.com)
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

global $DB, $CFG, $PAGE;

if ($ADMIN->fulltree) {
    require_once($CFG->dirroot . '/mod/jitsi/lib.php');

    $link = new moodle_url('/mod/jitsi/servermanagement.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/servermanagementlink',
            get_string('servermanagement', 'jitsi'),
            html_writer::link($link, get_string('servermanagementdesc', 'jitsi'))
        )
    );

    if ($DB->get_manager()->table_exists('jitsi_servers')) {
        $servers = $DB->get_records_menu('jitsi_servers', null, 'name ASC', 'id, name');

        if (!empty($servers)) {
            // Si el valor guardado no apunta a un servidor existente, corregirlo al primero disponible.
            $currentserverconfig = get_config('mod_jitsi', 'server');
            if (empty($currentserverconfig) || !array_key_exists($currentserverconfig, $servers)) {
                $firstid = array_key_first($servers);
                set_config('server', $firstid, 'mod_jitsi');
            }

            $settings->add(new admin_setting_configselect(
                'mod_jitsi/server',
                get_string('server', 'jitsi'),
                get_string('serverdesc', 'jitsi'),
                0,
                $servers
            ));
        }
    }

    $linkusagestats = new moodle_url('/mod/jitsi/sessionusagestats.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/sessionusagestats',
            '',
            '<a href=' . $linkusagestats . ' >' . get_string('sessionusagestats', 'jitsi') . '</a>'
            . ' <span class="text-muted small">(' . get_string('sessionusagestatsslow', 'jitsi') . ')</span>'
        )
    );

    $settings->add(new admin_setting_heading('mod_jitsi/config', get_string('config', 'jitsi'), ''));
    $settings->add(
        new admin_setting_confightmleditor(
            'mod_jitsi/help',
            get_string('help', 'jitsi'),
            get_string('helpex', 'jitsi'),
            null
        )
    );
    $options = ['username' => get_string('username', 'jitsi'),
        'nameandsurname' => get_string('nameandsurname', 'jitsi'),
        'alias' => get_string('alias', 'jitsi'),
    ];
    $settings->add(
        new admin_setting_configselect(
            'mod_jitsi/id',
            get_string('identification', 'jitsi'),
            get_string('identificationex', 'jitsi'),
            'username',
            $options,
        )
    );
    $sessionoptions = ['Course Shortname', 'Session ID', 'Session Name'];
    $sessionoptionsdefault = [0, 1, 2];

    $optionsseparator = ['.', '-', '_', 'empty'];
    $settings->add(
        new admin_setting_configselect(
            'mod_jitsi/separator',
            get_string('separator', 'jitsi'),
            get_string('separatorex', 'jitsi'),
            0,
            $optionsseparator,
        ),
    );
    $settings->add(
        new admin_setting_configmultiselect(
            'mod_jitsi/sesionname',
            get_string('sessionnamefields', 'jitsi'),
            get_string('sessionnamefieldsex', 'jitsi'),
            $sessionoptionsdefault,
            $sessionoptions,
        ),
    );
    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/invitebuttons',
            get_string('invitebutton', 'jitsi'),
            get_string('invitebuttonex', 'jitsi'),
            1,
        ),
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/blurbutton',
            get_string('blurbutton', 'jitsi'),
            get_string('blurbuttonex', 'jitsi'),
            1
        )
    );
    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/shareyoutube',
            get_string('youtubebutton', 'jitsi'),
            get_string('youtubebuttonex', 'jitsi'),
            1
        )
    );
    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/finishandreturn',
            get_string('finishandreturn', 'jitsi'),
            get_string('finishandreturnex', 'jitsi'),
            1
        )
    );
    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/deeplink',
            get_string('deeplink', 'jitsi'),
            get_string('deeplinkex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configpasswordunmask(
            'mod_jitsi/password',
            get_string('password', 'jitsi'),
            get_string('passwordex', 'jitsi'),
            ''
        )
    );
    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/securitybutton',
            get_string('securitybutton', 'jitsi'),
            get_string('securitybuttonex', 'jitsi'),
            0
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/showavatars',
            get_string('showavatars', 'jitsi'),
            get_string('showavatarsex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/record',
            get_string('record', 'jitsi'),
            get_string('recordex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/participantspane',
            get_string('participantspane', 'jitsi'),
            get_string('participantspaneex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/raisehand',
            get_string('raisehand', 'jitsi'),
            get_string('raisehandex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/reactions',
            get_string('reactions', 'jitsi'),
            get_string('reactionsex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/chat',
            get_string('chat', 'jitsi'),
            get_string('chatex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/polls',
            get_string('polls', 'jitsi'),
            get_string('pollsex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/whiteboard',
            get_string('whiteboard', 'jitsi'),
            get_string('whiteboardex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/startwithaudiomuted',
            get_string('startwithaudiomuted', 'jitsi'),
            get_string('startwithaudiomutedex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/startwithvideomuted',
            get_string('startwithvideomuted', 'jitsi'),
            get_string('startwithvideomutedex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/channellastcam',
            get_string('simultaneouscameras', 'jitsi'),
            get_string('simultaneouscamerasex', 'jitsi'),
            '15',
            PARAM_INT,
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/allowbreakoutrooms',
            get_string('allowbreakoutrooms', 'jitsi'),
            get_string('allowbreakoutroomsex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/transcription',
            get_string('transcription', 'jitsi'),
            get_string('transcriptionex', 'jitsi'),
            1
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/sendemail',
            get_string('sendemail', 'jitsi'),
            get_string('sendemailex', 'jitsi'),
            0
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/privatesessions',
            get_string('privatesessions', 'jitsi'),
            get_string('privatesessionsex', 'jitsi'),
            0
        )
    );

    $is8x8server = false;
    $currentserverid = get_config('mod_jitsi', 'server');
    if (!empty($currentserverid) && $DB->get_manager()->table_exists('jitsi_servers')) {
        $currentserver = $DB->get_record('jitsi_servers', ['id' => $currentserverid]);
        if ($currentserver && $currentserver->type == 2) {
            $is8x8server = true;
        }
    }

    $dropboxheadingdesc = get_string('dropboxconfigex', 'jitsi');
    if ($is8x8server) {
        $dropboxheadingdesc = '<div class="alert alert-warning mt-2">'
            . get_string('dropboxnotwith8x8', 'jitsi')
            . '</div>' . $dropboxheadingdesc;
    }

    $settings->add(
        new admin_setting_heading(
            'jitsidropbox',
            get_string('dropboxconfig', 'jitsi'),
            $dropboxheadingdesc
        )
    );

    $settings->add(new admin_setting_configtext(
        'mod_jitsi/dropbox_appkey',
        get_string('dropboxappkey', 'jitsi'),
        get_string('dropboxappkeyex', 'jitsi'),
        ''
    ));

    $settings->add(new admin_setting_configtext(
        'mod_jitsi/dropbox_redirect_uri',
        get_string('dropboxredirecturi', 'jitsi'),
        get_string('dropboxredirecturiex', 'jitsi'),
        ''
    ));

    if ($is8x8server) {
        $PAGE->requires->js_init_code('
            (function() {
                var fields = ["s_mod_jitsi_dropbox_appkey", "s_mod_jitsi_dropbox_redirect_uri"];
                fields.forEach(function(name) {
                    var el = document.querySelector("[name=\'" + name + "\']");
                    if (el) {
                        el.disabled = true;
                        el.style.opacity = "0.5";
                        el.style.cursor = "not-allowed";
                    }
                });
            })();
        ');
    }

    $settings->add(
        new admin_setting_heading(
            'jitsistreaming',
            get_string('streamingconfig', 'jitsi'),
            get_string('streamingconfigex', 'jitsi')
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/livebutton',
            get_string('streamingbutton', 'jitsi'),
            get_string('streamingbuttonex', 'jitsi'),
            1
        )
    );

    $streamingoptions = ['0' => get_string('jitsiinterface', 'jitsi'), '1' => get_string('integrated', 'jitsi')];
    $settings->add(
        new admin_setting_configselect(
            'mod_jitsi/streamingoption',
            get_string('streamingoption', 'jitsi'),
            get_string('streamingoptionex', 'jitsi'),
            '0',
            $streamingoptions,
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/oauth_id',
            get_string('oauthid', 'jitsi'),
            get_string('oauthidex', 'jitsi', $CFG->wwwroot . '/mod/jitsi/auth.php'),
            '',
        )
    );

    $settings->add(
        new admin_setting_configpasswordunmask(
            'mod_jitsi/oauth_secret',
            get_string('oauthsecret', 'jitsi'),
            get_string('oauthsecretex', 'jitsi'),
            ''
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/numbervideosdeleted',
            get_string('numbervideosdeleted', 'jitsi'),
            get_string('numbervideosdeletedex', 'jitsi'),
            '1',
            PARAM_INT,
            1
        )
    );

    $settings->add(new admin_setting_configduration(
        'mod_jitsi/videosexpiry',
        new lang_string('videoexpiry', 'jitsi'),
        new lang_string('videoexpiryex', 'jitsi'),
        4 * WEEKSECS,
        WEEKSECS
    ));

    $settings->add(
        new admin_setting_configselect(
            'mod_jitsi/latency',
            get_string('latency', 'jitsi'),
            get_string('latencyex', 'jitsi'),
            '0',
            ['0' => 'Normal', '1' => 'Low', '2' => 'Ultra Low']
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/selfdeclaredmadeforkids',
            get_string('forkids', 'jitsi'),
            get_string('forkidsex', 'jitsi'),
            0
        )
    );

    $link = new moodle_url('/mod/jitsi/adminaccounts.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/loginoutyoutube',
            '',
            '<a href=' . $link . ' >' . get_string('accounts', 'jitsi') . '</a>'
        )
    );

    $link = new moodle_url('/mod/jitsi/adminrecord.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/records_admin',
            '',
            '<a href=' . $link . ' >' . get_string('deletesources', 'jitsi') . '</a>'
        )
    );

    $link = new moodle_url('/mod/jitsi/recordingmatrix.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/records_matrix',
            '',
            '<a href=' . $link . ' >' . get_string('livesessionsnow', 'jitsi') . '</a>'
        )
    );

    $link = new moodle_url('/mod/jitsi/search.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/search',
            '',
            '<a href=' . $link . ' >' . get_string('searchrecords', 'jitsi') . '</a>'
        )
    );

    $link = new moodle_url('/mod/jitsi/stats.php');
    $settings->add(
        new admin_setting_heading(
            'mod_jitsi/stats',
            '',
            '<a href=' . $link . ' >' . get_string('jitsi_recording_statistics', 'jitsi') . '</a>'
        )
    );

    // Google Cloud (GCP) integration for single shared Jitsi server.
    $settings->add(
        new admin_setting_heading(
            'jitsigcp',
            get_string('gcpheading', 'jitsi'),
            get_string('gcpheadingex', 'jitsi')
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/gcp_project',
            get_string('gcpproject', 'jitsi'),
            get_string('gcpprojectex', 'jitsi'),
            ''
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/gcp_zone',
            get_string('gcpzone', 'jitsi'),
            get_string('gcpzoneex', 'jitsi'),
            ''
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/gcp_image',
            get_string('gcpimage', 'jitsi'),
            get_string('gcpimageex', 'jitsi'),
            'projects/debian-cloud/global/images/family/debian-12'
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/gcp_network',
            get_string('gcpnetwork', 'jitsi'),
            get_string('gcpnetworkex', 'jitsi'),
            'global/networks/default'
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/gcp_hostname',
            get_string('gcphostname', 'jitsi'),
            get_string('gcphostnameex', 'jitsi'),
            ''
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/gcp_letsencrypt_email',
            get_string('gcpleemail', 'jitsi'),
            get_string('gcpleemailex', 'jitsi'),
            ''
        )
    );


    $settings->add(
        new admin_setting_configstoredfile(
            'mod_jitsi/gcp_serviceaccount_jsonfile',
            get_string('gcpserviceaccountjsonfile', 'jitsi'),
            get_string('gcpserviceaccountjsonfileex', 'jitsi'),
            'gcpserviceaccountjson',
            0,
            ['maxfiles' => 1, 'accepted_types' => ['.json']]
        )
    );

    // Experimental Section.
    $settings->add(
        new admin_setting_heading(
            'jitsiexperimental',
            get_string('experimental', 'jitsi'),
            get_string('experimentalex', 'jitsi')
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/sharestream',
            get_string('sharestream', 'jitsi'),
            get_string('sharestreamex', 'jitsi'),
            0
        )
    );

    $settings->add(
        new admin_setting_configcheckbox(
            'mod_jitsi/aienabled',
            get_string('aienabled', 'jitsi'),
            get_string('aienabledex', 'jitsi'),
            0
        )
    );

    $settings->add(
        new admin_setting_configtext(
            'mod_jitsi/aiquizquestions',
            get_string('aiquizquestions', 'jitsi'),
            get_string('aiquizquestionsex', 'jitsi'),
            10,
            PARAM_INT
        )
    );

    $settings->add(
        new admin_setting_configselect(
            'mod_jitsi/vertexairegion',
            get_string('vertexairegion', 'jitsi'),
            get_string('vertexairegionex', 'jitsi'),
            'us-central1',
            [
                'us-central1'    => 'us-central1 — Iowa, USA',
                'us-east4'       => 'us-east4 — Virginia, USA',
                'europe-west1'   => 'europe-west1 — Belgium (EU)',
                'europe-west4'   => 'europe-west4 — Netherlands (EU)',
                'europe-west9'   => 'europe-west9 — Paris, France (EU)',
                'asia-northeast1' => 'asia-northeast1 — Tokyo, Japan',
                'asia-southeast1' => 'asia-southeast1 — Singapore',
            ]
        )
    );
}
