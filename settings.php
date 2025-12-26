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

global $DB, $CFG;

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
            $settings->add(new admin_setting_configselect(
                'mod_jitsi/server',
                get_string('server', 'jitsi'),
                get_string('serverdesc', 'jitsi'),
                0,
                $servers
            ));
        }
    }

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
            'mod_jitsi/whiteboard',
            get_string('whiteboard', 'jitsi'),
            get_string('whiteboardex', 'jitsi'),
            1
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
        new admin_setting_configcheckbox(
            'mod_jitsi/allowbreakoutrooms',
            get_string('allowbreakoutrooms', 'jitsi'),
            get_string('allowbreakoutroomsex', 'jitsi'),
            1
        )
    );

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
            'mod_jitsi/gcp_machine_type',
            get_string('gcpmachinetype', 'jitsi'),
            get_string('gcpmachinetypeex', 'jitsi'),
            'e2-standard-4'
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
            'mod_jitsi/privatesessions',
            get_string('privatesessions', 'jitsi'),
            get_string('privatesessionsex', 'jitsi'),
            0
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
}
