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

namespace mod_jitsi;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->dirroot . '/mod/jitsi/lib.php');

/**
 * Unit tests for mod_jitsi lib.php
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class lib_test extends \advanced_testcase {

    // -------------------------------------------------------------------------
    // normalizesessionname() — pure unit tests, no DB needed
    // -------------------------------------------------------------------------

    /**
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_removes_spaces(): void {
        $this->assertEquals('HelloWorld', normalizesessionname('Hello World'));
    }

    /**
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_removes_special_chars(): void {
        $this->assertEquals('roomname', normalizesessionname('room@name!'));
    }

    /**
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_keeps_hyphens_and_underscores(): void {
        $this->assertEquals('Test-Session_1', normalizesessionname('Test-Session_1'));
    }

    /**
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_removes_accents(): void {
        // Accented characters are not in [a-zA-Z0-9\-_] so they get stripped.
        $this->assertEquals('caf', normalizesessionname('café'));
    }

    /**
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_alphanumeric_unchanged(): void {
        $this->assertEquals('Room123', normalizesessionname('Room123'));
    }

    // -------------------------------------------------------------------------
    // createsession() — regression test for issue #138
    // Type 0 server (no JWT): roomName must appear in the JS output.
    // -------------------------------------------------------------------------

    /**
     * Regression test for issue #138.
     * On a type-0 server (public/no JWT), createsession() must emit
     * `roomName: "..."` so users join the correct room instead of landing
     * on the Jitsi homepage.
     *
     * @covers ::createsession
     */
    public function test_type0_server_sets_roomname_in_output(): void {
        global $DB, $PAGE;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        // Minimal admin config values consumed by createsession().
        set_config('livebutton', '0', 'mod_jitsi');
        set_config('shareyoutube', '0', 'mod_jitsi');
        set_config('blurbutton', '0', 'mod_jitsi');
        set_config('securitybutton', '0', 'mod_jitsi');
        set_config('record', '0', 'mod_jitsi');
        set_config('participantspane', '0', 'mod_jitsi');
        set_config('raisehand', '0', 'mod_jitsi');
        set_config('whiteboard', '0', 'mod_jitsi');
        set_config('allowbreakoutrooms', '0', 'mod_jitsi');
        set_config('startwithaudiomuted', '0', 'mod_jitsi');
        set_config('startwithvideomuted', '0', 'mod_jitsi');
        set_config('reactions', '1', 'mod_jitsi');
        set_config('chat', '1', 'mod_jitsi');
        set_config('polls', '1', 'mod_jitsi');
        set_config('transcription', '1', 'mod_jitsi');
        set_config('channellastcam', '-1', 'mod_jitsi');
        set_config('tokentype', '0', 'mod_jitsi');
        set_config('dropbox_appkey', '', 'mod_jitsi');

        // Create a type-0 server (public Jitsi, no JWT).
        $server = (object)[
            'name'               => 'Public server',
            'type'               => 0,
            'domain'             => 'meet.jit.si',
            'appid'              => '',
            'secret'             => '',
            'eightbyeightappid'  => '',
            'eightbyeightapikeyid' => '',
            'privatekey'         => '',
            'gcpproject'         => '',
            'gcpzone'            => '',
            'gcpinstancename'    => '',
            'gcpstaticipname'    => '',
            'gcpstaticipaddress' => '',
            'provisioningstatus' => '',
            'provisioningtoken'  => '',
            'provisioningerror'  => '',
            'timecreated'        => time(),
            'timemodified'       => time(),
        ];
        $serverid = $DB->insert_record('jitsi_servers', $server);
        set_config('server', $serverid, 'mod_jitsi');

        // Create course + activity + enrol admin.
        $course = $this->getDataGenerator()->create_course();
        $jitsirecord = $this->getDataGenerator()->create_module('jitsi', [
            'course'          => $course->id,
            'name'            => 'Test session',
            'sessionwithtoken' => 0,
            'token'           => sha1(uniqid('', true)),
            'tokeninterno'    => sha1(uniqid('', true)),
            'tokeninvitacion' => '',
        ]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsirecord->id, $course->id);

        $PAGE->set_url('/mod/jitsi/view.php', ['id' => $cm->id]);
        $PAGE->set_context(\context_module::instance($cm->id));

        // Capture all output from createsession().
        ob_start();
        createsession(
            0,                   // $teacher (student)
            $cm->id,             // $cmid
            'https://example.com/avatar.png', // $avatar
            'Test User',         // $nombre
            'TestRoom-1',        // $session
            'test@example.com',  // $mail
            $jitsirecord         // $jitsi object
        );
        $output = ob_get_clean();

        // The critical assertion: roomName must be present in the JS output.
        $this->assertStringContainsString(
            'roomName:',
            $output,
            'createsession() must emit roomName for type-0 servers (regression #138)'
        );

        // Also verify the actual room value is the normalised session name.
        $this->assertStringContainsString(
            'TestRoom-1',
            $output,
            'roomName must contain the normalised session name'
        );

        // Verify no JWT token is generated for type-0 servers.
        $this->assertStringNotContainsString(
            'jwt:',
            $output,
            'Type-0 servers must not generate a JWT token'
        );
    }
}
