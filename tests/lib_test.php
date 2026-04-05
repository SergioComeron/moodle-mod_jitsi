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
final class lib_test extends \advanced_testcase {
    /**
     * Test that spaces are removed from session names.
     *
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_removes_spaces(): void {
        $this->assertEquals('HelloWorld', normalizesessionname('Hello World'));
    }

    /**
     * Test that special characters are removed from session names.
     *
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_removes_special_chars(): void {
        $this->assertEquals('roomname', normalizesessionname('room@name!'));
    }

    /**
     * Test that hyphens and underscores are preserved in session names.
     *
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_keeps_hyphens_and_underscores(): void {
        $this->assertEquals('Test-Session_1', normalizesessionname('Test-Session_1'));
    }

    /**
     * Test that accented characters are removed from session names.
     *
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_removes_accents(): void {
        $this->assertEquals('caf', normalizesessionname('café'));
    }

    /**
     * Test that alphanumeric session names are returned unchanged.
     *
     * @covers ::normalizesessionname
     */
    public function test_normalizesessionname_alphanumeric_unchanged(): void {
        $this->assertEquals('Room123', normalizesessionname('Room123'));
    }

    /**
     * Test that jitsi_add_instance inserts a record and returns its ID.
     *
     * @covers ::jitsi_add_instance
     */
    public function test_add_instance_creates_record(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $this->assertNotEmpty($jitsi->id);
        $this->assertTrue($DB->record_exists('jitsi', ['id' => $jitsi->id]));
    }

    /**
     * Test that jitsi_update_instance updates the record in the database.
     *
     * @covers ::jitsi_update_instance
     */
    public function test_update_instance_modifies_record(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id, 'name' => 'Original']);

        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id);
        $update = $DB->get_record('jitsi', ['id' => $jitsi->id]);
        $update->name = 'Updated';
        $update->instance = $jitsi->id;
        $update->coursemodule = $cm->id;

        $result = jitsi_update_instance($update);

        $this->assertTrue((bool)$result);
        $this->assertEquals('Updated', $DB->get_field('jitsi', 'name', ['id' => $jitsi->id]));
    }

    /**
     * Test that jitsi_delete_instance removes the record from the database.
     *
     * @covers ::jitsi_delete_instance
     */
    public function test_delete_instance_removes_record(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $this->assertTrue($DB->record_exists('jitsi', ['id' => $jitsi->id]));

        $result = jitsi_delete_instance($jitsi->id);

        $this->assertTrue($result);
        $this->assertFalse($DB->record_exists('jitsi', ['id' => $jitsi->id]));
    }

    /**
     * Test that jitsi_delete_instance returns false for a non-existent ID.
     *
     * @covers ::jitsi_delete_instance
     */
    public function test_delete_instance_returns_false_for_nonexistent(): void {
        $this->resetAfterTest(true);

        $result = jitsi_delete_instance(999999);

        $this->assertFalse($result);
    }

    /**
     * Test that jitsi_delete_instance also removes associated records.
     *
     * @covers ::jitsi_delete_instance
     */
    public function test_delete_instance_removes_associated_records(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $DB->insert_record('jitsi_record', [
            'jitsi'       => $jitsi->id,
            'name'        => 'Test recording',
            'source'      => 0,
            'timecreated' => time(),
            'deleted'     => 0,
            'visible'     => 1,
        ]);

        $this->assertTrue($DB->record_exists('jitsi_record', ['jitsi' => $jitsi->id]));

        jitsi_delete_instance($jitsi->id);

        $this->assertFalse($DB->record_exists('jitsi_record', ['jitsi' => $jitsi->id]));
    }

    /**
     * Test that jitsi_add_instance sets timecreated.
     *
     * @covers ::jitsi_add_instance
     */
    public function test_add_instance_sets_timecreated(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $before = time();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $after = time();

        $record = $DB->get_record('jitsi', ['id' => $jitsi->id]);
        $this->assertGreaterThanOrEqual($before, $record->timecreated);
        $this->assertLessThanOrEqual($after, $record->timecreated);
    }

    /**
     * Test that jitsi_add_instance stores the correct course ID.
     *
     * @covers ::jitsi_add_instance
     */
    public function test_add_instance_stores_correct_course(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $record = $DB->get_record('jitsi', ['id' => $jitsi->id]);
        $this->assertEquals($course->id, $record->course);
    }

    /**
     * Test that jitsi_update_instance sets timemodified.
     *
     * @covers ::jitsi_update_instance
     */
    public function test_update_instance_sets_timemodified(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id);

        $before = time();
        $update = $DB->get_record('jitsi', ['id' => $jitsi->id]);
        $update->instance = $jitsi->id;
        $update->coursemodule = $cm->id;
        jitsi_update_instance($update);
        $after = time();

        $record = $DB->get_record('jitsi', ['id' => $jitsi->id]);
        $this->assertGreaterThanOrEqual($before, $record->timemodified);
        $this->assertLessThanOrEqual($after, $record->timemodified);
    }

    /**
     * Test that deleting an instance with multiple recordings removes all of them.
     *
     * @covers ::jitsi_delete_instance
     */
    public function test_delete_instance_removes_multiple_recordings(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        for ($i = 0; $i < 3; $i++) {
            $DB->insert_record('jitsi_record', [
                'jitsi'       => $jitsi->id,
                'name'        => 'Recording ' . $i,
                'source'      => 0,
                'timecreated' => time(),
                'deleted'     => 0,
                'visible'     => 1,
            ]);
        }

        $this->assertEquals(3, $DB->count_records('jitsi_record', ['jitsi' => $jitsi->id]));

        jitsi_delete_instance($jitsi->id);

        $this->assertEquals(0, $DB->count_records('jitsi_record', ['jitsi' => $jitsi->id]));
    }

    /**
     * Test that two instances in the same course are independent.
     *
     * @covers ::jitsi_add_instance
     */
    public function test_two_instances_in_same_course_are_independent(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi1 = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id, 'name' => 'Session A']);
        $jitsi2 = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id, 'name' => 'Session B']);

        $this->assertNotEquals($jitsi1->id, $jitsi2->id);
        $this->assertEquals(2, $DB->count_records('jitsi', ['course' => $course->id]));

        jitsi_delete_instance($jitsi1->id);

        $this->assertFalse($DB->record_exists('jitsi', ['id' => $jitsi1->id]));
        $this->assertTrue($DB->record_exists('jitsi', ['id' => $jitsi2->id]));
    }

    /**
     * Regression test for issue #138.
     *
     * On a type-0 server (public/no JWT), createsession() must emit
     * roomName so users join the correct room instead of landing
     * on the Jitsi homepage.
     *
     * @covers ::createsession
     */
    public function test_type0_server_sets_roomname_in_output(): void {
        global $DB, $PAGE;

        $this->resetAfterTest(true);
        $this->setAdminUser();

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

        $server = (object)[
            'name'                => 'Public server',
            'type'                => 0,
            'domain'              => 'meet.jit.si',
            'appid'               => '',
            'secret'              => '',
            'eightbyeightappid'   => '',
            'eightbyeightapikeyid' => '',
            'privatekey'          => '',
            'gcpproject'          => '',
            'gcpzone'             => '',
            'gcpinstancename'     => '',
            'gcpstaticipname'     => '',
            'gcpstaticipaddress'  => '',
            'provisioningstatus'  => '',
            'provisioningtoken'   => '',
            'provisioningerror'   => '',
            'timecreated'         => time(),
            'timemodified'        => time(),
        ];
        $serverid = $DB->insert_record('jitsi_servers', $server);
        set_config('server', $serverid, 'mod_jitsi');

        $course = $this->getDataGenerator()->create_course();
        $jitsirecord = $this->getDataGenerator()->create_module('jitsi', [
            'course'           => $course->id,
            'name'             => 'Test session',
            'sessionwithtoken' => 0,
            'token'            => sha1(uniqid('', true)),
            'tokeninterno'     => sha1(uniqid('', true)),
            'tokeninvitacion'  => '',
        ]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsirecord->id, $course->id);

        $PAGE->set_url('/mod/jitsi/view.php', ['id' => $cm->id]);
        $PAGE->set_cm($cm);
        $PAGE->set_context(\context_module::instance($cm->id));

        ob_start();
        createsession(
            0,
            $cm->id,
            'https://example.com/avatar.png',
            'Test User',
            'TestRoom-1',
            'test@example.com',
            $jitsirecord
        );
        $output = ob_get_clean();

        $this->assertStringContainsString(
            'roomName:',
            $output,
            'createsession() must emit roomName for type-0 servers (regression #138)'
        );

        $this->assertStringContainsString(
            'TestRoom-1',
            $output,
            'roomName must contain the normalised session name'
        );

        $this->assertStringNotContainsString(
            'jwt:',
            $output,
            'Type-0 servers must not generate a JWT token'
        );
    }
}
