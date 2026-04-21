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
 * Unit tests for mod_jitsi external functions (push subscriptions, tutoring schedule, incoming call).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @runTestsInSeparateProcesses
 */
final class external_test extends \advanced_testcase {
    /**
     * Load the external API class (requires isolated process due to externallib.php).
     */
    protected function setUp(): void {
        global $CFG;
        parent::setUp();
        require_once($CFG->dirroot . '/mod/jitsi/classes/external.php');
    }

    // Push subscription tests.

    /**
     * Test that register_push_subscription creates a new record.
     *
     * @covers \mod_jitsi_external::register_push_subscription
     */
    public function test_register_push_subscription_creates_record(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $endpoint  = 'https://push.example.com/sub/abc123';
        $authkey   = 'dGVzdGF1dGhrZXk';
        $p256dhkey = 'dGVzdHAyNTZkaGtleQ';

        $result = \mod_jitsi_external::register_push_subscription($endpoint, $authkey, $p256dhkey);

        $this->assertTrue($result['success']);
        $this->assertTrue($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user->id]));
        $record = $DB->get_record_sql(
            'SELECT * FROM {jitsi_push_subscriptions} WHERE userid = :uid',
            ['uid' => $user->id]
        );
        $this->assertEquals($authkey, $record->authkey);
        $this->assertEquals($p256dhkey, $record->p256dhkey);
    }

    /**
     * Test that registering the same endpoint twice updates the existing record.
     *
     * @covers \mod_jitsi_external::register_push_subscription
     */
    public function test_register_push_subscription_updates_existing(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $endpoint = 'https://push.example.com/sub/abc123';

        \mod_jitsi_external::register_push_subscription($endpoint, 'oldauth', 'oldp256');
        \mod_jitsi_external::register_push_subscription($endpoint, 'newauth', 'newp256');

        $count = $DB->count_records('jitsi_push_subscriptions', ['userid' => $user->id]);
        $this->assertEquals(1, $count);

        $record = $DB->get_record_sql(
            'SELECT * FROM {jitsi_push_subscriptions} WHERE userid = :uid',
            ['uid' => $user->id]
        );
        $this->assertEquals('newauth', $record->authkey);
        $this->assertEquals('newp256', $record->p256dhkey);
    }

    /**
     * Test that unregister_push_subscription removes the record.
     *
     * @covers \mod_jitsi_external::unregister_push_subscription
     */
    public function test_unregister_push_subscription_removes_record(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $endpoint = 'https://push.example.com/sub/abc123';
        \mod_jitsi_external::register_push_subscription($endpoint, 'auth', 'p256');

        $this->assertTrue($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user->id]));

        $result = \mod_jitsi_external::unregister_push_subscription($endpoint);

        $this->assertTrue($result['success']);
        $this->assertFalse($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user->id]));
    }

    /**
     * Test that unregister_push_subscription only removes the current user's record.
     *
     * @covers \mod_jitsi_external::unregister_push_subscription
     */
    public function test_unregister_push_subscription_does_not_affect_other_users(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user1 = $this->getDataGenerator()->create_user();
        $user2 = $this->getDataGenerator()->create_user();
        $endpoint = 'https://push.example.com/sub/shared';

        // Register for both users (same endpoint, different user records).
        $now = time();
        $DB->insert_record('jitsi_push_subscriptions', [
            'userid'       => $user1->id,
            'endpoint'     => $endpoint,
            'authkey'      => 'auth1',
            'p256dhkey'    => 'p256_1',
            'timecreated'  => $now,
            'timemodified' => $now,
        ]);
        $DB->insert_record('jitsi_push_subscriptions', [
            'userid'       => $user2->id,
            'endpoint'     => $endpoint,
            'authkey'      => 'auth2',
            'p256dhkey'    => 'p256_2',
            'timecreated'  => $now,
            'timemodified' => $now,
        ]);

        // Unregister as user1.
        $this->setUser($user1);
        \mod_jitsi_external::unregister_push_subscription($endpoint);

        $this->assertFalse($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user1->id]));
        $this->assertTrue($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user2->id]));
    }

    /**
     * Test that a user can have multiple subscriptions (different endpoints).
     *
     * @covers \mod_jitsi_external::register_push_subscription
     */
    public function test_register_push_subscription_multiple_endpoints(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        \mod_jitsi_external::register_push_subscription('https://push.example.com/a', 'auth1', 'p256_1');
        \mod_jitsi_external::register_push_subscription('https://push.example.com/b', 'auth2', 'p256_2');

        $this->assertEquals(2, $DB->count_records('jitsi_push_subscriptions', ['userid' => $user->id]));
    }

    // Incoming call tests.

    /**
     * Test that check_incoming_call returns incoming=false when no log entries exist.
     *
     * @covers \mod_jitsi_external::check_incoming_call
     */
    public function test_check_incoming_call_no_call(): void {
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $result = \mod_jitsi_external::check_incoming_call(time() - 60);

        $this->assertFalse($result['incoming']);
        $this->assertEquals(0, $result['callerid']);
    }

    /**
     * Test that check_incoming_call detects a matching log entry.
     *
     * @covers \mod_jitsi_external::check_incoming_call
     */
    public function test_check_incoming_call_detects_call(): void {
        global $DB;
        $this->resetAfterTest(true);

        $callee = $this->getDataGenerator()->create_user();
        $caller = $this->getDataGenerator()->create_user();

        $this->setUser($callee);

        $since = time() - 30;

        // Insert a fake logstore entry: caller entered callee's session.
        $DB->insert_record('logstore_standard_log', [
            'eventname'   => '\mod_jitsi\event\jitsi_private_session_enter',
            'component'   => 'mod_jitsi',
            'action'      => 'enter',
            'target'      => 'jitsi_private_session',
            'objecttable' => '',
            'objectid'    => 0,
            'crud'        => 'r',
            'edulevel'    => 0,
            'contextid'   => \context_system::instance()->id,
            'contextlevel' => CONTEXT_SYSTEM,
            'contextinstanceid' => 0,
            'userid'      => $caller->id,
            'courseid'    => 0,
            'relateduserid' => 0,
            'anonymous'   => 0,
            'other'       => json_encode(['peerid' => $callee->id]),
            'timecreated' => time(),
            'origin'      => 'web',
            'ip'          => '127.0.0.1',
            'realuserid'  => $caller->id,
        ]);

        $result = \mod_jitsi_external::check_incoming_call($since);

        $this->assertTrue($result['incoming']);
        $this->assertEquals($caller->id, $result['callerid']);
        $this->assertNotEmpty($result['callername']);
    }

    /**
     * Test that check_incoming_call ignores entries before the 'since' timestamp.
     *
     * @covers \mod_jitsi_external::check_incoming_call
     */
    public function test_check_incoming_call_ignores_old_entries(): void {
        global $DB;
        $this->resetAfterTest(true);

        $callee = $this->getDataGenerator()->create_user();
        $caller = $this->getDataGenerator()->create_user();

        $this->setUser($callee);

        // Insert an old log entry.
        $DB->insert_record('logstore_standard_log', [
            'eventname'   => '\mod_jitsi\event\jitsi_private_session_enter',
            'component'   => 'mod_jitsi',
            'action'      => 'enter',
            'target'      => 'jitsi_private_session',
            'objecttable' => '',
            'objectid'    => 0,
            'crud'        => 'r',
            'edulevel'    => 0,
            'contextid'   => \context_system::instance()->id,
            'contextlevel' => CONTEXT_SYSTEM,
            'contextinstanceid' => 0,
            'userid'      => $caller->id,
            'courseid'    => 0,
            'relateduserid' => 0,
            'anonymous'   => 0,
            'other'       => json_encode(['peerid' => $callee->id]),
            'timecreated' => time() - 3600, // 1 hour ago.
            'origin'      => 'web',
            'ip'          => '127.0.0.1',
            'realuserid'  => $caller->id,
        ]);

        // Poll from 30 seconds ago — should not find the old entry.
        $result = \mod_jitsi_external::check_incoming_call(time() - 30);

        $this->assertFalse($result['incoming']);
    }

    /**
     * Test that check_incoming_call ignores entries where peerid does not match.
     *
     * @covers \mod_jitsi_external::check_incoming_call
     */
    public function test_check_incoming_call_ignores_wrong_peer(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user    = $this->getDataGenerator()->create_user();
        $caller  = $this->getDataGenerator()->create_user();
        $someone = $this->getDataGenerator()->create_user();

        $this->setUser($user);

        // Caller entered someone else's session, not $user's.
        $DB->insert_record('logstore_standard_log', [
            'eventname'   => '\mod_jitsi\event\jitsi_private_session_enter',
            'component'   => 'mod_jitsi',
            'action'      => 'enter',
            'target'      => 'jitsi_private_session',
            'objecttable' => '',
            'objectid'    => 0,
            'crud'        => 'r',
            'edulevel'    => 0,
            'contextid'   => \context_system::instance()->id,
            'contextlevel' => CONTEXT_SYSTEM,
            'contextinstanceid' => 0,
            'userid'      => $caller->id,
            'courseid'    => 0,
            'relateduserid' => 0,
            'anonymous'   => 0,
            'other'       => json_encode(['peerid' => $someone->id]),
            'timecreated' => time(),
            'origin'      => 'web',
            'ip'          => '127.0.0.1',
            'realuserid'  => $caller->id,
        ]);

        $result = \mod_jitsi_external::check_incoming_call(time() - 60);

        $this->assertFalse($result['incoming']);
    }

    // Tutoring schedule tests.

    /**
     * Test that get_tutoring_schedule returns empty when user has no slots.
     *
     * @covers \mod_jitsi_external::get_tutoring_schedule
     */
    public function test_get_tutoring_schedule_empty(): void {
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $result = \mod_jitsi_external::get_tutoring_schedule();

        $this->assertIsArray($result['courses']);
        $this->assertEmpty($result['courses']);
    }

    /**
     * Test that save_tutoring_slot inserts a record for a teacher in a visible course.
     *
     * @covers \mod_jitsi_external::save_tutoring_slot
     */
    public function test_save_tutoring_slot_creates_record(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $result = \mod_jitsi_external::save_tutoring_slot($course->id, 1, '09:00', '11:00');

        $this->assertArrayHasKey('id', $result);
        $this->assertGreaterThan(0, $result['id']);

        $record = $DB->get_record('jitsi_tutoring_schedule', ['id' => $result['id']]);
        $this->assertEquals($teacher->id, $record->userid);
        $this->assertEquals($course->id, $record->courseid);
        $this->assertEquals(1, $record->weekday);
        $this->assertEquals(9 * 3600, $record->timestart);
        $this->assertEquals(11 * 3600, $record->timeend);
    }

    /**
     * Test that save_tutoring_slot throws when end time is before start time.
     *
     * @covers \mod_jitsi_external::save_tutoring_slot
     */
    public function test_save_tutoring_slot_rejects_invalid_time_range(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $this->expectException(\moodle_exception::class);
        \mod_jitsi_external::save_tutoring_slot($course->id, 1, '11:00', '09:00');
    }

    /**
     * Test that save_tutoring_slot throws when user lacks teacher capability.
     *
     * @covers \mod_jitsi_external::save_tutoring_slot
     */
    public function test_save_tutoring_slot_requires_teacher_capability(): void {
        $this->resetAfterTest(true);

        $student = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');
        $this->setUser($student);

        $this->expectException(\moodle_exception::class);
        \mod_jitsi_external::save_tutoring_slot($course->id, 1, '09:00', '11:00');
    }

    /**
     * Test that get_tutoring_schedule returns slots grouped by course after inserting some.
     *
     * @covers \mod_jitsi_external::get_tutoring_schedule
     */
    public function test_get_tutoring_schedule_returns_slots(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        \mod_jitsi_external::save_tutoring_slot($course->id, 1, '09:00', '11:00');
        \mod_jitsi_external::save_tutoring_slot($course->id, 3, '14:00', '16:00');

        $result = \mod_jitsi_external::get_tutoring_schedule();

        $this->assertCount(1, $result['courses']);
        $this->assertEquals($course->id, $result['courses'][0]['courseid']);
        $this->assertCount(2, $result['courses'][0]['slots']);

        $first = $result['courses'][0]['slots'][0];
        $this->assertEquals(1, $first['weekday']);
        $this->assertEquals('09:00', $first['timestart']);
        $this->assertEquals('11:00', $first['timeend']);
    }

    /**
     * Test that delete_tutoring_slot removes the record when called by its owner.
     *
     * @covers \mod_jitsi_external::delete_tutoring_slot
     */
    public function test_delete_tutoring_slot_owner_can_delete(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $saveresult = \mod_jitsi_external::save_tutoring_slot($course->id, 2, '10:00', '12:00');
        $slotid = $saveresult['id'];

        $this->assertTrue($DB->record_exists('jitsi_tutoring_schedule', ['id' => $slotid]));

        $result = \mod_jitsi_external::delete_tutoring_slot($slotid);

        $this->assertTrue($result['success']);
        $this->assertFalse($DB->record_exists('jitsi_tutoring_schedule', ['id' => $slotid]));
    }

    /**
     * Test that delete_tutoring_slot throws when called by a different user.
     *
     * @covers \mod_jitsi_external::delete_tutoring_slot
     */
    public function test_delete_tutoring_slot_non_owner_cannot_delete(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $other   = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');

        // Create slot as teacher.
        $this->setUser($teacher);
        $saveresult = \mod_jitsi_external::save_tutoring_slot($course->id, 2, '10:00', '12:00');
        $slotid = $saveresult['id'];

        // Try to delete as another user.
        $this->setUser($other);
        $this->expectException(\moodle_exception::class);
        \mod_jitsi_external::delete_tutoring_slot($slotid);
    }

    /**
     * Test that save_tutoring_slot with equal start and end times throws.
     *
     * @covers \mod_jitsi_external::save_tutoring_slot
     */
    public function test_save_tutoring_slot_rejects_equal_times(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $this->expectException(\moodle_exception::class);
        \mod_jitsi_external::save_tutoring_slot($course->id, 1, '10:00', '10:00');
    }
}
