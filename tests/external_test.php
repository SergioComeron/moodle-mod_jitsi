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
     * @covers \mod_jitsi\external\register_push_subscription::execute
     */
    public function test_register_push_subscription_creates_record(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $endpoint  = 'https://push.example.com/sub/abc123';
        $authkey   = 'dGVzdGF1dGhrZXk';
        $p256dhkey = 'dGVzdHAyNTZkaGtleQ';

        $result = \mod_jitsi\external\register_push_subscription::execute($endpoint, $authkey, $p256dhkey);

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
     * @covers \mod_jitsi\external\register_push_subscription::execute
     */
    public function test_register_push_subscription_updates_existing(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $endpoint = 'https://push.example.com/sub/abc123';

        \mod_jitsi\external\register_push_subscription::execute($endpoint, 'oldauth', 'oldp256');
        \mod_jitsi\external\register_push_subscription::execute($endpoint, 'newauth', 'newp256');

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
     * @covers \mod_jitsi\external\unregister_push_subscription::execute
     */
    public function test_unregister_push_subscription_removes_record(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $endpoint = 'https://push.example.com/sub/abc123';
        \mod_jitsi\external\register_push_subscription::execute($endpoint, 'auth', 'p256');

        $this->assertTrue($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user->id]));

        $result = \mod_jitsi\external\unregister_push_subscription::execute($endpoint);

        $this->assertTrue($result['success']);
        $this->assertFalse($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user->id]));
    }

    /**
     * Test that unregister_push_subscription only removes the current user's record.
     *
     * @covers \mod_jitsi\external\unregister_push_subscription::execute
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
        \mod_jitsi\external\unregister_push_subscription::execute($endpoint);

        $this->assertFalse($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user1->id]));
        $this->assertTrue($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user2->id]));
    }

    /**
     * Test that a user can have multiple subscriptions (different endpoints).
     *
     * @covers \mod_jitsi\external\register_push_subscription::execute
     */
    public function test_register_push_subscription_multiple_endpoints(): void {
        global $DB;
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        \mod_jitsi\external\register_push_subscription::execute('https://push.example.com/a', 'auth1', 'p256_1');
        \mod_jitsi\external\register_push_subscription::execute('https://push.example.com/b', 'auth2', 'p256_2');

        $this->assertEquals(2, $DB->count_records('jitsi_push_subscriptions', ['userid' => $user->id]));
    }

    // Incoming call tests.

    /**
     * Test that check_incoming_call returns incoming=false when no log entries exist.
     *
     * @covers \mod_jitsi\external\check_incoming_call::execute
     */
    public function test_check_incoming_call_no_call(): void {
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $result = \mod_jitsi\external\check_incoming_call::execute(time() - 60);

        $this->assertFalse($result['incoming']);
        $this->assertEquals(0, $result['callerid']);
    }

    /**
     * Test that check_incoming_call detects a matching log entry.
     *
     * @covers \mod_jitsi\external\check_incoming_call::execute
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

        $result = \mod_jitsi\external\check_incoming_call::execute($since);

        $this->assertTrue($result['incoming']);
        $this->assertEquals($caller->id, $result['callerid']);
        $this->assertNotEmpty($result['callername']);
    }

    /**
     * Test that check_incoming_call ignores entries before the 'since' timestamp.
     *
     * @covers \mod_jitsi\external\check_incoming_call::execute
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
        $result = \mod_jitsi\external\check_incoming_call::execute(time() - 30);

        $this->assertFalse($result['incoming']);
    }

    /**
     * Test that check_incoming_call ignores entries where peerid does not match.
     *
     * @covers \mod_jitsi\external\check_incoming_call::execute
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

        $result = \mod_jitsi\external\check_incoming_call::execute(time() - 60);

        $this->assertFalse($result['incoming']);
    }

    // Tutoring schedule tests.

    /**
     * Test that get_tutoring_schedule returns empty when user has no slots.
     *
     * @covers \mod_jitsi\external\get_tutoring_schedule::execute
     */
    public function test_get_tutoring_schedule_empty(): void {
        $this->resetAfterTest(true);

        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);

        $result = \mod_jitsi\external\get_tutoring_schedule::execute();

        $this->assertIsArray($result['courses']);
        $this->assertEmpty($result['courses']);
    }

    /**
     * Test that save_tutoring_slot inserts a record for a teacher in a visible course.
     *
     * @covers \mod_jitsi\external\save_tutoring_slot::execute
     */
    public function test_save_tutoring_slot_creates_record(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $result = \mod_jitsi\external\save_tutoring_slot::execute($course->id, 1, '09:00', '11:00');

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
     * @covers \mod_jitsi\external\save_tutoring_slot::execute
     */
    public function test_save_tutoring_slot_rejects_invalid_time_range(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $this->expectException(\moodle_exception::class);
        \mod_jitsi\external\save_tutoring_slot::execute($course->id, 1, '11:00', '09:00');
    }

    /**
     * Test that save_tutoring_slot throws when user lacks teacher capability.
     *
     * @covers \mod_jitsi\external\save_tutoring_slot::execute
     */
    public function test_save_tutoring_slot_requires_teacher_capability(): void {
        $this->resetAfterTest(true);

        $student = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');
        $this->setUser($student);

        $this->expectException(\moodle_exception::class);
        \mod_jitsi\external\save_tutoring_slot::execute($course->id, 1, '09:00', '11:00');
    }

    /**
     * Test that get_tutoring_schedule returns slots grouped by course after inserting some.
     *
     * @covers \mod_jitsi\external\get_tutoring_schedule::execute
     */
    public function test_get_tutoring_schedule_returns_slots(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        \mod_jitsi\external\save_tutoring_slot::execute($course->id, 1, '09:00', '11:00');
        \mod_jitsi\external\save_tutoring_slot::execute($course->id, 3, '14:00', '16:00');

        $result = \mod_jitsi\external\get_tutoring_schedule::execute();

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
     * @covers \mod_jitsi\external\delete_tutoring_slot::execute
     */
    public function test_delete_tutoring_slot_owner_can_delete(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $saveresult = \mod_jitsi\external\save_tutoring_slot::execute($course->id, 2, '10:00', '12:00');
        $slotid = $saveresult['id'];

        $this->assertTrue($DB->record_exists('jitsi_tutoring_schedule', ['id' => $slotid]));

        $result = \mod_jitsi\external\delete_tutoring_slot::execute($slotid);

        $this->assertTrue($result['success']);
        $this->assertFalse($DB->record_exists('jitsi_tutoring_schedule', ['id' => $slotid]));
    }

    /**
     * Test that delete_tutoring_slot throws when called by a different user.
     *
     * @covers \mod_jitsi\external\delete_tutoring_slot::execute
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
        $saveresult = \mod_jitsi\external\save_tutoring_slot::execute($course->id, 2, '10:00', '12:00');
        $slotid = $saveresult['id'];

        // Try to delete as another user.
        $this->setUser($other);
        $this->expectException(\moodle_exception::class);
        \mod_jitsi\external\delete_tutoring_slot::execute($slotid);
    }

    /**
     * Test that save_tutoring_slot with equal start and end times throws.
     *
     * @covers \mod_jitsi\external\save_tutoring_slot::execute
     */
    public function test_save_tutoring_slot_rejects_equal_times(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $course  = $this->getDataGenerator()->create_course(['visible' => 1]);
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->setUser($teacher);

        $this->expectException(\moodle_exception::class);
        \mod_jitsi\external\save_tutoring_slot::execute($course->id, 1, '10:00', '10:00');
    }

    // Audit button tests.

    /**
     * Create a course with a jitsi activity and return [jitsi instance, cm].
     *
     * @return array
     */
    protected function create_jitsi_activity(): array {
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, 0, false, MUST_EXIST);
        return [$jitsi, $cm];
    }

    /**
     * Test that press_button_cam triggers the cam event.
     *
     * @covers \mod_jitsi\external\press_button_cam::execute
     */
    public function test_press_button_cam_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\press_button_cam::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_press_button_cam::class, $events[0]);
        $this->assertEquals($jitsi->id, $events[0]->objectid);
    }

    /**
     * Test that press_button_desktop triggers the desktop event.
     *
     * @covers \mod_jitsi\external\press_button_desktop::execute
     */
    public function test_press_button_desktop_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\press_button_desktop::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_press_button_desktop::class, $events[0]);
    }

    /**
     * Test that press_button_microphone triggers the microphone event.
     *
     * @covers \mod_jitsi\external\press_button_microphone::execute
     */
    public function test_press_button_microphone_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\press_button_microphone::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_press_button_microphone::class, $events[0]);
    }

    /**
     * Test that press_button_end triggers the end event.
     *
     * @covers \mod_jitsi\external\press_button_end::execute
     */
    public function test_press_button_end_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\press_button_end::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_press_button_end::class, $events[0]);
    }

    /**
     * Test that press_record_button triggers the record event.
     *
     * @covers \mod_jitsi\external\press_record_button::execute
     */
    public function test_press_record_button_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\press_record_button::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_press_record_button::class, $events[0]);
    }

    // Presence tests.

    /**
     * Test that presence_join creates a presence record and returns the count.
     *
     * @covers \mod_jitsi\external\presence_join::execute
     */
    public function test_presence_join_creates_record(): void {
        global $DB;
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $total = \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa1');

        $this->assertEquals(1, $total);
        $records = $DB->get_records('jitsi_presence', ['jitsiid' => $jitsi->id]);
        $this->assertCount(1, $records);
        $record = reset($records);
        $this->assertEquals($user->id, $record->userid);
    }

    /**
     * Test that joining twice with the same hash updates instead of duplicating.
     *
     * @covers \mod_jitsi\external\presence_join::execute
     */
    public function test_presence_join_updates_existing(): void {
        global $DB;
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        [$jitsi, $cm] = $this->create_jitsi_activity();

        \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa1');
        $total = \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa1');

        $this->assertEquals(1, $total);
        $this->assertCount(1, $DB->get_records('jitsi_presence', ['jitsiid' => $jitsi->id]));
    }

    /**
     * Test that presence_leave removes the presence record.
     *
     * @covers \mod_jitsi\external\presence_leave::execute
     */
    public function test_presence_leave_removes_record(): void {
        global $DB;
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        [$jitsi, $cm] = $this->create_jitsi_activity();

        \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa1');
        $result = \mod_jitsi\external\presence_leave::execute($jitsi->id, 'hashaaa1');

        $this->assertTrue($result);
        $this->assertCount(0, $DB->get_records('jitsi_presence', ['jitsiid' => $jitsi->id]));
    }

    /**
     * Test that presence_heartbeat keeps the entry and clears stale ones.
     *
     * @covers \mod_jitsi\external\presence_heartbeat::execute
     */
    public function test_presence_heartbeat_clears_stale(): void {
        global $DB;
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        [$jitsi, $cm] = $this->create_jitsi_activity();

        // Insert a stale entry (older than the 150s threshold).
        $stale = (object)[
            'jitsiid' => $jitsi->id,
            'userid' => $user->id,
            'sessionhash' => 'stalehash',
            'guestname' => null,
            'timecreated' => time() - 1000,
            'timemodified' => time() - 1000,
        ];
        $DB->insert_record('jitsi_presence', $stale);

        \mod_jitsi\external\presence_join::execute($jitsi->id, 'freshhash');
        $result = \mod_jitsi\external\presence_heartbeat::execute($jitsi->id, 'freshhash');

        $this->assertTrue($result);
        $hashes = $DB->get_fieldset_select('jitsi_presence', 'sessionhash', 'jitsiid = ?', [$jitsi->id]);
        $this->assertContains('freshhash', $hashes);
        $this->assertNotContains('stalehash', $hashes);
    }

    /**
     * Test that get_presence_count returns the number of active participants.
     *
     * @covers \mod_jitsi\external\get_presence_count::execute
     */
    public function test_get_presence_count_returns_active(): void {
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        [$jitsi, $cm] = $this->create_jitsi_activity();

        \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa1');
        \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa2');

        $this->assertEquals(2, \mod_jitsi\external\get_presence_count::execute($jitsi->id));
    }

    /**
     * Test that get_presence_users returns the participant names.
     *
     * @covers \mod_jitsi\external\get_presence_users::execute
     */
    public function test_get_presence_users_returns_names(): void {
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Lovelace']);
        $this->setUser($user);
        [$jitsi, $cm] = $this->create_jitsi_activity();

        \mod_jitsi\external\presence_join::execute($jitsi->id, 'hashaaa1');
        $users = \mod_jitsi\external\get_presence_users::execute($jitsi->id);

        $this->assertCount(1, $users);
        $this->assertEquals($user->id, $users[0]['userid']);
        $this->assertEquals(0, $users[0]['isguest']);
        $this->assertStringContainsString('Ada', $users[0]['name']);
    }

    // Participants / session state tests.

    /**
     * Test that update_participants stores the participant count.
     *
     * @covers \mod_jitsi\external\update_participants::execute
     */
    public function test_update_participants_stores_count(): void {
        global $DB;
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $result = \mod_jitsi\external\update_participants::execute($jitsi->id, 5);

        $this->assertEquals(5, $result);
        $this->assertEquals(5, $DB->get_field('jitsi', 'numberofparticipants', ['id' => $jitsi->id]));
    }

    /**
     * Test that participating_session triggers the participating event.
     *
     * @covers \mod_jitsi\external\participating_session::execute
     */
    public function test_participating_session_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\participating_session::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_session_participating::class, $events[0]);
    }

    // Jibri recording status tests.

    /**
     * Test that set_jibri_recording toggles the jitsi status field.
     *
     * @covers \mod_jitsi\external\set_jibri_recording::execute
     */
    public function test_set_jibri_recording_toggles_status(): void {
        global $DB;
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        \mod_jitsi\external\set_jibri_recording::execute($jitsi->id, 1);
        $this->assertEquals('recording', $DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));

        \mod_jitsi\external\set_jibri_recording::execute($jitsi->id, 0);
        $this->assertNull($DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));
    }

    /**
     * Test that get_jibri_recording reflects the recording status.
     *
     * @covers \mod_jitsi\external\get_jibri_recording::execute
     */
    public function test_get_jibri_recording_reads_status(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $this->assertEquals(0, \mod_jitsi\external\get_jibri_recording::execute($jitsi->id));

        \mod_jitsi\external\set_jibri_recording::execute($jitsi->id, 1);
        $this->assertEquals(1, \mod_jitsi\external\get_jibri_recording::execute($jitsi->id));
    }

    // Recording view / segment tests.

    /**
     * Create a GCS source record linked to the given jitsi activity, return its id.
     *
     * @param \stdClass $jitsi
     * @return int sourcerecord id
     */
    protected function create_recording($jitsi): int {
        global $DB, $USER;
        $srid = $DB->insert_record('jitsi_source_record', (object)[
            'timecreated'     => time(),
            'userid'          => $USER->id,
            'embed'           => 0,
            'maxparticipants' => 0,
            'type'            => 0,
            'timeexpires'     => 0,
            'ai_quiz_id'      => 0,
        ]);
        $DB->insert_record('jitsi_record', (object)[
            'jitsi'   => $jitsi->id,
            'deleted' => 0,
            'source'  => $srid,
            'visible' => 1,
            'name'    => 'rec',
        ]);
        return $srid;
    }

    /**
     * Test that recording_segments::merge merges overlapping segments.
     *
     * @covers \mod_jitsi\local\recording_segments::merge
     */
    public function test_recording_segments_merge_overlapping(): void {
        $merged = \mod_jitsi\local\recording_segments::merge([[0, 10], [5, 15], [20, 25]], 30);
        $this->assertEquals([[0, 15], [20, 25]], $merged);
    }

    /**
     * Test that recording_segments::merge drops invalid/out-of-range segments.
     *
     * @covers \mod_jitsi\local\recording_segments::merge
     */
    public function test_recording_segments_merge_filters_invalid(): void {
        $merged = \mod_jitsi\local\recording_segments::merge([[5, 5], [-1, 3], [10, 9], [0, 8]], 30);
        $this->assertEquals([[0, 8]], $merged);
    }

    /**
     * Test that log_recording_view triggers the recording_viewed event.
     *
     * @covers \mod_jitsi\external\log_recording_view::execute
     */
    public function test_log_recording_view_triggers_event(): void {
        $this->resetAfterTest(true);
        set_config('portal_license_key', 'testkey', 'mod_jitsi');
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = $this->create_recording($jitsi);

        $sink = $this->redirectEvents();
        $result = \mod_jitsi\external\log_recording_view::execute($srid, $cm->id, 50);
        $events = $sink->get_events();

        $this->assertTrue($result['success']);
        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\recording_viewed::class, $events[0]);
    }

    /**
     * Test that save_recording_segments stores merged segments.
     *
     * @covers \mod_jitsi\external\save_recording_segments::execute
     */
    public function test_save_recording_segments_stores_merged(): void {
        global $DB;
        $this->resetAfterTest(true);
        set_config('portal_license_key', 'testkey', 'mod_jitsi');
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = $this->create_recording($jitsi);

        $result = \mod_jitsi\external\save_recording_segments::execute($srid, $cm->id, '[[0,10],[5,15]]', 30.0, '[]');

        $this->assertTrue($result['success']);
        $this->assertEquals([[0, 15]], json_decode($result['segments'], true));
        $this->assertEquals(1, $DB->count_records('jitsi_recording_segments', ['sourcerecordid' => $srid]));
    }

    /**
     * Test that get_bucket_viewers returns who watched a given bucket.
     *
     * @covers \mod_jitsi\external\get_bucket_viewers::execute
     */
    public function test_get_bucket_viewers_returns_watcher(): void {
        $this->resetAfterTest(true);
        set_config('portal_license_key', 'testkey', 'mod_jitsi');
        $user = $this->getDataGenerator()->create_user(['firstname' => 'Grace', 'lastname' => 'Hopper']);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = $this->create_recording($jitsi);
        $this->getDataGenerator()->enrol_user($user->id, $jitsi->course, 'editingteacher');
        $this->setUser($user);
        \mod_jitsi\external\save_recording_segments::execute($srid, $cm->id, '[[0,15]]', 30.0, '[]');

        // Read back the heatmap as a user with viewattendance (admin).
        $this->setAdminUser();
        $result = \mod_jitsi\external\get_bucket_viewers::execute($srid, $cm->id, 0);

        $this->assertEquals(0, $result['bucketstart']);
        $this->assertEquals(10, $result['bucketend']);
        $this->assertCount(1, $result['viewers']);
        $this->assertEquals($user->id, $result['viewers'][0]['userid']);
    }
}
