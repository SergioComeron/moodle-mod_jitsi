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

use PHPUnit\Framework\Attributes\CoversMethod;

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
#[CoversMethod(\mod_jitsi\external\register_push_subscription::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\unregister_push_subscription::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\check_incoming_call::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\get_tutoring_schedule::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\save_tutoring_slot::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\delete_tutoring_slot::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\press_button_cam::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\press_button_desktop::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\press_button_microphone::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\press_button_end::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\press_record_button::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\presence_join::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\presence_leave::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\presence_heartbeat::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\get_presence_count::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\get_presence_users::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\update_participants::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\participating_session::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\set_jibri_recording::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\get_jibri_recording::class, 'execute')]
#[CoversMethod(\mod_jitsi\local\recording_segments::class, 'merge')]
#[CoversMethod(\mod_jitsi\external\log_recording_view::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\save_recording_segments::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\get_bucket_viewers::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\log_error::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\send_error::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\save_recording_link::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\search_shared_sessions::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\search_coursemates::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\get_teacher_schedule::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\view_jitsi::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\queue_ai_summary::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\queue_ai_transcription::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\queue_ai_quiz::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\add_recording_link::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\update_recording_link::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\set_recording_visibility::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\delete_recording::class, 'execute')]
final class external_test extends \advanced_testcase {
    // Push subscription tests.

    /**
     * Test that register_push_subscription creates a new record.
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
     */
    public function test_recording_segments_merge_overlapping(): void {
        $merged = \mod_jitsi\local\recording_segments::merge([[0, 10], [5, 15], [20, 25]], 30);
        $this->assertEquals([[0, 15], [20, 25]], $merged);
    }

    /**
     * Test that recording_segments::merge drops invalid/out-of-range segments.
     */
    public function test_recording_segments_merge_filters_invalid(): void {
        $merged = \mod_jitsi\local\recording_segments::merge([[5, 5], [-1, 3], [10, 9], [0, 8]], 30);
        $this->assertEquals([[0, 8]], $merged);
    }

    /**
     * Test that log_recording_view triggers the recording_viewed event.
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

    // Error logging tests.

    /**
     * Test that log_error triggers the jitsi_error event.
     */
    public function test_log_error_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        \mod_jitsi\external\log_error::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_error::class, $events[0]);
    }

    /**
     * Test that send_error emails the admins and triggers the error event.
     */
    public function test_send_error_emails_admins_and_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $user = $this->getDataGenerator()->create_user();

        $eventsink = $this->redirectEvents();
        $mailsink = $this->redirectEmails();
        \mod_jitsi\external\send_error::execute($jitsi->id, $user->id, 'something broke', $cm->id);
        $messages = $mailsink->get_messages();
        $events = $eventsink->get_events();

        $this->assertGreaterThanOrEqual(1, count($messages));
        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_error::class, $events[0]);
        $this->assertEquals($cm->instance, $events[0]->objectid);
    }

    // Search / recording-link tests.

    /**
     * Test that save_recording_link creates source + record and is idempotent.
     */
    public function test_save_recording_link_creates_and_dedupes(): void {
        global $DB;
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $result = \mod_jitsi\external\save_recording_link::execute($jitsi->id, 'https://example.com/rec.mp4', 0);

        $this->assertGreaterThan(0, $result['idsource']);
        $this->assertEquals(1, $DB->count_records('jitsi_source_record', ['id' => $result['idsource']]));
        $this->assertEquals(1, $DB->count_records('jitsi_record', ['source' => $result['idsource']]));

        // Saving the same link again returns the same source (no duplicate).
        $result2 = \mod_jitsi\external\save_recording_link::execute($jitsi->id, 'https://example.com/rec.mp4', 0);
        $this->assertEquals($result['idsource'], $result2['idsource']);
        $this->assertEquals(1, $DB->count_records('jitsi_record', ['source' => $result['idsource']]));
    }

    /**
     * Test that search_shared_sessions finds a master session by name (as admin).
     */
    public function test_search_shared_sessions_finds_by_name(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', [
            'course' => $course->id,
            'name'   => 'Findable Session XYZ',
        ]);

        $results = \mod_jitsi\external\search_shared_sessions::execute('Findable', '');

        $this->assertNotEmpty($results);
        $this->assertEquals($jitsi->tokeninterno, $results[0]['value']);
    }

    /**
     * Test that search_coursemates finds a user sharing a course.
     */
    public function test_search_coursemates_finds_shared_course_user(): void {
        $this->resetAfterTest(true);
        $course = $this->getDataGenerator()->create_course();
        $me = $this->getDataGenerator()->create_user();
        $mate = $this->getDataGenerator()->create_user(['firstname' => 'Bartholomew', 'lastname' => 'Smith']);
        $this->getDataGenerator()->enrol_user($me->id, $course->id, 'student');
        $this->getDataGenerator()->enrol_user($mate->id, $course->id, 'student');
        $this->setUser($me);

        $result = \mod_jitsi\external\search_coursemates::execute('Bartho');

        $this->assertCount(1, $result['users']);
        $this->assertEquals($mate->id, $result['users'][0]['id']);
    }

    /**
     * Test that get_teacher_schedule returns slots for a teacher in a shared course.
     */
    public function test_get_teacher_schedule_returns_slots(): void {
        $this->resetAfterTest(true);
        $course = $this->getDataGenerator()->create_course();
        $teacher = $this->getDataGenerator()->create_user();
        $student = $this->getDataGenerator()->create_user();
        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');

        // The teacher publishes a slot.
        $this->setUser($teacher);
        \mod_jitsi\external\save_tutoring_slot::execute($course->id, 1, '10:00', '11:00');

        // The student can see it because they share a course.
        $this->setUser($student);
        $result = \mod_jitsi\external\get_teacher_schedule::execute($teacher->id);

        $this->assertTrue($result['hasschedule']);
        $this->assertCount(1, $result['slots']);
        $this->assertEquals('10:00', $result['slots'][0]['timestart']);
    }

    // View / AI queue tests.
    // Note: getminutesfromlastconexion is a thin delegation to the lib.php function
    // of the same name, which assumes a prior connection log exists (it reads
    // ->timecreated off the row unconditionally). That pre-existing fragility in
    // lib.php is out of scope here, so this wrapper is migrated without a dedicated test.

    /**
     * Test that view_jitsi triggers the course_module_viewed event.
     */
    public function test_view_jitsi_triggers_event(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();

        $sink = $this->redirectEvents();
        $result = \mod_jitsi\external\view_jitsi::execute($cm->id);
        $events = $sink->get_events();

        $this->assertTrue($result['status']);
        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\course_module_viewed::class, $events[0]);
    }

    /**
     * Create a GCS source record (storage.googleapis.com link) and return its id.
     *
     * @return int sourcerecord id
     */
    protected function create_gcs_source(): int {
        global $DB, $USER;
        return (int)$DB->insert_record('jitsi_source_record', (object)[
            'link'            => 'https://storage.googleapis.com/bucket/rec.mp4',
            'timecreated'     => time(),
            'userid'          => $USER->id,
            'embed'           => 0,
            'maxparticipants' => 0,
            'type'            => 0,
            'timeexpires'     => 0,
            'ai_quiz_id'      => 0,
        ]);
    }

    /**
     * Test that queue_ai_summary enqueues the ad-hoc task for a GCS recording.
     */
    public function test_queue_ai_summary_queues_task(): void {
        $this->resetAfterTest(true);
        set_config('aienabled', 1, 'mod_jitsi');
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = $this->create_gcs_source();

        $result = \mod_jitsi\external\queue_ai_summary::execute($srid, $cm->id);

        $this->assertTrue($result['success']);
        $tasks = \core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_ai_summary::class);
        $this->assertCount(1, $tasks);
    }

    /**
     * Test that queue_ai_transcription sets status pending and enqueues the task.
     */
    public function test_queue_ai_transcription_sets_pending_and_queues(): void {
        global $DB;
        $this->resetAfterTest(true);
        set_config('aienabled', 1, 'mod_jitsi');
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = $this->create_gcs_source();

        $result = \mod_jitsi\external\queue_ai_transcription::execute($srid, $cm->id);

        $this->assertTrue($result['success']);
        $this->assertEquals('pending', $DB->get_field('jitsi_source_record', 'ai_transcription_status', ['id' => $srid]));
        $tasks = \core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_ai_transcription::class);
        $this->assertCount(1, $tasks);
    }

    /**
     * Test that queue_ai_quiz enqueues the ad-hoc task for a GCS recording.
     */
    public function test_queue_ai_quiz_queues_task(): void {
        $this->resetAfterTest(true);
        set_config('aienabled', 1, 'mod_jitsi');
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = $this->create_gcs_source();

        $result = \mod_jitsi\external\queue_ai_quiz::execute($srid, $cm->id);

        $this->assertTrue($result['success']);
        $tasks = \core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_ai_quiz::class);
        $this->assertCount(1, $tasks);
    }

    /**
     * Test that queue_ai_summary refuses a non-GCS recording.
     */
    public function test_queue_ai_summary_rejects_non_gcs(): void {
        global $DB;
        $this->resetAfterTest(true);
        set_config('aienabled', 1, 'mod_jitsi');
        $this->setAdminUser();
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $srid = (int)$DB->insert_record('jitsi_source_record', (object)[
            'link'            => 'https://youtu.be/abc123',
            'timecreated'     => time(),
            'userid'          => get_admin()->id,
            'embed'           => 0,
            'maxparticipants' => 0,
            'type'            => 0,
            'timeexpires'     => 0,
            'ai_quiz_id'      => 0,
        ]);

        $result = \mod_jitsi\external\queue_ai_summary::execute($srid, $cm->id);

        $this->assertFalse($result['success']);
        $this->assertCount(0, \core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_ai_summary::class));
    }

    // Recording CRUD web service tests.

    /**
     * Test add_recording_link creates both the source record and the linking record.
     */
    public function test_add_recording_link_creates_records(): void {
        global $DB;
        $this->resetAfterTest(true);
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $teacher = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'editingteacher');
        $this->setUser($teacher);

        $result = \mod_jitsi\external\add_recording_link::execute($cm->id, 'https://example.com/rec.mp4', 'My rec', 0);

        $this->assertTrue($result['success']);
        $record = $DB->get_record('jitsi_record', ['jitsi' => $jitsi->id]);
        $this->assertNotEmpty($record);
        $this->assertEquals('My rec', $record->name);
        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
        $this->assertEquals(1, (int)$source->type);
        $this->assertEquals('https://example.com/rec.mp4', $source->link);
    }

    /**
     * Test update_recording_link updates the URL and name of an existing recording.
     */
    public function test_update_recording_link_updates(): void {
        global $DB;
        $this->resetAfterTest(true);
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $teacher = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'editingteacher');
        $this->setUser($teacher);
        $recordid = \mod_jitsi\local\recording::add_link($jitsi->id, 'https://example.com/a.mp4', 'Old', 0, $teacher->id);

        $result = \mod_jitsi\external\update_recording_link::execute(
            $cm->id,
            $recordid,
            'https://example.com/b.mp4',
            'New',
            0
        );

        $this->assertTrue($result['success']);
        $record = $DB->get_record('jitsi_record', ['id' => $recordid]);
        $this->assertEquals('New', $record->name);
        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
        $this->assertEquals('https://example.com/b.mp4', $source->link);
    }

    /**
     * Test set_recording_visibility toggles the visible flag both ways.
     */
    public function test_set_recording_visibility_toggles(): void {
        global $DB;
        $this->resetAfterTest(true);
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $teacher = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'editingteacher');
        $this->setUser($teacher);
        $recordid = \mod_jitsi\local\recording::add_link($jitsi->id, 'https://example.com/a.mp4', 'R', 0, $teacher->id);

        \mod_jitsi\external\set_recording_visibility::execute($cm->id, $recordid, 0);
        $this->assertEquals(0, (int)$DB->get_field('jitsi_record', 'visible', ['id' => $recordid]));
        \mod_jitsi\external\set_recording_visibility::execute($cm->id, $recordid, 1);
        $this->assertEquals(1, (int)$DB->get_field('jitsi_record', 'visible', ['id' => $recordid]));
    }

    /**
     * Test delete_recording marks the record as deleted.
     */
    public function test_delete_recording_marks_deleted(): void {
        global $DB;
        $this->resetAfterTest(true);
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $teacher = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'editingteacher');
        $this->setUser($teacher);
        $recordid = \mod_jitsi\local\recording::add_link($jitsi->id, 'https://example.com/a.mp4', 'R', 0, $teacher->id);

        $result = \mod_jitsi\external\delete_recording::execute($cm->id, $recordid);

        $this->assertTrue($result['success']);
        $this->assertEquals(1, (int)$DB->get_field('jitsi_record', 'deleted', ['id' => $recordid]));
    }

    /**
     * Test add_recording_link denies users without the record capability.
     */
    public function test_add_recording_link_requires_capability(): void {
        $this->resetAfterTest(true);
        [$jitsi, $cm] = $this->create_jitsi_activity();
        $student = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'student');
        $this->setUser($student);

        $this->expectException(\required_capability_exception::class);
        \mod_jitsi\external\add_recording_link::execute($cm->id, 'https://example.com/a.mp4', 'R', 0);
    }
}
