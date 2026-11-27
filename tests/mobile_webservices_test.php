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

use core_external\external_api;
use mod_jitsi\external\get_presence_count;
use mod_jitsi\external\get_presence_users;
use mod_jitsi\external\get_recordings;
use mod_jitsi\external\get_session_state;
use mod_jitsi\external\presence_heartbeat;
use mod_jitsi\external\presence_join;
use mod_jitsi\external\presence_leave;
use PHPUnit\Framework\Attributes\CoversClass;

/**
 * Tests for the web services published to the mobile app.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(get_session_state::class)]
#[CoversClass(get_recordings::class)]
final class mobile_webservices_test extends \advanced_testcase {
    /**
     * Create a course with a jitsi activity.
     *
     * @param array $data Extra activity fields.
     * @return array [course, jitsi record, course module]
     */
    protected function create_activity(array $data = []): array {
        // Activities with dates create calendar events, which needs a user who can manage them.
        $this->setAdminUser();
        $course = $this->getDataGenerator()->create_course(['shortname' => 'MOBILE1']);
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id] + $data);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, 0, false, MUST_EXIST);
        return [$course, $jitsi, $cm];
    }

    /**
     * Add a recording to an activity.
     *
     * @param int $jitsiid Activity instance id.
     * @param string $name Recording name.
     * @param array $record Extra jitsi_record fields.
     * @param array $source Extra jitsi_source_record fields.
     * @return int jitsi_record id.
     */
    protected function add_recording(int $jitsiid, string $name, array $record = [], array $source = []): int {
        global $DB;
        $sourceid = $DB->insert_record('jitsi_source_record', (object) ($source + [
            'link' => 'yt' . $name,
            'timecreated' => time() - 60,
            'userid' => 0,
            'type' => 0,
            'timeexpires' => 0,
            'ai_summary' => 'secret summary',
            'ai_transcription' => 'secret transcription',
        ]));
        return (int) $DB->insert_record('jitsi_record', (object) ($record + [
            'jitsi' => $jitsiid,
            'source' => $sourceid,
            'deleted' => 0,
            'visible' => 1,
            'name' => $name,
        ]));
    }

    /**
     * Assert that a call is refused because the user cannot see the activity or lacks a capability.
     *
     * Prohibiting mod/jitsi:view also makes the activity unavailable, so validate_context may refuse
     * the call before require_capability does. Both outcomes deny access.
     *
     * @param callable $call The call to make.
     * @param string $message Failure message.
     */
    protected function assert_access_denied(callable $call, string $message = 'Access must be denied'): void {
        try {
            $call();
            $this->fail($message);
        } catch (\require_login_exception | \required_capability_exception $e) {
            $this->assertNotEmpty($e->getMessage());
        }
    }

    /**
     * Call get_session_state and clean the result like the web service layer does.
     *
     * @param int $cmid Course module id.
     * @return array
     */
    protected function session_state(int $cmid): array {
        return external_api::clean_returnvalue(get_session_state::execute_returns(), get_session_state::execute($cmid));
    }

    /**
     * Call get_recordings and clean the result like the web service layer does.
     *
     * @param int $cmid Course module id.
     * @return array
     */
    protected function recordings(int $cmid): array {
        return external_api::clean_returnvalue(get_recordings::execute_returns(), get_recordings::execute($cmid));
    }

    /**
     * An activity without dates is open and uses the default domain.
     */
    public function test_session_state_open_without_dates(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity(['timeopen' => 0, 'timeclose' => 0, 'minpretime' => 10]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $state = $this->session_state($cm->id);

        $this->assertSame('open', $state['state']);
        $this->assertSame(0, $state['minutesbefore']);
        $this->assertSame(10, $state['minpretime']);
        $this->assertSame('meet.jit.si', $state['domain']);
        $this->assertFalse($state['jwt_required']);
        $this->assertNotSame('', $state['room']);
    }

    /**
     * Before timeopen minus minpretime the session has not started.
     */
    public function test_session_state_not_started(): void {
        $this->resetAfterTest();
        $timeopen = time() + HOURSECS;
        [$course, $jitsi, $cm] = $this->create_activity(['timeopen' => $timeopen, 'timeclose' => 0, 'minpretime' => 15]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $state = $this->session_state($cm->id);

        $this->assertSame('notstarted', $state['state']);
        $this->assertSame($timeopen, $state['timeopen']);
        $this->assertGreaterThanOrEqual(44, $state['minutesbefore']);
        $this->assertLessThanOrEqual(45, $state['minutesbefore']);
    }

    /**
     * Inside the minpretime window the session is open.
     */
    public function test_session_state_open_within_minpretime(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity(['timeopen' => time() + 300, 'timeclose' => 0, 'minpretime' => 10]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $this->assertSame('open', $this->session_state($cm->id)['state']);
    }

    /**
     * After timeclose the session is closed.
     */
    public function test_session_state_closed(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity([
            'timeopen' => time() - DAYSECS,
            'timeclose' => time() - HOURSECS,
            'minpretime' => 0,
        ]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $state = $this->session_state($cm->id);

        $this->assertSame('closed', $state['state']);
        $this->assertSame(0, $state['minutesbefore']);
    }

    /**
     * The configured server is reported, but never its secret or app id.
     */
    public function test_session_state_does_not_leak_server_secrets(): void {
        global $DB;
        $this->resetAfterTest();
        $serverid = $DB->insert_record('jitsi_servers', (object) [
            'name' => 'Private',
            'type' => 1,
            'domain' => 'meet.example.org',
            'appid' => 'myappid-xyz',
            'secret' => 'supersecretvalue-123',
            'timecreated' => time(),
            'timemodified' => time(),
        ]);
        set_config('server', $serverid, 'mod_jitsi');
        [$course, $jitsi, $cm] = $this->create_activity();
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $state = $this->session_state($cm->id);

        $this->assertSame('meet.example.org', $state['domain']);
        $this->assertTrue($state['jwt_required']);
        $encoded = json_encode($state);
        $this->assertStringNotContainsString('supersecretvalue-123', $encoded);
        $this->assertStringNotContainsString('myappid-xyz', $encoded);
        $this->assertEqualsCanonicalizing(
            ['state', 'timeopen', 'timeclose', 'minpretime', 'minutesbefore', 'room', 'domain', 'jwt_required'],
            array_keys($state)
        );
    }

    /**
     * Users not enrolled in the course cannot read the session state.
     */
    public function test_session_state_requires_course_access(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $this->setUser($this->getDataGenerator()->create_user());

        $this->expectException(\require_login_exception::class);
        get_session_state::execute($cm->id);
    }

    /**
     * Users without mod/jitsi:view cannot read the session state.
     */
    public function test_session_state_requires_view_capability(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $roleid = $DB->get_field('role', 'id', ['shortname' => 'student']);
        assign_capability('mod/jitsi:view', CAP_PROHIBIT, $roleid, \context_module::instance($cm->id)->id, true);
        $this->setUser($student);

        $this->assert_access_denied(fn() => get_session_state::execute($cm->id));
    }

    /**
     * Students only get visible, not deleted, not expired recordings, without AI data.
     */
    public function test_recordings_student_sees_only_visible(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $visible = $this->add_recording($jitsi->id, 'visible');
        $this->add_recording($jitsi->id, 'hidden', ['visible' => 0]);
        $this->add_recording($jitsi->id, 'deleted', ['deleted' => 1]);
        $this->add_recording($jitsi->id, 'expired', [], ['type' => 1, 'timeexpires' => time() - 10]);
        $future = time() + DAYSECS;
        $external = $this->add_recording($jitsi->id, 'external', [], ['type' => 1, 'link' => 'https://example.org/r.mp4',
            'timeexpires' => $future]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $recordings = $this->recordings($cm->id);

        $this->assertSame([$external, $visible], array_column($recordings, 'id'));
        $this->assertSame('https://example.org/r.mp4', $recordings[0]['url']);
        $this->assertSame($future, $recordings[0]['timeexpires']);
        $this->assertSame(1, $recordings[0]['type']);
        $this->assertSame('ytvisible', $recordings[1]['url']);
        $this->assertSame(0, $recordings[1]['type']);
        $this->assertStringNotContainsString('secret', json_encode($recordings));
    }

    /**
     * Teachers with mod/jitsi:hide also get hidden recordings, flagged as hidden.
     */
    public function test_recordings_teacher_sees_hidden(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $this->add_recording($jitsi->id, 'visible');
        $hidden = $this->add_recording($jitsi->id, 'hidden', ['visible' => 0]);
        $this->add_recording($jitsi->id, 'deleted', ['deleted' => 1, 'visible' => 0]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'editingteacher'));

        $recordings = $this->recordings($cm->id);

        $this->assertCount(2, $recordings);
        $this->assertSame($hidden, $recordings[0]['id']);
        $this->assertSame(0, $recordings[0]['visible']);
    }

    /**
     * A session shared by invitation lists the recordings of the master session.
     */
    public function test_recordings_shared_session_uses_master(): void {
        $this->resetAfterTest();
        [$course, $master] = $this->create_activity();
        $this->add_recording($master->id, 'master');
        $shared = $this->getDataGenerator()->create_module('jitsi', [
            'course' => $course->id,
            'sessionwithtoken' => 1,
            'tokeninvitacion' => $master->tokeninterno,
        ]);
        $this->setUser($this->getDataGenerator()->create_and_enrol($course, 'student'));

        $recordings = $this->recordings($shared->cmid);

        $this->assertCount(1, $recordings);
        $this->assertSame('master', $recordings[0]['name']);
    }

    /**
     * Users without mod/jitsi:viewrecords cannot list recordings, as in the web tab.
     */
    public function test_recordings_require_viewrecords(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $this->add_recording($jitsi->id, 'visible');
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $roleid = $DB->get_field('role', 'id', ['shortname' => 'student']);
        $contextid = \context_module::instance($cm->id)->id;
        assign_capability('mod/jitsi:viewrecords', CAP_PROHIBIT, $roleid, $contextid, true);
        $userroleid = $DB->get_field('role', 'id', ['shortname' => 'user']);
        assign_capability('mod/jitsi:viewrecords', CAP_PROHIBIT, $userroleid, $contextid, true);
        $this->setUser($student);

        $this->expectException(\required_capability_exception::class);
        get_recordings::execute($cm->id);
    }

    /**
     * Users not enrolled in the course cannot list recordings.
     */
    public function test_recordings_require_course_access(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $this->add_recording($jitsi->id, 'visible');
        $this->setUser($this->getDataGenerator()->create_user());

        $this->expectException(\require_login_exception::class);
        get_recordings::execute($cm->id);
    }

    /**
     * Presence services still reject logged-in users that are not enrolled in the course.
     */
    public function test_presence_rejects_users_without_course_access(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi] = $this->create_activity();
        $this->setUser($this->getDataGenerator()->create_user());

        $calls = [
            fn() => presence_join::execute($jitsi->id, 'hash1'),
            fn() => presence_heartbeat::execute($jitsi->id, 'hash1'),
            fn() => presence_leave::execute($jitsi->id, 'hash1'),
            fn() => get_presence_count::execute($jitsi->id),
            fn() => get_presence_users::execute($jitsi->id),
        ];
        foreach ($calls as $i => $call) {
            try {
                $call();
                $this->fail("Presence call $i must be rejected without course access");
            } catch (\require_login_exception $e) {
                $this->assertInstanceOf(\require_login_exception::class, $e);
            }
        }
        $this->assertSame(0, $DB->count_records('jitsi_presence'));
    }

    /**
     * Presence reads still reject anonymous callers.
     */
    public function test_presence_reads_reject_anonymous(): void {
        $this->resetAfterTest();
        [$course, $jitsi] = $this->create_activity();
        $this->setUser(null);

        foreach ([get_presence_count::class, get_presence_users::class] as $class) {
            try {
                $class::execute($jitsi->id);
                $this->fail("$class must reject anonymous callers");
            } catch (\moodle_exception $e) {
                $this->assertInstanceOf(\require_login_exception::class, $e);
            }
        }
    }

    /**
     * Presence services reject enrolled users whose mod/jitsi:view is prohibited.
     */
    public function test_presence_requires_view_capability(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_activity();
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $roleid = $DB->get_field('role', 'id', ['shortname' => 'student']);
        assign_capability('mod/jitsi:view', CAP_PROHIBIT, $roleid, \context_module::instance($cm->id)->id, true);
        $this->setUser($student);

        $calls = [
            fn() => presence_join::execute($jitsi->id, 'hash1'),
            fn() => presence_heartbeat::execute($jitsi->id, 'hash1'),
            fn() => presence_leave::execute($jitsi->id, 'hash1'),
            fn() => get_presence_count::execute($jitsi->id),
            fn() => get_presence_users::execute($jitsi->id),
        ];
        foreach ($calls as $i => $call) {
            $this->assert_access_denied($call, "Presence call $i must be rejected without mod/jitsi:view");
        }
        $this->assertSame(0, $DB->count_records('jitsi_presence'));
    }

    /**
     * The seven functions are declared for the official mobile service.
     */
    public function test_functions_are_in_mobile_service(): void {
        global $CFG;
        $functions = [];
        require($CFG->dirroot . '/mod/jitsi/db/services.php');
        $names = [
            'mod_jitsi_get_session_state',
            'mod_jitsi_get_recordings',
            'mod_jitsi_presence_join',
            'mod_jitsi_presence_leave',
            'mod_jitsi_presence_heartbeat',
            'mod_jitsi_get_presence_count',
            'mod_jitsi_get_presence_users',
        ];
        foreach ($names as $name) {
            $this->assertArrayHasKey($name, $functions);
            $this->assertContains(MOODLE_OFFICIAL_MOBILE_SERVICE, $functions[$name]['services'], $name);
        }
    }
}
