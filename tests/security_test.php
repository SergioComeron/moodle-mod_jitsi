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
 * Regression tests for the access checks of the session entry points and session web services.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversMethod(\mod_jitsi\output\mobile::class, 'mobile_session_view')]
#[CoversMethod(\mod_jitsi\local\room::class, 'for_activity')]
#[CoversMethod(\mod_jitsi\local\invitation::class, 'get_access_error')]
#[CoversMethod(\mod_jitsi\local\external_access::class, 'validate_activity')]
#[CoversMethod(\mod_jitsi\external\participating_session::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\press_button_cam::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\set_jibri_recording::class, 'execute')]
#[CoversMethod(\mod_jitsi\external\save_recording_link::class, 'execute')]
#[CoversMethod(\mod_jitsi\local\session::class, 'build_token')]
final class security_test extends \advanced_testcase {
    /**
     * Create a course with a Jitsi activity, a teacher and a student.
     *
     * @return array [$course, $jitsi, $cm, $teacher, $student]
     */
    protected function create_course_with_jitsi(): array {
        $generator = $this->getDataGenerator();
        $course = $generator->create_course(['shortname' => 'secA']);
        $jitsi = $generator->create_module('jitsi', ['course' => $course->id, 'name' => 'Clase A']);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, 0, false, MUST_EXIST);
        $teacher = $generator->create_and_enrol($course, 'editingteacher');
        $student = $generator->create_and_enrol($course, 'student');
        return [$course, $jitsi, $cm, $teacher, $student];
    }

    /**
     * Decode the payload of a JWT.
     *
     * @param string $jwt Token
     * @return array
     */
    protected function jwt_payload(string $jwt): array {
        $parts = explode('.', $jwt);
        return json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    }

    /**
     * C1: the mobile session view ignores the moderator flag, room, name and avatar sent by the app.
     */
    public function test_mobile_session_view_ignores_client_room_and_moderator(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi, $cm, $teacher, $student] = $this->create_course_with_jitsi();
        $serverid = $DB->insert_record('jitsi_servers', (object)[
            'name' => 'self', 'type' => 1, 'domain' => 'meet.example.org', 'appid' => 'app', 'secret' => 'secret',
            'timecreated' => time(), 'timemodified' => time(),
        ]);
        set_config('server', $serverid, 'mod_jitsi');
        set_config('id', 'username', 'mod_jitsi');

        $this->setUser($student);
        $result = \mod_jitsi\output\mobile::mobile_session_view([
            'courseid' => $course->id,
            'cmid' => $cm->id,
            'nom' => 'Profesor X',
            'ses' => 'othercourse.99.victim',
            'avatar' => 'https://evil.example/a.png',
            't' => 1,
            'appisdesktop' => false,
        ]);
        $data = json_decode($result['otherdata'], true);
        $expectedroom = \mod_jitsi\local\room::normalize_session_name(\mod_jitsi\local\room::for_activity($jitsi, $course));
        $this->assertSame($expectedroom, $data['room']);

        $payload = $this->jwt_payload(substr($data['jwt'], strlen('jwt=')));
        $this->assertFalse($payload['moderator']);
        $this->assertSame('member', $payload['context']['user']['affiliation']);
        $this->assertSame($student->username, $payload['context']['user']['name']);
        $this->assertStringNotContainsString('evil.example', $payload['context']['user']['avatar']);
        $this->assertSame(urlencode($expectedroom), $payload['room']);
    }

    /**
     * C1: a user without access to the activity cannot get a token for it from the app.
     */
    public function test_mobile_session_view_requires_access_to_cm(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_course_with_jitsi();
        $this->setUser($this->getDataGenerator()->create_user());

        $this->expectException(\require_login_exception::class);
        \mod_jitsi\output\mobile::mobile_session_view([
            'courseid' => SITEID, 'cmid' => $cm->id, 'nom' => '', 'ses' => 'x', 'avatar' => '', 't' => 0,
            'appisdesktop' => false,
        ]);
    }

    /**
     * C2: the room is always computed on the server from the activity (own and shared sessions).
     */
    public function test_room_for_activity(): void {
        $this->resetAfterTest();
        $generator = $this->getDataGenerator();
        [$course, $jitsi] = $this->create_course_with_jitsi();
        $this->assertSame(
            \mod_jitsi\local\room::build_name(
                'secA',
                $jitsi->id,
                'Clase A',
                get_config('mod_jitsi', 'sesionname'),
                get_config('mod_jitsi', 'separator')
            ),
            \mod_jitsi\local\room::for_activity($jitsi, $course)
        );

        // An activity that joins another one's session through its token gets the room of the owner.
        $course2 = $generator->create_course(['shortname' => 'secB']);
        $guest = $generator->create_module('jitsi', ['course' => $course2->id, 'sessionwithtoken' => 1,
            'tokeninvitacion' => $jitsi->tokeninterno]);
        $this->assertSame(
            \mod_jitsi\local\room::for_activity($jitsi, $course),
            \mod_jitsi\local\room::for_activity($guest, $course2)
        );

        // If the owner activity is gone there is no room.
        $guest->tokeninvitacion = 'missing';
        $this->assertNull(\mod_jitsi\local\room::for_activity($guest, $course2));
    }

    /**
     * C2: session.php no longer reads the room, avatar or moderator flag from the request.
     */
    public function test_session_php_does_not_read_client_room(): void {
        global $CFG;
        $source = file_get_contents($CFG->dirroot . '/mod/jitsi/session.php');
        $this->assertStringNotContainsString("_param('ses'", $source);
        $this->assertStringNotContainsString("required_param('t'", $source);
        $this->assertStringNotContainsString("required_param('avatar'", $source);
        $this->assertStringContainsString('room::for_activity(', $source);
    }

    /**
     * C3: JaaS tokens are bound to one room and expire soon.
     */
    public function test_jaas_token_is_scoped_to_room(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($res, $privatekey);
        $server = (object)[
            'type' => 2, 'appid' => '', 'domain' => '8x8.vc', 'secret' => '',
            'eightbyeightappid' => 'vpaas-x', 'eightbyeightapikeyid' => 'vpaas-x/k1', 'privatekey' => $privatekey,
        ];
        $token = \mod_jitsi\local\session::build_token(
            $server,
            \context_system::instance(),
            'Room-1',
            false,
            'member',
            'Ann',
            '',
            ''
        );
        $payload = $this->jwt_payload($token['jwt']);
        $this->assertSame('Room-1', $payload['room']);
        $this->assertLessThanOrEqual(time() + \mod_jitsi\local\session::JAAS_TOKEN_LIFETIME, $payload['exp']);
        $this->assertLessThan(time() + 24 * 3600, $payload['exp']);
    }

    /**
     * C4: the invitation checks are repeated on the joining page.
     */
    public function test_invitation_access_error(): void {
        $this->resetAfterTest();
        $now = time();
        $jitsi = (object)['validitytime' => $now + 3600, 'timeopen' => 0, 'timeclose' => 0, 'minpretime' => 0];

        set_config('invitebuttons', 0, 'mod_jitsi');
        $this->assertNotNull(\mod_jitsi\local\invitation::get_access_error($jitsi, $now));

        set_config('invitebuttons', 1, 'mod_jitsi');
        $this->assertNull(\mod_jitsi\local\invitation::get_access_error($jitsi, $now));

        // Expired link.
        $this->assertNotNull(\mod_jitsi\local\invitation::get_access_error(
            (object)array_merge((array)$jitsi, ['validitytime' => $now - 1]),
            $now
        ));
        // Link never enabled.
        $this->assertNotNull(\mod_jitsi\local\invitation::get_access_error(
            (object)array_merge((array)$jitsi, ['validitytime' => 0]),
            $now
        ));
        // Session closed.
        $this->assertNotNull(\mod_jitsi\local\invitation::get_access_error(
            (object)array_merge((array)$jitsi, ['timeclose' => $now - 1]),
            $now
        ));
        // Session not open yet (taking the pre-time into account).
        $this->assertNotNull(\mod_jitsi\local\invitation::get_access_error(
            (object)array_merge((array)$jitsi, ['timeopen' => $now + 1200, 'minpretime' => 10]),
            $now
        ));
        $this->assertNull(\mod_jitsi\local\invitation::get_access_error(
            (object)array_merge((array)$jitsi, ['timeopen' => $now + 300, 'minpretime' => 10]),
            $now
        ));
    }

    /**
     * C4: universal.php resolves the activity from the invitation token, not from enumerable ids.
     */
    public function test_universal_php_requires_token(): void {
        global $CFG;
        $source = file_get_contents($CFG->dirroot . '/mod/jitsi/universal.php');
        $this->assertStringContainsString("required_param('t', PARAM_ALPHANUMEXT)", $source);
        $this->assertStringNotContainsString("required_param('ses'", $source);
        $this->assertStringNotContainsString("required_param('id'", $source);
        $this->assertStringContainsString('invitation::get_access_error(', $source);
    }

    /**
     * Enable the standard log store so participation rows are written.
     */
    protected function enable_standard_log(): void {
        set_config('enabled_stores', 'logstore_standard', 'tool_log');
        set_config('buffersize', 0, 'logstore_standard');
        get_log_manager(true);
    }

    /**
     * Count participation rows for a user in a course module.
     *
     * @param int $userid User id
     * @param int $cmid Course module id
     * @return int
     */
    protected function count_participating(int $userid, int $cmid): int {
        global $DB;
        return $DB->count_records('logstore_standard_log', ['userid' => $userid, 'contextlevel' => CONTEXT_MODULE,
            'contextinstanceid' => $cmid, 'action' => 'participating']);
    }

    /**
     * C5: participation is logged for the current user and at most once per minute.
     */
    public function test_participating_session_rate_limited(): void {
        $this->resetAfterTest();
        $this->preventResetByRollback();
        $this->enable_standard_log();
        [$course, $jitsi, $cm, $teacher, $student] = $this->create_course_with_jitsi();
        $this->setUser($student);

        $this->assertSame('ok', \mod_jitsi\external\participating_session::execute($jitsi->id, $teacher->id, $cm->id));
        for ($i = 0; $i < 5; $i++) {
            $this->assertSame(
                'ignored',
                \mod_jitsi\external\participating_session::execute($jitsi->id, $student->id, $cm->id)
            );
        }
        $this->assertSame(1, $this->count_participating($student->id, $cm->id));
        $this->assertSame(0, $this->count_participating($teacher->id, $cm->id));
    }

    /**
     * C5: a user cannot log participation in an activity of a course they are not in.
     */
    public function test_participating_session_requires_course_access(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm] = $this->create_course_with_jitsi();
        $this->setUser($this->getDataGenerator()->create_user());

        $this->expectException(\require_login_exception::class);
        \mod_jitsi\external\participating_session::execute($jitsi->id, 0, $cm->id);
    }

    /**
     * C5: the course module must belong to the Jitsi activity passed.
     */
    public function test_participating_session_rejects_mismatched_cm(): void {
        $this->resetAfterTest();
        [$course, $jitsi, $cm, $teacher, $student] = $this->create_course_with_jitsi();
        $other = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $this->setUser($student);

        $this->expectException(\invalid_parameter_exception::class);
        \mod_jitsi\external\participating_session::execute($other->id, 0, $cm->id);
    }

    /**
     * C5: the button events need the view capability too.
     */
    public function test_press_button_requires_view_capability(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi, $cm, $teacher, $student] = $this->create_course_with_jitsi();
        $roleid = $DB->get_field('role', 'id', ['shortname' => 'student']);
        assign_capability('mod/jitsi:view', CAP_PROHIBIT, $roleid, \context_module::instance($cm->id)->id, true);
        $this->setUser($student);

        // Depending on the Moodle version this surfaces as a login or a capability exception.
        $this->expectException(\moodle_exception::class);
        \mod_jitsi\external\press_button_cam::execute($jitsi->id, 0, $cm->id);
    }

    /**
     * C7 and C9: only users who can record change the recording state or publish recording links.
     */
    public function test_recording_writes_need_record_capability(): void {
        global $DB;
        $this->resetAfterTest();
        [$course, $jitsi, $cm, $teacher, $student] = $this->create_course_with_jitsi();

        $this->setUser($student);
        $this->assertFalse(\mod_jitsi\external\set_jibri_recording::execute($jitsi->id, 1));
        $this->assertNull($DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));
        $result = \mod_jitsi\external\save_recording_link::execute($jitsi->id, 'https://phishing.example/x', 0);
        $this->assertSame(0, $result['idsource']);
        $this->assertSame(0, $DB->count_records('jitsi_record', ['jitsi' => $jitsi->id]));

        $this->setUser($teacher);
        $this->assertTrue(\mod_jitsi\external\set_jibri_recording::execute($jitsi->id, 1));
        $this->assertSame('recording', $DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));

        $this->setUser(0);
        $this->assertFalse(\mod_jitsi\external\set_jibri_recording::execute($jitsi->id, 0));
        $this->assertSame('recording', $DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));
    }
}
