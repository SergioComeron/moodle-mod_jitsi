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

use mod_jitsi\external\get_presence_users;
use mod_jitsi\external\presence_heartbeat;
use mod_jitsi\external\presence_join;
use mod_jitsi\external\presence_leave;
use mod_jitsi\local\presence_token;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;

/**
 * Access control tests for the presence web services.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(presence_token::class)]
#[CoversMethod(\mod_jitsi\local\presence::class, 'authorise')]
#[CoversMethod(presence_join::class, 'execute')]
#[CoversMethod(presence_leave::class, 'execute')]
#[CoversMethod(presence_heartbeat::class, 'execute')]
#[CoversMethod(get_presence_users::class, 'execute')]
final class presence_access_test extends \advanced_testcase {
    /**
     * Create a course with a jitsi activity.
     *
     * @return array [jitsi record, course module]
     */
    protected function create_activity(): array {
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, 0, false, MUST_EXIST);
        return [$jitsi, $cm];
    }

    /**
     * An anonymous client without a token cannot join.
     */
    public function test_join_anonymous_without_token_rejected(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $this->setUser(null);

        try {
            presence_join::execute($jitsi->id, 'abc123', 'Fake participant');
            $this->fail('Anonymous join without token must be rejected');
        } catch (\moodle_exception $e) {
            $this->assertInstanceOf(\require_login_exception::class, $e);
        }
        $this->assertSame(0, $DB->count_records('jitsi_presence'));
    }

    /**
     * Anonymous heartbeat and leave without a token are rejected too.
     */
    public function test_heartbeat_and_leave_anonymous_without_token_rejected(): void {
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $this->setUser(null);

        foreach ([presence_heartbeat::class, presence_leave::class] as $class) {
            try {
                $class::execute($jitsi->id, 'abc123');
                $this->fail($class . ' without token must be rejected');
            } catch (\require_login_exception $e) {
                $this->assertInstanceOf(\require_login_exception::class, $e);
            }
        }
    }

    /**
     * A forged token is rejected.
     */
    public function test_join_forged_token_rejected(): void {
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $this->setUser(null);
        $issued = presence_token::issue((int) $jitsi->id, 0, 'Guest');
        [$data] = explode('.', $issued['token']);

        $this->expectException(\moodle_exception::class);
        presence_join::execute($jitsi->id, $issued['sessionhash'], '', $data . '.' . str_repeat('0', 64));
    }

    /**
     * A token issued for another activity is rejected.
     */
    public function test_join_token_for_other_activity_rejected(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        [$other] = $this->create_activity();
        $this->setUser(null);
        $issued = presence_token::issue((int) $other->id, 0, 'Guest');

        try {
            presence_join::execute($jitsi->id, $issued['sessionhash'], '', $issued['token']);
            $this->fail('Token for another activity must be rejected');
        } catch (\moodle_exception $e) {
            $this->assertSame('invalidaccess', $e->errorcode);
        }
        $this->assertSame(0, $DB->count_records('jitsi_presence'));
    }

    /**
     * A token cannot be replayed with another session hash.
     */
    public function test_join_token_with_other_sessionhash_rejected(): void {
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $this->setUser(null);
        $issued = presence_token::issue((int) $jitsi->id, 0, 'Guest');

        $this->expectException(\moodle_exception::class);
        presence_join::execute($jitsi->id, 'someoneelseshash', '', $issued['token']);
    }

    /**
     * An expired token is rejected.
     */
    public function test_join_expired_token_rejected(): void {
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $this->setUser(null);
        $issued = presence_token::issue((int) $jitsi->id, 0, 'Guest', time() - presence_token::TTL - 60);

        $this->expectException(\moodle_exception::class);
        presence_join::execute($jitsi->id, $issued['sessionhash'], '', $issued['token']);
    }

    /**
     * A token issued to one Moodle user cannot be used by another one.
     */
    public function test_join_token_of_other_user_rejected(): void {
        $this->resetAfterTest();
        [$jitsi, $cm] = $this->create_activity();
        $alice = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'student');
        $mallory = $this->getDataGenerator()->create_user();
        $issued = presence_token::issue((int) $jitsi->id, (int) $alice->id);
        $this->setUser($mallory);

        $this->expectException(\moodle_exception::class);
        presence_join::execute($jitsi->id, $issued['sessionhash'], '', $issued['token']);
    }

    /**
     * A logged-in user without access to the activity cannot join without a token.
     */
    public function test_join_logged_in_without_capability_rejected(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $outsider = $this->getDataGenerator()->create_user();
        $this->setUser($outsider);

        try {
            presence_join::execute($jitsi->id, 'abc123');
            $this->fail('User without access must be rejected');
        } catch (\moodle_exception $e) {
            $this->assertInstanceOf(\moodle_exception::class, $e);
        }
        $this->assertSame(0, $DB->count_records('jitsi_presence'));
    }

    /**
     * An enrolled user whose mod/jitsi:view is prohibited cannot join without a token.
     */
    public function test_join_enrolled_without_view_capability_rejected(): void {
        $this->resetAfterTest();
        [$jitsi, $cm] = $this->create_activity();
        $user = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'student');
        $roleid = $this->getDataGenerator()->create_role();
        assign_capability('mod/jitsi:view', CAP_PROHIBIT, $roleid, \context_module::instance($cm->id)->id, true);
        role_assign($roleid, $user->id, \context_module::instance($cm->id)->id);
        $this->setUser($user);

        // Depending on the Moodle version this surfaces as an inaccessible activity or a missing capability.
        $this->expectException(\moodle_exception::class);
        presence_join::execute($jitsi->id, 'abc123');
    }

    /**
     * A valid guest token is accepted; the name comes from the token, cleaned, never from the client.
     */
    public function test_join_valid_guest_token_accepted(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi, $cm] = $this->create_activity();
        $this->setUser(null);
        $longname = '<b>Eve</b><script>alert(1)</script> ' . str_repeat('x', 300);
        $issued = presence_token::issue((int) $jitsi->id, 0, $longname);

        $total = presence_join::execute($jitsi->id, $issued['sessionhash'], 'Client supplied name', $issued['token']);
        $this->assertSame(1, $total);
        presence_heartbeat::execute($jitsi->id, $issued['sessionhash'], $issued['token']);

        $row = $DB->get_record('jitsi_presence', ['jitsiid' => $jitsi->id], '*', MUST_EXIST);
        $this->assertSame(0, (int) $row->userid);
        $this->assertStringStartsWith('Eve', $row->guestname);
        $this->assertStringNotContainsString('<', $row->guestname);
        $this->assertStringNotContainsString('Client supplied', $row->guestname);
        $this->assertLessThanOrEqual(presence_token::GUESTNAME_MAXLENGTH, \core_text::strlen($row->guestname));

        // Other participants see the cleaned name.
        $viewer = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'student');
        $this->setUser($viewer);
        $users = get_presence_users::execute($jitsi->id);
        $users = \core_external\external_api::clean_returnvalue(get_presence_users::execute_returns(), $users);
        $this->assertCount(1, $users);
        $this->assertStringNotContainsString('<', $users[0]['name']);

        // The guest can leave with the same token.
        $this->setUser(null);
        $this->assertTrue(presence_leave::execute($jitsi->id, $issued['sessionhash'], $issued['token']));
        $this->assertSame(0, $DB->count_records('jitsi_presence', ['jitsiid' => $jitsi->id]));
    }

    /**
     * A valid token for a Moodle user is accepted for that user (e.g. invitation link while logged in).
     */
    public function test_join_valid_user_token_accepted(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        $user = $this->getDataGenerator()->create_user();
        $this->setUser($user);
        $issued = presence_token::issue((int) $jitsi->id, (int) $user->id);

        $this->assertSame(1, presence_join::execute($jitsi->id, $issued['sessionhash'], '', $issued['token']));
        $this->assertTrue($DB->record_exists('jitsi_presence', ['jitsiid' => $jitsi->id, 'userid' => $user->id]));
    }

    /**
     * Leave and heartbeat only touch the caller's own row of that activity.
     */
    public function test_leave_and_heartbeat_only_touch_own_rows(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi, $cm] = $this->create_activity();
        [$other] = $this->create_activity();
        $user = $this->getDataGenerator()->create_and_enrol(get_course($cm->course), 'student');

        $old = time() - 1000;
        // Another user's row with the same hash in this activity.
        $DB->insert_record('jitsi_presence', (object) [
            'jitsiid' => $jitsi->id, 'userid' => 0, 'sessionhash' => 'sharedhash', 'guestname' => 'Guest',
            'timecreated' => time(), 'timemodified' => time(),
        ]);
        // A stale row in another activity must not be cleaned by this activity's heartbeat.
        $DB->insert_record('jitsi_presence', (object) [
            'jitsiid' => $other->id, 'userid' => 0, 'sessionhash' => 'otherhash', 'guestname' => 'Guest',
            'timecreated' => $old, 'timemodified' => $old,
        ]);

        $this->setUser($user);
        // Taking over someone else's session hash is refused.
        try {
            presence_join::execute($jitsi->id, 'sharedhash');
            $this->fail('Joining with another participant\'s session hash must be rejected');
        } catch (\moodle_exception $e) {
            $this->assertSame('invalidaccess', $e->errorcode);
        }
        // Heartbeat and leave with that hash do not touch the other participant's row.
        presence_heartbeat::execute($jitsi->id, 'sharedhash');
        presence_leave::execute($jitsi->id, 'sharedhash');
        $this->assertTrue($DB->record_exists('jitsi_presence', ['jitsiid' => $jitsi->id, 'userid' => 0]));

        // The user's own row is refreshed and removed as expected.
        presence_join::execute($jitsi->id, 'ownhash');
        presence_heartbeat::execute($jitsi->id, 'ownhash');
        $this->assertTrue($DB->record_exists('jitsi_presence', ['jitsiid' => $jitsi->id, 'userid' => $user->id]));
        presence_leave::execute($jitsi->id, 'ownhash');
        $this->assertFalse($DB->record_exists('jitsi_presence', ['jitsiid' => $jitsi->id, 'userid' => $user->id]));
        $this->assertTrue($DB->record_exists('jitsi_presence', ['jitsiid' => $jitsi->id, 'userid' => 0]));

        // A stale row in another activity is not cleaned by this activity's heartbeat.
        $this->assertTrue($DB->record_exists('jitsi_presence', ['jitsiid' => $other->id, 'sessionhash' => 'otherhash']));
    }

    /**
     * The signing secret is generated once and reused.
     */
    public function test_secret_is_generated_and_stable(): void {
        $this->resetAfterTest();
        unset_config('presencesecret', 'mod_jitsi');
        $issued = presence_token::issue(5, 0, 'Guest');
        $secret = get_config('mod_jitsi', 'presencesecret');
        $this->assertGreaterThanOrEqual(32, strlen($secret));
        presence_token::issue(5, 0, 'Guest');
        $this->assertSame($secret, get_config('mod_jitsi', 'presencesecret'));
        $payload = presence_token::verify($issued['token'], 5, $issued['sessionhash']);
        $this->assertSame(0, $payload->userid);
        $this->assertSame('Guest', $payload->guestname);
    }
}
