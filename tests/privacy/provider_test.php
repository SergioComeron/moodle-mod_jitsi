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

namespace mod_jitsi\privacy;

use PHPUnit\Framework\Attributes\CoversClass;
use core_privacy\local\request\approved_contextlist;
use core_privacy\local\request\approved_userlist;
use core_privacy\local\request\userlist;

/**
 * Privacy provider tests for mod_jitsi.
 *
 * @package    mod_jitsi
 * @category   test
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(\mod_jitsi\privacy\provider::class)]
final class provider_test extends \advanced_testcase {
    /** @var \stdClass Course. */
    private $course;

    /** @var \stdClass Jitsi activity (carries cmid). */
    private $jitsi;

    /** @var \context_module Module context of the activity. */
    private $context;

    /**
     * Create a course and a jitsi activity shared by the data-flow tests.
     */
    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest();
        $this->course = $this->getDataGenerator()->create_course();
        $this->jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $this->course->id]);
        $this->context = \context_module::instance($this->jitsi->cmid);
    }

    /**
     * Insert a daily-usage row for a user in this activity.
     *
     * @param int $userid
     */
    private function add_usage(int $userid): void {
        global $DB;
        $DB->insert_record('jitsi_usage_daily', (object)[
            'daykey'     => 20260101,
            'userid'     => $userid,
            'cmid'       => $this->jitsi->cmid,
            'courseid'   => $this->course->id,
            'categoryid' => $this->course->category,
            'sessions'   => 2,
            'minutes'    => 30,
        ]);
    }

    /**
     * Insert a web-push subscription (user-context data) for a user.
     *
     * @param int $userid
     */
    private function add_push_subscription(int $userid): void {
        global $DB;
        $DB->insert_record('jitsi_push_subscriptions', (object)[
            'userid'       => $userid,
            'endpoint'     => 'https://push.example.com/' . $userid,
            'authkey'      => 'auth' . $userid,
            'p256dhkey'    => 'p256' . $userid,
            'timecreated'  => time(),
            'timemodified' => time(),
        ]);
    }

    /**
     * The provider implements every declared interface, so the privacy
     * subsystem reports the component as compliant.
     *
     * Regression guard for #193: a missing core_userlist_provider method left
     * the class abstract and fataled the plugin privacy registry page.
     */
    public function test_provider_is_compliant(): void {
        $manager = new \core_privacy\manager();
        $this->assertTrue($manager->component_is_compliant('mod_jitsi'));

        // The metadata collection is buildable and non-empty.
        $collection = new \core_privacy\local\metadata\collection('mod_jitsi');
        $result = provider::get_metadata($collection);
        $this->assertNotEmpty($result->get_collection());
    }

    /**
     * get_contexts_for_userid returns both the module and the user context.
     */
    public function test_get_contexts_for_userid(): void {
        $user = $this->getDataGenerator()->create_user();
        // Materialise the user context, as it always exists for a real user who
        // ever subscribed to push notifications (add_user_context reads {context}).
        $usercontext = \context_user::instance($user->id);
        $this->add_usage($user->id);
        $this->add_push_subscription($user->id);

        $contextids = provider::get_contexts_for_userid($user->id)->get_contextids();

        // Context ids come back as strings from get_contextids(); compare loosely.
        $this->assertContainsEquals($this->context->id, $contextids);
        $this->assertContainsEquals($usercontext->id, $contextids);
    }

    /**
     * get_users_in_context lists every user with data in the module context.
     */
    public function test_get_users_in_context(): void {
        $user1 = $this->getDataGenerator()->create_user();
        $user2 = $this->getDataGenerator()->create_user();
        $this->add_usage($user1->id);
        $this->add_usage($user2->id);

        $userlist = new userlist($this->context, 'mod_jitsi');
        provider::get_users_in_context($userlist);
        $userids = $userlist->get_userids();

        $this->assertContains((int)$user1->id, $userids);
        $this->assertContains((int)$user2->id, $userids);
    }

    /**
     * delete_data_for_users only deletes the approved users, leaving others.
     *
     * This is the method that was misnamed in #193.
     */
    public function test_delete_data_for_users(): void {
        global $DB;
        $user1 = $this->getDataGenerator()->create_user();
        $user2 = $this->getDataGenerator()->create_user();
        $this->add_usage($user1->id);
        $this->add_usage($user2->id);

        $approved = new approved_userlist($this->context, 'mod_jitsi', [$user1->id]);
        provider::delete_data_for_users($approved);

        $this->assertFalse($DB->record_exists('jitsi_usage_daily', ['userid' => $user1->id]));
        $this->assertTrue($DB->record_exists('jitsi_usage_daily', ['userid' => $user2->id]));
    }

    /**
     * delete_data_for_all_users_in_context wipes every user's data there.
     */
    public function test_delete_data_for_all_users_in_context(): void {
        global $DB;
        $user1 = $this->getDataGenerator()->create_user();
        $user2 = $this->getDataGenerator()->create_user();
        $this->add_usage($user1->id);
        $this->add_usage($user2->id);

        provider::delete_data_for_all_users_in_context($this->context);

        $this->assertFalse($DB->record_exists('jitsi_usage_daily', ['cmid' => $this->jitsi->cmid]));
    }

    /**
     * delete_data_for_user removes the user's module- and user-context data.
     */
    public function test_delete_data_for_user(): void {
        global $DB;
        $user = $this->getDataGenerator()->create_user();
        $this->add_usage($user->id);
        $this->add_push_subscription($user->id);

        $approved = new approved_contextlist(
            $user,
            'mod_jitsi',
            [$this->context->id, \context_user::instance($user->id)->id]
        );
        provider::delete_data_for_user($approved);

        $this->assertFalse($DB->record_exists('jitsi_usage_daily', ['userid' => $user->id]));
        $this->assertFalse($DB->record_exists('jitsi_push_subscriptions', ['userid' => $user->id]));
    }
}
