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

use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\CoversMethod;

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
#[CoversMethod(\mod_jitsi\local\room::class, 'normalize_session_name')]
#[CoversFunction('jitsi_add_instance')]
#[CoversFunction('jitsi_update_instance')]
#[CoversFunction('jitsi_delete_instance')]
#[CoversMethod(\mod_jitsi\local\util::class, 'base64url_encode')]
#[CoversMethod(\mod_jitsi\local\util::class, 'base64url_decode')]
#[CoversMethod(\mod_jitsi\local\recording_segments::class, 'format_seconds')]
#[CoversMethod(\mod_jitsi\local\recording_segments::class, 'watched_pct')]
#[CoversMethod(\mod_jitsi\local\invitation::class, 'is_timed_out')]
#[CoversMethod(\mod_jitsi\local\invitation::class, 'generate_code')]
#[CoversMethod(\mod_jitsi\local\invitation::class, 'is_original')]
#[CoversFunction('jitsi_supports')]
#[CoversMethod(\mod_jitsi\local\recording::class, 'is_deletable')]
#[CoversMethod(\mod_jitsi\local\recording::class, 'set_visibility')]
#[CoversMethod(\mod_jitsi\local\recording::class, 'add_link')]
#[CoversMethod(\mod_jitsi\local\recording::class, 'update_link')]
#[CoversMethod(\mod_jitsi\local\tutoring::class, 'check_availability')]
#[CoversMethod(\mod_jitsi\local\session::class, 'create')]
#[CoversMethod(\mod_jitsi\local\session::class, 'build_token')]
#[CoversMethod(\mod_jitsi\local\room::class, 'build_name')]
#[CoversMethod(\mod_jitsi\local\room::class, 'sanitize')]
#[CoversMethod(\mod_jitsi\local\attendance::class, 'minutes')]
#[CoversMethod(\mod_jitsi\local\attendance::class, 'minutes_between')]
#[CoversMethod(\mod_jitsi\local\attendance::class, 'last_connection')]
#[CoversMethod(\mod_jitsi\local\server::class, 'check_gcp_status')]
#[CoversMethod(\mod_jitsi\local\jibri::class, 'is_ready')]
#[CoversMethod(\mod_jitsi\local\attendance::class, 'update_completion')]
#[CoversMethod(\mod_jitsi\output\heatmap_bar::class, 'context')]
#[CoversMethod(\mod_jitsi\output\segments_bar::class, 'context')]
#[CoversMethod(\mod_jitsi\output\session_page::class, 'context')]
#[CoversMethod(\mod_jitsi\local\session::class, 'build_toolbar_buttons')]
#[CoversMethod(\mod_jitsi\local\session::class, 'build_config_overwrite')]
#[CoversMethod(\mod_jitsi\local\session::class, 'build_interface_config_overwrite')]
final class lib_test extends \advanced_testcase {
    /**
     * Test that spaces are removed from session names.
     */
    public function test_normalizesessionname_removes_spaces(): void {
        $this->assertEquals('HelloWorld', \mod_jitsi\local\room::normalize_session_name('Hello World'));
    }

    /**
     * Test that special characters are removed from session names.
     */
    public function test_normalizesessionname_removes_special_chars(): void {
        $this->assertEquals('roomname', \mod_jitsi\local\room::normalize_session_name('room@name!'));
    }

    /**
     * Test that hyphens and underscores are preserved in session names.
     */
    public function test_normalizesessionname_keeps_hyphens_and_underscores(): void {
        $this->assertEquals('Test-Session_1', \mod_jitsi\local\room::normalize_session_name('Test-Session_1'));
    }

    /**
     * Test that accented characters are removed from session names.
     */
    public function test_normalizesessionname_removes_accents(): void {
        $this->assertEquals('caf', \mod_jitsi\local\room::normalize_session_name('café'));
    }

    /**
     * Test that alphanumeric session names are returned unchanged.
     */
    public function test_normalizesessionname_alphanumeric_unchanged(): void {
        $this->assertEquals('Room123', \mod_jitsi\local\room::normalize_session_name('Room123'));
    }

    /**
     * Test that jitsi_add_instance inserts a record and returns its ID.
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
     */
    public function test_delete_instance_returns_false_for_nonexistent(): void {
        $this->resetAfterTest(true);

        $result = jitsi_delete_instance(999999);

        $this->assertFalse($result);
    }

    /**
     * Test that jitsi_delete_instance also removes associated records.
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
     * Test that base64urlencode and base64urldecode are inverse operations.
     */
    public function test_base64url_encode_decode_roundtrip(): void {
        $original = 'Hello World+/=';
        $encoded = \mod_jitsi\local\util::base64url_encode($original);
        $this->assertEquals($original, \mod_jitsi\local\util::base64url_decode($encoded));
    }

    /**
     * Test that base64urlencode replaces +, / and = with URL-safe characters.
     */
    public function test_base64urlencode_uses_url_safe_chars(): void {
        $encoded = \mod_jitsi\local\util::base64url_encode('Hello World+/=');
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
        $this->assertStringNotContainsString('=', $encoded);
    }

    /**
     * Test that recording_segments::format_seconds renders compact durations.
     */
    public function test_recording_segments_format_seconds(): void {
        $this->assertEquals('45s', \mod_jitsi\local\recording_segments::format_seconds(45));
        $this->assertEquals('2min', \mod_jitsi\local\recording_segments::format_seconds(120));
        $this->assertEquals('1min 5s', \mod_jitsi\local\recording_segments::format_seconds(65));
        $this->assertEquals('1h 1min 1s', \mod_jitsi\local\recording_segments::format_seconds(3661));
    }

    /**
     * Test that recording_segments::watched_pct computes the watched percentage.
     */
    public function test_recording_segments_watched_pct(): void {
        $this->assertEquals(0, \mod_jitsi\local\recording_segments::watched_pct([], 100));
        $this->assertEquals(0, \mod_jitsi\local\recording_segments::watched_pct([[0, 50]], 0));
        $this->assertEquals(50, \mod_jitsi\local\recording_segments::watched_pct([[0, 50]], 100));
        // Overlapping/excess coverage is capped at 100.
        $this->assertEquals(100, \mod_jitsi\local\recording_segments::watched_pct([[0, 80], [40, 120]], 100));
    }

    /**
     * Test that istimedout returns true when validitytime is in the past.
     */
    public function test_istimedout_returns_true_when_expired(): void {
        $jitsi = new \stdClass();
        $jitsi->validitytime = time() - 3600;
        $this->assertTrue(\mod_jitsi\local\invitation::is_timed_out($jitsi));
    }

    /**
     * Test that istimedout returns false when validitytime is in the future.
     */
    public function test_istimedout_returns_false_when_not_expired(): void {
        $jitsi = new \stdClass();
        $jitsi->validitytime = time() + 3600;
        $this->assertFalse(\mod_jitsi\local\invitation::is_timed_out($jitsi));
    }

    /**
     * Test that generatecode returns timecreated + id.
     */
    public function test_generatecode_returns_sum_of_timecreated_and_id(): void {
        $jitsi = new \stdClass();
        $jitsi->timecreated = 1000000;
        $jitsi->id = 42;
        $this->assertEquals(1000042, \mod_jitsi\local\invitation::generate_code($jitsi));
    }

    /**
     * Test that isoriginal returns true when code matches generatecode.
     */
    public function test_isoriginal_returns_true_for_correct_code(): void {
        $jitsi = new \stdClass();
        $jitsi->timecreated = 1000000;
        $jitsi->id = 42;
        $this->assertTrue(\mod_jitsi\local\invitation::is_original(1000042, $jitsi));
    }

    /**
     * Test that isoriginal returns false for a wrong code.
     */
    public function test_isoriginal_returns_false_for_wrong_code(): void {
        $jitsi = new \stdClass();
        $jitsi->timecreated = 1000000;
        $jitsi->id = 42;
        $this->assertFalse(\mod_jitsi\local\invitation::is_original(9999, $jitsi));
    }

    /**
     * Test that jitsi_supports returns true for required features.
     */
    public function test_jitsi_supports_required_features(): void {
        $this->assertTrue(jitsi_supports(FEATURE_MOD_INTRO));
        $this->assertTrue(jitsi_supports(FEATURE_SHOW_DESCRIPTION));
        $this->assertTrue(jitsi_supports(FEATURE_BACKUP_MOODLE2));
        $this->assertTrue(jitsi_supports(FEATURE_COMPLETION_HAS_RULES));
    }

    /**
     * Test that jitsi_supports returns null for unknown features.
     */
    public function test_jitsi_supports_returns_null_for_unknown_features(): void {
        $this->assertNull(jitsi_supports(FEATURE_GROUPINGS));
    }

    /**
     * Test that isdeletable returns false when a non-deleted record exists for the source.
     */
    public function test_isdeletable_returns_false_when_active_record_exists(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $sourceid = $DB->insert_record('jitsi_source_record', [
            'jitsi'       => $jitsi->id,
            'link'        => 'https://youtube.com/test',
            'timecreated' => time(),
            'userid'      => 0,
        ]);

        $DB->insert_record('jitsi_record', [
            'jitsi'       => $jitsi->id,
            'source'      => $sourceid,
            'name'        => 'Test',
            'timecreated' => time(),
            'deleted'     => 0,
            'visible'     => 1,
        ]);

        $this->assertFalse(\mod_jitsi\local\recording::is_deletable($sourceid));
    }

    /**
     * Test that isdeletable returns true when no active records exist for the source.
     */
    public function test_isdeletable_returns_true_when_no_active_records(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $sourceid = $DB->insert_record('jitsi_source_record', [
            'jitsi'       => $jitsi->id,
            'link'        => 'https://youtube.com/test',
            'timecreated' => time(),
            'userid'      => 0,
        ]);

        $this->assertTrue(\mod_jitsi\local\recording::is_deletable($sourceid));
    }

    /**
     * Test that set_visibility toggles the visible flag of a recording.
     */
    public function test_set_visibility_toggles_visible_flag(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $sourceid = $DB->insert_record('jitsi_source_record', [
            'jitsi'       => $jitsi->id,
            'link'        => 'https://example.com/v.mp4',
            'timecreated' => time(),
            'userid'      => 0,
            'type'        => 1,
        ]);
        $recordid = $DB->insert_record('jitsi_record', [
            'jitsi'       => $jitsi->id,
            'source'      => $sourceid,
            'name'        => 'Test',
            'timecreated' => time(),
            'deleted'     => 0,
            'visible'     => 1,
        ]);

        \mod_jitsi\local\recording::set_visibility($recordid, 0);
        $this->assertEquals(0, $DB->get_field('jitsi_record', 'visible', ['id' => $recordid]));

        \mod_jitsi\local\recording::set_visibility($recordid, 1);
        $this->assertEquals(1, $DB->get_field('jitsi_record', 'visible', ['id' => $recordid]));
    }

    /**
     * Test that add_link creates a source record and a jitsi_record linking it.
     */
    public function test_add_link_creates_source_and_record(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $recordid = \mod_jitsi\local\recording::add_link($jitsi->id, 'https://example.com/v.mp4', 'My rec', 1, 7);

        $record = $DB->get_record('jitsi_record', ['id' => $recordid], '*', MUST_EXIST);
        $this->assertEquals($jitsi->id, $record->jitsi);
        $this->assertEquals('My rec', $record->name);
        $this->assertEquals(1, $record->visible);
        $this->assertEquals(0, $record->deleted);

        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        $this->assertEquals('https://example.com/v.mp4', $source->link);
        $this->assertEquals(1, $source->type);
        $this->assertEquals(7, $source->userid);
        // Embed is only honoured for Dropbox links.
        $this->assertEquals(0, $source->embed);
    }

    /**
     * Test that add_link honours the embed flag only for Dropbox links and
     * falls back to a date-based name when none is given.
     */
    public function test_add_link_embed_only_for_dropbox_and_default_name(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $recordid = \mod_jitsi\local\recording::add_link($jitsi->id, 'https://www.dropbox.com/s/x/v.mp4', '', 1, 7);

        $record = $DB->get_record('jitsi_record', ['id' => $recordid], '*', MUST_EXIST);
        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        $this->assertEquals(1, $source->embed);
        // Empty name falls back to a userdate() string.
        $this->assertNotEmpty($record->name);
    }

    /**
     * Test that update_link updates the URL and name of a type-1 recording.
     */
    public function test_update_link_updates_url_and_name(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $recordid = \mod_jitsi\local\recording::add_link($jitsi->id, 'https://example.com/old.mp4', 'Old', 0, 7);
        \mod_jitsi\local\recording::update_link($recordid, 'https://example.com/new.mp4', 'New', 0);

        $record = $DB->get_record('jitsi_record', ['id' => $recordid], '*', MUST_EXIST);
        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        $this->assertEquals('New', $record->name);
        $this->assertEquals('https://example.com/new.mp4', $source->link);
    }

    /**
     * Test that update_link leaves non type-1 sources (e.g. YouTube) untouched.
     */
    public function test_update_link_ignores_non_type1(): void {
        global $DB;

        $this->resetAfterTest(true);
        $this->setAdminUser();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $sourceid = $DB->insert_record('jitsi_source_record', [
            'jitsi'       => $jitsi->id,
            'link'        => 'https://youtube.com/orig',
            'timecreated' => time(),
            'userid'      => 0,
            'type'        => 0,
        ]);
        $recordid = $DB->insert_record('jitsi_record', [
            'jitsi'       => $jitsi->id,
            'source'      => $sourceid,
            'name'        => 'Orig',
            'timecreated' => time(),
            'deleted'     => 0,
            'visible'     => 1,
        ]);

        \mod_jitsi\local\recording::update_link($recordid, 'https://example.com/new.mp4', 'New', 0);

        $source = $DB->get_record('jitsi_source_record', ['id' => $sourceid], '*', MUST_EXIST);
        $this->assertEquals('https://youtube.com/orig', $source->link);
        $this->assertEquals('Orig', $DB->get_field('jitsi_record', 'name', ['id' => $recordid]));
    }

    /**
     * Test that jitsi_check_tutoring_availability returns hasschedule=false
     * when teacher has no slots in any shared visible course.
     */
    public function test_check_tutoring_availability_no_schedule(): void {
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $student = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course(['visible' => 1]);

        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');

        $result = \mod_jitsi\local\tutoring::check_availability($teacher->id, $student->id);

        $this->assertFalse($result['hasschedule']);
        $this->assertTrue($result['available']);
        $this->assertNull($result['nextslot']);
    }

    /**
     * Test that jitsi_check_tutoring_availability returns hasschedule=false
     * when they share no visible course (course is hidden).
     */
    public function test_check_tutoring_availability_hidden_course(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user();
        $student = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course(['visible' => 0]);

        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');

        // Add a slot for the teacher in that hidden course.
        $DB->insert_record('jitsi_tutoring_schedule', [
            'userid'       => $teacher->id,
            'courseid'     => $course->id,
            'weekday'      => 1,
            'timestart'    => 0,
            'timeend'      => 86399,
            'timecreated'  => time(),
            'timemodified' => time(),
        ]);

        $result = \mod_jitsi\local\tutoring::check_availability($teacher->id, $student->id);

        $this->assertFalse($result['hasschedule']);
    }

    /**
     * Test that jitsi_check_tutoring_availability returns available=true
     * when current time falls within a slot covering the whole day.
     */
    public function test_check_tutoring_availability_within_slot(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user(['timezone' => 'UTC']);
        $student = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course(['visible' => 1]);

        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');

        // Add a slot covering the entire day for every weekday.
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $currentweekday = (int)$now->format('w');
        $DB->insert_record('jitsi_tutoring_schedule', [
            'userid'       => $teacher->id,
            'courseid'     => $course->id,
            'weekday'      => $currentweekday,
            'timestart'    => 0,
            'timeend'      => 86399,
            'timecreated'  => time(),
            'timemodified' => time(),
        ]);

        $result = \mod_jitsi\local\tutoring::check_availability($teacher->id, $student->id);

        $this->assertTrue($result['hasschedule']);
        $this->assertTrue($result['available']);
    }

    /**
     * Test that jitsi_check_tutoring_availability returns available=false
     * when slot is for a different weekday than today.
     */
    public function test_check_tutoring_availability_outside_slot(): void {
        global $DB;
        $this->resetAfterTest(true);

        $teacher = $this->getDataGenerator()->create_user(['timezone' => 'UTC']);
        $student = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course(['visible' => 1]);

        $this->getDataGenerator()->enrol_user($teacher->id, $course->id, 'editingteacher');
        $this->getDataGenerator()->enrol_user($student->id, $course->id, 'student');

        // Create a slot for a different weekday.
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        $otherday = ((int)$now->format('w') + 1) % 7;
        $DB->insert_record('jitsi_tutoring_schedule', [
            'userid'       => $teacher->id,
            'courseid'     => $course->id,
            'weekday'      => $otherday,
            'timestart'    => 0,
            'timeend'      => 86399,
            'timecreated'  => time(),
            'timemodified' => time(),
        ]);

        $result = \mod_jitsi\local\tutoring::check_availability($teacher->id, $student->id);

        $this->assertTrue($result['hasschedule']);
        $this->assertFalse($result['available']);
    }

    /**
     * Test that jitsi_check_tutoring_availability returns hasschedule=false
     * when the user is not enrolled as teacher in any visible course.
     */
    public function test_check_tutoring_availability_not_a_teacher(): void {
        $this->resetAfterTest(true);

        $user1 = $this->getDataGenerator()->create_user();
        $user2 = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course(['visible' => 1]);

        // Both enrolled as students — neither is a teacher.
        $this->getDataGenerator()->enrol_user($user1->id, $course->id, 'student');
        $this->getDataGenerator()->enrol_user($user2->id, $course->id, 'student');

        $result = \mod_jitsi\local\tutoring::check_availability($user1->id, $user2->id);

        $this->assertFalse($result['hasschedule']);
    }

    /**
     * Regression test for issue #138.
     *
     * On a type-0 server (public/no JWT), \mod_jitsi\local\session::create() must emit
     * roomName so users join the correct room instead of landing
     * on the Jitsi homepage.
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
        \mod_jitsi\local\session::create(
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
            '\mod_jitsi\local\session::create() must emit roomName for type-0 servers (regression #138)'
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

    /**
     * Run \mod_jitsi\local\session::create() against a freshly inserted server and return its echoed output.
     *
     * @param array $serverfields Fields overriding the jitsi_servers defaults
     * @param array $configs mod_jitsi config overrides
     * @return string Captured output
     */
    protected function createsession_output(array $serverfields, array $configs = []): string {
        global $DB, $PAGE;

        $baseconfig = [
            'livebutton' => '0', 'shareyoutube' => '0', 'blurbutton' => '0',
            'securitybutton' => '0', 'record' => '0', 'participantspane' => '0',
            'raisehand' => '0', 'whiteboard' => '0', 'allowbreakoutrooms' => '0',
            'startwithaudiomuted' => '0', 'startwithvideomuted' => '0',
            'reactions' => '1', 'chat' => '1', 'polls' => '1', 'transcription' => '1',
            'channellastcam' => '-1', 'tokentype' => '0', 'dropbox_appkey' => '',
        ];
        foreach (array_merge($baseconfig, $configs) as $k => $v) {
            set_config($k, $v, 'mod_jitsi');
        }

        $serverdefaults = [
            'name' => 'Test server', 'type' => 0, 'domain' => 'meet.jit.si',
            'appid' => '', 'secret' => '', 'eightbyeightappid' => '',
            'eightbyeightapikeyid' => '', 'privatekey' => '', 'gcpproject' => '',
            'gcpzone' => '', 'gcpinstancename' => '', 'gcpstaticipname' => '',
            'gcpstaticipaddress' => '', 'provisioningstatus' => '',
            'provisioningtoken' => '', 'provisioningerror' => '',
            'timecreated' => time(), 'timemodified' => time(),
        ];
        $server = (object)array_merge($serverdefaults, $serverfields);
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
        \mod_jitsi\local\session::create(
            0,
            $cm->id,
            'https://example.com/avatar.png',
            'Test User',
            'TestRoom-1',
            'test@example.com',
            $jitsirecord
        );
        return ob_get_clean();
    }

    /**
     * Type-1 (self-hosted JWT) servers must emit roomName and a valid HS256 JWT.
     */
    public function test_type1_server_emits_signed_jwt(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        $output = $this->createsession_output([
            'type'   => 1,
            'domain' => 'jitsi.example.com',
            'appid'  => 'myappid',
            'secret' => 'mysecret',
        ]);

        $this->assertStringContainsString('roomName: "TestRoom-1"', $output);
        $this->assertStringContainsString('jwt:', $output);

        // Extract the JWT and verify it is signed with the server secret (HS256).
        $this->assertSame(1, preg_match('/jwt: "([^"]+)"/', $output, $m));
        [$h, $p, $s] = explode('.', $m[1]);
        $header = json_decode(base64_decode(strtr($h, '-_', '+/')), true);
        $this->assertEquals('HS256', $header['alg']);
        $expectedsig = str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode(hash_hmac('sha256', $h . '.' . $p, 'mysecret', true))
        );
        $this->assertEquals($expectedsig, $s, 'JWT signature must match HMAC-SHA256 with the server secret');
    }

    /**
     * Type-2 (8x8 JaaS) servers must emit the appid-prefixed roomName and an RS256 JWT.
     */
    public function test_type2_server_emits_jaas_room_and_jwt(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($res, $privatekey);

        $output = $this->createsession_output([
            'type'                 => 2,
            'domain'               => '8x8.vc',
            'eightbyeightappid'    => 'vpaas-magic-cookie-abc',
            'eightbyeightapikeyid' => 'vpaas-magic-cookie-abc/key1',
            'privatekey'           => $privatekey,
        ]);

        $this->assertStringContainsString('roomName: "vpaas-magic-cookie-abc/TestRoom-1"', $output);
        $this->assertStringContainsString('jwt:', $output);
        $this->assertSame(1, preg_match('/jwt: "([^"]+)"/', $output, $m));
        $header = json_decode(base64_decode(strtr(explode('.', $m[1])[0], '-_', '+/')), true);
        $this->assertEquals('RS256', $header['alg']);
    }

    /**
     * Type-3 (GCP) servers with app credentials must emit roomName and a JWT (HS256, as type 1).
     */
    public function test_type3_server_emits_jwt(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        $output = $this->createsession_output([
            'type'   => 3,
            'domain' => 'gcp.example.com',
            'appid'  => 'gcpapp',
            'secret' => 'gcpsecret',
        ]);

        $this->assertStringContainsString('roomName: "TestRoom-1"', $output);
        $this->assertStringContainsString('jwt:', $output);
    }

    /**
     * build_token returns the plain (url-encoded) room name and no JWT for type-0 servers.
     */
    public function test_build_token_type0_no_jwt(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('tokentype', '0', 'mod_jitsi');

        $server = (object)[
            'type' => 0, 'appid' => '', 'domain' => 'meet.jit.si', 'secret' => '',
            'eightbyeightappid' => '', 'eightbyeightapikeyid' => '', 'privatekey' => '',
        ];
        $token = \mod_jitsi\local\session::build_token(
            $server,
            \context_system::instance(),
            'Room-1',
            false,
            'member',
            'Ann',
            'http://a/av.png',
            'a@b.c'
        );

        $this->assertSame('Room-1', $token['roomname']);
        $this->assertNull($token['jwt']);
    }

    /**
     * build_token signs an HS256 JWT for type-1 servers with the server secret and the expected claims.
     */
    public function test_build_token_type1_hs256_claims_and_signature(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('tokentype', '0', 'mod_jitsi');

        $server = (object)[
            'type' => 1, 'appid' => 'myapp', 'domain' => 'jitsi.example.com', 'secret' => 'sec',
            'eightbyeightappid' => '', 'eightbyeightapikeyid' => '', 'privatekey' => '',
        ];
        $token = \mod_jitsi\local\session::build_token(
            $server,
            \context_system::instance(),
            'Room-1',
            true,
            'owner',
            'Ann',
            'http://a/av.png',
            'a@b.c'
        );

        $this->assertSame('Room-1', $token['roomname']);
        $this->assertNotNull($token['jwt']);
        [$h, $p, $s] = explode('.', $token['jwt']);
        $header = json_decode(base64_decode(strtr($h, '-_', '+/')), true);
        $payload = json_decode(base64_decode(strtr($p, '-_', '+/')), true);
        $this->assertSame('HS256', $header['alg']);
        $this->assertSame('Room-1', $payload['room']);
        $this->assertSame('myapp', $payload['iss']);
        $this->assertTrue($payload['moderator']);
        $expected = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode(hash_hmac('sha256', $h . '.' . $p, 'sec', true)));
        $this->assertSame($expected, $s, 'JWT signature must be HMAC-SHA256 of header.payload with the server secret');
    }

    /**
     * build_token signs an RS256 JWT verifiable with the public key, and prefixes the room with the JaaS appid.
     */
    public function test_build_token_type2_rs256_verifiable(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($res, $privatekey);
        $publickey = openssl_pkey_get_details($res)['key'];

        $server = (object)[
            'type' => 2, 'appid' => '', 'domain' => '8x8.vc', 'secret' => '',
            'eightbyeightappid' => 'vpaas-cookie', 'eightbyeightapikeyid' => 'vpaas-cookie/k1', 'privatekey' => $privatekey,
        ];
        $token = \mod_jitsi\local\session::build_token(
            $server,
            \context_system::instance(),
            'Room-1',
            true,
            'owner',
            'Ann',
            'http://a/av.png',
            'a@b.c'
        );

        $this->assertSame('vpaas-cookie/Room-1', $token['roomname']);
        [$h, $p, $s] = explode('.', $token['jwt']);
        $header = json_decode(base64_decode(strtr($h, '-_', '+/')), true);
        $this->assertSame('RS256', $header['alg']);
        $signature = base64_decode(strtr($s, '-_', '+/'));
        $this->assertSame(1, openssl_verify($h . '.' . $p, $signature, $publickey, OPENSSL_ALGO_SHA256));
    }

    /**
     * jitsi_build_room_name combines parts with no separator by default.
     */
    public function test_build_room_name_default_settings(): void {
        // Default sesionname=0,1,2 and separator=0 ('.') — but last part has no trailing sep.
        // shortname=prueba, id=4, name=Prueba dev to master 4.6.0
        // string_sanitize converts spaces to hyphens and strips dots.
        $result = \mod_jitsi\local\room::build_name('prueba', 4, 'Prueba dev to master 4.6.0', '0,1,2', 3);
        $this->assertEquals('prueba4prueba-dev-to-master-460', $result);
    }

    /**
     * jitsi_build_room_name uses dot separator between all but last part.
     */
    public function test_build_room_name_dot_separator(): void {
        $result = \mod_jitsi\local\room::build_name('mycourse', 7, 'My Session', '0,1,2', 0);
        $this->assertEquals('mycourse.7.my-session', $result);
    }

    /**
     * jitsi_build_room_name defaults to '0,1,2' when sesionname is empty.
     */
    public function test_build_room_name_empty_sesionname_defaults(): void {
        $a = \mod_jitsi\local\room::build_name('course', 1, 'Test', '', 3);
        $b = \mod_jitsi\local\room::build_name('course', 1, 'Test', '0,1,2', 3);
        $this->assertEquals($b, $a);
    }

    /**
     * jitsi_build_room_name defaults to '0,1,2' when sesionname is false (config not set).
     */
    public function test_build_room_name_false_sesionname_defaults(): void {
        $a = \mod_jitsi\local\room::build_name('course', 2, 'Demo', false, 3);
        $b = \mod_jitsi\local\room::build_name('course', 2, 'Demo', '0,1,2', 3);
        $this->assertEquals($b, $a);
    }

    /**
     * jitsi_build_room_name result matches room name extracted from Jibri filename.
     *
     * Regression test for the bug where preg_replace('/[^a-zA-Z0-9]/','') was used
     * instead of \mod_jitsi\local\room::sanitize(), causing spaces to be stripped rather than
     * converted to hyphens, so the callback could never match an activity.
     */
    public function test_build_room_name_matches_jibri_filename_room(): void {
        // Filename: prueba4prueba-dev-to-master-460_2026-04-19-08-27-30.mp4
        // Room extracted by finalize script: prueba4prueba-dev-to-master-460.
        $room = \mod_jitsi\local\room::build_name('prueba', 4, 'Prueba dev to master 4.6.0', '0,1,2', 3);
        $this->assertEquals('prueba4prueba-dev-to-master-460', strtolower($room));
    }

    /**
     * Test that dot separator is stripped for Jibri filename matching.
     *
     * Jibri strips dots from room names in MP4 filenames. When separator='0' (dot),
     * 'prueba.4.session' in the URL becomes 'prueba4session' in the filename.
     * The jibrirecording callback must match both forms.
     */
    public function test_build_room_name_dot_separator_stripped_matches_jibri_filename(): void {
        $builtname = \mod_jitsi\local\room::build_name('prueba', 4, 'Prueba dev to master 4.6.0', '0,1,2', 0);
        $this->assertEquals('prueba.4.prueba-dev-to-master-460', strtolower($builtname));

        // Simulate what the jibrirecording callback does to match Jibri filenames.
        $jibrifilename = 'prueba4prueba-dev-to-master-460';
        $strippeddot   = strtolower(str_replace('.', '', $builtname));
        $this->assertEquals($jibrifilename, $strippeddot);
    }

    /**
     * room::sanitize lowercases, turns whitespace into hyphens and strips punctuation/dots.
     */
    public function test_room_sanitize_normalises_spaces_and_punctuation(): void {
        $this->assertEquals('my-session-460', \mod_jitsi\local\room::sanitize('My Session 4.6.0'));
        // With forcelowercase disabled the case is preserved.
        $this->assertEquals('My-Session', \mod_jitsi\local\room::sanitize('My Session!', false));
        // The "anal" flag removes every non-alphanumeric character (including hyphens).
        $this->assertEquals('mysession', \mod_jitsi\local\room::sanitize('My Session', true, true));
    }

    /**
     * Insert a 'participating' log row for the given module/user/time.
     *
     * @param int $cmid
     * @param int $userid
     * @param int $timecreated
     */
    protected function insert_participating_log($cmid, $userid, $timecreated): void {
        global $DB;
        $DB->insert_record('logstore_standard_log', (object)[
            'eventname'         => '\\mod_jitsi\\event\\jitsi_session_participating',
            'component'         => 'mod_jitsi',
            'action'            => 'participating',
            'target'            => 'session',
            'crud'              => 'r',
            'edulevel'          => 0,
            'contextid'         => 1,
            'contextlevel'      => CONTEXT_MODULE,
            'contextinstanceid' => $cmid,
            'userid'            => $userid,
            'anonymous'         => 0,
            'timecreated'       => $timecreated,
        ]);
    }

    /**
     * Test that attendance::minutes counts only this user's 'participating' rows.
     */
    public function test_attendance_minutes_counts_participating(): void {
        $this->resetAfterTest(true);
        $cmid = 4321;
        $userid = 777;

        $this->insert_participating_log($cmid, $userid, time());
        $this->insert_participating_log($cmid, $userid, time());
        $this->insert_participating_log($cmid, $userid, time());
        // Different user and different module must not be counted.
        $this->insert_participating_log($cmid, 888, time());
        $this->insert_participating_log(9999, $userid, time());

        $this->assertEquals(3, \mod_jitsi\local\attendance::minutes($cmid, $userid));
    }

    /**
     * Test that attendance::minutes_between only counts rows inside the time window.
     */
    public function test_attendance_minutes_between_respects_window(): void {
        $this->resetAfterTest(true);
        $cmid = 4322;
        $userid = 778;
        $now = time();

        $this->insert_participating_log($cmid, $userid, $now - 100);
        $this->insert_participating_log($cmid, $userid, $now - 50);
        // Outside the window.
        $this->insert_participating_log($cmid, $userid, $now - 5000);

        $this->assertEquals(2, \mod_jitsi\local\attendance::minutes_between($cmid, $userid, $now - 200, $now));
    }

    /**
     * attendance::last_connection returns 0 when the user has never connected.
     */
    public function test_attendance_last_connection_returns_zero_when_no_log(): void {
        $this->resetAfterTest(true);

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $user = $this->getDataGenerator()->create_user();

        $this->assertSame(0, \mod_jitsi\local\attendance::last_connection($cm->id, $user->id));
    }

    /**
     * attendance::last_connection returns the timestamp of the most recent connection.
     */
    public function test_attendance_last_connection_returns_latest_timestamp(): void {
        global $DB;
        $this->resetAfterTest(true);

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $context = \context_module::instance($cm->id);
        $user = $this->getDataGenerator()->create_user();
        $now = time();

        // Two connections for this user; the latest must win.
        $this->insert_log_with_context($context->id, $cm->id, $user->id, 'participating', $now - 500);
        $this->insert_log_with_context($context->id, $cm->id, $user->id, 'enter', $now - 100);
        // A different user must not interfere.
        $this->insert_log_with_context($context->id, $cm->id, 99999, 'participating', $now);

        $this->assertSame($now - 100, \mod_jitsi\local\attendance::last_connection($cm->id, $user->id));
    }

    /**
     * server::check_gcp_status returns 'running' for non-GCP servers (type != 3).
     */
    public function test_server_check_gcp_status_non_gcp_is_running(): void {
        $this->resetAfterTest(true);
        $server = (object)['type' => 1];
        $this->assertSame('running', \mod_jitsi\local\server::check_gcp_status($server)['status']);
    }

    /**
     * server::check_gcp_status returns 'error' while a GCP server is still provisioning.
     */
    public function test_server_check_gcp_status_provisioning_is_error(): void {
        $this->resetAfterTest(true);
        $server = (object)['type' => 3, 'provisioningstatus' => 'provisioning'];
        $this->assertSame('error', \mod_jitsi\local\server::check_gcp_status($server)['status']);
    }

    /**
     * server::check_gcp_status treats a GCP server without instance metadata as 'running'.
     */
    public function test_server_check_gcp_status_no_instance_is_running(): void {
        $this->resetAfterTest(true);
        $server = (object)[
            'type'               => 3,
            'provisioningstatus' => 'ready',
            'gcpinstancename'    => '',
            'gcpproject'         => '',
            'gcpzone'            => '',
        ];
        $this->assertSame('running', \mod_jitsi\local\server::check_gcp_status($server)['status']);
    }

    /**
     * Insert a log row for the given context/module/user/action/time.
     *
     * @param int $contextid
     * @param int $cmid
     * @param int $userid
     * @param string $action
     * @param int $timecreated
     */
    protected function insert_log_with_context($contextid, $cmid, $userid, $action, $timecreated): void {
        global $DB;
        $DB->insert_record('logstore_standard_log', (object)[
            'eventname'         => '\\mod_jitsi\\event\\jitsi_session_participating',
            'component'         => 'mod_jitsi',
            'action'            => $action,
            'target'            => 'session',
            'crud'              => 'r',
            'edulevel'          => 0,
            'contextid'         => $contextid,
            'contextlevel'      => CONTEXT_MODULE,
            'contextinstanceid' => $cmid,
            'userid'            => $userid,
            'anonymous'         => 0,
            'timecreated'       => $timecreated,
        ]);
    }

    /**
     * Insert a Jibri pool row for a server with the given status.
     *
     * @param int $serverid
     * @param string $status
     */
    protected function insert_jibri_pool($serverid, $status): void {
        global $DB;
        $DB->insert_record('jitsi_jibri_pool', (object)[
            'serverid'     => $serverid,
            'status'       => $status,
            'timecreated'  => time(),
            'timemodified' => time(),
        ]);
    }

    /**
     * Test jibri::is_ready across the disabled / pool / legacy-fallback paths.
     */
    public function test_jibri_is_ready(): void {
        $this->resetAfterTest(true);

        // Jibri disabled on the server -> never ready.
        $disabled = (object)['id' => 555, 'jibri_enabled' => 0, 'jibri_provisioningstatus' => 'ready'];
        $this->assertFalse(\mod_jitsi\local\jibri::is_ready($disabled));

        // Enabled with an idle pool VM -> ready.
        $enabled = (object)['id' => 555, 'jibri_enabled' => 1, 'jibri_provisioningstatus' => ''];
        $this->insert_jibri_pool(555, 'idle');
        $this->assertTrue(\mod_jitsi\local\jibri::is_ready($enabled));

        // Pool entries exist but only provisioning -> not ready, no legacy fallback.
        $provisioning = (object)['id' => 556, 'jibri_enabled' => 1, 'jibri_provisioningstatus' => 'ready'];
        $this->insert_jibri_pool(556, 'provisioning');
        $this->assertFalse(\mod_jitsi\local\jibri::is_ready($provisioning));

        // No pool entries -> legacy provisioningstatus field is used.
        $legacy = (object)['id' => 557, 'jibri_enabled' => 1, 'jibri_provisioningstatus' => 'ready'];
        $this->assertTrue(\mod_jitsi\local\jibri::is_ready($legacy));
        $legacy->jibri_provisioningstatus = 'provisioning';
        $this->assertFalse(\mod_jitsi\local\jibri::is_ready($legacy));
    }

    /**
     * Test that attendance::update_completion marks the activity complete when
     * automatic completion by minutes is configured.
     */
    public function test_attendance_update_completion_marks_complete(): void {
        global $CFG;
        $this->resetAfterTest(true);
        $CFG->enablecompletion = 1;

        $course = $this->getDataGenerator()->create_course(['enablecompletion' => 1]);
        $jitsi = $this->getDataGenerator()->create_module('jitsi', [
            'course'            => $course->id,
            'completion'        => COMPLETION_TRACKING_AUTOMATIC,
            'completionminutes' => 5,
        ]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $user = $this->getDataGenerator()->create_user();
        $this->getDataGenerator()->enrol_user($user->id, $course->id);
        $this->setUser($user);

        // The custom completion rule needs at least completionminutes connected minutes.
        for ($i = 0; $i < 5; $i++) {
            $this->insert_participating_log($cm->id, $user->id, time());
        }

        \mod_jitsi\local\attendance::update_completion($cm);

        $completion = new \completion_info($course);
        $data = $completion->get_data($cm, false, $user->id);
        $this->assertEquals(COMPLETION_COMPLETE, $data->completionstate);
    }

    /**
     * heatmap_bar::context returns null when there are no recording segments.
     */
    public function test_heatmap_bar_context_empty(): void {
        $this->resetAfterTest(true);
        $this->assertNull(\mod_jitsi\output\heatmap_bar::context(555, 77));
    }

    /**
     * heatmap_bar::context aggregates viewers and plays per bucket.
     */
    public function test_heatmap_bar_context_aggregates(): void {
        global $DB;
        $this->resetAfterTest(true);
        $user = $this->getDataGenerator()->create_user(['firstname' => 'Ada', 'lastname' => 'Lovelace']);
        $srid = 555;
        $cmid = 77;

        $DB->insert_record('jitsi_recording_segments', (object)[
            'userid'         => $user->id,
            'sourcerecordid' => $srid,
            'cmid'           => $cmid,
            'segments'       => json_encode([[0, 15]]),
            'playcounts'     => json_encode([3, 1]),
            'duration'       => 20,
            'timecreated'    => time(),
            'timemodified'   => time(),
        ]);

        $ctx = \mod_jitsi\output\heatmap_bar::context($srid, $cmid);

        $this->assertNotNull($ctx);
        // Duration 20 / 10s buckets = 2 buckets; segment 0-15 covers both.
        $this->assertCount(2, $ctx['viewerbuckets']);
        $this->assertEquals(10, $ctx['bucketsize']);
        // Playcounts [3,1] -> max plays 3 -> plays bar shown.
        $this->assertTrue($ctx['hasplays']);
        $this->assertCount(2, $ctx['playbuckets']);
        $this->assertStringContainsString('Ada', $ctx['viewersjson']);
    }

    /**
     * segments_bar::context maps each watched segment to a left/width percentage.
     */
    public function test_segments_bar_context(): void {
        $ctx = \mod_jitsi\output\segments_bar::context([[0, 50], [75, 100]], 100.0, 'mybar');

        $this->assertEquals('mybar', $ctx['barid']);
        $this->assertCount(2, $ctx['segments']);
        $this->assertEquals('0.00', $ctx['segments'][0]['left']);
        $this->assertEquals('50.00', $ctx['segments'][0]['width']);
        $this->assertEquals('75.00', $ctx['segments'][1]['left']);
        $this->assertEquals('25.00', $ctx['segments'][1]['width']);

        // A zero duration yields no segment bars.
        $this->assertCount(0, \mod_jitsi\output\segments_bar::context([[0, 50]], 0.0)['segments']);
    }

    /**
     * session_page::context shows the button row when either action button is enabled.
     */
    public function test_session_page_context_buttons(): void {
        $this->resetAfterTest(true);

        $ctx = \mod_jitsi\output\session_page::context(true, true, false);
        $this->assertTrue($ctx['textend']);
        $this->assertTrue($ctx['showbuttons']);
        $this->assertTrue($ctx['showstreaming']);
        $this->assertFalse($ctx['showrecording']);
        $this->assertArrayHasKey('streambtnlabel', $ctx);
        $this->assertArrayHasKey('recordbtnlabel', $ctx);
    }

    /**
     * session_page::context hides the button row when neither action button is enabled.
     */
    public function test_session_page_context_no_buttons(): void {
        $this->resetAfterTest(true);

        $ctx = \mod_jitsi\output\session_page::context(false, false, false);
        $this->assertFalse($ctx['textend']);
        $this->assertFalse($ctx['showbuttons']);
        $this->assertFalse($ctx['showstreaming']);
        $this->assertFalse($ctx['showrecording']);
    }

    /**
     * build_toolbar_buttons includes the recording and live-streaming buttons for a moderator
     * when the matching settings are on.
     */
    public function test_build_toolbar_buttons_includes_recording_and_streaming(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('record', '1', 'mod_jitsi');
        set_config('livebutton', '1', 'mod_jitsi');
        set_config('streamingoption', '0', 'mod_jitsi');

        $server = (object)['type' => 1];
        $buttons = \mod_jitsi\local\session::build_toolbar_buttons(
            $server,
            \context_system::instance(),
            false,
            false
        );

        $this->assertContains('recording', $buttons);
        $this->assertContains('livestreaming', $buttons);
        // Slot order is preserved: recording sits between 'chat' and 'etherpad'.
        $this->assertSame('chat', $buttons[7]);
        $this->assertSame('recording', $buttons[8]);
        $this->assertSame('etherpad', $buttons[9]);
    }

    /**
     * build_toolbar_buttons never exposes recording or live streaming in private sessions.
     */
    public function test_build_toolbar_buttons_private_omits_recording_and_streaming(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('record', '1', 'mod_jitsi');
        set_config('livebutton', '1', 'mod_jitsi');
        set_config('streamingoption', '0', 'mod_jitsi');

        $server = (object)['type' => 1];
        $buttons = \mod_jitsi\local\session::build_toolbar_buttons(
            $server,
            \context_system::instance(),
            true,
            false
        );

        $this->assertNotContains('recording', $buttons);
        $this->assertNotContains('livestreaming', $buttons);
    }

    /**
     * build_toolbar_buttons hides the recording button on GCP (type 3) servers, where the
     * Moodle-integrated record button is used instead.
     */
    public function test_build_toolbar_buttons_type3_omits_recording(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('record', '1', 'mod_jitsi');

        $server = (object)['type' => 3];
        $buttons = \mod_jitsi\local\session::build_toolbar_buttons(
            $server,
            \context_system::instance(),
            false,
            false
        );

        $this->assertNotContains('recording', $buttons);
    }

    /**
     * build_config_overwrite disables chat and polls together when chat is off.
     */
    public function test_build_config_overwrite_disables_chat_and_polls(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('chat', '0', 'mod_jitsi');

        $config = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );

        $this->assertTrue($config['disableChat']);
        $this->assertTrue($config['disablePolls']);
        $this->assertSame('Subject', $config['subject']);
    }

    /**
     * build_config_overwrite forces recording and live streaming off for private sessions,
     * without emitting the create()-only liveStreaming object.
     */
    public function test_build_config_overwrite_private_forces_recording_off(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('record', '1', 'mod_jitsi');
        set_config('livebutton', '1', 'mod_jitsi');

        $config = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            true,
            false
        );

        $this->assertFalse($config['fileRecordingsEnabled']);
        $this->assertFalse($config['liveStreamingEnabled']);
        $this->assertArrayNotHasKey('liveStreaming', $config);
    }

    /**
     * build_config_overwrite emits both liveStreaming keys when a non-private session disables it.
     */
    public function test_build_config_overwrite_disables_livestreaming_both_keys(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('livebutton', '0', 'mod_jitsi');

        $config = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );

        $this->assertFalse($config['liveStreamingEnabled']);
        $this->assertSame(['enabled' => false], $config['liveStreaming']);
    }

    /**
     * build_config_overwrite gives moderators only the grant-moderator lockdown and no remote mute.
     */
    public function test_build_config_overwrite_moderator_remote_menu(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        $config = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );

        $this->assertSame(['disableGrantModerator' => true], $config['remoteVideoMenu']);
        $this->assertArrayNotHasKey('disableRemoteMute', $config);
    }

    /**
     * build_config_overwrite locks down the remote video menu and remote mute for non-moderators.
     */
    public function test_build_config_overwrite_nonmoderator_remote_menu(): void {
        $this->resetAfterTest(true);

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id);
        $context = \context_module::instance($cm->id);
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $this->setUser($student);

        $config = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            $context,
            ['microphone'],
            false,
            false
        );

        $this->assertSame(
            ['disableKick' => true, 'disableGrantModerator' => true],
            $config['remoteVideoMenu']
        );
        $this->assertTrue($config['disableRemoteMute']);
    }

    /**
     * build_config_overwrite reveals the breakout-room buttons only when the setting is on.
     */
    public function test_build_config_overwrite_breakout_rooms_toggle(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        set_config('allowbreakoutrooms', '1', 'mod_jitsi');
        $on = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );
        $this->assertFalse($on['breakoutRooms']['hideAddRoomButton']);

        set_config('allowbreakoutrooms', '0', 'mod_jitsi');
        $off = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );
        $this->assertTrue($off['breakoutRooms']['hideAddRoomButton']);
    }

    /**
     * build_config_overwrite omits the dropbox block for 8x8 (type 2) servers but includes it
     * for other types when an app key is set.
     */
    public function test_build_config_overwrite_dropbox_by_server_type(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();
        set_config('dropbox_appkey', 'abc123', 'mod_jitsi');

        $type1 = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );
        $this->assertSame('abc123', $type1['dropbox']['appKey']);

        $type2 = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 2],
            (object)['name' => 'Subject'],
            \context_system::instance(),
            ['microphone'],
            false,
            false
        );
        $this->assertArrayNotHasKey('dropbox', $type2);
    }

    /**
     * build_config_overwrite serialises to valid JSON that is also a usable JS object literal.
     */
    public function test_build_config_overwrite_is_json_serialisable(): void {
        $this->resetAfterTest(true);
        $this->setAdminUser();

        $config = \mod_jitsi\local\session::build_config_overwrite(
            (object)['type' => 1],
            (object)['name' => "O'Brien & co"],
            \context_system::instance(),
            ['microphone', '', 'camera'],
            false,
            false
        );

        $json = json_encode($config, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $this->assertNotFalse($json);
        $decoded = json_decode($json, true);
        $this->assertSame("O'Brien & co", $decoded['subject']);
        $this->assertSame(['microphone', '', 'camera'], $decoded['toolbarButtons']);
    }

    /**
     * build_interface_config_overwrite carries the toolbar buttons and watermark link.
     */
    public function test_build_interface_config_overwrite(): void {
        $this->resetAfterTest(true);
        set_config('watermarklink', 'https://example.com/logo', 'mod_jitsi');

        $iface = \mod_jitsi\local\session::build_interface_config_overwrite(['microphone', 'camera']);

        $this->assertSame(['microphone', 'camera'], $iface['TOOLBAR_BUTTONS']);
        $this->assertTrue($iface['SHOW_JITSI_WATERMARK']);
        $this->assertSame('https://example.com/logo', $iface['JITSI_WATERMARK_LINK']);
    }
}
