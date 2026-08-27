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

use mod_jitsi\local\acta;
use mod_jitsi\local\acta_llm;
use mod_jitsi\local\vertex_ai;
use PHPUnit\Framework\Attributes\CoversClass;

defined('MOODLE_INTERNAL') || die();

/**
 * Tests for session minutes (acta).
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(acta::class)]
#[CoversClass(acta_llm::class)]
final class acta_test extends \advanced_testcase {
    /**
     * Store the existing Vertex service-account JSON and a GCP project.
     */
    protected function store_vertex_service_account(): void {
        set_config('gcp_project', 'acta-test-project', 'mod_jitsi');
        $fs = get_file_storage();
        $syscontext = \context_system::instance();
        $fs->create_file_from_string([
            'contextid' => $syscontext->id,
            'component' => 'mod_jitsi',
            'filearea' => 'gcpserviceaccountjson',
            'itemid' => 0,
            'filepath' => '/',
            'filename' => 'service-account.json',
        ], '{"type":"service_account","project_id":"acta-test-project"}');
    }

    /**
     * Insert a participating log used by the existing attendance counters.
     *
     * @param int $cmid Course module id
     * @param int $userid User id
     * @param int $timecreated Unix timestamp
     */
    protected function insert_participating_log(int $cmid, int $userid, int $timecreated): void {
        global $DB;
        $DB->insert_record('logstore_standard_log', (object)[
            'eventname' => '\\mod_jitsi\\event\\jitsi_session_participating',
            'component' => 'mod_jitsi',
            'action' => 'participating',
            'target' => 'session',
            'crud' => 'r',
            'edulevel' => 0,
            'contextid' => 1,
            'contextlevel' => CONTEXT_MODULE,
            'contextinstanceid' => $cmid,
            'userid' => $userid,
            'anonymous' => 0,
            'timecreated' => $timecreated,
        ]);
    }

    /**
     * Without Vertex or a BYOK key the feature stays off.
     */
    public function test_unavailable_without_key(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $this->assertFalse(acta::is_available($jitsi));
        $this->assertNull(acta::provider($jitsi));
        $this->assertNull(acta::credentials($jitsi));
        $this->assertSame(0, acta::queue_from_session_end($jitsi, (int)$jitsi->cmid));
    }

    /**
     * Site enable without Vertex or a key still leaves the feature off.
     */
    public function test_site_enable_without_key_stays_off(): void {
        $this->resetAfterTest();
        set_config('actaenabled', 1, 'mod_jitsi');
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $this->assertFalse(acta::is_available($jitsi));
        $this->assertNull(acta::provider($jitsi));
        $this->assertFalse(vertex_ai::is_configured());
    }

    /**
     * An activity-level key is used when acta is enabled and Vertex is not configured.
     */
    public function test_activity_key_enables_feature(): void {
        $this->resetAfterTest();
        set_config('actaenabled', 1, 'mod_jitsi');
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        acta::save_activity_key((int)$jitsi->id, 'sk-activity');
        $this->assertSame(acta::PROVIDER_BYOK, acta::provider($jitsi));
        $creds = acta::credentials($jitsi);
        $this->assertNotNull($creds);
        $this->assertSame('sk-activity', $creds['apikey']);
    }

    /**
     * An activity key alone does not enable acta while the site toggle is off.
     */
    public function test_activity_key_without_site_enable_stays_off(): void {
        $this->resetAfterTest();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        acta::save_activity_key((int)$jitsi->id, 'sk-activity');
        $this->assertNull(acta::provider($jitsi));
        $this->assertNull(acta::credentials($jitsi));
        $this->assertFalse(acta::is_available($jitsi));
    }

    /**
     * Vertex configured (existing project + service-account JSON) wins over BYOK.
     */
    public function test_provider_prefers_vertex_over_byok(): void {
        $this->resetAfterTest();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');
        $this->store_vertex_service_account();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $this->assertTrue(vertex_ai::is_configured());
        $this->assertSame(acta::PROVIDER_VERTEX, acta::provider($jitsi));
        $this->assertTrue(acta::is_available($jitsi));
        $this->assertNotNull(acta::credentials($jitsi));
    }

    /**
     * Without Vertex, a site BYOK key is the backend.
     */
    public function test_provider_byok_when_vertex_not_configured(): void {
        $this->resetAfterTest();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $this->assertFalse(vertex_ai::is_configured());
        $this->assertSame(acta::PROVIDER_BYOK, acta::provider($jitsi));
        $this->assertTrue(acta::is_available($jitsi));
    }

    /**
     * Vertex without a BYOK key still enables acta.
     */
    public function test_provider_vertex_without_byok(): void {
        $this->resetAfterTest();
        set_config('actaenabled', 1, 'mod_jitsi');
        $this->store_vertex_service_account();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);

        $this->assertSame(acta::PROVIDER_VERTEX, acta::provider($jitsi));
        $this->assertNull(acta::credentials($jitsi));
        $this->assertTrue(acta::is_available($jitsi));
    }

    /**
     * Hang-up without Vertex or a key does not create an acta and still fires the audit event.
     */
    public function test_hangup_without_key_does_not_create_acta(): void {
        global $DB;
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('actaenabled', 1, 'mod_jitsi');
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);

        $sink = $this->redirectEvents();
        \mod_jitsi\external\press_button_end::execute($jitsi->id, 0, $cm->id);
        $events = $sink->get_events();

        $this->assertCount(1, $events);
        $this->assertInstanceOf(\mod_jitsi\event\jitsi_press_button_end::class, $events[0]);
        $this->assertFalse($DB->record_exists('jitsi_session_acta', ['jitsi' => $jitsi->id]));
        $this->assertEmpty(\core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_session_acta::class));
    }

    /**
     * A teacher hang-up with Vertex configured (no BYOK) queues minutes.
     */
    public function test_teacher_hangup_queues_acta_with_vertex(): void {
        global $DB;
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('actaenabled', 1, 'mod_jitsi');
        $this->store_vertex_service_account();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $this->assertSame(acta::PROVIDER_VERTEX, acta::provider($jitsi));

        \mod_jitsi\external\press_button_end::execute($jitsi->id, 0, $cm->id);

        $this->assertTrue($DB->record_exists('jitsi_session_acta', ['jitsi' => $jitsi->id, 'status' => 'pending']));
        $tasks = \core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_session_acta::class);
        $this->assertNotEmpty($tasks);
    }

    /**
     * generate() with neither Vertex nor BYOK does not throw and does not invent minutes.
     */
    public function test_generate_without_llm_does_not_block(): void {
        global $DB;
        $this->resetAfterTest();
        $this->setAdminUser();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);

        $actaid = (int)$DB->insert_record('jitsi_session_acta', (object)[
            'jitsi' => $jitsi->id,
            'cmid' => $cm->id,
            'userid' => 2,
            'sessionstart' => time() - 60,
            'sessionend' => time(),
            'status' => 'pending',
            'timecreated' => time(),
            'timemodified' => time(),
        ]);

        acta::generate($actaid);

        $acta = $DB->get_record('jitsi_session_acta', ['id' => $actaid], '*', MUST_EXIST);
        $this->assertSame('error', $acta->status);
        $this->assertNotEmpty($acta->error);
        $this->assertEmpty($acta->summary);
    }

    /**
     * A teacher hang-up with BYOK configured queues minutes for the attendance window.
     */
    public function test_teacher_hangup_queues_acta(): void {
        global $DB;
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $this->insert_participating_log((int)$cm->id, (int)$student->id, time() - 60);

        \mod_jitsi\external\press_button_end::execute($jitsi->id, 0, $cm->id);

        $this->assertTrue($DB->record_exists('jitsi_session_acta', ['jitsi' => $jitsi->id, 'status' => 'pending']));
        $tasks = \core\task\manager::get_adhoc_tasks(\mod_jitsi\task\generate_session_acta::class);
        $this->assertNotEmpty($tasks);
    }

    /**
     * Students hanging up do not queue minutes.
     */
    public function test_student_hangup_does_not_queue_acta(): void {
        global $DB;
        $this->resetAfterTest();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $this->setUser($student);

        \mod_jitsi\external\press_button_end::execute($jitsi->id, (int)$student->id, $cm->id);
        $this->assertFalse($DB->record_exists('jitsi_session_acta', ['jitsi' => $jitsi->id]));
    }

    /**
     * Generation stores summary, reused attendance and pendientes; payload has no recording URL.
     */
    public function test_generate_uses_transcript_not_recording(): void {
        global $DB, $USER;
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $now = time();
        $this->insert_participating_log((int)$cm->id, (int)$student->id, $now - 90);
        $this->insert_participating_log((int)$cm->id, (int)$student->id, $now - 30);

        $generator = $this->getDataGenerator()->get_plugin_generator('mod_jitsi');
        $recording = $generator->create_recording([
            'jitsiid' => $jitsi->id,
            'link' => 'https://storage.googleapis.com/secret-bucket/full-recording.mp4',
            'timecreated' => $now - 20,
        ]);
        $DB->set_field(
            'jitsi_source_record',
            'ai_transcription',
            '[00:00] Please finish exercise three for next week.',
            ['id' => $recording->source]
        );

        $actaid = acta::queue_from_session_end($jitsi, (int)$cm->id, true);
        $this->assertGreaterThan(0, $actaid);

        $seenuser = '';
        acta::generate($actaid, static function (string $system, string $user) use (&$seenuser): string {
            $seenuser = $system . "\n" . $user;
            return json_encode([
                'summary' => 'The class assigned exercise three.',
                'action_items' => ['Finish exercise three'],
            ]);
        });

        $this->assertStringContainsString('JSON object', $seenuser);
        $this->assertStringContainsString('exercise three', $seenuser);
        $this->assertStringNotContainsString('storage.googleapis.com', $seenuser);
        $this->assertStringNotContainsString('full-recording.mp4', $seenuser);
        $this->assertStringNotContainsString('sk-site', $seenuser);

        $acta = $DB->get_record('jitsi_session_acta', ['id' => $actaid], '*', MUST_EXIST);
        $this->assertSame('ready', $acta->status);
        $this->assertSame('transcript', $acta->source);
        $this->assertStringContainsString('exercise three', $acta->summary);
        $this->assertStringContainsString('Finish exercise three', $acta->actionitems);
        $attendees = json_decode($acta->attendancejson, true);
        $this->assertSame((int)$student->id, (int)$attendees[0]['userid']);
        $this->assertSame(2, (int)$attendees[0]['minutes']);
        $this->assertSame((int)$USER->id, (int)$acta->userid);
    }

    /**
     * Without a transcript the prompt forbids invented topics and still stores attendance.
     */
    public function test_generate_without_transcript_uses_metadata_only(): void {
        global $DB;
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $this->insert_participating_log((int)$cm->id, (int)$student->id, time() - 30);

        $actaid = acta::queue_from_session_end($jitsi, (int)$cm->id, true);
        $seenuser = '';
        acta::generate($actaid, static function (string $system, string $user) use (&$seenuser): string {
            $seenuser = $system . "\n" . $user;
            return json_encode([
                'summary' => 'Minutes from attendance only.',
                'action_items' => [],
            ]);
        });

        $this->assertStringContainsString('No transcript is available', $seenuser);
        $acta = $DB->get_record('jitsi_session_acta', ['id' => $actaid], '*', MUST_EXIST);
        $this->assertSame('metadata', $acta->source);
        $this->assertSame('ready', $acta->status);
        $this->assertSame('[]', $acta->actionitems);
    }

    /**
     * Completions URL helper appends the chat path only when needed.
     */
    public function test_completions_url_normalises_endpoint(): void {
        $this->assertSame(
            'https://api.openai.com/v1/chat/completions',
            acta_llm::completions_url('https://api.openai.com/v1')
        );
        $this->assertSame(
            'https://api.openai.com/v1/chat/completions',
            acta_llm::completions_url('https://api.openai.com/v1/chat/completions')
        );
        $this->assertSame(
            'https://api.openai.com/v1/chat/completions',
            acta_llm::completions_url('')
        );
    }

    /**
     * JSON object parser accepts fenced replies.
     */
    public function test_parse_json_object_strips_fences(): void {
        $parsed = acta_llm::parse_json_object("```json\n{\"summary\":\"Hi\",\"action_items\":[]}\n```");
        $this->assertSame('Hi', $parsed['summary']);
        $this->assertSame([], $parsed['action_items']);
    }

    /**
     * Teachers see the acta block; students with only view do not.
     */
    public function test_export_for_view_is_teacher_only(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        set_config('actaenabled', 1, 'mod_jitsi');
        set_config('acta_apikey', 'sk-site', 'mod_jitsi');

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, $course->id, false, MUST_EXIST);
        $context = \context_module::instance($cm->id);

        $this->assertNotNull(acta::export_for_view($jitsi, $cm, $context));

        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $this->setUser($student);
        $this->assertNull(acta::export_for_view($jitsi, $cm, $context));
    }
}
