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

use mod_jitsi\external\get_recording_options;
use mod_jitsi\external\set_jibri_recording;
use mod_jitsi\external\state_record;
use mod_jitsi\local\session;
use mod_jitsi\output\mobile;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversMethod;

/**
 * Recording from the mobile app: options, recording flag and the mobile toolbar.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversClass(get_recording_options::class)]
#[CoversClass(set_jibri_recording::class)]
#[CoversClass(state_record::class)]
#[CoversMethod(session::class, 'recording_options')]
#[CoversMethod(mobile::class, 'mobile_session_view')]
final class mobile_recording_test extends \advanced_testcase {
    /**
     * Create and select a default server.
     *
     * @param int $type Server type.
     * @param array $fields Extra fields.
     * @return \stdClass
     */
    protected function set_server(int $type, array $fields = []): \stdClass {
        global $DB;
        $server = (object) ($fields + [
            'name' => 'Server ' . $type,
            'type' => $type,
            'domain' => 'jitsi.example.com',
            'appid' => 'app',
            'secret' => 'sec',
            'eightbyeightappid' => '',
            'eightbyeightapikeyid' => '',
            'privatekey' => '',
            'timecreated' => time(),
            'timemodified' => time(),
        ]);
        $server->id = $DB->insert_record('jitsi_servers', $server);
        set_config('server', $server->id, 'mod_jitsi');
        return $server;
    }

    /**
     * Create a course with an activity, a student and a teacher.
     *
     * @param array $data Extra activity fields.
     * @return array [jitsi, cm, student, teacher]
     */
    protected function create_activity(array $data = []): array {
        $this->setAdminUser();
        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id] + $data);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi->id, 0, false, MUST_EXIST);
        $student = $this->getDataGenerator()->create_and_enrol($course, 'student');
        $teacher = $this->getDataGenerator()->create_and_enrol($course, 'editingteacher');
        return [$jitsi, $cm, $student, $teacher];
    }

    /**
     * Web-like recording settings.
     *
     * @param array $settings Overrides.
     */
    protected function configure(array $settings = []): void {
        $settings += [
            'record' => 1,
            'recordingoption' => 1,
            'livebutton' => 1,
            'streamingoption' => 1,
            'dropbox_appkey' => '',
        ];
        foreach ($settings as $name => $value) {
            set_config($name, $value, 'mod_jitsi');
        }
    }

    /**
     * Call get_recording_options and clean the result like the web service layer does.
     *
     * @param int $cmid
     * @return array
     */
    protected function options(int $cmid): array {
        return \core_external\external_api::clean_returnvalue(
            get_recording_options::execute_returns(),
            get_recording_options::execute($cmid)
        );
    }

    /**
     * A student on a self-hosted server can neither record nor stream.
     */
    public function test_options_student_cannot_record(): void {
        $this->resetAfterTest();
        $this->configure(['dropbox_appkey' => 'dbkey-public']);
        $this->set_server(1);
        [$jitsi, $cm, $student] = $this->create_activity();
        $this->setUser($student);

        $this->assertSame([
            'canrecord' => false,
            'ismoderator' => false,
            'filerecording' => false,
            'streaming' => false,
            'dropbox' => false,
            'mode' => 'none',
            'streamingmode' => 'none',
        ], $this->options($cm->id));
    }

    /**
     * A teacher on a self-hosted server records from the Jitsi toolbar; no secrets are returned.
     */
    public function test_options_teacher_selfhosted_native(): void {
        $this->resetAfterTest();
        $this->configure(['dropbox_appkey' => 'dbkey-public']);
        $this->set_server(1, ['secret' => 'very-secret-value']);
        [$jitsi, $cm, , $teacher] = $this->create_activity();
        $this->setUser($teacher);

        $options = $this->options($cm->id);

        $this->assertTrue($options['canrecord']);
        $this->assertTrue($options['ismoderator']);
        $this->assertTrue($options['filerecording']);
        $this->assertSame('native', $options['mode']);
        $this->assertTrue($options['dropbox']);
        // Moodle streaming needs a YouTube account in use.
        $this->assertFalse($options['streaming']);
        $this->assertSame('none', $options['streamingmode']);
        $encoded = json_encode($options);
        $this->assertStringNotContainsString('dbkey-public', $encoded);
        $this->assertStringNotContainsString('very-secret-value', $encoded);
    }

    /**
     * Streaming follows streamingoption and the YouTube account in use.
     */
    public function test_options_streaming(): void {
        global $DB;
        $this->resetAfterTest();
        $this->set_server(1);
        [$jitsi, $cm, , $teacher] = $this->create_activity();

        $this->configure(['streamingoption' => 0]);
        $this->setUser($teacher);
        $options = $this->options($cm->id);
        $this->assertTrue($options['streaming']);
        $this->assertSame('native', $options['streamingmode']);

        $this->configure(['streamingoption' => 1]);
        $DB->insert_record('jitsi_record_account', (object) ['name' => 'yt', 'inuse' => 1, 'inqueue' => 0]);
        $options = $this->options($cm->id);
        $this->assertTrue($options['streaming']);
        $this->assertSame('moodle', $options['streamingmode']);

        $this->configure(['livebutton' => 0]);
        $this->assertFalse($this->options($cm->id)['streaming']);
    }

    /**
     * On 8x8 with recordingoption=1 and on GCP the Moodle record button is used; GCP needs Jibri.
     */
    public function test_options_moodle_button_servers(): void {
        $this->resetAfterTest();
        $this->configure();
        [$jitsi, $cm, , $teacher] = $this->create_activity();
        $this->setUser($teacher);

        $this->set_server(2, ['eightbyeightappid' => 'vpaas-x', 'appid' => '', 'secret' => '']);
        $options = $this->options($cm->id);
        $this->assertTrue($options['filerecording']);
        $this->assertSame('moodle', $options['mode']);

        $this->set_server(3, ['jibri_enabled' => 0]);
        $options = $this->options($cm->id);
        $this->assertFalse($options['filerecording']);
        $this->assertSame('none', $options['mode']);
    }

    /**
     * With record=0 nobody records.
     */
    public function test_options_record_disabled(): void {
        $this->resetAfterTest();
        $this->configure(['record' => 0]);
        $this->set_server(1);
        [$jitsi, $cm, , $teacher] = $this->create_activity();
        $this->setUser($teacher);

        $options = $this->options($cm->id);
        $this->assertTrue($options['canrecord']);
        $this->assertFalse($options['filerecording']);
        $this->assertSame('none', $options['mode']);
    }

    /**
     * The native mode matches the record button that build_toolbar_buttons() gives the web.
     */
    public function test_options_match_web_toolbar(): void {
        $this->resetAfterTest();
        [$jitsi, $cm, $student, $teacher] = $this->create_activity();
        $context = \context_module::instance($cm->id);
        $cases = [
            [0, ['record' => 1]], [1, ['record' => 1]], [1, ['record' => 0]], [1, ['streamingoption' => 0]],
            [2, ['recordingoption' => 0]], [2, ['recordingoption' => 1]], [3, []],
        ];
        foreach ($cases as [$type, $settings]) {
            $this->setAdminUser();
            $this->configure($settings);
            $server = $this->set_server($type);
            foreach ([$student, $teacher] as $user) {
                $this->setUser($user);
                $buttons = session::build_toolbar_buttons($server, $context, false, false);
                $options = $this->options($cm->id);
                $label = "type $type " . json_encode($settings) . " user {$user->id}";
                $this->assertSame(in_array('recording', $buttons, true), $options['mode'] === 'native', $label);
                $this->assertSame(
                    in_array('livestreaming', $buttons, true),
                    $options['streamingmode'] === 'native',
                    $label
                );
            }
        }
    }

    /**
     * Users without access to the course cannot read the options.
     */
    public function test_options_require_course_access(): void {
        $this->resetAfterTest();
        $this->set_server(1);
        [$jitsi, $cm] = $this->create_activity();
        $this->setUser($this->getDataGenerator()->create_user());

        $this->expectException(\require_login_exception::class);
        get_recording_options::execute($cm->id);
    }

    /**
     * set_jibri_recording does nothing for students or anonymous callers and works for teachers.
     */
    public function test_set_jibri_recording_requires_record(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi, $cm, $student, $teacher] = $this->create_activity();

        $this->setUser($student);
        $this->assertFalse(set_jibri_recording::execute($jitsi->id, 1));
        $this->assertNull($DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));

        $this->setUser(null);
        $this->assertFalse(set_jibri_recording::execute($jitsi->id, 1));
        $this->assertNull($DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));

        $this->setUser($teacher);
        $this->assertTrue(set_jibri_recording::execute($jitsi->id, 1));
        $this->assertSame('recording', $DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));
        $this->assertTrue(set_jibri_recording::execute($jitsi->id, 0));
        $this->assertNull($DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));
    }

    /**
     * set_jibri_recording validates the context: teachers of another course cannot set the flag.
     */
    public function test_set_jibri_recording_other_course(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi] = $this->create_activity();
        [, , , $otherteacher] = $this->create_activity();
        $this->setUser($otherteacher);

        try {
            set_jibri_recording::execute($jitsi->id, 1);
            $this->fail('A teacher of another course must not set the flag');
        } catch (\require_login_exception $e) {
            $this->assertNull($DB->get_field('jitsi', 'status', ['id' => $jitsi->id]));
        }
    }

    /**
     * state_record reports the real flag to participants and nothing to outsiders.
     */
    public function test_state_record_reads_status(): void {
        global $DB;
        $this->resetAfterTest();
        [$jitsi, $cm, $student, $teacher] = $this->create_activity();

        $this->setUser($student);
        $this->assertSame('recording0', state_record::execute($jitsi->id, 'true'));
        $DB->set_field('jitsi', 'status', 'recording', ['id' => $jitsi->id]);
        $this->assertSame('recording1', state_record::execute($jitsi->id, 'true'));
        $this->assertSame('recording1', state_record::execute($jitsi->id));
        $this->setUser($teacher);
        $this->assertSame('recording1', state_record::execute($jitsi->id, 'false'));

        $this->setUser(null);
        $this->assertSame('recording0', state_record::execute($jitsi->id, 'true'));
        $this->setUser($this->getDataGenerator()->create_user());
        $this->assertSame('recording0', state_record::execute($jitsi->id, 'true'));
        $this->assertSame('recording0', state_record::execute(999999, 'true'));
    }

    /**
     * The service definitions publish the recording functions to the app.
     */
    public function test_service_definitions(): void {
        global $CFG;
        $functions = [];
        require($CFG->dirroot . '/mod/jitsi/db/services.php');

        $this->assertTrue($functions['mod_jitsi_set_jibri_recording']['loginrequired']);
        foreach (['mod_jitsi_set_jibri_recording', 'mod_jitsi_get_recording_options', 'mod_jitsi_state_record'] as $name) {
            $this->assertContains(MOODLE_OFFICIAL_MOBILE_SERVICE, $functions[$name]['services'], $name);
            $this->assertContains('local_mobile', $functions[$name]['services'], $name);
        }
        $this->assertFalse($functions['mod_jitsi_state_record']['loginrequired']);
    }

    /**
     * The mobile toolbar shows the record button only to users who can record.
     */
    public function test_mobile_toolbar_record_button(): void {
        $this->resetAfterTest();
        $this->configure(['streamingoption' => 0]);
        $this->set_server(1);
        [$jitsi, $cm, $student, $teacher] = $this->create_activity();

        $toolbar = function () use ($cm): array {
            $result = mobile::mobile_session_view(['cmid' => $cm->id, 'appisdesktop' => false]);
            $config = json_decode($result['otherdata'], true)['config'];
            preg_match('/config\.toolbarButtons=([^&]*)/', $config, $m);
            return json_decode(urldecode($m[1]), true);
        };

        $this->setUser($student);
        $buttons = $toolbar();
        $this->assertNotContains('recording', $buttons);
        $this->assertNotContains('livestreaming', $buttons);

        $this->setUser($teacher);
        $buttons = $toolbar();
        $this->assertContains('recording', $buttons);
        $this->assertContains('livestreaming', $buttons);
    }
}
