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

/**
 * Unit tests for the mod_jitsi data generator.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class generator_test extends \advanced_testcase {
    /**
     * create_recording() inserts both the source row and the linking record.
     *
     * @covers \mod_jitsi_generator::create_recording
     */
    public function test_create_recording_links_source_and_record(): void {
        global $DB;
        $this->resetAfterTest();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_jitsi');

        $rec = $generator->create_recording([
            'jitsiid' => $jitsi->id,
            'name' => 'Lesson 1',
            'link' => 'https://example.com/l1.mp4',
            'visible' => 0,
        ]);

        $record = $DB->get_record('jitsi_record', ['id' => $rec->id], '*', MUST_EXIST);
        $this->assertEquals($jitsi->id, $record->jitsi);
        $this->assertEquals('Lesson 1', $record->name);
        $this->assertEquals(0, $record->visible);
        $this->assertEquals(0, $record->deleted);

        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        $this->assertEquals('https://example.com/l1.mp4', $source->link);
    }

    /**
     * create_recording() applies sensible defaults (visible link, never expires).
     *
     * @covers \mod_jitsi_generator::create_recording
     */
    public function test_create_recording_defaults(): void {
        global $DB;
        $this->resetAfterTest();

        $course = $this->getDataGenerator()->create_course();
        $jitsi = $this->getDataGenerator()->create_module('jitsi', ['course' => $course->id]);
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_jitsi');

        $rec = $generator->create_recording(['jitsiid' => $jitsi->id, 'name' => 'Default']);

        $record = $DB->get_record('jitsi_record', ['id' => $rec->id], '*', MUST_EXIST);
        $this->assertEquals(1, $record->visible);

        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        $this->assertEquals(0, $source->timeexpires);
        $this->assertNotEmpty($source->link);
    }

    /**
     * create_recording() requires a jitsiid.
     *
     * @covers \mod_jitsi_generator::create_recording
     */
    public function test_create_recording_requires_jitsiid(): void {
        $this->resetAfterTest();
        $generator = $this->getDataGenerator()->get_plugin_generator('mod_jitsi');

        $this->expectException(\coding_exception::class);
        $generator->create_recording(['name' => 'Orphan']);
    }
}
