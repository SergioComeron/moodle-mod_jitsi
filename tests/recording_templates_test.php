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
 * Render tests for the recordings tab Mustache templates.
 *
 * @package    mod_jitsi
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class recording_templates_test extends \advanced_testcase {
    /**
     * Common action context shared by the row templates.
     *
     * @return array
     */
    private function actions(): array {
        return [
            'candelete'     => true,
            'canhidetoggle' => true,
            'visible'       => true,
            'canedit'       => true,
            'recordid'      => 5,
            'cmid'          => 12,
        ];
    }

    /**
     * The video template renders the player and action buttons.
     *
     * @covers \mod_view_table
     */
    public function test_video_template_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/view_recording_video', array_merge($this->actions(), [
            'inplacename'    => '<span>Rec</span>',
            'timecreated'    => '1 January 2026',
            'aidropdown'     => '',
            'videoid'        => 'jitsi-video-9',
            'sourcerecordid' => 9,
            'embedurl'       => 'https://storage.googleapis.com/b/r.mp4',
            'barhtml'        => '',
            'heatmaphtml'    => '',
            'aiaccordion'    => '',
        ]));
        $this->assertStringContainsString('jitsi-video-9', $html);
        $this->assertStringContainsString('data-action="delete"', $html);
        $this->assertStringContainsString('data-action="edit"', $html);
        $this->assertStringContainsString('data-sourcerecordid="9"', $html);
    }

    /**
     * The external template renders the open/download button.
     *
     * @covers \mod_view_table
     */
    public function test_external_template_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/view_recording_external', array_merge($this->actions(), [
            'inplacename'    => '<span>Rec</span>',
            'timecreated'    => '1 January 2026',
            'jibriwarn'      => '',
            'openurl'        => 'https://8x8.vc/rec',
            'openlabel'      => 'Download',
            'sourcerecordid' => 9,
        ]));
        $this->assertStringContainsString('jitsi-recording-link', $html);
        $this->assertStringContainsString('https://8x8.vc/rec', $html);
        $this->assertStringContainsString('data-action="delete"', $html);
    }

    /**
     * The YouTube template renders the iframe and (optionally) actions.
     *
     * @covers \mod_view_table
     */
    public function test_youtube_template_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/view_recording_youtube', [
            'inplacename'    => '<span>Rec</span>',
            'timecreated'    => '1 January 2026',
            'showactions'    => true,
            'candelete'      => true,
            'canhidetoggle'  => true,
            'visible'        => false,
            'canedit'        => false,
            'recordid'       => 5,
            'cmid'           => 12,
            'embedlink'      => 'dQw4w9WgXcQ',
            'branch5'        => true,
            'alignmentclass' => 'text-end',
        ]);
        $this->assertStringContainsString('youtube.com/embed/dQw4w9WgXcQ', $html);
        $this->assertStringContainsString('data-action="show"', $html);
        $this->assertStringNotContainsString('data-action="edit"', $html);
    }

    /**
     * The add/edit form template renders inputs and submit button.
     *
     * @covers \mod_view_table
     */
    public function test_form_template_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/view_recording_form', [
            'formtitle'    => 'Add a recording link',
            'cmid'         => 12,
            'recordid'     => '',
            'url'          => '',
            'name'         => '',
            'isdropbox'    => false,
            'embedchecked' => false,
            'submitlabel'  => 'Add a recording link',
            'iscancel'     => false,
            'cancelurl'    => '#',
        ]);
        $this->assertStringContainsString('jitsi-recording-form', $html);
        $this->assertStringContainsString('data-cmid="12"', $html);
        $this->assertStringContainsString('recordingurl', $html);
    }
}
