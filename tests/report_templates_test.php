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
 * Render tests for the usage stats and attendance report Mustache templates.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class report_templates_test extends \advanced_testcase {
    /**
     * The usage stats template renders cards, sections, tables and selectors.
     *
     * @covers \mod_jitsi
     */
    public function test_usage_stats_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/usage_stats', [
            'backurl' => 'https://example.com/admin/settings.php?section=modsettingjitsi',
            'backlabel' => 'Back to settings',
            'formhtml' => '<form id="filterform"></form>',
            'rowclass' => 'mb-4',
            'colclass' => 'col-md-3 col-sm-6 mb-3',
            'smallcards' => false,
            'cards' => [
                ['value' => 42, 'label' => 'Total sessions'],
                ['value' => '2h 30min', 'label' => 'Total minutes'],
            ],
            'nodatahtml' => null,
            'sections' => [
                [
                    'title' => 'Monthly usage',
                    'toplimit' => null,
                    'charthtml' => '<div id="mychart"></div>',
                    'tableclass' => 'mt-3',
                    'head' => ['Month', 'Sessions'],
                    'rows' => [
                        ['cells' => ['2026-01', 10]],
                        ['cells' => ['2026-02', 20]],
                    ],
                    'downloadhtml' => '<form id="dl-monthly"></form>',
                ],
                [
                    'title' => 'Top courses',
                    'toplimit' => [
                        'label' => 'Top limit',
                        'options' => [
                            ['n' => 10, 'url' => '#', 'current' => true, 'notfirst' => false],
                            ['n' => 25, 'url' => 'https://example.com/x?toplimit=25', 'current' => false, 'notfirst' => true],
                        ],
                    ],
                    'charthtml' => null,
                    'tableclass' => null,
                    'head' => ['Course'],
                    'rows' => [['cells' => ['<a href="https://example.com/course">C1</a>']]],
                    'downloadhtml' => '<form id="dl-courses"></form>',
                ],
            ],
        ]);

        $this->assertStringContainsString('filterform', $html);
        $this->assertStringContainsString('Total sessions', $html);
        $this->assertStringContainsString('Monthly usage', $html);
        $this->assertStringContainsString('mychart', $html);
        $this->assertStringContainsString('generaltable mt-3', $html);
        $this->assertStringContainsString('dl-monthly', $html);
        // Top limit selector: current option bold, other linked.
        $this->assertStringContainsString('<strong>10</strong>', $html);
        $this->assertStringContainsString('toplimit=25', $html);
        // Cell HTML is not double-escaped.
        $this->assertStringContainsString('<a href="https://example.com/course">C1</a>', $html);
    }

    /**
     * The attendance report template renders tabs, sessions table and recordings.
     *
     * @covers \mod_jitsi
     */
    public function test_attendance_report_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/attendance_report', [
            'backurl' => 'https://example.com/mod/jitsi/view.php?id=12',
            'backlabel' => 'My activity',
            'sessionintro' => ['<div class="alert" id="intro-notice">notice</div>'],
            'sessions' => [
                'rowclass' => 'mb-4',
                'colclass' => 'col-md-4 col-sm-6 mb-3',
                'smallcards' => false,
                'cards' => [['value' => 5, 'label' => 'Unique users']],
                'table' => [
                    'tableclass' => null,
                    'head' => ['<a href="#sort">Name ▲</a>', 'Sessions'],
                    'rows' => [['cells' => ['<a href="https://example.com/user">Alice</a>', 3]]],
                ],
                'downloadhtml' => '<form id="dl-attendance"></form>',
            ],
            'formhtml' => '<form id="dateform"></form>',
            'gcs' => [
                'recordings' => [
                    [
                        'title' => 'Recording 1 — 1 Jan',
                        'rowclass' => 'mb-2',
                        'colclass' => 'col-md-3 col-sm-6 mb-2',
                        'smallcards' => true,
                        'cards' => [['value' => 3, 'label' => 'Total plays']],
                        'heatmaphtml' => '<div class="jitsi-heatmap" id="hm-1"></div>',
                        'table' => [
                            'tableclass' => 'table-sm',
                            'head' => ['Name'],
                            'rows' => [['cells' => ['Alice']]],
                        ],
                        'last' => false,
                    ],
                    [
                        'title' => 'Recording 2 — 2 Jan',
                        'rowclass' => 'mb-2',
                        'colclass' => 'col-md-3 col-sm-6 mb-2',
                        'smallcards' => true,
                        'cards' => [['value' => 0, 'label' => 'Total plays']],
                        'heatmaphtml' => '',
                        'table' => null,
                        'last' => true,
                    ],
                ],
            ],
            'links' => [
                'recordings' => [
                    ['title' => 'External rec', 'table' => null, 'last' => true],
                ],
            ],
            'coursesections' => [
                [
                    'first' => true,
                    'title' => 'Activity overview',
                    'table' => [
                        'tableclass' => 'table-sm',
                        'head' => ['Activity'],
                        'rows' => [['cells' => ['Session A']]],
                    ],
                    'nodatahtml' => null,
                ],
                [
                    'first' => false,
                    'title' => 'Student engagement',
                    'table' => null,
                    'nodatahtml' => '<div id="students-nodata"></div>',
                ],
            ],
        ]);

        // Tabs with both BS4 and BS5 toggles.
        $this->assertStringContainsString('id="tab-sessions-link"', $html);
        $this->assertStringContainsString('data-toggle="tab"', $html);
        $this->assertStringContainsString('data-bs-toggle="tab"', $html);
        // Sessions tab.
        $this->assertStringContainsString('intro-notice', $html);
        $this->assertStringContainsString('Unique users', $html);
        $this->assertStringContainsString('<a href="#sort">Name ▲</a>', $html);
        $this->assertStringContainsString('dl-attendance', $html);
        // Recordings tab: GCS recording with table, second without (noviews text),
        // hr only between recordings.
        $this->assertStringContainsString('hm-1', $html);
        $this->assertStringContainsString('Recording 2 — 2 Jan', $html);
        $this->assertSame(1, substr_count($html, '<hr>'));
        // Course tab.
        $this->assertStringContainsString('Activity overview', $html);
        $this->assertStringContainsString('students-nodata', $html);
    }
}
