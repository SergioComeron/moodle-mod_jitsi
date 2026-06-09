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
 * Render tests for the server management Mustache templates.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class server_templates_test extends \advanced_testcase {
    /**
     * The server table renders a non-GCP row with edit/delete and a GCP row
     * with the pre-rendered Start/Stop/wait controls.
     *
     * @covers \mod_jitsi
     */
    public function test_server_table_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/server_table', [
            'settingsurl' => 'https://example.com/admin/settings.php?section=modsettingjitsi',
            'addserverurl' => 'https://example.com/mod/jitsi/servermanagement.php?action=add',
            'servers' => [
                [
                    'id' => 3,
                    'name' => 'My server',
                    'typelabel' => 'Self-hosted (JWT)',
                    'isgcp' => false,
                    'domain' => 'meet.example.com',
                    'statusclass' => 'bg-secondary',
                    'statustext' => 'N/A',
                    'statustitle' => '',
                    'jibripool' => null,
                    'jibrilegacy' => null,
                    'editurl' => 'https://example.com/mod/jitsi/servermanagement.php?action=edit&id=3',
                    'gcp' => null,
                    'gcs' => null,
                    'addjibriurl' => null,
                    'deleteurl' => 'https://example.com/mod/jitsi/servermanagement.php?action=delete&id=3',
                ],
                [
                    'id' => 4,
                    'name' => 'GCP server',
                    'typelabel' => '🌩️ GCP Auto-Managed',
                    'isgcp' => true,
                    'domain' => 'jitsi.example.com',
                    'statusclass' => 'bg-success',
                    'statustext' => '🟢 Running',
                    'statustitle' => '',
                    'jibripool' => [
                        'serverid' => 4,
                        'poolsize' => 2,
                        'entries' => [
                            [
                                'badgeclass' => 'bg-success',
                                'badgetext' => '✅ idle',
                                'title' => 'jibri-2601010101',
                                'deleteurl' => 'https://example.com/x?action=deletejibrientry',
                            ],
                        ],
                        'addurl' => 'https://example.com/x?action=addtojibripool',
                    ],
                    'jibrilegacy' => null,
                    'editurl' => null,
                    'gcp' => [
                        'serverid' => 4,
                        'starturl' => 'https://example.com/x?action=gcpstart',
                        'stopurl' => 'https://example.com/x?action=gcpstop',
                        'showstart' => false,
                        'showstop' => true,
                        'showwait' => false,
                    ],
                    'gcs' => [
                        'url' => 'https://example.com/x?action=enablegcs',
                        'label' => 'Enable GCS',
                        'buttonclass' => 'btn-outline-secondary',
                    ],
                    'addjibriurl' => null,
                    'deleteurl' => 'https://example.com/x?action=delete',
                ],
            ],
        ]);

        // Header controls and modal shell.
        $this->assertStringContainsString('btn-creategcpvm', $html);
        $this->assertStringContainsString('id="gcpModal"', $html);

        // Non-GCP row: edit link, no GCP controls.
        $this->assertStringContainsString('action=edit&amp;id=3', $html);

        // GCP row: status badge, pre-rendered controls with visibility classes.
        $this->assertStringContainsString('gcp-status-4', $html);
        $this->assertStringContainsString('jitsi-gcp-actions', $html);
        $this->assertStringContainsString('jitsi-gcp-start d-none', $html);
        $this->assertStringContainsString('jitsi-gcp-stop"', $html);
        $this->assertStringContainsString('jitsi-poolsize-input', $html);
        $this->assertStringContainsString('data-serverid="4"', $html);
    }

    /**
     * The add-Jibri confirmation page renders the script and the confirm form.
     *
     * @covers \mod_jitsi
     */
    public function test_addjibri_confirm_renders(): void {
        global $OUTPUT;
        $this->resetAfterTest(true);
        $html = $OUTPUT->render_from_template('mod_jitsi/addjibri_confirm', [
            'hostname' => 'meet.example.com',
            'script' => "#!/bin/bash\necho reconfigure",
            'confirmurl' => 'https://example.com/mod/jitsi/servermanagement.php?action=addjibri&id=3&confirm=1',
            'cancelurl' => 'https://example.com/mod/jitsi/servermanagement.php',
            'sesskey' => 'abc123',
        ]);

        $this->assertStringContainsString('jibri-reconfig-script', $html);
        $this->assertStringContainsString('copy-reconfig-script', $html);
        $this->assertStringContainsString('echo reconfigure', $html);
        $this->assertStringContainsString('name="jibrimachinetype"', $html);
        $this->assertStringContainsString('name="sesskey" value="abc123"', $html);
    }
}
