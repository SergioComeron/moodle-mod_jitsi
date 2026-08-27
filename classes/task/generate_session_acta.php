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

/**
 * Ad-hoc task to generate session minutes (acta) via Vertex or BYOK.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;

use mod_jitsi\local\acta;

/**
 * Ad-hoc task: build summary + pendientes from attendance and an optional transcript.
 *
 * Custom data expected:
 *   - actaid (int): ID of the jitsi_session_acta row
 *
 * @package mod_jitsi
 */
class generate_session_acta extends \core\task\adhoc_task {
    /**
     * Returns the component that owns this task.
     *
     * @return string
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Localised task name for the scheduled-task admin page and tests.
     *
     * @return string
     */
    public function get_name() {
        return get_string('task_generate_session_acta', 'jitsi');
    }

    /**
     * Execute the task.
     */
    public function execute(): void {
        $data = $this->get_custom_data();
        if (empty($data->actaid)) {
            mtrace('generate_session_acta: missing actaid in custom data');
            return;
        }
        acta::generate((int)$data->actaid);
        mtrace('generate_session_acta: processed acta ' . (int)$data->actaid);
    }
}
