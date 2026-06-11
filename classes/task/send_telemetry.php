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
 * Weekly opt-in telemetry ping to the developer's stats endpoint.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\task;

/**
 * Sends anonymous usage data to the developer if the admin has opted in.
 */
class send_telemetry extends \core\task\scheduled_task {
    /**
     * Returns the task name.
     * @return string
     */
    public function get_name() {
        return get_string('task_send_telemetry', 'jitsi');
    }

    /**
     * Executes the task.
     */
    public function execute() {
        $status = \mod_jitsi\local\telemetry::send();
        mtrace('mod_jitsi send_telemetry: ' . $status);
    }
}
