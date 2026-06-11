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
 * Ad-hoc task that activates telemetry shortly after registration.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\task;

/**
 * Sends the first telemetry ping soon after a site registers.
 *
 * Queued by portal_register.php on registration. The license key is only
 * available once the admin confirms the e-mail, so this task retries on a few
 * hours' interval until the first ping succeeds (or it gives up), instead of
 * waiting for the weekly scheduled task's slot.
 *
 * @package mod_jitsi
 */
class activate_telemetry extends \core\task\adhoc_task {
    /** Maximum retry attempts (≈ every 4h → ~5 days of coverage). */
    const MAX_ATTEMPTS = 30;

    /** Delay between retries, in seconds. */
    const RETRY_DELAY = 4 * HOURSECS;

    /**
     * Returns the component that owns this task.
     */
    public function get_component(): string {
        return 'mod_jitsi';
    }

    /**
     * Attempt a telemetry ping; re-queue until the first success or the cap.
     */
    public function execute(): void {
        $data = $this->get_custom_data();
        $attempt = (int)($data->attempt ?? 0);

        $status = \mod_jitsi\local\telemetry::send();
        mtrace("mod_jitsi activate_telemetry (attempt {$attempt}): {$status}");

        // First successful ping (or a server-side deactivation): we are done.
        if ($status === 'pinged' || $status === 'deactivated') {
            return;
        }

        if ($attempt + 1 >= self::MAX_ATTEMPTS) {
            mtrace('mod_jitsi activate_telemetry: max attempts reached, giving up.');
            return;
        }

        // Not activated yet (e-mail not confirmed, or portal unreachable): retry.
        $next = new self();
        $next->set_component('mod_jitsi');
        $next->set_custom_data((object)['attempt' => $attempt + 1]);
        $next->set_next_run_time(time() + self::RETRY_DELAY);
        \core\task\manager::queue_adhoc_task($next);
    }
}
