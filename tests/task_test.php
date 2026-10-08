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

use PHPUnit\Framework\Attributes\CoversMethod;

defined('MOODLE_INTERNAL') || die();

/**
 * Unit tests for mod_jitsi scheduled tasks.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
#[CoversMethod(\mod_jitsi\task\cron_task_delete::class, 'execute')]
final class task_test extends \advanced_testcase {
    /**
     * cron_task_delete must not fatal when a jitsi_record points at a missing
     * source record: it should remove the orphan row and keep processing.
     */
    public function test_cron_task_delete_handles_orphan_source(): void {
        global $DB;
        $this->resetAfterTest(true);
        set_config('numbervideosdeleted', 10, 'mod_jitsi');
        set_config('videosexpiry', 3600, 'mod_jitsi');

        // Orphan record: deleted=1 and source points to a non-existent jitsi_source_record.
        $orphanid = $DB->insert_record('jitsi_record', (object)[
            'jitsi'   => 1,
            'source'  => 999999,
            'deleted' => 1,
            'visible' => 1,
            'name'    => 'orphan',
        ]);

        $task = new \mod_jitsi\task\cron_task_delete();
        // Would fatal on $source->timecreated before the fix. Buffer the task's mtrace output.
        ob_start();
        $task->execute();
        ob_end_clean();

        $this->assertFalse($DB->record_exists('jitsi_record', ['id' => $orphanid]));
    }
}
