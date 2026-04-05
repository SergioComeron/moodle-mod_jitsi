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
 * A scheduled task for guacamole cron.
 *
 * @package    mod_jitsi
 * @copyright  2023 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace mod_jitsi\task;
defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/mod/jitsi/lib.php');

/**
 * A scheduled task class.
 *
 * @package    mod_jitsi
 */
class cron_task_delete extends \core\task\scheduled_task {
    /**
     * Get a descriptive name for this task (shown to admins).
     *
     * @return string
     */
    public function get_name() {
        return get_string('crontaskdelete', 'jitsi');
    }

    /**
     * Run jitsi cron.
     */
    public function execute() {
        global $DB;

        $recordstodelete = $DB->get_records(
            'jitsi_record',
            ['deleted' => 1],
            '',
            '*',
            0,
            get_config('mod_jitsi', 'numbervideosdeleted')
        );
        mtrace("Date: " . userdate(time()));
        mtrace("Deleting until: " . userdate(time() - get_config('mod_jitsi', 'videosexpiry')));
        foreach ($recordstodelete as $recordtodelete) {
            $source = $DB->get_record('jitsi_source_record', ['id' => $recordtodelete->source]);
            if (($source->timecreated < time() - get_config('mod_jitsi', 'videosexpiry'))) {
                if (deleterecordyoutube($source->id)) {
                    mtrace("Deleting source: " . $source->link . " from " . userdate($source->timecreated));
                    $DB->delete_records('jitsi_source_record', ['id' => $recordtodelete->source]);
                    mtrace("Deleting record: " . $recordtodelete->name);
                    $DB->delete_records('jitsi_record', ['id' => $recordtodelete->id]);
                } else {
                    mtrace("Could not delete source: " . $source->link);
                }
            }
        }
        return true;
    }
}
