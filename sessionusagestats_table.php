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
 * Table class for top courses in session usage statistics.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();
require_once($CFG->libdir . '/tablelib.php');

/**
 * Table to display top courses by Jitsi session usage.
 */
class mod_sessionusagestats_table extends table_sql {
    /**
     * Constructor
     * @param string $uniqueid Unique id for this table.
     */
    public function __construct($uniqueid) {
        parent::__construct($uniqueid);
        $columns = ['coursename', 'activityname', 'sessions', 'uniqueusers', 'minutes', 'avgtime'];
        $this->define_columns($columns);

        $headers = [
            get_string('course', 'jitsi'),
            get_string('activity', 'jitsi'),
            get_string('sessionsentered', 'jitsi'),
            get_string('uniqueusers', 'jitsi'),
            get_string('totaluserminutes', 'jitsi'),
            get_string('averagetimeperuser', 'jitsi'),
        ];
        $this->define_headers($headers);
    }

    /**
     * Format the course name column.
     *
     * @param object $values Row values.
     * @return string Formatted course name with link.
     */
    protected function col_coursename($values) {
        $urlcourse = new moodle_url('/course/view.php', ['id' => $values->courseid]);
        return '<a href="' . $urlcourse . '">' . format_string($values->coursename) . '</a>';
    }

    /**
     * Format the activity name column.
     *
     * @param object $values Row values.
     * @return string Formatted activity name with link.
     */
    protected function col_activityname($values) {
        if (!empty($values->cmid)) {
            $urlactivity = new moodle_url('/mod/jitsi/view.php', ['id' => $values->cmid]);
            return '<a href="' . $urlactivity . '">' . format_string($values->activityname) . '</a>';
        }
        return format_string($values->activityname);
    }
}
