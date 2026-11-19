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
 * Overview class to display information about the Jitsi module in the course overview (Moodle 5.0+).
 *
 * @package   mod_jitsi
 * @copyright 2024 Sergio Comerón Sánchez-Paniagua <jitsi@sergiocomeron.com>
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\courseformat;

use core_courseformat\activityoverviewbase;
use core_courseformat\local\overview\overviewitem;
use moodle_url;
use html_writer;

/**
 * Overview class to display information about the Jitsi module in the course overview (Moodle 5.0+).
 */
class overview extends activityoverviewbase {
    /**
     * Returns additional items to be displayed in the course overview.
     *
     * @return overviewitem[]
     */
    public function get_extra_overview_items(): array {
        return [
            'sessionstatus' => $this->get_session_timeopen_item(),
        ];
    }

    /**
     * Creates an item that displays the timeopen of the Jitsi session.
     *
     * @return overviewitem|null
     */
    private function get_session_timeopen_item(): ?overviewitem {
        global $DB;
        $jitsi = $DB->get_record('jitsi', ['id' => $this->cm->instance]);
        if ($jitsi->timeopen != 0) {
            return new overviewitem(
                name: get_string('timeopen', 'mod_jitsi'),
                value: $sessionactive ? 1 : 0,
                content: userdate($jitsi->timeopen),
            );
        } else {
            return null;
        }
    }

    /**
     * Return main action.
     *
     * @return overviewitem|null
     */
    public function get_actions_overview(): ?overviewitem {
        $url = new moodle_url('/mod/jitsi/view.php', ['id' => $this->cm->id]);
        $link = html_writer::link($url, get_string('joinmeeting', 'mod_jitsi'));

        return new overviewitem(
            name: get_string('action', 'mod_jitsi'),
            value: 'join',
            content: $link
        );
    }
}
