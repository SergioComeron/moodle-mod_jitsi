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

namespace mod_jitsi\output;

/**
 * Layout shell for a Jitsi session: status line, action buttons and the iframe container.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class session_page {
    /**
     * Build the Mustache context for the session layout.
     *
     * @param bool $textend True on Moodle 5.0+ (text-end utility class instead of text-right)
     * @param bool $showstreaming Whether the live streaming button should be shown
     * @param bool $showrecording Whether the Moodle recording button (GCP Jibri or 8x8 cloud) should be shown
     * @return array Template context
     */
    public static function context(bool $textend, bool $showstreaming, bool $showrecording): array {
        return [
            'textend'        => $textend,
            'showbuttons'    => $showstreaming || $showrecording,
            'showstreaming'  => $showstreaming,
            'showrecording'  => $showrecording,
            'streambtnlabel' => get_string('streambtn', 'jitsi'),
            'recordbtnlabel' => get_string('recordbtn', 'jitsi'),
        ];
    }

    /**
     * Render the session layout HTML.
     *
     * @param bool $textend True on Moodle 5.0+ (text-end utility class instead of text-right)
     * @param bool $showstreaming Whether the live streaming button should be shown
     * @param bool $showrecording Whether the Moodle recording button (GCP Jibri or 8x8 cloud) should be shown
     * @return string
     */
    public static function render(bool $textend, bool $showstreaming, bool $showrecording): string {
        global $OUTPUT;
        return $OUTPUT->render_from_template(
            'mod_jitsi/session_page',
            self::context($textend, $showstreaming, $showrecording)
        );
    }
}
