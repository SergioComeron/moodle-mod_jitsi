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
 * Event fired when a user enters a private Jitsi session.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\event;

/**
 * Event fired when a user enters a private Jitsi session.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class jitsi_private_session_enter extends \core\event\base {
    /**
     * Create instance of event.
     *
     * @param int $peerid  ID of the peer user in the private session
     * @return jitsi_private_session_enter
     */
    public static function event_with_peer($peerid) {
        $data = [
            'context' => \context_system::instance(),
            'other'   => [
                'peerid' => $peerid,
            ],
        ];
        return self::create($data);
    }

    /**
     * Init method.
     */
    protected function init() {
        $this->data['crud'] = 'r';
        $this->data['edulevel'] = self::LEVEL_PARTICIPATING;
    }

    /**
     * Return localised event name.
     *
     * @return string
     */
    public static function get_name() {
        return get_string('enterprivatesession', 'jitsi');
    }

    /**
     * Returns description of what happened.
     *
     * @return string
     */
    public function get_description() {
        return "The user with id '{$this->userid}' entered a private Jitsi session with peer id '{$this->other['peerid']}'.";
    }

    /**
     * Custom validation.
     *
     * @throws \coding_exception
     */
    protected function validate_data() {
        parent::validate_data();
        if (!isset($this->other['peerid'])) {
            throw new \coding_exception('The \'peerid\' value must be set in event other data.');
        }
    }

    /**
     * Get url related to the action.
     *
     * @return \moodle_url
     */
    public function get_url() {
        return new \moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $this->other['peerid']]);
    }

    /**
     * Mapping between log fields and event properties.
     */
    public static function get_objectid_mapping() {
        return false;
    }
}
