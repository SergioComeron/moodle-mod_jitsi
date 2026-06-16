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
 * Behat data generator for mod_jitsi.
 *
 * @package    mod_jitsi
 * @category   test
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class behat_mod_jitsi_generator extends behat_generator_base {
    /**
     * Get a list of the entities that Behat can create using the generator step.
     *
     * @return array
     */
    protected function get_creatable_entities(): array {
        return [
            'recordings' => [
                'singular' => 'recording',
                'datagenerator' => 'recording',
                'required' => ['jitsi', 'name'],
                'switchids' => ['jitsi' => 'jitsiid', 'user' => 'userid'],
            ],
        ];
    }

    /**
     * Resolve a jitsi instance id from an activity idnumber.
     *
     * @param string $idnumber the activity idnumber
     * @return int the jitsi instance id
     */
    protected function get_jitsi_id(string $idnumber): int {
        $cm = $this->get_cm_by_activity_name('jitsi', $idnumber);

        return $cm->instance;
    }
}
