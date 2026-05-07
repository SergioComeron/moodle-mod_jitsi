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

/**
 * Ensures every capability defined in db/access.php has a lang string in lang/en/jitsi.php.
 *
 * Moodle's Capability overview page calls get_string('jitsi:<name>', 'mod_jitsi') for
 * every capability. A missing string triggers a debugging notice on that page.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class lang_strings_test extends \advanced_testcase {
    /**
     * Every capability in db/access.php must have a matching lang string.
     *
     * @covers \mod_jitsi
     */
    public function test_capability_lang_strings_exist(): void {
        global $CFG;

        $capabilities = [];
        require($CFG->dirroot . '/mod/jitsi/db/access.php');

        $sm = get_string_manager();
        $missing = [];

        foreach (array_keys($capabilities) as $capname) {
            // Capability names are 'mod/jitsi:foo' — the string key is 'jitsi:foo'.
            $stringkey = str_replace('mod/', '', $capname);
            if (!$sm->string_exists($stringkey, 'mod_jitsi')) {
                $missing[] = $stringkey;
            }
        }

        $this->assertEmpty(
            $missing,
            'Missing lang strings for capabilities: ' . implode(', ', $missing)
            . '. Add them to lang/en/jitsi.php.'
        );
    }
}
