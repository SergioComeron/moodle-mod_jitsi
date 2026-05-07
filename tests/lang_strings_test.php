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
 * Ensures lang strings referenced from code exist in lang/en/jitsi.php.
 *
 * Covers capabilities, scheduled/ad-hoc task names, event names, and the
 * plugin strings required by Moodle core. A missing string causes a debugging
 * notice or a broken UI — these tests catch regressions before release.
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

    /**
     * Every task class must return a non-empty name without triggering a debugging notice.
     *
     * @covers \mod_jitsi
     */
    public function test_task_get_name_strings_exist(): void {
        global $CFG;

        $this->resetAfterTest();

        $taskdir = $CFG->dirroot . '/mod/jitsi/classes/task';
        $failed = [];

        foreach (glob($taskdir . '/*.php') as $file) {
            $classname = '\\mod_jitsi\\task\\' . basename($file, '.php');
            require_once($file);

            if (!class_exists($classname)) {
                continue;
            }

            $task = new $classname();
            $this->resetDebugging();
            $name = $task->get_name();
            $debugs = $this->getDebuggingMessages();

            if (!empty($debugs) || $name === '') {
                $failed[] = $classname;
            }
        }

        $this->assertEmpty(
            $failed,
            'Tasks with missing or empty lang strings for get_name(): ' . implode(', ', $failed)
            . '. Add the required strings to lang/en/jitsi.php.'
        );
    }

    /**
     * Every event class must return a non-empty name without triggering a debugging notice.
     *
     * @covers \mod_jitsi
     */
    public function test_event_get_name_strings_exist(): void {
        global $CFG;

        $this->resetAfterTest();

        $eventdir = $CFG->dirroot . '/mod/jitsi/classes/event';
        $failed = [];

        foreach (glob($eventdir . '/*.php') as $file) {
            $classname = '\\mod_jitsi\\event\\' . basename($file, '.php');
            require_once($file);

            if (!class_exists($classname)) {
                continue;
            }

            $this->resetDebugging();
            $name = $classname::get_name();
            $debugs = $this->getDebuggingMessages();

            if (!empty($debugs) || $name === '') {
                $failed[] = $classname;
            }
        }

        $this->assertEmpty(
            $failed,
            'Events with missing or empty lang strings for get_name(): ' . implode(', ', $failed)
            . '. Add the required strings to lang/en/jitsi.php.'
        );
    }

    /**
     * Moodle core requires certain plugin strings to exist for every activity module.
     *
     * @covers \mod_jitsi
     */
    public function test_required_module_strings_exist(): void {
        $sm = get_string_manager();
        $required = ['modulename', 'modulenameplural', 'pluginadministration', 'pluginname'];
        $missing = [];

        foreach ($required as $key) {
            if (!$sm->string_exists($key, 'mod_jitsi')) {
                $missing[] = $key;
            }
        }

        $this->assertEmpty(
            $missing,
            'Missing required module lang strings: ' . implode(', ', $missing)
            . '. Add them to lang/en/jitsi.php.'
        );
    }
}
