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

defined('MOODLE_INTERNAL') || die();

/**
 * Access checks for the site-admin Jitsi pages.
 *
 * Behat cannot assert the require_admin() error page, because Moodle's
 * automatic exception check fails the scenario. These tests request the
 * pages as a normal user instead.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
final class admin_pages_access_test extends \advanced_testcase {
    /**
     * Pages that must call require_admin() and must not call require_login().
     *
     * @return string[]
     */
    private function admin_pages(): array {
        return [
            'auth.php',
            'search.php',
            'adminaccounts.php',
            'adminrecord.php',
            'recordingmatrix.php',
        ];
    }

    /**
     * Every admin page gates access with require_admin().
     */
    public function test_admin_pages_call_require_admin(): void {
        global $CFG;

        foreach ($this->admin_pages() as $page) {
            $source = file_get_contents($CFG->dirroot . '/mod/jitsi/' . $page);
            $this->assertNotFalse($source, $page);
            $this->assertMatchesRegularExpression('/^\s*require_admin\(\);/m', $source, $page);
            $this->assertDoesNotMatchRegularExpression('/^\s*require_login\(/m', $source, $page);
        }
    }

    /**
     * A regular user is rejected by the YouTube OAuth script.
     */
    public function test_auth_php_rejects_non_admin(): void {
        $this->assert_non_admin_rejected('auth.php');
    }

    /**
     * A regular user is rejected by the recording search page.
     */
    public function test_search_php_rejects_non_admin(): void {
        $this->assert_non_admin_rejected('search.php');
    }

    /**
     * A regular user is rejected by the recording accounts page.
     */
    public function test_adminaccounts_php_rejects_non_admin(): void {
        $this->assert_non_admin_rejected('adminaccounts.php');
    }

    /**
     * A regular user is rejected by the recordings-to-delete page.
     */
    public function test_adminrecord_php_rejects_non_admin(): void {
        $this->assert_non_admin_rejected('adminrecord.php');
    }

    /**
     * An administrator can open the YouTube OAuth script.
     *
     * The callback is this same script. Passing require_admin() here is the
     * check Google's redirect hits while the admin session is still alive.
     */
    public function test_admin_can_open_auth_php(): void {
        $this->resetAfterTest();
        $this->setAdminUser();
        $_GET['name'] = 'TestAccount';

        $output = '';
        ob_start();
        try {
            $this->include_page('auth.php');
            $output = ob_get_contents();
        } finally {
            ob_end_clean();
            unset($_GET['name'], $_SESSION['name']);
        }

        $this->assertStringContainsString('jitsi_oauth_id', $output);
        $this->assertStringContainsString('jitsi_oauth_secret', $output);
    }

    /**
     * Include one admin page as the current user.
     *
     * The working directory is the plugin directory because some pages
     * require sibling files with a relative path. SCRIPT_FILENAME is set so
     * those pages can resolve Moodle's config.php.
     *
     * recordingmatrix.php is not included here: it declares the same
     * isincluded() function as adminrecord.php. Its require_admin() call is
     * checked by test_admin_pages_call_require_admin().
     *
     * @param string $page File name inside mod/jitsi
     */
    private function include_page(string $page): void {
        global $CFG, $DB, $PAGE, $OUTPUT, $USER, $SESSION, $SITE, $COURSE;

        $directory = $CFG->dirroot . '/mod/jitsi';
        $previous = getcwd();
        $scriptfilename = $_SERVER['SCRIPT_FILENAME'] ?? '';
        $_SERVER['SCRIPT_FILENAME'] = $directory . '/' . $page;
        chdir($directory);
        try {
            require($directory . '/' . $page);
        } finally {
            $_SERVER['SCRIPT_FILENAME'] = $scriptfilename;
            if ($previous !== false) {
                chdir($previous);
            }
        }
    }

    /**
     * Request a page as a non-admin and expect the site:config denial.
     *
     * @param string $page File name inside mod/jitsi
     */
    private function assert_non_admin_rejected(string $page): void {
        $this->resetAfterTest();
        $this->setUser($this->getDataGenerator()->create_user());

        ob_start();
        try {
            $this->include_page($page);
            $this->fail($page . ' should reject a non-admin');
        } catch (\required_capability_exception $exception) {
            $this->assertSame('nopermissions', $exception->errorcode);
        } finally {
            ob_end_clean();
        }
    }
}
