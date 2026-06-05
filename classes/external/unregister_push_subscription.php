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

namespace mod_jitsi\external;

use core_external\external_api;
use core_external\external_function_parameters;
use core_external\external_single_structure;
use core_external\external_value;

/**
 * External API: unregister a Web Push subscription for the current user.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class unregister_push_subscription extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'endpoint' => new external_value(PARAM_URL, 'Push endpoint URL'),
        ]);
    }

    /**
     * Unregister a Web Push subscription.
     *
     * @param string $endpoint
     * @return array
     */
    public static function execute($endpoint) {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), [
            'endpoint' => $endpoint,
        ]);

        $context = \context_system::instance();
        self::validate_context($context);

        $DB->delete_records_select(
            'jitsi_push_subscriptions',
            'userid = :userid AND ' . $DB->sql_compare_text('endpoint') . ' = ' . $DB->sql_compare_text(':endpoint'),
            ['userid' => $USER->id, 'endpoint' => $params['endpoint']]
        );

        return ['success' => true];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether unregistration succeeded'),
        ]);
    }
}
