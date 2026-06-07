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
 * External API: update an existing external recording link (type 1).
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2024 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class update_recording_link extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'cmid' => new external_value(PARAM_INT, 'Course module ID for capability check'),
            'recordid' => new external_value(PARAM_INT, 'ID of the jitsi_record being edited'),
            'url' => new external_value(PARAM_URL, 'New recording URL'),
            'name' => new external_value(PARAM_TEXT, 'New display name (defaults to source date when empty)', VALUE_DEFAULT, ''),
            'embed' => new external_value(PARAM_INT, 'Whether to embed (only honoured for Dropbox links)', VALUE_DEFAULT, 0),
        ]);
    }

    /**
     * Update an existing external recording link.
     *
     * @param int $cmid
     * @param int $recordid
     * @param string $url
     * @param string $name
     * @param int $embed
     * @return array
     */
    public static function execute($cmid, $recordid, $url, $name = '', $embed = 0) {
        $params = self::validate_parameters(self::execute_parameters(), [
            'cmid' => $cmid,
            'recordid' => $recordid,
            'url' => $url,
            'name' => $name,
            'embed' => $embed,
        ]);

        $cm = get_coursemodule_from_id('jitsi', $params['cmid'], 0, false, MUST_EXIST);
        $context = \context_module::instance($cm->id);
        self::validate_context($context);
        require_capability('mod/jitsi:record', $context);

        if (empty($params['url'])) {
            return ['success' => false, 'message' => get_string('error')];
        }

        \mod_jitsi\local\recording::update_link($params['recordid'], $params['url'], $params['name'], $params['embed']);

        return ['success' => true, 'message' => get_string('updated', 'jitsi')];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'success' => new external_value(PARAM_BOOL, 'Whether the link was updated'),
            'message' => new external_value(PARAM_TEXT, 'Result message'),
        ]);
    }
}
