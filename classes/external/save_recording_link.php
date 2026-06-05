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
 * External API: save a recording link from the Jitsi recordingLinkAvailable event.
 *
 * @package    mod_jitsi
 * @category   external
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class save_recording_link extends external_api {
    /**
     * Returns description of method parameters.
     *
     * @return external_function_parameters
     */
    public static function execute_parameters() {
        return new external_function_parameters([
            'jitsi' => new external_value(PARAM_INT, 'Jitsi session id', VALUE_REQUIRED),
            'link'  => new external_value(PARAM_URL, 'Recording link URL provided by recordingLinkAvailable event', VALUE_REQUIRED),
            'ttl'   => new external_value(PARAM_INT, 'Time to live in seconds (0 = no expiry)', VALUE_DEFAULT, 0),
        ]);
    }

    /**
     * Saves a recording link received from the Jitsi recordingLinkAvailable iframe event.
     * Creates entries in jitsi_source_record (type=1) and jitsi_record so the recording
     * appears automatically in the activity's recordings tab.
     *
     * @param int    $jitsi Jitsi session id
     * @param string $link  Full URL of the recording
     * @param int    $ttl   Time-to-live in seconds reported by Jitsi (0 = unknown/no expiry)
     * @return array
     */
    public static function execute($jitsi, $link, $ttl = 0) {
        global $DB, $USER;

        $params = self::validate_parameters(self::execute_parameters(), [
            'jitsi' => $jitsi,
            'link'  => $link,
            'ttl'   => $ttl,
        ]);

        // Make sure the jitsi session exists.
        $jitsirecord = $DB->get_record('jitsi', ['id' => $params['jitsi']], '*', MUST_EXIST);

        // Avoid saving the same link twice for the same session.
        $existingsource = $DB->get_record_sql(
            'SELECT s.id FROM {jitsi_source_record} s
             JOIN {jitsi_record} r ON r.source = s.id
             WHERE s.link = :link AND r.jitsi = :jitsi AND r.deleted = 0',
            ['link' => $params['link'], 'jitsi' => $params['jitsi']]
        );
        if ($existingsource) {
            // If the existing record has no expiry, try to set it now.
            $existingfull = $DB->get_record('jitsi_source_record', ['id' => $existingsource->id]);
            if ($existingfull && empty($existingfull->timeexpires)) {
                $is8x8link = strpos($params['link'], '8x8.vc') !== false;
                if ($params['ttl'] > 0) {
                    $existingfull->timeexpires = $existingfull->timecreated + $params['ttl'];
                    $DB->update_record('jitsi_source_record', $existingfull);
                } else if ($is8x8link) {
                    $existingfull->timeexpires = $existingfull->timecreated + 86400;
                    $DB->update_record('jitsi_source_record', $existingfull);
                }
            }
            return ['idsource' => $existingsource->id];
        }

        // Create the source record with type = 1 (external link).
        $sourcerecord = new \stdClass();
        $sourcerecord->link            = $params['link'];
        $sourcerecord->account         = null;
        $sourcerecord->timecreated     = time();
        $sourcerecord->userid          = $USER->id;
        $sourcerecord->embed           = 0;
        $sourcerecord->maxparticipants = 0;
        $sourcerecord->type            = 1;
        $jaasttl = 86400; // JaaS recordings expire after 24 hours if no TTL is provided.
        $is8x8link = strpos($params['link'], '8x8.vc') !== false;
        if ($params['ttl'] > 0) {
            $sourcerecord->timeexpires = time() + $params['ttl'];
        } else if ($is8x8link) {
            $sourcerecord->timeexpires = time() + $jaasttl;
        } else {
            $sourcerecord->timeexpires = 0;
        }
        $idsource = $DB->insert_record('jitsi_source_record', $sourcerecord);

        // Create the jitsi_record linking the source to the session.
        $record = new \stdClass();
        $record->jitsi   = $params['jitsi'];
        $record->deleted = 0;
        $record->source  = $idsource;
        $record->visible = 1;
        $record->name    = userdate(time());
        $DB->insert_record('jitsi_record', $record);

        return ['idsource' => $idsource];
    }

    /**
     * Returns description of method return value.
     *
     * @return external_single_structure
     */
    public static function execute_returns() {
        return new external_single_structure([
            'idsource' => new external_value(PARAM_INT, 'Id of the created jitsi_source_record'),
        ]);
    }
}
