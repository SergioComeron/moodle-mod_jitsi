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
 * Privacy Subsystem implementation for mod_jitsi.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\privacy;

use core_privacy\local\metadata\collection;

/**
 * Privacy Subsystem implementation for mod_jitsi.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class provider implements
    \core_privacy\local\metadata\provider,
    \core_privacy\local\request\data_provider {
    /**
     * Returns meta data about this system.
     *
     * @param   collection     $collection The initialised collection to add items to.
     * @return  collection     A listing of user data stored through this system.
     */
    public static function get_metadata(collection $collection): collection {
        // Data sent to the Jitsi Meet server (identity inside the conference).
        $collection->add_external_location_link('jitsi', [
            'username' => 'privacy:metadata:jitsi:username',
            'avatar'   => 'privacy:metadata:jitsi:avatar',
            'email'    => 'privacy:metadata:jitsi:email',
        ], 'privacy:metadata:jitsi');

        // Recording content sent to Google Vertex AI for AI feature generation.
        // This only happens when a teacher explicitly triggers summary, quiz or
        // transcription generation for a GCS recording.
        $collection->add_external_location_link('vertexai', [
            'recording' => 'privacy:metadata:vertexai:recording',
        ], 'privacy:metadata:vertexai');

        // AI-generated content stored in jitsi_source_record.
        $collection->add_database_table('jitsi_source_record', [
            'ai_summary'       => 'privacy:metadata:jitsi_source_record:ai_summary',
            'ai_transcription' => 'privacy:metadata:jitsi_source_record:ai_transcription',
            'ai_quiz_id'       => 'privacy:metadata:jitsi_source_record:ai_quiz_id',
        ], 'privacy:metadata:jitsi_source_record');

        return $collection;
    }
}
