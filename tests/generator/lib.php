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
 * Data generator for mod_jitsi PHPUnit tests.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class mod_jitsi_generator extends testing_module_generator {
    /**
     * Creates a new jitsi activity instance.
     *
     * @param array|stdClass|null $record
     * @param array|null $options
     * @return stdClass the created jitsi record
     */
    public function create_instance($record = null, ?array $options = null): stdClass {
        $record = (object)(array)$record;

        if (!isset($record->name)) {
            $record->name = 'Test Jitsi ' . $this->instancecount;
        }
        if (!isset($record->intro)) {
            $record->intro = 'Test intro';
        }
        if (!isset($record->introformat)) {
            $record->introformat = FORMAT_HTML;
        }
        if (!isset($record->token)) {
            $record->token = sha1(uniqid('token_', true));
        }
        if (!isset($record->tokeninterno)) {
            $record->tokeninterno = sha1(uniqid('interno_', true));
        }
        if (!isset($record->tokeninvitacion)) {
            $record->tokeninvitacion = '';
        }
        if (!isset($record->sessionwithtoken)) {
            $record->sessionwithtoken = 0;
        }
        if (!isset($record->timeopen)) {
            $record->timeopen = 0;
        }
        if (!isset($record->timeclose)) {
            $record->timeclose = 0;
        }
        if (!isset($record->completionminutes)) {
            $record->completionminutes = 0;
        }
        if (!isset($record->numberofparticipants)) {
            $record->numberofparticipants = 0;
        }

        return parent::create_instance($record, $options);
    }

    /**
     * Creates a recording for a jitsi activity.
     *
     * Inserts the two rows the activity expects: a {jitsi_source_record}
     * (URL/metadata) and a {jitsi_record} that links the source to the
     * activity. view.php and recordingstab.php join both tables.
     *
     * @param array|stdClass|null $record Must include jitsiid (the jitsi instance id).
     * @return stdClass the created jitsi_record row
     */
    public function create_recording($record = null): stdClass {
        global $DB;

        $record = (object)(array)$record;

        if (empty($record->jitsiid)) {
            throw new coding_exception(
                'create_recording() requires a jitsiid (use the "jitsi" column with the activity idnumber).'
            );
        }
        if (!isset($record->name)) {
            $record->name = 'Test recording';
        }

        $source = (object)[
            'link' => $record->link ?? 'https://example.com/recording.mp4',
            'account' => $record->account ?? null,
            'timecreated' => $record->timecreated ?? time(),
            'userid' => $record->userid ?? 0,
            'embed' => $record->embed ?? 0,
            'maxparticipants' => $record->maxparticipants ?? 0,
            'type' => $record->type ?? 1,
            'timeexpires' => $record->timeexpires ?? 0,
            'ai_quiz_id' => 0,
        ];
        $sourceid = $DB->insert_record('jitsi_source_record', $source);

        $rec = (object)[
            'jitsi' => $record->jitsiid,
            'deleted' => $record->deleted ?? 0,
            'source' => $sourceid,
            'visible' => isset($record->visible) ? (int)$record->visible : 1,
            'name' => $record->name,
        ];
        $rec->id = $DB->insert_record('jitsi_record', $rec);

        return $rec;
    }
}
