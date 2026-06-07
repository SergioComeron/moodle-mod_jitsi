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

namespace mod_jitsi\local;

/**
 * Helpers for Jitsi recording lifecycle.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class recording {
    /**
     * Whether a source record can be deleted, i.e. no active (non-deleted)
     * jitsi_record still points at it.
     *
     * @param int $sourcerecordid jitsi_source_record id
     * @return bool
     */
    public static function is_deletable($sourcerecordid) {
        global $DB;
        $records = $DB->get_records('jitsi_record', ['source' => $sourcerecordid, 'deleted' => 0]);
        return empty($records);
    }

    /**
     * Mark a recording for deletion and, when it is the last record for a YouTube
     * source, toggle the video's privacy.
     *
     * @param int $idrecord jitsi_record id
     * @param int $option 1 = deleted, 2 = deleted (kept link)
     */
    public static function mark_to_delete($idrecord, $option) {
        global $DB;
        $record = $DB->get_record('jitsi_record', ['id' => $idrecord]);
        $source = $DB->get_record('jitsi_source_record', ['id' => $record->source]);
        if ($option == 1) {
            $record->deleted = 1;
        } else if ($option == 2) {
            $record->deleted = 2;
        }
        $records = $DB->get_records('jitsi_record', ['source' => $record->source]);
        if (count($records) == 1 && $source->type == 0) {
            youtube::toggle_state($source->link);
        }
        $DB->update_record('jitsi_record', $record);
    }

    /**
     * Toggle the visibility of a recording in the activity recordings list.
     *
     * @param int $recordid jitsi_record id
     * @param int $visible 1 = visible, 0 = hidden
     */
    public static function set_visibility($recordid, $visible) {
        global $DB;
        $record = $DB->get_record('jitsi_record', ['id' => $recordid], '*', MUST_EXIST);
        $record->visible = $visible ? 1 : 0;
        $DB->update_record('jitsi_record', $record);
    }

    /**
     * Add an external recording link (type 1) to an activity, creating both the
     * source record and the jitsi_record that links it to the activity.
     *
     * @param int $jitsiid jitsi activity instance id
     * @param string $url Recording URL
     * @param string $name Display name (defaults to the current date/time when empty)
     * @param int $embed Whether to embed (only honoured for Dropbox links)
     * @param int $userid Author user id
     * @return int The new jitsi_record id
     */
    public static function add_link($jitsiid, $url, $name, $embed, $userid) {
        global $DB;
        $sourcerecord = new \stdClass();
        $sourcerecord->link = $url;
        $sourcerecord->account = null;
        $sourcerecord->timecreated = time();
        $sourcerecord->userid = $userid;
        $sourcerecord->embed = (strpos($url, 'dropbox.com') !== false) ? $embed : 0;
        $sourcerecord->maxparticipants = 0;
        $sourcerecord->type = 1;
        $sourcerecord->id = $DB->insert_record('jitsi_source_record', $sourcerecord);

        $record = new \stdClass();
        $record->jitsi = $jitsiid;
        $record->deleted = 0;
        $record->source = $sourcerecord->id;
        $record->visible = 1;
        $record->name = empty($name) ? userdate(time()) : $name;
        return $DB->insert_record('jitsi_record', $record);
    }

    /**
     * Update an existing external recording link (type 1 only).
     *
     * @param int $recordid jitsi_record id being edited
     * @param string $url New recording URL
     * @param string $name New display name (defaults to the source creation date when empty)
     * @param int $embed Whether to embed (only honoured for Dropbox links)
     */
    public static function update_link($recordid, $url, $name, $embed) {
        global $DB;
        $record = $DB->get_record('jitsi_record', ['id' => $recordid], '*', MUST_EXIST);
        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $record->source], '*', MUST_EXIST);
        if ($sourcerecord->type != 1) {
            return;
        }
        $sourcerecord->link = $url;
        $sourcerecord->embed = (strpos($url, 'dropbox.com') !== false) ? $embed : 0;
        $DB->update_record('jitsi_source_record', $sourcerecord);
        $record->name = empty($name) ? userdate($sourcerecord->timecreated) : $name;
        $DB->update_record('jitsi_record', $record);
    }

    /**
     * Delete the recording file behind a recording link (GCS object or Jibri VM file).
     *
     * @param string $link Recording URL
     * @return bool True if the file was deleted
     */
    public static function delete_jibri_file($link) {
        global $DB;

        // GCS URL format: https://storage.googleapis.com/<bucket>/<filename>.
        if (preg_match('/^https:\/\/storage\.googleapis\.com\/([^\/]+)\/(.+)$/', $link, $m)) {
            $bucketname = $m[1];
            $objectname = $m[2];
            $server = $DB->get_record('jitsi_servers', ['gcs_bucket' => $bucketname, 'gcs_enabled' => 1]);
            if (!$server) {
                return false;
            }
            try {
                require_once(__DIR__ . '/../../api/vendor/autoload.php');
                $client = new \Google\Client();
                $client->addScope(\Google\Service\Storage::DEVSTORAGE_FULL_CONTROL);
                // GCP servers store credentials in Moodle file storage, not in privatekey field.
                $fs = get_file_storage();
                $ctx = \context_system::instance();
                $files = $fs->get_area_files(
                    $ctx->id,
                    'mod_jitsi',
                    'gcpserviceaccountjson',
                    0,
                    'itemid, filepath, filename',
                    false
                );
                if (!empty($files)) {
                    $file = reset($files);
                    $key = json_decode($file->get_content(), true);
                    if (is_array($key)) {
                        $client->setAuthConfig($key);
                    } else {
                        $client->useApplicationDefaultCredentials();
                    }
                } else {
                    $client->useApplicationDefaultCredentials();
                }
                $storage = new \Google\Service\Storage($client);
                $storage->objects->delete($bucketname, $objectname);
                return true;
            } catch (\Exception $e) {
                return false;
            }
        }

        // Jibri VM URL format: http://<ip>/recordings/<filename>.
        if (!preg_match('/^http:\/\/(\d+\.\d+\.\d+\.\d+)\/recordings\/(.+)$/', $link, $m)) {
            return false;
        }
        $ip = $m[1];
        $filename = basename($m[2]);
        $servers = $DB->get_records('jitsi_servers', ['jibri_enabled' => 1]);
        foreach ($servers as $server) {
            if (empty($server->provisioningtoken)) {
                continue;
            }
            $url = 'http://' . $ip . '/delete-recording'
                . '?file=' . rawurlencode($filename)
                . '&token=' . rawurlencode($server->provisioningtoken);
            $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
            $response = @file_get_contents($url, false, $ctx);
            if ($response !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Delete a recording's DB records (jitsi_record + jitsi_source_record) and the
     * AI-generated quiz course module if one was created.
     *
     * @param int $source jitsi_source_record id
     */
    public static function delete($source) {
        global $DB;
        // Delete the AI-generated quiz course module if one was created.
        $sourcerecord = $DB->get_record('jitsi_source_record', ['id' => $source]);
        if ($sourcerecord && !empty($sourcerecord->ai_quiz_id) && (int)$sourcerecord->ai_quiz_id > 0) {
            $cmid = (int)$sourcerecord->ai_quiz_id;
            if ($DB->record_exists('course_modules', ['id' => $cmid])) {
                course_delete_module($cmid);
            }
        }
        $DB->delete_records('jitsi_record', ['source' => $source]);
        $DB->delete_records('jitsi_source_record', ['id' => $source]);
    }
}
