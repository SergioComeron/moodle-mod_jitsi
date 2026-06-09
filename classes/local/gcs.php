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
 * Google Cloud Storage helpers for Jibri recordings.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\local;

/**
 * Google Cloud Storage API helpers (client, buckets).
 *
 * Credentials come from the 'gcpserviceaccountjson' file area in Moodle file
 * storage, NOT from the server record's privatekey (empty for GCP servers).
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class gcs {
    /**
     * Creates and returns a configured Google Cloud Storage service client.
     *
     * @return \Google\Service\Storage
     */
    public static function client(): \Google\Service\Storage {
        $client = new \Google\Client();
        $client->setScopes(['https://www.googleapis.com/auth/cloud-platform']);
        $fs = get_file_storage();
        $context = \context_system::instance();
        $files = $fs->get_area_files($context->id, 'mod_jitsi', 'gcpserviceaccountjson', 0, 'itemid, filepath, filename', false);
        if (!empty($files)) {
            $file = reset($files);
            $content = $file->get_content();
            $json = json_decode($content, true);
            if (is_array($json)) {
                $client->setAuthConfig($json);
            } else {
                $client->useApplicationDefaultCredentials();
            }
        } else {
            $client->useApplicationDefaultCredentials();
        }
        return new \Google\Service\Storage($client);
    }

    /**
     * Creates a GCS bucket if it does not exist. Returns the bucket name.
     *
     * @param \Google\Service\Storage $gcs GCS service instance.
     * @param string $project GCP project ID.
     * @param string $bucketname Bucket name (must be globally unique).
     * @param string $location GCS location (e.g. 'europe-west1').
     * @return string The bucket name.
     */
    public static function ensure_bucket(
        \Google\Service\Storage $gcs,
        string $project,
        string $bucketname,
        string $location
    ): string {
        try {
            $gcs->buckets->get($bucketname);
        } catch (\Google\Service\Exception $e) {
            if ($e->getCode() == 404) {
                $bucket = new \Google\Service\Storage\Bucket([
                    'name' => $bucketname,
                    'location' => $location,
                    'storageClass' => 'STANDARD',
                ]);
                $gcs->buckets->insert($project, $bucket);
            } else {
                throw $e;
            }
        }
        return $bucketname;
    }

    /**
     * Derives a globally-unique GCS bucket name for a server.
     *
     * @param string $project GCP project ID.
     * @param int $serverid jitsi_servers record ID.
     * @return string Bucket name (max 63 chars, lowercase, hyphens only).
     */
    public static function bucket_name(string $project, int $serverid): string {
        $slug = preg_replace('/[^a-z0-9-]/', '-', strtolower($project));
        $name = 'mod-jitsi-' . $slug . '-s' . $serverid;
        return substr($name, 0, 63);
    }
}
