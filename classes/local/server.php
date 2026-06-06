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
 * Helpers to query the runtime status of a Jitsi server instance.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class server {
    /**
     * Check if a GCP server instance is running.
     *
     * @param \stdClass $server Server record from jitsi_servers table
     * @return array Array with 'status' ('running'|'stopped'|'error') and optional 'message'
     */
    public static function check_gcp_status($server) {
        // Only check GCP servers (type 3).
        if ($server->type != 3) {
            return ['status' => 'running']; // Non-GCP servers are always considered "running".
        }

        // Check if server is still provisioning.
        if ($server->provisioningstatus === 'provisioning' || $server->provisioningstatus === 'error') {
            return [
                'status' => 'error',
                'message' => 'Server is still being provisioned or has an error',
            ];
        }

        // If no GCP instance name, assume it's not a GCP-managed server.
        if (empty($server->gcpinstancename) || empty($server->gcpproject) || empty($server->gcpzone)) {
            return ['status' => 'running'];
        }

        // Check if Google API client is available.
        $autoloader = __DIR__ . '/../../api/vendor/autoload.php';
        if (!file_exists($autoloader)) {
            return [
                'status' => 'error',
                'message' => 'Google API client not installed',
            ];
        }

        try {
            require_once($autoloader);

            // Initialize Google Client.
            $client = new \Google\Client();
            $client->setScopes(['https://www.googleapis.com/auth/cloud-platform']);

            // Try to read Service Account uploaded via settings.
            $fs = get_file_storage();
            $context = \context_system::instance();
            $files = $fs->get_area_files(
                $context->id,
                'mod_jitsi',
                'gcpserviceaccountjson',
                0,
                'itemid, filepath, filename',
                false
            );

            if (!empty($files)) {
                $file = reset($files);
                $jsoncontent = $file->get_content();
                $client->setAuthConfig(json_decode($jsoncontent, true));
            } else {
                // Fallback to Application Default Credentials.
                $client->useApplicationDefaultCredentials();
            }

            $compute = new \Google\Service\Compute($client);

            // Get instance status.
            $instance = $compute->instances->get(
                $server->gcpproject,
                $server->gcpzone,
                $server->gcpinstancename
            );

            $status = $instance->getStatus();

            // Possible statuses: PROVISIONING, STAGING, RUNNING, STOPPING, STOPPED, SUSPENDING, SUSPENDED, TERMINATED.
            if ($status === 'RUNNING') {
                return ['status' => 'running'];
            } else if ($status === 'STOPPED' || $status === 'TERMINATED' || $status === 'SUSPENDED') {
                return [
                    'status' => 'stopped',
                    'message' => 'Instance status: ' . $status,
                ];
            } else {
                return [
                    'status' => 'transitioning',
                    'message' => 'Instance status: ' . $status,
                ];
            }
        } catch (\Exception $e) {
            return [
                'status' => 'error',
                'message' => $e->getMessage(),
            ];
        }
    }
}
