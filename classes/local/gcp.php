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
 * Google Compute Engine helpers for GCP auto-managed Jitsi servers.
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace mod_jitsi\local;

/**
 * Google Compute Engine API helpers (client, instances, firewall, static IPs).
 *
 * @package    mod_jitsi
 * @copyright  2025 Sergio Comerón (jitsi@sergiocomeron.com)
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class gcp {
    /**
     * Load the Google API PHP Client autoloader and report availability.
     *
     * Tries the same locations the plugin has always used (api/vendor first).
     *
     * @return bool True if the Google Compute classes are available.
     */
    public static function load_google_api(): bool {
        global $CFG;

        if (!class_exists('Google\\Client') || !class_exists('Google\\Service\\Compute')) {
            $autoloaders = [
                $CFG->dirroot . '/mod/jitsi/api/vendor/autoload.php',
                $CFG->dirroot . '/mod/jitsi/vendor/autoload.php',
                $CFG->dirroot . '/vendor/autoload.php',
            ];
            foreach ($autoloaders as $autoload) {
                if (file_exists($autoload)) {
                    require_once($autoload);
                    break;
                }
            }
        }
        return class_exists('Google\\Client') && class_exists('Google\\Service\\Compute');
    }

    /**
     * Creates and returns a configured Google Compute Engine service client.
     *
     * Authentication priority:
     * 1. Service account JSON file stored in the mod_jitsi 'gcpserviceaccountjson' file area.
     * 2. Application Default Credentials (environment variable, gcloud CLI, etc.).
     *
     * @return \Google\Service\Compute A configured Google Compute Engine service instance.
     */
    public static function client(): \Google\Service\Compute {
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
        return new \Google\Service\Compute($client);
    }

    /**
     * Ensure there is a permissive firewall rule on the VM's network for web + media ports.
     *
     * @param \Google\Service\Compute $compute GCP Compute service instance.
     * @param string $project GCP project ID.
     * @param string $network Network name or selfLink.
     * @return string One of: 'created' | 'exists' | 'noperms' | 'error:<msg>'.
     */
    public static function ensure_firewall(\Google\Service\Compute $compute, string $project, string $network): string {
        $rulename = 'mod-jitsi-allow-web';
        // Build full selfLink for network if we received a short path like 'global/networks/default'.
        if (strpos($network, 'projects/') !== 0) {
            $network = sprintf('projects/%s/%s', $project, ltrim($network, '/'));
        }
        // Try a cheap GET first; if we lack permission it will throw.
        try {
            $compute->firewalls->get($project, $rulename);
            return 'exists';
        } catch (\Exception $e) {
            // Firewall rule doesn't exist or we lack GET permission - proceed to attempt create.
            debugging('Firewall GET failed, attempting create: ' . $e->getMessage(), DEBUG_DEVELOPER);
        }
        $fw = new \Google\Service\Compute\Firewall([
            'name' => $rulename,
            'description' => 'Allow HTTP/HTTPS and Jitsi media (UDP/10000) for Moodle Jitsi plugin',
            'direction' => 'INGRESS',
            'priority' => 1000,
            'network' => $network,
            'sourceRanges' => ['0.0.0.0/0'],
            'targetTags' => ['mod-jitsi-web'],
            'allowed' => [
                ['IPProtocol' => 'tcp', 'ports' => ['80', '443']],
                ['IPProtocol' => 'udp', 'ports' => ['10000']],
            ],
        ]);
        try {
            $compute->firewalls->insert($project, $fw);
            return 'created';
        } catch (\Exception $e) {
            $msg = $e->getMessage();
            // 409 Already exists or similar → treat as exists.
            if (
                stripos($msg, 'alreadyexists') !== false || stripos($msg, 'already exists') !== false ||
                stripos($msg, 'duplicate') !== false
            ) {
                return 'exists';
            }
            // Permission errors → assume admin manages firewall; don't warn in UI.
            if (
                stripos($msg, 'permission') !== false || stripos($msg, 'denied') !== false ||
                stripos($msg, 'insufficient') !== false
            ) {
                return 'noperms';
            }
            return 'error:' . $msg;
        }
    }

    /**
     * Creates a bare Compute Engine VM and returns its operation name.
     *
     * @param \Google\Service\Compute $compute GCP Compute service instance.
     * @param string $project GCP project ID.
     * @param string $zone GCP zone (e.g. europe-west1-b).
     * @param array $opts Instance options (name, machineType, startupScript, etc.).
     * @return string Operation name.
     */
    public static function create_instance(\Google\Service\Compute $compute, string $project, string $zone, array $opts): string {
        $name = $opts['name'];
        $machinetype = sprintf('zones/%s/machineTypes/%s', $zone, $opts['machineType']);
        $diskimage = $opts['image'];
        $network = $opts['network'];

        // Optional metadata: startup-script + variables.
        $metadataitems = [];
        if (!empty($opts['startupScript'])) {
            $metadataitems[] = ['key' => 'startup-script', 'value' => $opts['startupScript']];
        }
        if (!empty($opts['hostname'])) {
            $metadataitems[] = ['key' => 'HOSTNAME_FQDN', 'value' => $opts['hostname']];
        }
        if (!empty($opts['letsencryptEmail'])) {
            $metadataitems[] = ['key' => 'LE_EMAIL', 'value' => $opts['letsencryptEmail']];
        }
        if (!empty($opts['callbackUrl'])) {
            $metadataitems[] = ['key' => 'CALLBACK_URL', 'value' => $opts['callbackUrl']];
        }
        // Allow callers to inject arbitrary extra metadata items.
        if (!empty($opts['extraMetadata']) && is_array($opts['extraMetadata'])) {
            foreach ($opts['extraMetadata'] as $item) {
                if (!empty($item['key'])) {
                    $metadataitems[] = ['key' => $item['key'], 'value' => (string)$item['value']];
                }
            }
        }

        // Configure access config (static IP if provided, otherwise ephemeral).
        $accessconfig = ['name' => 'External NAT', 'type' => 'ONE_TO_ONE_NAT'];
        if (!empty($opts['staticIpAddress'])) {
            // Use the reserved static IP address.
            $accessconfig['natIP'] = $opts['staticIpAddress'];
        }

        $tags = !empty($opts['tags']) ? $opts['tags'] : ['mod-jitsi-web'];
        $instanceparams = [
            'name' => $name,
            'machineType' => $machinetype,
            'labels' => [ 'app' => 'jitsi', 'plugin' => 'mod-jitsi' ],
            'tags' => ['items' => $tags],
            'networkInterfaces' => [[
                'network' => $network,
                'accessConfigs' => [$accessconfig],
            ]],
            'disks' => [[
                'boot' => true,
                'autoDelete' => true,
                'initializeParams' => ['sourceImage' => $diskimage, 'diskSizeGb' => 20],
            ]],
        ];
        // Attach a service account if requested (gives GCP tools like gsutil ADC access).
        if (!empty($opts['serviceAccount'])) {
            $scopes = !empty($opts['serviceAccountScopes'])
                ? $opts['serviceAccountScopes']
                : ['https://www.googleapis.com/auth/cloud-platform'];
            $instanceparams['serviceAccounts'] = [[
                'email' => $opts['serviceAccount'],
                'scopes' => $scopes,
            ]];
        }
        if (!empty($metadataitems)) {
            $instanceparams['metadata'] = ['items' => $metadataitems];
        }

        $instance = new \Google\Service\Compute\Instance($instanceparams);
        $op = $compute->instances->insert($project, $zone, $instance);
        return $op->getName();
    }

    /**
     * Updates specific metadata keys on a GCP instance, preserving existing ones.
     *
     * @param \Google\Service\Compute $compute GCP Compute service instance.
     * @param string $project GCP project ID.
     * @param string $zone GCP zone.
     * @param string $instancename Instance name.
     * @param array $updates Key-value pairs to update or add.
     */
    public static function update_instance_metadata(
        \Google\Service\Compute $compute,
        string $project,
        string $zone,
        string $instancename,
        array $updates
    ): void {
        $instance = $compute->instances->get($project, $zone, $instancename);
        $metadata = $instance->getMetadata();
        $items = $metadata->getItems() ?? [];
        foreach ($updates as $key => $value) {
            $found = false;
            foreach ($items as $item) {
                if ($item->getKey() === $key) {
                    $item->setValue($value);
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                $newitem = new \Google\Service\Compute\MetadataItems();
                $newitem->setKey($key);
                $newitem->setValue($value);
                $items[] = $newitem;
            }
        }
        $metadata->setItems($items);
        $compute->instances->setMetadata($project, $zone, $instancename, $metadata);
    }

    /**
     * Wait for a Google Cloud Platform zone operation to complete.
     *
     * @param \Google\Service\Compute $compute The Google Compute API client instance.
     * @param string $project The GCP project ID.
     * @param string $zone The GCP zone where the operation is being performed.
     * @param string $opname The name of the operation to wait for.
     * @param int $timeout Maximum seconds to wait. Defaults to 420 (7 minutes).
     * @throws \moodle_exception If the operation fails or exceeds the timeout.
     */
    public static function wait_zone_op(
        \Google\Service\Compute $compute,
        string $project,
        string $zone,
        string $opname,
        int $timeout = 420
    ): void {
        $start = time();
        do {
            $op = $compute->zoneOperations->get($project, $zone, $opname);
            if ($op->getStatus() === 'DONE') {
                if ($op->getError()) {
                    throw new \moodle_exception('gcpoperationerror', 'mod_jitsi', '', json_encode($op->getError()));
                }
                return;
            }
            usleep(500000);
        } while (time() - $start < $timeout);
        throw new \moodle_exception('gcpoperationtimeout', 'mod_jitsi');
    }

    /**
     * Wait for a Google Cloud Platform regional operation to complete.
     *
     * @param \Google\Service\Compute $compute The Google Compute API client instance.
     * @param string $project The GCP project ID.
     * @param string $region The GCP region where the operation is being performed.
     * @param string $opname The name of the operation to wait for.
     * @param int $timeout Maximum seconds to wait. Defaults to 120.
     * @throws \moodle_exception If the operation fails or exceeds the timeout.
     */
    public static function wait_region_op(
        \Google\Service\Compute $compute,
        string $project,
        string $region,
        string $opname,
        int $timeout = 120
    ): void {
        $start = time();
        do {
            $op = $compute->regionOperations->get($project, $region, $opname);
            if ($op->getStatus() === 'DONE') {
                if ($op->getError()) {
                    throw new \moodle_exception('gcpoperationerror', 'mod_jitsi', '', json_encode($op->getError()));
                }
                return;
            }
            usleep(500000);
        } while (time() - $start < $timeout);
        throw new \moodle_exception('gcpoperationtimeout', 'mod_jitsi');
    }

    /**
     * Finds an available (unused) static IP in the region.
     *
     * @param \Google\Service\Compute $compute GCP Compute client.
     * @param string $project GCP project ID.
     * @param string $region GCP region.
     * @return array|null Array with ['name' => string, 'address' => string] or null if none available.
     */
    public static function find_available_static_ip(
        \Google\Service\Compute $compute,
        string $project,
        string $region
    ): ?array {
        try {
            $addresses = $compute->addresses->listAddresses($project, $region);

            if ($addresses->getItems()) {
                foreach ($addresses->getItems() as $addr) {
                    // IP is available if it's not assigned to any resource (users array is empty).
                    if (empty($addr->getUsers()) && $addr->getStatus() === 'RESERVED') {
                        return [
                            'name' => $addr->getName(),
                            'address' => $addr->getAddress(),
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            debugging('Failed to list addresses: ' . $e->getMessage(), DEBUG_NORMAL);
        }

        return null;
    }

    /**
     * Reserves a static IP address in GCP and returns the address name.
     *
     * @param \Google\Service\Compute $compute GCP Compute client.
     * @param string $project GCP project ID.
     * @param string $region GCP region (e.g., 'europe-west1' from zone 'europe-west1-b').
     * @param string $name Name for the static IP address.
     * @return string The reserved static IP address name.
     */
    public static function reserve_static_ip(
        \Google\Service\Compute $compute,
        string $project,
        string $region,
        string $name
    ): string {
        $address = new \Google\Service\Compute\Address();
        $address->setName($name);
        $address->setDescription('Static IP for Jitsi server ' . $name);
        $address->setAddressType('EXTERNAL');

        $op = $compute->addresses->insert($project, $region, $address);
        self::wait_region_op($compute, $project, $region, $op->getName());

        return $name;
    }

    /**
     * Releases a static IP address in GCP.
     *
     * @param \Google\Service\Compute $compute GCP Compute client.
     * @param string $project GCP project ID.
     * @param string $region GCP region.
     * @param string $name Name of the static IP address to release.
     */
    public static function release_static_ip(
        \Google\Service\Compute $compute,
        string $project,
        string $region,
        string $name
    ): void {
        try {
            $op = $compute->addresses->delete($project, $region, $name);
            self::wait_region_op($compute, $project, $region, $op->getName());
        } catch (\Exception $e) {
            // Log error but don't throw - IP might already be deleted.
            debugging('Failed to release static IP ' . $name . ': ' . $e->getMessage(), DEBUG_NORMAL);
        }
    }
}
