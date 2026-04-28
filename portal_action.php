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
 * Handles portal registration actions from the plugin settings page.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('moodle/site:config', context_system::instance());
require_sesskey();

$action = required_param('action', PARAM_ALPHA);
$returnurl = new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']);

if ($action === 'resend') {
    $email = get_config('mod_jitsi', 'portal_email');
    if ($email) {
        $sitehash = hash('sha256', $CFG->wwwroot);
        $payload  = json_encode([
            'email'     => $email,
            'site_hash' => $sitehash,
            'site_name' => $CFG->fullname,
            'site_url'  => $CFG->wwwroot,
        ]);
        $ch = curl_init('https://portal.sergiocomeron.com/register-site.php');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        ]);
        $resendresponse = curl_exec($ch);
        $resendhttpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($resendresponse === false || $resendhttpcode < 200 || $resendhttpcode >= 300) {
            redirect(
                $returnurl,
                get_string('portalregistrationerror', 'jitsi'),
                null,
                \core\output\notification::NOTIFY_ERROR
            );
        }
    }
    redirect(
        $returnurl,
        get_string('portalregistrationsent', 'jitsi'),
        null,
        \core\output\notification::NOTIFY_SUCCESS
    );
}

if ($action === 'register') {
    $email = required_param('email', PARAM_EMAIL);

    $sitehash = hash('sha256', $CFG->wwwroot);

    $payload = json_encode(['email' => $email, 'site_hash' => $sitehash]);

    $ch = curl_init('https://portal.sergiocomeron.com/register-site.php');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
    ]);
    $response = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $data = json_decode($response, true);

    if ($httpcode === 200 && !empty($data['ok'])) {
        set_config('portal_email', $email, 'mod_jitsi');
        set_config('portal_status', 'pending', 'mod_jitsi');
        redirect($returnurl, get_string('portalregistrationsent', 'jitsi'), null, \core\output\notification::NOTIFY_SUCCESS);
    } else {
        redirect($returnurl, get_string('portalregistrationerror', 'jitsi'), null, \core\output\notification::NOTIFY_ERROR);
    }
}

if ($action === 'unregister') {
    unset_config('portal_email', 'mod_jitsi');
    unset_config('portal_status', 'mod_jitsi');
    unset_config('portal_license_key', 'mod_jitsi');
    redirect($returnurl, get_string('portalunregistered', 'jitsi'), null, \core\output\notification::NOTIFY_SUCCESS);
}

redirect($returnurl);
