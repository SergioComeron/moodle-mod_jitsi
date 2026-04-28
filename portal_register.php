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
 * Standalone registration page for mod_jitsi Account.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once('../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('moodle/site:config', context_system::instance());

$PAGE->set_url(new moodle_url('/mod/jitsi/portal_register.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('portalheading', 'jitsi'));
$PAGE->set_heading(get_string('portalheading', 'jitsi'));

$returnurl = new moodle_url('/admin/settings.php', ['section' => 'modsettingjitsi']);

if (optional_param('cancel', 0, PARAM_INT)) {
    redirect($returnurl);
}

$email = optional_param('email', '', PARAM_EMAIL);
if ($email && confirm_sesskey()) {
    $sitehash = hash('sha256', $CFG->wwwroot);
    $payload  = json_encode(['email' => $email, 'site_hash' => $sitehash]);

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

    $result = json_decode($response, true);

    if ($httpcode === 200 && !empty($result['ok'])) {
        set_config('portal_email', $email, 'mod_jitsi');
        set_config('portal_status', 'pending', 'mod_jitsi');
        redirect(
            $returnurl,
            get_string('portalregistrationsent', 'jitsi'),
            null,
            \core\output\notification::NOTIFY_SUCCESS
        );
    } else {
        redirect(
            $returnurl,
            get_string('portalregistrationerror', 'jitsi'),
            null,
            \core\output\notification::NOTIFY_ERROR
        );
    }
}

echo $OUTPUT->header();
echo html_writer::tag('p', get_string('portalheadingex', 'jitsi'));

$actionurl = new moodle_url('/mod/jitsi/portal_register.php');
echo html_writer::start_tag('form', ['method' => 'post', 'action' => $actionurl->out(false)]);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'sesskey', 'value' => sesskey()]);
echo html_writer::start_div('mb-3');
echo html_writer::tag(
    'label',
    get_string('portalemail', 'jitsi'),
    ['for' => 'jitsi_portal_email', 'class' => 'form-label fw-bold']
);
echo html_writer::empty_tag('input', [
    'type'        => 'email',
    'name'        => 'email',
    'id'          => 'jitsi_portal_email',
    'class'       => 'form-control',
    'style'       => 'max-width:360px',
    'placeholder' => 'admin@yoursite.com',
    'required'    => 'required',
]);
echo html_writer::end_div();
echo html_writer::tag(
    'button',
    get_string('portalregisterbutton', 'jitsi'),
    ['type' => 'submit', 'class' => 'btn btn-primary me-2']
);
echo html_writer::tag(
    'button',
    get_string('cancel', 'core'),
    ['type' => 'submit', 'name' => 'cancel', 'value' => '1', 'class' => 'btn btn-secondary']
);
echo html_writer::end_tag('form');

echo $OUTPUT->footer();
