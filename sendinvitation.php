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
 * Send invitation email for a Jitsi session.
 *
 * @package    mod_jitsi
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(dirname(dirname(__FILE__))) . '/lib/moodlelib.php');
require_once(dirname(__FILE__) . '/lib.php');

$id = required_param('id', PARAM_INT);

$cm = get_coursemodule_from_id('jitsi', $id, 0, false, MUST_EXIST);
$course = $DB->get_record('course', ['id' => $cm->course], '*', MUST_EXIST);
$jitsi = $DB->get_record('jitsi', ['id' => $cm->instance], '*', MUST_EXIST);

require_login($course, false, $cm);
$context = context_module::instance($cm->id);
require_capability('mod/jitsi:createlink', $context);

$PAGE->set_url(new moodle_url('/mod/jitsi/sendinvitation.php', ['id' => $id]));
$PAGE->set_context($context);
$PAGE->set_cm($cm);
$PAGE->set_title(get_string('sendinvitation', 'jitsi'));
$PAGE->set_heading($course->fullname);

$recipient = optional_param('recipient', '', PARAM_EMAIL);
$message   = optional_param('message', '', PARAM_TEXT);
$sent      = false;
$errors    = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    require_sesskey();
    if (empty($recipient)) {
        $errors[] = get_string('required');
    } else {
        $inviteurl = (new moodle_url('/mod/jitsi/formuniversal.php', ['t' => $jitsi->token]))->out(false);

        $bodyparams = (object)[
            'session' => $jitsi->name,
            'course'  => $course->fullname,
            'url'     => $inviteurl,
            'message' => $message,
            'sender'  => fullname($USER),
        ];
        $subject     = get_string('sendinvitationsubject', 'jitsi', $jitsi->name);
        $messagetext = get_string('sendinvitationbody', 'jitsi', $bodyparams);

        $recipientuser = (object)[
            'id'          => -1,
            'email'       => $recipient,
            'firstname'   => $recipient,
            'lastname'    => '',
            'mailformat'  => 0,
            'maildisplay' => 0,
            'auth'        => 'manual',
            'deleted'     => 0,
            'suspended'   => 0,
            'username'    => $recipient,
            'confirmed'   => 1,
            'lang'        => current_language(),
        ];

        email_to_user($recipientuser, $USER, $subject, $messagetext);
        $sent = true;
    }
}

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('sendinvitation', 'jitsi'));

if ($sent) {
    echo $OUTPUT->notification(get_string('sendinvitationsent', 'jitsi', s($recipient)), 'success');
}

if (!empty($errors)) {
    foreach ($errors as $error) {
        echo $OUTPUT->notification($error, 'error');
    }
}

$actionurl = (new moodle_url('/mod/jitsi/sendinvitation.php', ['id' => $id]))->out(false);
echo html_writer::start_tag('form', ['method' => 'post', 'action' => $actionurl, 'class' => 'mform']);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'sesskey', 'value' => sesskey()]);

echo html_writer::start_div('form-group row fitem');
echo html_writer::tag(
    'label',
    get_string('sendinvitationrecipient', 'jitsi'),
    ['for' => 'recipient', 'class' => 'col-md-3 col-form-label']
);
echo html_writer::start_div('col-md-9 felement');
echo html_writer::empty_tag('input', [
    'type'        => 'email',
    'name'        => 'recipient',
    'id'          => 'recipient',
    'class'       => 'form-control',
    'placeholder' => get_string('sendinvitationemailplaceholder', 'jitsi'),
    'value'       => s($sent ? '' : $recipient),
    'required'    => 'required',
    'autofocus'   => 'autofocus',
]);
echo html_writer::end_div();
echo html_writer::end_div();

echo html_writer::start_div('form-group row fitem');
echo html_writer::tag(
    'label',
    get_string('sendinvitationmessage', 'jitsi'),
    ['for' => 'message', 'class' => 'col-md-3 col-form-label']
);
echo html_writer::start_div('col-md-9 felement');
echo html_writer::tag('textarea', s($sent ? '' : $message), [
    'name'  => 'message',
    'id'    => 'message',
    'class' => 'form-control',
    'rows'  => 4,
]);
echo html_writer::end_div();
echo html_writer::end_div();

echo html_writer::start_div('form-group row fitem');
echo html_writer::start_div('col-md-9 offset-md-3 felement');
echo html_writer::tag('button', get_string('sendinvitation', 'jitsi'), [
    'type'  => 'submit',
    'class' => 'btn btn-primary',
]);
$backurl = new moodle_url('/mod/jitsi/view.php', ['id' => $id]);
echo ' ' . html_writer::link($backurl, get_string('cancel'), ['class' => 'btn btn-secondary ml-2']);
echo html_writer::end_div();
echo html_writer::end_div();

echo html_writer::end_tag('form');

echo $OUTPUT->footer();
