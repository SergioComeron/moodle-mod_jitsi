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
 * Private session between two users.
 *
 * @package    mod_jitsi
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(dirname(dirname(__FILE__))) . '/lib/moodlelib.php');
require_once(dirname(__FILE__) . '/lib.php');

$peerid = required_param('peer', PARAM_INT);
$peer = $DB->get_record('user', ['id' => $peerid], '*', MUST_EXIST);

$PAGE->set_url('/mod/jitsi/sessionpriv.php', ['peer' => $peerid]);
$PAGE->set_context(context_system::instance());
require_login();

$PAGE->set_title(get_string('privatesession', 'jitsi', $peer->firstname));
$PAGE->set_heading(get_string('privatesession', 'jitsi', $peer->firstname));

echo $OUTPUT->header();

if (get_config('mod_jitsi', 'privatesessions') == 1) {
    // Symmetric room: always the same regardless of who initiates.
    $minid = min($USER->id, $peerid);
    $maxid = max($USER->id, $peerid);
    $session = $SITE->shortname . '-priv-' . $minid . '-' . $maxid;

    $nom = null;
    switch (get_config('mod_jitsi', 'id')) {
        case 'username':
            $nom = $USER->username;
            break;
        case 'nameandsurname':
            $nom = $USER->firstname . ' ' . $USER->lastname;
            break;
    }

    $avatar = get_config('mod_jitsi', 'showavatars') ? $CFG->wwwroot . '/user/pix.php/' . $USER->id . '/f1.jpg' : null;

    // Both participants are moderators in a private 1-on-1 session.
    $teacher = 1;

    // Log the private session access.
    $event = \mod_jitsi\event\jitsi_private_session_enter::event_with_peer($peerid);
    $event->trigger();

    // Notify the peer when someone enters their session.
    if ($USER->id != $peerid) {
        sendnotificationprivatesession($USER, $peer);
    }

    createsessionpriv($teacher, 0, $avatar, $nom, $session, null, 0, false, $peerid);
} else {
    echo get_string('privatesessiondisabled', 'jitsi');
}

echo $OUTPUT->footer();
