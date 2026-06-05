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
 * Notification helpers: private-session messages, admin error emails and Web Push.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class notification {
    /**
     * Notify the session owner that a user entered their private session.
     *
     * @param \stdClass $fromuser User entering the private session
     * @param \stdClass $touser User session owner
     */
    public static function notify_private_session($fromuser, $touser) {
        global $CFG;
        $message = new \core\message\message();
        $message->component = 'mod_jitsi';
        $message->name = 'onprivatesession';
        $message->userfrom = \core_user::get_noreply_user();
        $message->userto = $touser;
        $message->subject = get_string('userenter', 'jitsi', $fromuser->firstname);
        $message->fullmessage = get_string('userenter', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
        $message->fullmessageformat = FORMAT_MARKDOWN;
        $message->fullmessagehtml = get_string('user') . ' <a href="' . $CFG->wwwroot
            . '/user/profile.php?id=' . $fromuser->id . '"> '
            . $fromuser->firstname . ' ' . $fromuser->lastname
            . '</a> ' . get_string('hasentered', 'jitsi') . '. ' . get_string('click', 'jitsi') . '<a href="'
            . new \moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id])
            . '"> ' . get_string('here', 'jitsi') . '</a> ' . get_string('toenter', 'jitsi');
        $message->smallmessage = get_string('userenter', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
        $message->notification = 1;
        $message->contexturl = new \moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id]);
        $message->contexturlname = 'Private session';
        $content = ['*' => ['header' => '', 'footer' => '']];
        $message->set_additional_content('email', $content);
        message_send($message);
    }

    /**
     * Notify a user that another user is calling them to a private session.
     *
     * @param \stdClass $fromuser User starting the call
     * @param \stdClass $touser User being called
     */
    public static function notify_call($fromuser, $touser) {
        global $CFG;
        $message = new \core\message\message();
        $message->component = 'mod_jitsi';
        $message->name = 'callprivatesession';
        $message->userfrom = \core_user::get_noreply_user();
        $message->userto = $touser;
        $message->subject = get_string('usercall', 'jitsi', $fromuser->firstname);
        $message->fullmessage = get_string('usercall', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
        $message->fullmessageformat = FORMAT_MARKDOWN;
        $message->fullmessagehtml = get_string('user') . ' <a href="' . $CFG->wwwroot
            . '/user/profile.php?id=' . $fromuser->id . '"> '
            . $fromuser->firstname . ' ' . $fromuser->lastname
            . '</a> ' . get_string('iscalling', 'jitsi') . '. ' . get_string('click', 'jitsi') . '<a href="'
            . new \moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id])
            . '"> ' . get_string('here', 'jitsi') . '</a> ' . get_string('toenter', 'jitsi');
        $message->smallmessage = get_string('usercall', 'jitsi', $fromuser->firstname . ' ' . $fromuser->lastname);
        $message->notification = 1;
        $message->contexturl = new \moodle_url('/mod/jitsi/sessionpriv.php', ['peer' => $fromuser->id]);
        $message->contexturlname = 'Private session';
        $content = ['*' => ['header' => '', 'footer' => '']];
        $message->set_additional_content('email', $content);
        message_send($message);
    }

    /**
     * Email site admins about a streaming/recording error and log the error event.
     *
     * @param int $jitsi Jitsi session id
     * @param int $user User id
     * @param string $error Error message
     * @param \stdClass $source Source record (provides the streaming account)
     */
    public static function send_error($jitsi, $user, $error, $source) {
        global $PAGE, $DB, $CFG;
        $jitsiob = $DB->get_record('jitsi', ['id' => $jitsi]);
        $cm = get_coursemodule_from_instance('jitsi', $jitsi);
        $cmid = $cm->id;
        $PAGE->set_context(\context_module::instance($cmid));

        $admins = get_admins();
        $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);
        $DB->update_record('jitsi', $jitsiob);

        $user = $DB->get_record('user', ['id' => $user]);
        $mensaje = "El usuario " . $user->firstname . " " . $user->lastname .
            " ha tenido un error al intentar grabar la sesión de jitsi con id " . $jitsi . "\nInfo:\n" . $error .
            " en la cuenta: " . $account->name . " (id: " . $account->id . ")\n
        Para más información, mira el log:\n
        LOG: " . $CFG->wwwroot . "/report/log/index.php?chooselog=1&id=" . $jitsiob->course . "&modid=" . $cmid . "\n
        URL: " . $CFG->wwwroot . "/mod/jitsi/view.php?id=" . $cmid . "\n
        Nombre de la sesión: " . $DB->get_record('jitsi', ['id' => $jitsi])->name . "\n
        Curso: " . $DB->get_record('course', ['id' => $DB->get_record('jitsi', ['id' => $jitsi])->course])->fullname . "\n
        Usuario: " . $user->username . "\n";
        foreach ($admins as $admin) {
            email_to_user($admin, $admin, "ERROR JITSI! el usuario: "
                . $user->username . " ha tenido un error en el jitsi: " . $jitsi, $mensaje);
        }

        $event = \mod_jitsi\event\jitsi_error::create([
            'objectid' => $cmid,
            'context' => $PAGE->context,
            'other' => ['error' => $error, 'account' => $account->id],
        ]);
        $event->add_record_snapshot('course', $PAGE->course);
        $event->add_record_snapshot('jitsi', $jitsiob);
        $event->trigger();
    }

    /**
     * Send a Web Push notification to a user across their registered subscriptions.
     *
     * @param int $userid Recipient user ID
     * @param string $title Notification title
     * @param string $body Notification body
     * @param string $url URL to open when notification is clicked
     */
    public static function send_push($userid, $title, $body, $url) {
        global $DB, $CFG;

        $autoloader = __DIR__ . '/../../api/vendor/autoload.php';
        if (!file_exists($autoloader)) {
            return;
        }
        require_once($autoloader);

        $subscriptions = $DB->get_records('jitsi_push_subscriptions', ['userid' => $userid]);
        if (empty($subscriptions)) {
            return;
        }

        // Get or generate VAPID keys.
        $publickey = get_config('mod_jitsi', 'vapid_public_key');
        $privatekey = get_config('mod_jitsi', 'vapid_private_key');

        if (!$publickey || !$privatekey) {
            $keys = \Minishlink\WebPush\VAPID::createVapidKeys();
            set_config('vapid_public_key', $keys['publicKey'], 'mod_jitsi');
            set_config('vapid_private_key', $keys['privateKey'], 'mod_jitsi');
            $publickey = $keys['publicKey'];
            $privatekey = $keys['privateKey'];
        }

        // VAPID subject must be a mailto: URI or https:// URL.
        // mailto: is more reliable across push services.
        $admin = get_admin();
        $vapidsubject = 'mailto:' . $admin->email;

        $auth = [
            'VAPID' => [
                'subject'    => $vapidsubject,
                'publicKey'  => $publickey,
                'privateKey' => $privatekey,
            ],
        ];

        try {
            $webpush = new \Minishlink\WebPush\WebPush($auth);
            $payload = json_encode([
                'title' => $title,
                'body'  => $body,
                'url'   => $url,
                'icon'  => $CFG->wwwroot . '/mod/jitsi/pix/icon.png',
            ]);

            foreach ($subscriptions as $sub) {
                $subscription = \Minishlink\WebPush\Subscription::create([
                    'endpoint' => $sub->endpoint,
                    'keys'     => [
                        'auth'   => $sub->authkey,
                        'p256dh' => $sub->p256dhkey,
                    ],
                ]);
                $webpush->queueNotification($subscription, $payload);
            }

            foreach ($webpush->flush() as $report) {
                debugging('Web Push report for ' . $report->getEndpoint() . ': '
                    . ($report->isSuccess() ? 'OK' : $report->getReason()), DEBUG_DEVELOPER);
                if ($report->isSubscriptionExpired()) {
                    $DB->delete_records_select(
                        'jitsi_push_subscriptions',
                        'userid = :userid AND ' . $DB->sql_compare_text('endpoint') . ' = ' . $DB->sql_compare_text(':endpoint'),
                        ['userid' => $userid, 'endpoint' => $report->getEndpoint()]
                    );
                }
            }
        } catch (\Exception $e) {
            debugging('Web Push error: ' . $e->getMessage(), DEBUG_DEVELOPER);
        }
    }
}
