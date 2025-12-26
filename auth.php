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
 * Library of interface functions and constants for module jitsi
 *
 * All the core Moodle functions, neeeded to allow the module to work
 * integrated in Moodle should be placed here.
 *
 * All the jitsi specific functions, needed to implement all the module
 * logic, should go to locallib.php. This will help to save some memory when
 * Moodle is performing actions across all modules.
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname(dirname(dirname(__FILE__))) . '/config.php');
require_once(dirname(dirname(dirname(__FILE__))) . '/lib/moodlelib.php');
require_once(dirname(__FILE__) . '/lib.php');
require_once(__DIR__ . '/api/vendor/autoload.php');

require_login();
global $DB, $CFG;
$name = optional_param('name', null, PARAM_TEXT);

$PAGE->set_context(context_system::instance());

$tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";
if ($name) {
    if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
        throw new \Exception('Api client not found on ' . $CFG->wwwroot . '/mod/jitsi/api/vendor/autoload.php');
    }

    $accountbyname = $DB->get_record('jitsi_record_account', ['name' => $name]);
    if ($accountbyname) {
        if ($accountbyname->inuse == 1 && $accountbyname->clientaccesstoken == null && $accountbyname->clientrefreshtoken == null) {
            $accountbyname->inuse = 0;
            $DB->update_record('jitsi_record_account', $accountbyname);
        }
    }

    $accountinuse = $DB->get_record('jitsi_record_account', ['inuse' => 1]);

    unset($_SESSION[$tokensessionkey]);
    if ($accountinuse) {
        $client = new Google_Client();
        $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
        $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

        $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";
        $client->setAccessToken($accountinuse->clientaccesstoken);

        $t = time();
        $timediff = $t - $accountinuse->tokencreated;

        if ($timediff > 3599) {
            // Validate refresh token exists before attempting to use it.
            if (empty($accountinuse->clientrefreshtoken)) {
                // Mark account as not in use and throw clear error.
                $accountinuse->inuse = 0;
                $DB->update_record('jitsi_record_account', $accountinuse);
                throw new moodle_exception(
                    'error',
                    'mod_jitsi',
                    '',
                    'The YouTube account "' . $accountinuse->name . '" is missing a refresh token. ' .
                    'Please delete and re-add this account in Site administration > Plugins > Activity modules > ' .
                    'Jitsi > Streaming/Recording accounts. Make sure to use an incognito/private browser window ' .
                    'when re-adding the account to force Google to provide a new refresh token.'
                );
            }

            $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($accountinuse->clientrefreshtoken);

            $accountinuse->clientaccesstoken = $newaccesstoken['access_token'];
            $newrefreshaccesstoken = $client->getRefreshToken();
            $accountinuse->refreshtoken = $newrefreshaccesstoken;
            $accountinuse->tokencreated = time();
            $DB->update_record('jitsi_record_account', $accountinuse);
        }

        $accountinuse->inuse = 0;
        $DB->update_record('jitsi_record_account', $accountinuse);
    }

    $_SESSION['name'] = $name;
}

$accounttab = $DB->get_record('jitsi_record_account', ['name' => $_SESSION['name']]);
if (!$accounttab) {
    $_SESSION[$tokensessionkey] = null;
}

if (get_config('mod_jitsi', 'oauth_id') == null || get_config('mod_jitsi', 'oauth_secret') == null) {
    echo "Empty parameters 'jitsi_oauth_id' & 'jitsi_oauth_secret'";
} else {
    if (!file_exists(__DIR__ . '/api/vendor/autoload.php')) {
        throw new \Exception('please run "composer require google/apiclient:~2.0" in "' . __DIR__ . '"');
    }

    require_once(__DIR__ . '/api/vendor/autoload.php');

    $oauth2clientid = get_config('mod_jitsi', 'oauth_id');
    $oauth2clientsecret = get_config('mod_jitsi', 'oauth_secret');

    $client = new Google_Client();
    $client->setClientId($oauth2clientid);
    $client->setClientSecret($oauth2clientsecret);
    $client->setScopes('https://www.googleapis.com/auth/youtube');
    $client->setAccessType("offline");
    $client->setPrompt("consent"); // Force Google to always return refresh token.

    $httparray = explode(":", $CFG->wwwroot);
    $principiohttp = $httparray[0] . '://';

    $redirect = filter_var(
        $principiohttp . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'],
        FILTER_SANITIZE_URL
    );
    $client->setRedirectUri($redirect);

    $tokensessionkey = 'token-' . $client->prepareScopes();

    if (isset($_GET['code'])) {
        $paramstring = base64UrlDecode($_GET['state']);
        $paramarray = explode("&", $paramstring);
        $randstring = $paramarray[1];
        $namestring = $paramarray[0];
        $randarray = explode("=", $randstring);
        $namearray = explode("=", $namestring);
        $rand = $randarray[1];
        $name = $namearray[1];

        if (strval($_SESSION['rand']) !== strval($rand)) {
            die('The session state did not match.');
        }
        $client->authenticate($_GET['code']);
        $_SESSION[$tokensessionkey] = $client->getAccessToken();

        header('Location: ' . $redirect);
    }

    if (isset($_SESSION[$tokensessionkey])) {
        $client->setAccessToken($_SESSION[$tokensessionkey]);
    }

    if ($client->getAccessToken()) {
        try {
            $PAGE->set_url('/mod/jitsi/auth.php');
            $PAGE->set_title(format_string(get_string('accounts', 'jitsi')));
            $PAGE->set_heading(format_string(get_string('accounts', 'jitsi')));
            echo $OUTPUT->header();


            $accesstoken = $client->getAccessToken()["access_token"];
            $clientrefreshtoken = $client->getRefreshToken();

            // Validate that Google returned a refresh token.
            if (empty($clientrefreshtoken)) {
                echo $OUTPUT->box_start('generalbox alert alert-danger');
                echo '<h4>' . get_string('error') . '</h4>';
                echo '<p><strong>' . get_string('refreshtokenmissing', 'jitsi') . '</strong></p>';
                echo '<p>' . get_string('refreshtokenmissingdetail', 'jitsi') . '</p>';
                echo '<ol>';
                echo '<li>' . get_string('refreshtokenstep1', 'jitsi') .
                     ' <a href="https://myaccount.google.com/permissions" target="_blank">' .
                     'https://myaccount.google.com/permissions</a></li>';
                echo '<li>' . get_string('refreshtokenstep2', 'jitsi') . '</li>';
                echo '<li>' . get_string('refreshtokenstep3', 'jitsi') . '</li>';
                echo '</ol>';
                echo $OUTPUT->box_end();

                $link = new moodle_url('/mod/jitsi/adminaccounts.php');
                echo '<a href="' . $link . '" class="btn btn-primary">' . get_string('back') . '</a>';
                echo $OUTPUT->footer();
                exit;
            }

            echo $OUTPUT->box(get_string('accountconnected', 'jitsi'));

            $link = new moodle_url('/mod/jitsi/adminaccounts.php');
            echo '<a href=' . $link . '>' . get_string('back') . '</a>';

            $account = $DB->get_record('jitsi_record_account', ['name' => $_SESSION['name']]);

            if ($account == null) {
                $account = new stdClass();

                $time = time();

                $account->name = $_SESSION['name'];
                $account->clientaccesstoken = $accesstoken;
                $account->clientrefreshtoken = $clientrefreshtoken;
                $account->tokencreated = $time;
                $account->inuse = 1;
                $DB->insert_record('jitsi_record_account', $account);
            } else {
                $time = time();
                $account->clientaccesstoken = $accesstoken;
                $account->clientrefreshtoken = $clientrefreshtoken;
                $account->tokencreated = $time;
                $account->inuse = 1;
                $DB->update_record('jitsi_record_account', $account);
            }
        } catch (Google_Service_Exception $e) {
            $htmlbody = sprintf(
                '<p>A service error occurred: <code>%s</code></p>',
                htmlspecialchars($e->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401)
            );
        } catch (Google_Exception $e) {
            $htmlbody = sprintf(
                '<p>A service error occurred: <code>%s</code></p>',
                htmlspecialchars(
                    $e->getMessage(),
                    ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML401
                )
            );
        }
        $_SESSION[$tokensessionkey] = $client->getAccessToken();

        echo $OUTPUT->footer();
    } else if ($oauth2clientid == 'REPLACE_ME') {
        echo "<h3>Client Credentials Required</h3>";
        echo "<p>You need to set <code>\$OAUTH2_CLIENT_ID</code> and";
        echo   "<code>\$OAUTH2_CLIENT_ID</code> before proceeding.";
        echo "<p>";
    } else {
        $PAGE->set_url('/mod/jitsi/auth.php');
        $PAGE->set_title(format_string(get_string('accounts', 'jitsi')));
        $PAGE->set_heading(format_string(get_string('accounts', 'jitsi')));
        echo $OUTPUT->header();

        $rand = mt_rand();
        $stateparameters = 'name=' . $name . '&rand=' . $rand;
        $state = base64UrlEncode($stateparameters);
        $client->setState($state);
        $_SESSION['rand'] = $rand;

        $authurl = $client->createAuthUrl();
        echo "<h3>Authorization Required</h3>";
        echo "<p>You need to <a href=\"$authurl\">authorize access</a> before proceeding.<p>";

        echo $OUTPUT->footer();
    }
}
