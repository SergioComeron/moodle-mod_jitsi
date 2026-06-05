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
 * Google/YouTube API client helpers (OAuth token handling and account rotation).
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class google {
    /**
     * Get a Google API client for the currently in-use streaming account.
     *
     * @return \Google_Client|false Client, or false if the token could not be refreshed
     */
    public static function get_client() {
        global $DB;
        $account = $DB->get_record('jitsi_record_account', ['inuse' => 1]);
        return self::get_client_by_account($account);
    }

    /**
     * Get a Google API client for a specific streaming account, refreshing the
     * access token if expired.
     *
     * @param \stdClass $account Streaming account record
     * @return \Google_Client|false Client, or false if the token could not be refreshed
     */
    public static function get_client_by_account($account) {
        global $DB;
        if (!file_exists(__DIR__ . '/../../api/vendor/autoload.php')) {
            throw new \Exception('please run "composer require google/apiclient:~2.0" in "'
                . __DIR__ . '/../../api"');
        }
        require_once(__DIR__ . '/../../api/vendor/autoload.php');

        $client = new \Google_Client();

        $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
        $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

        $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";

        $_SESSION[$tokensessionkey] = $account->clientaccesstoken;
        $client->setAccessToken($_SESSION[$tokensessionkey]);

        if ($client->isAccessTokenExpired()) {
            // Validate refresh token exists before attempting to use it.
            if (empty($account->clientrefreshtoken)) {
                if ($account->inuse == 1) {
                    $account->inuse = 0;
                }
                $account->clientaccesstoken = null;
                $account->tokencreated = 0;
                $DB->update_record('jitsi_record_account', $account);
                throw new \moodle_exception(
                    'error',
                    'mod_jitsi',
                    '',
                    'The YouTube account "' . $account->name . '" is missing a refresh token. ' .
                    'Please delete and re-add this account in Site administration > Plugins > Activity modules > ' .
                    'Jitsi > Streaming/Recording accounts.'
                );
            }

            try {
                $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($account->clientrefreshtoken);
                $account->clientaccesstoken = $newaccesstoken["access_token"];
                $newrefreshaccesstoken = $client->getRefreshToken();
                $newrefreshaccesstoken = $client->getRefreshToken();
                $account->clientrefreshtoken = $newrefreshaccesstoken;
                $account->tokencreated = time();
            } catch (\Google_Service_Exception $e) {
                if ($account->inuse == 1) {
                    $account->inuse = 0;
                }
                $account->clientaccesstoken = null;
                $account->clientrefreshtoken = null;
                $account->tokencreated = 0;
                $DB->update_record('jitsi_record_account', $account);
                $client->revokeToken();
                return false;
            } catch (\Google_Exception $e) {
                if ($account->inuse == 1) {
                    $account->inuse = 0;
                }
                $account->clientaccesstoken = null;
                $account->clientrefreshtoken = null;
                $account->tokencreated = 0;
                $DB->update_record('jitsi_record_account', $account);
                $client->revokeToken();
                return false;
            }
        }
        return $client;
    }

    /**
     * Rotate the in-use streaming account to the next queued one.
     *
     * @return int The id of the account left in use
     */
    public static function change_account() {
        global $DB;

        $sql = 'select * from {jitsi_record_account} where {jitsi_record_account}.inqueue = 1 and
         {jitsi_record_account}.clientaccesstoken != \'\' and {jitsi_record_account}.clientrefreshtoken != \'\' order by id asc';
        $accounts = $DB->get_records_sql($sql);
        $accountinuse = $DB->get_record('jitsi_record_account', ['inuse' => 1]);
        if ($accounts == null) {
            return $accountinuse->id;
        }
        $arrayparaiterar = array_slice($accounts, array_search($accountinuse->id, array_keys($accounts)) + 1);

        if (count($arrayparaiterar) == 0) {
            $arrayparaiterar = array_slice($accounts, 0);
        }
        $newaccountinuse = current($arrayparaiterar);
        $accountinuse->inuse = 0;
        $newaccountinuse->inuse = 1;
        $DB->update_record('jitsi_record_account', $accountinuse);
        $DB->update_record('jitsi_record_account', $newaccountinuse);

        return $newaccountinuse->id;
    }
}
