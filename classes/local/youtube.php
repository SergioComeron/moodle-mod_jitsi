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
 * Operations on YouTube recordings (delete, embeddable, privacy toggle).
 *
 * @package    mod_jitsi
 * @copyright  2021 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class youtube {
    /**
     * Delete a recording's video from YouTube (and its jitsi_record) when deletable.
     *
     * @param int $idsource Jitsi source record id
     * @return bool
     */
    public static function delete_record($idsource) {
        global $CFG, $DB, $PAGE;
        require_once($CFG->dirroot . '/mod/jitsi/lib.php');
        $res = false;
        $source = $DB->get_record('jitsi_source_record', ['id' => $idsource]);
        $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);
        if (\mod_jitsi\local\recording::is_deletable($idsource)) {
            if ($source->link != null) {
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
                try {
                    $client->setAccessToken($_SESSION[$tokensessionkey]);
                } catch (\Exception $e) {
                    $account->clientaccesstoken = null;
                    $account->clientrefreshtoken = null;
                    $account->tokencreated = 0;
                    $DB->update_record('jitsi_record_account', $account);
                    return false;
                }
                if ($client->isAccessTokenExpired()) {
                    // Validate refresh token exists before attempting to use it.
                    if (empty($account->clientrefreshtoken)) {
                        if ($account->inuse == 1) {
                            $account->inuse = 0;
                        }
                        $account->clientaccesstoken = null;
                        $account->tokencreated = 0;
                        $DB->update_record('jitsi_record_account', $account);
                        return false;
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
                $youtube = new \Google_Service_YouTube($client);
                try {
                    $listresponse = $youtube->videos->listVideos("snippet", ['id' => $source->link]);
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
                if ($listresponse['items'] != []) {
                    if ($client->getAccessToken($idsource)) {
                        try {
                            $youtube->videos->delete($source->link);
                            delete_jitsi_record($idsource);
                            return true;
                        } catch (\Google_Service_Exception $e) {
                            throw new \Exception("exception" . $e->getMessage());
                        } catch (\Google_Exception $e) {
                            throw new \Exception("exception" . $e->getMessage());
                        }
                    }
                } else {
                    delete_jitsi_record($idsource);
                }
            } else {
                delete_jitsi_record($idsource);
            }
        }
        return $res;
    }

    /**
     * Make a YouTube video embeddable.
     *
     * @param int $idvideo YouTube video id (jitsi_source_record.link)
     * @return mixed Update response, or false on error
     */
    public static function make_embeddable($idvideo) {
        global $CFG, $DB;
        require_once($CFG->dirroot . '/mod/jitsi/lib.php');

        $source = $DB->get_record('jitsi_source_record', ['link' => $idvideo]);
        $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);
        $client = \mod_jitsi\local\google::get_client_by_account($account);
        $youtube = new \Google_Service_YouTube($client);

        try {
            $listresponse = $youtube->videos->listVideos("status", ['id' => $idvideo]);
            $video = $listresponse[0];

            $videostatus = $video->getStatus();
            if ($videostatus != null) {
                $updatevideo = new \Google_Service_YouTube_Video();
                $updatevideo->setId($idvideo);
                $updatestatus = new \Google_Service_YouTube_VideoStatus();
                $updatestatus->setEmbeddable(true);
                $updatevideo->setStatus($updatestatus);
                $updateresponse = $youtube->videos->update("status", $updatevideo);
                $source->embed = 1;
                $DB->update_record('jitsi_source_record', $source);
            }
        } catch (\Google_Service_Exception $e) {
            $record = $DB->get_record('jitsi_record', ['source' => $source->id]);
            $jitsi = $DB->get_record('jitsi', ['id' => $record->jitsi]);
            $source->embed = -1;
            $DB->update_record('jitsi_source_record', $source);
            senderror($jitsi->id, $source->userid, 'ERROR doembedable: ' . $e->getMessage(), $source);
            return false;
        } catch (\Google_Exception $e) {
            $record = $DB->get_record('jitsi_record', ['source' => $source->id]);
            $jitsi = $DB->get_record('jitsi', ['id' => $record->jitsi]);
            $source->embed = -1;
            $DB->update_record('jitsi_source_record', $source);
            senderror($jitsi->id, $source->userid, 'ERROR doembedable: ' . $e->getMessage(), $source);
            return false;
        }

        return $updateresponse;
    }

    /**
     * Toggle a YouTube video's privacy between unlisted and private.
     *
     * @param int $idvideo YouTube video id (jitsi_source_record.link)
     * @return mixed Update response, or false on error
     */
    public static function toggle_state($idvideo) {
        global $CFG, $DB;
        if (!file_exists(__DIR__ . '/../../api/vendor/autoload.php')) {
            throw new \Exception('please run "composer require google/apiclient:~2.0" in "'
                . __DIR__ . '/../../api"');
        }
        require_once(__DIR__ . '/../../api/vendor/autoload.php');

        $client = new \Google_Client();

        $client->setClientId(get_config('mod_jitsi', 'oauth_id'));
        $client->setClientSecret(get_config('mod_jitsi', 'oauth_secret'));

        $tokensessionkey = 'token-' . "https://www.googleapis.com/auth/youtube";

        $source = $DB->get_record('jitsi_source_record', ['link' => $idvideo]);
        $account = $DB->get_record('jitsi_record_account', ['id' => $source->account]);

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
                return false;
            }

            try {
                $newaccesstoken = $client->fetchAccessTokenWithRefreshToken($account->clientrefreshtoken);
                $account->clientaccesstoken = $newaccesstoken["access_token"];
                $newraccesstfreshaccesstoken = $client->getRefreshToken();
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

        $youtube = new \Google_Service_YouTube($client);

        try {
            $listresponse = $youtube->videos->listVideos("status", ['id' => $idvideo]);
            $video = $listresponse[0];

            $videostatus = $video['status'];
            if ($videostatus != null) {
                if ($videostatus['privacyStatus'] == 'unlisted') {
                    $videostatus['privacyStatus'] = 'private';
                    $updateresponse = $youtube->videos->update("status", $video);
                } else {
                    $videostatus['privacyStatus'] = 'unlisted';
                    $updateresponse = $youtube->videos->update("status", $video);
                }
            }
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
        return $updateresponse;
    }
}
