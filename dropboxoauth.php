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
 * Dropbox OAuth2 redirect landing page for the "Record to Dropbox" button.
 *
 * Dropbox redirects here after the implicit-grant authorisation with the
 * access token in the URL fragment. The fragment never reaches the server;
 * the inline script below hands the token back to the opener session page
 * (same origin) via postMessage and closes the popup.
 *
 * @package    mod_jitsi
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(dirname($_SERVER['SCRIPT_FILENAME'], 3) . '/config.php');

require_login();

$PAGE->set_url('/mod/jitsi/dropboxoauth.php');
$PAGE->set_context(context_system::instance());

header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Dropbox</title></head>
<body>
<script>
(function() {
    var params = new URLSearchParams(window.location.hash.substring(1));
    var token = params.get('access_token');
    if (window.opener && token) {
        window.opener.postMessage({
            type: 'jitsiDropboxToken',
            token: token,
            expiresIn: parseInt(params.get('expires_in') || '0', 10)
        }, window.location.origin);
    }
    window.close();
})();
</script>
</body>
</html>
