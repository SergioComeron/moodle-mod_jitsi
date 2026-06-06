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
 * AMD module: settings-driven controls for an active Jitsi session.
 *
 * Wires up two optional, configuration-gated behaviours on the conference api:
 *  - auto-fill the room password (for moderators and on passwordRequired), and
 *  - report the session end and redirect away when the meeting is closed (finish-and-return).
 *
 * @module     mod_jitsi/session_controls
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import Notification from 'core/notification';

/**
 * Register the configured session controls.
 *
 * The live JitsiMeetExternalAPI instance is read from window.jitsiSessionApi, set by the
 * inline session script, since js_call_amd can only pass JSON-serialisable arguments.
 *
 * @param {object} config Configuration.
 * @param {number} config.jitsiid Jitsi activity instance id.
 * @param {number} config.userid Current user id.
 * @param {number} config.cmid Course module id.
 * @param {?string} config.password Room password to auto-fill (null/empty to disable).
 * @param {boolean} config.finishAndReturn Whether to redirect away when the meeting closes.
 * @param {boolean} config.reportEnd Whether to report the session end (press_button_end) on close.
 * @param {?string} config.closeRedirectUrl URL to redirect to when the meeting closes.
 */
export const init = (config) => {
    const api = window.jitsiSessionApi;
    if (!api) {
        return;
    }

    if (config.password) {
        api.addEventListener('participantRoleChanged', (event) => {
            if (event.role === 'moderator') {
                api.executeCommand('password', config.password);
            }
        });
        api.on('passwordRequired', () => {
            api.executeCommand('password', config.password);
        });
    }

    if (config.finishAndReturn) {
        api.on('readyToClose', () => {
            if (config.reportEnd) {
                Ajax.call([{
                    methodname: 'mod_jitsi_press_button_end',
                    args: {jitsi: config.jitsiid, user: config.userid, cmid: config.cmid},
                }])[0].fail(Notification.exception);
            }
            api.dispose();
            if (config.closeRedirectUrl) {
                window.location.href = config.closeRedirectUrl;
            }
        });
    }
};
