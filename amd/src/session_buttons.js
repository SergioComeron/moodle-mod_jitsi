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
 * AMD module: audit toolbar button presses in an active Jitsi session.
 *
 * Logs camera, desktop, hangup and microphone toolbar clicks to the server so they can be
 * shown in the attendance/activity reports.
 *
 * @module     mod_jitsi/session_buttons
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import Notification from 'core/notification';

/** Map of Jitsi toolbar button keys to the web service that records the press. */
const BUTTON_METHODS = {
    'camera': 'mod_jitsi_press_button_cam',
    'desktop': 'mod_jitsi_press_button_desktop',
    '__end': 'mod_jitsi_press_button_end',
    'microphone': 'mod_jitsi_press_button_microphone',
};

/**
 * Register the toolbar-button audit listener.
 *
 * The live JitsiMeetExternalAPI instance is read from window.jitsiSessionApi, set by the
 * inline session script, since js_call_amd can only pass JSON-serialisable arguments.
 *
 * @param {object} config Configuration.
 * @param {number} config.jitsiid Jitsi activity instance id.
 * @param {number} config.userid Current user id.
 * @param {number} config.cmid Course module id.
 */
export const init = (config) => {
    const api = window.jitsiSessionApi;
    if (!api) {
        return;
    }

    api.addEventListener('toolbarButtonClicked', (event) => {
        const methodname = BUTTON_METHODS[event.key];
        if (!methodname) {
            return;
        }
        Ajax.call([{
            methodname: methodname,
            args: {jitsi: config.jitsiid, user: config.userid, cmid: config.cmid},
        }])[0].fail(Notification.exception);
    });
};
