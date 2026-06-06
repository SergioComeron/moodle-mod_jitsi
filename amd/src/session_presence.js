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
 * AMD module: presence tracking for an active Jitsi session.
 *
 * Reports the local participant's presence to the server via periodic heartbeats and a
 * "still participating" ping, plus on join/leave, and redirects once the conference is left.
 *
 * @module     mod_jitsi/session_presence
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';

/** Presence heartbeat interval in milliseconds. */
const HEARTBEAT_INTERVAL = 30000;

/** "Still participating" ping interval in milliseconds. */
const PARTICIPATING_INTERVAL = 60000;

/** Delay before redirecting after the conference is left, in milliseconds. */
const REDIRECT_DELAY = 2000;

/**
 * Generate a random per-tab session hash to disambiguate multiple tabs/windows.
 *
 * @returns {string} A short random identifier.
 */
const generateSessionHash = () => {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
};

/**
 * Start presence tracking for a Jitsi session.
 *
 * The live JitsiMeetExternalAPI instance is read from window.jitsiSessionApi, set by the
 * inline session script, since js_call_amd can only pass JSON-serialisable arguments.
 *
 * @param {object} config Configuration.
 * @param {number} config.jitsiid Jitsi activity instance id.
 * @param {number} config.cmid Course module id.
 * @param {number} config.userid Current user id.
 * @param {boolean} config.isGuest Whether the current user is a guest.
 * @param {string} config.guestName Display name to report for guests.
 * @param {boolean} config.trackJoinLeave Whether to report join/leave and redirect on leave.
 * @param {?string} config.redirectUrl URL to redirect to after leaving (null to stay put).
 */
export const init = (config) => {
    const api = window.jitsiSessionApi;
    const sessionHash = generateSessionHash();

    // Periodically flag that this user is still participating in the session.
    setInterval(() => {
        Ajax.call([{
            methodname: 'mod_jitsi_participating_session',
            args: {jitsi: config.jitsiid, user: config.userid, cmid: config.cmid},
        }]);
    }, PARTICIPATING_INTERVAL);

    // Periodic presence heartbeat.
    setInterval(() => {
        Ajax.call([{
            methodname: 'mod_jitsi_presence_heartbeat',
            args: {jitsiid: config.jitsiid, sessionhash: sessionHash},
        }]);
    }, HEARTBEAT_INTERVAL);

    if (!config.trackJoinLeave || !api) {
        return;
    }

    api.on('videoConferenceJoined', () => {
        Ajax.call([{
            methodname: 'mod_jitsi_presence_join',
            args: {
                jitsiid: config.jitsiid,
                sessionhash: sessionHash,
                guestname: config.isGuest ? config.guestName : '',
            },
        }]);
    });

    api.on('videoConferenceLeft', () => {
        Ajax.call([{
            methodname: 'mod_jitsi_presence_leave',
            args: {jitsiid: config.jitsiid, sessionhash: sessionHash},
        }]);
        if (config.redirectUrl) {
            setTimeout(() => {
                window.location.href = config.redirectUrl;
            }, REDIRECT_DELAY);
        }
    });
};
