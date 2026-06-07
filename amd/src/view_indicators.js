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
 * AMD module: live header indicators for the activity view.
 *
 * Polls the server every few seconds to refresh the connected-attendees count/list
 * and to toggle the Jibri "is being recorded" badge.
 *
 * @module     mod_jitsi/view_indicators
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import Config from 'core/config';
import {getString} from 'core/str';

/** Poll interval in milliseconds. */
const POLL_INTERVAL = 15000;

/**
 * Refresh the connected-attendees count and dropdown list.
 *
 * @param {number} jitsiid Jitsi activity instance id.
 * @param {number} courseid Course id, for profile links.
 * @param {string} noUsersText Localised "no connected users" text.
 */
const refreshPresence = (jitsiid, courseid, noUsersText) => {
    Ajax.call([{
        methodname: 'mod_jitsi_get_presence_users',
        args: {jitsiid: jitsiid},
    }])[0].then((users) => {
        const countEl = document.getElementById('jitsi-presence-count');
        const listEl = document.getElementById('jitsi-presence-list');
        if (countEl) {
            countEl.textContent = users.length;
        }
        if (!listEl) {
            return users;
        }
        listEl.innerHTML = '';
        if (users.length === 0) {
            const li = document.createElement('li');
            const span = document.createElement('span');
            span.className = 'dropdown-item-text text-muted';
            span.textContent = noUsersText;
            li.appendChild(span);
            listEl.appendChild(li);
            return users;
        }
        users.forEach((u) => {
            const li = document.createElement('li');
            if (u.isguest) {
                const span = document.createElement('span');
                span.className = 'dropdown-item-text';
                const icon = document.createElement('i');
                icon.className = 'fa fa-user-secret text-muted me-1';
                icon.setAttribute('aria-hidden', 'true');
                span.appendChild(icon);
                span.appendChild(document.createTextNode(u.name));
                li.appendChild(span);
            } else {
                const a = document.createElement('a');
                a.className = 'dropdown-item';
                a.href = Config.wwwroot + '/user/view.php?id=' + u.userid + '&course=' + courseid;
                a.target = '_blank';
                a.textContent = u.name;
                li.appendChild(a);
            }
            listEl.appendChild(li);
        });
        return users;
    }).catch(() => {
        return;
    });
};

/**
 * Refresh the current user's total connected-minutes counter.
 *
 * @param {number} cmid Course module id.
 */
const refreshUserMinutes = (cmid) => {
    Ajax.call([{
        methodname: 'mod_jitsi_get_user_minutes',
        args: {cmid: cmid},
    }])[0].then((result) => {
        const minutesEl = document.getElementById('jitsi-user-minutes');
        if (minutesEl) {
            minutesEl.textContent = result.minutes;
        }
        return result;
    }).catch(() => {
        return;
    });
};

/**
 * Toggle the Jibri "is being recorded" badge based on current recording status.
 *
 * @param {number} jitsiid Jitsi activity instance id.
 */
const refreshJibriBadge = (jitsiid) => {
    Ajax.call([{
        methodname: 'mod_jitsi_get_jibri_recording',
        args: {jitsiid: jitsiid},
    }])[0].then((recording) => {
        const badge = document.getElementById('jitsi-jibri-badge');
        if (badge) {
            badge.classList.toggle('d-none', !recording);
        }
        return recording;
    }).catch(() => {
        return;
    });
};

/**
 * Start the live header indicators.
 *
 * @param {object} config Configuration.
 * @param {number} config.jitsiid Jitsi activity instance id.
 * @param {number} config.courseid Course id, for profile links.
 * @param {number} config.cmid Course module id, for the user-minutes counter.
 */
export const init = (config) => {
    getString('noconnectedusers', 'mod_jitsi').then((noUsersText) => {
        setInterval(() => {
            refreshPresence(config.jitsiid, config.courseid, noUsersText);
        }, POLL_INTERVAL);
        return noUsersText;
    }).catch(() => {
        return;
    });

    setInterval(() => {
        refreshJibriBadge(config.jitsiid);
        refreshUserMinutes(config.cmid);
    }, POLL_INTERVAL);
};
