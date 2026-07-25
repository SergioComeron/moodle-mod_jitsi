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
 * AMD module: live GCP instance status for the server management table.
 *
 * Polls the gcpserversstatus endpoint and updates each server's status badge.
 * The Start/Stop/wait controls are all pre-rendered by PHP inside a
 * .jitsi-gcp-actions container; this module only toggles their visibility, so
 * static action links (delete, add Jibri, GCS) are never touched — unlike the
 * old inline script that rebuilt the cell from innerHTML regexes and silently
 * dropped any link it didn't know about.
 *
 * Also handles the Jibri pool desired-size inputs.
 *
 * @module     mod_jitsi/server_status
 * @copyright  2025 Sergio Comerón <jitsi@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Notification from 'core/notification';
import {getStrings} from 'core/str';

/** Poll interval in milliseconds. */
const POLL_INTERVAL = 10000;

/**
 * Map of GCP instance status to badge appearance, emoji, localisable label key and button state.
 * The visible label is resolved from `strings` at render time (see loadStrings).
 */
const STATUS_MAP = {
    'RUNNING': {badge: 'bg-success', emoji: '🟢', key: 'statusrunning', state: 'running'},
    'STOPPED': {badge: 'bg-danger', emoji: '🔴', key: 'statusstopped', state: 'stopped'},
    'TERMINATED': {badge: 'bg-danger', emoji: '🔴', key: 'statusstopped', state: 'stopped'},
    'STOPPING': {badge: 'bg-warning', emoji: '🟡', key: 'statusstopping', state: 'transition'},
    'PROVISIONING': {badge: 'bg-info', emoji: '🔵', key: 'statusstarting', state: 'running'},
    'STAGING': {badge: 'bg-info', emoji: '🔵', key: 'statusstarting', state: 'running'},
    'SUSPENDING': {badge: 'bg-warning', emoji: '🟡', key: 'statussuspending', state: 'transition'},
    'SUSPENDED': {badge: 'bg-secondary', emoji: '⚫', key: 'statussuspended', state: 'stopped'},
    'REPAIRING': {badge: 'bg-warning', emoji: '🔧', key: 'statusrepairing', state: 'transition'},
    'NOT_FOUND': {badge: 'bg-dark', emoji: '❌', key: 'statusnotfound', state: 'stopped'},
    'ERROR': {badge: 'bg-secondary', emoji: '⚠️', key: 'statuserror', state: 'stopped'},
};

/** Localised label per STATUS_MAP key, plus the pool-size error, populated by loadStrings(). */
const strings = {};

/**
 * Load the status labels and the pool-size error string into the module cache.
 *
 * @return {Promise} Resolves once the strings are cached.
 */
const loadStrings = () => {
    const keys = ['statusrunning', 'statusstopped', 'statusstopping', 'statusstarting',
        'statussuspending', 'statussuspended', 'statusrepairing', 'statusnotfound',
        'statuserror', 'poolsizeupdatefailed'];
    return getStrings(keys.map((key) => ({key, component: 'mod_jitsi'})))
        .then((values) => {
            keys.forEach((key, i) => {
                strings[key] = values[i];
            });
            return strings;
        }).catch(Notification.exception);
};

/**
 * Toggle the pre-rendered Start/Stop/wait controls for one server.
 *
 * @param {string|number} serverId Server id.
 * @param {string} state One of 'running' | 'stopped' | 'transition'.
 */
const updateButtons = (serverId, state) => {
    const container = document.querySelector('.jitsi-gcp-actions[data-serverid="' + serverId + '"]');
    if (!container) {
        return;
    }
    const start = container.querySelector('.jitsi-gcp-start');
    const stop = container.querySelector('.jitsi-gcp-stop');
    const wait = container.querySelector('.jitsi-gcp-wait');
    if (start) {
        start.classList.toggle('d-none', state !== 'stopped');
    }
    if (stop) {
        stop.classList.toggle('d-none', state !== 'running');
    }
    if (wait) {
        wait.classList.toggle('d-none', state !== 'transition');
    }
};

/**
 * Poll the server statuses once and update badges + buttons.
 *
 * @param {object} cfg Module config.
 */
const updateStatuses = (cfg) => {
    fetch(cfg.statusUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({sesskey: cfg.sesskey, ids: cfg.serverIds.join(',')}),
    })
        .then((res) => res.json())
        .then((data) => {
            if (data.error) {
                return;
            }
            for (const id in data) {
                const badge = document.getElementById('gcp-status-' + id);
                if (!badge) {
                    continue;
                }
                const status = data[id].status;
                const entry = STATUS_MAP[status];
                if (entry) {
                    badge.className = 'badge ' + entry.badge;
                    badge.textContent = entry.emoji + ' ' + (strings[entry.key] || status);
                    if (status === 'ERROR' && data[id].message) {
                        badge.title = data[id].message;
                    }
                    updateButtons(id, entry.state);
                } else {
                    badge.className = 'badge bg-secondary';
                    badge.textContent = status;
                }
            }
            return;
        })
        .catch(() => {
            return;
        });
};

/**
 * Wire the Jibri pool desired-size inputs.
 *
 * @param {object} cfg Module config.
 */
const wirePoolSizeInputs = (cfg) => {
    document.querySelectorAll('.jitsi-poolsize-input').forEach((input) => {
        input.addEventListener('change', () => {
            const url = cfg.poolSizeUrl + '&id=' + encodeURIComponent(input.dataset.serverid) +
                '&poolsize=' + encodeURIComponent(input.value);
            fetch(url, {method: 'POST'})
                .then((r) => r.json())
                .then((d) => {
                    if (d.status !== 'ok') {
                        Notification.addNotification({
                            message: strings.poolsizeupdatefailed || 'Could not update pool size.',
                            type: 'error',
                        });
                    }
                    return;
                })
                .catch(() => {
                    Notification.addNotification({
                        message: strings.poolsizeupdatefailed || 'Could not update pool size.',
                        type: 'error',
                    });
                });
        });
    });
};

/**
 * Start polling GCP statuses and wire the pool size inputs.
 *
 * @param {object} config Module config.
 * @param {string} config.sesskey Session key.
 * @param {string} config.statusUrl gcpserversstatus endpoint.
 * @param {string} config.poolSizeUrl updatepoolsize endpoint (with sesskey).
 * @param {Array<number>} config.serverIds GCP server ids to poll.
 */
export const init = (config) => {
    loadStrings();
    wirePoolSizeInputs(config);
    if (!config.serverIds || config.serverIds.length === 0) {
        return;
    }
    setInterval(() => updateStatuses(config), POLL_INTERVAL);
    setTimeout(() => updateStatuses(config), 2000);
};
