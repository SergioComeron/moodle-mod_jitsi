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
 * AMD module: AI actions dropdown and transcript timestamp navigation.
 *
 * Handles the "generate" AI actions (summary/quiz/transcription) behind a GDPR
 * confirmation modal, and seeking a recording to a transcript timestamp.
 *
 * @module     mod_jitsi/ai_actions
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import Notification from 'core/notification';
import {getString} from 'core/str';
import {add as addToast} from 'core/toast';
import ModalSaveCancel from 'core/modal_save_cancel';
import ModalEvents from 'core/modal_events';

/** GDPR notice body HTML, set from config at init. */
let gdprBody = '';

/** Poll interval while a generation task is queued, in ms. */
const POLL_MS = 20000;

/** Give up polling a recording after this many ticks (~30 minutes). */
const MAX_TICKS = 90;

/** Recordings being polled, keyed by "sourcerecordid-cmid". */
const watched = new Map();

/** Interval id of the active poller, or null. */
let pollTimer = null;

/**
 * Ask the recordings table to re-fetch itself (handled by recordings_lazyload).
 */
const triggerReload = () => {
    document.dispatchEvent(new CustomEvent('mod_jitsi/recordings:reload'));
};

/**
 * One poll tick: query the AI status of every watched recording and reload
 * the recordings table when any of them has finished.
 */
const pollTick = async() => {
    const keys = [...watched.keys()];
    const requests = keys.map((key) => ({
        methodname: 'mod_jitsi_get_ai_status',
        args: {
            sourcerecordid: watched.get(key).sourcerecordid,
            cmid: watched.get(key).cmid,
        },
    }));
    const promises = Ajax.call(requests);
    let reloadNeeded = false;
    for (let i = 0; i < keys.length; i++) {
        try {
            const status = await promises[i];
            const entry = watched.get(keys[i]);
            entry.ticks++;
            const pending = [status.summary, status.quiz, status.transcription].includes('pending');
            if (!pending) {
                watched.delete(keys[i]);
                reloadNeeded = true;
            } else if (entry.ticks >= MAX_TICKS) {
                watched.delete(keys[i]);
            }
        } catch (ex) {
            watched.delete(keys[i]);
        }
    }
    if (watched.size === 0 && pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
    if (reloadNeeded) {
        triggerReload();
    }
};

/**
 * Start polling the AI status of a recording until its tasks finish.
 *
 * @param {number} sourcerecordid jitsi_source_record id.
 * @param {number} cmid Course module id.
 */
const startWatching = (sourcerecordid, cmid) => {
    const key = sourcerecordid + '-' + cmid;
    if (!watched.has(key)) {
        watched.set(key, {sourcerecordid, cmid, ticks: 0});
    }
    if (!pollTimer) {
        pollTimer = setInterval(() => {
            pollTick().catch(() => null);
        }, POLL_MS);
    }
};

/**
 * Scan the page for queued generations (rendered as .jitsi-ai-pending) and poll them.
 */
const scanPending = () => {
    document.querySelectorAll('.jitsi-ai-pending[data-sourcerecordid]').forEach((el) => {
        startWatching(parseInt(el.dataset.sourcerecordid, 10), parseInt(el.dataset.cmid, 10));
    });
};

/**
 * Fire the AI action web service, notify the user and refresh the recordings table.
 *
 * @param {object} action The action descriptor (methodname, sourcerecordid, cmid, el).
 */
const executeAction = async(action) => {
    action.el.classList.add('disabled');
    try {
        const result = await Ajax.call([{
            methodname: action.methodname,
            args: {sourcerecordid: action.sourcerecordid, cmid: action.cmid},
        }])[0];
        if (result.success) {
            await addToast(result.message, {type: 'info'});
            // Re-render the table: the item switches to its queued state and
            // scanPending() picks it up for polling.
            triggerReload();
            startWatching(action.sourcerecordid, action.cmid);
        } else {
            await addToast(result.message, {type: 'warning'});
            action.el.classList.remove('disabled');
        }
    } catch (ex) {
        Notification.exception(ex);
        action.el.classList.remove('disabled');
    }
};

/**
 * Show the GDPR confirmation modal before running an AI action.
 *
 * @param {object} action The action descriptor passed on to executeAction.
 */
const showGdprModal = async(action) => {
    try {
        const [title, confirmText] = await Promise.all([
            getString('aigdprnoticetitle', 'mod_jitsi'),
            getString('confirm', 'core'),
        ]);
        const modal = await ModalSaveCancel.create({
            title: title,
            body: gdprBody,
        });
        modal.setSaveButtonText(confirmText);
        const root = modal.getRoot();
        root.on(ModalEvents.save, () => {
            modal.destroy();
            executeAction(action);
        });
        root.on(ModalEvents.cancel, () => {
            modal.destroy();
        });
        modal.show();
    } catch (e) {
        // Fallback: native browser confirm if modal modules/strings are unavailable.
        const plainText = gdprBody.replace(/<[^>]+>/g, '');
        // eslint-disable-next-line no-alert
        if (window.confirm(plainText)) {
            executeAction(action);
        }
    }
};

/**
 * Initialise the AI actions dropdown and transcript timestamp navigation.
 *
 * @param {object} config Configuration.
 * @param {string} config.gdprBody GDPR notice body HTML shown in the confirm modal.
 */
export const init = (config) => {
    gdprBody = config.gdprBody;

    // Poll generations already queued when the table is (re)rendered.
    scanPending();
    document.addEventListener('mod_jitsi/recordings:loaded', scanPending);

    document.addEventListener('click', (e) => {
        const generateItem = e.target.closest('.jitsi-ai-generate');
        if (generateItem) {
            e.preventDefault();
            showGdprModal({
                methodname: generateItem.dataset.method,
                sourcerecordid: parseInt(generateItem.dataset.sourcerecordid, 10),
                cmid: parseInt(generateItem.dataset.cmid, 10),
                el: generateItem,
            });
            return;
        }

        const tsLink = e.target.closest('.jitsi-transcript-ts');
        if (tsLink) {
            e.preventDefault();
            const videoId = tsLink.dataset.video;
            const seconds = parseFloat(tsLink.dataset.seconds);
            const video = document.getElementById(videoId);
            if (video) {
                video.currentTime = seconds;
                video.play();
                video.scrollIntoView({behavior: 'smooth', block: 'center'});
            }
        }
    });
};
