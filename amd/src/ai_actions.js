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
import ModalFactory from 'core/modal_factory';
import ModalEvents from 'core/modal_events';

/** Maps each AI web service method to its "queued" confirmation string key. */
const QUEUED_MAP = {
    'mod_jitsi_queue_ai_summary': 'aisummaryqueued',
    'mod_jitsi_queue_ai_quiz': 'aiquizqueued',
    'mod_jitsi_queue_ai_transcription': 'aitranscriptionqueued',
};

/** GDPR notice body HTML, set from config at init. */
let gdprBody = '';

/**
 * Fire the AI action web service and update the menu item on success.
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
            action.el.textContent = await getString(QUEUED_MAP[action.methodname], 'mod_jitsi');
        } else {
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
        const modal = await ModalFactory.create({
            type: ModalFactory.types.SAVE_CANCEL,
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
