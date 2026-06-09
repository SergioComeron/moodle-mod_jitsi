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
 * AMD module: recording viewer poller for recordun.php.
 *
 * Polls the server every few seconds and swaps the embedded YouTube player in or out
 * as the activity's source recording appears or disappears.
 *
 * @module     mod_jitsi/recordun_poll
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';

/** Poll interval in milliseconds. */
const POLL_INTERVAL = 10000;

/** Delay before swapping content, to let the recording finish processing, in milliseconds. */
const SWAP_DELAY = 10000;

/** Whether a video is currently shown. */
let hasVideo = false;

/** Whether a content swap is in progress, to avoid overlapping transitions. */
let swapping = false;

/**
 * Returns a promise that resolves after the given delay.
 *
 * @param {number} ms Milliseconds to wait.
 * @return {Promise}
 */
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Render the embedded YouTube player for the given video id.
 *
 * @param {HTMLElement} container Video container element.
 * @param {string} link YouTube video id.
 */
const showVideo = (container, link) => {
    const wrapper = document.createElement('div');
    wrapper.className = 'embed-responsive embed-responsive-16by9';
    const iframe = document.createElement('iframe');
    iframe.className = 'embed-responsive-item';
    iframe.src = 'https://youtube.com/embed/' + encodeURIComponent(link);
    iframe.allowFullscreen = true;
    wrapper.appendChild(iframe);
    container.replaceChildren(wrapper);
};

/**
 * Render the "no recording" alert.
 *
 * @param {HTMLElement} container Video container element.
 * @param {string} text Localised "no recording" message.
 */
const showNoRecording = (container, text) => {
    const alert = document.createElement('div');
    alert.className = 'alert alert-warning text-center';
    alert.setAttribute('role', 'alert');
    alert.textContent = text;
    container.replaceChildren(alert);
};

/**
 * Render the loading spinner.
 *
 * @param {HTMLElement} container Video container element.
 * @param {string} text Localised "loading video" message.
 */
const showLoading = (container, text) => {
    const box = document.createElement('div');
    box.className = 'd-flex flex-column align-items-center justify-content-center';
    box.style.height = '100vh';
    const spinner = document.createElement('div');
    spinner.className = 'spinner-border';
    spinner.setAttribute('role', 'status');
    const sr = document.createElement('span');
    sr.className = 'sr-only';
    sr.textContent = text;
    spinner.appendChild(sr);
    box.appendChild(spinner);
    box.appendChild(document.createElement('br'));
    box.appendChild(document.createTextNode(text));
    container.replaceChildren(box);
};

/**
 * Poll the server once and reconcile the displayed content with the recording state.
 *
 * @param {object} config Configuration (see init).
 */
const poll = (config) => {
    if (swapping) {
        return;
    }
    Ajax.call([{
        methodname: 'mod_jitsi_check_source_record',
        args: {cmid: config.cmid},
    }])[0].then(async(response) => {
        const container = document.getElementById('videoContainer');
        if (!container) {
            return response;
        }
        if (response.found && !hasVideo) {
            swapping = true;
            showLoading(container, config.loadingtext);
            await wait(SWAP_DELAY);
            showVideo(container, response.link);
            hasVideo = true;
            swapping = false;
        } else if (!response.found && hasVideo) {
            swapping = true;
            await wait(SWAP_DELAY);
            showNoRecording(container, config.norecordingtext);
            hasVideo = false;
            swapping = false;
        }
        return response;
    }).catch(() => {
        swapping = false;
    });
};

/**
 * Start polling for recording availability.
 *
 * @param {object} config Configuration.
 * @param {number} config.cmid Course module id.
 * @param {boolean} config.hasvideo Whether a video is shown on initial load.
 * @param {string} config.loadingtext Localised "loading video" message.
 * @param {string} config.norecordingtext Localised "no recording" message.
 */
export const init = (config) => {
    hasVideo = !!config.hasvideo;
    swapping = false;
    setInterval(() => poll(config), POLL_INTERVAL);
};
