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
 * AMD module: lazy-load the recordings tab content and drive its CRUD over web services.
 *
 * Fetches the recordings tab HTML the first time the tab becomes active (or on load if it
 * is already active), wires the Dropbox embed toggle, and handles delete/hide/show/edit and
 * the add/edit form via AJAX web services, re-fetching the fragment after each change so the
 * page never reloads.
 *
 * @module     mod_jitsi/recordings_lazyload
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// Loaded so inplace_editable's global event delegation handles the injected markup.
import 'core/inplace_editable';
import Ajax from 'core/ajax';
import Notification from 'core/notification';
import {get_string as getString} from 'core/str';

let container = null;
let baseUrl = '';
let loaded = false;

/**
 * Build the fragment URL, carrying over the current page query (minus tab) and setting
 * (or clearing) editrecordid.
 *
 * @param {number} editRecordId Record id to edit, or 0 to show the add form.
 * @return {string} The fragment URL to fetch.
 */
const buildUrl = (editRecordId) => {
    const url = new URL(baseUrl, window.location.origin);
    const current = new URLSearchParams(window.location.search);
    current.delete('tab');
    current.forEach((value, key) => {
        if (key !== 'editrecordid') {
            url.searchParams.set(key, value);
        }
    });
    if (editRecordId) {
        url.searchParams.set('editrecordid', editRecordId);
    } else {
        url.searchParams.delete('editrecordid');
    }
    return url.toString();
};

/**
 * Wire the Dropbox-only embed option in the add/edit recording form.
 */
const initDropboxToggle = () => {
    const urlInput = document.getElementById('recordingurl');
    if (!urlInput) {
        return;
    }
    urlInput.addEventListener('input', function() {
        const isDropbox = this.value.indexOf('dropbox.com') !== -1;
        const embedOpt = document.getElementById('dropboxembedoption');
        if (embedOpt) {
            embedOpt.style.display = isDropbox ? 'block' : 'none';
        }
        const embedChk = document.getElementById('embedrecording');
        if (embedChk && !isDropbox) {
            embedChk.checked = false;
        }
    });
};

/**
 * Fetch the recordings fragment and inject it into the container.
 *
 * @param {number} editRecordId Record id to edit, or 0 to show the add form.
 * @return {Promise} Resolves once the fragment has been injected.
 */
const loadRecordings = (editRecordId = 0) => {
    if (loaded && !editRecordId) {
        return Promise.resolve();
    }
    loaded = true;
    container.innerHTML = '<div class="text-center p-3">'
        + '<div class="spinner-border" role="status"></div></div>';
    return fetch(buildUrl(editRecordId), {credentials: 'same-origin'})
        .then((r) => r.text())
        .then((html) => {
            container.innerHTML = html;
            initDropboxToggle();
            return html;
        })
        .catch(Notification.exception);
};

/**
 * Force a re-fetch of the recordings fragment, preserving the page scroll position.
 *
 * The container height is pinned while loading so the spinner does not collapse the
 * layout, and the scroll offset is restored once the new markup is injected.
 *
 * @param {number} editRecordId Record id to edit, or 0 to show the add form.
 * @return {Promise} Resolves once reloaded.
 */
const reload = (editRecordId = 0) => {
    const scrollY = window.scrollY;
    container.style.minHeight = container.offsetHeight + 'px';
    loaded = false;
    return loadRecordings(editRecordId).then((html) => {
        container.style.minHeight = '';
        window.scrollTo(window.scrollX, scrollY);
        return html;
    });
};

/**
 * Call a web service and reload the fragment on success.
 *
 * @param {string} methodname Web service method name.
 * @param {object} args Web service arguments.
 * @return {Promise} Resolves once the service responded and the fragment reloaded.
 */
const callAndReload = (methodname, args) => {
    return Ajax.call([{methodname, args}])[0]
        .then(() => reload())
        .catch(Notification.exception);
};

/**
 * Confirm deletion of a recording and call the web service.
 *
 * @param {number} cmid Course module id.
 * @param {number} recordid Recording id.
 * @return {Promise} Resolves once deleted, or silently if cancelled.
 */
const confirmAndDelete = async(cmid, recordid) => {
    const [title, question, yes, no] = await Promise.all([
        getString('confirm'),
        getString('confirmdeleterecordinactivity', 'jitsi'),
        getString('delete'),
        getString('cancel'),
    ]);
    try {
        await Notification.saveCancelPromise(title, question, yes, no);
    } catch (cancelled) {
        // User dismissed the confirmation dialog.
        return;
    }
    await callAndReload('mod_jitsi_delete_recording', {cmid, recordid});
};

/**
 * Handle a click on a recording action button (delete/hide/show/edit).
 *
 * @param {Event} e Click event.
 */
const handleActionClick = (e) => {
    const btn = e.target.closest('.jitsi-rec-action');
    if (!btn) {
        return;
    }
    e.preventDefault();
    const action = btn.dataset.action;
    const recordid = parseInt(btn.dataset.recordid, 10);
    const cmid = parseInt(btn.dataset.cmid, 10);

    if (action === 'edit') {
        reload(recordid);
        return;
    }
    if (action === 'hide') {
        callAndReload('mod_jitsi_set_recording_visibility', {cmid, recordid, visible: 0});
        return;
    }
    if (action === 'show') {
        callAndReload('mod_jitsi_set_recording_visibility', {cmid, recordid, visible: 1});
        return;
    }
    if (action === 'delete') {
        confirmAndDelete(cmid, recordid).catch(Notification.exception);
    }
};

/**
 * Handle submission of the add/edit recording form.
 *
 * @param {Event} e Submit event.
 */
const handleFormSubmit = (e) => {
    const form = e.target.closest('.jitsi-recording-form');
    if (!form) {
        return;
    }
    e.preventDefault();
    const cmid = parseInt(form.dataset.cmid, 10);
    const recordid = parseInt(form.dataset.recordid, 10) || 0;
    const urlField = form.querySelector('[name="recordingurl"]');
    const nameField = form.querySelector('[name="recordingname"]');
    const embedField = form.querySelector('[name="embedrecording"]');
    const url = urlField ? urlField.value : '';
    const name = nameField ? nameField.value : '';
    const embed = embedField && embedField.checked ? 1 : 0;
    if (!url) {
        return;
    }

    if (recordid) {
        callAndReload('mod_jitsi_update_recording_link', {cmid, recordid, url, name, embed});
    } else {
        callAndReload('mod_jitsi_add_recording_link', {cmid, url, name, embed});
    }
};

/**
 * Handle a click on the form cancel button (return to the add form).
 *
 * @param {Event} e Click event.
 */
const handleCancelClick = (e) => {
    const cancel = e.target.closest('.jitsi-recording-form-cancel');
    if (!cancel) {
        return;
    }
    e.preventDefault();
    reload();
};

/**
 * Initialise lazy-loading and CRUD of the recordings tab.
 *
 * @param {object} config Configuration.
 * @param {string} config.recordingsUrl URL of the recordings tab fragment to fetch.
 */
export const init = (config) => {
    container = document.getElementById('jitsi-recordings-content');
    if (!container) {
        return;
    }
    baseUrl = config.recordingsUrl;

    container.addEventListener('click', (e) => {
        handleActionClick(e);
        handleCancelClick(e);
    });
    container.addEventListener('submit', handleFormSubmit);

    const recordPane = document.getElementById('record');
    if (recordPane && recordPane.classList.contains('active')) {
        loadRecordings();
    }

    if (recordPane) {
        const observer = new MutationObserver((mutations) => {
            for (let i = 0; i < mutations.length; i++) {
                if (mutations[i].attributeName === 'class' && recordPane.classList.contains('active')) {
                    observer.disconnect();
                    loadRecordings();
                    break;
                }
            }
        });
        observer.observe(recordPane, {attributes: true, attributeFilter: ['class']});
    }
};
