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
 * AMD module: lazy-load the recordings tab content on the activity view.
 *
 * Fetches the recordings tab HTML the first time the tab becomes active (or on load
 * if it is already active), and wires the Dropbox embed toggle in the add/edit form.
 *
 * @module     mod_jitsi/recordings_lazyload
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// Loaded so inplace_editable's global event delegation handles the injected markup.
import 'core/inplace_editable';

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
 * Initialise lazy-loading of the recordings tab.
 *
 * @param {object} config Configuration.
 * @param {string} config.recordingsUrl URL of the recordings tab fragment to fetch.
 */
export const init = (config) => {
    const container = document.getElementById('jitsi-recordings-content');
    if (!container) {
        return;
    }
    let loaded = false;

    const loadRecordings = () => {
        if (loaded) {
            return;
        }
        loaded = true;
        container.innerHTML = '<div class="text-center p-3">'
            + '<div class="spinner-border" role="status"></div></div>';
        const params = new URLSearchParams(window.location.search);
        params.delete('tab');
        let url = config.recordingsUrl;
        const sep = url.indexOf('?') === -1 ? '?' : '&';
        const extra = params.toString();
        if (extra) {
            url += sep + extra;
        }
        fetch(url, {credentials: 'same-origin'})
            .then((r) => r.text())
            .then((html) => {
                container.innerHTML = html;
                initDropboxToggle();
                return html;
            })
            .catch(() => {
                return;
            });
    };

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
