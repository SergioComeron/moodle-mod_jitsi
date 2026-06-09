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
 * AMD module: copy-to-clipboard button bound to another element's text.
 *
 * @module     mod_jitsi/copy_button
 * @copyright  2025 Sergio Comerón <jitsi@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Wire a button to copy the text content of a source element.
 *
 * @param {object} config Module config.
 * @param {string} config.buttonId Id of the button element.
 * @param {string} config.sourceId Id of the element whose textContent is copied.
 */
export const init = (config) => {
    const btn = document.getElementById(config.buttonId);
    const source = document.getElementById(config.sourceId);
    if (!btn || !source || !navigator.clipboard) {
        return;
    }
    const label = btn.textContent;
    btn.addEventListener('click', () => {
        navigator.clipboard.writeText(source.textContent).then(() => {
            btn.textContent = '✓ Copied!';
            setTimeout(() => {
                btn.textContent = label;
            }, 2000);
            return;
        }).catch(() => {
            return;
        });
    });
};
