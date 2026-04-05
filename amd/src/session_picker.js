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
 * AMD module for the shared session autocomplete picker in mod_jitsi.
 *
 * Implements the transport function required by core/form-autocomplete
 * to search for Jitsi master sessions via AJAX.
 *
 * @module     mod_jitsi/session_picker
 * @copyright  2026 Sergio Comerón Sánchez-Paniagua <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';

/**
 * Transport function called by core/form-autocomplete on each keystroke.
 *
 * @param {string} selector  CSS selector of the underlying input element
 * @param {string} query     Current search string typed by the user
 * @param {Function} callback  Call with [{value, label}] array on success
 * @param {Function} failure   Call with error on failure
 */
export const transport = (selector, query, callback, failure) => {
    // Read the current activity's own tokeninterno from the data carrier element
    // so it can be excluded from search results (a session cannot join itself).
    const excludeToken = document.getElementById('jitsi-session-picker-data')
        ?.dataset.excludeToken ?? '';

    Ajax.call([{
        methodname: 'mod_jitsi_search_shared_sessions',
        args: {query: query, excludetoken: excludeToken},
        done: (results) => {
            callback(results);
        },
        fail: failure,
    }]);
};

/**
 * Process results returned by the transport function before rendering.
 * Required by core/form-autocomplete alongside transport.
 *
 * @param {string} selector  CSS selector of the underlying input element
 * @param {Array}  results   Array of {value, label} objects from transport callback
 * @return {Array}           Same array, ready to be added as <option> elements
 */
export const processResults = (selector, results) => {
    return results;
};
