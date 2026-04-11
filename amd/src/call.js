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
 * AMD module for the call.php coursemate search.
 *
 * @module     mod_jitsi/call
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import {get_string as getString} from 'core/str';

/**
 * Initialise the call search UI.
 *
 * @param {string} sessionPrivUrl  Base URL of sessionpriv.php
 */
export const init = (sessionPrivUrl) => {
    const input = document.getElementById('jitsi-call-search');
    const results = document.getElementById('jitsi-call-results');

    if (!input || !results) {
        return;
    }

    let debounceTimer = null;

    input.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        const query = input.value.trim();

        if (query.length < 2) {
            results.innerHTML = '';
            return;
        }

        debounceTimer = setTimeout(() => {
            Ajax.call([{
                methodname: 'mod_jitsi_search_coursemates',
                args: {query},
            }])[0].then((response) => {
                results.innerHTML = '';

                if (!response.users.length) {
                    return getString('callnoresults', 'mod_jitsi').then((str) => {
                        const item = document.createElement('div');
                        item.className = 'list-group-item text-muted';
                        item.textContent = str;
                        results.appendChild(item);
                        return;
                    });
                }

                response.users.forEach((user) => {
                    const item = document.createElement('a');
                    item.href = `${sessionPrivUrl}?peer=${user.id}`;
                    item.className = 'list-group-item list-group-item-action d-flex align-items-center gap-2';

                    const img = document.createElement('img');
                    img.src = user.profileimageurl;
                    img.alt = '';
                    img.width = 32;
                    img.height = 32;
                    img.className = 'rounded-circle';

                    const name = document.createElement('span');
                    name.textContent = `${user.firstname} ${user.lastname}`;

                    item.appendChild(img);
                    item.appendChild(name);
                    results.appendChild(item);
                });
                return;
            }).catch(() => {
                results.innerHTML = '';
            });
        }, 300);
    });
};
