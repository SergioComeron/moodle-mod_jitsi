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
 * AMD module: hover tooltip for recording heatmap buckets.
 *
 * Shows the time range and viewer names of the hovered bucket of a
 * .jitsi-heatmap bar (see \mod_jitsi\output\heatmap_bar).
 *
 * @module     mod_jitsi/heatmap_tooltip
 * @copyright  2026 Sergio Comerón <jitsi@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import {getString} from 'core/str';

/**
 * Initialise the heatmap hover tooltip.
 */
export const init = async() => {
    const strNoViewers = await getString('heatmapbucketnoviewers', 'mod_jitsi');

    const tip = document.createElement('div');
    tip.style.cssText = 'position:fixed;z-index:9999;background:#333;color:#fff;padding:6px 10px;'
        + 'border-radius:4px;font-size:12px;pointer-events:none;display:none;max-width:220px;line-height:1.4';
    document.body.appendChild(tip);

    document.addEventListener('mousemove', (e) => {
        const bucket = e.target.closest('[data-bucket]');
        if (!bucket) {
            tip.style.display = 'none';
            return;
        }
        const bar = bucket.closest('.jitsi-heatmap[data-viewers]');
        if (!bar) {
            tip.style.display = 'none';
            return;
        }

        const viewers = JSON.parse(bar.dataset.viewers || '{}');
        const list = viewers[bucket.dataset.bucket] || [];

        const strong = document.createElement('strong');
        strong.textContent = bucket.dataset.start + '–' + bucket.dataset.end;
        tip.replaceChildren(strong, document.createElement('br'));
        if (!list.length) {
            tip.appendChild(document.createTextNode(strNoViewers));
        } else {
            list.forEach((name, i) => {
                if (i > 0) {
                    tip.appendChild(document.createElement('br'));
                }
                tip.appendChild(document.createTextNode(name));
            });
        }
        tip.style.display = 'block';
        tip.style.left = (e.clientX + 12) + 'px';
        tip.style.top = (e.clientY - 10) + 'px';
    });

    document.addEventListener('mouseleave', (e) => {
        if (!e.target.closest('[data-bucket]')) {
            tip.style.display = 'none';
        }
    }, true);
};
