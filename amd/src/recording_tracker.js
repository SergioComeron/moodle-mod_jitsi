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
 * AMD module: watched-segment tracking for recording playback on the activity view.
 *
 * Tracks which parts of a GCS recording a user has actually watched, merges contiguous
 * segments, renders a progress bar, periodically persists segments to the server, and
 * logs a first-view for both embedded <video> recordings and external recording links.
 *
 * @module     mod_jitsi/recording_tracker
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';

/** How often watched segments are persisted to the server while playing, in ms. */
const SAVE_INTERVAL = 30000;

/**
 * Merge overlapping/contiguous [start, end] segments into a minimal sorted set.
 *
 * @param {Array.<Array.<number>>} segs Segments as [start, end] pairs.
 * @returns {Array.<Array.<number>>} Merged segments.
 */
const mergeSegments = (segs) => {
    if (!segs.length) {
        return [];
    }
    const sorted = segs.slice().sort((a, b) => a[0] - b[0]);
    const merged = [sorted[0].slice()];
    for (let i = 1; i < sorted.length; i++) {
        const last = merged[merged.length - 1];
        if (sorted[i][0] <= last[1]) {
            last[1] = Math.max(last[1], sorted[i][1]);
        } else {
            merged.push(sorted[i].slice());
        }
    }
    return merged;
};

/**
 * Redraw the watched-progress bar and percentage label for a recording.
 *
 * @param {(number|string)} sourcerecordid Source record id.
 * @param {Array.<Array.<number>>} segments Watched segments.
 * @param {number} duration Total recording duration in seconds.
 */
const updateBar = (sourcerecordid, segments, duration) => {
    const bar = document.getElementById('jitsi-segbar-' + sourcerecordid);
    const label = document.getElementById('jitsi-segbar-pct-' + sourcerecordid);
    if (!bar || !duration) {
        return;
    }
    let html = '';
    let watched = 0;
    segments.forEach((seg) => {
        const left = (seg[0] / duration) * 100;
        const width = ((seg[1] - seg[0]) / duration) * 100;
        watched += seg[1] - seg[0];
        html += '<div style="position:absolute;left:' + left.toFixed(2)
            + '%;width:' + width.toFixed(2)
            + '%;height:100%;background:#0d6efd"></div>';
    });
    bar.innerHTML = html;
    if (label) {
        label.textContent = Math.min(100, Math.round((watched / duration) * 100)) + '%';
    }
};

/**
 * Resolve the best-known duration for a video, falling back to the tracker value.
 *
 * @param {HTMLVideoElement} video The video element.
 * @param {object} t The tracker state for this video.
 * @returns {number} Duration in seconds (0 if unknown).
 */
const getDuration = (video, t) => {
    const d = video.duration;
    return (d && isFinite(d)) ? d : (t.duration || 0);
};

/** Per-video tracker state, keyed by "sourcerecordid_cmid". */
const trackers = {};

/** Recording links already logged this page load, to avoid duplicate view logs. */
const linkClicked = {};

/**
 * Persist the merged watched segments for a video to the server.
 *
 * @param {HTMLVideoElement} video The video element.
 */
const saveSegments = (video) => {
    const key = video.dataset.sourcerecordid + '_' + video.dataset.cmid;
    const t = trackers[key];
    const dur = getDuration(video, t);
    if (!t || !t.segments.length || !dur) {
        return;
    }
    const merged = mergeSegments(t.segments.slice());
    const sessionMerged = mergeSegments(t.sessionSegs.slice());
    t.sessionSegs = [];
    Ajax.call([{
        methodname: 'mod_jitsi_save_recording_segments',
        args: {
            sourcerecordid: parseInt(video.dataset.sourcerecordid, 10),
            cmid: parseInt(video.dataset.cmid, 10),
            segments: JSON.stringify(merged),
            duration: dur,
            session_segments: JSON.stringify(sessionMerged)
        }
    }])[0].then((result) => {
        if (result.success && result.segments) {
            t.segments = JSON.parse(result.segments);
            updateBar(video.dataset.sourcerecordid, t.segments, getDuration(video, t));
        }
        return result;
    }).catch(() => {
        return;
    });
};

/**
 * Initialise watched-segment tracking for a single video element.
 *
 * @param {HTMLVideoElement} video The video element.
 */
const setupTracking = (video) => {
    const key = video.dataset.sourcerecordid + '_' + video.dataset.cmid;
    if (trackers[key]) {
        return;
    }
    // Seed existing segments from the server-rendered bar so the bar
    // stays accurate during playback without waiting for the next save.
    const wrap = document.getElementById('jitsi-segbar-wrap-' + video.dataset.sourcerecordid);
    const seedSegs = (wrap && wrap.dataset.segments) ? JSON.parse(wrap.dataset.segments) : [];
    const seedDur = (wrap && wrap.dataset.duration) ? parseFloat(wrap.dataset.duration) : 0;
    trackers[key] = {
        segments: seedSegs, segStart: null, lastTime: 0,
        saveTimer: null, played: false, duration: seedDur, sessionSegs: []
    };
    const t = trackers[key];

    // Capture duration from metadata and update the bar immediately —
    // this fixes the case where duration was stored as 0 in the DB.
    video.addEventListener('loadedmetadata', () => {
        if (video.duration && isFinite(video.duration)) {
            t.duration = video.duration;
            if (t.segments.length) {
                updateBar(video.dataset.sourcerecordid, mergeSegments(t.segments), t.duration);
            }
        }
    });
    // If metadata is already loaded (video cached), trigger the update now.
    if (video.readyState >= 1 && video.duration && isFinite(video.duration)) {
        t.duration = video.duration;
        if (seedSegs.length) {
            updateBar(video.dataset.sourcerecordid, mergeSegments(seedSegs), t.duration);
        }
    } else if (seedSegs.length && seedDur) {
        updateBar(video.dataset.sourcerecordid, seedSegs, seedDur);
    }

    // Detect seeks via delta in timeupdate instead of seeking/seeked events,
    // which have a timing race where timeupdate can update lastTime to the
    // new seek position before seeking fires.
    video.addEventListener('timeupdate', () => {
        if (video.paused || video.ended || t.segStart === null) {
            return;
        }
        const ct = video.currentTime;
        const delta = ct - t.lastTime;
        const dur = getDuration(video, t);
        if (delta > 0 && delta < 2) {
            t.lastTime = ct;
            updateBar(video.dataset.sourcerecordid,
                mergeSegments(t.segments.concat([[t.segStart, ct]])), dur);
        } else if (delta >= 2 || delta < 0) {
            if (t.lastTime > t.segStart) {
                t.segments.push([t.segStart, t.lastTime]);
                t.sessionSegs.push([t.segStart, t.lastTime]);
            }
            t.segStart = ct;
            t.lastTime = ct;
        }
    });

    video.addEventListener('pause', () => {
        if (t.segStart !== null) {
            if (t.lastTime > t.segStart) {
                t.segments.push([t.segStart, t.lastTime]);
                t.sessionSegs.push([t.segStart, t.lastTime]);
            }
            t.segStart = null;
        }
        clearInterval(t.saveTimer);
        t.saveTimer = null;
        updateBar(video.dataset.sourcerecordid, mergeSegments(t.segments), getDuration(video, t));
        saveSegments(video);
    });

    video.addEventListener('ended', () => {
        const dur = getDuration(video, t);
        if (t.segStart !== null) {
            t.segments.push([t.segStart, dur || t.lastTime]);
            t.sessionSegs.push([t.segStart, dur || t.lastTime]);
            t.segStart = null;
        }
        clearInterval(t.saveTimer);
        t.saveTimer = null;
        updateBar(video.dataset.sourcerecordid, mergeSegments(t.segments), dur);
        saveSegments(video);
    });
};

/**
 * Initialise recording view tracking for the activity view page.
 */
export const init = () => {
    // Capture-phase delegation: handles play for lazy-loaded videos.
    document.addEventListener('play', (e) => {
        const video = e.target;
        if (video.tagName !== 'VIDEO' || !video.dataset.sourcerecordid) {
            return;
        }
        setupTracking(video);
        const key = video.dataset.sourcerecordid + '_' + video.dataset.cmid;
        const t = trackers[key];
        t.segStart = video.currentTime;
        t.lastTime = video.currentTime;
        t.sessionSegs = [];
        if (!t.saveTimer) {
            t.saveTimer = setInterval(() => {
                saveSegments(video);
            }, SAVE_INTERVAL);
        }
        if (!t.played) {
            t.played = true;
            Ajax.call([{
                methodname: 'mod_jitsi_log_recording_view',
                args: {
                    sourcerecordid: parseInt(video.dataset.sourcerecordid, 10),
                    cmid: parseInt(video.dataset.cmid, 10),
                    milestone: 0
                }
            }]);
        }
    }, true);

    document.querySelectorAll('video[data-sourcerecordid]').forEach(setupTracking);

    // Track clicks on non-embeddable recording links (8x8, external, Jibri).
    document.addEventListener('click', (e) => {
        const link = e.target.closest('.jitsi-recording-link');
        if (!link || !link.dataset.sourcerecordid) {
            return;
        }
        const key = link.dataset.sourcerecordid + '_' + link.dataset.cmid;
        if (linkClicked[key]) {
            return;
        }
        linkClicked[key] = true;
        Ajax.call([{
            methodname: 'mod_jitsi_log_recording_view',
            args: {
                sourcerecordid: parseInt(link.dataset.sourcerecordid, 10),
                cmid: parseInt(link.dataset.cmid, 10),
                milestone: 0
            }
        }]);
    });
};
