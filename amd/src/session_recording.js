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
 * AMD module: recording and live-streaming controls for an active Jitsi session.
 *
 * Drives the Moodle-integrated stream/record buttons, the YouTube live-streaming flow and the
 * recording status/link reporting. Only loaded for non-private sessions.
 *
 * @module     mod_jitsi/session_recording
 * @copyright  2024 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import Notification from 'core/notification';
import {getStrings} from 'core/str';

/**
 * Replace the #state banner contents, if the element is present.
 *
 * @param {string} html The HTML to set.
 */
const setState = (html) => {
    const state = document.getElementById('state');
    if (state) {
        state.innerHTML = html;
    }
};

/**
 * Build the "session is being recorded/streamed" warning banner.
 *
 * @param {string} text The message to show beside the icon.
 * @returns {string} The banner HTML.
 */
const recordingBanner = (text) => {
    return '<div class="alert alert-primary" role="alert">' +
        '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" ' +
        'class="bi bi-exclamation-triangle-fill flex-shrink-0 me-2" viewBox="0 0 16 16" ' +
        'role="img" aria-label="Warning:">' +
        '<path d="M0 5a2 2 0 0 1 2-2h7.5a2 2 0 0 1 1.983 1.738l3.11-1.382A1 1 0 0 1 ' +
        '16 4.269v7.462a1 1 0 0 1-1.406.913l-3.111-1.382A2 ' +
        '2 0 0 1 9.5 13H2a2 2 0 0 1-2-2V5zm11.5 5.175 3.5 1.556V4.269l-3.5 1.556v4.35zM2 4a1 1 0 0 ' +
        '0-1 1v6a1 1 0 0 0 1 1h7.5a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1H2z"/>' +
        '</svg> ' + text + '</div>';
};

/**
 * Start recording/streaming controls for a Jitsi session.
 *
 * The live JitsiMeetExternalAPI instance is read from window.jitsiSessionApi, set by the
 * inline session script, since js_call_amd can only pass JSON-serialisable arguments.
 *
 * @param {object} config Configuration.
 * @param {number} config.jitsiid Jitsi activity instance id.
 * @param {number} config.userid Current user id.
 * @param {number} config.cmid Course module id.
 * @param {string} config.session Room/session name.
 */
export const init = (config) => {
    const api = window.jitsiSessionApi;
    if (!api) {
        return;
    }

    let idsource = null;
    let recordingStateReceived = false;

    // Cached language strings (populated asynchronously; the controls below are only ever
    // triggered by user interaction, well after this resolves).
    const str = {
        preparing: '',
        bloquedby: '',
        streamingstarting: '',
        internalerror: '',
        wasbloquedby: '',
        beingrecorded: '',
    };
    getStrings([
        {key: 'preparing', component: 'mod_jitsi'},
        {key: 'recordingbloquedby', component: 'mod_jitsi'},
        {key: 'streamingisstarting', component: 'mod_jitsi'},
        {key: 'internalerror', component: 'mod_jitsi'},
        {key: 'recordingwasbloquedby', component: 'mod_jitsi'},
        {key: 'sessionisbeingrecorded', component: 'mod_jitsi'},
    ]).then(([preparing, bloquedby, streamingstarting, internalerror, wasbloquedby, beingrecorded]) => {
        str.preparing = preparing;
        str.bloquedby = bloquedby;
        str.streamingstarting = streamingstarting;
        str.internalerror = internalerror;
        str.wasbloquedby = wasbloquedby;
        str.beingrecorded = beingrecorded;
        return str;
    }).catch(Notification.exception);

    /**
     * Fire a web service request without awaiting its result, reporting failures.
     *
     * @param {string} methodname The external function name.
     * @param {object} args The call arguments.
     */
    const fire = (methodname, args) => {
        Ajax.call([{methodname, args}])[0].fail(Notification.exception);
    };

    /**
     * Begin a YouTube live stream: create it server-side, then start it via the api.
     */
    const stream = () => {
        Ajax.call([{
            methodname: 'mod_jitsi_create_stream',
            args: {session: config.session, jitsi: config.jitsiid, userid: config.userid},
        }])[0].done((response) => {
            idsource = response.idsource;
            if (response.error === 'errorauthor') {
                window.alert(str.bloquedby + response.usercomplete); // eslint-disable-line no-alert
                setState('<div class="alert alert-light" role="alert"></div>');
            } else if (response.error === 'erroryoutube') {
                fire('mod_jitsi_delete_record_youtube', {idsource: idsource});
                setState('<div class="alert alert-light" role="alert">ERROR RECORD ACCOUNT. TRY AGAIN IN A FEW SECONDS</div>');
                fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
            } else if (response.error === 'erroraccount') {
                setState('<div class="alert alert-warning" role="alert">' + response.errorinfo + '</div>');
                fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
            } else if (response.stream === 'streaming') {
                window.alert(str.streamingstarting); // eslint-disable-line no-alert
            } else {
                api.executeCommand('startRecording', {mode: 'stream', youtubeStreamKey: response.stream});
            }
        }).fail((ex) => {
            fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
            fire('mod_jitsi_send_error', {
                jitsi: config.jitsiid, user: config.userid, error: ex.backtrace, cmid: config.cmid,
            });
            setState('<div class="alert alert-light" role="alert">' + str.internalerror + '</div>');
        });
    };

    /**
     * Stop a YouTube live stream, handling the "started by another teacher" case.
     */
    const stopStream = () => {
        Ajax.call([{
            methodname: 'mod_jitsi_stop_stream',
            args: {jitsi: config.jitsiid, userid: config.userid},
        }])[0].done((response) => {
            if (response.error === 'errorauthor') {
                Ajax.call([{
                    methodname: 'mod_jitsi_getminutesfromlastconexion',
                    args: {cmid: config.cmid, user: response.user},
                }])[0].done((minutos) => {
                    if ((Date.now() / 1000) - minutos > 60) {
                        // eslint-disable-next-line no-alert
                        if (window.confirm(str.wasbloquedby + response.usercomplete)) {
                            setState('');
                            fire('mod_jitsi_stop_stream_noauthor', {jitsi: config.jitsiid, userid: config.userid});
                            api.executeCommand('stopRecording', 'stream');
                        }
                    } else {
                        window.alert(str.bloquedby + response.usercomplete); // eslint-disable-line no-alert
                    }
                }).fail(Notification.exception);
                setState(recordingBanner(str.beingrecorded));
            } else {
                api.executeCommand('stopRecording', 'stream');
            }
        }).fail(Notification.exception);
    };

    /**
     * Toggle the live-stream button: report the press, then start or stop streaming.
     */
    const handleStreamBtn = () => {
        const btn = document.getElementById('streamBtn');
        if (!btn) {
            return;
        }
        btn.disabled = true;
        fire('mod_jitsi_press_record_button', {jitsi: config.jitsiid, user: config.userid, cmid: config.cmid});
        if (btn.classList.contains('btn-warning')) {
            stopStream();
        } else {
            setState('<div class="alert alert-light" role="alert">' + str.preparing + '</div>');
            stream();
        }
    };

    /**
     * Toggle the file-record button via the api.
     */
    const handleRecordBtn = () => {
        const btn = document.getElementById('recordBtn');
        if (!btn) {
            return;
        }
        btn.disabled = true;
        if (btn.classList.contains('btn-danger')) {
            api.stopRecording('file');
        } else {
            api.startRecording({mode: 'file'});
        }
    };

    // Enable the action buttons after 5s if no recording-state event has arrived.
    setTimeout(() => {
        if (recordingStateReceived) {
            return;
        }
        const sb = document.getElementById('streamBtn');
        const rb = document.getElementById('recordBtn');
        if (sb) {
            sb.disabled = false;
        }
        if (rb) {
            rb.disabled = false;
        }
    }, 5000);

    const streamBtn = document.getElementById('streamBtn');
    if (streamBtn) {
        streamBtn.addEventListener('click', handleStreamBtn);
    }
    const recordBtn = document.getElementById('recordBtn');
    if (recordBtn) {
        recordBtn.addEventListener('click', handleRecordBtn);
    }

    // Reflect recording/streaming state on the buttons and banner, and report it server-side.
    api.addEventListener('recordingStatusChanged', (event) => {
        recordingStateReceived = true;
        const sb = document.getElementById('streamBtn');
        const rb = document.getElementById('recordBtn');
        if (event.mode === 'file') {
            if (event.on) {
                if (rb) {
                    rb.classList.remove('btn-outline-danger');
                    rb.classList.add('btn-danger');
                    rb.disabled = false;
                }
                if (sb) {
                    sb.disabled = true;
                }
            } else {
                if (rb) {
                    rb.classList.remove('btn-danger');
                    rb.classList.add('btn-outline-danger');
                    rb.disabled = false;
                }
                if (sb) {
                    sb.disabled = false;
                }
            }
            fire('mod_jitsi_set_jibri_recording', {jitsiid: config.jitsiid, recording: event.on ? 1 : 0});
        }
        if (event.on && event.mode === 'stream') {
            if (sb) {
                sb.classList.remove('btn-outline-warning');
                sb.classList.add('btn-warning');
                sb.disabled = false;
            }
            if (rb) {
                rb.disabled = true;
            }
            setState(recordingBanner(str.beingrecorded));
        } else if (event.on === false && event.mode === 'stream') {
            if (sb) {
                sb.classList.remove('btn-warning');
                sb.classList.add('btn-outline-warning');
                setTimeout(() => {
                    sb.disabled = false;
                }, 2000);
            }
            if (rb) {
                setTimeout(() => {
                    rb.disabled = false;
                }, 2000);
            }
            setState('');
        }
        fire('mod_jitsi_state_record', {jitsi: config.jitsiid, state: event.on});
    });

    // On a Jitsi recording error, drop the YouTube source and report it.
    api.addEventListener('recordingStatusChanged', (event) => {
        if (event.error) {
            fire('mod_jitsi_delete_record_youtube', {idsource: idsource});
            fire('mod_jitsi_send_error', {
                jitsi: config.jitsiid,
                user: config.userid,
                error: 'Error de servidor jitsi: ' + event.error,
                cmid: config.cmid,
            });
        }
    });

    // Persist the recording link when Jitsi publishes it.
    api.addEventListener('recordingLinkAvailable', (event) => {
        fire('mod_jitsi_save_recording_link', {jitsi: config.jitsiid, link: event.link, ttl: event.ttl || 0});
    });

    // Persist the recording link when a recording stops and exposes a URL.
    api.addEventListener('recordingStatusChanged', (event) => {
        if (!event.on && event.url) {
            fire('mod_jitsi_save_recording_link', {jitsi: config.jitsiid, link: event.url, ttl: 0});
        }
    });
};
