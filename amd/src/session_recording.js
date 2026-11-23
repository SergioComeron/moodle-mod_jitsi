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
 * @param {boolean} config.canRecord Whether the current user can record this activity.
 * @param {string} config.dropboxAppKey Dropbox app key ('' disables the Dropbox button).
 * @param {string} config.dropboxOauthUrl URL of the plugin's Dropbox OAuth landing page.
 */
export const init = (config) => {
    const api = window.jitsiSessionApi;
    if (!api) {
        return;
    }

    let idsource = null;
    // Stream key from the YouTube broadcast created for this attempt. Retries must
    // send it again; a bare stream start is rejected.
    let youtubeStreamKey = '';
    let recordingStateReceived = false;
    // Timestamp of the last record/stream click from this client, and of the last
    // confirmed "recording is on" event. A failure is only released by the client
    // that just tried to start, and never while someone else is already recording.
    let startAttemptAt = 0;
    let confirmedAt = 0;
    let failureShownAt = 0;
    let releasing = false;
    // While waiting for a Jibri to boot, retries stay silent and the final error
    // is shown only after WAIT_MS. ignoringStop swallows the stop we send ourselves.
    let waitingUntil = 0;
    let retryTimer = 0;
    let ignoringStop = false;
    const WAIT_MS = 120000;
    const RETRY_MS = 12000;

    /** Errors that mean the recorder never started (no Jibri, or it rejected the start). */
    const START_FAILURES = ['service-unavailable', 'busy', 'resource-constraint', 'error'];
    /** Errors that mean no recorder is registered yet, so it is worth waiting for one. */
    const NOT_READY = ['service-unavailable', 'busy', 'resource-constraint'];

    // Cached language strings (populated asynchronously; the controls below are only ever
    // triggered by user interaction, well after this resolves).
    const str = {
        preparing: '',
        bloquedby: '',
        streamingstarting: '',
        internalerror: '',
        wasbloquedby: '',
        beingrecorded: '',
        recordaccounterror: '',
        startfailed: '',
        waiting: '',
    };
    getStrings([
        {key: 'preparing', component: 'mod_jitsi'},
        {key: 'recordingbloquedby', component: 'mod_jitsi'},
        {key: 'streamingisstarting', component: 'mod_jitsi'},
        {key: 'internalerror', component: 'mod_jitsi'},
        {key: 'recordingwasbloquedby', component: 'mod_jitsi'},
        {key: 'sessionisbeingrecorded', component: 'mod_jitsi'},
        {key: 'recordaccounterror', component: 'mod_jitsi'},
        {key: 'recordingstartfailed', component: 'mod_jitsi'},
        {key: 'recordingwaitingforjibri', component: 'mod_jitsi'},
    ]).then(([preparing, bloquedby, streamingstarting, internalerror, wasbloquedby, beingrecorded,
        recordaccounterror, startfailed, waiting]) => {
        str.preparing = preparing;
        str.bloquedby = bloquedby;
        str.streamingstarting = streamingstarting;
        str.internalerror = internalerror;
        str.wasbloquedby = wasbloquedby;
        str.beingrecorded = beingrecorded;
        str.recordaccounterror = recordaccounterror;
        str.startfailed = startfailed;
        str.waiting = waiting;
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
     * Enable or disable the stream, record and Dropbox buttons at once.
     *
     * @param {boolean} disabled Whether the buttons should be disabled.
     */
    const setControlsDisabled = (disabled) => {
        const sb = document.getElementById('streamBtn');
        const rb = document.getElementById('recordBtn');
        const db = document.getElementById('dropboxBtn');
        if (sb) {
            sb.disabled = disabled;
        }
        if (rb) {
            rb.disabled = disabled;
        }
        if (db) {
            db.disabled = disabled;
        }
    };

    /**
     * Remember that this client just asked Jitsi to start recording or streaming.
     */
    const noteStartAttempt = () => {
        startAttemptAt = Date.now();
    };

    /**
     * True when this client tried to start a recording a few seconds ago.
     *
     * @returns {boolean}
     */
    const recentStartAttempt = () => {
        return startAttemptAt > 0 && (Date.now() - startAttemptAt) < 60000;
    };

    /**
     * Put the stream, record and Dropbox buttons back to their idle look.
     */
    const resetRecordingControls = () => {
        const sb = document.getElementById('streamBtn');
        const rb = document.getElementById('recordBtn');
        const db = document.getElementById('dropboxBtn');
        if (rb) {
            rb.classList.remove('btn-danger');
            rb.classList.add('btn-outline-danger');
            rb.disabled = false;
        }
        if (sb) {
            sb.classList.remove('btn-warning');
            sb.classList.add('btn-outline-warning');
            sb.disabled = false;
        }
        if (db) {
            db.disabled = false;
        }
    };

    /**
     * A start failed (no Jibri, or Jicofo still holding the previous failed session).
     *
     * Drop Moodle's "someone is recording" lock and tell Jitsi to stop, so the next
     * click is not rejected as if another user were recording.
     *
     * @param {object} event recordingStatusChanged payload.
     */
    const releaseFailedRecording = (event) => {
        if (releasing || !config.canRecord) {
            return;
        }
        releasing = true;
        youtubeStreamKey = '';
        const mode = event.mode === 'stream' ? 'stream' : 'file';
        fire('mod_jitsi_set_jibri_recording', {jitsiid: config.jitsiid, recording: 0});
        if (mode === 'stream' || idsource) {
            fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
            if (idsource) {
                fire('mod_jitsi_delete_record_youtube', {idsource: idsource});
                idsource = null;
            }
        }
        fire('mod_jitsi_send_error', {
            jitsi: config.jitsiid,
            user: config.userid,
            error: 'Error de servidor jitsi: ' + event.error,
            cmid: config.cmid,
        });
        try {
            if (mode === 'file') {
                api.stopRecording('file');
            } else {
                api.executeCommand('stopRecording', 'stream');
            }
        } catch (e) { // eslint-disable-line no-unused-vars
            // The session may already be off. The Moodle lock is cleared either way.
        }
        resetRecordingControls();
        failureShownAt = Date.now();
        setState('<div class="alert alert-warning" role="alert">' + str.startfailed + '</div>');
        startAttemptAt = 0;
        confirmedAt = 0;
        setTimeout(() => {
            releasing = false;
        }, 1000);
    };

    /**
     * Stop waiting for a recorder. Does not change the banner.
     */
    const cancelWait = () => {
        waitingUntil = 0;
        if (retryTimer) {
            clearTimeout(retryTimer);
            retryTimer = 0;
        }
    };

    /**
     * Banner shown instead of the Jitsi "no recorder" notice while we retry.
     */
    const showWaiting = () => {
        failureShownAt = Date.now();
        setState('<div class="alert alert-info" role="alert">' + str.waiting + '</div>');
    };

    /**
     * Stop a failed file start without telling the user it failed.
     *
     * @param {object} event recordingStatusChanged payload.
     */
    const quietStop = (event) => {
        if (releasing || !config.canRecord) {
            return;
        }
        releasing = true;
        ignoringStop = true;
        const mode = event.mode === 'stream' ? 'stream' : 'file';
        fire('mod_jitsi_set_jibri_recording', {jitsiid: config.jitsiid, recording: 0});
        try {
            if (mode === 'file') {
                api.stopRecording('file');
            } else {
                api.executeCommand('stopRecording', 'stream');
            }
        } catch (e) { // eslint-disable-line no-unused-vars
            ignoringStop = false;
        }
        confirmedAt = 0;
        setTimeout(() => {
            releasing = false;
        }, 1000);
    };

    /**
     * No Jibri is registered yet. Keep the session unlocked and try again until
     * one shows up, or the wait expires.
     *
     * @param {object} event recordingStatusChanged payload.
     */
    const holdForRecorder = (event) => {
        if (!config.canRecord) {
            return;
        }
        if (!waitingUntil) {
            waitingUntil = Date.now() + WAIT_MS;
        }
        if (Date.now() > waitingUntil) {
            cancelWait();
            releaseFailedRecording(event);
            return;
        }
        showWaiting();
        if (releasing) {
            return;
        }
        if (retryTimer) {
            clearTimeout(retryTimer);
            retryTimer = 0;
        }
        quietStop(event);
        const mode = event.mode === 'stream' ? 'stream' : 'file';
        retryTimer = setTimeout(() => {
            retryTimer = 0;
            if (!waitingUntil) {
                return;
            }
            if (Date.now() > waitingUntil) {
                cancelWait();
                releaseFailedRecording({mode: mode, error: 'service-unavailable'});
                return;
            }
            // A stream retry without the key is rejected locally and never reaches Jicofo.
            if (mode === 'stream' && !youtubeStreamKey) {
                cancelWait();
                releaseFailedRecording({mode: mode, error: 'service-unavailable'});
                return;
            }
            noteStartAttempt();
            try {
                if (mode === 'stream') {
                    api.executeCommand('startRecording', {
                        mode: 'stream',
                        youtubeStreamKey: youtubeStreamKey,
                    });
                } else {
                    api.startRecording({mode: 'file'});
                }
            } catch (e) { // eslint-disable-line no-unused-vars
                // The wait deadline still ends this if Jitsi never answers.
            }
        }, RETRY_MS);
    };

    /**
     * Safety net: if no button reflects an active state shortly after starting,
     * re-enable them so a silent start failure can't leave the controls stuck.
     */
    const armControlsWatchdog = () => {
        setTimeout(() => {
            const sb = document.getElementById('streamBtn');
            const rb = document.getElementById('recordBtn');
            const streaming = sb && sb.classList.contains('btn-warning');
            const recording = rb && rb.classList.contains('btn-danger');
            if (!streaming && !recording) {
                setControlsDisabled(false);
            }
        }, 20000);
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
                setControlsDisabled(false);
            } else if (response.error === 'erroryoutube') {
                fire('mod_jitsi_delete_record_youtube', {idsource: idsource});
                setState('<div class="alert alert-light" role="alert">' + str.recordaccounterror + '</div>');
                fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
                setControlsDisabled(false);
            } else if (response.error === 'erroraccount') {
                setState('<div class="alert alert-warning" role="alert">' + response.errorinfo + '</div>');
                fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
                setControlsDisabled(false);
            } else if (response.stream === 'streaming') {
                window.alert(str.streamingstarting); // eslint-disable-line no-alert
                setControlsDisabled(false);
            } else {
                // Success: recordingStatusChanged(stream, on) will set the final button states.
                youtubeStreamKey = response.stream;
                noteStartAttempt();
                api.executeCommand('startRecording', {mode: 'stream', youtubeStreamKey: youtubeStreamKey});
            }
        }).fail((ex) => {
            fire('mod_jitsi_stop_stream_byerror', {jitsi: config.jitsiid, userid: config.userid});
            fire('mod_jitsi_send_error', {
                jitsi: config.jitsiid, user: config.userid, error: ex.backtrace, cmid: config.cmid,
            });
            setState('<div class="alert alert-light" role="alert">' + str.internalerror + '</div>');
            setControlsDisabled(false);
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
        fire('mod_jitsi_press_record_button', {jitsi: config.jitsiid, user: config.userid, cmid: config.cmid});
        if (btn.classList.contains('btn-warning')) {
            // Stopping: only this button needs disabling (record is already disabled).
            btn.disabled = true;
            stopStream();
        } else {
            // Starting: disable BOTH buttons until streaming is confirmed, so a
            // file recording can't be launched while the stream is preparing.
            setControlsDisabled(true);
            armControlsWatchdog();
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
        if (btn.classList.contains('btn-danger')) {
            // Stopping: only this button needs disabling (stream is already disabled).
            btn.disabled = true;
            api.stopRecording('file');
        } else {
            // Starting: disable BOTH buttons until recording is confirmed, so a
            // stream can't be launched while the recording is preparing.
            setControlsDisabled(true);
            armControlsWatchdog();
            noteStartAttempt();
            api.startRecording({mode: 'file'});
        }
    };

    // Short-lived Dropbox access token obtained via the OAuth popup (page-lifetime cache).
    let dropboxToken = null;
    let dropboxTokenExpiry = 0;

    /**
     * Start a file recording uploaded to the user's Dropbox.
     *
     * @param {string} token Dropbox OAuth2 access token.
     */
    const startDropboxRecording = (token) => {
        setControlsDisabled(true);
        armControlsWatchdog();
        noteStartAttempt();
        api.startRecording({mode: 'file', dropboxToken: token});
    };

    // The OAuth popup (mod/jitsi/dropboxoauth.php) posts the token back here.
    window.addEventListener('message', (e) => {
        if (e.origin !== window.location.origin || !e.data || e.data.type !== 'jitsiDropboxToken') {
            return;
        }
        dropboxToken = e.data.token;
        dropboxTokenExpiry = Date.now() + Math.max((e.data.expiresIn || 0) - 60, 300) * 1000;
        startDropboxRecording(dropboxToken);
    });

    /**
     * Handle the "Record to Dropbox" button: reuse a cached token or run the OAuth popup.
     */
    const handleDropboxBtn = () => {
        if (!config.dropboxAppKey) {
            return;
        }
        if (dropboxToken && Date.now() < dropboxTokenExpiry) {
            startDropboxRecording(dropboxToken);
            return;
        }
        const url = 'https://www.dropbox.com/oauth2/authorize'
            + '?client_id=' + encodeURIComponent(config.dropboxAppKey)
            + '&response_type=token'
            + '&redirect_uri=' + encodeURIComponent(config.dropboxOauthUrl);
        window.open(url, 'jitsidropboxoauth', 'width=600,height=700');
    };

    // Enable the action buttons after 5s if no recording-state event has arrived.
    setTimeout(() => {
        if (recordingStateReceived) {
            return;
        }
        setControlsDisabled(false);
    }, 5000);

    const streamBtn = document.getElementById('streamBtn');
    if (streamBtn) {
        streamBtn.addEventListener('click', handleStreamBtn);
    }
    const recordBtn = document.getElementById('recordBtn');
    if (recordBtn) {
        recordBtn.addEventListener('click', handleRecordBtn);
    }
    const dropboxBtn = document.getElementById('dropboxBtn');
    if (dropboxBtn) {
        dropboxBtn.addEventListener('click', handleDropboxBtn);
    }

    // The native Jitsi toolbar (self-hosted) does not go through the Moodle buttons.
    api.addEventListener('toolbarButtonClicked', (event) => {
        if (event.key === 'recording' || event.key === 'livestreaming') {
            noteStartAttempt();
        }
    });

    // Reflect recording/streaming state on the buttons and banner, and report it server-side.
    api.addEventListener('recordingStatusChanged', (event) => {
        recordingStateReceived = true;
        if (releasing) {
            return;
        }
        if (ignoringStop && event.on === false && !event.error) {
            ignoringStop = false;
            return;
        }
        const startFailure = START_FAILURES.indexOf(event.error) !== -1
            || event.error === 'unexpected-request';
        const notReady = NOT_READY.indexOf(event.error) !== -1;
        // A recording that was already on before this click belongs to someone else.
        const preexisting = confirmedAt > 0 && startAttemptAt > 0 && confirmedAt < startAttemptAt;
        if (event.error && preexisting) {
            // Someone else is actually recording. Leave their session and the buttons alone.
            return;
        }
        if (event.on && !event.error && waitingUntil
                && (event.mode === 'file' || event.mode === 'stream')) {
            cancelWait();
            if (event.mode === 'file') {
                setState('');
            }
        } else if (waitingUntil && event.on === false && !event.error) {
            // The user stopped while we were waiting. Do not start again.
            cancelWait();
            setState('');
        }
        if (event.error && notReady && !preexisting
                && (recentStartAttempt() || waitingUntil)
                && (event.mode === 'file' || event.mode === 'stream')) {
            holdForRecorder(event);
            return;
        }
        if (event.error && startFailure && recentStartAttempt() && !preexisting
                && (event.mode === 'file' || event.mode === 'stream')) {
            cancelWait();
            releaseFailedRecording(event);
            return;
        }
        if (event.on && !event.error && (event.mode === 'file' || event.mode === 'stream')) {
            confirmedAt = Date.now();
        }
        if (event.on === false && !event.error) {
            confirmedAt = 0;
        }
        const sb = document.getElementById('streamBtn');
        const rb = document.getElementById('recordBtn');
        const db = document.getElementById('dropboxBtn');
        const active = event.on && !event.error;
        if (event.mode === 'file') {
            // Any file recording (8x8 cloud or Dropbox) turns the record button
            // red, which then acts as the single stop control.
            if (active) {
                if (rb) {
                    rb.classList.remove('btn-outline-danger');
                    rb.classList.add('btn-danger');
                    rb.disabled = false;
                }
                if (sb) {
                    sb.disabled = true;
                }
                if (db) {
                    db.disabled = true;
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
                if (db) {
                    db.disabled = false;
                }
            }
            if (!event.error) {
                fire('mod_jitsi_set_jibri_recording', {jitsiid: config.jitsiid, recording: active ? 1 : 0});
            }
        }
        if (active && event.mode === 'stream') {
            if (sb) {
                sb.classList.remove('btn-outline-warning');
                sb.classList.add('btn-warning');
                sb.disabled = false;
            }
            if (rb) {
                rb.disabled = true;
            }
            if (db) {
                db.disabled = true;
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
            if (db) {
                setTimeout(() => {
                    db.disabled = false;
                }, 2000);
            }
            if (!waitingUntil && (Date.now() - failureShownAt) > 60000) {
                setState('');
            }
        }
        if (!event.error) {
            fire('mod_jitsi_state_record', {jitsi: config.jitsiid, state: event.on});
        }
    });

    // Persist the recording link when Jitsi publishes it.
    api.addEventListener('recordingLinkAvailable', (event) => {
        fire('mod_jitsi_save_recording_link', {jitsi: config.jitsiid, link: event.link, ttl: event.ttl || 0});
    });

    // Persist the recording link when a recording stops and exposes a URL.
    api.addEventListener('recordingStatusChanged', (event) => {
        if (!event.on && !event.error && event.url) {
            fire('mod_jitsi_save_recording_link', {jitsi: config.jitsiid, link: event.url, ttl: 0});
        }
    });
};
