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
 * AMD module for the call.php page: coursemate search, incoming call polling, and Web Push.
 *
 * @module     mod_jitsi/call
 * @copyright  2019 Sergio Comerón <sergiocomeron@icloud.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

import Ajax from 'core/ajax';
import {get_string as getString} from 'core/str';

// ─── Ringtone via Web Audio API ───────────────────────────────────────────────

/**
 * Play a short ringtone using the Web Audio API.
 */
const playRingtone = () => {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const playBeep = (startTime, freq) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.connect(gain);
            gain.connect(ctx.destination);
            osc.frequency.value = freq;
            osc.type = 'sine';
            gain.gain.setValueAtTime(0.3, startTime);
            gain.gain.exponentialRampToValueAtTime(0.001, startTime + 0.3);
            osc.start(startTime);
            osc.stop(startTime + 0.3);
        };
        playBeep(ctx.currentTime, 880);
        playBeep(ctx.currentTime + 0.4, 1100);
        playBeep(ctx.currentTime + 0.8, 880);
    } catch (e) {
        // Web Audio not available.
    }
};

// ─── Incoming call polling ────────────────────────────────────────────────────

let lastChecked = Math.floor(Date.now() / 1000) - 5;
let shownCallerId = 0;

/**
 * Show the incoming call modal.
 *
 * @param {object} response Response from check_incoming_call
 * @param {string} sessionPrivUrl Base URL of sessionpriv.php
 */
const showCallModal = (response, sessionPrivUrl) => {
    const modal = document.getElementById('jitsi-incoming-modal');
    if (!modal) {
        return;
    }
    const avatar = document.getElementById('jitsi-caller-avatar');
    const nameEl = document.getElementById('jitsi-caller-name');
    const joinBtn = document.getElementById('jitsi-join-btn');

    if (avatar) {
        avatar.src = response.calleravatar;
        avatar.alt = response.callername;
    }
    if (nameEl) {
        getString('incomingcallfrom', 'mod_jitsi', response.callername).then(str => {
            nameEl.textContent = str;
            return;
        }).catch(() => {
            nameEl.textContent = response.callername;
        });
    }
    if (joinBtn) {
        joinBtn.href = `${sessionPrivUrl}?peer=${response.callerid}`;
    }

    playRingtone();

    // Show modal using Bootstrap (available globally in Moodle themes).
    // eslint-disable-next-line no-undef
    if (typeof jQuery !== 'undefined' && jQuery.fn.modal) {
        // eslint-disable-next-line no-undef
        jQuery('#jitsi-incoming-modal').modal('show');
    } else {
        modal.style.display = 'block';
        modal.classList.add('show');
    }
};

/**
 * Poll for incoming calls every 10 seconds.
 *
 * @param {string} sessionPrivUrl Base URL of sessionpriv.php
 */
const startPolling = (sessionPrivUrl) => {
    const poll = () => {
        const since = lastChecked;
        lastChecked = Math.floor(Date.now() / 1000);

        Ajax.call([{
            methodname: 'mod_jitsi_check_incoming_call',
            args: {since},
        }])[0].then((response) => {
            if (response.incoming && response.callerid !== shownCallerId) {
                shownCallerId = response.callerid;
                showCallModal(response, sessionPrivUrl);
            }
            return;
        }).catch(() => {
            // Silently ignore polling errors.
        });
    };

    // First poll after 5 seconds, then every 10 seconds.
    setTimeout(() => {
        poll();
        setInterval(poll, 10000);
    }, 5000);
};

// ─── Web Push ────────────────────────────────────────────────────────────────

/**
 * Convert a base64url string to Uint8Array (needed for VAPID key).
 *
 * @param {string} base64String
 * @returns {Uint8Array}
 */
const urlBase64ToUint8Array = (base64String) => {
    const padding = '='.repeat((4 - (base64String.length % 4)) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    return Uint8Array.from([...rawData].map(c => c.charCodeAt(0)));
};

/**
 * Initialise Web Push: register service worker and manage subscription.
 *
 * @param {string} swUrl  URL of push-sw.js
 * @param {string} vapidKey VAPID public key (base64url)
 */
const initPush = async(swUrl, vapidKey) => {
    const btn = document.getElementById('jitsi-push-btn');
    const status = document.getElementById('jitsi-push-status');

    window.console.log('[Jitsi Push] initPush called. vapidKey length:', vapidKey ? vapidKey.length : 0);
    window.console.log('[Jitsi Push] SW support:', 'serviceWorker' in navigator, '| Push support:', 'PushManager' in window);

    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !vapidKey) {
        window.console.log('[Jitsi Push] Aborting: missing browser support or vapidKey.');
        return;
    }

    if (btn) {
        btn.style.display = '';
    }

    let swReg;
    try {
        // No explicit scope — defaults to the directory of the script, which is always correct
        // regardless of whether Moodle is installed in a subdirectory.
        window.console.log('[Jitsi Push] Registering service worker...');
        swReg = await navigator.serviceWorker.register(swUrl);
        window.console.log('[Jitsi Push] SW registered. State:', swReg.active ? swReg.active.state : 'no active');

        // Wait for the SW to become active without blocking on navigator.serviceWorker.ready
        // (which can hang indefinitely if the SW is stuck in "waiting" state).
        await new Promise((resolve) => {
            const sw = swReg.active || swReg.installing || swReg.waiting;
            if (!sw || sw.state === 'activated') {
                resolve();
                return;
            }
            sw.addEventListener('statechange', function handler() {
                if (sw.state === 'activated' || sw.state === 'redundant') {
                    sw.removeEventListener('statechange', handler);
                    resolve();
                }
            });
            // Safety timeout: don't block the UI forever.
            setTimeout(resolve, 3000);
        });
        window.console.log('[Jitsi Push] SW ready. Attaching click handler...');
    } catch (e) {
        window.console.error('[Jitsi Push] Service worker registration failed:', e);
        if (status) {
            status.textContent = 'Service worker error: ' + e.message;
        }
        return;
    }

    const setStatus = (text) => {
        if (status) {
            status.textContent = text;
        }
    };

    const updateUI = async() => {
        const perm = window.Notification.permission;
        if (perm === 'denied') {
            if (btn) {
                btn.disabled = true;
            }
            getString('pushnotificationsblocked', 'mod_jitsi').then(str => {
                setStatus(str);
                return;
            }).catch(() => {});
            return;
        }

        const sub = await swReg.pushManager.getSubscription();
        if (sub) {
            if (btn) {
                btn.disabled = false;
                getString('disablepushnotifications', 'mod_jitsi').then(str => {
                    btn.textContent = str;
                    return;
                }).catch(() => {});
            }
            getString('pushnotificationsenabled', 'mod_jitsi').then(str => {
                setStatus('✓ ' + str);
                return;
            }).catch(() => {});
        } else {
            if (btn) {
                btn.disabled = false;
                getString('enablepushnotifications', 'mod_jitsi').then(str => {
                    btn.textContent = str;
                    return;
                }).catch(() => {});
            }
            setStatus('');
        }
    };

    await updateUI();

    if (btn) {
        btn.addEventListener('click', async() => {
            window.console.log('[Jitsi Push] Button clicked.');
            btn.disabled = true;

            try {
                const sub = await swReg.pushManager.getSubscription();
                if (sub) {
                    // Unsubscribe.
                    setStatus('...');
                    await sub.unsubscribe();
                    Ajax.call([{
                        methodname: 'mod_jitsi_unregister_push_subscription',
                        args: {endpoint: sub.endpoint},
                    }]);
                } else {
                    // Request permission — browser shows its own dialog.
                    setStatus('Requesting permission...');
                    const perm = await window.Notification.requestPermission();
                    if (perm !== 'granted') {
                        setStatus(perm === 'denied' ? 'Permission denied by browser.' : 'Permission not granted.');
                        await updateUI();
                        return;
                    }

                    setStatus('Subscribing...');
                    const newSub = await swReg.pushManager.subscribe({
                        userVisibleOnly: true,
                        applicationServerKey: urlBase64ToUint8Array(vapidKey),
                    });

                    setStatus('Saving subscription...');
                    const key = newSub.getKey('p256dh');
                    const auth = newSub.getKey('auth');
                    await Ajax.call([{
                        methodname: 'mod_jitsi_register_push_subscription',
                        args: {
                            endpoint:  newSub.endpoint,
                            authkey:   btoa(String.fromCharCode(...new Uint8Array(auth))),
                            p256dhkey: btoa(String.fromCharCode(...new Uint8Array(key))),
                        },
                    }])[0];
                }
            } catch (e) {
                window.console.error('[Jitsi Push] Subscription error:', e);
                setStatus('Error: ' + e.message);
            }

            await updateUI();
        });
    }
};

// ─── Coursemate search ────────────────────────────────────────────────────────

/**
 * Initialise the call search UI, incoming call polling, and Web Push.
 *
 * @param {string} sessionPrivUrl  Base URL of sessionpriv.php
 * @param {string} swUrl           URL of push-sw.js
 * @param {string} vapidKey        VAPID public key (base64url)
 */
export const init = (sessionPrivUrl, swUrl, vapidKey) => {
    const input = document.getElementById('jitsi-call-search');
    const results = document.getElementById('jitsi-call-results');

    if (input && results) {
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

                    const badgePromises = response.users
                        .filter(u => u.hasschedule)
                        .map(u => {
                            if (u.available) {
                                return getString('tutoringavailable', 'mod_jitsi')
                                    .then(str => ({id: u.id, str, cls: 'badge-success'}));
                            }
                            const key = u.nextslot ? 'tutoringnextslot' : 'tutoringnotavailable';
                            return getString(key, 'mod_jitsi', u.nextslot || null)
                                .then(str => ({id: u.id, str, cls: 'badge-warning'}));
                        });

                    return Promise.all(badgePromises).then(badgeData => {
                        const badgeMap = {};
                        badgeData.forEach(b => { badgeMap[b.id] = b; });

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
                            name.className = 'flex-grow-1';
                            name.textContent = `${user.firstname} ${user.lastname}`;

                            item.appendChild(img);
                            item.appendChild(name);

                            if (badgeMap[user.id]) {
                                const badge = document.createElement('span');
                                badge.className = `badge ${badgeMap[user.id].cls} ml-2`;
                                badge.textContent = badgeMap[user.id].str;
                                item.appendChild(badge);
                            }

                            results.appendChild(item);
                        });
                    });
                }).catch(() => {
                    results.innerHTML = '';
                });
            }, 300);
        });
    }

    // Start incoming call polling.
    startPolling(sessionPrivUrl);

    // Initialise Web Push.
    if (swUrl && vapidKey) {
        initPush(swUrl, vapidKey).catch(() => {});
    }
};
