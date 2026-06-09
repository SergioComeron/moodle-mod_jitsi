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
 * AMD module: GCP "Create VM" wizard for the server management page.
 *
 * Drives the modal that creates a Jitsi VM in Google Cloud: options step,
 * creation request, operation polling and the provisioning state machine
 * (waiting_dns → dns_ready → installing → completed/error). On page load it
 * also resumes the modal if a server is still provisioning.
 *
 * @module     mod_jitsi/gcp_wizard
 * @copyright  2025 Sergio Comerón <jitsi@sergiocomeron.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/** Module config, set on init. */
let cfg = null;

/** Modal elements. */
let modalEl = null;
let modalBody = null;
let backdrop = null;

/** Info about the VM being created. */
const vmInfo = {};

/** Whether the DNS warning step has already been rendered. */
let dnsWarningShown = false;

/**
 * Show the modal.
 */
const showModal = () => {
    if (!modalEl) {
        return;
    }
    modalEl.classList.add('show');
    modalEl.style.display = 'block';
    modalEl.removeAttribute('aria-hidden');
    backdrop = document.createElement('div');
    backdrop.className = 'modal-backdrop fade show';
    document.body.appendChild(backdrop);
};

/**
 * Hide the modal.
 */
const closeModal = () => {
    if (modalEl) {
        modalEl.classList.remove('show');
        modalEl.style.display = 'none';
        modalEl.setAttribute('aria-hidden', 'true');
    }
    if (backdrop && backdrop.parentNode) {
        backdrop.parentNode.removeChild(backdrop);
    }
};

/**
 * POST url-encoded data and parse the JSON response.
 *
 * @param {string} url Target URL.
 * @param {object} data Form fields.
 * @return {Promise<object>} Parsed JSON.
 */
const postJSON = async(url, data) => {
    const res = await fetch(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams(data),
    });
    if (!res.ok) {
        throw new Error('HTTP ' + res.status);
    }
    return JSON.parse(await res.text());
};

/**
 * Render a spinner step in the modal body.
 *
 * @param {string} title Step title (may contain emoji).
 * @param {string[]} paragraphs Paragraph texts.
 */
const renderSpinnerStep = (title, paragraphs) => {
    if (!modalBody) {
        return;
    }
    modalBody.innerHTML = '<h5>' + title + '</h5>' +
        paragraphs.map((p) => '<p>' + p + '</p>').join('') +
        '<div class="text-center"><div class="spinner-border spinner-border-sm" role="status"></div></div>';
};

/**
 * Render an error step with a close action.
 *
 * @param {string} html Error body HTML.
 */
const renderError = (html) => {
    if (!modalBody) {
        return;
    }
    modalBody.innerHTML = '<div class="alert alert-danger">' + html + '</div>' +
        '<div class="text-center mt-3">' +
        '<button type="button" class="btn btn-secondary" data-action="close-modal">Close</button>' +
        '</div>';
};

/**
 * Wire a copy-to-clipboard button.
 *
 * @param {string} id Button element id.
 * @param {string} text Text to copy.
 * @param {string} label Button label to restore after copying.
 */
const wireCopyButton = (id, text, label) => {
    const btn = document.getElementById(id);
    if (btn && navigator.clipboard) {
        btn.addEventListener('click', () => {
            navigator.clipboard.writeText(text);
            btn.textContent = '✓ Copied!';
            setTimeout(() => {
                btn.textContent = label;
            }, 2000);
        });
    }
};

/**
 * Render the success step once the server is registered.
 *
 * @param {string} ip Public IP.
 * @param {string} hostname Hostname reported by the server.
 * @param {number} serverid New jitsi_servers id.
 */
const showSuccessMessage = (ip, hostname, serverid) => {
    const host = hostname || cfg.hostname || 'your-hostname.example.com';
    if (!modalBody) {
        return;
    }
    modalBody.innerHTML = '<h5>✅ Jitsi Server Ready & Registered!</h5>' +
        '<p class="text-success"><strong>Installation completed and server registered in Moodle</strong></p>' +
        '<p>Public IP: <strong>' + ip + '</strong></p>' +
        '<p>Your Jitsi Meet server is ready at: <code>https://' + host + '</code></p>' +
        '<div class="mt-3">' +
        '<button id="set-default-server" class="btn btn-success me-2">Set as Default Server</button>' +
        '<button id="copy-ip" class="btn btn-outline-secondary me-2">Copy IP</button>' +
        '<a href="' + cfg.redirectUrl + '" class="btn btn-primary">Close</a>' +
        '</div>';
    wireCopyButton('copy-ip', ip, 'Copy IP');
    const setDefaultBtn = document.getElementById('set-default-server');
    if (setDefaultBtn && serverid) {
        setDefaultBtn.addEventListener('click', () => {
            setDefaultBtn.disabled = true;
            setDefaultBtn.textContent = 'Setting...';
            window.location.href = cfg.redirectUrl + '?action=setdefaultserver&id=' + serverid +
                '&sesskey=' + cfg.sesskey;
        });
    }
};

/**
 * Render the "configure DNS" step.
 *
 * @param {object} data checkjitsiready response.
 */
const showDnsWarning = (data) => {
    const host = data.hostname || cfg.hostname || 'your-hostname.example.com';
    const authHost = 'auth.' + host;
    const ip = data.ip || vmInfo.ip || '';
    if (!modalBody) {
        return;
    }
    modalBody.innerHTML = '<div class="alert alert-warning"><h5>⚠️ Action Required: Configure DNS</h5>' +
        '<p><strong>Public IP: <code>' + ip + '</code></strong></p>' +
        '<p>Please create the following DNS A records:</p>' +
        '<ul class="text-start">' +
        '<li><code>' + host + ' → ' + ip + '</code></li>' +
        '<li><code>' + authHost + ' → ' + ip + '</code></li>' +
        '</ul>' +
        '<p class="text-muted">The installation will continue automatically once DNS propagates ' +
        '(checking every 15 seconds, timeout 15 minutes).</p>' +
        '<div id="dns-copy-buttons" class="mt-2">' +
        '<button id="copy-ip-dns" class="btn btn-sm btn-outline-primary me-2">Copy IP</button>' +
        '<button id="copy-records" class="btn btn-sm btn-outline-secondary">Copy DNS Records</button>' +
        '</div>' +
        '</div>' +
        '<div class="text-center">' +
        '<div class="spinner-border spinner-border-sm" role="status"></div>' +
        '<p class="mt-2">Waiting for DNS propagation...</p>' +
        '</div>';
    wireCopyButton('copy-ip-dns', ip, 'Copy IP');
    wireCopyButton('copy-records', host + ' A ' + ip + '\n' + authHost + ' A ' + ip, 'Copy DNS Records');
};

/**
 * Poll the provisioning status reported by the VM until completed or error.
 */
const checkJitsiReady = async() => {
    try {
        const data = await postJSON(cfg.checkReadyUrl, {
            sesskey: cfg.sesskey,
            instance: vmInfo.instancename,
        });
        if (data.status === 'provisioning') {
            renderSpinnerStep('⚙️ VM Initializing...',
                ['The virtual machine is starting up and running initial setup scripts.']);
            setTimeout(checkJitsiReady, 5000);
        } else if (data.status === 'waiting_dns') {
            if (!dnsWarningShown) {
                dnsWarningShown = true;
                showDnsWarning(data);
            }
            setTimeout(checkJitsiReady, 10000);
        } else if (data.status === 'dns_ready') {
            renderSpinnerStep('✅ DNS Configured!',
                ['<span class="text-success">DNS records detected. Starting Jitsi installation...</span>']);
            setTimeout(checkJitsiReady, 5000);
        } else if (data.status === 'installing') {
            renderSpinnerStep('⚙️ Installing Jitsi Meet...', [
                'The VM is ready. Installing and configuring Jitsi services.',
                '<span class="text-muted">This takes 8-12 minutes. Please wait...</span>',
            ]);
            setTimeout(checkJitsiReady, 10000);
        } else if (data.status === 'completed') {
            showSuccessMessage(data.ip, data.hostname, data.serverid);
        } else if (data.status === 'error') {
            const errorMsg = data.error || 'Unknown installation error';
            if (modalBody) {
                modalBody.innerHTML = '<div class="alert alert-danger">' +
                    '<h5>❌ Installation Failed</h5>' +
                    '<p><strong>Error:</strong> ' + errorMsg + '</p>' +
                    '<p class="text-muted">Please check the VM console logs in Google Cloud Console ' +
                    'for more details.</p>' +
                    '</div>' +
                    '<div class="mt-3">' +
                    '<a href="' + cfg.redirectUrl + '" class="btn btn-primary">Close</a>' +
                    '</div>';
            }
        }
    } catch (e) {
        if (modalBody) {
            modalBody.innerHTML = '<p class="text-warning">Cannot verify status. Check the VM console.</p>';
        }
    }
};

/**
 * Poll the GCP zone operation until the VM exists, then hand over to checkJitsiReady.
 *
 * @param {string} opname GCP operation name.
 */
const pollStatus = async(opname) => {
    try {
        const data = await postJSON(cfg.statusUrl, {sesskey: cfg.sesskey, opname: opname});
        if (data.status === 'pending') {
            setTimeout(() => pollStatus(opname), 1500);
        } else if (data.status === 'done') {
            vmInfo.ip = data.ip || '';
            renderSpinnerStep('⚙️ VM Created - Starting Configuration...', ['Checking installation status...']);
            setTimeout(checkJitsiReady, 3000);
        } else if (modalBody) {
            modalBody.textContent = 'Error: ' + (data.message || 'Unknown');
        }
    } catch (e) {
        if (modalBody) {
            modalBody.textContent = 'Error: ' + e.message;
        }
    }
};

/**
 * Request the VM creation and start polling.
 *
 * @param {boolean} enableJibri Create a dedicated Jibri VM too.
 * @param {string} jibriMachineType Jibri VM machine type.
 * @param {boolean} enableGcs Upload recordings to GCS.
 * @param {string} jitsiMachineType Jitsi VM machine type.
 */
const startVMCreation = async(enableJibri, jibriMachineType, enableGcs, jitsiMachineType) => {
    dnsWarningShown = false;
    renderSpinnerStep('⏳ Creating VM...', ['Setting up infrastructure in Google Cloud.']);
    try {
        const postData = {sesskey: cfg.sesskey, jitsimachinetype: jitsiMachineType || 'e2-standard-4'};
        if (enableJibri) {
            postData.enablejibri = '1';
            postData.jibrimachinetype = jibriMachineType || 'n2-standard-4';
            if (enableGcs) {
                postData.enablegcs = '1';
            }
        }
        const data = await postJSON(cfg.createUrl, postData);
        if (data && data.status === 'pending' && data.opname) {
            vmInfo.instancename = data.instancename;
            pollStatus(data.opname);
        } else if (data && data.status === 'error') {
            renderError('<strong>Error starting VM creation:</strong><br>' + (data.message || 'Unknown error occurred'));
        } else {
            renderError('Error: Unexpected response from server');
        }
    } catch (e) {
        renderError('<strong>Error:</strong><br>' + e.message);
    }
};

/**
 * Render the options step (machine types, Jibri, GCS).
 */
const showStep0 = () => {
    if (!modalBody) {
        return;
    }
    modalBody.innerHTML =
        '<h5 class="mb-3">Create VM in Google Cloud</h5>' +
        '<div class="mb-3 text-start">' +
        '<label class="form-label fw-semibold" for="jitsi-machine-type">Jitsi server machine type</label>' +
        '<select class="form-select" id="jitsi-machine-type">' +
        '<option value="e2-medium">e2-medium — 2 vCPU (shared), 4 GB RAM — ~10 concurrent users</option>' +
        '<option value="e2-standard-2">e2-standard-2 — 2 vCPU, 8 GB RAM — ~20 concurrent users</option>' +
        '<option value="e2-standard-4" selected>e2-standard-4 — 4 vCPU, 16 GB RAM — ' +
        '~50 concurrent users (recommended)</option>' +
        '<option value="e2-standard-8">e2-standard-8 — 8 vCPU, 32 GB RAM — ~100 concurrent users</option>' +
        '<option value="n2-standard-4">n2-standard-4 — 4 vCPU, 16 GB RAM — ' +
        '~60 concurrent users (higher performance)</option>' +
        '<option value="n2-standard-8">n2-standard-8 — 8 vCPU, 32 GB RAM — ~120 concurrent users</option>' +
        '</select>' +
        '<small class="text-muted d-block mt-1">The machine type determines how many simultaneous participants ' +
        'the server can handle.</small>' +
        '</div>' +
        '<div class="mb-3 text-start">' +
        '<div class="form-check">' +
        '<input class="form-check-input" type="checkbox" id="jibri-enable-check">' +
        '<label class="form-check-label fw-semibold" for="jibri-enable-check">' +
        'Enable Jibri recording (dedicated VM)' +
        '</label>' +
        '</div>' +
        '<small class="text-muted d-block mt-1 ms-4">' +
        'A second VM will be created as a dedicated Jibri recording server. Requires at least 4 vCPUs / 8 GB RAM.' +
        '</small>' +
        '</div>' +
        '<div class="mb-3 text-start" id="jibri-machine-row" style="display:none">' +
        '<label class="form-label fw-semibold" for="jibri-machine-type">Jibri VM machine type</label>' +
        '<input type="text" class="form-control" id="jibri-machine-type" value="n2-standard-4">' +
        '<small class="text-muted">Minimum recommended: <code>n2-standard-4</code> (4 vCPUs, 16 GB RAM).</small>' +
        '</div>' +
        '<div class="mb-3 text-start" id="gcs-enable-row" style="display:none">' +
        '<div class="form-check">' +
        '<input class="form-check-input" type="checkbox" id="gcs-enable-check">' +
        '<label class="form-check-label fw-semibold" for="gcs-enable-check">' +
        'Upload recordings to Google Cloud Storage' +
        '</label>' +
        '</div>' +
        '<small class="text-muted d-block mt-1 ms-4">' +
        'Recordings will be uploaded to a GCS bucket and served via a permanent public URL instead of ' +
        'the Jibri VM disk.' +
        '</small>' +
        '</div>' +
        '<div class="d-flex justify-content-end gap-2 mt-3">' +
        '<button type="button" class="btn btn-secondary" data-action="close-modal">Cancel</button>' +
        '<button type="button" class="btn btn-primary" id="jibri-confirm-btn">Create VM</button>' +
        '</div>';
    const check = document.getElementById('jibri-enable-check');
    const machineRow = document.getElementById('jibri-machine-row');
    const gcsRow = document.getElementById('gcs-enable-row');
    const confirmBtn = document.getElementById('jibri-confirm-btn');
    if (check && machineRow) {
        check.addEventListener('change', () => {
            machineRow.style.display = check.checked ? '' : 'none';
            if (gcsRow) {
                gcsRow.style.display = check.checked ? '' : 'none';
            }
        });
    }
    if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
            const enableJibri = check && check.checked;
            const machineTypeEl = document.getElementById('jibri-machine-type');
            const jibriMachine = (machineTypeEl && machineTypeEl.value.trim()) || 'n2-standard-4';
            const jitsiMachineEl = document.getElementById('jitsi-machine-type');
            const jitsiMachine = (jitsiMachineEl && jitsiMachineEl.value.trim()) || 'e2-standard-4';
            const gcsCheck = document.getElementById('gcs-enable-check');
            const enableGcs = enableJibri && gcsCheck && gcsCheck.checked;
            startVMCreation(enableJibri, jibriMachine, enableGcs, jitsiMachine);
        });
    }
};

/**
 * On page load, resume the wizard if a server is still provisioning.
 */
const checkOnLoad = async() => {
    try {
        const response = await fetch(cfg.listUrl);
        const servers = await response.json();
        if (servers && servers.length > 0) {
            for (const srv of servers) {
                if (srv.provisioningstatus && srv.provisioningstatus !== 'ready' && srv.provisioningstatus !== 'error') {
                    vmInfo.instancename = srv.gcpinstancename;
                    showModal();
                    renderSpinnerStep('⚙️ Resuming provisioning...', []);
                    setTimeout(checkJitsiReady, 2000);
                    break;
                }
            }
        }
    } catch (e) {
        // Provisioning check is best-effort; ignore failures.
    }
};

/**
 * Initialise the wizard.
 *
 * @param {object} config Module config.
 * @param {string} config.sesskey Session key.
 * @param {string} config.statusUrl gcpstatusjson endpoint.
 * @param {string} config.createUrl creategcpvm (ajax) endpoint.
 * @param {string} config.listUrl listprovisioningservers endpoint.
 * @param {string} config.redirectUrl Server management page URL.
 * @param {string} config.checkReadyUrl checkjitsiready endpoint.
 * @param {string} config.hostname Configured gcp_hostname (may be empty).
 */
export const init = (config) => {
    cfg = config;
    const btn = document.getElementById('btn-creategcpvm');
    if (!btn) {
        return;
    }
    modalEl = document.getElementById('gcpModal');
    modalBody = document.getElementById('gcp-modal-body');

    // Delegated handler for the Cancel/Close buttons rendered inside the modal.
    if (modalEl) {
        modalEl.addEventListener('click', (e) => {
            if (e.target.closest('[data-action="close-modal"]')) {
                closeModal();
            }
        });
    }

    btn.addEventListener('click', () => {
        showModal();
        showStep0();
    });

    checkOnLoad();
};
