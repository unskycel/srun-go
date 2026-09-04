/**
 * SRun Desktop Client - Modern Fluent 2.0 Frontend Logic
 */

let is_online = false;
let is_available = true;
let is_busy = false;
let srun_host = '';
let srun_self = '';
let active_ip = null;
let selected_ips = [];
let user_name = '';
let saved_accounts = [];
let timer_interval = null;
let live_poll_interval = null;
let current_online_seconds = 0;

const DEFAULT_IP_TOKEN = '__DEFAULT_ROUTE__';

const settingsWizard = {
    step: 'gateway',
    gateway: '',
    selfService: '',
    probeMeta: null,
    results: [],
    selectedTokens: new Set([DEFAULT_IP_TOKEN]),
    activeToken: DEFAULT_IP_TOKEN,
    reachableCount: 0,
};

// --- Initialization & Lifecycle ---
window.addEventListener('DOMContentLoaded', () => {
    bindGlobalKeyboardEvents();
    loadConfig();
    updateOnlineStatus();

    // Close dropdowns on click outside
    document.addEventListener('click', (e) => {
        const wrap = document.getElementById('nic-dropdown-wrap');
        if (wrap && !wrap.contains(e.target)) {
            closeNicDropdown();
        }

        const accMenu = document.getElementById('account-dropdown-menu');
        const accBtn = document.getElementById('btn-account-dropdown');
        if (accMenu && !accMenu.contains(e.target) && accBtn && !accBtn.contains(e.target)) {
            closeAccountDropdown();
        }
    });

    // Managed Adaptive Polling Timer
    startLivePolling();

    // Smart Visibility Lifecycle: pause timer when window is minimized/hidden in tray (0% CPU)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            stopLivePolling();
        } else {
            // Instant wake-up: refresh status immediately, then resume polling
            if (!is_busy) {
                updateOnlineStatus();
                loadConfig();
            }
            startLivePolling();
        }
    });

    window.addEventListener('focus', () => {
        if (!document.hidden && !is_busy) {
            updateOnlineStatus();
        }
    });
});

function startLivePolling() {
    stopLivePolling();
    live_poll_interval = setInterval(() => {
        if (!is_busy && !document.hidden) {
            updateOnlineStatus();
        }
    }, 8000);
}

function stopLivePolling() {
    if (live_poll_interval) {
        clearInterval(live_poll_interval);
        live_poll_interval = null;
    }
}

function bindGlobalKeyboardEvents() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeNicDropdown();
            closeAccountDropdown();
            closeSettings();
            closeAccountManager();
            closeAccountEditor();
            closeLogsModal();
            closeDialog(false);
        } else if (e.key === 'Enter') {
            const activeEl = document.activeElement;
            if (activeEl && (activeEl.id === 'username' || activeEl.id === 'password')) {
                e.preventDefault();
                submit();
            } else if (activeEl && (activeEl.id === 'settings-gateway' || activeEl.id === 'settings-self-service')) {
                e.preventDefault();
                proceedSettingsStep();
            }
        } else if (e.ctrlKey && e.key.toLowerCase() === 'r') {
            e.preventDefault();
            handleManualRefresh();
        }
    });
}

// --- Status & Dashboard Rendering ---
function setPanelState(online, available = true) {
    is_online = online;
    is_available = available;

    const authPanel = document.getElementById('auth-panel');
    const statusBadge = document.getElementById('status-badge');
    const statusText = document.getElementById('status-badge-text');
    const mainBtnText = document.getElementById('main-btn-text');

    if (online) {
        document.body.classList.add('online');
        if (authPanel) authPanel.setAttribute('data-state', 'online');
        if (statusBadge) statusBadge.setAttribute('data-state', 'online');
        if (statusText) statusText.innerText = '校园网已连接';
        if (mainBtnText) mainBtnText.innerText = '断开连接';
    } else {
        document.body.classList.remove('online');
        if (authPanel) authPanel.setAttribute('data-state', 'offline');
        if (statusBadge) statusBadge.setAttribute('data-state', 'offline');
        if (statusText) statusText.innerText = available ? '未连接校园网' : '未在校园网环境';
        if (mainBtnText) mainBtnText.innerText = '连接校园网';
        stopOnlineTimer();
    }
}

function setActionLoading(loading, text) {
    is_busy = loading;
    const btn = document.getElementById('main-action-btn');
    const btnText = document.getElementById('main-btn-text');
    if (!btn) return;

    if (loading) {
        btn.disabled = true;
        btn.classList.add('loading');
        if (text && btnText) btnText.innerText = text;
    } else {
        btn.disabled = false;
        btn.classList.remove('loading');
    }
}

function updateOnlineStatus() {
    if (!window.pywebview || !window.pywebview.api) return;

    const ipParam = active_ip === null ? null : active_ip;
    window.pywebview.api.get_online_data(ipParam).then((res) => {
        if (!res) return;

        const avail = res.is_available !== undefined ? res.is_available : true;
        const online = res.is_online !== undefined ? res.is_online : false;
        const data = res.data || {};

        if (!avail) {
            setPanelState(false, false);
            return;
        }

        if (online) {
            setPanelState(true, true);
            renderOnlineMetrics(data);
        } else {
            setPanelState(false, true);
        }
    }).catch(() => {
        setPanelState(false, false);
    });
}

function renderOnlineMetrics(data) {
    const userEl = document.getElementById('username-text');
    const ipEl = document.getElementById('ip-address');
    const flowEl = document.getElementById('used-flow');
    const balanceEl = document.getElementById('balance-last');

    if (userEl) userEl.innerText = data.user_name || user_name || '--';
    if (ipEl) ipEl.innerText = data.online_ip || data.client_ip || '--';

    if (flowEl) {
        const bytes = data.sum_bytes || 0;
        if (bytes > 1024 * 1024 * 1024) {
            flowEl.innerText = (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
        } else {
            flowEl.innerText = (bytes / 1024 / 1024).toFixed(2) + ' MB';
        }
    }

    if (balanceEl) {
        const bal = data.user_balance !== undefined ? parseFloat(data.user_balance) : 0.0;
        balanceEl.innerText = bal.toFixed(2) + ' 元';
    }

    if (data.user_time) {
        startOnlineTimer(parseInt(data.user_time, 10));
    }
}

function startOnlineTimer(initialSeconds) {
    current_online_seconds = initialSeconds || 0;
    renderOnlineTimerText();

    if (timer_interval) clearInterval(timer_interval);
    timer_interval = setInterval(() => {
        current_online_seconds++;
        renderOnlineTimerText();
    }, 1000);
}

function stopOnlineTimer() {
    if (timer_interval) {
        clearInterval(timer_interval);
        timer_interval = null;
    }
}

function renderOnlineTimerText() {
    const timeEl = document.getElementById('online-time');
    if (!timeEl) return;

    const hrs = Math.floor(current_online_seconds / 3600);
    const mins = Math.floor((current_online_seconds % 3600) / 60);
    const secs = current_online_seconds % 60;

    if (hrs > 0) {
        timeEl.innerText = `${hrs}小时 ${mins}分`;
    } else {
        timeEl.innerText = `${mins}分 ${secs}秒`;
    }
}

// --- Configuration & NIC Selector ---
function applyConfig(cfg) {
    if (!cfg) return;

    const userInput = document.getElementById('username');
    const passInput = document.getElementById('password');
    const autoLoginSwitch = document.getElementById('auto-login');
    const autoStartSwitch = document.getElementById('auto-start');

    user_name = cfg.username || '';
    saved_accounts = Array.isArray(cfg.accounts) ? cfg.accounts : [];
    if (userInput) userInput.value = user_name;
    if (passInput) {
        passInput.value = cfg.has_password ? '************' : '';
    }

    if (autoLoginSwitch) {
        autoLoginSwitch.setAttribute('data-state', cfg.auto_login ? 'selected' : 'unselected');
    }
    if (autoStartSwitch) {
        autoStartSwitch.setAttribute('data-state', cfg.auto_start ? 'selected' : 'unselected');
    }

    srun_host = cfg.gateway || '';
    srun_self = cfg.self_service || '';
    active_ip = cfg.active_ip || null;
    selected_ips = Array.isArray(cfg.local_ips) ? cfg.local_ips.slice() : [];

    renderIpSelector();
    renderAccountDropdown();
    renderAccountManagerCards();

    if (!srun_host) {
        openSettings();
    }
}

function loadConfig() {
    if (!window.pywebview || !window.pywebview.api || !window.pywebview.api.get_config) {
        return Promise.resolve(null);
    }

    return window.pywebview.api.get_config().then((cfg) => {
        applyConfig(cfg);
        return cfg;
    });
}

function toggleNicDropdown(e) {
    if (e) e.stopPropagation();
    const trigger = document.getElementById('nic-dropdown-trigger');
    const menu = document.getElementById('nic-dropdown-menu');
    if (!trigger || !menu) return;

    const isOpen = menu.classList.contains('open');
    if (isOpen) {
        closeNicDropdown();
    } else {
        menu.classList.add('open');
        trigger.setAttribute('aria-expanded', 'true');
    }
}

function closeNicDropdown() {
    const trigger = document.getElementById('nic-dropdown-trigger');
    const menu = document.getElementById('nic-dropdown-menu');
    if (menu) menu.classList.remove('open');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
}

function selectNicOption(val, text) {
    active_ip = val === DEFAULT_IP_TOKEN ? null : val;
    const textEl = document.getElementById('nic-selected-text');
    if (textEl) textEl.innerText = text;

    closeNicDropdown();
    renderIpSelector();

    if (window.pywebview && window.pywebview.api) {
        window.pywebview.api.set_active_ip(active_ip).then(() => {
            updateOnlineStatus();
        });
    }
}

function renderIpSelector() {
    const menu = document.getElementById('nic-dropdown-menu');
    const selectedTextEl = document.getElementById('nic-selected-text');
    if (!menu) return;

    menu.innerHTML = '';

    const defaultVal = DEFAULT_IP_TOKEN;
    const defaultLabel = '默认路由 (自动)';
    const isDefaultSelected = active_ip === null || active_ip === DEFAULT_IP_TOKEN;

    if (isDefaultSelected && selectedTextEl) {
        selectedTextEl.innerText = defaultLabel;
    }

    // 1. Default Option
    const defaultOptionEl = document.createElement('div');
    defaultOptionEl.className = `custom-dropdown-option ${isDefaultSelected ? 'selected' : ''}`;
    defaultOptionEl.onclick = (e) => {
        e.stopPropagation();
        selectNicOption(defaultVal, defaultLabel);
    };
    defaultOptionEl.innerHTML = `
        <span>${defaultLabel}</span>
        ${isDefaultSelected ? '<span class="option-check">✓</span>' : ''}
    `;
    menu.appendChild(defaultOptionEl);

    // 2. Local IP Options
    let hasSelectedActive = isDefaultSelected;
    if (Array.isArray(selected_ips)) {
        selected_ips.forEach((ip) => {
            if (!ip) return;
            const ipStr = String(ip);
            const isSelected = !isDefaultSelected && active_ip && String(active_ip) === ipStr;

            if (isSelected) {
                hasSelectedActive = true;
                if (selectedTextEl) selectedTextEl.innerText = ipStr;
            }

            const optEl = document.createElement('div');
            optEl.className = `custom-dropdown-option ${isSelected ? 'selected' : ''}`;
            optEl.onclick = (e) => {
                e.stopPropagation();
                selectNicOption(ipStr, ipStr);
            };
            optEl.innerHTML = `
                <span>${ipStr}</span>
                ${isSelected ? '<span class="option-check">✓</span>' : ''}
            `;
            menu.appendChild(optEl);
        });
    }

    if (!hasSelectedActive) {
        active_ip = null;
        if (selectedTextEl) selectedTextEl.innerText = defaultLabel;
    }
}

// --- User Actions: Login / Logout ---
function submit() {
    if (is_busy) return;

    if (!srun_host) {
        showAlert('请先配置深澜网关地址！');
        openSettings();
        return;
    }

    if (is_online) {
        // Perform Logout
        setActionLoading(true, '正在断开连接...');
        window.pywebview.api.logout(active_ip).then(() => {
            setActionLoading(false);
            setPanelState(false, true);
            showMiniToast('校园网已断开');
            updateOnlineStatus();
        }).catch((err) => {
            setActionLoading(false);
            showAlert(`注销异常: ${err}`);
            updateOnlineStatus();
        });
    } else {
        // Perform Login
        const userInput = document.getElementById('username');
        const passInput = document.getElementById('password');
        const autoLogin = document.getElementById('auto-login').getAttribute('data-state') === 'selected';
        const autoStart = document.getElementById('auto-start').getAttribute('data-state') === 'selected';

        const u = userInput ? userInput.value.trim() : '';
        const p = passInput ? passInput.value : '';

        if (!u) {
            showAlert('请输入校园网账号！');
            if (userInput) userInput.focus();
            return;
        }

        // Save credentials first
        const payload = {
            username: u,
            auto_login: autoLogin,
            auto_start: autoStart
        };
        if (p && p !== '************') {
            payload.password = p;
        }

        setActionLoading(true, '正在认证登录...');
        window.pywebview.api.set_config(payload).then(() => {
            window.pywebview.api.login(active_ip).then((res) => {
                setActionLoading(false);
                if (res && (res.error === 'ok' || (res.suc_msg && res.suc_msg.includes('ok')))) {
                    setPanelState(true, true);
                    showMiniToast('登录成功！');
                    updateOnlineStatus();
                } else {
                    const errText = (res && (res.error_msg || res.error)) || '登录失败，请检查账号密码';
                    showAlert(`登录失败：${errText}`);
                    updateOnlineStatus();
                }
            }).catch((err) => {
                setActionLoading(false);
                showAlert(`连接网关异常: ${err}`);
            });
        });
    }
}

function handleManualRefresh() {
    const icon = document.getElementById('refresh-icon-svg');
    if (icon) {
        icon.style.transition = 'transform 0.5s cubic-bezier(0.16, 1, 0.3, 1)';
        icon.style.transform = 'rotate(360deg)';
        setTimeout(() => {
            icon.style.transition = 'none';
            icon.style.transform = 'none';
        }, 500);
    }
    updateOnlineStatus();
    loadConfig();
    showMiniToast('已刷新状态');
}

function startSelfService() {
    if (!srun_self) {
        showAlert('请先在设置中配置【自服务地址】！');
        openSettings();
        return;
    }
    window.pywebview.api.start_self_service(active_ip);
}

function togglePasswordVisibility() {
    const passInput = document.getElementById('password');
    const eyeIcon = document.getElementById('eye-icon');
    if (!passInput) return;

    if (passInput.type === 'password') {
        passInput.type = 'text';
        if (eyeIcon) eyeIcon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>';
    } else {
        passInput.type = 'password';
        if (eyeIcon) eyeIcon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
    }
}

function toggleSwitch(el) {
    const state = el.getAttribute('data-state');
    const newState = state === 'selected' ? 'unselected' : 'selected';
    el.setAttribute('data-state', newState);

    const autoLogin = document.getElementById('auto-login')?.getAttribute('data-state') === 'selected';
    const autoStart = (el.id === 'settings-auto-start' || el.id === 'auto-start')
        ? (newState === 'selected')
        : (document.getElementById('auto-start')?.getAttribute('data-state') === 'selected');

    if (el.id === 'auto-start') {
        const setAutoStartEl = document.getElementById('settings-auto-start');
        if (setAutoStartEl) setAutoStartEl.setAttribute('data-state', newState);
    } else if (el.id === 'settings-auto-start') {
        const mainAutoStartEl = document.getElementById('auto-start');
        if (mainAutoStartEl) mainAutoStartEl.setAttribute('data-state', newState);
    }

    window.pywebview.api.set_config({
        auto_login: autoLogin,
        auto_start: autoStart
    });
}

function copyOnlineIP() {
    const ipEl = document.getElementById('ip-address');
    if (!ipEl || ipEl.innerText === '--') return;

    navigator.clipboard.writeText(ipEl.innerText).then(() => {
        showMiniToast('出口 IP 已复制到剪贴板');
    });
}

function showMiniToast(msg) {
    const t = document.getElementById('mini-toast');
    if (!t) return;
    t.innerText = msg;
    t.classList.add('show');
    setTimeout(() => {
        t.classList.remove('show');
    }, 2000);
}

function handleSettingsAutoStartSync(el) {
    const state = el.getAttribute('data-state');
    const mainAutoStart = document.getElementById('auto-start');
    if (mainAutoStart) mainAutoStart.setAttribute('data-state', state);
}

function handleSettingsAutoReconnectToggle(el) {
    const isSelected = el.getAttribute('data-state') === 'selected';
    const setIntervalWrapEl = document.getElementById('settings-interval-wrap');
    if (setIntervalWrapEl) {
        if (isSelected) {
            setIntervalWrapEl.classList.remove('disabled');
        } else {
            setIntervalWrapEl.classList.add('disabled');
        }
    }
}

// --- Settings Wizard ---
function openSettings() {
    window.pywebview.api.get_ip_settings().then((settings) => {
        if (!settings) return;

        settingsWizard.step = 'gateway';
        settingsWizard.gateway = settings.gateway || srun_host || '';
        settingsWizard.selfService = settings.self_service || srun_self || '';

        const sel = Array.isArray(settings.selected) ? settings.selected : selected_ips;
        settingsWizard.selectedTokens = new Set(sel.map(tokenForIp));
        settingsWizard.activeToken = tokenForIp(settings.active !== undefined ? settings.active : active_ip);

        document.getElementById('settings-gateway').value = settingsWizard.gateway;
        document.getElementById('settings-self-service').value = settingsWizard.selfService;

        const autoStart = settings.auto_start !== undefined ? settings.auto_start : (document.getElementById('auto-start')?.getAttribute('data-state') === 'selected');
        const autoReconnect = settings.auto_reconnect !== undefined ? settings.auto_reconnect : false;
        const sleeptime = settings.sleeptime || 5;

        const setAutoStartEl = document.getElementById('settings-auto-start');
        const setAutoRecEl = document.getElementById('settings-auto-reconnect');
        const setSleeptimeEl = document.getElementById('settings-sleeptime');
        const setIntervalWrapEl = document.getElementById('settings-interval-wrap');

        if (setAutoStartEl) setAutoStartEl.setAttribute('data-state', autoStart ? 'selected' : 'unselected');
        if (setAutoRecEl) setAutoRecEl.setAttribute('data-state', autoReconnect ? 'selected' : 'unselected');
        if (setSleeptimeEl) setSleeptimeEl.value = sleeptime;
        if (setIntervalWrapEl) {
            if (autoReconnect) {
                setIntervalWrapEl.classList.remove('disabled');
            } else {
                setIntervalWrapEl.classList.add('disabled');
            }
        }

        document.getElementById('settings-step-gateway').classList.add('active');
        document.getElementById('settings-step-ip').classList.remove('active');
        document.getElementById('settings-probe-status').innerText = '点击下方按钮将检查网关连通性';

        document.getElementById('settings-action-next').classList.remove('hidden');
        document.getElementById('settings-action-refresh').classList.add('hidden');
        document.getElementById('settings-action-save').classList.add('hidden');
        document.getElementById('settings-action-back').classList.add('hidden');

        const mask = document.getElementById('settings-mask');
        if (mask) {
            mask.style.display = 'flex';
            setTimeout(() => { mask.style.opacity = '1'; }, 20);
        }
    });
}

function closeSettings() {
    const mask = document.getElementById('settings-mask');
    if (!mask) return;
    mask.style.opacity = '0';
    setTimeout(() => { mask.style.display = 'none'; }, 250);
}

function proceedSettingsStep() {
    const gwInput = document.getElementById('settings-gateway').value.trim();
    const ssInput = document.getElementById('settings-self-service').value.trim();

    if (!gwInput) {
        showAlert('深澜网关地址不能为空！');
        return;
    }

    settingsWizard.gateway = gwInput;
    settingsWizard.selfService = ssInput;
    document.getElementById('settings-probe-status').innerText = '正在探测网关连通性...';
    document.getElementById('settings-action-next').disabled = true;

    window.pywebview.api.probe_gateway_ips(gwInput, ssInput).then((res) => {
        document.getElementById('settings-action-next').disabled = false;
        if (!res || !Array.isArray(res.results)) {
            document.getElementById('settings-probe-status').innerText = '探测失败，请检查网关地址';
            return;
        }

        settingsWizard.results = res.results;
        settingsWizard.reachableCount = res.reachable_count || 0;
        initializeSelectionFromProbe(res);

        renderProbeResults();
        settingsWizard.step = 'ip';

        document.getElementById('settings-step-gateway').classList.remove('active');
        document.getElementById('settings-step-ip').classList.add('active');

        document.getElementById('settings-action-next').classList.add('hidden');
        document.getElementById('settings-action-refresh').classList.remove('hidden');
        document.getElementById('settings-action-save').classList.remove('hidden');
        document.getElementById('settings-action-back').classList.remove('hidden');
    }).catch(() => {
        document.getElementById('settings-action-next').disabled = false;
        document.getElementById('settings-probe-status').innerText = '网络连接超时';
    });
}

function backSettingsStep() {
    settingsWizard.step = 'gateway';
    document.getElementById('settings-step-gateway').classList.add('active');
    document.getElementById('settings-step-ip').classList.remove('active');

    document.getElementById('settings-action-next').classList.remove('hidden');
    document.getElementById('settings-action-refresh').classList.add('hidden');
    document.getElementById('settings-action-save').classList.add('hidden');
    document.getElementById('settings-action-back').classList.add('hidden');
}

function refreshSettingsProbe() {
    proceedSettingsStep();
}

function tokenForIp(ip) {
    if (ip === null || ip === undefined || ip === '' || ip === 'null' || ip === 'default' || ip === 'auto') {
        return DEFAULT_IP_TOKEN;
    }
    return String(ip);
}

function initializeSelectionFromProbe(result) {
    const nextSelected = new Set();
    nextSelected.add(DEFAULT_IP_TOKEN);

    if (Array.isArray(result.results)) {
        result.results.forEach((item) => {
            if (item.reachable && item.ip) {
                nextSelected.add(tokenForIp(item.ip));
            }
        });
    }

    settingsWizard.selectedTokens = nextSelected;
    settingsWizard.activeToken = DEFAULT_IP_TOKEN;
}

function renderProbeResults() {
    const container = document.getElementById('settings-probe-results');
    if (!container) return;
    container.innerHTML = '';

    settingsWizard.results.forEach((item) => {
        const row = document.createElement('div');
        row.className = 'probe-item';

        const token = tokenForIp(item.ip);
        const isChecked = settingsWizard.selectedTokens.has(token);

        row.innerHTML = `
            <input type="checkbox" id="chk-${token}" ${isChecked ? 'checked' : ''} onchange="toggleProbeToken('${token}', this.checked)" />
            <label for="chk-${token}" style="flex:1; cursor:pointer; display:flex; justify-content:space-between;">
                <span>${item.label || item.ip || '默认路由'}</span>
                <span style="color:${item.reachable ? 'var(--success)' : 'var(--danger)'}; font-size:11px;">${item.message || (item.reachable ? 'OK' : '不可达')}</span>
            </label>
        `;
        container.appendChild(row);
    });
}

function toggleProbeToken(token, checked) {
    if (checked) {
        settingsWizard.selectedTokens.add(token);
    } else {
        settingsWizard.selectedTokens.delete(token);
    }
}

function saveSettings() {
    const selectedArray = Array.from(settingsWizard.selectedTokens).map((t) => {
        return t === DEFAULT_IP_TOKEN ? null : t;
    });

    const activeVal = settingsWizard.activeToken === DEFAULT_IP_TOKEN ? null : settingsWizard.activeToken;
    const autoStart = document.getElementById('settings-auto-start')?.getAttribute('data-state') === 'selected';
    const autoReconnect = document.getElementById('settings-auto-reconnect')?.getAttribute('data-state') === 'selected';
    const sleeptimeVal = parseInt(document.getElementById('settings-sleeptime')?.value, 10) || 5;

    const payload = {
        gateway: settingsWizard.gateway,
        self_service: settingsWizard.selfService,
        selected: selectedArray,
        active: activeVal,
        auto_start: autoStart,
        auto_reconnect: autoReconnect,
        sleeptime: sleeptimeVal
    };

    window.pywebview.api.update_ip_settings(payload).then(() => {
        closeSettings();
        showMiniToast('配置已保存');
        loadConfig();
        updateOnlineStatus();
    });
}

function handleResetConfig() {
    showConfirmAlert('确定要重置所有配置与登录信息吗？', () => {
        window.pywebview.api.reset_config().then(() => {
            closeSettings();
            showMiniToast('配置已恢复默认');
            loadConfig();
            updateOnlineStatus();
        });
    });
}

// --- Dialog / Alert System ---
let dialogResultCallback = null;

function showAlert(msg) {
    const mask = document.getElementById('dialog-mask');
    const msgEl = document.getElementById('dialog-msg');
    const cancelBtn = document.getElementById('dialog-btn-cancel');
    const altBtn = document.getElementById('dialog-btn-alt');
    const confirmBtn = document.getElementById('dialog-btn-confirm');

    if (msgEl) msgEl.innerText = msg;
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (altBtn) altBtn.style.display = 'none';
    if (confirmBtn) confirmBtn.innerText = '确定';

    dialogResultCallback = null;
    if (mask) {
        mask.style.display = 'flex';
        setTimeout(() => { mask.style.opacity = '1'; }, 20);
    }
}

function showConfirmAlert(msg, onConfirm) {
    const mask = document.getElementById('dialog-mask');
    const msgEl = document.getElementById('dialog-msg');
    const cancelBtn = document.getElementById('dialog-btn-cancel');
    const altBtn = document.getElementById('dialog-btn-alt');
    const confirmBtn = document.getElementById('dialog-btn-confirm');

    if (msgEl) msgEl.innerText = msg;
    if (cancelBtn) {
        cancelBtn.style.display = 'inline-block';
        cancelBtn.innerText = '取消';
    }
    if (altBtn) altBtn.style.display = 'none';
    if (confirmBtn) confirmBtn.innerText = '确定';

    dialogResultCallback = (action) => {
        if (action === true && typeof onConfirm === 'function') {
            onConfirm();
        }
    };
    if (mask) {
        mask.style.display = 'flex';
        setTimeout(() => { mask.style.opacity = '1'; }, 20);
    }
}

function showThreeOptionDialog(msg, confirmText, onConfirm, altText, onAlt) {
    const mask = document.getElementById('dialog-mask');
    const msgEl = document.getElementById('dialog-msg');
    const cancelBtn = document.getElementById('dialog-btn-cancel');
    const altBtn = document.getElementById('dialog-btn-alt');
    const confirmBtn = document.getElementById('dialog-btn-confirm');

    if (msgEl) msgEl.innerText = msg;
    if (cancelBtn) {
        cancelBtn.style.display = 'inline-block';
        cancelBtn.innerText = '取消';
    }
    if (altBtn) {
        altBtn.style.display = 'inline-block';
        altBtn.innerText = altText || '仅切换默认';
    }
    if (confirmBtn) {
        confirmBtn.innerText = confirmText || '立即重连';
    }

    dialogResultCallback = (action) => {
        if (action === true && typeof onConfirm === 'function') {
            onConfirm();
        } else if (action === 'alt' && typeof onAlt === 'function') {
            onAlt();
        }
    };
    if (mask) {
        mask.style.display = 'flex';
        setTimeout(() => { mask.style.opacity = '1'; }, 20);
    }
}

function closeDialog(action) {
    const mask = document.getElementById('dialog-mask');
    if (mask) {
        mask.style.opacity = '0';
        setTimeout(() => { mask.style.display = 'none'; }, 250);
    }
    const cb = dialogResultCallback;
    dialogResultCallback = null;
    if (typeof cb === 'function') {
        cb(action);
    }
}

// --- Multi-Account Switching & Management Logic ---
function toggleAccountDropdown(e) {
    if (e) e.stopPropagation();
    const menu = document.getElementById('account-dropdown-menu');
    if (!menu) return;

    if (!menu.classList.contains('hidden')) {
        closeAccountDropdown();
        return;
    }

    renderAccountDropdown();
    menu.classList.remove('hidden');
}

function closeAccountDropdown() {
    const menu = document.getElementById('account-dropdown-menu');
    if (menu) menu.classList.add('hidden');
}

function renderAccountDropdown() {
    const menu = document.getElementById('account-dropdown-menu');
    if (!menu) return;

    if (saved_accounts.length === 0) {
        menu.innerHTML = `
            <div style="padding: 10px; font-size: 11px; color: var(--ink-muted); text-align: center;">
                暂无保存的账号
            </div>
            <div class="account-dropdown-footer">
                <button class="text-link-btn" onclick="closeAccountDropdown(); openAccountEditor();">+ 添加账号</button>
                <button class="text-link-btn" onclick="closeAccountDropdown(); openAccountManager();">用户管理</button>
            </div>
        `;
        return;
    }

    let itemsHtml = '';
    saved_accounts.forEach((acc) => {
        const isActive = acc.username === user_name;
        itemsHtml += `
            <div class="account-dropdown-item ${isActive ? 'active' : ''}" onclick="handleAccountSelect('${acc.username}')">
                <div class="account-item-info">
                    <span class="account-item-user">${acc.username}</span>
                    <span class="account-item-remark">${acc.remark || (isActive ? '当前活跃账号' : '')}</span>
                </div>
                ${isActive ? '<span class="account-item-tag">使用中</span>' : ''}
            </div>
        `;
    });

    menu.innerHTML = `
        <div style="max-height: 140px; overflow-y: auto;">
            ${itemsHtml}
        </div>
        <div class="account-dropdown-footer">
            <button class="text-link-btn" onclick="closeAccountDropdown(); openAccountEditor();">+ 添加账号</button>
            <button class="text-link-btn" onclick="closeAccountDropdown(); openAccountManager();">用户管理</button>
        </div>
    `;
}

function requestSwitchAccount(targetUsername) {
    if (!targetUsername || targetUsername === user_name) return;

    if (is_online) {
        const userEl = document.getElementById('username-text');
        const currentOnlineUser = (userEl && userEl.innerText && userEl.innerText !== '--') ? userEl.innerText : user_name;
        showThreeOptionDialog(
            `当前已连接校园网（在线账号：${currentOnlineUser}），切换至「${targetUsername}」时如何处理？`,
            '立即注销并重连',
            () => {
                closeAccountManager();
                closeAccountDropdown();
                setActionLoading(true, '正在断开当前连接...');
                window.pywebview.api.logout(active_ip).then(() => {
                    setActionLoading(true, `正在以 ${targetUsername} 重新登录...`);
                    return window.pywebview.api.switch_account(targetUsername);
                }).then((cfg) => {
                    applyConfig(cfg);
                    return window.pywebview.api.login(active_ip);
                }).then((res) => {
                    setActionLoading(false);
                    if (res && res.success) {
                        updateOnlineStatus();
                        showMiniToast(`已切换至 ${targetUsername} 并重新连接`);
                    } else {
                        const err = (res && (res.error_msg || res.error)) || '登录失败，请检查密码';
                        showAlert(`登录失败: ${err}`);
                        updateOnlineStatus();
                    }
                }).catch((err) => {
                    setActionLoading(false);
                    showAlert(`切换重连异常: ${err}`);
                    updateOnlineStatus();
                });
            },
            '仅切换默认账号',
            () => {
                window.pywebview.api.switch_account(targetUsername).then((cfg) => {
                    applyConfig(cfg);
                    showMiniToast(`已将 ${targetUsername} 设为默认账号（下次登录生效）`);
                }).catch((err) => {
                    showAlert(`切换账号失败: ${err}`);
                });
            }
        );
    } else {
        window.pywebview.api.switch_account(targetUsername).then((cfg) => {
            applyConfig(cfg);
            showMiniToast(`已切换至: ${targetUsername}`);
        }).catch((err) => {
            showAlert(`切换账号失败: ${err}`);
        });
    }
}

function handleAccountSelect(username) {
    closeAccountDropdown();
    requestSwitchAccount(username);
}

// --- Account Management Modal ---
function openAccountManager() {
    closeAccountDropdown();
    const showModal = () => {
        renderAccountManagerCards();
        const mask = document.getElementById('accounts-mask');
        if (mask) {
            mask.style.display = 'flex';
            setTimeout(() => { mask.style.opacity = '1'; }, 20);
        }
    };

    if (window.pywebview && window.pywebview.api && window.pywebview.api.get_accounts) {
        window.pywebview.api.get_accounts().then((accounts) => {
            if (Array.isArray(accounts)) {
                saved_accounts = accounts;
            }
            showModal();
        }).catch(() => {
            showModal();
        });
    } else {
        showModal();
    }
}

function closeAccountManager() {
    const mask = document.getElementById('accounts-mask');
    if (!mask) return;
    mask.style.opacity = '0';
    setTimeout(() => { mask.style.display = 'none'; }, 250);
}

function renderAccountManagerCards() {
    const container = document.getElementById('account-cards-container');
    if (!container) return;

    if (saved_accounts.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 20px; font-size: 12px; color: var(--ink-muted);">
                还没有保存任何账号，点击下方按钮添加
            </div>
        `;
        return;
    }

    let cardsHtml = '';
    saved_accounts.forEach((acc) => {
        const isActive = acc.username === user_name;
        cardsHtml += `
            <div class="account-card ${isActive ? 'active' : ''}">
                <div class="account-card-header">
                    <span class="account-card-user">
                        ${acc.username}
                        ${isActive ? '<span class="account-item-tag">当前使用</span>' : ''}
                    </span>
                    <span class="account-card-remark">${acc.remark || ''}</span>
                </div>
                <div class="account-card-actions">
                    ${!isActive ? `<button class="card-btn card-btn-switch" onclick="handleManagerSwitch('${acc.username}')">切换</button>` : ''}
                    <button class="card-btn card-btn-edit" onclick="openAccountEditor('${acc.username}')">编辑</button>
                    <button class="card-btn card-btn-delete" onclick="handleManagerDelete('${acc.username}')">删除</button>
                </div>
            </div>
        `;
    });

    container.innerHTML = cardsHtml;
}

function handleManagerSwitch(username) {
    requestSwitchAccount(username);
}

function handleManagerDelete(username) {
    showConfirmAlert(`确定要删除账号 ${username} 吗？`, () => {
        window.pywebview.api.delete_account(username).then(() => {
            loadConfig().then(() => {
                window.pywebview.api.get_accounts().then((accounts) => {
                    saved_accounts = Array.isArray(accounts) ? accounts : [];
                    renderAccountManagerCards();
                    renderAccountDropdown();
                    showMiniToast(`账号 ${username} 已删除`);
                });
            });
        }).catch((err) => {
            showAlert(`删除账号失败: ${err}`);
        });
    });
}

// --- Account Editor Modal ---
let current_editing_username = null;

function openAccountEditor(targetUsername) {
    current_editing_username = targetUsername || null;
    const titleEl = document.getElementById('account-editor-title');
    const userInput = document.getElementById('editor-username');
    const passInput = document.getElementById('editor-password');
    const remarkInput = document.getElementById('editor-remark');
    const autoLoginSwitch = document.getElementById('editor-autologin');

    if (targetUsername) {
        if (titleEl) titleEl.innerText = '编辑账号';
        const target = saved_accounts.find(a => a.username === targetUsername);
        if (userInput) {
            userInput.value = targetUsername;
            userInput.disabled = true;
        }
        if (passInput) {
            passInput.value = '';
            passInput.placeholder = '留空保留原密码';
        }
        if (remarkInput) remarkInput.value = (target && target.remark) || '';
        if (autoLoginSwitch) {
            autoLoginSwitch.setAttribute('data-state', (target && target.auto_login) ? 'selected' : 'unselected');
        }
    } else {
        if (titleEl) titleEl.innerText = '添加账号';
        if (userInput) {
            userInput.value = '';
            userInput.disabled = false;
        }
        if (passInput) {
            passInput.value = '';
            passInput.placeholder = '请输入认证密码';
        }
        if (remarkInput) remarkInput.value = '';
        if (autoLoginSwitch) {
            autoLoginSwitch.setAttribute('data-state', 'unselected');
        }
    }

    const mask = document.getElementById('account-editor-mask');
    if (mask) {
        mask.style.display = 'flex';
        setTimeout(() => { mask.style.opacity = '1'; }, 20);
    }
}

function closeAccountEditor() {
    const mask = document.getElementById('account-editor-mask');
    if (!mask) return;
    mask.style.opacity = '0';
    setTimeout(() => { mask.style.display = 'none'; }, 250);
}

function saveAccountFromEditor() {
    const userInput = document.getElementById('editor-username');
    const passInput = document.getElementById('editor-password');
    const remarkInput = document.getElementById('editor-remark');
    const autoLoginSwitch = document.getElementById('editor-autologin');

    const username = userInput ? userInput.value.trim() : '';
    const password = passInput ? passInput.value : '';
    const remark = remarkInput ? remarkInput.value.trim() : '';
    const autoLogin = autoLoginSwitch ? autoLoginSwitch.getAttribute('data-state') === 'selected' : false;

    if (!username) {
        showAlert('账号不能为空！');
        return;
    }

    if (!current_editing_username && !password) {
        showAlert('新添加账号必须设置密码！');
        return;
    }

    const payload = {
        username: username,
        password: password,
        remark: remark,
        auto_login: autoLogin
    };

    window.pywebview.api.save_account(payload).then((cfg) => {
        closeAccountEditor();
        applyConfig(cfg);
        showMiniToast(`账号 ${username} 已保存`);
    }).catch((err) => {
        showAlert(`保存账号失败: ${err}`);
    });
}

// --- In-Memory Real-Time Logs Modal ---
let current_logs_cache = [];
let current_log_filter = 'all';

function openLogsModal() {
    const mask = document.getElementById('logs-mask');
    if (!mask) return;
    mask.style.display = 'flex';
    setTimeout(() => { mask.style.opacity = '1'; }, 20);
    renderLogs();
}

function closeLogsModal() {
    const mask = document.getElementById('logs-mask');
    if (!mask) return;
    mask.style.opacity = '0';
    setTimeout(() => { mask.style.display = 'none'; }, 200);
}

function setLogFilter(filter) {
    current_log_filter = filter;
    document.querySelectorAll('.log-filter-pill').forEach((pill) => {
        pill.classList.toggle('active', pill.getAttribute('data-filter') === filter);
    });
    renderLogs();
}

function renderLogs() {
    if (!window.pywebview || !window.pywebview.api || !window.pywebview.api.get_logs) return;
    window.pywebview.api.get_logs().then((logs) => {
        current_logs_cache = Array.isArray(logs) ? logs : [];
        const container = document.getElementById('logs-console-box');
        if (!container) return;

        // Compute counts for filter badges
        const countAll = current_logs_cache.length;
        const countError = current_logs_cache.filter((e) => {
            const lvl = (e.level || '').toUpperCase();
            return lvl === 'ERROR' || lvl === 'WARN';
        }).length;
        const countEvent = current_logs_cache.filter((e) => {
            const lvl = (e.level || '').toUpperCase();
            return lvl === 'EVENT' || lvl === 'SUCCESS';
        }).length;

        const badgeAll = document.getElementById('badge-count-all');
        const badgeErr = document.getElementById('badge-count-error');
        const badgeEvt = document.getElementById('badge-count-event');
        if (badgeAll) badgeAll.innerText = countAll;
        if (badgeErr) badgeErr.innerText = countError;
        if (badgeEvt) badgeEvt.innerText = countEvent;

        // Filter records
        let filtered = current_logs_cache;
        if (current_log_filter === 'error') {
            filtered = current_logs_cache.filter((e) => {
                const lvl = (e.level || '').toUpperCase();
                return lvl === 'ERROR' || lvl === 'WARN';
            });
        } else if (current_log_filter === 'event') {
            filtered = current_logs_cache.filter((e) => {
                const lvl = (e.level || '').toUpperCase();
                return lvl === 'EVENT' || lvl === 'SUCCESS';
            });
        }

        if (filtered.length === 0) {
            let emptyMsg = '暂无运行日志';
            if (current_log_filter === 'error') {
                emptyMsg = '✨ 系统运行良好<br>暂无异常与错误记录';
            } else if (current_log_filter === 'event') {
                emptyMsg = '暂无重连或网卡事件记录';
            }
            container.innerHTML = `<div class="logs-empty-tip">${emptyMsg}</div>`;
            return;
        }

        let html = '';
        filtered.forEach((item) => {
            const time = escapeHtml(item.time || '');
            const level = escapeHtml(item.level || 'INFO').toUpperCase();
            const msg = escapeHtml(item.message || '');
            const badgeClass = `log-badge-${level.toLowerCase()}`;

            html += `<div class="log-row">
                <span class="log-time">${time}</span>
                <span class="log-badge ${badgeClass}">${level}</span>
                <span class="log-msg">${msg}</span>
            </div>`;
        });

        container.innerHTML = html;
        container.scrollTop = container.scrollHeight;
    }).catch((err) => {
        console.error('get_logs error:', err);
    });
}

function copyLogsToClipboard() {
    if (!current_logs_cache || current_logs_cache.length === 0) {
        showMiniToast('暂无日志可复制');
        return;
    }

    // Filter copy content based on current view filter
    let toCopy = current_logs_cache;
    if (current_log_filter === 'error') {
        toCopy = current_logs_cache.filter((e) => {
            const lvl = (e.level || '').toUpperCase();
            return lvl === 'ERROR' || lvl === 'WARN';
        });
    } else if (current_log_filter === 'event') {
        toCopy = current_logs_cache.filter((e) => {
            const lvl = (e.level || '').toUpperCase();
            return lvl === 'EVENT' || lvl === 'SUCCESS';
        });
    }

    if (toCopy.length === 0) {
        showMiniToast('当前筛选分类下暂无日志');
        return;
    }

    const textLines = toCopy.map((item) => {
        return `[${item.time}] [${item.level}] ${item.message}`;
    });
    const content = textLines.join('\n');

    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(content).then(() => {
            showMiniToast(`已复制 ${toCopy.length} 条日志到剪贴板！`);
        }).catch(() => {
            fallbackCopyText(content);
        });
    } else {
        fallbackCopyText(content);
    }
}

function fallbackCopyText(content) {
    const textarea = document.createElement('textarea');
    textarea.value = content;
    document.body.appendChild(textarea);
    textarea.select();
    try {
        document.execCommand('copy');
        showMiniToast('日志已复制到剪贴板！');
    } catch (e) {
        showAlert('复制失败，请手动选择复制');
    }
    document.body.removeChild(textarea);
}

function clearLogs() {
    if (!window.pywebview || !window.pywebview.api || !window.pywebview.api.clear_logs) return;
    window.pywebview.api.clear_logs().then(() => {
        current_logs_cache = [];
        renderLogs();
        showMiniToast('运行日志已清空');
    }).catch((err) => {
        showAlert(`清空失败: ${err}`);
    });
}


