const state = {
  activeTab: "viewer",
  token: window.localStorage.getItem("viewerOperatorToken") || "",
  user: null,
  bootstrapConfigured: false,
};

const screens = {
  bootstrap: document.querySelector("#bootstrap-screen"),
  login: document.querySelector("#login-screen"),
  dashboard: document.querySelector("#dashboard-screen"),
};

const tabButtons = Array.from(document.querySelectorAll(".tab-button"));
const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));

function roleLabel(role) {
  return {
    root: "Администратор",
    admin: "Администратор сервисов",
    auditor: "Инженер по промышленной безопасности",
  }[role] || role || "-";
}

function showScreen(name) {
  Object.entries(screens).forEach(([key, element]) => element.classList.toggle("active", key === name));
}

function switchTab(name) {
  state.activeTab = name;
  tabButtons.forEach((button) => button.classList.toggle("active", button.dataset.tab === name));
  tabPanels.forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === name));
}

function setToken(token) {
  state.token = token;
  if (token) {
    window.localStorage.setItem("viewerOperatorToken", token);
  } else {
    window.localStorage.removeItem("viewerOperatorToken");
  }
}

function userCanManage() {
  if (!state.user) return false;
  if (state.user.role === "root") return true;
  const serviceId = document.querySelector("#service-id").value.trim();
  return state.user.access.some((entry) => entry.service_id === serviceId && entry.access_level === "manage");
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }
  const response = await fetch(path, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Request failed");
  }
  return data;
}

function showToast(message, kind = "success") {
  const stack = document.querySelector("#toast-stack");
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  node.textContent = message;
  stack.prepend(node);
  window.setTimeout(() => {
    node.classList.add("hidden");
    node.remove();
  }, 3200);
}

function setFormMessage(successId, errorId, message, kind = "success") {
  const successEl = document.querySelector(successId);
  const errorEl = document.querySelector(errorId);
  if (successEl) successEl.classList.add("hidden");
  if (errorEl) errorEl.classList.add("hidden");
  const target = kind === "success" ? successEl : errorEl;
  if (target && message) {
    target.textContent = message;
    target.classList.remove("hidden");
  }
}

function setManageMode() {
  const disabled = !userCanManage();
  ["register-button", "tls-enroll-button", "tls-renew-button", "cc-url", "cc-runtime-url", "service-id", "service-secret", "local-url", "settings-json"].forEach((id) => {
    const element = document.querySelector(`#${id}`);
    if (element) element.disabled = disabled;
  });
}

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function renderSessionState() {
  const target = document.querySelector("#session-state");
  const authTarget = document.querySelector("#auth-state");
  const content = state.user
    ? `
      <div class="kv-item"><strong>Пользователь</strong>${escapeHtml(state.user.username)}</div>
      <div class="kv-item"><strong>Роль</strong>${escapeHtml(roleLabel(state.user.role))}</div>
      <div class="kv-item"><strong>Доступ к сервису</strong>${userCanManage() ? "управление" : "просмотр"}</div>
    `
    : '<div class="kv-item">Оператор не аутентифицирован.</div>';
  target.innerHTML = content;
  authTarget.innerHTML = content;
}

function renderRegistrationState(data) {
  document.querySelector("#registration-state").innerHTML = `
    <div class="kv-item"><strong>Control Center</strong>${data.connection_status || "-"}</div>
    <div class="kv-item"><strong>Runtime URL</strong>${data.control_center_runtime_url || "-"}</div>
    <div class="kv-item"><strong>Runtime Registration</strong>${data.runtime_registration_status || "-"}</div>
    <div class="kv-item"><strong>Статус последней попытки</strong>${data.last_registration_status || "-"}</div>
    <div class="kv-item"><strong>Сообщение</strong>${data.last_registration_message || "-"}</div>
  `;
}

function renderTlsState(data) {
  document.querySelector("#tls-state").innerHTML = `
    <div class="kv-item"><strong>TLS enrolled</strong>${data.tls_enrolled ? "yes" : "no"}</div>
    <div class="kv-item"><strong>Runtime mTLS URL</strong>${data.control_center_runtime_url || "-"}</div>
    <div class="kv-item"><strong>Certificate serial</strong>${data.tls_serial_hex || "-"}</div>
    <div class="kv-item"><strong>Certificate expires</strong>${data.tls_expires_at || "-"}</div>
    <div class="kv-item"><strong>Restart required</strong>${data.restart_required ? "yes" : "no"}</div>
  `;
}

function renderEventHistory(events) {
  const history = document.querySelector("#event-history");
  history.innerHTML = "";
  if (!events.length) {
    history.innerHTML = '<div class="kv-item">Событий пока нет.</div>';
    return;
  }
  for (const item of events) {
    const node = document.createElement("article");
    node.className = "history-item";
    node.innerHTML = `
      <div class="event-head">
        <strong>${escapeHtml(item.category)}</strong>
        <span class="event-status ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>
      </div>
      <div>${escapeHtml(item.message)}</div>
      <div class="muted">${escapeHtml(item.created_at)}</div>
      <pre class="json-block">${escapeHtml(JSON.stringify(item.details, null, 2))}</pre>
    `;
    history.appendChild(node);
  }
}

function renderViewerRecords(records) {
  const target = document.querySelector("#viewer-records");
  target.innerHTML = "";
  if (!records.length) {
    target.innerHTML = '<section class="panel"><div class="kv-item">Очередь пока пустая.</div></section>';
    return;
  }
  for (const record of records) {
    const isDenied = record.decision === "deny-access" || record.decision === "error";
    const missing = record.missing_required.length ? record.missing_required.join(", ") : "нет";
    const img = record.annotated_image_base64
      ? `<img src="data:${record.annotated_image_media_type || "image/jpeg"};base64,${record.annotated_image_base64}" alt="inspection result" />`
      : '<div class="image-placeholder">Фото недоступно</div>';
    const node = document.createElement("article");
    node.className = `viewer-card ${isDenied ? "denied" : "permitted"}`;
    node.innerHTML = `
      <div class="viewer-image">${img}</div>
      <div class="viewer-body">
        <div class="viewer-head">
          <strong>${escapeHtml(record.decision_label)}</strong>
          <span class="result-badge ${isDenied ? "danger" : "ok"}">${isDenied ? "Нарушение" : "Допуск"}</span>
        </div>
        <div class="muted">${escapeHtml(record.inspection_completed_at || record.received_at)}</div>
        <div class="kv-list">
          <div class="kv-item"><strong>КПП</strong>${escapeHtml(record.checkpoint_service_id)}</div>
          <div class="kv-item"><strong>Недостающие СИЗ</strong>${escapeHtml(missing)}</div>
          <div class="kv-item"><strong>Причина</strong>${escapeHtml(record.reason_text || record.reason_code || "-")}</div>
          <div class="kv-item"><strong>Request ID</strong>${escapeHtml(record.request_id)}</div>
        </div>
      </div>
    `;
    target.appendChild(node);
  }
}

function renderState(data) {
  document.querySelector("#current-user").textContent = state.user ? `${state.user.username} · ${roleLabel(state.user.role)}` : "";
  document.querySelector("#overview-state").innerHTML = `
    <div class="kv-item"><strong>Service ID</strong>${data.service_id}</div>
    <div class="kv-item"><strong>Control Center</strong>${data.connection_status || "-"}</div>
    <div class="kv-item"><strong>Runtime Registration</strong>${data.runtime_registration_status || "-"}</div>
    <div class="kv-item"><strong>Registered</strong>${data.registered}</div>
    <div class="kv-item"><strong>Config Version</strong>${data.config_version}</div>
    <div class="kv-item"><strong>Runtime URL</strong>${data.control_center_runtime_url || "-"}</div>
    <div class="kv-item"><strong>Last Error</strong>${data.last_error || "-"}</div>
  `;
  document.querySelector("#effective-settings").textContent = JSON.stringify(data.settings, null, 2);
  document.querySelector("#cc-url").value = data.control_center_url || "";
  document.querySelector("#cc-runtime-url").value = data.control_center_runtime_url || "";
  document.querySelector("#service-id").value = data.service_id || "";
  document.querySelector("#local-url").value = data.local_url || "";
  document.querySelector("#settings-json").value = JSON.stringify(data.settings || {}, null, 2);
  renderViewerRecords(data.records || []);
  renderSessionState();
  renderRegistrationState(data);
  renderTlsState(data);
  renderEventHistory(data.events || []);
  setManageMode();
}

async function loadDashboard() {
  const data = await api("/api/state");
  renderState(data);
  showScreen("dashboard");
}

async function loadBootstrapState() {
  const data = await api("/api/bootstrap");
  state.bootstrapConfigured = data.configured;
  if (!data.configured) {
    document.querySelector("#bootstrap-cc-url").value = data.control_center_url || "";
    document.querySelector("#bootstrap-runtime-url").value = data.control_center_runtime_url || "";
    document.querySelector("#bootstrap-service-id").value = data.service_id || "viewer-01";
    document.querySelector("#bootstrap-local-url").value = data.local_url || "";
    showScreen("bootstrap");
    return false;
  }
  return true;
}

async function saveBootstrap(event) {
  event.preventDefault();
  setFormMessage("#bootstrap-success", "#bootstrap-error", "");
  try {
    const result = await api("/api/bootstrap", {
      method: "POST",
      body: JSON.stringify({
        control_center_url: document.querySelector("#bootstrap-cc-url").value.trim(),
        control_center_runtime_url: document.querySelector("#bootstrap-runtime-url").value.trim() || null,
        service_id: document.querySelector("#bootstrap-service-id").value.trim(),
        service_secret: document.querySelector("#bootstrap-service-secret").value,
        local_url: document.querySelector("#bootstrap-local-url").value.trim(),
      }),
    });
    state.bootstrapConfigured = true;
    const message = result.message || "Bootstrap saved";
    setFormMessage("#bootstrap-success", "#bootstrap-error", message, "success");
    document.querySelector("#login-info").textContent = message;
    document.querySelector("#login-info").classList.remove("hidden");
    showToast(message, "success");
    showScreen("login");
  } catch (error) {
    setFormMessage("#bootstrap-success", "#bootstrap-error", error.message, "error");
    showToast(error.message, "error");
  }
}

async function login(event) {
  event.preventDefault();
  setFormMessage("#login-info", "#login-error", "");
  try {
    const data = await api("/api/session/login", {
      method: "POST",
      body: JSON.stringify({
        username: document.querySelector("#login-username").value.trim(),
        password: document.querySelector("#login-password").value,
      }),
    });
    setToken(data.access_token);
    state.user = data.user;
    setFormMessage("#login-info", "#login-error", `Оператор ${data.user.username} успешно аутентифицирован.`, "success");
    showToast(`Вход выполнен: ${data.user.username}`, "success");
    await loadDashboard();
  } catch (error) {
    setFormMessage("#login-info", "#login-error", error.message, "error");
    showToast(error.message, "error");
  }
}

function logout() {
  setToken("");
  state.user = null;
  renderSessionState();
  showToast("Сессия завершена", "success");
  showScreen(state.bootstrapConfigured ? "login" : "bootstrap");
}

async function saveControlCenter(event) {
  event.preventDefault();
  setFormMessage("#control-center-success", "#control-center-error", "");
  try {
    await api("/api/control-center", {
      method: "POST",
      body: JSON.stringify({
        control_center_url: document.querySelector("#cc-url").value.trim(),
        control_center_runtime_url: document.querySelector("#cc-runtime-url").value.trim() || null,
        service_id: document.querySelector("#service-id").value.trim(),
        service_secret: document.querySelector("#service-secret").value,
        local_url: document.querySelector("#local-url").value.trim(),
      }),
    });
    const message = "Настройки подключения сохранены. Сервис повторит регистрацию автоматически.";
    setFormMessage("#control-center-success", "#control-center-error", message, "success");
    showToast(message, "success");
    await loadDashboard();
    switchTab("registration");
  } catch (error) {
    setFormMessage("#control-center-success", "#control-center-error", error.message, "error");
    showToast(error.message, "error");
  }
}

async function registerRuntime() {
  setFormMessage("#control-center-success", "#control-center-error", "");
  try {
    const result = await api("/api/register", { method: "POST" });
    const message = result.approved ? "Регистрация сервиса подтверждена." : "Регистрация не подтверждена.";
    setFormMessage("#control-center-success", "#control-center-error", message, "success");
    showToast(message, "success");
    await loadDashboard();
    switchTab("registration");
  } catch (error) {
    setFormMessage("#control-center-success", "#control-center-error", error.message, "error");
    showToast(error.message, "error");
  }
}

async function proposeSettings(event) {
  event.preventDefault();
  setFormMessage("#settings-success", "#settings-error", "");
  try {
    const result = await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({ settings: JSON.parse(document.querySelector("#settings-json").value || "{}") }),
    });
    const message = result.accepted ? `Настройки приняты, версия ${result.config_version}.` : `Настройки отклонены: ${result.reason || "unknown reason"}.`;
    setFormMessage("#settings-success", "#settings-error", message, result.accepted ? "success" : "error");
    showToast(message, result.accepted ? "success" : "error");
    await loadDashboard();
    switchTab("settings");
  } catch (error) {
    setFormMessage("#settings-success", "#settings-error", error.message, "error");
    showToast(error.message, "error");
  }
}

async function enrollTls() {
  setFormMessage("#tls-success", "#tls-error", "");
  try {
    const result = await api("/api/tls/enroll", { method: "POST" });
    const message = `Сертификат выпущен: ${result.serial_hex}, истекает ${result.expires_at}. Для HTTPS UI перезапустите сервис.`;
    setFormMessage("#tls-success", "#tls-error", message, "success");
    showToast(message, "success");
    await loadDashboard();
    switchTab("registration");
  } catch (error) {
    setFormMessage("#tls-success", "#tls-error", error.message, "error");
    showToast(error.message, "error");
  }
}

async function renewTls() {
  setFormMessage("#tls-success", "#tls-error", "");
  try {
    const result = await api("/api/tls/renew", { method: "POST" });
    const message = `Сертификат перевыпущен: ${result.serial_hex}, истекает ${result.expires_at}. Для HTTPS UI перезапустите сервис.`;
    setFormMessage("#tls-success", "#tls-error", message, "success");
    showToast(message, "success");
    await loadDashboard();
    switchTab("registration");
  } catch (error) {
    setFormMessage("#tls-success", "#tls-error", error.message, "error");
    showToast(error.message, "error");
  }
}

function bindEvents() {
  tabButtons.forEach((button) => button.addEventListener("click", () => switchTab(button.dataset.tab)));
  document.querySelector("#bootstrap-form").addEventListener("submit", saveBootstrap);
  document.querySelector("#login-form").addEventListener("submit", login);
  document.querySelector("#refresh-button").addEventListener("click", () => loadDashboard().catch(logout));
  document.querySelector("#register-button").addEventListener("click", registerRuntime);
  document.querySelector("#logout-button").addEventListener("click", logout);
  document.querySelector("#control-center-form").addEventListener("submit", saveControlCenter);
  document.querySelector("#settings-form").addEventListener("submit", proposeSettings);
  document.querySelector("#tls-enroll-button").addEventListener("click", enrollTls);
  document.querySelector("#tls-renew-button").addEventListener("click", renewTls);
}

async function bootstrap() {
  bindEvents();
  const configured = await loadBootstrapState();
  if (!configured) return;
  if (!state.token) {
    showScreen("login");
    return;
  }
  try {
    const session = await api("/api/session/me");
    state.user = session.user;
    await loadDashboard();
  } catch {
    logout();
  }
}

bootstrap();
