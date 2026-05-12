const state = {
  activeTab: "overview",
  token: window.localStorage.getItem("deliveryOperatorToken") || "",
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

function showScreen(name) {
  Object.entries(screens).forEach(([key, element]) => {
    element.classList.toggle("active", key === name);
  });
}

function switchTab(name) {
  state.activeTab = name;
  tabButtons.forEach((button) => button.classList.toggle("active", button.dataset.tab === name));
  tabPanels.forEach((panel) => panel.classList.toggle("active", panel.dataset.panel === name));
}

function setToken(token) {
  state.token = token;
  if (token) {
    window.localStorage.setItem("deliveryOperatorToken", token);
  } else {
    window.localStorage.removeItem("deliveryOperatorToken");
  }
}

function roleLabel(role) {
  return {
    root: "Администратор",
    admin: "Администратор сервисов",
    auditor: "Инженер по промышленной безопасности",
  }[role] || role || "-";
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
  if (target) {
    target.textContent = message;
    target.classList.remove("hidden");
  }
}

function setManageMode() {
  const disabled = !userCanManage();
  ["register-button", "tls-enroll-button", "tls-renew-button", "cc-url", "cc-runtime-url", "service-id", "service-secret", "local-url", "settings-json", "test-decision", "test-reason-code", "test-reason-text", "test-include-image", "test-webhook-button", "test-email-button"].forEach((id) => {
    const element = document.querySelector(`#${id}`);
    if (element) element.disabled = disabled;
  });
}

function renderSessionState() {
  const target = document.querySelector("#session-state");
  const authTarget = document.querySelector("#auth-state");
  const content = state.user
    ? `
      <div class="kv-item"><strong>Пользователь</strong>${state.user.username}</div>
      <div class="kv-item"><strong>Роль</strong>${roleLabel(state.user.role)}</div>
      <div class="kv-item"><strong>Доступ к сервису</strong>${userCanManage() ? "manage" : "read-only"}</div>
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
    <div class="kv-item"><strong>Последняя проверка связи</strong>${data.last_connection_check_at || "-"}</div>
    <div class="kv-item"><strong>Последняя регистрация</strong>${data.last_registration_at || "-"}</div>
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
        <strong>${item.category}</strong>
        <span class="event-status ${item.status}">${item.status}</span>
      </div>
      <div>${item.message}</div>
      <div class="muted">${item.created_at}</div>
      <pre class="json-block">${JSON.stringify(item.details, null, 2)}</pre>
    `;
    history.appendChild(node);
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
    <div class="kv-item"><strong>TLS enrolled</strong>${data.tls_enrolled ? "yes" : "no"}</div>
    <div class="kv-item"><strong>TLS expires</strong>${data.tls_expires_at || "-"}</div>
    <div class="kv-item"><strong>Restart required</strong>${data.restart_required ? "yes" : "no"}</div>
    <div class="kv-item"><strong>Heartbeat Status</strong>${data.last_heartbeat_status || "-"}</div>
    <div class="kv-item"><strong>Last Heartbeat</strong>${data.last_heartbeat_at || "-"}</div>
    <div class="kv-item"><strong>Last Error</strong>${data.last_error || "-"}</div>
  `;
  document.querySelector("#effective-settings").textContent = JSON.stringify(data.settings, null, 2);
  document.querySelector("#cc-url").value = data.control_center_url || "";
  document.querySelector("#cc-runtime-url").value = data.control_center_runtime_url || "";
  document.querySelector("#service-id").value = data.service_id || "";
  document.querySelector("#local-url").value = data.local_url || "";
  document.querySelector("#settings-json").value = JSON.stringify(data.settings || {}, null, 2);

  const history = document.querySelector("#delivery-history");
  history.innerHTML = "";
  for (const item of data.history) {
    const node = document.createElement("article");
    node.className = "history-item";
    node.innerHTML = `
      <strong>${item.status}</strong>
      <div class="muted">${item.request_id} · ${item.created_at}</div>
      <pre class="json-block">${JSON.stringify(item.details, null, 2)}</pre>
    `;
    history.appendChild(node);
  }

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
    document.querySelector("#bootstrap-service-id").value = data.service_id || "delivery-01";
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
    const message = result.accepted
      ? `Настройки приняты, версия ${result.config_version}.`
      : `Настройки отклонены: ${result.reason || "unknown reason"}.`;
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

function deliveryTestPayload() {
  return {
    decision: document.querySelector("#test-decision").value.trim() || "deny-access",
    reason_code: document.querySelector("#test-reason-code").value.trim() || "ppe_missing",
    reason_text: document.querySelector("#test-reason-text").value.trim() || "PPE violation detected",
    include_sample_image: document.querySelector("#test-include-image").checked,
  };
}

async function runDeliveryTest(kind) {
  setFormMessage("#delivery-test-success", "#delivery-test-error", "");
  try {
    const data = await api(`/api/test/${kind}`, {
      method: "POST",
      body: JSON.stringify(deliveryTestPayload()),
    });
    const message = `Тест ${kind} выполнен успешно.`;
    document.querySelector("#delivery-test-result").textContent = JSON.stringify(data, null, 2);
    setFormMessage("#delivery-test-success", "#delivery-test-error", message, "success");
    showToast(message, "success");
    await loadDashboard();
    switchTab("deliveries");
  } catch (error) {
    document.querySelector("#delivery-test-result").textContent = "";
    setFormMessage("#delivery-test-success", "#delivery-test-error", error.message, "error");
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
  document.querySelector("#test-webhook-button").addEventListener("click", () => runDeliveryTest("webhook"));
  document.querySelector("#test-email-button").addEventListener("click", () => runDeliveryTest("email"));
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
