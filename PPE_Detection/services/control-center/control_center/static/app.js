const state = {
  token: window.localStorage.getItem("controlCenterToken") || "",
  user: null,
  services: [],
  routes: [],
  users: [],
  audit: [],
  runtimeEvents: [],
  auditFilters: { target_id: "", action: "" },
  runtimeFilters: { request_id: "", source_service_id: "", severity: "" },
  activeTab: "overview",
};

const loginScreen = document.querySelector("#login-screen");
const dashboardScreen = document.querySelector("#dashboard-screen");
const currentUserEl = document.querySelector("#current-user");
const profileSummaryEl = document.querySelector("#profile-summary");
const serviceListEl = document.querySelector("#service-list");
const routeListEl = document.querySelector("#route-list");
const userListEl = document.querySelector("#user-list");
const auditListEl = document.querySelector("#audit-list");
const runtimeEventListEl = document.querySelector("#runtime-event-list");
const rootUserPanel = document.querySelector("#root-user-panel");
const rootUserCreatePanel = document.querySelector("#root-user-create-panel");
const rootServicePanel = document.querySelector("#root-service-panel");
const rootGrantPanel = document.querySelector("#root-grant-panel");
const rootRoutePanel = document.querySelector("#root-route-panel");
const serviceModal = document.querySelector("#service-modal");
const userModal = document.querySelector("#user-modal");
const routeModal = document.querySelector("#route-modal");
const deleteServiceButton = document.querySelector("#delete-service-button");
const deleteUserButton = document.querySelector("#delete-user-button");
const deleteRouteButton = document.querySelector("#delete-route-button");
const closeServiceModalButton = document.querySelector("#close-service-modal");
const closeUserModalButton = document.querySelector("#close-user-modal");
const closeRouteModalButton = document.querySelector("#close-route-modal");
const tabButtons = Array.from(document.querySelectorAll(".tab-button"));
const tabPanels = Array.from(document.querySelectorAll(".tab-panel"));

function formValue(id) {
  return document.querySelector(`#${id}`).value.trim();
}

function csvValue(id) {
  return formValue(id).split(",").map((item) => item.trim()).filter(Boolean);
}

function boolValue(id) {
  return document.querySelector(`#${id}`).value === "true";
}

function numberValue(id, fallback = 0) {
  const value = Number(formValue(id));
  return Number.isFinite(value) ? value : fallback;
}

function textValue(value) {
  return value == null ? "" : String(value);
}

function roleLabel(role) {
  return {
    root: "Администратор",
    admin: "Администратор сервисов",
    auditor: "Инженер по промышленной безопасности",
  }[role] || role || "-";
}

const SERVICE_TEMPLATES = {
  checkpoint: [
    {
      id: "chemical-shop",
      name: "Химический цех",
      settings: {
        required_ppe: ["mask", "safety_vest"],
      },
    },
    {
      id: "mine",
      name: "Шахта",
      settings: {
        required_ppe: ["hardhat", "safety_vest"],
      },
    },
  ],
};

function serviceOptions(type, selected = "", includeEmpty = true) {
  const options = includeEmpty ? ['<option value="">-</option>'] : [];
  const services = state.services.filter((entry) => entry.service_type === type);
  if (selected && !services.some((service) => service.service_id === selected)) {
    const value = escapeHtml(selected);
    options.push(`<option value="${value}" selected>${value}</option>`);
  }
  for (const service of services) {
    const value = escapeHtml(service.service_id);
    options.push(`<option value="${value}" ${service.service_id === selected ? "selected" : ""}>${value}</option>`);
  }
  return options.join("");
}

function parseDatabaseDsn(dsn = "") {
  if (!dsn) {
    return { host: "", port: "", database: "", username: "", password: "" };
  }
  try {
    const url = new URL(dsn);
    return {
      host: url.hostname || "",
      port: url.port || "",
      database: decodeURIComponent(url.pathname.replace(/^\//, "")),
      username: decodeURIComponent(url.username || ""),
      password: decodeURIComponent(url.password || ""),
    };
  } catch {
    return { host: "", port: "", database: "", username: "", password: "" };
  }
}

function buildDatabaseDsn(type, host, port, database, username, password) {
  if (!host || !database) {
    return "";
  }
  const scheme = type === "mysql" ? "mysql" : "postgresql";
  const auth = username ? `${encodeURIComponent(username)}${password ? `:${encodeURIComponent(password)}` : ""}@` : "";
  const portPart = port ? `:${port}` : "";
  return `${scheme}://${auth}${host}${portPart}/${encodeURIComponent(database)}`;
}

function setSettingsEditorMode(mode) {
  document.querySelector("#service-settings-form").classList.toggle("hidden", mode !== "form");
  document.querySelector("#service-settings-template-wrap").classList.toggle("hidden", mode !== "template");
  document.querySelector("#service-settings-json-wrap").classList.toggle("hidden", mode !== "json");
}

function renderTemplateOptions(service) {
  const select = document.querySelector("#service-settings-template");
  const templates = SERVICE_TEMPLATES[service.service_type] || [];
  if (!templates.length) {
    select.innerHTML = '<option value="">Нет шаблонов</option>';
    select.disabled = true;
    return;
  }
  select.disabled = false;
  select.innerHTML = templates.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join("");
}

function settingsFromSelectedTemplate(service) {
  const templateId = formValue("service-settings-template");
  const template = (SERVICE_TEMPLATES[service.service_type] || []).find((item) => item.id === templateId);
  if (!template) {
    throw new Error("Для этого сервиса нет выбранного шаблона");
  }
  return {
    ...(service.settings || {}),
    ...template.settings,
  };
}

function renderServiceSettingsForm(service) {
  const settings = service.settings || {};
  const target = document.querySelector("#service-settings-form");
  if (service.service_type === "worker") {
    const p = settings.processing || {};
    target.innerHTML = `
      <fieldset><legend>Worker model</legend>
        <label><span>Model</span><select id="sf-worker-model">
          <option value="hansung-yolov8-ppe">Hansung PPE</option>
          <option value="hexmon-vyra-yolo-ppe">Hexmon Vyra PPE</option>
        </select></label>
        <label><span>Confidence</span><input id="sf-worker-confidence" type="number" min="0" max="1" step="0.01" value="${p.confidence_threshold == null ? 0.5 : p.confidence_threshold}" /></label>
        <label><span>Image size</span><input id="sf-worker-image-size" type="number" min="64" step="32" value="${p.image_size || 640}" /></label>
        <label><span>Max local queue</span><input id="sf-max-local-queue" type="number" min="1" value="${settings.max_local_queue_size || 10}" /></label>
      </fieldset>`;
    document.querySelector("#sf-worker-model").value = p.model_name || "hansung-yolov8-ppe";
  } else if (service.service_type === "storage") {
    const b = settings.backend || {};
    target.innerHTML = `
      <fieldset><legend>Storage backend</legend>
        <label><span>Backend</span><select id="sf-storage-type"><option value="sqlite">SQLite</option><option value="postgres">PostgreSQL</option><option value="mysql">MySQL</option></select></label>
        <label><span>DSN</span><input id="sf-storage-dsn" type="text" value="${escapeHtml(b.dsn || "")}" placeholder="postgresql://user:pass@host:5432/db или mysql://user:pass@host:3306/db" /></label>
        <label><span>SQLite path</span><input id="sf-storage-sqlite" type="text" value="${escapeHtml(b.sqlite_path || "/data/storage_records.db")}" /></label>
        <label><span>Table</span><input id="sf-storage-table" type="text" value="${escapeHtml(b.table_name || "inspection_results")}" /></label>
        <label><span>Write timeout</span><input id="sf-storage-timeout" type="number" min="1" value="${settings.write_timeout_sec || 10}" /></label>
      </fieldset>`;
    document.querySelector("#sf-storage-type").value = b.type || "sqlite";
  } else if (service.service_type === "checkpoint") {
    target.innerHTML = `
      <fieldset><legend>Checkpoint</legend>
        <label><span>Image source</span><select id="sf-checkpoint-source"><option value="upload">Upload</option><option value="camera">Camera</option><option value="both">Both</option></select></label>
        <label><span>Required PPE</span><input id="sf-checkpoint-ppe" type="text" value="${escapeHtml((settings.required_ppe || []).join(", "))}" /></label>
        <label><span>Max image bytes</span><input id="sf-checkpoint-max" type="number" min="1" value="${settings.max_image_size_bytes || 10000000}" /></label>
      </fieldset>`;
    document.querySelector("#sf-checkpoint-source").value = settings.image_source_mode || "upload";
  } else if (service.service_type === "delivery_service") {
    const webhook = (settings.channels || {}).webhook || {};
    const email = (settings.channels || {}).email || {};
    target.innerHTML = `
      <fieldset><legend>Delivery</legend>
        <label><span>Webhook URL</span><input id="sf-delivery-webhook-url" type="text" value="${escapeHtml(webhook.url || "")}" /></label>
        <label><span>Email mode</span><select id="sf-delivery-email-mode"><option value="log">log</option><option value="smtp">smtp</option></select></label>
        <label><span>Email recipients</span><input id="sf-delivery-email-to" type="text" value="${escapeHtml((email.to || []).join(", "))}" /></label>
        <label><span>Send timeout</span><input id="sf-delivery-timeout" type="number" min="1" value="${settings.send_timeout_sec || 10}" /></label>
      </fieldset>`;
    document.querySelector("#sf-delivery-email-mode").value = email.mode || "log";
  } else if (service.service_type === "control_center") {
    target.innerHTML = `
      <fieldset><legend>Control Center defaults</legend>
        <label><span>Default worker</span><input id="sf-cc-worker" type="text" value="${escapeHtml(settings.default_worker_service_id || "")}" /></label>
        <label><span>Storage services</span><input id="sf-cc-storage" type="text" value="${escapeHtml((settings.default_storage_service_ids || []).join(", "))}" /></label>
        <label><span>Delivery services</span><input id="sf-cc-delivery" type="text" value="${escapeHtml((settings.default_delivery_service_ids || []).join(", "))}" /></label>
        <label><span>Viewer services</span><input id="sf-cc-viewer" type="text" value="${escapeHtml((settings.default_viewer_service_ids || []).join(", "))}" /></label>
      </fieldset>`;
  } else {
    target.innerHTML = '<div class="muted">Для этого типа доступен экспертный JSON.</div>';
  }
}

function settingsFromForm(serviceType, current) {
  const settings = JSON.parse(JSON.stringify(current || {}));
  if (serviceType === "worker") {
    const model = formValue("sf-worker-model");
    const isHexmon = model === "hexmon-vyra-yolo-ppe";
    const modelConfig = {
      model_name: model,
      model_source: "huggingface",
      model_repo: isHexmon ? "Hexmon/vyra-yolo-ppe-detection" : "Hansung-Cho/yolov8-ppe-detection",
      model_file: "best.pt",
      class_map: isHexmon
        ? {
            "Hardhat": "hardhat",
            "NO-Hardhat": "no_hardhat",
            "Mask": "mask",
            "NO-Mask": "no_mask",
            "Safety Vest": "safety_vest",
            "NO-Safety Vest": "no_safety_vest",
            "Gloves": "gloves",
            "NO-Gloves": "no_gloves",
            "Goggles": "goggles",
            "NO-Goggles": "no_goggles",
            "Person": "person",
            "Fall-Detected": "fall_detected",
            "Ladder": "ladder",
            "Safety Cone": "safety_cone",
          }
        : {
            "Hardhat": "hardhat",
            "No-Hardhat": "no_hardhat",
            "Mask": "mask",
            "No-Mask": "no_mask",
            "Safety Vest": "safety_vest",
            "NO-Safety Vest": "no_safety_vest",
            "No-Safety Vest": "no_safety_vest",
            "Person": "person",
          },
      violation_classes: isHexmon
        ? ["no_hardhat", "no_mask", "no_safety_vest", "no_gloves", "no_goggles"]
        : ["no_hardhat", "no_mask", "no_safety_vest"],
    };
    settings.max_local_queue_size = Number(formValue("sf-max-local-queue") || 10);
    settings.processing = { ...(settings.processing || {}), ...modelConfig, confidence_threshold: Number(formValue("sf-worker-confidence") || 0.5), image_size: Number(formValue("sf-worker-image-size") || 640), mode: "ultralytics" };
  } else if (serviceType === "storage") {
    settings.write_timeout_sec = Number(formValue("sf-storage-timeout") || 10);
    settings.backend = { ...(settings.backend || {}), type: formValue("sf-storage-type"), dsn: formValue("sf-storage-dsn"), sqlite_path: formValue("sf-storage-sqlite"), table_name: formValue("sf-storage-table"), create_table: true, connect_timeout_sec: 10 };
  } else if (serviceType === "checkpoint") {
    settings.image_source_mode = formValue("sf-checkpoint-source");
    settings.required_ppe = csvValue("sf-checkpoint-ppe");
    settings.max_image_size_bytes = Number(formValue("sf-checkpoint-max") || 10000000);
  } else if (serviceType === "delivery_service") {
    settings.send_timeout_sec = Number(formValue("sf-delivery-timeout") || 10);
    settings.channels = settings.channels || {};
    settings.channels.webhook = { ...(settings.channels.webhook || {}), url: formValue("sf-delivery-webhook-url") };
    settings.channels.email = { ...(settings.channels.email || {}), mode: formValue("sf-delivery-email-mode"), to: csvValue("sf-delivery-email-to") };
  } else if (serviceType === "control_center") {
    settings.default_worker_service_id = formValue("sf-cc-worker");
    settings.default_storage_service_ids = csvValue("sf-cc-storage");
    settings.default_delivery_service_ids = csvValue("sf-cc-delivery");
    settings.default_viewer_service_ids = csvValue("sf-cc-viewer");
  }
  return settings;
}

function renderServiceSettingsForm(service) {
  const settings = service.settings || {};
  const target = document.querySelector("#service-settings-form");
  if (service.service_type === "worker") {
    const p = settings.processing || {};
    target.innerHTML = `
      <fieldset><legend>Worker model</legend>
        <div class="settings-grid">
          <label><span>Model</span><select id="sf-worker-model"><option value="hansung-yolov8-ppe">Hansung PPE</option><option value="hexmon-vyra-yolo-ppe">Hexmon Vyra PPE</option></select></label>
          <label><span>Confidence</span><input id="sf-worker-confidence" type="number" min="0" max="1" step="0.01" value="${p.confidence_threshold == null ? 0.5 : p.confidence_threshold}" /></label>
          <label><span>Image size</span><input id="sf-worker-image-size" type="number" min="64" step="32" value="${p.image_size || 640}" /></label>
          <label><span>Max local queue</span><input id="sf-max-local-queue" type="number" min="1" value="${settings.max_local_queue_size || 10}" /></label>
          <label><span>Heartbeat interval, sec</span><input id="sf-worker-heartbeat" type="number" min="2" value="${settings.heartbeat_interval_sec || 10}" /></label>
        </div>
      </fieldset>`;
    document.querySelector("#sf-worker-model").value = p.model_name || "hansung-yolov8-ppe";
  } else if (service.service_type === "storage") {
    const b = settings.backend || {};
    const parsed = parseDatabaseDsn(b.dsn || "");
    target.innerHTML = `
      <fieldset><legend>Storage backend</legend>
        <div class="settings-grid">
          <label><span>Backend</span><select id="sf-storage-type"><option value="sqlite">SQLite</option><option value="postgres">PostgreSQL</option><option value="mysql">MySQL</option></select></label>
          <label><span>Table</span><input id="sf-storage-table" type="text" value="${escapeHtml(textValue(b.table_name || "inspection_results"))}" /></label>
          <label class="span-all"><span>SQLite path</span><input id="sf-storage-sqlite" type="text" value="${escapeHtml(textValue(b.sqlite_path || "/data/storage_records.db"))}" /></label>
          <label><span>DB host</span><input id="sf-storage-host" type="text" value="${escapeHtml(parsed.host)}" placeholder="postgres-storage" /></label>
          <label><span>DB port</span><input id="sf-storage-port" type="number" min="1" value="${escapeHtml(parsed.port)}" placeholder="5432" /></label>
          <label><span>Database</span><input id="sf-storage-dbname" type="text" value="${escapeHtml(parsed.database)}" placeholder="ppe_storage" /></label>
          <label><span>User</span><input id="sf-storage-user" type="text" value="${escapeHtml(parsed.username)}" placeholder="ppe" /></label>
          <label><span>Password</span><input id="sf-storage-password" type="password" value="${escapeHtml(parsed.password)}" /></label>
          <label><span>Connect timeout, sec</span><input id="sf-storage-connect-timeout" type="number" min="1" value="${b.connect_timeout_sec || 10}" /></label>
          <label><span>Write timeout, sec</span><input id="sf-storage-timeout" type="number" min="1" value="${settings.write_timeout_sec || 10}" /></label>
          <label><span>Create table</span><select id="sf-storage-create-table"><option value="true">yes</option><option value="false">no</option></select></label>
          <label><span>Heartbeat interval, sec</span><input id="sf-storage-heartbeat" type="number" min="2" value="${settings.heartbeat_interval_sec || 10}" /></label>
          <label><span>Max local queue</span><input id="sf-storage-queue" type="number" min="1" value="${settings.max_local_queue_size || 20}" /></label>
        </div>
      </fieldset>`;
    document.querySelector("#sf-storage-type").value = b.type || "sqlite";
    document.querySelector("#sf-storage-create-table").value = String(b.create_table !== false);
  } else if (service.service_type === "checkpoint") {
    target.innerHTML = `
      <fieldset><legend>Checkpoint</legend>
        <div class="settings-grid">
          <label><span>Image source</span><select id="sf-checkpoint-source"><option value="upload">Upload</option><option value="camera">Camera</option><option value="both">Both</option></select></label>
          <label><span>Inspection timeout, sec</span><input id="sf-checkpoint-timeout" type="number" min="1" value="${settings.inspection_timeout_sec || 10}" /></label>
          <label><span>Required PPE</span><input id="sf-checkpoint-ppe" type="text" value="${escapeHtml((settings.required_ppe || []).join(", "))}" /></label>
          <label><span>Allowed MIME types</span><input id="sf-checkpoint-mime" type="text" value="${escapeHtml((settings.allowed_mime_types || []).join(", "))}" /></label>
          <label><span>Max image bytes</span><input id="sf-checkpoint-max" type="number" min="1" value="${settings.max_image_size_bytes || 10000000}" /></label>
          <label><span>Retry count</span><input id="sf-checkpoint-retry-count" type="number" min="0" value="${settings.request_retry_count || 0}" /></label>
          <label><span>Retry delay, ms</span><input id="sf-checkpoint-retry-delay" type="number" min="0" value="${settings.request_retry_delay_ms || 250}" /></label>
          <label><span>Heartbeat interval, sec</span><input id="sf-checkpoint-heartbeat" type="number" min="2" value="${settings.heartbeat_interval_sec || 10}" /></label>
        </div>
      </fieldset>`;
    document.querySelector("#sf-checkpoint-source").value = settings.image_source_mode || "upload";
  } else if (service.service_type === "delivery_service") {
    const webhook = (settings.channels || {}).webhook || {};
    const email = (settings.channels || {}).email || {};
    target.innerHTML = `
      <fieldset><legend>Delivery</legend>
        <div class="settings-grid">
          <label><span>Webhook enabled</span><select id="sf-delivery-webhook-enabled"><option value="true">yes</option><option value="false">no</option></select></label>
          <label><span>Webhook method</span><select id="sf-delivery-webhook-method"><option value="POST">POST</option><option value="PUT">PUT</option><option value="PATCH">PATCH</option></select></label>
          <label class="span-all"><span>Webhook URL</span><input id="sf-delivery-webhook-url" type="text" value="${escapeHtml(textValue(webhook.url))}" /></label>
          <label><span>Signature header</span><input id="sf-delivery-webhook-secret-header" type="text" value="${escapeHtml(textValue(webhook.secret_header || "X-PPE-Signature"))}" /></label>
          <label><span>Signature secret</span><input id="sf-delivery-webhook-secret" type="password" value="${escapeHtml(textValue(webhook.secret))}" /></label>
          <label><span>Email enabled</span><select id="sf-delivery-email-enabled"><option value="false">no</option><option value="true">yes</option></select></label>
          <label><span>Email mode</span><select id="sf-delivery-email-mode"><option value="log">log</option><option value="smtp">smtp</option></select></label>
          <label><span>SMTP host</span><input id="sf-delivery-smtp-host" type="text" value="${escapeHtml(textValue(email.smtp_host))}" /></label>
          <label><span>SMTP port</span><input id="sf-delivery-smtp-port" type="number" min="1" value="${email.smtp_port || 587}" /></label>
          <label><span>SMTP TLS</span><select id="sf-delivery-smtp-tls"><option value="true">yes</option><option value="false">no</option></select></label>
          <label><span>SMTP username</span><input id="sf-delivery-smtp-user" type="text" value="${escapeHtml(textValue(email.username))}" /></label>
          <label><span>SMTP password</span><input id="sf-delivery-smtp-password" type="password" value="${escapeHtml(textValue(email.password))}" /></label>
          <label><span>From</span><input id="sf-delivery-email-from" type="text" value="${escapeHtml(textValue(email.from))}" /></label>
          <label><span>Recipients</span><input id="sf-delivery-email-to" type="text" value="${escapeHtml((email.to || []).join(", "))}" /></label>
          <label class="span-all"><span>Subject template</span><input id="sf-delivery-subject" type="text" value="${escapeHtml(textValue(email.subject_template || "PPE inspection: {decision}"))}" /></label>
          <label><span>Send timeout, sec</span><input id="sf-delivery-timeout" type="number" min="1" value="${settings.send_timeout_sec || 10}" /></label>
          <label><span>Heartbeat interval, sec</span><input id="sf-delivery-heartbeat" type="number" min="2" value="${settings.heartbeat_interval_sec || 10}" /></label>
          <label><span>Max local queue</span><input id="sf-delivery-queue" type="number" min="1" value="${settings.max_local_queue_size || 20}" /></label>
        </div>
      </fieldset>`;
    document.querySelector("#sf-delivery-webhook-enabled").value = String(webhook.enabled !== false);
    document.querySelector("#sf-delivery-webhook-method").value = webhook.method || "POST";
    document.querySelector("#sf-delivery-email-enabled").value = String(email.enabled === true);
    document.querySelector("#sf-delivery-email-mode").value = email.mode || "log";
    document.querySelector("#sf-delivery-smtp-tls").value = String(email.smtp_tls !== false);
  } else if (service.service_type === "viewer") {
    target.innerHTML = `
      <fieldset><legend>Viewer</legend>
        <div class="settings-grid">
          <label><span>Heartbeat interval, sec</span><input id="sf-viewer-heartbeat" type="number" min="2" value="${settings.heartbeat_interval_sec || 10}" /></label>
          <label><span>Max records</span><input id="sf-viewer-queue" type="number" min="1" value="${settings.max_local_queue_size || 200}" /></label>
        </div>
      </fieldset>`;
  } else if (service.service_type === "control_center") {
    target.innerHTML = `
      <fieldset><legend>Control Center defaults</legend>
        <div class="settings-grid">
          <label><span>Default worker</span><select id="sf-cc-worker">${serviceOptions("worker", settings.default_worker_service_id || "")}</select></label>
          <label><span>Allow default route</span><select id="sf-cc-allow-default"><option value="false">no</option><option value="true">yes</option></select></label>
          <label><span>Default storage services</span><input id="sf-cc-storage" type="text" value="${escapeHtml((settings.default_storage_service_ids || []).join(", "))}" /></label>
          <label><span>Default delivery services</span><input id="sf-cc-delivery" type="text" value="${escapeHtml((settings.default_delivery_service_ids || []).join(", "))}" /></label>
          <label><span>Default viewer services</span><input id="sf-cc-viewer" type="text" value="${escapeHtml((settings.default_viewer_service_ids || []).join(", "))}" /></label>
          <label><span>Worker result timeout, sec</span><input id="sf-cc-worker-timeout" type="number" min="1" value="${settings.worker_result_timeout_sec || 10}" /></label>
          <label><span>Delivery retry limit</span><input id="sf-cc-retry-limit" type="number" min="0" value="${settings.delivery_retry_limit || 5}" /></label>
          <label><span>Delivery retry delay, sec</span><input id="sf-cc-retry-delay" type="number" min="0" value="${settings.delivery_retry_delay_sec || 5}" /></label>
          <label><span>Certificate TTL, hours</span><input id="sf-cc-cert-ttl" type="number" min="1" value="${settings.service_certificate_ttl_hours || 24}" /></label>
        </div>
      </fieldset>`;
    document.querySelector("#sf-cc-allow-default").value = String(settings.allow_default_route === true);
  } else {
    target.innerHTML = '<div class="muted">Use expert JSON for this service type.</div>';
  }
}

function settingsFromForm(serviceType, current) {
  const settings = JSON.parse(JSON.stringify(current || {}));
  if (serviceType === "worker") {
    const model = formValue("sf-worker-model");
    const isHexmon = model === "hexmon-vyra-yolo-ppe";
    const modelConfig = {
      model_name: model,
      model_source: "huggingface",
      model_repo: isHexmon ? "Hexmon/vyra-yolo-ppe-detection" : "Hansung-Cho/yolov8-ppe-detection",
      model_file: "best.pt",
      class_map: isHexmon
        ? { "Hardhat": "hardhat", "NO-Hardhat": "no_hardhat", "Mask": "mask", "NO-Mask": "no_mask", "Safety Vest": "safety_vest", "NO-Safety Vest": "no_safety_vest", "Gloves": "gloves", "NO-Gloves": "no_gloves", "Goggles": "goggles", "NO-Goggles": "no_goggles", "Person": "person", "Fall-Detected": "fall_detected", "Ladder": "ladder", "Safety Cone": "safety_cone" }
        : { "Hardhat": "hardhat", "No-Hardhat": "no_hardhat", "Mask": "mask", "No-Mask": "no_mask", "Safety Vest": "safety_vest", "NO-Safety Vest": "no_safety_vest", "No-Safety Vest": "no_safety_vest", "Person": "person" },
      violation_classes: isHexmon ? ["no_hardhat", "no_mask", "no_safety_vest", "no_gloves", "no_goggles"] : ["no_hardhat", "no_mask", "no_safety_vest"],
    };
    settings.heartbeat_interval_sec = numberValue("sf-worker-heartbeat", 10);
    settings.max_local_queue_size = numberValue("sf-max-local-queue", 10);
    settings.processing = { ...(settings.processing || {}), ...modelConfig, confidence_threshold: numberValue("sf-worker-confidence", 0.5), image_size: numberValue("sf-worker-image-size", 640), mode: "ultralytics" };
  } else if (serviceType === "storage") {
    const backendType = formValue("sf-storage-type");
    settings.heartbeat_interval_sec = numberValue("sf-storage-heartbeat", 10);
    settings.write_timeout_sec = numberValue("sf-storage-timeout", 10);
    settings.max_local_queue_size = numberValue("sf-storage-queue", 20);
    settings.accepted_target_kinds = ["database"];
    settings.backend = {
      ...(settings.backend || {}),
      type: backendType,
      sqlite_path: formValue("sf-storage-sqlite"),
      dsn: backendType === "sqlite" ? "" : buildDatabaseDsn(backendType, formValue("sf-storage-host"), formValue("sf-storage-port"), formValue("sf-storage-dbname"), formValue("sf-storage-user"), formValue("sf-storage-password")),
      table_name: formValue("sf-storage-table") || "inspection_results",
      create_table: boolValue("sf-storage-create-table"),
      connect_timeout_sec: numberValue("sf-storage-connect-timeout", 10),
    };
  } else if (serviceType === "checkpoint") {
    settings.heartbeat_interval_sec = numberValue("sf-checkpoint-heartbeat", 10);
    settings.inspection_timeout_sec = numberValue("sf-checkpoint-timeout", 10);
    settings.request_retry_count = numberValue("sf-checkpoint-retry-count", 0);
    settings.request_retry_delay_ms = numberValue("sf-checkpoint-retry-delay", 250);
    settings.max_image_size_bytes = numberValue("sf-checkpoint-max", 10000000);
    settings.allowed_mime_types = csvValue("sf-checkpoint-mime");
    settings.image_source_mode = formValue("sf-checkpoint-source");
    settings.required_ppe = csvValue("sf-checkpoint-ppe");
  } else if (serviceType === "delivery_service") {
    settings.heartbeat_interval_sec = numberValue("sf-delivery-heartbeat", 10);
    settings.send_timeout_sec = numberValue("sf-delivery-timeout", 10);
    settings.max_local_queue_size = numberValue("sf-delivery-queue", 20);
    settings.accepted_target_kinds = ["webhook", "email"];
    settings.channels = settings.channels || {};
    settings.channels.webhook = { ...(settings.channels.webhook || {}), enabled: boolValue("sf-delivery-webhook-enabled"), url: formValue("sf-delivery-webhook-url"), method: formValue("sf-delivery-webhook-method"), headers: (settings.channels.webhook || {}).headers || {}, secret_header: formValue("sf-delivery-webhook-secret-header") || "X-PPE-Signature", secret: formValue("sf-delivery-webhook-secret") };
    settings.channels.email = { ...(settings.channels.email || {}), enabled: boolValue("sf-delivery-email-enabled"), mode: formValue("sf-delivery-email-mode"), smtp_host: formValue("sf-delivery-smtp-host"), smtp_port: numberValue("sf-delivery-smtp-port", 587), smtp_tls: boolValue("sf-delivery-smtp-tls"), username: formValue("sf-delivery-smtp-user"), password: formValue("sf-delivery-smtp-password"), from: formValue("sf-delivery-email-from"), to: csvValue("sf-delivery-email-to"), subject_template: formValue("sf-delivery-subject") || "PPE inspection: {decision}" };
  } else if (serviceType === "viewer") {
    settings.heartbeat_interval_sec = numberValue("sf-viewer-heartbeat", 10);
    settings.max_local_queue_size = numberValue("sf-viewer-queue", 200);
    settings.accepted_target_kinds = ["viewer"];
  } else if (serviceType === "control_center") {
    settings.default_worker_service_id = formValue("sf-cc-worker");
    settings.default_storage_service_ids = csvValue("sf-cc-storage");
    settings.default_delivery_service_ids = csvValue("sf-cc-delivery");
    settings.default_viewer_service_ids = csvValue("sf-cc-viewer");
    settings.allow_default_route = boolValue("sf-cc-allow-default");
    settings.worker_result_timeout_sec = numberValue("sf-cc-worker-timeout", 10);
    settings.delivery_retry_limit = numberValue("sf-cc-retry-limit", 5);
    settings.delivery_retry_delay_sec = numberValue("sf-cc-retry-delay", 5);
    settings.service_certificate_ttl_hours = numberValue("sf-cc-cert-ttl", 24);
  }
  return settings;
}

function showScreen(name) {
  loginScreen.classList.toggle("active", name === "login");
  dashboardScreen.classList.toggle("active", name === "dashboard");
}

function setToken(token) {
  state.token = token;
  if (token) {
    window.localStorage.setItem("controlCenterToken", token);
  } else {
    window.localStorage.removeItem("controlCenterToken");
  }
}

async function api(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (state.token) {
    headers.Authorization = `Bearer ${state.token}`;
  }

  const response = await fetch(path, { ...options, headers });
  if (response.status === 204) {
    return null;
  }

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(formatApiError(data));
  }
  return data;
}

function formatApiError(data) {
  if (!data || typeof data !== "object") {
    return "Request failed";
  }
  if (typeof data.detail === "string") {
    return data.detail;
  }
  if (Array.isArray(data.detail)) {
    return data.detail
      .map((item) => {
        if (!item || typeof item !== "object") {
          return String(item);
        }
        const path = Array.isArray(item.loc) ? item.loc.slice(1).join(".") : "field";
        return `${path}: ${item.msg || "invalid value"}`;
      })
      .join("\n");
  }
  return "Request failed";
}

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function switchTab(name) {
  state.activeTab = name;
  for (const button of tabButtons) {
    button.classList.toggle("active", button.dataset.tab === name);
  }
  for (const panel of tabPanels) {
    panel.classList.toggle("active", panel.dataset.panel === name);
  }
}

function renderProfile() {
  currentUserEl.textContent = state.user ? `${state.user.username} · ${roleLabel(state.user.role)}` : "";
  if (!state.user) {
    profileSummaryEl.innerHTML = "";
    return;
  }

  const grants = state.user.access.length
    ? state.user.access.map((entry) => `${entry.service_id} (${entry.access_level})`).join(", ")
    : "global access or no scoped grants";

  profileSummaryEl.innerHTML = `
    <div class="kv-item"><strong>Пользователь</strong>${state.user.username}</div>
    <div class="kv-item"><strong>Роль</strong>${roleLabel(state.user.role)}</div>
    <div class="kv-item"><strong>Created</strong>${state.user.created_at}</div>
    <div class="kv-item"><strong>Access</strong>${grants}</div>
  `;
}

function serviceStatusBadge(status) {
  if (status === "active") return "badge";
  if (status === "disabled") return "badge danger";
}

function serviceStatusLabel(status) {
  if (status === "active") return "включен";
  if (status === "disabled") return "отключен";
}

function runtimeStatusBadge(service) {
  if (service.admin_state === "disabled") {
    return "badge neutral";
  }
  if (service.registration_status !== "approved") {
    return service.registration_status === "denied" ? "badge danger" : "badge warn";
  }
  if (!service.last_seen_at) {
    return "badge warn";
  }
  const lastSeen = Date.parse(service.last_seen_at);
  if (Number.isNaN(lastSeen)) {
    return "badge warn";
  }
  return Date.now() - lastSeen <= 90000 ? "badge" : "badge danger";
}

function runtimeStatusLabel(service) {
  if (service.admin_state === "disabled") {
    return "interaction disabled";
  }
  if (service.registration_status === "pending") {
    return "awaiting registration";
  }
  if (service.registration_status === "denied") {
    return "registration denied";
  }
  if (!service.last_seen_at) {
    return "no heartbeat yet";
  }
  const lastSeen = Date.parse(service.last_seen_at);
  if (Number.isNaN(lastSeen)) {
    return "heartbeat unknown";
  }
  return Date.now() - lastSeen <= 90000 ? "online" : "offline";
}

function renderLastSeen(lastSeenAt) {
  if (!lastSeenAt) {
    return "not received";
  }
  return lastSeenAt;
}

function renderServices() {
  serviceListEl.innerHTML = "";
  if (!state.services.length) {
    serviceListEl.innerHTML = '<div class="muted">Нет доступных сервисов.</div>';
    return;
  }

  for (const service of state.services) {
    const canManage =
      (state.user && state.user.role === "root") ||
      (state.user && state.user.access.some((entry) => entry.service_id === service.service_id && entry.access_level === "manage"));

    const card = document.createElement("article");
    card.className = "service-card";
    card.innerHTML = `
      <div class="service-head">
        <div>
          <strong>${service.display_name}</strong>
          <div class="meta">${service.service_id} · ${service.service_type}</div>
        </div>
        <div class="service-badges">
          <span class="${serviceStatusBadge(service.admin_state)}">interaction: ${serviceStatusLabel(service.admin_state)}</span>
          <span class="${runtimeStatusBadge(service)}">runtime: ${runtimeStatusLabel(service)}</span>
        </div>
      </div>
      <div class="service-runtime">
        <div class="meta"><strong>Registration:</strong> ${service.registration_status || "unknown"}</div>
        <div class="meta"><strong>Last heartbeat:</strong> ${renderLastSeen(service.last_seen_at)}</div>
        <div class="meta"><strong>Local URL:</strong> ${service.local_url || "not set"}</div>
        <div class="meta"><strong>Config version:</strong> ${service.config_version == null ? "-" : service.config_version}</div>
        <div class="meta"><strong>Certificate:</strong> ${service.certificate_status || "not issued"}</div>
        <div class="meta"><strong>Cert serial:</strong> ${service.certificate_serial_hex || "-"}</div>
        <div class="meta"><strong>Cert expires:</strong> ${service.certificate_expires_at || "-"}</div>
      </div>
      <pre class="json-block">${escapeHtml(JSON.stringify(service.settings, null, 2))}</pre>
      <div class="service-actions">
        ${canManage ? `<button type="button" data-edit-service="${service.service_id}">Редактировать</button>` : ""}
        ${state.user && state.user.role === "root" && service.service_id !== "control-center"
          ? `<button class="secondary" type="button" data-rotate-service="${service.service_id}">Перевыпустить secret</button>`
          : ""}
        ${state.user && state.user.role === "root" && service.service_id !== "control-center"
          ? `<button class="secondary" type="button" data-revoke-service-cert="${service.service_id}">Отозвать cert</button>`
          : ""}
        ${state.user && state.user.role === "root" && service.service_id !== "control-center"
          ? `<button class="secondary" type="button" data-delete-service="${service.service_id}">Удалить</button>`
          : ""}
      </div>
    `;
    serviceListEl.appendChild(card);
  }
}

function renderUsers() {
  userListEl.innerHTML = "";
  if (!state.user || state.user.role !== "root") {
    return;
  }

  for (const user of state.users) {
    const grantsHtml = user.access.length
      ? user.access
          .map(
            (entry) => `
              <span class="grant-chip">
                ${entry.service_id}:${entry.access_level}
                <button class="chip-button" type="button" data-revoke-username="${user.username}" data-revoke-service="${entry.service_id}">x</button>
              </span>
            `
          )
          .join("")
      : '<span class="meta">no scoped grants</span>';

    const card = document.createElement("article");
    card.className = "user-card";
    card.innerHTML = `
      <div class="user-head">
        <div>
          <strong>${user.username}</strong>
          <div class="meta">${roleLabel(user.role)}</div>
        </div>
        <span class="badge">${user.is_active ? "active" : "disabled"}</span>
      </div>
      <div class="meta">Created: ${user.created_at}</div>
      <div class="service-actions">
        <button type="button" data-edit-user="${user.username}">Редактировать</button>
        ${user.username !== "root" ? `<button class="secondary" type="button" data-delete-user="${user.username}">Удалить</button>` : ""}
      </div>
      <div class="grant-list">${grantsHtml}</div>
    `;
    userListEl.appendChild(card);
  }
}

function renderAudit() {
  auditListEl.innerHTML = "";
  if (!state.audit.length) {
    auditListEl.innerHTML = '<div class="muted">Событий пока нет.</div>';
    return;
  }

  for (const item of state.audit) {
    const entry = document.createElement("article");
    entry.className = "audit-item";
    entry.innerHTML = `
      <div class="audit-head">
        <div>
          <strong>${item.action}</strong>
          <div class="meta">${item.target_type}${item.target_id ? ` · ${item.target_id}` : ""}</div>
        </div>
        <span class="meta">${item.created_at}</span>
      </div>
      <pre class="json-block">${escapeHtml(JSON.stringify(item.details, null, 2))}</pre>
    `;
    auditListEl.appendChild(entry);
  }
}

function renderRoutes() {
  routeListEl.innerHTML = "";
  if (!state.routes.length) {
    routeListEl.innerHTML = '<div class="muted">Маршрутов пока нет.</div>';
    return;
  }

  for (const route of state.routes) {
    const targetsHtml = route.targets.length
      ? route.targets
          .map(
            (target) => `
              <div class="route-target">
                <strong>${target.target_service_id}</strong>
                <div class="meta">${target.target_kind} · required: ${target.is_required} · order: ${target.order_index}</div>
                ${Object.keys(target.filter || {}).length ? `<pre class="json-block">${escapeHtml(JSON.stringify(target.filter, null, 2))}</pre>` : ""}
              </div>
            `
          )
          .join("")
      : '<div class="muted">Нет delivery targets.</div>';

    const card = document.createElement("article");
    card.className = "route-card";
    card.innerHTML = `
      <div class="route-head">
        <div>
          <strong>${route.name}</strong>
          <div class="meta">${route.route_id}</div>
        </div>
        <div class="service-badges">
          <span class="${route.is_active ? "badge" : "badge danger"}">${route.is_active ? "active" : "disabled"}</span>
        </div>
      </div>
      <div class="service-runtime">
        <div class="meta"><strong>Checkpoint:</strong> ${route.checkpoint_service_id || "любой"}</div>
        <div class="meta"><strong>Worker:</strong> ${route.worker_service_id}</div>
        <div class="meta"><strong>Updated:</strong> ${route.updated_at}</div>
      </div>
      <div class="route-target-list">${targetsHtml}</div>
      <div class="meta"><strong>Route targets JSON</strong></div>
      <pre class="json-block">${escapeHtml(JSON.stringify(route.targets || [], null, 2))}</pre>
      <div class="service-actions">
        ${state.user && state.user.role === "root" ? `<button type="button" data-edit-route="${route.route_id}">Редактировать</button>` : ""}
      </div>
    `;
    routeListEl.appendChild(card);
  }
}

function renderRuntimeEvents() {
  runtimeEventListEl.innerHTML = "";
  if (!state.runtimeEvents.length) {
    runtimeEventListEl.innerHTML = '<div class="muted">Runtime событий пока нет.</div>';
    return;
  }

  for (const item of state.runtimeEvents) {
    const entry = document.createElement("article");
    entry.className = "runtime-event-item";
    entry.innerHTML = `
      <div class="runtime-event-head">
        <div>
          <strong>${item.event_type}</strong>
          <div class="meta">${item.source_service_id} · ${item.source_service_type} · ${item.event_class}</div>
        </div>
        <div class="service-badges">
          <span class="${item.severity === "error" ? "badge danger" : "badge"}">${item.severity}</span>
          <span class="meta">${item.created_at}</span>
        </div>
      </div>
      <div class="service-runtime">
        <div class="meta"><strong>Request ID:</strong> ${item.request_id || "-"}</div>
        <div class="meta"><strong>Job ID:</strong> ${item.job_id || "-"}</div>
      </div>
      <pre class="json-block">${escapeHtml(JSON.stringify(item.payload || {}, null, 2))}</pre>
    `;
    runtimeEventListEl.appendChild(entry);
  }
}

function renderPanels() {
  const isRoot = state.user && state.user.role === "root";
  rootUserPanel.classList.toggle("hidden", !isRoot);
  rootUserCreatePanel.classList.toggle("hidden", !isRoot);
  rootServicePanel.classList.toggle("hidden", !isRoot);
  rootGrantPanel.classList.toggle("hidden", !isRoot);
  rootRoutePanel.classList.toggle("hidden", !isRoot);
  document.querySelectorAll(".root-only").forEach((element) => {
    element.classList.toggle("hidden", !isRoot);
  });

  if (!isRoot && state.activeTab === "users") {
    switchTab("overview");
  }
}

function openModal(modal) {
  modal.classList.remove("hidden");
}

function closeModal(modal) {
  modal.classList.add("hidden");
}

function fillServiceEditor(serviceId) {
  const service = state.services.find((entry) => entry.service_id === serviceId);
  if (!service) return;

  document.querySelector("#service-update-id").value = service.service_id;
  document.querySelector("#service-update-name").value = service.display_name;
  document.querySelector("#service-update-status").value = service.admin_state;
  document.querySelector("#service-update-settings").value = JSON.stringify(service.settings, null, 2);
  renderServiceSettingsForm(service);
  renderTemplateOptions(service);
  document.querySelector("#service-settings-mode").value = "form";
  setSettingsEditorMode("form");
  document.querySelector("#service-update-error").classList.add("hidden");
  deleteServiceButton.dataset.serviceId = service.service_id;
  openModal(serviceModal);
}

function showProvisioningResult(payload) {
  const panel = document.querySelector("#service-provisioning-result");
  const pre = document.querySelector("#service-provisioning-json");
  pre.textContent = JSON.stringify(payload, null, 2);
  panel.classList.remove("hidden");
}

function defaultRouteTargets() {
  const storageEntry = state.services.find((entry) => entry.service_type === "storage");
  const deliveryEntry = state.services.find((entry) => entry.service_type === "delivery_service");
  const viewerEntry = state.services.find((entry) => entry.service_type === "viewer");
  const storage = storageEntry ? storageEntry.service_id : "storage-01";
  const delivery = deliveryEntry ? deliveryEntry.service_id : "delivery-01";
  const viewer = viewerEntry ? viewerEntry.service_id : "";
  const targets = [
    { target_service_id: storage, target_kind: "database", is_required: true, order_index: 10, filter: {} },
    { target_service_id: delivery, target_kind: "webhook", is_required: false, order_index: 20, filter: {} },
  ];
  if (viewer) {
    targets.push({ target_service_id: viewer, target_kind: "viewer", is_required: false, order_index: 40, filter: {} });
  }
  return targets;
}

function setRouteTargetsExpert(prefix, enabled) {
  const base = prefix === "new" ? "new-route" : prefix;
  document.querySelector(`#${base}-targets-form`).classList.toggle("hidden", enabled);
  document.querySelector(`#${base}-targets-json-wrap`).classList.toggle("hidden", !enabled);
}

function renderRouteTargetsForm(prefix, targets = defaultRouteTargets()) {
  const base = prefix === "new" ? "new-route" : prefix;
  const databaseTarget = targets.find((target) => target.target_kind === "database") || {};
  const webhookTarget = targets.find((target) => target.target_kind === "webhook") || {};
  const emailTarget = targets.find((target) => target.target_kind === "email") || {};
  const viewerTarget = targets.find((target) => target.target_kind === "viewer") || {};
  document.querySelector(`#${base}-targets-form`).innerHTML = `
    <div class="route-target-editor">
      <strong>Database storage</strong>
      <label><span>Storage service</span><select id="${prefix}-target-storage">${serviceOptions("storage", databaseTarget.target_service_id || "", true)}</select></label>
      <label><span>Required</span><select id="${prefix}-target-storage-required"><option value="true">yes</option><option value="false">no</option></select></label>
    </div>
    <div class="route-target-editor">
      <strong>Webhook delivery</strong>
      <label><span>Delivery service</span><select id="${prefix}-target-webhook">${serviceOptions("delivery_service", webhookTarget.target_service_id || "", true)}</select></label>
      <label><span>Webhook URL override</span><input id="${prefix}-target-webhook-url" type="text" value="${escapeHtml(textValue((webhookTarget.filter || {}).url))}" /></label>
      <label><span>Required</span><select id="${prefix}-target-webhook-required"><option value="false">no</option><option value="true">yes</option></select></label>
    </div>
    <div class="route-target-editor">
      <strong>Email delivery</strong>
      <label><span>Delivery service</span><select id="${prefix}-target-email">${serviceOptions("delivery_service", emailTarget.target_service_id || "", true)}</select></label>
      <label><span>Required</span><select id="${prefix}-target-email-required"><option value="false">no</option><option value="true">yes</option></select></label>
    </div>
    <div class="route-target-editor">
      <strong>Viewer queue</strong>
      <label><span>Viewer service</span><select id="${prefix}-target-viewer">${serviceOptions("viewer", viewerTarget.target_service_id || "", true)}</select></label>
      <label><span>Required</span><select id="${prefix}-target-viewer-required"><option value="false">no</option><option value="true">yes</option></select></label>
    </div>
  `;
  document.querySelector(`#${prefix}-target-storage-required`).value = String(databaseTarget.is_required !== false);
  document.querySelector(`#${prefix}-target-webhook-required`).value = String(webhookTarget.is_required === true);
  document.querySelector(`#${prefix}-target-email-required`).value = String(emailTarget.is_required === true);
  document.querySelector(`#${prefix}-target-viewer-required`).value = String(viewerTarget.is_required === true);
}

function routeTargetsFromForm(prefix) {
  const targets = [];
  const storageService = formValue(`${prefix}-target-storage`);
  if (storageService) {
    targets.push({ target_service_id: storageService, target_kind: "database", is_required: boolValue(`${prefix}-target-storage-required`), order_index: 10, filter: {} });
  }
  const webhookService = formValue(`${prefix}-target-webhook`);
  if (webhookService) {
    const url = formValue(`${prefix}-target-webhook-url`);
    targets.push({ target_service_id: webhookService, target_kind: "webhook", is_required: boolValue(`${prefix}-target-webhook-required`), order_index: 20, filter: url ? { url } : {} });
  }
  const emailService = formValue(`${prefix}-target-email`);
  if (emailService) {
    targets.push({ target_service_id: emailService, target_kind: "email", is_required: boolValue(`${prefix}-target-email-required`), order_index: 30, filter: {} });
  }
  const viewerService = formValue(`${prefix}-target-viewer`);
  if (viewerService) {
    targets.push({ target_service_id: viewerService, target_kind: "viewer", is_required: boolValue(`${prefix}-target-viewer-required`), order_index: 40, filter: {} });
  }
  return targets;
}

function renderRouteServiceSelects(route = {}) {
  document.querySelector("#new-route-checkpoint").innerHTML = serviceOptions("checkpoint", "", true);
  document.querySelector("#new-route-worker").innerHTML = serviceOptions("worker", "", true);
  document.querySelector("#route-update-checkpoint").innerHTML = serviceOptions("checkpoint", route.checkpoint_service_id || "", true);
  document.querySelector("#route-update-worker").innerHTML = serviceOptions("worker", route.worker_service_id || "", true);
}

function fillUserEditor(username) {
  const user = state.users.find((entry) => entry.username === username);
  if (!user) return;

  document.querySelector("#edit-user-username").value = user.username;
  document.querySelector("#edit-user-role").value = user.role;
  document.querySelector("#edit-user-active").value = String(user.is_active);
  document.querySelector("#edit-user-password").value = "";
  document.querySelector("#update-user-error").classList.add("hidden");
  deleteUserButton.dataset.username = user.username;
  openModal(userModal);
}

function fillRouteEditor(routeId) {
  const route = state.routes.find((entry) => entry.route_id === routeId);
  if (!route) return;

  renderRouteServiceSelects(route);
  document.querySelector("#route-update-id").value = route.route_id;
  document.querySelector("#route-update-name").value = route.name;
  document.querySelector("#route-update-checkpoint").value = route.checkpoint_service_id || "";
  document.querySelector("#route-update-worker").value = route.worker_service_id;
  document.querySelector("#route-update-priority").value = String(route.priority);
  document.querySelector("#route-update-default").value = String(route.is_default);
  document.querySelector("#route-update-active").value = String(route.is_active);
  document.querySelector("#route-update-targets").value = JSON.stringify(route.targets || [], null, 2);
  document.querySelector("#route-update-targets-expert").checked = false;
  setRouteTargetsExpert("route-update", false);
  renderRouteTargetsForm("route-update", route.targets || []);
  document.querySelector("#route-update-error").classList.add("hidden");
  deleteRouteButton.dataset.routeId = route.route_id;
  openModal(routeModal);
}

async function loadDashboard() {
  state.user = await api("/api/v1/auth/me");
  state.services = await api("/api/v1/services");
  state.routes = await api("/api/v1/routes");
  const auditParams = new URLSearchParams(Object.entries(state.auditFilters).filter(([, value]) => value));
  const runtimeParams = new URLSearchParams(Object.entries(state.runtimeFilters).filter(([, value]) => value));
  state.audit = await api(`/api/v1/audit${auditParams.toString() ? `?${auditParams}` : ""}`);
  state.runtimeEvents = await api(`/api/v1/runtime-events${runtimeParams.toString() ? `?${runtimeParams}` : ""}`);
  state.users = state.user.role === "root" ? await api("/api/v1/users") : [];

  renderRouteServiceSelects();
  renderRouteTargetsForm("new", defaultRouteTargets());
  const newTargetsExpert = document.querySelector("#new-route-targets-expert");
  setRouteTargetsExpert("new", newTargetsExpert ? newTargetsExpert.checked : false);
  renderProfile();
  renderPanels();
  renderServices();
  renderRoutes();
  renderUsers();
  renderAudit();
  renderRuntimeEvents();
  showScreen("dashboard");
}

async function handleLogin(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#login-error");
  errorEl.classList.add("hidden");

  try {
    const payload = {
      username: document.querySelector("#login-username").value.trim(),
      password: document.querySelector("#login-password").value,
    };
    const result = await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    setToken(result.access_token);
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

function handleLogout() {
  setToken("");
  state.user = null;
  state.services = [];
  state.routes = [];
  state.audit = [];
  state.runtimeEvents = [];
  state.users = [];
  closeModal(serviceModal);
  closeModal(userModal);
  closeModal(routeModal);
  document.querySelector("#edit-user-username").value = "";
  switchTab("overview");
  showScreen("login");
}

async function handleCreateUser(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#create-user-error");
  errorEl.classList.add("hidden");

  try {
    const payload = {
      username: document.querySelector("#new-user-username").value.trim(),
      password: document.querySelector("#new-user-password").value,
      role: document.querySelector("#new-user-role").value,
      access: [],
    };
    await api("/api/v1/users", { method: "POST", body: JSON.stringify(payload) });
    event.target.reset();
    switchTab("users");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleUpdateUser(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#update-user-error");
  errorEl.classList.add("hidden");

  try {
    const username = document.querySelector("#edit-user-username").value;
    if (!username) {
      throw new Error("Выберите пользователя для редактирования");
    }
    const password = document.querySelector("#edit-user-password").value;
    const payload = {
      role: document.querySelector("#edit-user-role").value,
      is_active: document.querySelector("#edit-user-active").value === "true",
    };
    if (password) {
      payload.password = password;
    }
    await api(`/api/v1/users/${encodeURIComponent(username)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    closeModal(userModal);
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleDeleteUser(username) {
  if (!username) {
    return;
  }
  if (!window.confirm(`Удалить пользователя ${username}?`)) {
    return;
  }

  const errorEl = document.querySelector("#update-user-error");
  errorEl.classList.add("hidden");

  try {
    await api(`/api/v1/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    document.querySelector("#edit-user-username").value = "";
    closeModal(userModal);
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleCreateService(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#create-service-error");
  errorEl.classList.add("hidden");

  try {
    const payload = {
      service_id: document.querySelector("#new-service-id").value.trim(),
      service_type: document.querySelector("#new-service-type").value,
      display_name: document.querySelector("#new-service-name").value.trim(),
      settings: JSON.parse(document.querySelector("#new-service-settings").value || "{}"),
    };
    const result = await api("/api/v1/services", { method: "POST", body: JSON.stringify(payload) });
    event.target.reset();
    document.querySelector("#new-service-settings").value = "{}";
    showProvisioningResult({
      service_id: result.service_id,
      service_type: result.service_type,
      bootstrap_secret: result.bootstrap_secret,
    });
    switchTab("services");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleRotateServiceCredentials(serviceId) {
  if (!serviceId) return;
  if (!window.confirm(`Перевыпустить bootstrap secret для ${serviceId}?`)) return;

  try {
    const result = await api(`/api/v1/services/${encodeURIComponent(serviceId)}/credentials/rotate`, { method: "POST" });
    showProvisioningResult(result);
    switchTab("services");
  } catch (error) {
    const errorEl = document.querySelector("#service-update-error");
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleRevokeServiceCertificate(serviceId) {
  if (!serviceId) return;
  if (!window.confirm(`Отозвать активный сертификат сервиса ${serviceId}?`)) return;

  try {
    const result = await api(`/api/v1/pki/services/${encodeURIComponent(serviceId)}/revoke`, { method: "POST" });
    showProvisioningResult(result);
    switchTab("services");
    await loadDashboard();
  } catch (error) {
    const errorEl = document.querySelector("#service-update-error");
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleUpdateService(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#service-update-error");
  errorEl.classList.add("hidden");

  try {
    const serviceId = document.querySelector("#service-update-id").value;
    if (!serviceId) {
      throw new Error("Выберите сервис для редактирования");
    }
    const service = state.services.find((entry) => entry.service_id === serviceId);
    if (!service) {
      throw new Error("Сервис не найден в текущем списке");
    }
    const settingsMode = document.querySelector("#service-settings-mode").value;
    const payload = {
      display_name: document.querySelector("#service-update-name").value.trim(),
      admin_state: document.querySelector("#service-update-status").value,
      settings: settingsMode === "json"
        ? JSON.parse(document.querySelector("#service-update-settings").value || "{}")
        : settingsMode === "template"
          ? settingsFromSelectedTemplate(service)
          : settingsFromForm(service.service_type, service.settings),
    };
    await api(`/api/v1/services/${encodeURIComponent(serviceId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    closeModal(serviceModal);
    switchTab("services");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleDeleteService(serviceId) {
  if (!serviceId) {
    return;
  }
  if (!window.confirm(`Удалить сервис ${serviceId}?`)) {
    return;
  }

  const errorEl = document.querySelector("#service-update-error");
  errorEl.classList.add("hidden");

  try {
    await api(`/api/v1/services/${encodeURIComponent(serviceId)}`, { method: "DELETE" });
    closeModal(serviceModal);
    deleteServiceButton.dataset.serviceId = "";
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleGrantAccess(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#grant-access-error");
  errorEl.classList.add("hidden");

  try {
    const payload = {
      username: document.querySelector("#grant-username").value.trim(),
      service_id: document.querySelector("#grant-service-id").value.trim(),
    };
    await api("/api/v1/access/grants", { method: "POST", body: JSON.stringify(payload) });
    event.target.reset();
    switchTab("users");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleCreateRoute(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#create-route-error");
  errorEl.classList.add("hidden");

  try {
    const payload = {
      route_id: document.querySelector("#new-route-id").value.trim(),
      name: document.querySelector("#new-route-name").value.trim(),
      checkpoint_service_id: document.querySelector("#new-route-checkpoint").value.trim() || null,
      worker_service_id: document.querySelector("#new-route-worker").value.trim(),
      is_default: document.querySelector("#new-route-default").value === "true",
      priority: Number(document.querySelector("#new-route-priority").value || 0),
      is_active: document.querySelector("#new-route-active").value === "true",
      targets: document.querySelector("#new-route-targets-expert").checked
        ? JSON.parse(document.querySelector("#new-route-targets").value || "[]")
        : routeTargetsFromForm("new"),
    };
    await api("/api/v1/routes", { method: "POST", body: JSON.stringify(payload) });
    event.target.reset();
    document.querySelector("#new-route-targets").value = `[
  {
    "target_service_id": "storage-01",
    "target_kind": "database",
    "is_required": true,
    "order_index": 10,
    "filter": {}
  },
  {
    "target_service_id": "delivery-01",
    "target_kind": "webhook",
    "is_required": false,
    "order_index": 20,
    "filter": {}
  },
  {
    "target_service_id": "viewer-01",
    "target_kind": "viewer",
    "is_required": false,
    "order_index": 40,
    "filter": {}
  }
]`;
    document.querySelector("#new-route-targets-expert").checked = false;
    renderRouteTargetsForm("new", defaultRouteTargets());
    setRouteTargetsExpert("new", false);
    switchTab("routes");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleUpdateRoute(event) {
  event.preventDefault();
  const errorEl = document.querySelector("#route-update-error");
  errorEl.classList.add("hidden");

  try {
    const routeId = document.querySelector("#route-update-id").value;
    const payload = {
      name: document.querySelector("#route-update-name").value.trim(),
      checkpoint_service_id: document.querySelector("#route-update-checkpoint").value.trim() || null,
      worker_service_id: document.querySelector("#route-update-worker").value.trim(),
      is_default: document.querySelector("#route-update-default").value === "true",
      priority: Number(document.querySelector("#route-update-priority").value || 0),
      is_active: document.querySelector("#route-update-active").value === "true",
      targets: document.querySelector("#route-update-targets-expert").checked
        ? JSON.parse(document.querySelector("#route-update-targets").value || "[]")
        : routeTargetsFromForm("route-update"),
    };
    await api(`/api/v1/routes/${encodeURIComponent(routeId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
    closeModal(routeModal);
    switchTab("routes");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleDeleteRoute(routeId) {
  if (!routeId) return;
  if (!window.confirm(`Удалить маршрут ${routeId}?`)) {
    return;
  }
  const errorEl = document.querySelector("#route-update-error");
  errorEl.classList.add("hidden");
  try {
    await api(`/api/v1/routes/${encodeURIComponent(routeId)}`, { method: "DELETE" });
    closeModal(routeModal);
    deleteRouteButton.dataset.routeId = "";
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
  }
}

async function handleRevokeAccess(username, serviceId) {
  if (!window.confirm(`Отозвать доступ ${serviceId} у пользователя ${username}?`)) {
    return;
  }

  const errorEl = document.querySelector("#grant-access-error");
  errorEl.classList.add("hidden");

  try {
    await api("/api/v1/access/grants", {
      method: "DELETE",
      body: JSON.stringify({ username, service_id: serviceId }),
    });
    switchTab("users");
    await loadDashboard();
  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.classList.remove("hidden");
    switchTab("users");
  }
}

function bindEvents() {
  document.querySelector("#login-form").addEventListener("submit", handleLogin);
  document.querySelector("#logout-button").addEventListener("click", handleLogout);
  document.querySelector("#refresh-button").addEventListener("click", () => loadDashboard().catch(handleLogout));
  document.querySelector("#audit-filter-apply").addEventListener("click", () => {
    state.auditFilters = {
      target_id: document.querySelector("#audit-filter-target").value.trim(),
      action: document.querySelector("#audit-filter-action").value.trim(),
    };
    loadDashboard().catch(handleLogout);
  });
  document.querySelector("#runtime-filter-apply").addEventListener("click", () => {
    state.runtimeFilters = {
      request_id: document.querySelector("#runtime-filter-request").value.trim(),
      source_service_id: document.querySelector("#runtime-filter-service").value.trim(),
      severity: document.querySelector("#runtime-filter-severity").value,
    };
    loadDashboard().catch(handleLogout);
  });
  document.querySelector("#create-user-form").addEventListener("submit", handleCreateUser);
  document.querySelector("#update-user-form").addEventListener("submit", handleUpdateUser);
  document.querySelector("#create-service-form").addEventListener("submit", handleCreateService);
  document.querySelector("#download-root-cert-button").addEventListener("click", () => {
    window.open("/api/v1/pki/root-cert", "_blank", "noopener,noreferrer");
  });
  document.querySelector("#create-route-form").addEventListener("submit", handleCreateRoute);
  document.querySelector("#new-route-targets-expert").addEventListener("change", (event) => setRouteTargetsExpert("new", event.target.checked));
  document.querySelector("#grant-access-form").addEventListener("submit", handleGrantAccess);
  document.querySelector("#service-update-form").addEventListener("submit", handleUpdateService);
  document.querySelector("#service-settings-mode").addEventListener("change", (event) => setSettingsEditorMode(event.target.value));
  document.querySelector("#route-update-form").addEventListener("submit", handleUpdateRoute);
  document.querySelector("#route-update-targets-expert").addEventListener("change", (event) => setRouteTargetsExpert("route-update", event.target.checked));
  deleteServiceButton.addEventListener("click", () => handleDeleteService(deleteServiceButton.dataset.serviceId));
  deleteUserButton.addEventListener("click", () => handleDeleteUser(deleteUserButton.dataset.username));
  deleteRouteButton.addEventListener("click", () => handleDeleteRoute(deleteRouteButton.dataset.routeId));
  closeServiceModalButton.addEventListener("click", () => closeModal(serviceModal));
  closeUserModalButton.addEventListener("click", () => closeModal(userModal));
  closeRouteModalButton.addEventListener("click", () => closeModal(routeModal));
  serviceModal.addEventListener("click", (event) => {
    if (event.target === serviceModal) closeModal(serviceModal);
  });
  userModal.addEventListener("click", (event) => {
    if (event.target === userModal) closeModal(userModal);
  });
  routeModal.addEventListener("click", (event) => {
    if (event.target === routeModal) closeModal(routeModal);
  });

  for (const button of tabButtons) {
    button.addEventListener("click", () => switchTab(button.dataset.tab));
  }

  serviceListEl.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.dataset.editService) {
      fillServiceEditor(target.dataset.editService);
      switchTab("services");
      return;
    }
    if (target.dataset.rotateService) {
      handleRotateServiceCredentials(target.dataset.rotateService);
      return;
    }
    if (target.dataset.revokeServiceCert) {
      handleRevokeServiceCertificate(target.dataset.revokeServiceCert);
      return;
    }
    if (target.dataset.deleteService) {
      handleDeleteService(target.dataset.deleteService);
    }
  });

  routeListEl.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.dataset.editRoute) {
      fillRouteEditor(target.dataset.editRoute);
      switchTab("routes");
    }
  });

  userListEl.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.dataset.editUser) {
      fillUserEditor(target.dataset.editUser);
      switchTab("users");
      return;
    }
    if (target.dataset.deleteUser) {
      handleDeleteUser(target.dataset.deleteUser);
      return;
    }
    if (target.dataset.revokeUsername && target.dataset.revokeService) {
      handleRevokeAccess(target.dataset.revokeUsername, target.dataset.revokeService);
    }
  });
}

async function bootstrap() {
  bindEvents();
  if (!state.token) {
    showScreen("login");
    return;
  }
  try {
    await loadDashboard();
  } catch {
    handleLogout();
  }
}

bootstrap();
