'use strict';

const REFRESH_MS = 15000;
let currentSession = null;
let portalMode = 'login';
let csrfToken = '';
let editingUser = null;
let editingId = null;
let latestConfig = null;
let latestSetup = null;
let latestCluster = null;
let latestStatus = null;
let historyItems = [];
let historyPage = 1;
let memberRowsInitialized = false;
let provisionCandidates = [];
let provisionTransaction = '';
let provisionPayload = null;
let provisionPoll = null;
let provisionRunning = false;
let reconciliationRunning = false;
let apiIntegrationItems = [];
const runningSyncs = new Set();
const readinessResults = new Map();
const HISTORY_PAGE_SIZE = 10;

const $ = (selector) => document.querySelector(selector);

const VALID_VIEWS = new Set(['inicio', 'configuracion', 'instancias', 'operacion', 'seguridad']);

function switchView(requested) {
  const view = VALID_VIEWS.has(requested) ? requested : 'inicio';
  document.querySelectorAll('[data-view-panel]').forEach((panel) => {
    panel.classList.toggle('active', panel.dataset.viewPanel === view);
  });
  document.querySelectorAll('[data-view]').forEach((button) => {
    button.classList.toggle('active', button.dataset.view === view);
  });
  if (window.location.hash !== '#' + view) {
    window.history.replaceState(null, '', '#' + view);
  }
  window.scrollTo({top: 0, behavior: 'smooth'});
}

function friendlyInstanceName(identifier, fallbackIndex) {
  const items = (latestConfig && latestConfig.instancias) || [];
  const index = items.findIndex((item) => item.id === identifier);
  const item = index >= 0 ? items[index] : null;
  if (item && item.display_name && item.display_name !== item.id) return item.display_name;
  const position = index >= 0 ? index : Number(fallbackIndex);
  return Number.isFinite(position) && position >= 0 ? 'Vaultwarden ' + String(position + 1) : 'Vaultwarden';
}

function renderNextStep(setup) {
  const checks = setup.checks || {};
  let kicker = 'ESTADO';
  let title = 'Sistema operativo';
  let copy = 'La configuración requerida está completa.';
  let action = 'Ver operación';
  let target = 'operacion';
  if (!checks.portal_account) {
    kicker = 'SEGURIDAD';
    title = 'Cuenta del portal no disponible';
    copy = 'Crea la primera cuenta desde el portal de acceso.';
    action = 'Abrir seguridad';
    target = 'seguridad';
  } else if (!checks.identity) {
    kicker = 'REQUISITO';
    title = 'Identidad del nodo pendiente';
    copy = 'Define el nombre y la IP fija del nodo.';
    action = 'Abrir grupo';
    target = 'configuracion';
  } else if (!checks.data_access) {
    kicker = 'REQUISITO';
    title = 'Acceso a contenedores no disponible';
    copy = 'Revisa los requisitos de instalación del grupo.';
    action = 'Revisar requisitos';
    target = 'configuracion';
  } else if (!checks.floating_api_token) {
    kicker = 'REQUISITO';
    title = 'Token de IP flotante no configurado';
    copy = 'Introduce el token de integración generado por Keepalived.';
    action = 'Configurar conexión';
    target = 'configuracion';
  } else if (!checks.replication_token) {
    kicker = 'REQUISITO';
    title = 'Secreto entre Guardian no configurado';
    copy = 'Revisa los requisitos de instalación del grupo.';
    action = 'Revisar requisitos';
    target = 'configuracion';
  } else if (setup.mode !== 'active') {
    kicker = 'ESTADO';
    title = 'Protección pausada';
    copy = 'La replicación continua no está activa.';
    action = 'Abrir política';
    target = 'configuracion';
  } else if (!checks.instances) {
    kicker = 'ESTADO';
    title = 'Sin servicios registrados';
    copy = 'Añade un contenedor Vaultwarden existente.';
    action = 'Añadir Vaultwarden';
    target = 'instancias';
  } else if (!checks.peers) {
    title = 'Nodo operativo sin redundancia';
    copy = 'No hay otros Guardian en el grupo.';
    action = 'Añadir servidor';
    target = 'configuracion';
  }
  $('#next-kicker').textContent = kicker;
  $('#next-title').textContent = title;
  $('#next-copy').textContent = copy;
  $('#next-action').textContent = action;
  $('#next-action').dataset.targetView = target;
}

function text(selector, value) {
  $(selector).textContent = value === null || value === undefined || value === '' ? '—' : String(value);
}

function cell(value, className) {
  const element = document.createElement('td');
  element.className = className || '';
  element.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
  return element;
}

function showNotice(message, kind) {
  const notice = $('#notice');
  notice.textContent = message || '';
  notice.className = message ? 'notice' + (kind ? ' notice-' + kind : '') : 'notice hidden';
}

function confirmarEnPanel(opciones) {
  const dialogo = $('#app-dialog');
  if (!dialogo || dialogo.open) return Promise.resolve(false);

  $('#dialog-title').textContent = opciones.titulo || 'Confirmar acción';
  const body = $('#dialog-body');
  body.textContent = '';
  for (const message of (opciones.mensajes || [])) {
    const paragraph = document.createElement('p');
    paragraph.textContent = message;
    body.append(paragraph);
  }
  if ((opciones.elementos || []).length) {
    const list = document.createElement('ul');
    for (const entry of opciones.elementos) {
      const item = document.createElement('li');
      item.textContent = typeof entry === 'string' ? entry : entry.texto;
      if (entry && entry.peligro) item.classList.add('riesgo');
      list.append(item);
    }
    body.append(list);
  }

  const acceptance = $('#dialog-acceptance');
  const checkbox = $('#dialog-checkbox');
  const confirm = $('#dialog-confirm');
  const requiresAcceptance = Boolean(opciones.aceptacion);
  acceptance.classList.toggle('hidden', !requiresAcceptance);
  checkbox.checked = false;
  $('#dialog-acceptance-text').textContent = opciones.aceptacion || '';
  confirm.textContent = opciones.accion || 'Confirmar';
  confirm.className = 'button accion-dialogo' + (opciones.peligro ? ' danger' : '');
  confirm.disabled = requiresAcceptance;
  checkbox.onchange = () => {
    confirm.disabled = requiresAcceptance && !checkbox.checked;
  };

  dialogo.returnValue = 'cancelar';
  return new Promise((resolve) => {
    dialogo.addEventListener('close', () => {
      resolve(dialogo.returnValue === 'confirmar');
    }, {once: true});
    dialogo.showModal();
    (requiresAcceptance ? checkbox : confirm).focus();
  });
}

function showFormMessage(message, kind) {
  const element = $('#form-message');
  element.textContent = message || '';
  element.className = message ? 'form-message' + (kind ? ' ' + kind : '') : 'form-message';
}

async function api(path, options) {
  const requestOptions = Object.assign({cache: 'no-store', credentials: 'same-origin'}, options || {});
  const headers = new Headers(requestOptions.headers || {});
  const method = String(requestOptions.method || 'GET').toUpperCase();
  if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers.set('X-CSRF-Token', csrfToken);
  }
  if (requestOptions.body !== undefined && !(requestOptions.body instanceof Blob)) {
    headers.set('Content-Type', 'application/json');
  }
  requestOptions.headers = headers;
  const response = await fetch(path, requestOptions);
  let body = {};
  try { body = await response.json(); } catch (error) { /* respuesta sin JSON */ }
  if (!response.ok) {
    const requestError = new Error(body.error || ('HTTP ' + response.status));
    requestError.status = response.status;
    requestError.code = body.code || '';
    requestError.body = body;
    if (response.status === 401 && currentSession
        && path !== '/api/v1/session') {
      showLogin('La sesión ha finalizado.', 'warning');
    }
    throw requestError;
  }
  return body;
}

function isAdmin() {
  return Boolean(currentSession);
}

function setAdminUi() {
  const connected = isAdmin();
  document.querySelectorAll('.admin-control').forEach((element) => {
    element.classList.toggle('hidden', !connected);
  });
  $('#settings-fields').disabled = !connected;
  $('#keepalived-integration-fields').disabled = !connected;
  $('#application-settings-fields').disabled = !connected;
  $('#api-integration-fields').disabled = !connected;
  $('#private-ca-fields').disabled = !connected;
  $('#cluster-fields').disabled = !connected;
  $('#add-member').disabled = !connected;
  $('#reconcile-members').disabled = !connected || reconciliationRunning;
  $('#cluster-access-hint').textContent = connected
    ? 'Los cambios se distribuyen al guardar el grupo.'
    : '';
  $('#settings-message').textContent = connected
    ? 'La política se aplica a todos los miembros.'
    : '';
  if (currentSession) {
    $('#current-user').textContent =
      currentSession.display_name || currentSession.username;
  }
}

const SETUP_LABELS = {
  portal_account: 'Cuenta del portal',
  identity: 'Nodo identificado',
  data_mount: 'Montaje de datos',
  data_access: 'Acceso a los contenedores',
  peers: 'Otros Guardian',
  instances: 'Vaultwarden registrado',
  replication_token: 'Secreto entre Guardian',
  api_token: 'Token API para integraciones',
  floating_api_token: 'Token API de IP flotante'
};

function updatePolicySummary() {
  const interval = Number($('#setting-interval').value || 0);
  const retention = Number($('#setting-retention').value || 0);
  const packageMb = Number($('#setting-package').value || 0);
  $('#policy-settings-summary').textContent = 'Cada ' + String(interval || '—') + ' s · '
    + String(retention || '—') + ' backups · ' + String(packageMb || '—') + ' MB';
}

function renderSetup(setup, config) {
  latestSetup = setup;
  const state = setup.state || 'empty';
  const badge = $('#setup-badge');
  badge.textContent = state === 'ready' ? 'listo' : (state === 'in_progress' ? 'en progreso' : 'pendiente');
  badge.className = 'badge ' + (state === 'ready' ? 'badge-good' : 'badge-warning');

  const requirements = setup.requirements || {};
  const setupChecks = setup.checks || {};
  const entries = Object.entries(SETUP_LABELS);
  const checks = $('#setup-checks');
  const fragment = document.createDocumentFragment();
  let passedCount = 0;
  const missing = [];
  for (const [key, label] of entries) {
    const item = document.createElement('div');
    const passed = Boolean(setupChecks[key]);
    const optional = requirements[key] === false;
    if (passed) passedCount += 1;
    if (!passed && !optional) missing.push(label);
    item.className = 'setup-check ' + (passed ? 'done' : (optional ? 'optional' : 'pending'));
    const marker = document.createElement('span');
    marker.className = 'setup-check-marker';
    marker.textContent = passed ? '✓' : (optional ? '◇' : '!');
    const copy = document.createElement('span');
    const title = document.createElement('strong');
    const detail = document.createElement('small');
    title.textContent = label;
    detail.textContent = passed ? 'Completado' : (optional ? 'Opcional' : 'Pendiente');
    copy.append(title, detail);
    item.append(marker, copy);
    fragment.append(item);
  }
  checks.replaceChildren(fragment);
  $('#setup-checks-summary').textContent = String(passedCount) + ' de ' + String(entries.length) + ' completados';
  $('#setup-checks-badge').textContent = String(passedCount) + '/' + String(entries.length);
  $('#setup-checks-badge').className = 'badge ' + (missing.length ? 'badge-warning' : 'badge-good');

  const issues = $('#setup-issues');
  issues.replaceChildren();
  issues.classList.toggle('hidden', !missing.length);
  for (const label of missing) {
    const item = document.createElement('span');
    item.textContent = 'Pendiente · ' + label;
    issues.append(item);
  }

  const settings = config.configuracion_operativa || {};
  text('#local-node', settings.node);
  text('#local-node-ip', settings.node_ip);
  text('#local-floating-api', settings.floating_api);
  text('#local-peers', Object.keys(settings.peers || {}).join(', ') || 'ninguno');
  const keepalivedConfigured = Boolean(config.token_ip_flotante_configurado);
  $('#keepalived-integration-badge').textContent = keepalivedConfigured ? 'configurado' : 'pendiente';
  $('#keepalived-integration-badge').className = 'badge ' + (keepalivedConfigured ? 'badge-good' : 'badge-warning');
  $('#keepalived-integration-token').placeholder = keepalivedConfigured
    ? 'Configurado · introduce otro para sustituirlo'
    : 'fip_…';
  const application = config.ajustes_aplicacion || {};
  if (!$('#application-settings-form').contains(document.activeElement)) {
    $('#application-portal-access').value = application.allow_insecure_portal
      ? 'http' : 'https';
    $('#application-session').value = application.session_minutes || 30;
    $('#application-history-size').value = application.history_max_mb || 16;
    $('#application-history-entries').value = application.history_max_entries || 5000;
  }
  $('#application-settings-badge').textContent = 'este Guardian';
  $('#application-settings-badge').className = 'badge badge-good';
  const apiCount = Number(application.api_integration_count || 0);
  $('#api-integration-badge').textContent = apiCount === 1
    ? '1 aplicación' : String(apiCount) + ' aplicaciones';
  $('#api-integration-badge').className = 'badge ' + (apiCount ? 'badge-good' : '');
  const caConfigured = Boolean(application.private_ca_configured);
  $('#private-ca-badge').textContent = caConfigured ? 'configurada' : 'CA del sistema';
  $('#private-ca-badge').className = 'badge ' + (caConfigured ? 'badge-good' : '');
  $('#disable-private-ca').disabled = !isAdmin() || !caConfigured;
  if (!$('#settings-form').contains(document.activeElement)) {
    $('#setting-mode').value = settings.mode || 'observe';
    document.querySelectorAll('input[name="mode-choice"]').forEach((input) => {
      input.checked = input.value === $('#setting-mode').value;
    });
    $('#setting-interval').value = settings.interval_seconds || 30;
    $('#setting-retention').value = settings.backup_retention || 5;
    $('#setting-package').value = settings.max_package_mb || 256;
  }
  updatePolicySummary();
  initializeMemberRows(config);
  renderNextStep(setup);
  toggleActiveConfirmation();
  renderDashboard();
}

function toggleActiveConfirmation() {
  const active = $('#setting-mode').value === 'active';
  $('#active-effect').classList.toggle('hidden', !active);
}

function confirmActiveGroup() {
  return confirmarEnPanel({
    titulo: 'Activar la protección del grupo',
    mensajes: [
      'La política se aplicará a todos los Guardian del grupo.',
      'Sólo el portador de la IP enviará cada Vaultwarden. Los pasivos podrán detener brevemente su contenedor para aplicar una copia.',
      'En un alta automática, Guardian reservará la IP al final y Keepalived elegirá el portador.'
    ],
    accion: 'Activar protección'
  });
}

async function saveSettings(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  try {
    const previousMode = latestConfig.configuracion_operativa.mode;
    const payload = {
      mode: $('#setting-mode').value,
      interval_seconds: Number($('#setting-interval').value),
      backup_retention: Number($('#setting-retention').value),
      max_package_mb: Number($('#setting-package').value)
    };
    if (payload.mode === 'active' && previousMode !== 'active'
        && !(await confirmActiveGroup())) return;
    if (payload.mode === 'active' && previousMode !== 'active') {
      payload.confirm_active = true;
    }
    const button = $('#settings-form button[type="submit"]');
    button.disabled = true;
    button.textContent = 'Aplicando en todos…';
    $('#settings-message').textContent = 'Validando todos los Guardian antes de aplicar la misma política…';
    $('#settings-message').className = 'form-message';
    const result = await api('/api/v1/cluster/policy', {
      method: 'PUT',
      body: JSON.stringify(payload)
    });
    $('#settings-message').textContent = 'Aplicada correctamente en ' + String(result.nodos) + ' Guardian.';
    $('#settings-message').className = 'form-message good';
    showNotice('La política del grupo está unificada.', 'success');
    await refresh();
  } catch (error) {
    $('#settings-message').textContent = error.message;
    $('#settings-message').className = 'form-message danger';
  } finally {
    const button = $('#settings-form button[type="submit"]');
    button.disabled = !isAdmin();
    button.textContent = 'Guardar en todo el grupo';
  }
}

async function saveKeepalivedIntegration(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const input = $('#keepalived-integration-token');
  const token = input.value.trim();
  if (!token) {
    $('#keepalived-integration-message').textContent = 'Introduce el token de Keepalived.';
    $('#keepalived-integration-message').className = 'form-message danger';
    return;
  }
  const button = $('#keepalived-integration-form button[type="submit"]');
  try {
    button.disabled = true;
    $('#keepalived-integration-message').textContent = 'Guardando…';
    await api('/api/v1/integrations/keepalived', {
      method: 'PUT',
      body: JSON.stringify({token})
    });
    input.value = '';
    $('#keepalived-integration-message').textContent = 'Conexión guardada.';
    $('#keepalived-integration-message').className = 'form-message good';
    await refresh();
  } catch (error) {
    $('#keepalived-integration-message').textContent = error.message;
    $('#keepalived-integration-message').className = 'form-message danger';
  } finally {
    button.disabled = !isAdmin();
  }
}

async function saveApplicationSettings(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const button = $('#application-settings-form button[type="submit"]');
  try {
    button.disabled = true;
    $('#application-settings-message').textContent = 'Guardando…';
    $('#application-settings-message').className = 'form-message';
    await api('/api/v1/application-settings', {
      method: 'PUT',
      body: JSON.stringify({
        session_minutes: Number($('#application-session').value),
        history_max_mb: Number($('#application-history-size').value),
        history_max_entries: Number($('#application-history-entries').value),
        allow_insecure_portal: $('#application-portal-access').value === 'http'
      })
    });
    $('#application-settings-message').textContent = 'Ajustes guardados sin reiniciar el contenedor.';
    $('#application-settings-message').className = 'form-message good';
    await refresh();
  } catch (error) {
    $('#application-settings-message').textContent = error.message;
    $('#application-settings-message').className = 'form-message danger';
  } finally {
    button.disabled = !isAdmin();
  }
}

function integrationDate(value) {
  if (!value) return 'Nunca utilizado';
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString('es-ES');
}

function showApiToken(name, token) {
  $('#api-token-result-title').textContent = 'Token de ' + name;
  $('#api-token-result-value').textContent = token;
  $('#copy-api-token').textContent = 'Copiar token';
  $('#api-token-result').classList.remove('hidden');
}

function renderApiIntegrations(items) {
  apiIntegrationItems = Array.isArray(items) ? items : [];
  const target = $('#api-integration-list');
  const fragment = document.createDocumentFragment();
  if (!apiIntegrationItems.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'No hay aplicaciones autorizadas en este Guardian.';
    fragment.append(empty);
  }
  for (const item of apiIntegrationItems) {
    const row = document.createElement('article');
    row.className = 'integration-row';

    const head = document.createElement('div');
    head.className = 'integration-row-head';
    const identity = document.createElement('div');
    identity.className = 'integration-identity';
    const title = document.createElement('strong');
    title.textContent = item.name;
    const hint = document.createElement('small');
    hint.textContent = (item.legacy ? 'Token anterior · ' : 'Bearer · ')
      + String(item.token_hint || 'oculto');
    identity.append(title, hint);
    const usage = document.createElement('div');
    usage.className = 'integration-usage';
    const used = document.createElement('span');
    used.textContent = item.last_used_at
      ? 'Último uso: ' + integrationDate(item.last_used_at)
      : 'Todavía no se ha utilizado';
    const endpoint = document.createElement('small');
    endpoint.textContent = item.last_endpoint
      ? String(item.last_endpoint) + ' · ' + String(item.usage_count || 0) + ' usos'
      : 'Sin peticiones registradas';
    usage.append(used, endpoint);
    head.append(identity, usage);

    const editor = document.createElement('div');
    editor.className = 'integration-editor';
    const nameLabel = document.createElement('label');
    nameLabel.textContent = 'Nombre';
    const nameInput = document.createElement('input');
    nameInput.value = item.name;
    nameInput.maxLength = 80;
    nameLabel.append(nameInput);
    const tokenLabel = document.createElement('label');
    tokenLabel.textContent = 'Sustituir token';
    const tokenInput = document.createElement('input');
    tokenInput.type = 'password';
    tokenInput.minLength = 32;
    tokenInput.autocomplete = 'new-password';
    tokenInput.placeholder = 'Déjalo vacío para conservarlo';
    tokenLabel.append(tokenInput);
    const actions = document.createElement('div');
    actions.className = 'integration-actions';

    const save = document.createElement('button');
    save.type = 'button';
    save.className = 'button primary small';
    save.textContent = 'Guardar';
    save.addEventListener('click', () => saveApiApplication(
      item, nameInput.value, tokenInput.value));
    const reveal = document.createElement('button');
    reveal.type = 'button';
    reveal.className = 'button secondary small';
    reveal.textContent = 'Ver token';
    reveal.addEventListener('click', () => revealApiApplication(item));
    const rotate = document.createElement('button');
    rotate.type = 'button';
    rotate.className = 'button secondary small';
    rotate.textContent = 'Generar otro';
    rotate.addEventListener('click', () => rotateApiApplication(item));
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button danger small';
    remove.textContent = 'Eliminar';
    remove.addEventListener('click', () => deleteApiApplication(item));
    actions.append(save, reveal, rotate, remove);
    editor.append(nameLabel, tokenLabel, actions);
    row.append(head, editor);
    fragment.append(row);
  }
  target.replaceChildren(fragment);
  const count = apiIntegrationItems.length;
  $('#api-integration-badge').textContent = count === 1
    ? '1 aplicación' : String(count) + ' aplicaciones';
  $('#api-integration-badge').className = 'badge ' + (count ? 'badge-good' : '');
}

async function loadApiIntegrations() {
  const result = await api('/api/v1/integrations/applications');
  renderApiIntegrations(result.items || []);
}

async function saveApiIntegration(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const name = $('#api-integration-name').value.trim();
  const input = $('#api-integration-token');
  const token = input.value.trim();
  if (!name) {
    $('#api-integration-message').textContent = 'Introduce el nombre de la aplicación.';
    $('#api-integration-message').className = 'form-message danger';
    return;
  }
  const button = $('#api-integration-form button[type="submit"]');
  try {
    button.disabled = true;
    $('#api-integration-message').textContent = 'Creando…';
    const payload = {name};
    if (token) payload.token = token;
    const result = await api('/api/v1/integrations/applications', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    $('#api-integration-name').value = '';
    input.value = '';
    showApiToken(name, result.token);
    $('#api-integration-message').textContent = 'Aplicación creada.';
    $('#api-integration-message').className = 'form-message good';
    await loadApiIntegrations();
  } catch (error) {
    $('#api-integration-message').textContent = error.message;
    $('#api-integration-message').className = 'form-message danger';
  } finally {
    button.disabled = !isAdmin();
  }
}

async function saveApiApplication(item, name, token) {
  const payload = {name: String(name || '').trim()};
  if (String(token || '').trim()) payload.token = String(token).trim();
  try {
    const result = await api(
      '/api/v1/integrations/applications/' + encodeURIComponent(item.id),
      {method: 'PUT', body: JSON.stringify(payload)}
    );
    if (result.token) showApiToken(payload.name, result.token);
    $('#api-integration-message').textContent = 'Aplicación actualizada.';
    $('#api-integration-message').className = 'form-message good';
    await loadApiIntegrations();
  } catch (error) {
    $('#api-integration-message').textContent = error.message;
    $('#api-integration-message').className = 'form-message danger';
  }
}

async function revealApiApplication(item) {
  try {
    const result = await api(
      '/api/v1/integrations/applications/' + encodeURIComponent(item.id) + '/token');
    showApiToken(item.name, result.token);
  } catch (error) {
    $('#api-integration-message').textContent = error.message;
    $('#api-integration-message').className = 'form-message danger';
  }
}

async function rotateApiApplication(item) {
  if (!isAdmin()) return;
  const accepted = await confirmarEnPanel({
    titulo: 'Generar otro token',
    mensajes: ['El token actual de ' + item.name + ' dejará de funcionar inmediatamente.'],
    accion: 'Generar token',
    peligro: true
  });
  if (!accepted) return;
  try {
    const result = await api(
      '/api/v1/integrations/applications/' + encodeURIComponent(item.id) + '/rotate',
      {method: 'POST', body: JSON.stringify({})}
    );
    showApiToken(item.name, result.token);
    $('#api-integration-message').textContent = 'Token sustituido.';
    $('#api-integration-message').className = 'form-message good';
    await loadApiIntegrations();
  } catch (error) {
    $('#api-integration-message').textContent = error.message;
    $('#api-integration-message').className = 'form-message danger';
  }
}

async function deleteApiApplication(item) {
  if (!isAdmin()) return;
  const accepted = await confirmarEnPanel({
    titulo: 'Eliminar acceso a la API',
    mensajes: [item.name + ' dejará de acceder a Vault Guardian inmediatamente.'],
    accion: 'Eliminar aplicación',
    peligro: true
  });
  if (!accepted) return;
  try {
    await api(
      '/api/v1/integrations/applications/' + encodeURIComponent(item.id),
      {method: 'DELETE'}
    );
    $('#api-token-result').classList.add('hidden');
    $('#api-integration-message').textContent = 'Aplicación eliminada.';
    $('#api-integration-message').className = 'form-message good';
    await loadApiIntegrations();
  } catch (error) {
    $('#api-integration-message').textContent = error.message;
    $('#api-integration-message').className = 'form-message danger';
  }
}

async function savePrivateCa(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const input = $('#private-ca-pem');
  const pem = input.value.trim();
  if (!pem) {
    $('#private-ca-message').textContent = 'Pega el certificado o la cadena PEM.';
    $('#private-ca-message').className = 'form-message danger';
    return;
  }
  const button = $('#private-ca-form button[type="submit"]');
  try {
    button.disabled = true;
    $('#private-ca-message').textContent = 'Validando y guardando…';
    await api('/api/v1/tls/private-ca', {
      method: 'PUT',
      body: JSON.stringify({pem})
    });
    input.value = '';
    $('#private-ca-message').textContent = 'CA privada guardada.';
    $('#private-ca-message').className = 'form-message good';
    await refresh();
  } catch (error) {
    $('#private-ca-message').textContent = error.message;
    $('#private-ca-message').className = 'form-message danger';
  } finally {
    button.disabled = !isAdmin();
  }
}

async function disablePrivateCa() {
  if (!isAdmin()) return;
  const accepted = await confirmarEnPanel({
    titulo: 'Dejar de utilizar la CA privada',
    mensajes: ['Vault Guardian volverá a confiar únicamente en las CA del sistema.'],
    accion: 'Usar CA del sistema'
  });
  if (!accepted) return;
  try {
    await api('/api/v1/tls/private-ca', {method: 'DELETE'});
    $('#private-ca-pem').value = '';
    $('#private-ca-message').textContent = 'Se utilizarán las CA del sistema.';
    $('#private-ca-message').className = 'form-message good';
    await refresh();
  } catch (error) {
    $('#private-ca-message').textContent = error.message;
    $('#private-ca-message').className = 'form-message danger';
  }
}

const CLUSTER_LABELS = {
  protected: 'Protegido',
  degraded: 'Degradado',
  unknown: 'Desconocido',
  conflict: 'Conflicto',
  unconfigured: 'Sin configurar'
};

function humanResult(value) {
  const raw = String(value || '');
  const labels = {
    sin_cambios: 'Sin cambios',
    sincronizado: 'Sincronizado',
    preparado: 'Preparado',
    bloqueado: 'Bloqueado',
    omitido: 'Omitido',
    en_espera: 'En espera del portador',
    error: 'Error'
  };
  if (labels[raw]) return labels[raw];
  const readable = raw.replaceAll('_', ' ');
  return readable ? readable.charAt(0).toUpperCase() + readable.slice(1) : 'Sin actividad';
}

function modeLabel(value) {
  return ({observe: 'Pausada', 'dry-run': 'Simulación', active: 'Activa'})[value] || String(value || '—');
}

function formatTimestamp(value) {
  if (!value) return 'Sin fecha';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString('es-ES', {
    day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'
  });
}

function replaceDashboardRows(selector, rows, emptyText) {
  const target = $(selector);
  const fragment = document.createDocumentFragment();
  if (!rows.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = emptyText;
    fragment.append(empty);
  } else {
    for (const row of rows) {
      const item = document.createElement('article');
      item.className = 'dashboard-row ' + (row.tone || '');
      const marker = document.createElement('span');
      marker.className = 'dashboard-row-marker';
      marker.setAttribute('aria-hidden', 'true');
      const copy = document.createElement('span');
      const title = document.createElement('strong');
      const detail = document.createElement('small');
      title.textContent = row.title;
      detail.textContent = row.detail || '';
      copy.append(title, detail);
      const state = document.createElement('span');
      state.className = 'dashboard-row-state';
      state.textContent = row.state || '';
      item.append(marker, copy, state);
      fragment.append(item);
    }
  }
  target.replaceChildren(fragment);
}

function latestEvent() {
  if (historyItems.length) return historyItems[0];
  const events = ((latestStatus && latestStatus.instancias) || [])
    .map((item) => item.last_event)
    .filter(Boolean)
    .sort((left, right) => String(right.at || '').localeCompare(String(left.at || '')));
  return events[0] || null;
}

function renderDashboard() {
  if (!latestCluster || !latestStatus || !latestSetup) return;
  const nodes = latestCluster.nodes || [];
  const services = latestCluster.instances || [];
  const reachable = Number(latestCluster.reachable_nodes || 0);
  const expected = Number(latestCluster.expected_nodes || nodes.length);
  const protectedCount = services.filter((item) => item.state === 'protected').length;
  const policy = latestStatus.politica || latestCluster.policy || {};
  const event = latestEvent();

  text('#overview-nodes', String(reachable) + '/' + String(expected));
  text('#overview-nodes-detail', reachable === expected ? 'Todos disponibles' : String(expected - reachable) + ' sin conexión');
  text('#overview-protected', String(protectedCount) + '/' + String(services.length));
  text('#overview-protected-detail', protectedCount === services.length && services.length ? 'Protección completa' : 'Requiere revisión');
  text('#overview-policy', modeLabel(policy.mode));
  text('#overview-policy-detail', 'Cada ' + String(policy.interval_seconds || '—') + ' s · '
    + String(policy.backup_retention || '—') + ' backups');
  text('#overview-last-event', event ? (event.instance ? friendlyInstanceName(event.instance) : 'Sistema') : 'Sin actividad');
  text('#overview-last-event-detail', event
    ? humanResult((event.result || {}).estado || 'evento') + ' · ' + formatTimestamp(event.at)
    : 'No hay eventos registrados');

  replaceDashboardRows('#overview-services', services.map((item) => ({
    title: friendlyInstanceName(item.id),
    detail: 'Portador: ' + String(item.porter || 'sin confirmar') + ' · Réplicas: '
      + String(item.confirmed_nodes || 0) + '/' + String(item.expected_nodes || 0),
    state: CLUSTER_LABELS[item.state] || item.state,
    tone: item.state === 'protected' ? 'good' : 'warning'
  })), 'No hay Vaultwarden registrados.');
  $('#overview-services-badge').textContent = String(protectedCount) + '/' + String(services.length);
  $('#overview-services-badge').className = 'badge ' + (protectedCount === services.length && services.length ? 'badge-good' : 'badge-warning');

  replaceDashboardRows('#overview-servers', nodes.map((node) => ({
    title: String(node.name || 'Servidor'),
    detail: node.local ? 'Este servidor' : 'Miembro del grupo',
    state: node.reachable ? 'Disponible' : 'Sin conexión',
    tone: node.reachable ? 'good' : 'danger'
  })), 'No hay servidores configurados.');
  $('#overview-servers-badge').textContent = String(reachable) + '/' + String(expected);
  $('#overview-servers-badge').className = 'badge ' + (reachable === expected && expected ? 'badge-good' : 'badge-warning');

  const issues = [];
  const requirements = latestSetup.requirements || {};
  for (const [key, label] of Object.entries(SETUP_LABELS)) {
    if (!(latestSetup.checks || {})[key] && requirements[key] !== false) {
      issues.push({title: label, detail: 'Requisito pendiente', state: 'Pendiente', tone: 'danger'});
    }
  }
  if (policy.mode !== 'active') {
    issues.push({title: 'Política de protección', detail: 'La replicación continua no está activa', state: modeLabel(policy.mode), tone: 'warning'});
  }
  if (!latestCluster.policy_consistent) {
    issues.push({title: 'Política del grupo', detail: 'Los servidores no comparten la misma configuración', state: 'Inconsistente', tone: 'danger'});
  }
  for (const node of nodes.filter((item) => !item.reachable)) {
    issues.push({title: String(node.name || 'Servidor'), detail: 'No responde al resto del grupo', state: 'Sin conexión', tone: 'danger'});
  }
  for (const service of services.filter((item) => item.state !== 'protected')) {
    issues.push({title: friendlyInstanceName(service.id), detail: 'La protección no está completa', state: CLUSTER_LABELS[service.state] || service.state, tone: 'warning'});
  }
  if (!issues.length) {
    issues.push({title: 'Sin incidencias activas', detail: 'El grupo no requiere intervención', state: 'Correcto', tone: 'good'});
  }
  replaceDashboardRows('#overview-issues', issues, 'Sin incidencias activas.');
  $('#overview-issues-badge').textContent = issues[0].tone === 'good' ? '0' : String(issues.length);
  $('#overview-issues-badge').className = 'badge ' + (issues[0].tone === 'good' ? 'badge-good' : 'badge-warning');

  const recent = historyItems.slice(0, 4).map((item) => ({
    title: item.instance ? friendlyInstanceName(item.instance) : 'Sistema',
    detail: formatTimestamp(item.at),
    state: humanResult((item.result || {}).estado || 'evento'),
    tone: (item.result || {}).estado === 'error' ? 'danger' : ''
  }));
  replaceDashboardRows('#overview-activity', recent, 'No hay actividad registrada.');
}

function endpointDefaults(value) {
  try {
    const parsed = new URL(value);
    return {
      node_ip: parsed.hostname
    };
  } catch (error) {
    return {node_ip: ''};
  }
}

function updateMemberPreview(row) {
  const name = row.querySelector('.member-name').value.trim();
  const ip = row.querySelector('.member-ip').value.trim();
  row.querySelector('[data-member-name-preview]').textContent = name || 'Sin nombre';
  row.querySelector('[data-member-ip-preview]').textContent = ip || 'Sin IP fija';
}

function addMemberRow(member, isLocal) {
  const row = document.createElement('details');
  row.className = 'member-row';
  row.open = !member;
  row.innerHTML = ''
    + '<summary class="member-row-summary">'
    + '<span class="member-row-number" data-member-number>Servidor</span>'
    + '<span class="member-preview"><small>Nombre</small><strong data-member-name-preview>Sin nombre</strong></span>'
    + '<span class="member-preview"><small>IP fija</small><strong data-member-ip-preview>Sin IP fija</strong></span>'
    + '<span class="member-row-toggle" aria-hidden="true"></span>'
    + '</summary>'
    + '<div class="member-row-body">'
    + '<div class="member-row-head">'
    + '<label class="member-local-choice"><input class="member-local" type="radio" name="cluster-local"><span>Este es el panel que estoy usando</span></label>'
    + '<button class="button small secondary member-remove" type="button">Quitar servidor</button>'
    + '</div>'
    + '<div class="member-row-fields">'
    + '<label><span>Nombre del servidor</span><input class="member-name" required pattern="[A-Za-z0-9][A-Za-z0-9_.-]*" placeholder="servidor-1"><small>Nombre estable y único dentro del grupo.</small></label>'
    + '<label><span>IP fija del servidor</span><input class="member-ip" required placeholder="192.0.2.10"><small>Ejemplo reservado para documentación; escribe la dirección propia del servidor, no la IP flotante.</small></label>'
    + '<label><span>URL de Vault Guardian</span><input class="member-url" required type="url" placeholder="http://192.0.2.10:6062"><small>Ejemplo reservado; escribe el panel de Guardian accesible desde los demás miembros.</small></label>'
    + '<label><span>URL de floating-IP</span><input class="member-floating" required type="url" placeholder="http://192.0.2.10:puerto"><small>Ejemplo reservado; escribe la API de floating-IP que se ejecuta en ese servidor.</small></label>'
    + '</div>'
    + '</div>';
  row.querySelector('.member-name').value = (member && member.name) || '';
  row.querySelector('.member-ip').value = (member && member.node_ip) || '';
  row.querySelector('.member-url').value = (member && member.guardian_url) || '';
  row.querySelector('.member-floating').value = (member && member.floating_api) || '';
  row.dataset.vaultwardenRoot = (member && member.vaultwarden_root) || '';
  row.querySelector('.member-local').checked = Boolean(isLocal);
  row.querySelector('.member-name').addEventListener('input', () => updateMemberPreview(row));
  row.querySelector('.member-ip').addEventListener('input', () => updateMemberPreview(row));
  row.querySelector('.member-url').addEventListener('blur', (event) => {
    const defaults = endpointDefaults(event.target.value);
    if (!row.querySelector('.member-ip').value) {
      row.querySelector('.member-ip').value = defaults.node_ip;
      updateMemberPreview(row);
    }
  });
  row.querySelector('.member-remove').addEventListener('click', () => {
    const wasLocal = row.querySelector('.member-local').checked;
    row.remove();
    if (wasLocal && $('.member-row .member-local')) {
      $('.member-row .member-local').checked = true;
    }
    updateMemberRowNumbers();
  });
  $('#member-rows').append(row);
  updateMemberPreview(row);
  updateMemberRowNumbers();
  return row;
}

function updateMemberRowNumbers() {
  document.querySelectorAll('.member-row [data-member-number]').forEach((element, index) => {
    element.textContent = 'Servidor ' + String(index + 1);
  });
}

function initializeMemberRows(config) {
  if (memberRowsInitialized) return;
  memberRowsInitialized = true;
  const settings = config.configuracion_operativa || {};
  $('#cluster-allow-http').checked = Boolean(settings.allow_insecure_http);
  let localUrl = window.location.origin;
  try {
    const parsed = new URL(window.location.origin);
    parsed.hostname = settings.node_ip || parsed.hostname;
    localUrl = parsed.origin;
  } catch (error) { /* usar el origen del navegador */ }
  addMemberRow({
    name: settings.node || '',
    node_ip: settings.node_ip || '',
    guardian_url: localUrl,
    floating_api: settings.floating_api || '',
    vaultwarden_root: settings.vaultwarden_root || ''
  }, true);
  for (const [name, guardianUrl] of Object.entries(settings.peers || {})) {
    const defaults = endpointDefaults(guardianUrl);
    const clusterNode = ((latestCluster && latestCluster.nodes) || [])
      .find((item) => item.name === name);
    const topology = (clusterNode && clusterNode.status && clusterNode.status.topologia) || {};
    addMemberRow({
      name: name,
      node_ip: topology.node_ip || defaults.node_ip,
      guardian_url: guardianUrl,
      floating_api: topology.floating_api || '',
      vaultwarden_root: topology.vaultwarden_root || ''
    }, false);
  }
}

function collectMembers() {
  return Array.from(document.querySelectorAll('.member-row')).map((row) => ({
    name: row.querySelector('.member-name').value.trim(),
    node_ip: row.querySelector('.member-ip').value.trim(),
    guardian_url: row.querySelector('.member-url').value.trim(),
    floating_api: row.querySelector('.member-floating').value.trim(),
    vaultwarden_root: row.dataset.vaultwardenRoot || '',
    local: row.querySelector('.member-local').checked
  }));
}

function reconciliationMessage(result) {
  const count = Number(result.replicas_creadas || 0);
  if (result.estado === 'reconciliado') {
    return 'Grupo protegido: Guardian creó ' + String(count)
      + (count === 1 ? ' réplica ausente' : ' réplicas ausentes')
      + ' y realizó una sincronización final.';
  }
  if (result.estado === 'reconciliacion_parcial') {
    return 'Las réplicas nuevas se crearon, pero el grupo sigue '
      + String(result.cluster_state || 'degradado') + '. Revisa Operación.';
  }
  if (result.estado === 'pendiente_modo_activo') {
    return 'La topología se guardó, pero hay réplicas pendientes. Activa la protección '
      + 'del grupo y pulsa «Comprobar y completar réplicas».';
  }
  if (result.cluster_state && result.cluster_state !== 'protected'
      && result.cluster_state !== 'unconfigured') {
    return 'No faltan contenedores, pero el grupo sigue ' + String(result.cluster_state)
      + '. Revisa las huellas y la conectividad en Operación.';
  }
  return 'No faltaba ninguna réplica; los Vaultwarden existentes ya estaban presentes en todos los servidores.';
}

async function saveCluster(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const form = $('#cluster-form');
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  const members = collectMembers();
  const local = members.find((item) => item.local);
  if (!local) {
    $('#cluster-message').textContent = 'Marca qué fila corresponde al panel que estás viendo.';
    $('#cluster-message').className = 'form-message danger';
    return;
  }
  const policy = {
    mode: $('#setting-mode').value,
    interval_seconds: Number($('#setting-interval').value),
    backup_retention: Number($('#setting-retention').value),
    max_package_mb: Number($('#setting-package').value)
  };
  if (policy.mode === 'active') {
    if (!(await confirmActiveGroup())) return;
  } else {
    const confirmed = await confirmarEnPanel({
      titulo: 'Guardar servidores del grupo',
      mensajes: [
        'Guardian validará todos los servidores y repartirá la misma configuración del grupo.',
        'No modificará Vaultwarden ni moverá la IP flotante.'
      ],
      accion: 'Guardar y distribuir'
    });
    if (!confirmed) return;
  }
  const submit = $('#cluster-form button[type="submit"]');
  const reconcileButton = $('#reconcile-members');
  try {
    reconciliationRunning = true;
    submit.disabled = true;
    reconcileButton.disabled = true;
    submit.textContent = 'Guardando y completando réplicas…';
    $('#cluster-message').textContent = 'Validando todos los Guardian. Si un servidor es nuevo, se clonarán allí los Vaultwarden existentes desde su portador actual…';
    $('#cluster-message').className = 'form-message';
    const result = await api('/api/v1/cluster/configuration', {
      method: 'PUT',
      body: JSON.stringify({
        local_name: local.name,
        members: members.map(({local: ignored, ...item}) => item),
        allow_insecure_http: $('#cluster-allow-http').checked,
        policy: policy,
        confirm_active: policy.mode === 'active'
      })
    });
    const reconciliation = result.reconciliacion || {};
    const identities = result.identidades || {};
    const identityFailures = Object.keys(identities.failed || {});
    const identityMessage = identityFailures.length
      ? ' Identidades pendientes en: ' + identityFailures.join(', ') + '.'
      : (Array.isArray(identities.updated) && identities.updated.length
        ? ' Acceso distribuido a todos los Guardian.'
        : '');
    $('#cluster-message').textContent = 'Configuración distribuida en '
      + String(result.nodos) + ' Guardian. ' + reconciliationMessage(reconciliation)
      + identityMessage;
    $('#cluster-message').className = 'form-message '
      + (identityFailures.length
        || reconciliation.estado === 'pendiente_modo_activo'
        || reconciliation.estado === 'reconciliacion_parcial' ? 'warning' : 'good');
    await refresh();
  } catch (error) {
    $('#cluster-message').textContent = error.message;
    $('#cluster-message').className = 'form-message danger';
  } finally {
    reconciliationRunning = false;
    submit.disabled = !isAdmin();
    reconcileButton.disabled = !isAdmin();
    submit.textContent = 'Guardar servidores del grupo';
  }
}

async function reconcileMembers() {
  if (!isAdmin() || reconciliationRunning) return;
  const confirmed = await confirmarEnPanel({
    titulo: 'Comprobar y completar réplicas',
    mensajes: [
      'Guardian buscará Vaultwarden ausentes en los servidores del grupo.',
      'Sólo el portador sano de cada IP podrá crear la copia. No se reservará ninguna IP nueva.'
    ],
    accion: 'Comprobar réplicas'
  });
  if (!confirmed) return;
  const button = $('#reconcile-members');
  reconciliationRunning = true;
  button.disabled = true;
  button.textContent = 'Comprobando y clonando…';
  $('#cluster-message').textContent = 'Comparando instancias. Las réplicas ausentes se crearán y validarán una por una…';
  $('#cluster-message').className = 'form-message';
  try {
    const result = await api('/api/v1/reconciliation', {
      method: 'POST',
      body: JSON.stringify({confirm: true})
    });
    $('#cluster-message').textContent = reconciliationMessage(result);
    $('#cluster-message').className = 'form-message '
      + (result.estado === 'reconciliado' || result.estado === 'sin_cambios'
        ? 'good' : 'warning');
    await refresh();
  } catch (error) {
    $('#cluster-message').textContent = 'No se pudo completar el grupo: ' + error.message;
    $('#cluster-message').className = 'form-message danger';
  } finally {
    reconciliationRunning = false;
    button.disabled = !isAdmin();
    button.textContent = 'Comprobar y completar réplicas';
  }
}

function renderCluster(data) {
  latestCluster = data;
  const state = data.state || 'unknown';
  const label = CLUSTER_LABELS[state] || state;
  $('#cluster-badge').textContent = label;
  $('#cluster-badge').className = 'badge state-' + state;
  $('#top-protection').textContent = label;
  $('#top-protection').className = 'chip state-' + state;
  const consistency = $('#policy-consistency');
  consistency.textContent = data.policy_consistent ? 'misma política' : 'política distinta';
  consistency.className = 'badge ' + (data.policy_consistent ? 'badge-good' : 'badge-warning');

  const members = $('#cluster-members');
  const memberFragment = document.createDocumentFragment();
  for (const node of data.nodes || []) {
    const item = document.createElement('div');
    item.className = 'member-chip ' + (node.reachable ? 'reachable' : 'unreachable');
    const marker = document.createElement('span');
    marker.className = 'member-status-icon';
    marker.setAttribute('aria-hidden', 'true');
    marker.textContent = node.reachable ? '✓' : '!';
    const copy = document.createElement('div');
    copy.className = 'member-status-copy';
    const name = document.createElement('strong');
    name.className = 'member-status-name';
    name.textContent = String(node.name || 'sin nombre');
    const detail = document.createElement('small');
    detail.className = 'member-status-detail';
    detail.textContent = node.local
      ? 'Este panel · identidad local'
      : (node.reachable ? 'Conectado al grupo' : 'Sin conexión');
    copy.append(name, detail);
    item.append(marker, copy);
    memberFragment.append(item);
  }
  if (!memberFragment.children.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'Todavía no hay miembros configurados.';
    memberFragment.append(empty);
  }
  members.replaceChildren(memberFragment);

  const serverTarget = $('#cluster-servers');
  const serverFragment = document.createDocumentFragment();
  for (const node of data.nodes || []) {
    const card = document.createElement('article');
    card.className = 'cluster-item ' + (node.reachable ? 'reachable' : 'unreachable');
    const heading = document.createElement('strong');
    heading.className = 'cluster-item-title';
    heading.textContent = String(node.name || 'servidor sin nombre');
    const detail = document.createElement('span');
    detail.className = 'cluster-item-detail';
    detail.textContent = node.reachable
      ? (node.local ? 'Este servidor' : 'Miembro remoto') + ' · modo ' + modeLabel((node.status || {}).modo)
      : 'No accesible · ' + String(node.error || 'sin respuesta');
    card.append(heading, detail);
    serverFragment.append(card);
  }
  if (!serverFragment.children.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'No hay servidores configurados.';
    serverFragment.append(empty);
  }
  serverTarget.replaceChildren(serverFragment);

  const serviceTarget = $('#cluster-services');
  const serviceFragment = document.createDocumentFragment();
  for (const instance of data.instances || []) {
    const card = document.createElement('article');
    card.className = 'cluster-item instance-state state-' + instance.state;
    const heading = document.createElement('strong');
    heading.className = 'cluster-item-title';
    heading.textContent = friendlyInstanceName(instance.id);
    const detail = document.createElement('span');
    detail.className = 'cluster-item-detail';
    detail.textContent = (CLUSTER_LABELS[instance.state] || instance.state)
      + ' · portador: ' + String(instance.porter || 'no confirmado')
      + ' · réplicas: ' + String(instance.confirmed_nodes) + '/' + String(instance.expected_nodes);
    card.append(heading, detail);
    serviceFragment.append(card);
  }
  if (!serviceFragment.children.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'No hay Vaultwarden configurados.';
    serviceFragment.append(empty);
  }
  serviceTarget.replaceChildren(serviceFragment);
  renderDashboard();
}

function renderHistory(items) {
  historyItems = Array.isArray(items) ? items : [];
  const target = $('#history');
  const pages = Math.max(1, Math.ceil(historyItems.length / HISTORY_PAGE_SIZE));
  historyPage = Math.min(Math.max(1, historyPage), pages);
  const start = (historyPage - 1) * HISTORY_PAGE_SIZE;
  const visible = historyItems.slice(start, start + HISTORY_PAGE_SIZE);
  const fragment = document.createDocumentFragment();

  $('#history-badge').textContent = historyItems.length + ' eventos';
  $('#history-badge').className = 'badge ' + (historyItems.length ? 'badge-good' : '');
  if (!visible.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'Todavía no hay operaciones registradas.';
    fragment.append(empty);
  } else {
    for (const event of visible) {
      const row = document.createElement('article');
      row.className = 'history-item';
      const result = event.result || {};
      const title = document.createElement('strong');
      title.textContent = (event.instance ? friendlyInstanceName(event.instance) : 'Sistema')
        + ' · ' + humanResult(result.estado || 'evento');
      const detail = document.createElement('span');
      detail.textContent = formatTimestamp(event.at) + (result.motivo ? ' · ' + result.motivo : '');
      row.append(title, detail);
      fragment.append(row);
    }
  }
  target.replaceChildren(fragment);
  $('#history-pagination').classList.toggle('hidden', historyItems.length <= HISTORY_PAGE_SIZE);
  $('#history-page').textContent = 'Página ' + String(historyPage) + ' de ' + String(pages);
  $('#history-previous').disabled = historyPage <= 1;
  $('#history-next').disabled = historyPage >= pages;
  renderDashboard();
}

async function loadHistory() {
  if (!isAdmin()) {
    historyItems = [];
    $('#history').innerHTML = '<span class="empty">Se requiere una sesión activa.</span>';
    $('#history-badge').textContent = 'requiere acceso';
    $('#history-badge').className = 'badge';
    $('#history-pagination').classList.add('hidden');
    renderDashboard();
    return;
  }
  try {
    const data = await api('/api/v1/history?limit=50');
    renderHistory(data.items || []);
  } catch (error) {
    $('#history').textContent = 'No se pudo cargar el historial: ' + error.message;
  }
}

function syncMessage(result, name) {
  const state = result.estado || 'finalizada';
  const actor = result.ejecutado_por ? ' por ' + result.ejecutado_por : '';
  if (state === 'sincronizado') {
    return name + ' sincronizado' + actor + ': '
      + String(result.destinos_ok || 0) + '/' + String(result.destinos_esperados || 0)
      + ' réplicas actualizadas.';
  }
  if (state === 'sin_cambios') return name + ' no tenía cambios pendientes' + actor + '.';
  if (state === 'preparado') return name + ' comprobado' + actor + '; simulación terminada sin enviar datos.';
  if (state === 'en_espera') return name + ' está esperando al portador de su IP.';
  if (state === 'omitido') return name + ' no se sincronizó: ' + String(result.motivo || 'operación omitida') + '.';
  if (state === 'bloqueado' || state === 'error') {
    return name + ' no se sincronizó: ' + String(result.motivo || humanResult(state)) + '.';
  }
  return name + ': ' + humanResult(state) + actor + '.';
}

function setSyncStatus(identifier, message, kind) {
  const target = Array.from(document.querySelectorAll('[data-sync-state]'))
    .find((element) => element.dataset.syncState === identifier);
  if (!target) return;
  target.textContent = message;
  target.className = 'operation-state' + (kind ? ' ' + kind : '');
}

async function syncInstance(identifier, button) {
  if (!isAdmin() || runningSyncs.has(identifier)) return;
  const name = friendlyInstanceName(identifier);
  const confirmed = await confirmarEnPanel({
    titulo: 'Sincronizar ' + name,
    mensajes: [
      'Se sincronizará únicamente ' + name + '.',
      'Guardian localizará qué servidor porta su IP y enviará esa copia a los demás.'
    ],
    accion: 'Sincronizar ahora'
  });
  if (!confirmed) return;
  runningSyncs.add(identifier);
  button.disabled = true;
  button.textContent = 'Sincronizando ' + name + '…';
  setSyncStatus(identifier, 'Iniciando ' + name + ' y localizando su portador…', 'running');
  showNotice('Sincronización iniciada para ' + name + '. Puedes seguir el progreso en su tarjeta.');
  try {
    const result = await api('/api/v1/instances/' + encodeURIComponent(identifier) + '/sync', {
      method: 'POST'
    });
    const successful = ['sincronizado', 'sin_cambios', 'preparado'].includes(result.estado);
    const message = syncMessage(result, name);
    setSyncStatus(identifier, 'Finalizada · ' + message, successful ? 'good' : 'warning');
    showNotice(message, successful ? 'success' : 'error');
    runningSyncs.delete(identifier);
    await refresh();
  } catch (error) {
    const message = 'Falló la sincronización de ' + name + ': ' + error.message;
    setSyncStatus(identifier, message, 'danger');
    showNotice(message, 'error');
  } finally {
    runningSyncs.delete(identifier);
    const currentButton = Array.from(document.querySelectorAll('[data-sync-button]'))
      .find((element) => element.dataset.syncButton === identifier);
    if (currentButton) {
      currentButton.disabled = false;
      currentButton.textContent = 'Sincronizar sólo ' + name;
    }
  }
}
const READINESS_REASONS = {
  container_not_running: 'contenedor detenido',
  floating_state_unknown: 'VIP desconocida',
  replication_conflict: 'conflicto de réplica',
  local_health_not_confirmed: 'salud local no confirmada',
  missing_fingerprint: 'sin huella local',
  fingerprint_not_confirmed: 'huella sin confirmar',
  behind_current_porter: 'réplica atrasada',
  reachable_nodes_diverge: 'los nodos divergen',
  replica_too_old_for_failover: 'réplica demasiado antigua'
};

function readinessCell(identifier) {
  return Array.from(document.querySelectorAll('[data-readiness]'))
    .find((element) => element.dataset.readiness === identifier);
}

function readinessPresentation(result) {
  if (!result) return {text: 'Pendiente de comprobar', className: 'muted'};
  if (result.error) return {text: result.error, className: 'warning'};
  const reasons = (result.reasons || []).map((reason) => READINESS_REASONS[reason] || reason);
  return result.ready
    ? {text: result.role === 'porter' ? 'Sí · portador actual' : 'Sí · candidato', className: 'good'}
    : {text: 'No' + (reasons.length ? ' · ' + reasons.join(', ') : ''), className: 'warning'};
}

function updateReadiness(identifier, result) {
  readinessResults.set(identifier, result);
  const target = readinessCell(identifier);
  if (!target) return;
  const presentation = readinessPresentation(result);
  target.textContent = presentation.text;
  target.className = presentation.className;
}

async function loadReadiness(items) {
  await Promise.all((items || []).map(async (item) => {
    let result;
    try {
      result = await api('/api/v1/instances/' + encodeURIComponent(item.id) + '/readiness');
    } catch (error) {
      if (error.status === 503 && error.body) {
        result = error.body;
      } else {
        result = {error: 'No disponible', reasons: []};
      }
    }
    updateReadiness(item.id, result);
  }));
}

function serviceFact(label, value, className, readinessId) {
  const wrapper = document.createElement('div');
  wrapper.className = 'service-fact';
  const caption = document.createElement('span');
  const content = document.createElement('strong');
  caption.textContent = label;
  content.textContent = value || '—';
  if (className) content.className = className;
  if (readinessId) content.dataset.readiness = readinessId;
  wrapper.append(caption, content);
  return wrapper;
}

function renderInstances(items, configItems) {
  const target = $('#instances');
  const fragment = document.createDocumentFragment();
  const byId = new Map((configItems || []).map((item) => [item.id, item]));
  const clusterById = new Map(((latestCluster && latestCluster.instances) || [])
    .map((item) => [item.id, item]));
  if (!items || !items.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'Todavía no has registrado ningún Vaultwarden.';
    fragment.append(empty);
    target.replaceChildren(fragment);
    return;
  }

  items.forEach((item, index) => {
    const config = byId.get(item.id) || {};
    const cluster = clusterById.get(item.id) || {};
    const floating = item.floating_ip || {};
    const result = item['último_resultado'] || {};
    const replicationEnabled = item.replicacion === true || config.replication_enabled === true;
    const name = friendlyInstanceName(item.id, index);
    const state = replicationEnabled ? (cluster.state || 'unknown') : 'unconfigured';
    const card = document.createElement('article');
    card.className = 'service-card service-state-' + state;

    const heading = document.createElement('div');
    heading.className = 'service-card-head';
    const identity = document.createElement('div');
    const title = document.createElement('h2');
    const subtitle = document.createElement('small');
    title.textContent = name;
    subtitle.textContent = replicationEnabled ? 'Replicación habilitada' : 'Replicación pausada';
    identity.append(title, subtitle);
    const protection = document.createElement('span');
    protection.className = 'badge ' + (state === 'protected' ? 'badge-good' : 'badge-warning');
    protection.textContent = replicationEnabled ? (CLUSTER_LABELS[state] || state) : 'Pausado';
    heading.append(identity, protection);

    const facts = document.createElement('div');
    facts.className = 'service-facts';
    const readiness = readinessPresentation(readinessResults.get(item.id));
    facts.append(
      serviceFact('Portador actual', floating.conocido ? String(floating.portador || 'sin portador') : 'Sin confirmar', floating.conocido ? 'good' : 'warning'),
      serviceFact('Réplicas confirmadas', cluster.expected_nodes
        ? String(cluster.confirmed_nodes || 0) + '/' + String(cluster.expected_nodes)
        : 'Sin datos', cluster.state === 'protected' ? 'good' : 'warning'),
      serviceFact('Estado en este servidor', floating.salud_local === true ? 'Sano' : 'No confirmado', floating.salud_local === true ? 'good' : 'warning'),
      serviceFact('Puede recibir la IP flotante', readiness.text, readiness.className, item.id)
    );

    const operation = document.createElement('div');
    operation.dataset.syncState = item.id;
    operation.className = 'service-last-operation';
    const operationLabel = document.createElement('span');
    const operationText = document.createElement('strong');
    operationLabel.textContent = 'Última operación';
    if (runningSyncs.has(item.id)) {
      operationText.textContent = 'Sincronización en curso…';
      operation.classList.add('running');
    } else if (result.estado) {
      operationText.textContent = syncMessage(result, name);
    } else {
      operationText.textContent = 'Sin operaciones registradas.';
    }
    operation.append(operationLabel, operationText);

    const actions = document.createElement('div');
    actions.className = 'instance-actions';
    if (isAdmin()) {
      const sync = document.createElement('button');
      sync.className = 'button small primary';
      sync.type = 'button';
      sync.dataset.syncButton = item.id;
      sync.textContent = runningSyncs.has(item.id) ? 'Sincronizando…' : 'Sincronizar';
      sync.disabled = !replicationEnabled || runningSyncs.has(item.id);
      sync.title = replicationEnabled ? 'Sincroniza únicamente ' + name : 'Activa primero la replicación de este Vaultwarden';
      sync.addEventListener('click', () => syncInstance(item.id, sync));
      const edit = document.createElement('button');
      edit.className = 'button small secondary';
      edit.type = 'button';
      edit.textContent = 'Editar';
      edit.addEventListener('click', () => editInstance(config));
      const remove = document.createElement('button');
      remove.className = 'button small danger';
      remove.type = 'button';
      remove.textContent = 'Quitar';
      remove.addEventListener('click', () => deleteInstance(item.id));
      actions.append(sync, edit, remove);
    }
    card.append(heading, facts, operation, actions);
    fragment.append(card);
  });
  target.replaceChildren(fragment);
  void loadReadiness(items);
}

function renderDiscovery(data) {
  const target = $('#discovery');
  target.textContent = '';
  const roots = data.raices || [];
  const directories = data.directorios || [];
  if (!directories.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = roots.length
      ? 'No hay subdirectorios detectables dentro de las raíces montadas.'
      : 'No hay raíces de datos disponibles.';
    target.append(empty);
    return;
  }
  for (const item of directories) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'discovery-item';
    button.disabled = !isAdmin();
    const title = document.createElement('strong');
    title.textContent = item.nombre;
    const detail = document.createElement('span');
    detail.textContent = item.path + (item.tiene_sqlite ? ' · db.sqlite3 detectada' : '');
    button.append(title, detail);
    button.addEventListener('click', () => {
      $('#instance-data-dir').value = item.path;
      showFormMessage('Directorio seleccionado: ' + item.path, 'good');
      $('#instance-form-wrap').classList.remove('hidden');
      $('#instance-data-dir').focus();
    });
    target.append(button);
  }
}

const PROVISION_SEQUENCE = [
  'validated',
  'snapshot_ready',
  'replicas_prepared',
  'data_applied',
  'replicas_ready',
  'source_registered',
  'complete'
];

const PROVISION_LABELS = {
  starting: 'Iniciando la operación',
  validating: 'Validando el origen y todos los servidores',
  validated: 'Todos los servidores han validado el plan',
  snapshot_ready: 'Instantánea inicial cifrada creada',
  replicas_prepared: 'Contenedores de réplica creados y detenidos',
  data_applied: 'Datos iniciales copiados',
  replicas_ready: 'Todas las réplicas están arrancadas y sanas',
  source_registered: 'Vaultwarden registrado en todo el grupo',
  floating_partial: 'IP reservada; esperando que floating-IP converja',
  complete: 'Protección completa',
  failed: 'La operación necesita atención'
};

const PROVISION_NODE_LABELS = {
  source_validated: 'Origen validado',
  validated: 'Destino validado',
  prepared: 'Réplica creada y detenida',
  data_applied: 'Datos iniciales copiados',
  ready: 'Réplica arrancada y sana',
  registered: 'Registrado en el grupo'
};

function provisionEnvironment() {
  const settings = (latestConfig && latestConfig.configuracion_operativa) || {};
  const configuredPeers = Object.keys(settings.peers || {});
  const nodes = (latestCluster && latestCluster.nodes) || [];
  const remotes = nodes.filter((node) => !node.local);
  const missingNodes = configuredPeers.filter(
    (name) => !remotes.some((node) => node.name === name)
  );
  const unreachable = remotes.filter((node) => !node.reachable).map((node) => node.name);
  const destinationPaths = Object.fromEntries(
    Array.from(document.querySelectorAll('[data-provision-destination]'))
      .map((input) => [input.dataset.provisionDestination, input.value.trim()])
  );
  const missingPaths = configuredPeers.filter((name) => !destinationPaths[name]);
  const tokenReady = Boolean(latestConfig && latestConfig.token_replicacion_configurado);
  const floatingTokenReady = Boolean(
    latestConfig && latestConfig.token_ip_flotante_configurado);
  return {
    modeReady: settings.mode === 'active',
    tokenReady: tokenReady,
    floatingTokenReady: floatingTokenReady,
    clusterReady: missingNodes.length === 0 && unreachable.length === 0,
    pathsReady: missingPaths.length === 0,
    remoteCount: configuredPeers.length,
    missingNodes: missingNodes,
    unreachable: unreachable,
    missingPaths: missingPaths
  };
}

function provisionDestinationNodes() {
  const settings = (latestConfig && latestConfig.configuracion_operativa) || {};
  const nodes = (latestCluster && latestCluster.nodes) || [];
  return Object.keys(settings.peers || {}).sort().map((name) => {
    const node = nodes.find((item) => item.name === name);
    const topology = (node && node.status && node.status.topologia) || {};
    return {name: name, defaultRoot: topology.vaultwarden_root || ''};
  });
}

function suggestedProvisionPath(node, directory) {
  const root = String(node.defaultRoot || '').replace(/\/+$/, '');
  return root && directory ? root + '/' + directory : '';
}

function renderProvisionDestinations(reset) {
  const target = $('#provision-destination-fields');
  const wrapper = $('#provision-destinations');
  const previous = new Map(
    Array.from(target.querySelectorAll('[data-provision-destination]')).map((input) => [
      input.dataset.provisionDestination,
      {value: input.value, suggested: input.dataset.suggested === 'true'}
    ])
  );
  const nodes = provisionDestinationNodes();
  const directory = $('#provision-data-directory').value.trim();
  target.replaceChildren();
  wrapper.classList.toggle('hidden', nodes.length === 0);
  for (const node of nodes) {
    const label = document.createElement('label');
    const title = document.createElement('span');
    const input = document.createElement('input');
    const hint = document.createElement('small');
    const suggested = suggestedProvisionPath(node, directory);
    const old = previous.get(node.name);
    const useSuggested = Boolean(reset || !old || old.suggested);
    title.textContent = 'Ruta host en ' + node.name;
    input.required = true;
    input.placeholder = '/mnt/user/appdata/' + (directory || 'vaultwarden-nuevo');
    input.dataset.provisionDestination = node.name;
    input.value = useSuggested ? suggested : old.value;
    input.dataset.suggested = String(Boolean(suggested && input.value === suggested));
    input.addEventListener('input', () => {
      input.dataset.suggested = 'false';
      renderProvisionRequirements();
    });
    hint.textContent = suggested
      ? 'Propuesta desde la configuración anterior; puedes cambiarla.'
      : 'Ruta completa del servidor. Se creará la carpeta final si no existe.';
    label.append(title, input, hint);
    target.append(label);
  }
}

function selectedProvisionCandidate() {
  return provisionCandidates.find((item) => item.container === $('#provision-source').value) || null;
}

function candidateCanProvision(candidate) {
  if (!candidate || !candidate.eligible || !candidate.running) return false;
  const registered = ((latestConfig && latestConfig.instancias) || [])
    .some((item) => item.container === candidate.container);
  return !registered;
}

function renderProvisionRequirements() {
  const target = $('#provision-requirements');
  const environment = provisionEnvironment();
  const candidateReady = candidateCanProvision(selectedProvisionCandidate());
  const checks = [
    {
      ok: environment.modeReady,
      text: environment.modeReady
        ? 'Protección del grupo activa'
        : 'Activa “Protección de todo el grupo” en Configuración'
    },
    {
      ok: environment.tokenReady,
      text: environment.tokenReady
        ? 'Contraseña entre Guardian disponible'
        : 'Falta la contraseña entre Guardian de la plantilla'
    },
    {
      ok: environment.floatingTokenReady,
      text: environment.floatingTokenReady
        ? 'Token de IP flotante disponible'
        : 'Falta el token API de Keepalived en la plantilla'
    },
    {
      ok: environment.clusterReady,
      text: environment.clusterReady
        ? 'Todos los Guardian configurados están accesibles'
        : 'Guardian no accesibles: ' + environment.missingNodes.concat(environment.unreachable).join(', ')
    },
    {
      ok: environment.pathsReady,
      text: environment.pathsReady
        ? (environment.remoteCount
          ? 'Cada servidor de destino tiene una ruta host concreta'
          : 'Primer Guardian: todavía no hay destinos remotos')
        : 'Indica la ruta host de la nueva réplica en: '
          + environment.missingPaths.join(', ')
    }
  ];
  target.textContent = '';
  checks.forEach((check) => {
    const item = document.createElement('span');
    item.className = check.ok ? 'good' : 'danger';
    item.textContent = (check.ok ? '✓ ' : '! ') + check.text;
    target.append(item);
  });
  const ready = candidateReady && checks.every((check) => check.ok);
  target.className = 'requirement-box ' + (ready ? 'ready' : 'blocked');
  if (!provisionTransaction) $('#start-provision').disabled = provisionRunning || !ready;
  const plan = $('#provision-plan');
  plan.textContent = environment.remoteCount
    ? 'Plan: crear ' + String(environment.remoteCount) + ' réplica(s), copiar una instantánea cifrada, comprobar todos los nodos y pedir una IP libre al final. Keepalived elegirá automáticamente el portador sano.'
    : 'Plan inicial: registrar este Vaultwarden y pedir una IP libre. No habrá redundancia hasta que añadas otro Guardian; el panel lo mostrará claramente.';
  return ready;
}

function renderProvisionCandidate() {
  const target = $('#provision-candidate');
  const candidate = selectedProvisionCandidate();
  target.textContent = '';
  if (!candidate) {
    target.innerHTML = '<span class="empty">Selecciona un contenedor para ver lo que Guardian ha detectado.</span>';
    renderProvisionRequirements();
    return;
  }
  const registered = ((latestConfig && latestConfig.instancias) || [])
    .some((item) => item.container === candidate.container);
  const facts = [
    ['Contenedor', candidate.container],
    ['Imagen', candidate.image || '—'],
    ['Puerto detectado', candidate.host_port || '—'],
    ['Datos /data', candidate.data_source || '—']
  ];
  facts.forEach(([label, value]) => {
    const item = document.createElement('span');
    const caption = document.createElement('small');
    const content = document.createElement('strong');
    caption.textContent = label;
    content.textContent = String(value);
    item.append(caption, content);
    target.append(item);
  });
  const state = document.createElement('p');
  if (registered) {
    state.textContent = 'Este contenedor ya pertenece a un Vaultwarden registrado.';
    state.className = 'form-message warning';
  } else if (!candidate.eligible || !candidate.running) {
    state.textContent = candidate.running === false
      ? 'El contenedor debe estar arrancado.'
      : 'No se puede clonar: ' + String((candidate.blockers || []).join(' · ') || 'configuración no compatible');
    state.className = 'form-message danger';
  } else {
    const keys = candidate.environment_keys || [];
    state.textContent = 'Listo para clonar. Guardian ha leído ' + String(keys.length)
      + ' nombres de variables, pero no ha enviado sus valores al navegador.';
    state.className = 'form-message good';
  }
  target.append(state);
  renderProvisionRequirements();
}

async function loadProvisionCandidates() {
  const select = $('#provision-source');
  select.innerHTML = '<option value="">Buscando contenedores oficiales…</option>';
  $('#provision-message').textContent = 'Leyendo el inventario local de Docker sin exponer secretos…';
  $('#provision-message').className = 'form-message';
  try {
    const result = await api('/api/v1/provisioning/candidates');
    provisionCandidates = result.items || [];
    select.textContent = '';
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = provisionCandidates.length
      ? 'Selecciona un Vaultwarden'
      : 'No se ha detectado ningún Vaultwarden oficial';
    select.append(placeholder);
    let firstUsable = '';
    provisionCandidates.forEach((candidate) => {
      const option = document.createElement('option');
      const usable = candidateCanProvision(candidate);
      option.value = candidate.container;
      option.textContent = candidate.container
        + (usable ? ' · puerto ' + String(candidate.host_port) : ' · revisar');
      select.append(option);
      if (!firstUsable && usable) firstUsable = candidate.container;
    });
    select.value = firstUsable || (provisionCandidates[0] && provisionCandidates[0].container) || '';
    $('#provision-message').textContent = firstUsable
      ? 'Selecciona el origen y revisa el plan antes de confirmar.'
      : 'No hay candidatos utilizables. Revisa los motivos mostrados en la lista.';
    $('#provision-message').className = 'form-message ' + (firstUsable ? 'good' : 'warning');
    renderProvisionDestinations(true);
    renderProvisionCandidate();
  } catch (error) {
    provisionCandidates = [];
    select.innerHTML = '<option value="">No se pudo leer Docker</option>';
    $('#provision-message').textContent = error.message;
    $('#provision-message').className = 'form-message danger';
    renderProvisionRequirements();
  }
}

function setProvisionLock(locked) {
  document.querySelectorAll('#provision-fields input, #provision-fields select')
    .forEach((control) => { control.disabled = locked; });
  $('#cancel-provision').disabled = provisionRunning;
}

function saveProvisionSession() {
  try {
    if (provisionTransaction && provisionPayload) {
      window.sessionStorage.setItem('vg-provision-transaction', provisionTransaction);
      window.sessionStorage.setItem('vg-provision-payload', JSON.stringify(provisionPayload));
    }
  } catch (error) { /* sessionStorage puede estar deshabilitado */ }
}

function clearProvisionSession() {
  try {
    window.sessionStorage.removeItem('vg-provision-transaction');
    window.sessionStorage.removeItem('vg-provision-payload');
  } catch (error) { /* sessionStorage puede estar deshabilitado */ }
  provisionTransaction = '';
  provisionPayload = null;
}

function restoreProvisionSession() {
  try {
    const transaction = window.sessionStorage.getItem('vg-provision-transaction') || '';
    const raw = window.sessionStorage.getItem('vg-provision-payload');
    if (transaction && raw) {
      provisionTransaction = transaction;
      provisionPayload = JSON.parse(raw);
      return true;
    }
  } catch (error) {
    clearProvisionSession();
  }
  return false;
}

function provisionTransactionId() {
  if (window.crypto && typeof window.crypto.randomUUID === 'function') {
    return 'provision:' + window.crypto.randomUUID();
  }
  return 'provision:' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 14);
}

function collectProvisionPayload() {
  return {
    source_container: $('#provision-source').value,
    instance_id: $('#provision-instance-id').value.trim(),
    display_name: $('#provision-display-name').value.trim(),
    data_directory: $('#provision-data-directory').value.trim(),
    destination_paths: Object.fromEntries(
      Array.from(document.querySelectorAll('[data-provision-destination]'))
        .map((input) => [input.dataset.provisionDestination, input.value.trim()])
    ),
    health_path: $('#provision-health-path').value.trim(),
    include_sends: $('#provision-include-sends').checked,
    confirm: $('#provision-confirm').checked
  };
}

function renderProvisionNodes(nodes) {
  const target = $('#provision-nodes');
  target.textContent = '';
  Object.entries(nodes || {}).forEach(([name, detail]) => {
    const item = document.createElement('span');
    const title = document.createElement('strong');
    const stage = document.createElement('small');
    title.textContent = name;
    stage.textContent = PROVISION_NODE_LABELS[detail.stage]
      || String(detail.stage || 'validado');
    item.append(title, stage);
    target.append(item);
  });
}

function renderProvisionState(state) {
  if (!state) return;
  const stage = state.stage || 'starting';
  const failed = stage === 'failed';
  const partial = stage === 'floating_partial';
  const complete = stage === 'complete' || state.complete === true;
  const effectiveStage = failed ? state.failed_at : stage;
  const completedIndex = effectiveStage === 'floating_partial'
    ? PROVISION_SEQUENCE.indexOf('source_registered')
    : PROVISION_SEQUENCE.indexOf(effectiveStage);
  const failedIndex = Math.min(completedIndex + 1, PROVISION_SEQUENCE.length - 1);
  document.querySelectorAll('[data-provision-step]').forEach((item) => {
    const index = PROVISION_SEQUENCE.indexOf(item.dataset.provisionStep);
    item.className = index <= completedIndex ? 'done' : '';
    if (!failed && index === completedIndex + 1 && !complete) item.className = 'running';
    if (failed && index === failedIndex) item.className = 'failed';
  });
  $('#provision-stage').textContent = failed
    ? 'Detenida en “' + String(PROVISION_LABELS[state.failed_at] || state.failed_at || 'validación') + '”'
    : String(PROVISION_LABELS[stage] || stage);
  $('#provision-badge').textContent = complete ? 'completado' : (failed ? 'requiere atención' : (partial ? 'convergiendo' : 'en curso'));
  $('#provision-badge').className = 'badge ' + (complete ? 'badge-good' : (failed ? 'badge-warning' : ''));
  renderProvisionNodes(state.nodes);
  const result = $('#provision-result');
  if (complete) {
    const ip = state.floating_ip && state.floating_ip.ip;
    result.textContent = 'Terminado. IP flotante reservada: ' + String(ip || 'confirmada')
      + '. Todas las réplicas estaban sanas antes de reservarla.';
    result.className = 'form-message good';
    provisionRunning = false;
    clearInterval(provisionPoll);
    provisionPoll = null;
    setProvisionLock(true);
    $('#start-provision').disabled = true;
    $('#start-provision').textContent = 'Protección creada';
    $('#cancel-provision').disabled = false;
    clearProvisionSession();
    showNotice('Vaultwarden protegido y disponible mediante la IP ' + String(ip || 'reservada') + '.', 'success');
    void refresh();
  } else if (failed) {
    result.textContent = String(state.error || 'La operación se detuvo de forma segura.')
      + ' Puedes reintentar: Guardian continuará la misma transacción sin duplicar recursos.';
    result.className = 'form-message danger';
    provisionRunning = false;
    clearInterval(provisionPoll);
    provisionPoll = null;
    setProvisionLock(true);
    $('#start-provision').disabled = false;
    $('#start-provision').textContent = 'Reintentar desde el punto seguro';
    $('#cancel-provision').disabled = false;
  } else {
    result.textContent = partial
      ? 'La IP ya está reservada; Guardian está esperando confirmación de todos los nodos.'
      : 'Operación en curso. No cierres este Guardian ni cambies los contenedores implicados.';
    result.className = 'form-message ' + (partial ? 'warning' : '');
  }
}

async function pollProvisionTransaction() {
  if (!provisionTransaction) return false;
  try {
    const state = await api('/api/v1/provisioning/transactions/' + encodeURIComponent(provisionTransaction));
    renderProvisionState(state);
    return true;
  } catch (error) {
    if (error.status !== 404) {
      $('#provision-result').textContent = 'No se pudo consultar el progreso: ' + error.message;
      $('#provision-result').className = 'form-message warning';
    }
    return false;
  }
}

async function startProvision(event) {
  event.preventDefault();
  if (!isAdmin() || provisionRunning) return;
  if (!provisionPayload) {
    const form = $('#provision-form');
    if (!form.checkValidity()) {
      form.reportValidity();
      return;
    }
    if (!renderProvisionRequirements()) return;
    provisionPayload = collectProvisionPayload();
    provisionTransaction = provisionTransactionId();
    saveProvisionSession();
  }
  provisionRunning = true;
  setProvisionLock(true);
  $('#start-provision').disabled = true;
  $('#start-provision').textContent = 'Creando protección…';
  $('#provision-progress').classList.remove('hidden');
  renderProvisionState({stage: 'starting', nodes: {}});
  clearInterval(provisionPoll);
  provisionPoll = window.setInterval(pollProvisionTransaction, 1500);
  try {
    const result = await api('/api/v1/provisioning', {
      method: 'POST',
      headers: {'Idempotency-Key': provisionTransaction},
      body: JSON.stringify(provisionPayload)
    });
    renderProvisionState(result);
  } catch (error) {
    const persisted = await pollProvisionTransaction();
    if (!persisted) {
      provisionRunning = false;
      clearInterval(provisionPoll);
      provisionPoll = null;
      clearProvisionSession();
      setProvisionLock(false);
      $('#start-provision').textContent = 'Crear protección completa';
      $('#provision-message').textContent = error.message;
      $('#provision-message').className = 'form-message danger';
      renderProvisionRequirements();
    }
  }
}

function closeProvision() {
  if (provisionRunning) return;
  $('#provision-form-wrap').classList.add('hidden');
}

function resetProvisionDraft() {
  $('#provision-form').reset();
  const position = ((latestConfig && latestConfig.instancias) || []).length + 1;
  const identifier = 'vaultwarden-' + String(position);
  $('#provision-display-name').value = 'Vaultwarden ' + String(position);
  $('#provision-instance-id').value = identifier;
  $('#provision-data-directory').value = identifier;
  $('#provision-health-path').value = '/alive';
  $('#provision-include-sends').checked = true;
}

async function newInstance() {
  if (!isAdmin()) return;
  resetForm();
  $('#instance-form-wrap').classList.add('hidden');
  $('#provision-form-wrap').classList.remove('hidden');
  switchView('instancias');
  if (restoreProvisionSession()) {
    provisionRunning = true;
    $('#provision-progress').classList.remove('hidden');
    setProvisionLock(true);
    $('#start-provision').disabled = true;
    $('#start-provision').textContent = 'Recuperando operación…';
    const restored = await pollProvisionTransaction();
    if (!restored) {
      provisionRunning = false;
      clearInterval(provisionPoll);
      provisionPoll = null;
      clearProvisionSession();
      resetProvisionDraft();
      $('#provision-progress').classList.add('hidden');
      $('#start-provision').textContent = 'Crear protección completa';
      setProvisionLock(false);
      await loadProvisionCandidates();
      $('#provision-message').textContent = 'La operación anterior no llegó a iniciarse; puedes crear una nueva.';
      $('#provision-message').className = 'form-message warning';
    } else if (provisionRunning) {
      clearInterval(provisionPoll);
      provisionPoll = window.setInterval(pollProvisionTransaction, 1500);
    }
  } else {
    resetProvisionDraft();
    $('#provision-progress').classList.add('hidden');
    $('#start-provision').textContent = 'Crear protección completa';
    setProvisionLock(false);
    await loadProvisionCandidates();
  }
  $('#provision-form-wrap').scrollIntoView({behavior: 'smooth', block: 'start'});
}

function render(data, config, version, options) {
  latestStatus = data;
  latestConfig = config;
  const items = data.instancias || [];
  const mode = data.modo || '—';
  text('#footer-node', data.nodo);
  text('#header-node', data.nodo);
  $('#mode').textContent = modeLabel(mode);
  $('#mode').className = 'pill ' + (mode === 'active' ? 'pill-danger' : 'pill-safe');
  $('#app-shell').dataset.version = version.version || '';
  setAdminUi();
  if (!(options && options.skipInstances)) {
    renderInstances(items, config.instancias || []);
  }
  renderDashboard();
}

function resetForm() {
  editingId = null;
  $('#instance-form').reset();
  $('#instance-id').disabled = false;
  $('#instance-health-path').value = '/api/health';
  $('#instance-include-sends').checked = true;
  $('#instance-replication-enabled').checked = false;
  $('#instance-form-title').textContent = 'Añadir Vaultwarden';
  $('#instance-form-wrap').classList.add('hidden');
  showFormMessage('');
}


function editInstance(instance) {
  if (!isAdmin() || !instance) return;
  editingId = instance.id;
  $('#instance-form-title').textContent = 'Editar ' + friendlyInstanceName(instance.id);
  $('#instance-display-name').value = instance.display_name && instance.display_name !== instance.id
    ? instance.display_name : friendlyInstanceName(instance.id);
  $('#instance-id').value = instance.id;
  $('#instance-id').disabled = true;
  $('#instance-container').value = instance.container || '';
  $('#instance-data-dir').value = instance.data_dir || '';
  $('#instance-health-port').value = instance.health_port || '';
  $('#instance-health-path').value = instance.health_path || '/api/health';
  $('#instance-floating-service').value = instance.floating_service || instance.id;
  $('#instance-include-sends').checked = instance.include_sends !== false;
  $('#instance-replication-enabled').checked = instance.replication_enabled === true;
  $('#instance-form-wrap').classList.remove('hidden');
  showFormMessage('Puedes cambiar la etiqueta y los recursos. El identificador interno permanece fijo.', 'good');
  $('#instance-form-wrap').scrollIntoView({behavior: 'smooth', block: 'start'});
  $('#instance-display-name').focus();
}

function collectForm() {
  return {
    id: $('#instance-id').value.trim(),
    display_name: $('#instance-display-name').value.trim(),
    container: $('#instance-container').value.trim(),
    data_dir: $('#instance-data-dir').value.trim(),
    health_port: Number($('#instance-health-port').value),
    health_path: $('#instance-health-path').value.trim(),
    floating_service: $('#instance-floating-service').value.trim(),
    include_sends: $('#instance-include-sends').checked,
    replication_enabled: $('#instance-replication-enabled').checked
  };
}

async function saveInstance(event) {
  event.preventDefault();
  if (!isAdmin()) return;
  const form = $('#instance-form');
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  const payload = collectForm();
  showFormMessage('Validando y guardando este Vaultwarden en todos los Guardian…');
  try {
    const path = editingId
      ? '/api/v1/instances/' + encodeURIComponent(editingId)
      : '/api/v1/instances';
    const result = await api(path, {method: editingId ? 'PUT' : 'POST', body: JSON.stringify(payload)});
    showNotice(payload.display_name + ' se ha guardado en '
      + String(result.nodos || 1) + ' Guardian.', 'success');
    resetForm();
    await refresh();
  } catch (error) {
    showFormMessage(error.message, 'danger');
  }
}

async function deleteInstance(identifier) {
  if (!isAdmin()) return;
  const name = friendlyInstanceName(identifier);
  const confirmed = await confirmarEnPanel({
    titulo: 'Quitar ' + name + ' de Guardian',
    mensajes: [
      'Se quitará el registro de todos los Guardian.',
      'Los datos y contenedores de Vaultwarden no se borrarán.'
    ],
    aceptacion: 'Entiendo que este Vaultwarden dejará de estar gestionado por Guardian.',
    accion: 'Quitar de Guardian',
    peligro: true
  });
  if (!confirmed) return;
  try {
    const result = await api('/api/v1/instances/' + encodeURIComponent(identifier), {method: 'DELETE'});
    showNotice(name + ' se ha quitado de ' + String(result.nodos || 1)
      + ' Guardian. Sus datos no se han tocado.', 'success');
    await refresh();
  } catch (error) {
    showNotice('No se pudo quitar ' + name + ': ' + error.message, 'error');
  }
}

async function validateInstance() {
  if (!isAdmin()) return;
  const form = $('#instance-form');
  if (!form.checkValidity()) {
    form.reportValidity();
    return;
  }
  showFormMessage('Validando datos, contenedor, endpoint de salud y Floating IP…');
  try {
    const result = await api('/api/v1/instances/validate', {
      method: 'POST',
      body: JSON.stringify(collectForm())
    });
    const summary = result.ok ? 'Validación correcta.' : 'La validación necesita atención.';
    showFormMessage(summary + ' Datos: ' + (result.datos.ok ? 'OK' : 'error')
      + ' · contenedor: ' + (result.contenedor.ok ? 'OK' : 'error')
      + ' · salud: ' + (result.salud.ok ? 'OK' : 'error')
      + ' · Floating IP: ' + (result.floating_ip.ok ? 'OK' : 'error'),
      result.ok ? 'good' : 'warning');
  } catch (error) {
    showFormMessage(error.message, 'danger');
  }
}

function applySession(session) {
  currentSession = session;
  csrfToken = session ? String(session.csrf_token || '') : '';
  if (!session) return;
  $('#current-user').textContent = session.display_name || session.username;
  $('#profile-username').textContent = session.username;
  $('#profile-display-name').value = session.display_name || session.username;
  const enabled = Boolean(session.two_factor_enabled);
  $('#two-factor-badge').textContent = enabled ? '2FA activo' : '2FA inactivo';
  $('#two-factor-badge').className = 'badge ' + (enabled ? 'badge-good' : 'badge-warning');
  $('#two-factor-summary').textContent = enabled
    ? 'Segundo factor activo · ' + String(session.recovery_codes_remaining || 0) + ' códigos de recuperación disponibles.'
    : 'El acceso utiliza usuario y contraseña.';
  $('#two-factor-start').classList.toggle('hidden', enabled);
  $('#two-factor-manage-form').classList.toggle('hidden', !enabled);
  if (enabled) $('#two-factor-setup').classList.add('hidden');
}

function setPortalMode(mode) {
  portalMode = mode === 'setup' ? 'setup' : 'login';
  const setup = portalMode === 'setup';
  $('#login-title').textContent = setup ? 'Crear primera cuenta' : 'Iniciar sesión';
  $('#login-subtitle').textContent = setup ? 'Configuración inicial' : 'Cuenta de Vault Guardian';
  $('#login-unconfigured').classList.toggle('hidden', !setup);
  $('#setup-display-wrap').classList.toggle('hidden', !setup);
  $('#setup-confirm-wrap').classList.toggle('hidden', !setup);
  $('#setup-cluster-wrap').classList.toggle('hidden', !setup);
  $('#setup-access-wrap').classList.toggle('hidden', !setup);
  $('#login-factor-wrap').classList.add('hidden');
  $('#setup-confirm-password').required = setup;
  $('#login-password').autocomplete = setup ? 'new-password' : 'current-password';
  $('#login-submit').textContent = setup ? 'Crear cuenta' : 'Entrar';
}

function showLogin(message, kind) {
  currentSession = null;
  csrfToken = '';
  $('#app-shell').classList.add('hidden');
  $('#login-page').classList.remove('hidden');
  $('#login-message').textContent = message || '';
  $('#login-message').className = message
    ? 'form-message ' + (kind || 'danger')
    : 'form-message';
  $('#login-password').value = '';
  $('#setup-confirm-password').value = '';
  $('#setup-cluster-token').value = '';
  $('#login-factor').value = '';
  window.setTimeout(() => $('#login-username').focus(), 0);
}

function showApp(session) {
  applySession(session);
  $('#login-page').classList.add('hidden');
  $('#app-shell').classList.remove('hidden');
  $('#login-message').textContent = '';
  setAdminUi();
}

function replicationNotice(replication) {
  const failed = Object.keys((replication && replication.failed) || {});
  if (failed.length) {
    showNotice('El cambio se guardó localmente, pero no llegó a: ' + failed.join(', ') + '.', 'error');
  }
}

async function login(event) {
  event.preventDefault();
  const button = $('#login-submit');
  const setup = portalMode === 'setup';
  button.disabled = true;
  button.textContent = setup ? 'Creando…' : 'Comprobando…';
  $('#login-message').textContent = '';
  try {
    let result;
    if (setup) {
      const password = $('#login-password').value;
      if (password !== $('#setup-confirm-password').value) {
        const mismatch = new Error('Las contraseñas no coinciden');
        mismatch.code = 'PASSWORD_MISMATCH';
        throw mismatch;
      }
      result = await api('/api/v1/auth/setup', {
        method: 'POST',
        body: JSON.stringify({
          username: $('#login-username').value.trim(),
          display_name: $('#setup-display-name').value.trim(),
          cluster_token: $('#setup-cluster-token').value.trim(),
          allow_insecure_portal: $('#setup-portal-access').value === 'http',
          password,
          password_confirmation: $('#setup-confirm-password').value
        })
      });
    } else {
      result = await api('/api/v1/session', {
        method: 'POST',
        body: JSON.stringify({
          username: $('#login-username').value.trim(),
          password: $('#login-password').value,
          second_factor: $('#login-factor').value.trim()
        })
      });
    }
    $('#login-factor-wrap').classList.add('hidden');
    $('#login-factor').value = '';
    showApp(result.session);
    if (setup) replicationNotice(result.replication);
    switchView(window.location.hash.slice(1));
    await Promise.all([refresh(), loadSecurity()]);
  } catch (error) {
    if (!setup && error.code === 'TWO_FACTOR_REQUIRED') {
      $('#login-factor-wrap').classList.remove('hidden');
      $('#login-message').textContent = 'Introduce el código 2FA o un código de recuperación.';
      $('#login-message').className = 'form-message warning';
      $('#login-factor').focus();
    } else {
      $('#login-message').textContent = error.message;
      $('#login-message').className = 'form-message danger';
    }
  } finally {
    button.disabled = false;
    button.textContent = setup ? 'Crear cuenta' : 'Entrar';
  }
}

async function disconnect() {
  try {
    await api('/api/v1/session', {method: 'DELETE'});
  } catch (error) { /* la cookie se descarta también en el cliente */ }
  resetForm();
  showLogin('Sesión cerrada.', 'good');
}

function renderUsers(items) {
  const target = $('#users-list');
  target.textContent = '';
  if (!items.length) {
    target.innerHTML = '<span class="empty">No hay usuarios.</span>';
    return;
  }
  for (const user of items) {
    const row = document.createElement('div');
    row.className = 'user-row';
    const identity = document.createElement('div');
    identity.className = 'user-identity';
    const name = document.createElement('strong');
    name.textContent = user.display_name || user.username;
    const detail = document.createElement('span');
    detail.textContent = user.username + ' · '
      + (user.enabled ? 'habilitado' : 'deshabilitado') + ' · '
      + (user.two_factor_enabled ? '2FA activo' : 'sin 2FA');
    identity.append(name, detail);
    const actions = document.createElement('div');
    actions.className = 'user-actions';
    const edit = document.createElement('button');
    edit.type = 'button';
    edit.className = 'button small secondary';
    edit.textContent = 'Editar';
    edit.disabled = user.username === currentSession.username;
    edit.addEventListener('click', () => openUserForm(user));
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'button small secondary';
    toggle.textContent = user.enabled ? 'Deshabilitar' : 'Habilitar';
    toggle.disabled = user.username === currentSession.username;
    toggle.addEventListener('click', () => toggleUser(user));
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'button small danger';
    remove.textContent = 'Eliminar';
    remove.disabled = user.username === currentSession.username;
    remove.addEventListener('click', () => deleteUser(user));
    actions.append(edit, toggle, remove);
    row.append(identity, actions);
    target.append(row);
  }
}

async function loadSecurity() {
  if (!currentSession) return;
  try {
    const [session, users] = await Promise.all([
      api('/api/v1/session'),
      api('/api/v1/users')
    ]);
    applySession(session);
    renderUsers(users.items || []);
  } catch (error) {
    if (error.status !== 401) {
      $('#user-message').textContent = error.message;
      $('#user-message').className = 'form-message danger';
    }
  }
}

function openUserForm(user) {
  editingUser = user || null;
  $('#user-form').classList.remove('hidden');
  $('#user-username').disabled = Boolean(user);
  $('#user-username').value = user ? user.username : '';
  $('#user-display-name').value = user ? (user.display_name || user.username) : '';
  $('#user-password').value = '';
  $('#user-password').required = !user;
  $('#user-message').textContent = user
    ? 'Deja la contraseña vacía para conservar la actual.'
    : '';
  $('#user-username').focus();
}

function closeUserForm() {
  editingUser = null;
  $('#user-form').reset();
  $('#user-username').disabled = false;
  $('#user-password').required = true;
  $('#user-form').classList.add('hidden');
  $('#user-message').textContent = '';
}

async function saveUser(event) {
  event.preventDefault();
  const payload = {
    display_name: $('#user-display-name').value.trim()
  };
  if ($('#user-password').value) payload.password = $('#user-password').value;
  if (!editingUser) {
    payload.username = $('#user-username').value.trim();
  }
  try {
    const result = await api(
      editingUser
        ? '/api/v1/users/' + encodeURIComponent(editingUser.username)
        : '/api/v1/users',
      {method: editingUser ? 'PUT' : 'POST', body: JSON.stringify(payload)}
    );
    replicationNotice(result.replication);
    closeUserForm();
    await loadSecurity();
  } catch (error) {
    $('#user-message').textContent = error.message;
    $('#user-message').className = 'form-message danger';
  }
}

async function toggleUser(user) {
  try {
    const result = await api('/api/v1/users/' + encodeURIComponent(user.username), {
      method: 'PUT',
      body: JSON.stringify({enabled: !user.enabled})
    });
    replicationNotice(result.replication);
    await loadSecurity();
  } catch (error) {
    showNotice(error.message, 'error');
  }
}

async function deleteUser(user) {
  const confirmed = await confirmarEnPanel({
    titulo: 'Eliminar usuario',
    mensajes: ['Se eliminará la cuenta ' + user.username + ' de Vault Guardian.'],
    accion: 'Eliminar',
    peligro: true
  });
  if (!confirmed) return;
  try {
    const result = await api('/api/v1/users/' + encodeURIComponent(user.username), {
      method: 'DELETE'
    });
    replicationNotice(result.replication);
    await loadSecurity();
  } catch (error) {
    showNotice(error.message, 'error');
  }
}

async function saveProfile(event) {
  event.preventDefault();
  const payload = {
    display_name: $('#profile-display-name').value.trim()
  };
  if ($('#profile-new-password').value) {
    payload.current_password = $('#profile-current-password').value;
    payload.new_password = $('#profile-new-password').value;
  }
  try {
    const result = await api('/api/v1/profile', {
      method: 'PUT',
      body: JSON.stringify(payload)
    });
    applySession(result.session);
    replicationNotice(result.replication);
    $('#profile-current-password').value = '';
    $('#profile-new-password').value = '';
    $('#profile-message').textContent = 'Cuenta actualizada.';
    $('#profile-message').className = 'form-message good';
  } catch (error) {
    $('#profile-message').textContent = error.message;
    $('#profile-message').className = 'form-message danger';
  }
}

async function startTwoFactor() {
  $('#two-factor-message').textContent = 'Preparando 2FA…';
  try {
    const result = await api('/api/v1/profile/2fa/setup', {method: 'POST'});
    replicationNotice(result.replication);
    $('#two-factor-secret').value = result.setup.secret;
    $('#two-factor-qr').src = result.setup.qr_data_url || '';
    $('#two-factor-qr').classList.toggle('hidden', !result.setup.qr_data_url);
    $('#two-factor-setup').classList.remove('hidden');
    $('#two-factor-message').textContent = 'Escanea el QR y confirma un código.';
    $('#two-factor-message').className = 'form-message';
  } catch (error) {
    $('#two-factor-message').textContent = error.message;
    $('#two-factor-message').className = 'form-message danger';
  }
}

function showRecoveryCodes(codes) {
  $('#recovery-codes').textContent = (codes || []).join('\n');
  $('#codes-dialog').showModal();
}

async function confirmTwoFactor(event) {
  event.preventDefault();
  try {
    const result = await api('/api/v1/profile/2fa/confirm', {
      method: 'POST',
      body: JSON.stringify({code: $('#two-factor-confirm-code').value.trim()})
    });
    applySession(result.session);
    replicationNotice(result.replication);
    $('#two-factor-confirm-code').value = '';
    showRecoveryCodes(result.recovery_codes);
    await loadSecurity();
  } catch (error) {
    $('#two-factor-message').textContent = error.message;
    $('#two-factor-message').className = 'form-message danger';
  }
}

async function disableTwoFactor() {
  try {
    const result = await api('/api/v1/profile/2fa/disable', {
      method: 'POST',
      body: JSON.stringify({code: $('#two-factor-manage-code').value.trim()})
    });
    applySession(result.session);
    replicationNotice(result.replication);
    $('#two-factor-manage-code').value = '';
    await loadSecurity();
  } catch (error) {
    $('#two-factor-message').textContent = error.message;
    $('#two-factor-message').className = 'form-message danger';
  }
}

async function regenerateRecovery() {
  try {
    const result = await api('/api/v1/profile/recovery-codes', {
      method: 'POST',
      body: JSON.stringify({code: $('#two-factor-manage-code').value.trim()})
    });
    replicationNotice(result.replication);
    $('#two-factor-manage-code').value = '';
    showRecoveryCodes(result.recovery_codes);
    await loadSecurity();
  } catch (error) {
    $('#two-factor-message').textContent = error.message;
    $('#two-factor-message').className = 'form-message danger';
  }
}

function formatBytes(value) {
  const bytes = Number(value) || 0;
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KiB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MiB';
}

function renderBackups(groups) {
  const target = $('#backups');
  target.textContent = '';
  const retention = latestConfig && latestConfig.backup_retention;
  $('#backup-retention').textContent = retention ? 'retención · ' + retention : '—';
  if (!groups.length) {
    const empty = document.createElement('span');
    empty.className = 'empty';
    empty.textContent = 'No hay backups disponibles para los Vaultwarden declarados.';
    target.append(empty);
    return;
  }
  for (const group of groups) {
    const card = document.createElement('article');
    card.className = 'backup-card';
    const heading = document.createElement('div');
    heading.className = 'backup-heading';
    const title = document.createElement('strong');
    title.textContent = friendlyInstanceName(group.instancia);
    const count = document.createElement('span');
    count.textContent = group.items.length + ' backup(s)';
    heading.append(title, count);
    card.append(heading);
    for (const item of group.items) {
      const row = document.createElement('div');
      row.className = 'backup-row';
      const detail = document.createElement('div');
      detail.className = 'backup-detail';
      const name = document.createElement('strong');
      name.textContent = item.nombre;
      const metadata = document.createElement('span');
      metadata.textContent = formatBytes(item.bytes) + ' · ' + item.modificado;
      detail.append(name, metadata);
      const restore = document.createElement('button');
      restore.className = 'button small secondary';
      restore.type = 'button';
      restore.textContent = 'Restaurar';
      restore.addEventListener('click', () => restoreBackup(group.instancia, item.nombre));
      row.append(detail, restore);
      card.append(row);
    }
    target.append(card);
  }
}

async function loadBackups() {
  const target = $('#backups');
  if (!isAdmin()) {
    target.innerHTML = '<span class="empty">Se requiere una sesión activa.</span>';
    $('#backup-retention').textContent = latestConfig && latestConfig.backup_retention
      ? 'retención · ' + latestConfig.backup_retention : '—';
    return;
  }
  const instances = (latestConfig && latestConfig.instancias) || [];
  if (!instances.length) {
    renderBackups([]);
    return;
  }
  try {
    const groups = await Promise.all(instances.map((item) =>
      api('/api/v1/instances/' + encodeURIComponent(item.id) + '/backups')));
    renderBackups(groups);
  } catch (error) {
    const message = document.createElement('span');
    message.className = 'empty';
    message.textContent = 'No se pudieron leer los backups: ' + error.message;
    target.replaceChildren(message);
  }
}

async function restoreBackup(identifier, backup) {
  if (!isAdmin()) return;
  const name = friendlyInstanceName(identifier);
  const confirmed = await confirmarEnPanel({
    titulo: 'Restaurar backup de ' + name,
    mensajes: [
      'El contenedor se detendrá, se restaurarán los datos y volverá a arrancar.',
      'Guardian creará antes un backup de seguridad del estado actual.'
    ],
    elementos: [{texto: 'El Vaultwarden debe estar fuera de la IP flotante.', peligro: true}],
    aceptacion: 'He comprobado que este Vaultwarden no porta la IP flotante.',
    accion: 'Restaurar backup',
    peligro: true
  });
  if (!confirmed) return;
  try {
    const result = await api('/api/v1/instances/' + encodeURIComponent(identifier) + '/restore', {
      method: 'POST',
      body: JSON.stringify({backup: backup, confirm: true})
    });
    showNotice('Restauración completada para ' + identifier + '. Se creó un backup de seguridad.', 'success');
    await refresh();
  } catch (error) {
    showNotice('No se pudo restaurar ' + identifier + ': ' + error.message, 'error');
  }
}

async function refresh(options) {
  const refreshButton = $('#overview-refresh');
  if (refreshButton && !(options && options.periodic)) {
    refreshButton.disabled = true;
    refreshButton.textContent = 'Actualizando…';
  }
  try {
    const results = await Promise.all([
      api('/api/v1/status'),
      api('/api/v1/config'),
      api('/api/v1/discovery'),
      api('/api/version'),
      api('/api/v1/setup'),
      api('/api/v1/cluster'),
      api('/api/v1/integrations/applications')
    ]);
    const activeView = (document.querySelector('[data-view-panel].active') || {}).dataset?.viewPanel;
    const skipInstances = Boolean(options && options.periodic && activeView === 'instancias');
    latestConfig = results[1];
    renderCluster(results[5]);
    render(results[0], results[1], results[3], {skipInstances: skipInstances});
    if (!skipInstances) renderDiscovery(results[2]);
    renderSetup(results[4], results[1]);
    if (!$('#api-integration-form').contains(document.activeElement)) {
      renderApiIntegrations(results[6].items || []);
    }
    await Promise.all([loadBackups(), loadHistory()]);
    $('#heartbeat').textContent = 'al día · ' + new Date().toLocaleTimeString('es-ES');
    $('#heartbeat').className = 'status-dot ok';
    $('#footer-time').textContent = 'actualizado ' + new Date().toLocaleTimeString('es-ES');
  } catch (error) {
    $('#heartbeat').textContent = 'sin contacto';
    $('#heartbeat').className = 'status-dot error';
    if (error.status !== 401) {
      showNotice('No se pudo leer el estado: ' + error.message, 'error');
    }
  } finally {
    if (refreshButton && !(options && options.periodic)) {
      refreshButton.disabled = false;
      refreshButton.textContent = 'Actualizar';
    }
  }
}

$('#login-form').addEventListener('submit', login);
$('#disconnect').addEventListener('click', disconnect);
$('#account-button').addEventListener('click', () => {
  switchView('seguridad');
  loadSecurity();
});
$('#profile-form').addEventListener('submit', saveProfile);
$('#new-user').addEventListener('click', () => openUserForm(null));
$('#cancel-user').addEventListener('click', closeUserForm);
$('#user-form').addEventListener('submit', saveUser);
$('#two-factor-start').addEventListener('click', startTwoFactor);
$('#two-factor-confirm-form').addEventListener('submit', confirmTwoFactor);
$('#two-factor-disable').addEventListener('click', disableTwoFactor);
$('#recovery-regenerate').addEventListener('click', regenerateRecovery);
$('#overview-refresh').addEventListener('click', () => refresh());
$('#refresh-instances').addEventListener('click', async () => {
  const button = $('#refresh-instances');
  button.disabled = true;
  button.textContent = 'Actualizando…';
  try {
    await refresh();
  } finally {
    button.disabled = false;
    button.textContent = 'Actualizar estado';
  }
});
$('#history-previous').addEventListener('click', () => {
  if (historyPage > 1) {
    historyPage -= 1;
    renderHistory(historyItems);
  }
});
$('#history-next').addEventListener('click', () => {
  if (historyPage * HISTORY_PAGE_SIZE < historyItems.length) {
    historyPage += 1;
    renderHistory(historyItems);
  }
});
['#setting-interval', '#setting-retention', '#setting-package'].forEach((selector) => {
  $(selector).addEventListener('input', updatePolicySummary);
});
$('#copy-recovery-codes').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('#recovery-codes').textContent);
    $('#copy-recovery-codes').textContent = 'Copiados';
  } catch (error) {
    $('#copy-recovery-codes').textContent = 'No se pudo copiar';
  }
});
$('#new-instance').addEventListener('click', newInstance);
$('#cancel-provision').addEventListener('click', closeProvision);
$('#provision-form').addEventListener('submit', startProvision);
$('#provision-source').addEventListener('change', () => {
  const candidate = selectedProvisionCandidate();
  if (candidate && !provisionTransaction) {
    $('#provision-data-directory').value = candidate.container;
  }
  renderProvisionDestinations(false);
  renderProvisionCandidate();
});
$('#provision-data-directory').addEventListener('input', () => {
  renderProvisionDestinations(false);
  renderProvisionRequirements();
});
$('#cancel-edit').addEventListener('click', resetForm);
$('#instance-form').addEventListener('submit', saveInstance);
$('#validate-instance').addEventListener('click', validateInstance);
$('#settings-form').addEventListener('submit', saveSettings);
$('#keepalived-integration-form').addEventListener('submit', saveKeepalivedIntegration);
$('#application-settings-form').addEventListener('submit', saveApplicationSettings);
$('#api-integration-form').addEventListener('submit', saveApiIntegration);
$('#copy-api-token').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText($('#api-token-result-value').textContent);
    $('#copy-api-token').textContent = 'Copiado';
  } catch (error) {
    $('#copy-api-token').textContent = 'No se pudo copiar';
  }
});
$('#private-ca-form').addEventListener('submit', savePrivateCa);
$('#disable-private-ca').addEventListener('click', disablePrivateCa);
$('#show-enrollment-token').addEventListener('click', async () => {
  if (!isAdmin()) return;
  try {
    const result = await api('/api/v1/cluster/enrollment-token');
    $('#enrollment-token').textContent = result.token;
    $('#enrollment-token').classList.remove('hidden');
  } catch (error) {
    $('#keepalived-integration-message').textContent = error.message;
    $('#keepalived-integration-message').className = 'form-message danger';
  }
});
$('#cluster-form').addEventListener('submit', saveCluster);
$('#reconcile-members').addEventListener('click', reconcileMembers);
$('#add-member').addEventListener('click', () => {
  if (!isAdmin()) return;
  const row = addMemberRow(null, !document.querySelector('.member-local:checked'));
  $('#cluster-message').textContent = 'Completa los datos del servidor nuevo y guarda el grupo.';
  $('#cluster-message').className = 'form-message';
  row.scrollIntoView({behavior: 'smooth', block: 'center'});
  row.querySelector('.member-name').focus();
});
$('#setting-mode').addEventListener('change', toggleActiveConfirmation);
document.querySelectorAll('[data-view]').forEach((button) => {
  button.addEventListener('click', () => switchView(button.dataset.view));
});
document.querySelectorAll('[data-view-link]').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    switchView(link.dataset.viewLink);
  });
});
document.querySelectorAll('input[name="mode-choice"]').forEach((input) => {
  input.addEventListener('change', () => {
    $('#setting-mode').value = input.value;
    toggleActiveConfirmation();
  });
});
$('#next-action').addEventListener('click', () => switchView($('#next-action').dataset.targetView));
async function initialize() {
  try {
    const [authStatus, version] = await Promise.all([
      api('/api/v1/auth/status'),
      api('/api/version')
    ]);
    $('#login-version').textContent = 'v' + String(version.version || '1.0.20');
    $('#setup-portal-access').value = authStatus.allow_insecure_portal ? 'http' : 'https';
    setPortalMode(authStatus.configured ? 'login' : 'setup');
    $('#login-form').querySelectorAll('input, button').forEach((element) => {
      element.disabled = Boolean(authStatus.requires_replication_secret);
    });
    if (authStatus.requires_replication_secret) {
      showLogin(
        'No se pudo preparar el secreto local de Guardian. Revisa el volumen de estado.',
        'warning'
      );
      return;
    }
    if (!authStatus.configured) {
      showLogin();
      return;
    }
    const session = await api('/api/v1/session');
    showApp(session);
    switchView(window.location.hash.slice(1));
    await Promise.all([refresh(), loadSecurity()]);
  } catch (error) {
    showLogin();
  }
}

initialize();
setInterval(() => {
  if (currentSession && !document.hidden) refresh({periodic: true});
}, REFRESH_MS);
