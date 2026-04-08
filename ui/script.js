const canvas = document.getElementById("trafficChart");
const ctx = canvas.getContext("2d");

const SAMPLE_SIZE = 20;
const STORAGE_KEYS = {
  controller: "daed-demo-controller",
  token: "daed-demo-token",
};

const refs = {
  controllerForm: document.getElementById("controllerForm"),
  controllerUrl: document.getElementById("controllerUrl"),
  controllerToken: document.getElementById("controllerToken"),
  controllerHint: document.getElementById("controllerHint"),
  connectButton: document.getElementById("connectButton"),
  refreshButton: document.getElementById("refreshButton"),
  apiStatusText: document.getElementById("apiStatusText"),
  apiStatusDot: document.getElementById("apiStatusDot"),
  versionLabel: document.getElementById("versionLabel"),
  uploadRate: document.getElementById("uploadRate"),
  downloadRate: document.getElementById("downloadRate"),
  uploadTotalValue: document.getElementById("uploadTotalValue"),
  downloadTotalValue: document.getElementById("downloadTotalValue"),
  trafficTransportValue: document.getElementById("trafficTransportValue"),
  chartScale: document.getElementById("chartScale"),
  chartTime: document.getElementById("chartTime"),
  controllerStateValue: document.getElementById("controllerStateValue"),
  modeValue: document.getElementById("modeValue"),
  logLevelValue: document.getElementById("logLevelValue"),
  memoryValue: document.getElementById("memoryValue"),
  aliveNodesValue: document.getElementById("aliveNodesValue"),
  groupCoverageValue: document.getElementById("groupCoverageValue"),
  memoryPressureValue: document.getElementById("memoryPressureValue"),
  aliveNodesBar: document.getElementById("aliveNodesBar"),
  groupCoverageBar: document.getElementById("groupCoverageBar"),
  memoryPressureBar: document.getElementById("memoryPressureBar"),
  runtimeVersionValue: document.getElementById("runtimeVersionValue"),
  tproxyPortValue: document.getElementById("tproxyPortValue"),
  allowLanValue: document.getElementById("allowLanValue"),
  bindAddressValue: document.getElementById("bindAddressValue"),
  proxyTabs: document.getElementById("proxyTabs"),
  proxyGrid: document.getElementById("proxyGrid"),
  currentGroupName: document.getElementById("currentGroupName"),
  currentGroupMeta: document.getElementById("currentGroupMeta"),
  resetGroupButton: document.getElementById("resetGroupButton"),
  reloadProxiesButton: document.getElementById("reloadProxiesButton"),
  logLevelSelect: document.getElementById("logLevelSelect"),
  saveConfigButton: document.getElementById("saveConfigButton"),
  refreshConfigButton: document.getElementById("refreshConfigButton"),
  configView: document.getElementById("configView"),
  editorLines: document.getElementById("editorLines"),
  editorNote: document.getElementById("editorNote"),
};

const state = {
  controllerUrl: "",
  token: "",
  apiStatus: {
    kind: "offline",
    message: "Disconnected",
  },
  version: null,
  config: null,
  memory: null,
  traffic: {
    up: 0,
    down: 0,
    upTotal: 0,
    downTotal: 0,
  },
  trafficSeries: createEmptySeries(),
  trafficTransport: "idle",
  proxies: {},
  groups: [],
  selectedGroup: "",
  ws: null,
  wsCloseIntent: false,
  wsRetryTimer: null,
  refreshTimer: null,
  refreshing: false,
  connecting: false,
  busyGroups: new Set(),
  busyDelayNodes: new Set(),
};

function createEmptySeries() {
  const now = Date.now();
  return {
    up: Array(SAMPLE_SIZE).fill(0),
    down: Array(SAMPLE_SIZE).fill(0),
    times: Array.from({ length: SAMPLE_SIZE }, (_, index) => now - (SAMPLE_SIZE - index - 1) * 1000),
  };
}

function resetLiveState() {
  state.version = null;
  state.config = null;
  state.memory = null;
  state.traffic = {
    up: 0,
    down: 0,
    upTotal: 0,
    downTotal: 0,
  };
  state.trafficSeries = createEmptySeries();
  state.proxies = {};
  state.groups = [];
  state.selectedGroup = "";
}

function loadPersistedConnection() {
  const query = new URLSearchParams(window.location.search);
  const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const urlFromQuery = query.get("controller");
  const tokenFromQuery = query.get("token");
  const tokenFromHash = hash.get("token");
  const servedByEmbeddedUI = window.location.pathname === "/ui/" || window.location.pathname.startsWith("/ui/");
  const sameOriginController = servedByEmbeddedUI ? window.location.origin : "";

  state.controllerUrl = urlFromQuery || sameOriginController || window.localStorage.getItem(STORAGE_KEYS.controller) || "";
  state.token = tokenFromQuery || tokenFromHash || window.localStorage.getItem(STORAGE_KEYS.token) || "";

  refs.controllerUrl.value = state.controllerUrl;
  refs.controllerToken.value = state.token;
}

function persistConnection() {
  window.localStorage.setItem(STORAGE_KEYS.controller, state.controllerUrl);
  window.localStorage.setItem(STORAGE_KEYS.token, state.token);
}

function normalizeControllerUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("Controller address is required");
  }

  const normalized = /^[a-z]+:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
  const url = new URL(normalized);
  url.pathname = "/";
  url.search = "";
  url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function buildHttpUrl(path) {
  const base = `${state.controllerUrl}/`;
  return new URL(path.replace(/^\//, ""), base);
}

function buildWebSocketUrl(path) {
  const url = buildHttpUrl(path);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  if (state.token) {
    url.searchParams.set("token", state.token);
  }
  return url.toString();
}

async function apiFetch(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) {
    headers.set("Authorization", `Bearer ${state.token}`);
  }
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(buildHttpUrl(path), {
    ...options,
    headers,
  });

  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const payload = await response.json();
      if (payload && typeof payload.message === "string" && payload.message) {
        message = payload.message;
      }
    } catch {
      // Ignore response body parse failures and keep the default message.
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }

  const text = await response.text();
  if (!text) {
    return null;
  }
  return JSON.parse(text);
}

function setApiStatus(kind, message) {
  state.apiStatus = { kind, message };
  renderHeaderStatus();
  refs.controllerStateValue.textContent = message.toLowerCase();
}

function renderHeaderStatus() {
  refs.apiStatusText.textContent = state.apiStatus.message;
  refs.apiStatusDot.classList.remove("offline", "warn");
  if (state.apiStatus.kind === "offline") {
    refs.apiStatusDot.classList.add("offline");
  } else if (state.apiStatus.kind === "warn") {
    refs.apiStatusDot.classList.add("warn");
  }
}

function setBusyState(busy) {
  state.connecting = busy;
  refs.connectButton.disabled = busy;
  refs.refreshButton.disabled = busy;
}

function startRefreshLoop() {
  stopRefreshLoop();
  state.refreshTimer = window.setInterval(() => {
    refreshSnapshot(false);
  }, 15000);
}

function stopRefreshLoop() {
  if (state.refreshTimer) {
    window.clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

function closeTrafficSocket() {
  if (state.wsRetryTimer) {
    window.clearTimeout(state.wsRetryTimer);
    state.wsRetryTimer = null;
  }
  if (state.ws) {
    state.wsCloseIntent = true;
    state.ws.close();
    state.ws = null;
  }
  state.trafficTransport = "idle";
}

function connectTrafficSocket() {
  closeTrafficSocket();

  let socket;
  try {
    socket = new WebSocket(buildWebSocketUrl("/traffic"));
  } catch {
    state.trafficTransport = "ws failed";
    renderTrafficMeta();
    return;
  }

  state.wsCloseIntent = false;
  state.ws = socket;
  state.trafficTransport = "ws connecting";
  renderTrafficMeta();

  socket.addEventListener("open", () => {
    if (state.ws !== socket) {
      return;
    }
    state.trafficTransport = "websocket";
    renderTrafficMeta();
  });

  socket.addEventListener("message", (event) => {
    if (state.ws !== socket) {
      return;
    }
    try {
      const payload = JSON.parse(event.data);
      updateTraffic(payload);
    } catch {
      // Ignore malformed frames and keep the current chart.
    }
  });

  socket.addEventListener("close", () => {
    if (state.ws !== socket) {
      return;
    }
    state.ws = null;
    if (state.wsCloseIntent) {
      return;
    }
    state.trafficTransport = "ws closed";
    renderTrafficMeta();
    state.wsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectTrafficSocket();
      }
    }, 3000);
  });
}

function updateTraffic(payload) {
  state.traffic = {
    up: Number(payload.up || 0),
    down: Number(payload.down || 0),
    upTotal: Number(payload.upTotal || 0),
    downTotal: Number(payload.downTotal || 0),
  };

  const upRate = bytesToMegabytes(state.traffic.up);
  const downRate = bytesToMegabytes(state.traffic.down);

  state.trafficSeries.up.push(upRate);
  state.trafficSeries.down.push(-downRate);
  state.trafficSeries.times.push(Date.now());

  trimTrafficSeries();
  renderTrafficMeta();
  renderChart();
}

function trimTrafficSeries() {
  while (state.trafficSeries.up.length > SAMPLE_SIZE) {
    state.trafficSeries.up.shift();
    state.trafficSeries.down.shift();
    state.trafficSeries.times.shift();
  }
}

function bytesToMegabytes(value) {
  return value / (1024 * 1024);
}

function humanBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value || 0);
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const digits = size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${units[unitIndex]}`;
}

function shortRate(value) {
  return bytesToMegabytes(value).toFixed(1);
}

function refreshProxyCollections(rawProxies) {
  state.proxies = rawProxies || {};
  state.groups = Object.values(state.proxies).filter((proxy) => Array.isArray(proxy.all) && proxy.all.length > 0);
  if (!state.groups.some((group) => group.name === state.selectedGroup)) {
    state.selectedGroup = state.groups[0]?.name || "";
  }
}

async function refreshSnapshot(updateStatus = true) {
  if (!state.controllerUrl || state.refreshing) {
    return;
  }
  state.refreshing = true;
  try {
    const [version, config, memory, proxiesPayload] = await Promise.all([
      apiFetch("/version"),
      apiFetch("/configs"),
      apiFetch("/memory"),
      apiFetch("/proxies"),
    ]);

    state.version = version;
    state.config = config;
    state.memory = memory;
    refreshProxyCollections(proxiesPayload.proxies);

    if (updateStatus) {
      setApiStatus("connected", "Connected");
      refs.controllerHint.textContent =
        "Connected to dae external controller. Proxy switches call `/proxies/{group}` and latency probes call `/proxies/{name}/delay`.";
      connectTrafficSocket();
      startRefreshLoop();
    }

    renderAll();
  } catch (error) {
    handleConnectionError(error);
  } finally {
    state.refreshing = false;
  }
}

function handleConnectionError(error) {
  closeTrafficSocket();
  stopRefreshLoop();
  resetLiveState();

  if (error.status === 401) {
    setApiStatus("warn", "Unauthorized");
    refs.controllerHint.textContent =
      "Controller rejected the request. If `external_controller_secret` is set, provide the Bearer token here.";
  } else {
    setApiStatus("offline", "Unavailable");
    refs.controllerHint.textContent =
      "Failed to reach the controller. Confirm dae is running and `global.external_controller` is listening on the address above.";
  }

  renderAll();
}

async function connectController() {
  try {
    state.controllerUrl = normalizeControllerUrl(refs.controllerUrl.value);
    state.token = refs.controllerToken.value.trim();
  } catch (error) {
    setApiStatus("warn", error.message);
    refs.controllerHint.textContent = error.message;
    renderAll();
    return;
  }

  persistConnection();
  resetLiveState();
  setBusyState(true);
  setApiStatus("warn", "Connecting");
  refs.controllerHint.textContent = "Requesting `/version`, `/configs`, `/memory`, and `/proxies` from the configured controller.";
  renderAll();
  await refreshSnapshot(true);
  setBusyState(false);
}

function computeLeafStats() {
  const leaves = Object.values(state.proxies).filter((proxy) => !Array.isArray(proxy.all));
  const alive = leaves.filter((proxy) => proxy.alive).length;
  return { leaves, alive };
}

function currentGroup() {
  return state.groups.find((group) => group.name === state.selectedGroup) || null;
}

function renderSystemStatus() {
  const group = currentGroup();
  const { leaves, alive } = computeLeafStats();
  const selectedGroups = state.groups.filter((item) => item.now).length;
  const aliveRatio = leaves.length ? Math.round((alive / leaves.length) * 100) : 0;
  const groupRatio = state.groups.length ? Math.round((selectedGroups / state.groups.length) * 100) : 0;

  const inUse = Number(state.memory?.inuse || 0);
  const osLimit = Number(state.memory?.oslimit || 0);
  const memoryRatio = osLimit > 0 ? Math.round((inUse / osLimit) * 100) : Math.min(100, Math.round((inUse / (512 * 1024 * 1024)) * 100));
  const memoryPressureText = osLimit > 0 ? `${memoryRatio}%` : `${memoryRatio}%*`;

  refs.controllerStateValue.textContent = state.apiStatus.message.toLowerCase();
  refs.modeValue.textContent = state.config?.mode || "-";
  refs.logLevelValue.textContent = state.config?.["log-level"] || "-";
  refs.memoryValue.textContent = inUse ? humanBytes(inUse) : "-";

  refs.aliveNodesValue.textContent = `${alive} / ${leaves.length}`;
  refs.groupCoverageValue.textContent = `${selectedGroups} / ${state.groups.length}`;
  refs.memoryPressureValue.textContent = inUse ? memoryPressureText : "N/A";

  refs.aliveNodesBar.style.width = `${aliveRatio}%`;
  refs.groupCoverageBar.style.width = `${groupRatio}%`;
  refs.memoryPressureBar.style.width = `${inUse ? memoryRatio : 0}%`;

  refs.runtimeVersionValue.textContent = state.version?.version || "-";
  refs.tproxyPortValue.textContent = state.config?.["tproxy-port"] ? String(state.config["tproxy-port"]) : "-";
  refs.allowLanValue.textContent = typeof state.config?.["allow-lan"] === "boolean" ? (state.config["allow-lan"] ? "yes" : "no") : "-";
  refs.bindAddressValue.textContent = state.config?.["bind-address"] || "-";

  refs.currentGroupName.textContent = group?.name || "No group";
  refs.currentGroupMeta.textContent = group
    ? `${group.type} · current: ${group.now || "none"} · ${group.all.length} node(s)`
    : "Connect controller to load proxies.";
  refs.resetGroupButton.disabled = !group || state.busyGroups.has(group.name);
}

function renderTrafficMeta() {
  refs.uploadRate.textContent = shortRate(state.traffic.up);
  refs.downloadRate.textContent = shortRate(state.traffic.down);
  refs.uploadTotalValue.textContent = humanBytes(state.traffic.upTotal);
  refs.downloadTotalValue.textContent = humanBytes(state.traffic.downTotal);
  refs.trafficTransportValue.textContent = state.trafficTransport;
}

function chartBounds() {
  const maxUp = Math.max(0.4, ...state.trafficSeries.up);
  const maxDown = Math.max(0.2, ...state.trafficSeries.down.map((value) => Math.abs(value)));
  return {
    maxUp: Number((maxUp * 1.15).toFixed(2)),
    maxDown: Number((maxDown * 1.15).toFixed(2)),
  };
}

function mapToY(value, height, bounds) {
  return ((bounds.maxUp - value) / (bounds.maxUp + bounds.maxDown)) * height;
}

function createSmoothPath(points, width, height, bounds) {
  const step = width / Math.max(1, points.length - 1);
  return points.map((value, index) => ({
    x: index * step,
    y: mapToY(value, height, bounds),
  }));
}

function drawGrid(width, height) {
  ctx.strokeStyle = "rgba(122, 132, 142, 0.12)";
  ctx.lineWidth = 1;

  for (let index = 0; index < 5; index += 1) {
    const y = (height / 4) * index;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  for (let index = 0; index < 6; index += 1) {
    const x = (width / 5) * index;
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, height);
    ctx.stroke();
  }
}

function drawSeries(points, width, height, bounds, options) {
  const mapped = createSmoothPath(points, width, height, bounds);
  ctx.beginPath();
  ctx.moveTo(mapped[0].x, mapped[0].y);

  for (let index = 0; index < mapped.length - 1; index += 1) {
    const current = mapped[index];
    const next = mapped[index + 1];
    const controlPointX = (current.x + next.x) / 2;
    ctx.bezierCurveTo(controlPointX, current.y, controlPointX, next.y, next.x, next.y);
  }

  ctx.lineWidth = 3;
  ctx.strokeStyle = options.stroke;
  ctx.stroke();

  ctx.lineTo(width, height);
  ctx.lineTo(0, height);
  ctx.closePath();

  const gradient = ctx.createLinearGradient(0, 0, 0, height);
  gradient.addColorStop(0, options.fill);
  gradient.addColorStop(1, "rgba(255, 255, 255, 0)");
  ctx.fillStyle = gradient;
  ctx.fill();
}

function renderScaleLabels(bounds) {
  const labels = [
    `${bounds.maxUp.toFixed(1)} MB/s`,
    `${(bounds.maxUp / 4).toFixed(1)} MB/s`,
    "0.0 MB/s",
    `-${(bounds.maxDown / 2).toFixed(1)} MB/s`,
    `-${bounds.maxDown.toFixed(1)} MB/s`,
  ];
  refs.chartScale.innerHTML = labels.map((label) => `<span>${label}</span>`).join("");
}

function renderTimeLabels() {
  const indexes = [0, 5, 10, 15, state.trafficSeries.times.length - 1];
  refs.chartTime.innerHTML = indexes
    .map((index) => {
      const timestamp = state.trafficSeries.times[index] || Date.now();
      const label = new Date(timestamp).toLocaleTimeString("zh-CN", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
      return `<span>${label}</span>`;
    })
    .join("");
}

function renderChart() {
  const ratio = window.devicePixelRatio || 1;
  const bounds = canvas.getBoundingClientRect();
  if (!bounds.width || !bounds.height) {
    return;
  }

  canvas.width = Math.floor(bounds.width * ratio);
  canvas.height = Math.floor(bounds.height * ratio);
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.scale(ratio, ratio);

  const width = bounds.width;
  const height = bounds.height;
  const scale = chartBounds();

  ctx.clearRect(0, 0, width, height);
  drawGrid(width, height);
  drawSeries(state.trafficSeries.up, width, height, scale, {
    stroke: "#4cc0b5",
    fill: "rgba(76, 192, 181, 0.24)",
  });
  drawSeries(state.trafficSeries.down, width, height, scale, {
    stroke: "#9b84d7",
    fill: "rgba(155, 132, 215, 0.18)",
  });

  renderScaleLabels(scale);
  renderTimeLabels();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function inferFlagTone(name) {
  const palette = ["us", "jp", "sg"];
  let hash = 0;
  for (const char of name) {
    hash += char.charCodeAt(0);
  }
  return palette[hash % palette.length];
}

function inferProxyLabel(name) {
  const match = name.match(/[A-Za-z]{2}/);
  return match ? match[0].toUpperCase() : "PX";
}

function proxyDelay(proxy) {
  const entry = Array.isArray(proxy?.history) ? proxy.history[0] : null;
  if (!entry || typeof entry.delay !== "number") {
    return null;
  }
  return entry.delay;
}

function renderProxyTabs() {
  refs.proxyTabs.innerHTML = state.groups.length
    ? state.groups
        .map(
          (group) => `
            <button
              class="proxy-tab ${group.name === state.selectedGroup ? "active" : ""}"
              data-group="${escapeHtml(group.name)}"
              type="button"
            >
              ${escapeHtml(group.name)}
            </button>
          `,
        )
        .join("")
    : `<div class="proxy-empty">No proxy groups returned by <code>/proxies</code>.</div>`;
}

function renderProxyGrid() {
  const group = currentGroup();
  if (!group) {
    refs.proxyGrid.innerHTML = `<div class="proxy-empty">Connect a reachable controller to load group and node data.</div>`;
    return;
  }

  refs.proxyGrid.innerHTML = group.all
    .map((proxyName) => {
      const proxy = state.proxies[proxyName] || { name: proxyName, alive: false };
      const delay = proxyDelay(proxy);
      const active = group.now === proxyName;
      const tone = inferFlagTone(proxyName);
      const address = proxy.addr || proxy.address || "address unavailable";
      const protocol = proxy.protocol || proxy.type || "unknown";
      const delayText = delay === null ? "pending" : `${delay} ms`;
      const busyDelay = state.busyDelayNodes.has(proxyName);
      const busyGroup = state.busyGroups.has(group.name);

      return `
        <article class="proxy-card ${active ? "current" : ""} ${busyDelay ? "busy" : ""}">
          <div class="proxy-top">
            <span class="flag ${tone}">${escapeHtml(inferProxyLabel(proxyName))}</span>
            <button
              class="refresh"
              type="button"
              aria-label="refresh delay"
              data-action="probe-delay"
              data-name="${escapeHtml(proxyName)}"
              ${busyDelay ? "disabled" : ""}
            ></button>
          </div>

          <h3>${escapeHtml(proxyName)}</h3>
          <div class="proxy-meta">${escapeHtml(address)}</div>
          <p><strong>${escapeHtml(delayText)}</strong></p>

          <div class="proxy-badges">
            <span class="proxy-badge">${escapeHtml(protocol)}</span>
            <span class="proxy-badge ${proxy.alive ? "" : "dim"}">${proxy.alive ? "alive" : "down"}</span>
            ${proxy.subscriptionTag ? `<span class="proxy-badge dim">${escapeHtml(proxy.subscriptionTag)}</span>` : ""}
          </div>

          <div class="proxy-actions">
            <button
              class="proxy-action"
              type="button"
              data-action="probe-delay"
              data-name="${escapeHtml(proxyName)}"
              ${busyDelay ? "disabled" : ""}
            >
              Probe
            </button>
            <button
              class="proxy-action primary"
              type="button"
              data-action="select-proxy"
              data-name="${escapeHtml(proxyName)}"
              ${active || busyGroup ? "disabled" : ""}
            >
              ${active ? "Selected" : "Use Node"}
            </button>
          </div>
        </article>
      `;
    })
    .join("");
}

function renderConfigSnapshot() {
  const snapshot = {
    controller: {
      url: state.controllerUrl || null,
      status: state.apiStatus.message,
      trafficTransport: state.trafficTransport,
    },
    version: state.version,
    configs: state.config,
    memory: state.memory,
    selectedGroup: currentGroup()
      ? {
          name: currentGroup().name,
          now: currentGroup().now,
          type: currentGroup().type,
          all: currentGroup().all,
        }
      : null,
  };

  const content = JSON.stringify(snapshot, null, 2);
  refs.configView.textContent = content;

  const lines = content.split("\n").length;
  refs.editorLines.innerHTML = Array.from({ length: lines }, (_, index) => `<span>${index + 1}</span>`).join("");

  if (state.config?.["log-level"]) {
    refs.logLevelSelect.value = state.config["log-level"];
  }
}

function renderVersionTitle() {
  refs.versionLabel.textContent = state.version?.version || "unlinked";
}

function renderAll() {
  renderHeaderStatus();
  renderVersionTitle();
  renderSystemStatus();
  renderTrafficMeta();
  renderProxyTabs();
  renderProxyGrid();
  renderConfigSnapshot();
  renderChart();

  refs.saveConfigButton.disabled = !state.config;
  refs.refreshConfigButton.disabled = !state.controllerUrl;
  refs.reloadProxiesButton.disabled = !state.controllerUrl;
}

async function probeDelay(name) {
  if (!state.controllerUrl) {
    return;
  }
  state.busyDelayNodes.add(name);
  renderProxyGrid();
  try {
    const payload = await apiFetch(`/proxies/${encodeURIComponent(name)}/delay?timeout=5000`);
    if (state.proxies[name]) {
      state.proxies[name].history = [{ delay: payload.delay, time: new Date().toISOString() }];
    }
    refs.editorNote.textContent = `Latency probe for ${name} returned ${payload.delay} ms from /proxies/${name}/delay.`;
  } catch (error) {
    refs.editorNote.textContent = `Latency probe failed for ${name}: ${error.message}`;
  } finally {
    state.busyDelayNodes.delete(name);
    renderProxyGrid();
  }
}

async function selectProxy(name) {
  const group = currentGroup();
  if (!group || !state.controllerUrl) {
    return;
  }

  state.busyGroups.add(group.name);
  renderProxyGrid();
  renderSystemStatus();

  try {
    await apiFetch(`/proxies/${encodeURIComponent(group.name)}`, {
      method: "PUT",
      body: JSON.stringify({ name }),
    });
    refs.editorNote.textContent = `Switched group ${group.name} to ${name} through /proxies/${group.name}.`;
    await refreshSnapshot(false);
  } catch (error) {
    refs.editorNote.textContent = `Failed to switch ${group.name} to ${name}: ${error.message}`;
  } finally {
    state.busyGroups.delete(group.name);
    renderAll();
  }
}

async function resetGroup() {
  const group = currentGroup();
  if (!group || !state.controllerUrl) {
    return;
  }

  state.busyGroups.add(group.name);
  renderSystemStatus();

  try {
    await apiFetch(`/proxies/${encodeURIComponent(group.name)}`, {
      method: "DELETE",
    });
    refs.editorNote.textContent = `Reset group ${group.name} to its default policy via DELETE /proxies/${group.name}.`;
    await refreshSnapshot(false);
  } catch (error) {
    refs.editorNote.textContent = `Failed to reset ${group.name}: ${error.message}`;
  } finally {
    state.busyGroups.delete(group.name);
    renderAll();
  }
}

async function updateLogLevel() {
  if (!state.controllerUrl) {
    return;
  }

  const level = refs.logLevelSelect.value;
  refs.saveConfigButton.disabled = true;
  try {
    await apiFetch("/configs", {
      method: "PATCH",
      body: JSON.stringify({ "log-level": level }),
    });
    refs.editorNote.textContent = `Updated controller log level to ${level} via PATCH /configs.`;
    await refreshSnapshot(false);
  } catch (error) {
    refs.editorNote.textContent = `Failed to update log level: ${error.message}`;
  } finally {
    refs.saveConfigButton.disabled = false;
    renderAll();
  }
}

function handleProxyGridClick(event) {
  const button = event.target.closest("[data-action]");
  if (!button) {
    return;
  }
  const action = button.dataset.action;
  const name = button.dataset.name;
  if (!name) {
    return;
  }
  if (action === "probe-delay") {
    probeDelay(name);
  } else if (action === "select-proxy") {
    selectProxy(name);
  }
}

function bindEvents() {
  refs.controllerForm.addEventListener("submit", (event) => {
    event.preventDefault();
    connectController();
  });

  refs.refreshButton.addEventListener("click", () => {
    refreshSnapshot(true);
  });

  refs.refreshConfigButton.addEventListener("click", () => {
    refreshSnapshot(false);
  });

  refs.reloadProxiesButton.addEventListener("click", () => {
    refreshSnapshot(false);
  });

  refs.saveConfigButton.addEventListener("click", () => {
    updateLogLevel();
  });

  refs.resetGroupButton.addEventListener("click", () => {
    resetGroup();
  });

  refs.proxyTabs.addEventListener("click", (event) => {
    const button = event.target.closest("[data-group]");
    if (!button) {
      return;
    }
    state.selectedGroup = button.dataset.group;
    renderAll();
  });

  refs.proxyGrid.addEventListener("click", handleProxyGridClick);
  window.addEventListener("resize", renderChart);
}

function boot() {
  loadPersistedConnection();
  bindEvents();
  renderAll();
  if (state.controllerUrl) {
    connectController();
  }
}

boot();
