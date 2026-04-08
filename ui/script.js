const canvas = document.getElementById("trafficChart");
const ctx = canvas.getContext("2d");

const DEFAULT_CONFIG_PLACEHOLDER = "# Connect controller to load /etc/dae/config.dae";
const SAMPLE_SIZE = 20;
const RELOAD_SYNC_ATTEMPTS = 8;
const RELOAD_SYNC_DELAY_MS = 800;
const MAX_LOG_ENTRIES = 200;
const LOG_LEVELS = ["trace", "debug", "info", "warn", "error"];
const VIEW_META = {
  dashboard: {
    eyebrow: "Dashboard",
    title: "daed Dashboard",
    banner: "Overview",
  },
  controller: {
    eyebrow: "External Controller",
    title: "Controller Workspace",
    banner: "External Controller",
  },
  proxies: {
    eyebrow: "Proxies",
    title: "Proxy Runtime",
    banner: "Proxy Groups",
  },
  traffic: {
    eyebrow: "Traffic",
    title: "Live Traffic",
    banner: "Traffic Flow",
  },
  configs: {
    eyebrow: "Configs",
    title: "Config Workspace",
    banner: "Runtime + Startup Config",
  },
  logs: {
    eyebrow: "Logs",
    title: "Live Logs",
    banner: "Structured Log Stream",
  },
};
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
  apiStatusText: document.getElementById("apiStatusText"),
  apiStatusDot: document.getElementById("apiStatusDot"),
  pageEyebrow: document.getElementById("pageEyebrow"),
  pageTitle: document.getElementById("pageTitle"),
  pageBanner: document.getElementById("pageBanner"),
  navItems: Array.from(document.querySelectorAll(".nav-item[data-view]")),
  viewButtons: Array.from(document.querySelectorAll("[data-open-view]")),
  pages: Array.from(document.querySelectorAll(".page[data-page]")),
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
  controllerUrlValue: document.getElementById("controllerUrlValue"),
  controllerAuthValue: document.getElementById("controllerAuthValue"),
  startupConfigPathValue: document.getElementById("startupConfigPathValue"),
  runtimeVersionValue: document.getElementById("runtimeVersionValue"),
  tproxyPortValue: document.getElementById("tproxyPortValue"),
  allowLanValue: document.getElementById("allowLanValue"),
  bindAddressValue: document.getElementById("bindAddressValue"),
  controllerDetailUrl: document.getElementById("controllerDetailUrl"),
  embeddedUiValue: document.getElementById("embeddedUiValue"),
  controllerTokenValue: document.getElementById("controllerTokenValue"),
  controllerConfigPathValue: document.getElementById("controllerConfigPathValue"),
  controllerPageNote: document.getElementById("controllerPageNote"),
  streamList: document.getElementById("streamList"),
  runtimeLogLevelSelect: document.getElementById("runtimeLogLevelSelect"),
  applyLogLevelButton: document.getElementById("applyLogLevelButton"),
  runtimeLogLevelNote: document.getElementById("runtimeLogLevelNote"),
  proxyTabs: document.getElementById("proxyTabs"),
  proxyGrid: document.getElementById("proxyGrid"),
  currentGroupName: document.getElementById("currentGroupName"),
  currentGroupMeta: document.getElementById("currentGroupMeta"),
  resetGroupButton: document.getElementById("resetGroupButton"),
  reloadProxiesButton: document.getElementById("reloadProxiesButton"),
  saveConfigButton: document.getElementById("saveConfigButton"),
  refreshConfigButton: document.getElementById("refreshConfigButton"),
  configPathValue: document.getElementById("configPathValue"),
  configModeValue: document.getElementById("configModeValue"),
  configLogLevelValue: document.getElementById("configLogLevelValue"),
  configTproxyValue: document.getElementById("configTproxyValue"),
  configAllowLanValue: document.getElementById("configAllowLanValue"),
  configBindValue: document.getElementById("configBindValue"),
  configView: document.getElementById("configView"),
  editorLines: document.getElementById("editorLines"),
  editorNote: document.getElementById("editorNote"),
  logsLevelSelect: document.getElementById("logsLevelSelect"),
  toggleLogsButton: document.getElementById("toggleLogsButton"),
  clearLogsButton: document.getElementById("clearLogsButton"),
  logsStatusText: document.getElementById("logsStatusText"),
  logsShell: document.getElementById("logsShell"),
  logsEmpty: document.getElementById("logsEmpty"),
  logsList: document.getElementById("logsList"),
};

const state = {
  controllerUrl: "",
  token: "",
  currentView: "dashboard",
  apiStatus: {
    kind: "offline",
    message: "Disconnected",
  },
  version: null,
  config: null,
  versionSignature: "",
  configSignature: "",
  daeConfigPath: "",
  daeConfigContent: DEFAULT_CONFIG_PLACEHOLDER,
  daeConfigDirty: false,
  daeConfigSignature: "",
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
  versionWs: null,
  versionWsCloseIntent: false,
  versionWsRetryTimer: null,
  configWs: null,
  configWsCloseIntent: false,
  configWsRetryTimer: null,
  daeConfigWs: null,
  daeConfigWsCloseIntent: false,
  daeConfigWsRetryTimer: null,
  proxyWs: null,
  proxyWsCloseIntent: false,
  proxyWsRetryTimer: null,
  proxySignature: "",
  memoryWs: null,
  memoryWsCloseIntent: false,
  memoryWsRetryTimer: null,
  logWs: null,
  logWsCloseIntent: false,
  logWsRetryTimer: null,
  logLevelChanging: false,
  logs: [],
  logsPaused: false,
  logsLevel: "info",
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
  state.versionSignature = "";
  state.config = null;
  state.configSignature = "";
  state.daeConfigPath = "";
  state.daeConfigContent = DEFAULT_CONFIG_PLACEHOLDER;
  state.daeConfigDirty = false;
  state.daeConfigSignature = "";
  state.memory = null;
  state.traffic = {
    up: 0,
    down: 0,
    upTotal: 0,
    downTotal: 0,
  };
  state.trafficSeries = createEmptySeries();
  state.proxies = {};
  state.proxySignature = "";
  state.groups = [];
  state.selectedGroup = "";
  state.logs = [];
  state.logsPaused = false;
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

function sleep(ms) {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

function stableJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function versionSnapshotSignature(payload) {
  return stableJson({
    meta: Boolean(payload?.meta),
    version: payload?.version || "",
  });
}

function configSnapshotSignature(payload) {
  return stableJson(payload || {});
}

function daeConfigDocumentSignature(doc) {
  return stableJson({
    path: doc?.path || "",
    content: doc?.content || "",
  });
}

function proxySnapshotSignature(rawProxies) {
  const proxies = rawProxies || {};
  return stableJson(
    Object.keys(proxies)
      .sort()
      .map((name) => {
        const proxy = proxies[name] || {};
        return {
          name,
          type: proxy.type || "",
          alive: Boolean(proxy.alive),
          delay: proxyDelay(proxy),
          now: proxy.now || "",
          all: Array.isArray(proxy.all) ? proxy.all : [],
          addr: proxy.addr || proxy.address || "",
          protocol: proxy.protocol || "",
          subscriptionTag: proxy.subscriptionTag || "",
          udp: Boolean(proxy.udp),
          xudp: Boolean(proxy.xudp),
        };
      }),
  );
}

function activeViewMeta() {
  return VIEW_META[state.currentView] || VIEW_META.dashboard;
}

function renderViewState() {
  const meta = activeViewMeta();
  refs.pageEyebrow.textContent = meta.eyebrow;
  refs.pageTitle.textContent = meta.title;
  refs.pageBanner.textContent = meta.banner;
  refs.navItems.forEach((item) => {
    item.classList.toggle("active", item.dataset.view === state.currentView);
  });
  refs.pages.forEach((page) => {
    page.classList.toggle("active", page.dataset.page === state.currentView);
  });
}

function setActiveView(view) {
  if (!VIEW_META[view]) {
    return;
  }
  state.currentView = view;
  renderViewState();
  if (view === "logs" && state.controllerUrl && state.apiStatus.kind === "connected" && !state.logsPaused) {
    connectLogSocket();
  } else if (view !== "logs") {
    closeLogSocket();
  }
  renderControllerPanel();
  renderLogs();
}

function wsState(socket, retryTimer) {
  if (!state.controllerUrl) {
    return "idle";
  }
  if (socket?.readyState === WebSocket.OPEN) {
    return "live";
  }
  if (socket?.readyState === WebSocket.CONNECTING) {
    return "opening";
  }
  if (retryTimer) {
    return "retrying";
  }
  return state.apiStatus.kind === "connected" ? "standby" : "offline";
}

function pushLogEntry(entry) {
  state.logs.unshift(entry);
  if (state.logs.length > MAX_LOG_ENTRIES) {
    state.logs.length = MAX_LOG_ENTRIES;
  }
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
  refs.applyLogLevelButton.disabled = busy || state.logLevelChanging || !state.controllerUrl;
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

function closeMemorySocket() {
  if (state.memoryWsRetryTimer) {
    window.clearTimeout(state.memoryWsRetryTimer);
    state.memoryWsRetryTimer = null;
  }
  if (state.memoryWs) {
    state.memoryWsCloseIntent = true;
    state.memoryWs.close();
    state.memoryWs = null;
  }
}

function closeVersionSocket() {
  if (state.versionWsRetryTimer) {
    window.clearTimeout(state.versionWsRetryTimer);
    state.versionWsRetryTimer = null;
  }
  if (state.versionWs) {
    state.versionWsCloseIntent = true;
    state.versionWs.close();
    state.versionWs = null;
  }
}

function closeConfigSocket() {
  if (state.configWsRetryTimer) {
    window.clearTimeout(state.configWsRetryTimer);
    state.configWsRetryTimer = null;
  }
  if (state.configWs) {
    state.configWsCloseIntent = true;
    state.configWs.close();
    state.configWs = null;
  }
}

function closeProxySocket() {
  if (state.proxyWsRetryTimer) {
    window.clearTimeout(state.proxyWsRetryTimer);
    state.proxyWsRetryTimer = null;
  }
  if (state.proxyWs) {
    state.proxyWsCloseIntent = true;
    state.proxyWs.close();
    state.proxyWs = null;
  }
}

function closeDaeConfigSocket() {
  if (state.daeConfigWsRetryTimer) {
    window.clearTimeout(state.daeConfigWsRetryTimer);
    state.daeConfigWsRetryTimer = null;
  }
  if (state.daeConfigWs) {
    state.daeConfigWsCloseIntent = true;
    state.daeConfigWs.close();
    state.daeConfigWs = null;
  }
}

function closeLogSocket() {
  if (state.logWsRetryTimer) {
    window.clearTimeout(state.logWsRetryTimer);
    state.logWsRetryTimer = null;
  }
  if (state.logWs) {
    state.logWsCloseIntent = true;
    state.logWs.close();
    state.logWs = null;
  }
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
  renderControllerPanel();

  socket.addEventListener("open", () => {
    if (state.ws !== socket) {
      return;
    }
    state.trafficTransport = "websocket";
    renderTrafficMeta();
    renderControllerPanel();
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
      renderControllerPanel();
      return;
    }
    state.trafficTransport = "ws closed";
    renderTrafficMeta();
    renderControllerPanel();
    state.wsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectTrafficSocket();
      }
    }, 3000);
  });
}

function connectMemorySocket() {
  closeMemorySocket();

  let socket;
  try {
    socket = new WebSocket(buildWebSocketUrl("/memory"));
  } catch {
    state.memoryWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectMemorySocket();
      }
    }, 3000);
    return;
  }

  state.memoryWsCloseIntent = false;
  state.memoryWs = socket;
  renderControllerPanel();

  socket.addEventListener("open", () => {
    if (state.memoryWs !== socket) {
      return;
    }
    renderControllerPanel();
  });

  socket.addEventListener("message", (event) => {
    if (state.memoryWs !== socket) {
      return;
    }
    try {
      const payload = JSON.parse(event.data);
      updateMemory(payload);
    } catch {
      // Ignore malformed frames and keep the current memory state.
    }
  });

  socket.addEventListener("close", () => {
    if (state.memoryWs !== socket) {
      return;
    }
    state.memoryWs = null;
    if (state.memoryWsCloseIntent) {
      renderControllerPanel();
      return;
    }
    renderControllerPanel();
    state.memoryWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectMemorySocket();
      }
    }, 3000);
  });
}

function applyVersionSnapshot(payload) {
  const signature = versionSnapshotSignature(payload);
  if (signature === state.versionSignature) {
    return;
  }
  state.versionSignature = signature;
  state.version = payload;
  renderVersionTitle();
  renderSystemStatus();
}

function applyConfigSnapshot(payload) {
  const signature = configSnapshotSignature(payload);
  if (signature === state.configSignature) {
    return;
  }
  state.configSignature = signature;
  state.config = payload;
  renderSystemStatus();
}

function applyProxySnapshot(rawProxies) {
  const signature = proxySnapshotSignature(rawProxies);
  if (signature === state.proxySignature) {
    return;
  }
  state.proxySignature = signature;
  refreshProxyCollections(rawProxies);
  renderSystemStatus();
  renderProxyTabs();
  renderProxyGrid();
}

function applyDaeConfigDocument(doc) {
  const signature = daeConfigDocumentSignature(doc);
  state.daeConfigPath = doc.path || "";
  if (signature === state.daeConfigSignature) {
    return;
  }
  state.daeConfigSignature = signature;
  if (!state.daeConfigDirty) {
    state.daeConfigContent = typeof doc.content === "string" ? doc.content : "";
    renderDaeConfigEditor();
  }
}

function connectVersionSocket() {
  closeVersionSocket();

  let socket;
  try {
    socket = new WebSocket(buildWebSocketUrl("/version"));
  } catch {
    state.versionWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectVersionSocket();
      }
    }, 3000);
    return;
  }

  state.versionWsCloseIntent = false;
  state.versionWs = socket;
  renderControllerPanel();

  socket.addEventListener("open", () => {
    if (state.versionWs !== socket) {
      return;
    }
    renderControllerPanel();
  });

  socket.addEventListener("message", (event) => {
    if (state.versionWs !== socket) {
      return;
    }
    try {
      applyVersionSnapshot(JSON.parse(event.data));
    } catch {
      // Ignore malformed frames and keep the current version state.
    }
  });

  socket.addEventListener("close", () => {
    if (state.versionWs !== socket) {
      return;
    }
    state.versionWs = null;
    if (state.versionWsCloseIntent) {
      renderControllerPanel();
      return;
    }
    renderControllerPanel();
    state.versionWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectVersionSocket();
      }
    }, 3000);
  });
}

function connectConfigSocket() {
  closeConfigSocket();

  let socket;
  try {
    socket = new WebSocket(buildWebSocketUrl("/configs"));
  } catch {
    state.configWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectConfigSocket();
      }
    }, 3000);
    return;
  }

  state.configWsCloseIntent = false;
  state.configWs = socket;
  renderControllerPanel();

  socket.addEventListener("open", () => {
    if (state.configWs !== socket) {
      return;
    }
    renderControllerPanel();
  });

  socket.addEventListener("message", (event) => {
    if (state.configWs !== socket) {
      return;
    }
    try {
      applyConfigSnapshot(JSON.parse(event.data));
    } catch {
      // Ignore malformed frames and keep the current config state.
    }
  });

  socket.addEventListener("close", () => {
    if (state.configWs !== socket) {
      return;
    }
    state.configWs = null;
    if (state.configWsCloseIntent) {
      renderControllerPanel();
      return;
    }
    renderControllerPanel();
    state.configWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectConfigSocket();
      }
    }, 3000);
  });
}

function connectProxySocket() {
  closeProxySocket();

  let socket;
  try {
    socket = new WebSocket(buildWebSocketUrl("/proxies"));
  } catch {
    state.proxyWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectProxySocket();
      }
    }, 3000);
    return;
  }

  state.proxyWsCloseIntent = false;
  state.proxyWs = socket;
  renderControllerPanel();

  socket.addEventListener("open", () => {
    if (state.proxyWs !== socket) {
      return;
    }
    renderControllerPanel();
  });

  socket.addEventListener("message", (event) => {
    if (state.proxyWs !== socket) {
      return;
    }
    try {
      const payload = JSON.parse(event.data);
      applyProxySnapshot(payload.proxies);
    } catch {
      // Ignore malformed frames and keep the current proxy state.
    }
  });

  socket.addEventListener("close", () => {
    if (state.proxyWs !== socket) {
      return;
    }
    state.proxyWs = null;
    if (state.proxyWsCloseIntent) {
      renderControllerPanel();
      return;
    }
    renderControllerPanel();
    state.proxyWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectProxySocket();
      }
    }, 3000);
  });
}

function connectDaeConfigSocket() {
  closeDaeConfigSocket();

  let socket;
  try {
    socket = new WebSocket(buildWebSocketUrl("/configs/dae"));
  } catch {
    state.daeConfigWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectDaeConfigSocket();
      }
    }, 3000);
    return;
  }

  state.daeConfigWsCloseIntent = false;
  state.daeConfigWs = socket;
  renderControllerPanel();

  socket.addEventListener("open", () => {
    if (state.daeConfigWs !== socket) {
      return;
    }
    renderControllerPanel();
  });

  socket.addEventListener("message", (event) => {
    if (state.daeConfigWs !== socket) {
      return;
    }
    try {
      applyDaeConfigDocument(JSON.parse(event.data));
    } catch {
      // Ignore malformed frames and keep the current editor state.
    }
  });

  socket.addEventListener("close", () => {
    if (state.daeConfigWs !== socket) {
      return;
    }
    state.daeConfigWs = null;
    if (state.daeConfigWsCloseIntent) {
      renderControllerPanel();
      return;
    }
    renderControllerPanel();
    state.daeConfigWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl) {
        connectDaeConfigSocket();
      }
    }, 3000);
  });
}

function connectLogSocket() {
  if (state.currentView !== "logs" || state.logsPaused) {
    return;
  }
  closeLogSocket();

  let socket;
  try {
    const url = buildHttpUrl("/logs");
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    if (state.token) {
      url.searchParams.set("token", state.token);
    }
    url.searchParams.set("format", "structured");
    url.searchParams.set("level", state.logsLevel);
    socket = new WebSocket(url.toString());
  } catch {
    state.logWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl && state.currentView === "logs" && !state.logsPaused) {
        connectLogSocket();
      }
    }, 3000);
    renderLogs();
    return;
  }

  state.logWsCloseIntent = false;
  state.logWs = socket;
  renderControllerPanel();
  renderLogs();

  socket.addEventListener("open", () => {
    if (state.logWs !== socket) {
      return;
    }
    renderControllerPanel();
    renderLogs();
  });

  socket.addEventListener("message", (event) => {
    if (state.logWs !== socket) {
      return;
    }
    try {
      pushLogEntry(JSON.parse(event.data));
      renderLogs();
    } catch {
      // Ignore malformed frames and keep the current log buffer.
    }
  });

  socket.addEventListener("close", () => {
    if (state.logWs !== socket) {
      return;
    }
    state.logWs = null;
    if (state.logWsCloseIntent) {
      renderControllerPanel();
      renderLogs();
      return;
    }
    renderControllerPanel();
    state.logWsRetryTimer = window.setTimeout(() => {
      if (state.controllerUrl && state.currentView === "logs" && !state.logsPaused) {
        connectLogSocket();
      }
    }, 3000);
    renderLogs();
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

function updateMemory(payload) {
  state.memory = {
    inuse: Number(payload.inuse || 0),
    oslimit: Number(payload.oslimit || 0),
  };
  renderSystemStatus();
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
    const [version, config, proxiesPayload, daeConfig] = await Promise.all([
      apiFetch("/version"),
      apiFetch("/configs"),
      apiFetch("/proxies"),
      apiFetch("/configs/dae"),
    ]);

    applyVersionSnapshot(version);
    applyConfigSnapshot(config);
    applyProxySnapshot(proxiesPayload.proxies);
    applyDaeConfigDocument(daeConfig);

    if (updateStatus) {
      setApiStatus("connected", "Connected");
      refs.controllerHint.textContent =
        "Connected to dae external controller. Runtime state snapshots stream every 5 seconds over WebSocket, and config edits write back to startup `config.dae`.";
      connectVersionSocket();
      connectConfigSocket();
      connectProxySocket();
      connectTrafficSocket();
      connectMemorySocket();
      connectDaeConfigSocket();
      if (state.currentView === "logs" && !state.logsPaused) {
        connectLogSocket();
      }
      renderAll();
    }
  } catch (error) {
    handleConnectionError(error);
  } finally {
    state.refreshing = false;
  }
}

function handleConnectionError(error) {
  closeVersionSocket();
  closeConfigSocket();
  closeProxySocket();
  closeTrafficSocket();
  closeMemorySocket();
  closeDaeConfigSocket();
  closeLogSocket();
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
  closeVersionSocket();
  closeConfigSocket();
  closeProxySocket();
  closeTrafficSocket();
  closeMemorySocket();
  closeDaeConfigSocket();
  closeLogSocket();
  resetLiveState();
  setBusyState(true);
  setApiStatus("warn", "Connecting");
  refs.controllerHint.textContent =
    "Opening live channels for `/version`, `/configs`, `/proxies`, `/traffic`, `/memory`, and startup `config.dae`.";
  renderAll();
  await refreshSnapshot(true);
  if (state.apiStatus.kind === "connected") {
    refs.editorNote.textContent = state.daeConfigPath ? `Loaded ${state.daeConfigPath}.` : "Loaded startup config.dae.";
  }
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
  refs.controllerUrlValue.textContent = state.controllerUrl || "-";
  refs.controllerAuthValue.textContent = state.token ? "Bearer + ws token" : "Bearer disabled";
  refs.startupConfigPathValue.textContent = state.daeConfigPath || "-";
  refs.configModeValue.textContent = state.config?.mode || "-";
  refs.configLogLevelValue.textContent = state.config?.["log-level"] || "-";
  refs.configTproxyValue.textContent = state.config?.["tproxy-port"] ? String(state.config["tproxy-port"]) : "-";
  refs.configAllowLanValue.textContent = typeof state.config?.["allow-lan"] === "boolean" ? (state.config["allow-lan"] ? "yes" : "no") : "-";
  refs.configBindValue.textContent = state.config?.["bind-address"] || "-";
  if (!state.logLevelChanging) {
    refs.runtimeLogLevelSelect.value = state.config?.["log-level"] || "info";
  }

  refs.currentGroupName.textContent = group?.name || "No group";
  refs.currentGroupMeta.textContent = group
    ? `${group.type} · current: ${group.now || "none"} · ${group.all.length} node(s)`
    : "Connect controller to load proxies.";
  refs.resetGroupButton.disabled = !group || state.busyGroups.has(group.name);
}

function renderControllerPanel() {
  refs.controllerDetailUrl.textContent = state.controllerUrl || "-";
  refs.embeddedUiValue.textContent = state.controllerUrl ? `${state.controllerUrl}/ui/` : "-";
  refs.controllerTokenValue.textContent = state.token ? `set (${state.token.length} chars)` : "not set";
  refs.controllerConfigPathValue.textContent = state.daeConfigPath || "-";
  refs.controllerPageNote.textContent = state.controllerUrl
    ? "HTTP requests use Bearer auth. WebSocket requests append token=... when a controller secret is set."
    : "Connect a dae controller to populate runtime details, startup config metadata, and live channels.";

  const streams = [
    ["version", wsState(state.versionWs, state.versionWsRetryTimer)],
    ["configs", wsState(state.configWs, state.configWsRetryTimer)],
    ["proxies", wsState(state.proxyWs, state.proxyWsRetryTimer)],
    ["traffic", wsState(state.ws, state.wsRetryTimer)],
    ["memory", wsState(state.memoryWs, state.memoryWsRetryTimer)],
    ["config.dae", wsState(state.daeConfigWs, state.daeConfigWsRetryTimer)],
    ["logs", wsState(state.logWs, state.logWsRetryTimer)],
  ];

  refs.streamList.innerHTML = streams
    .map(
      ([name, status]) => `
        <div class="stream-pill ${escapeHtml(status)}">
          <span>${escapeHtml(name)}</span>
          <strong>${escapeHtml(status)}</strong>
        </div>
      `,
    )
    .join("");

  refs.applyLogLevelButton.disabled = !state.controllerUrl || state.logLevelChanging || state.connecting;
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

function syncEditorLines() {
  const lines = Math.max(1, refs.configView.value.split("\n").length);
  refs.editorLines.innerHTML = Array.from({ length: lines }, (_, index) => `<span>${index + 1}</span>`).join("");
  refs.editorLines.scrollTop = refs.configView.scrollTop;
}

function renderDaeConfigEditor() {
  refs.configPathValue.textContent = state.daeConfigPath || "-";
  if (refs.configView.value !== state.daeConfigContent) {
    refs.configView.value = state.daeConfigContent;
  }
  syncEditorLines();
  refs.saveConfigButton.disabled = !state.controllerUrl || !state.daeConfigDirty;
  refs.refreshConfigButton.disabled = !state.controllerUrl;
}

async function loadDaeConfigDocument() {
  if (!state.controllerUrl) {
    return;
  }
  const doc = await apiFetch("/configs/dae");
  state.daeConfigDirty = false;
  applyDaeConfigDocument(doc);
  renderDaeConfigEditor();
}

function renderVersionTitle() {
  refs.versionLabel.textContent = state.version?.version || "unlinked";
}

function renderRuntimePanels() {
  renderVersionTitle();
  renderSystemStatus();
  renderControllerPanel();
  renderProxyTabs();
  renderProxyGrid();
  refs.reloadProxiesButton.disabled = !state.controllerUrl;
}

function renderLogs() {
  refs.logsLevelSelect.value = state.logsLevel;
  refs.toggleLogsButton.textContent = state.logsPaused ? "Resume" : "Pause";
  refs.toggleLogsButton.disabled = !state.controllerUrl;
  refs.clearLogsButton.disabled = state.logs.length === 0;
  refs.logsLevelSelect.disabled = !state.controllerUrl;

  let statusText = `Waiting for live events from /logs?format=structured&level=${state.logsLevel}.`;
  const currentState = wsState(state.logWs, state.logWsRetryTimer);
  if (!state.controllerUrl) {
    statusText = "Connect a controller to open the log stream.";
  } else if (state.logsPaused) {
    statusText = "Log stream paused locally. Resume to receive new events.";
  } else if (currentState === "live") {
    statusText = `Streaming live logs at level ${state.logsLevel}.`;
  } else if (currentState === "retrying" || currentState === "opening") {
    statusText = `Reconnecting /logs stream at level ${state.logsLevel}.`;
  }
  refs.logsStatusText.textContent = statusText;

  refs.logsEmpty.hidden = state.logs.length > 0;
  refs.logsList.innerHTML = state.logs
    .map((entry) => {
      const fields = Array.isArray(entry.fields) ? entry.fields : [];
      const fieldsText = fields.length ? fields.map((field) => `${field.key}=${field.value}`).join(" ") : "";
      return `
        <article class="log-entry">
          <div class="log-entry-top">
            <span class="log-time">${escapeHtml(entry.time || "--:--:--")}</span>
            <span class="log-level ${escapeHtml(entry.level || "info")}">${escapeHtml(entry.level || "info")}</span>
          </div>
          <p class="log-message">${escapeHtml(entry.message || "")}</p>
          ${fieldsText ? `<p class="log-fields">${escapeHtml(fieldsText)}</p>` : ""}
        </article>
      `;
    })
    .join("");
}

function renderAll() {
  renderViewState();
  renderHeaderStatus();
  renderTrafficMeta();
  renderRuntimePanels();
  renderDaeConfigEditor();
  renderLogs();
  renderChart();
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
      state.proxySignature = proxySnapshotSignature(state.proxies);
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
    if (state.proxies[group.name]) {
      state.proxies[group.name] = {
        ...state.proxies[group.name],
        now: name,
      };
      state.proxySignature = proxySnapshotSignature(state.proxies);
    }
    refs.editorNote.textContent = `Switched group ${group.name} to ${name} through /proxies/${group.name}.`;
  } catch (error) {
    refs.editorNote.textContent = `Failed to switch ${group.name} to ${name}: ${error.message}`;
  } finally {
    state.busyGroups.delete(group.name);
    renderSystemStatus();
    renderProxyGrid();
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
  } catch (error) {
    refs.editorNote.textContent = `Failed to reset ${group.name}: ${error.message}`;
  } finally {
    state.busyGroups.delete(group.name);
    renderSystemStatus();
    renderProxyGrid();
  }
}

async function resyncControllerAfterConfigSave() {
  let lastError = null;
  for (let attempt = 0; attempt < RELOAD_SYNC_ATTEMPTS; attempt += 1) {
    await sleep(RELOAD_SYNC_DELAY_MS);
    try {
      const [version, config, proxiesPayload, daeConfig] = await Promise.all([
        apiFetch("/version"),
        apiFetch("/configs"),
        apiFetch("/proxies"),
        apiFetch("/configs/dae"),
      ]);

      applyVersionSnapshot(version);
      applyConfigSnapshot(config);
      applyProxySnapshot(proxiesPayload.proxies);
      state.daeConfigDirty = false;
      applyDaeConfigDocument(daeConfig);

      setApiStatus("connected", "Connected");
      refs.controllerHint.textContent =
        "Connected to dae external controller. Runtime state snapshots stream every 5 seconds over WebSocket, and config edits write back to startup `config.dae`.";
      connectVersionSocket();
      connectConfigSocket();
      connectProxySocket();
      connectTrafficSocket();
      connectMemorySocket();
      connectDaeConfigSocket();
      if (state.currentView === "logs" && !state.logsPaused) {
        connectLogSocket();
      }
      renderRuntimePanels();
      renderDaeConfigEditor();
      renderLogs();
      refs.editorNote.textContent = `Saved ${state.daeConfigPath || "config.dae"} and reloaded dae.`;
      return;
    } catch (error) {
      lastError = error;
    }
  }

  if (lastError) {
    handleConnectionError(lastError);
    refs.editorNote.textContent = `Config was written, but dae did not come back cleanly: ${lastError.message}`;
  }
}

async function saveDaeConfig() {
  if (!state.controllerUrl) {
    return;
  }

  refs.saveConfigButton.disabled = true;
  refs.refreshConfigButton.disabled = true;
  try {
    const content = refs.configView.value;
    await apiFetch("/configs/dae", {
      method: "PUT",
      body: JSON.stringify({ content }),
    });
    state.daeConfigContent = content;
    refs.editorNote.textContent = `Saved ${state.daeConfigPath || "config.dae"}. Waiting for dae to reload...`;
    await resyncControllerAfterConfigSave();
  } catch (error) {
    refs.editorNote.textContent = `Failed to save config.dae: ${error.message}`;
  } finally {
    renderDaeConfigEditor();
  }
}

async function updateRuntimeLogLevel() {
  if (!state.controllerUrl) {
    return;
  }

  const level = refs.runtimeLogLevelSelect.value;
  if (!LOG_LEVELS.includes(level)) {
    refs.runtimeLogLevelNote.textContent = `Unsupported log level: ${level}`;
    return;
  }

  state.logLevelChanging = true;
  renderControllerPanel();

  try {
    await apiFetch("/configs", {
      method: "PATCH",
      body: JSON.stringify({ "log-level": level }),
    });
    applyConfigSnapshot({
      ...(state.config || {}),
      "log-level": level,
    });
    refs.runtimeLogLevelNote.textContent = `Runtime log level updated to ${level}.`;
  } catch (error) {
    refs.runtimeLogLevelNote.textContent = `Failed to update runtime log level: ${error.message}`;
  } finally {
    state.logLevelChanging = false;
    renderControllerPanel();
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

  refs.navItems.forEach((item) => {
    item.addEventListener("click", () => {
      setActiveView(item.dataset.view);
    });
  });

  refs.viewButtons.forEach((button) => {
    button.addEventListener("click", () => {
      setActiveView(button.dataset.openView);
    });
  });

  refs.refreshConfigButton.addEventListener("click", () => {
    loadDaeConfigDocument()
      .then(() => {
        refs.editorNote.textContent = state.daeConfigPath
          ? `Reloaded ${state.daeConfigPath} from disk.`
          : "Reloaded config.dae from disk.";
      })
      .catch((error) => {
        refs.editorNote.textContent = `Failed to reload config.dae: ${error.message}`;
      });
  });

  refs.reloadProxiesButton.addEventListener("click", () => {
    closeProxySocket();
    connectProxySocket();
    refs.editorNote.textContent = "Reconnected proxy stream.";
  });

  refs.saveConfigButton.addEventListener("click", () => {
    saveDaeConfig();
  });

  refs.applyLogLevelButton.addEventListener("click", () => {
    updateRuntimeLogLevel();
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
    renderSystemStatus();
    renderProxyTabs();
    renderProxyGrid();
  });

  refs.proxyGrid.addEventListener("click", handleProxyGridClick);
  refs.configView.addEventListener("input", () => {
    state.daeConfigDirty = refs.configView.value !== state.daeConfigContent;
    syncEditorLines();
    refs.saveConfigButton.disabled = !state.controllerUrl || !state.daeConfigDirty;
  });
  refs.configView.addEventListener("scroll", () => {
    refs.editorLines.scrollTop = refs.configView.scrollTop;
  });
  refs.logsLevelSelect.addEventListener("change", () => {
    state.logsLevel = refs.logsLevelSelect.value;
    if (state.currentView === "logs" && state.controllerUrl && !state.logsPaused) {
      connectLogSocket();
    }
    renderLogs();
  });
  refs.toggleLogsButton.addEventListener("click", () => {
    state.logsPaused = !state.logsPaused;
    if (state.logsPaused) {
      closeLogSocket();
    } else if (state.currentView === "logs" && state.controllerUrl) {
      connectLogSocket();
    }
    renderControllerPanel();
    renderLogs();
  });
  refs.clearLogsButton.addEventListener("click", () => {
    state.logs = [];
    renderLogs();
  });
  window.addEventListener("resize", renderChart);
}

function boot() {
  loadPersistedConnection();
  bindEvents();
  refs.logsLevelSelect.value = state.logsLevel;
  refs.runtimeLogLevelSelect.value = "info";
  setActiveView(state.currentView);
  renderAll();
  if (state.controllerUrl) {
    connectController();
  }
}

boot();
