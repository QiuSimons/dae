const DEFAULT_CONFIG_PLACEHOLDER = "# Connect controller to load /etc/dae/config.dae";
const DEFAULT_CONTROLLER_HINT =
  "登录后开始同步 Dashboard、Traffic、Proxies、Logs 和 Config。";
const DEFAULT_EDITOR_NOTE = "按 section 折叠编辑 config.dae；常见块走 GUI Builder，复杂语法可切到 Raw。";
const DEFAULT_LOG_LEVEL_NOTE = "通过 PATCH /configs 更新运行时日志级别，并保持页面状态同步。";
const SAMPLE_SIZE = 20;
const TRAFFIC_SAMPLE_INTERVAL_MS = 5000;
const CONNECTION_LIMIT = 200;
const RELOAD_SYNC_ATTEMPTS = 8;
const RELOAD_SYNC_DELAY_MS = 800;
const MAX_LOG_ENTRIES = 200;
const RETRY_DELAY_MS = 3000;
const LOG_LEVELS = ["trace", "debug", "info", "warn", "error"];
const DIAL_MODES = ["ip", "domain", "domain+", "domain++"];
const GUI_CONFIG_SECTIONS = new Set(["global", "subscription", "node", "dns", "group", "routing", "include"]);
const CONFIG_SECTION_TYPES = ["global", "subscription", "node", "dns", "group", "routing", "include"];
const GLOBAL_FIELD_DEFS = [
  {
    key: "log_level",
    label: "Log Level",
    type: "select",
    options: LOG_LEVELS,
    placeholder: "Select log level",
  },
  {
    key: "external_controller",
    label: "External Controller",
    type: "text",
    placeholder: "127.0.0.1:9090",
  },
  {
    key: "external_controller_secret",
    label: "Controller Token",
    type: "text",
    placeholder: "password",
  },
  {
    key: "tproxy_port",
    label: "TProxy Port",
    type: "number",
    placeholder: "12345",
  },
  {
    key: "wan_interface",
    label: "WAN Interface",
    type: "text",
    placeholder: "auto",
  },
  {
    key: "lan_interface",
    label: "LAN Interface",
    type: "text",
    placeholder: "eth0,br-lan",
  },
  {
    key: "dial_mode",
    label: "Dial Mode",
    type: "select",
    options: DIAL_MODES,
    placeholder: "Select dial mode",
  },
  {
    key: "allow_insecure",
    label: "Allow Insecure",
    type: "boolean",
  },
  {
    key: "disable_waiting_network",
    label: "Disable Waiting Network",
    type: "boolean",
  },
  {
    key: "auto_config_kernel_parameter",
    label: "Auto Kernel Param",
    type: "boolean",
  },
];

const VIEW_META = {
  dashboard: {
    eyebrow: "Dashboard",
    title: "daed Dashboard",
    banner: "Overview",
  },
  proxies: {
    eyebrow: "Proxies",
    title: "Proxy Runtime",
    banner: "Proxy Groups",
  },
  traffic: {
    eyebrow: "Traffic",
    title: "Realtime Traffic",
    banner: "Traffic Flow",
  },
  configs: {
    eyebrow: "Config",
    title: "Startup Config",
    banner: "config.dae Builder",
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
  sidebarCollapsed: "daed-demo-sidebar-collapsed",
  connectionSort: "daed-demo-connection-sort",
};

const CONFIG_SECTION_DESCRIPTIONS = {
  include: "拆分配置入口和 include 路径。",
  global: "全局运行参数、控制器、网络接口和拨号行为。",
  subscription: "订阅链接和订阅标签。",
  node: "手工添加的节点链接。",
  dns: "DNS 上游、绑定地址与 DNS routing。",
  group: "代理组、选路策略和组内筛选。",
  routing: "流量分流与 fallback 规则。",
  document: "无法拆分时按整份文档编辑。",
};

const refs = {
  controllerForm: document.getElementById("controllerForm"),
  controllerUrlField: document.getElementById("controllerUrlField"),
  controllerUrl: document.getElementById("controllerUrl"),
  controllerToken: document.getElementById("controllerToken"),
  controllerHint: document.getElementById("controllerHint"),
  connectButton: document.getElementById("connectButton"),
  controllerTopToggle: document.getElementById("controllerTopToggle"),
  controllerSummaryUrl: document.getElementById("controllerSummaryUrl"),
  controllerSummaryMeta: document.getElementById("controllerSummaryMeta"),
  controllerPanelTitle: document.getElementById("controllerPanelTitle"),
  pageEyebrow: document.getElementById("pageEyebrow"),
  pageTitle: document.getElementById("pageTitle"),
  pageBanner: document.getElementById("pageBanner"),
  versionLabel: document.getElementById("versionLabel"),
  navItems: Array.from(document.querySelectorAll(".nav-item[data-view]")),
  viewButtons: Array.from(document.querySelectorAll("[data-open-view]")),
  pages: Array.from(document.querySelectorAll(".page[data-page]")),
  sidebarToggles: Array.from(document.querySelectorAll("[data-sidebar-toggle]")),
  apiStatusText: document.getElementById("apiStatusText"),
  apiStatusDot: document.getElementById("apiStatusDot"),
  sidebarControllerText: document.getElementById("sidebarControllerText"),
  sidebarConnectionsValue: document.getElementById("sidebarConnectionsValue"),
  topConnectionsValue: document.getElementById("topConnectionsValue"),
  uploadRate: document.getElementById("uploadRate"),
  downloadRate: document.getElementById("downloadRate"),
  dashboardModeValue: document.getElementById("dashboardModeValue"),
  dashboardLogLevelValue: document.getElementById("dashboardLogLevelValue"),
  dashboardMemoryValue: document.getElementById("dashboardMemoryValue"),
  dashboardRssValue: document.getElementById("dashboardRssValue"),
  dashboardAliveValue: document.getElementById("dashboardAliveValue"),
  dashboardUpValue: document.getElementById("dashboardUpValue"),
  dashboardDownValue: document.getElementById("dashboardDownValue"),
  runtimeVersionValue: document.getElementById("runtimeVersionValue"),
  uploadTotalValue: document.getElementById("uploadTotalValue"),
  downloadTotalValue: document.getElementById("downloadTotalValue"),
  dashboardTrafficChart: document.getElementById("dashboardTrafficChart"),
  dashboardChartScale: document.getElementById("dashboardChartScale"),
  dashboardChartTime: document.getElementById("dashboardChartTime"),
  dashboardConnectionsTotal: document.getElementById("dashboardConnectionsTotal"),
  dashboardConnectionsTcp: document.getElementById("dashboardConnectionsTcp"),
  dashboardConnectionsUdp: document.getElementById("dashboardConnectionsUdp"),
  dashboardConnectionsUpdated: document.getElementById("dashboardConnectionsUpdated"),
  dashboardConnectionList: document.getElementById("dashboardConnectionList"),
  dashboardProxyTabs: document.getElementById("dashboardProxyTabs"),
  dashboardProxyGrid: document.getElementById("dashboardProxyGrid"),
  dashboardCurrentGroupName: document.getElementById("dashboardCurrentGroupName"),
  dashboardCurrentGroupMeta: document.getElementById("dashboardCurrentGroupMeta"),
  runtimeLogLevelSelect: document.getElementById("runtimeLogLevelSelect"),
  applyLogLevelButton: document.getElementById("applyLogLevelButton"),
  runtimeLogLevelNote: document.getElementById("runtimeLogLevelNote"),
  proxyTabs: document.getElementById("proxyTabs"),
  proxyGrid: document.getElementById("proxyGrid"),
  currentGroupName: document.getElementById("currentGroupName"),
  currentGroupMeta: document.getElementById("currentGroupMeta"),
  resetGroupButton: document.getElementById("resetGroupButton"),
  reloadProxiesButton: document.getElementById("reloadProxiesButton"),
  trafficChart: document.getElementById("trafficChart"),
  chartScale: document.getElementById("chartScale"),
  chartTime: document.getElementById("chartTime"),
  trafficUploadTotalValue: document.getElementById("trafficUploadTotalValue"),
  trafficDownloadTotalValue: document.getElementById("trafficDownloadTotalValue"),
  trafficConnectionsTotal: document.getElementById("trafficConnectionsTotal"),
  trafficConnectionsTcp: document.getElementById("trafficConnectionsTcp"),
  trafficConnectionsUdp: document.getElementById("trafficConnectionsUdp"),
  trafficConnectionsUpdated: document.getElementById("trafficConnectionsUpdated"),
  trafficConnectionsList: document.getElementById("trafficConnectionsList"),
  trafficConnectionsEmpty: document.getElementById("trafficConnectionsEmpty"),
  trafficSortSelect: document.getElementById("trafficSortSelect"),
  configPathValue: document.getElementById("configPathValue"),
  configSectionsCountValue: document.getElementById("configSectionsCountValue"),
  configCurrentSectionValue: document.getElementById("configCurrentSectionValue"),
  configSectionTypeSelect: document.getElementById("configSectionTypeSelect"),
  addConfigSectionButton: document.getElementById("addConfigSectionButton"),
  configSectionTabs: document.getElementById("configSectionTabs"),
  saveConfigButton: document.getElementById("saveConfigButton"),
  refreshConfigButton: document.getElementById("refreshConfigButton"),
  editorNote: document.getElementById("editorNote"),
  logsLevelSelect: document.getElementById("logsLevelSelect"),
  toggleLogsButton: document.getElementById("toggleLogsButton"),
  clearLogsButton: document.getElementById("clearLogsButton"),
  logsStatusText: document.getElementById("logsStatusText"),
  logsEmpty: document.getElementById("logsEmpty"),
  logsList: document.getElementById("logsList"),
};

function createSocketRecord() {
  return {
    socket: null,
    retryTimer: null,
    closeIntent: false,
  };
}

function createEmptySeries() {
  const now = Date.now();
  return {
    up: Array(SAMPLE_SIZE).fill(0),
    down: Array(SAMPLE_SIZE).fill(0),
    times: Array.from({ length: SAMPLE_SIZE }, (_, index) => now - (SAMPLE_SIZE - index - 1) * TRAFFIC_SAMPLE_INTERVAL_MS),
  };
}

function createEmptyConnectionsSnapshot() {
  return {
    updatedAt: "",
    total: 0,
    tcp: 0,
    udp: 0,
    connections: [],
  };
}

function createFallbackSections(content) {
  return [buildConfigSection(content, 0, "document")];
}

const state = {
  controllerUrl: "",
  token: "",
  currentView: "dashboard",
  apiStatus: {
    kind: "offline",
    message: "Disconnected",
  },
  controllerHintText: DEFAULT_CONTROLLER_HINT,
  editorNoteText: DEFAULT_EDITOR_NOTE,
  runtimeLogLevelNoteText: DEFAULT_LOG_LEVEL_NOTE,
  version: null,
  versionSignature: "",
  config: null,
  configSignature: "",
  memory: null,
  traffic: {
    up: 0,
    down: 0,
    upTotal: 0,
    downTotal: 0,
  },
  trafficSeries: createEmptySeries(),
  trafficTransport: "idle",
  connections: createEmptyConnectionsSnapshot(),
  connectionsSignature: "",
  connectionsAvailable: false,
  proxies: {},
  groups: [],
  selectedGroup: "",
  proxySignature: "",
  daeConfigPath: "",
  daeConfigOriginal: DEFAULT_CONFIG_PLACEHOLDER,
  daeConfigContent: DEFAULT_CONFIG_PLACEHOLDER,
  daeConfigSignature: "",
  daeConfigSections: createFallbackSections(DEFAULT_CONFIG_PLACEHOLDER),
  daeConfigSelected: "document-0",
  daeConfigDirty: false,
  logs: [],
  logsPaused: false,
  logsLevel: "info",
  refreshing: false,
  connecting: false,
  logLevelChanging: false,
  sidebarCollapsed: false,
  connectionSort: "download-speed",
  controllerExpanded: true,
  busyGroups: new Set(),
  busyDelayNodes: new Set(),
  sockets: {
    traffic: createSocketRecord(),
    memory: createSocketRecord(),
    version: createSocketRecord(),
    config: createSocketRecord(),
    daeConfig: createSocketRecord(),
    connections: createSocketRecord(),
    proxies: createSocketRecord(),
    logs: createSocketRecord(),
  },
};

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

function connectionsSnapshotSignature(payload, available = true) {
  return stableJson({
    available: Boolean(available),
    updatedAt: payload?.updatedAt || "",
    total: Number(payload?.total || 0),
    tcp: Number(payload?.tcp || 0),
    udp: Number(payload?.udp || 0),
    connections: Array.isArray(payload?.connections)
      ? payload.connections.map((conn) => ({
          id: conn?.id || "",
          network: conn?.network || "",
          state: conn?.state || "",
          source: conn?.source || "",
          sourceAddress: conn?.sourceAddress || "",
          sourcePort: Number(conn?.sourcePort || 0),
          destination: conn?.destination || "",
          destinationAddress: conn?.destinationAddress || "",
          destinationPort: Number(conn?.destinationPort || 0),
          process: conn?.process || "",
          pid: Number(conn?.pid || 0),
          outbound: conn?.outbound || "",
          direction: conn?.direction || "",
          mark: Number(conn?.mark || 0),
          dscp: Number(conn?.dscp || 0),
          must: Boolean(conn?.must),
          hasRouting: Boolean(conn?.hasRouting),
          mac: conn?.mac || "",
          lastSeen: conn?.lastSeen || "",
          uploadSpeed: Number(conn?.uploadSpeed || 0),
          downloadSpeed: Number(conn?.downloadSpeed || 0),
          uploadTotal: Number(conn?.uploadTotal || 0),
          downloadTotal: Number(conn?.downloadTotal || 0),
        }))
      : [],
  });
}

function proxyDelay(proxy) {
  const entry = Array.isArray(proxy?.history) ? proxy.history[0] : null;
  if (!entry || typeof entry.delay !== "number") {
    return null;
  }
  return entry.delay;
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

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

function bytesToMegabytes(value) {
  return Number(value || 0) / (1024 * 1024);
}

function shortRate(value) {
  return bytesToMegabytes(value).toFixed(1);
}

function formatByteRate(value) {
  return `${humanBytes(value)}/s`;
}

function formatYesNo(value) {
  if (typeof value !== "boolean") {
    return "-";
  }
  return value ? "yes" : "no";
}

function formatClock(value) {
  if (!value) {
    return "-";
  }
  const time = new Date(value);
  if (Number.isNaN(time.getTime())) {
    return "-";
  }
  return time.toLocaleTimeString("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

function formatTimeAgo(value) {
  if (!value) {
    return "-";
  }
  const time = new Date(value);
  const diffSeconds = Math.max(0, Math.floor((Date.now() - time.getTime()) / 1000));
  if (Number.isNaN(diffSeconds)) {
    return "-";
  }
  if (diffSeconds < 60) {
    return `${diffSeconds}s ago`;
  }
  if (diffSeconds < 3600) {
    return `${Math.floor(diffSeconds / 60)}m ago`;
  }
  return formatClock(value);
}

function titleCase(value) {
  return value
    .split(/[_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function classToken(value, fallback = "unknown") {
  const token = String(value || fallback)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return token || fallback;
}

function formatEndpoint(address, port) {
  const host = String(address || "").trim();
  const portNumber = Number(port || 0);
  if (!host || host === "-") {
    return "-";
  }
  return portNumber > 0 ? `${host}:${portNumber}` : host;
}

function formatConnectionLabel(label, address, port) {
  const primary = String(label || "").trim();
  if (primary && primary !== "-") {
    return primary;
  }
  return formatEndpoint(address, port);
}

function parseTimestamp(value) {
  const time = new Date(value);
  if (Number.isNaN(time.getTime())) {
    return 0;
  }
  return time.getTime();
}

function sortTrafficConnections(connections) {
  const ordered = [...connections];
  const sortMode = state.connectionSort;
  ordered.sort((left, right) => {
    let result = 0;

    if (sortMode === "upload-speed") {
      result = (right.uploadSpeed || 0) - (left.uploadSpeed || 0);
    } else if (sortMode === "download-total") {
      result = (right.downloadTotal || 0) - (left.downloadTotal || 0);
    } else if (sortMode === "upload-total") {
      result = (right.uploadTotal || 0) - (left.uploadTotal || 0);
    } else if (sortMode === "updated") {
      result = parseTimestamp(right.lastSeen) - parseTimestamp(left.lastSeen);
    } else if (sortMode === "process") {
      result = String(left.process || "").localeCompare(String(right.process || ""), "zh-CN");
    } else {
      result = (right.downloadSpeed || 0) - (left.downloadSpeed || 0);
    }

    if (result !== 0) {
      return result;
    }

    const bySeen = parseTimestamp(right.lastSeen) - parseTimestamp(left.lastSeen);
    if (bySeen !== 0) {
      return bySeen;
    }

    return String(left.id || "").localeCompare(String(right.id || ""), "zh-CN");
  });
  return ordered;
}

function isCompactMobileViewport() {
  return window.matchMedia("(max-width: 720px)").matches;
}

function resetLiveState() {
  state.version = null;
  state.versionSignature = "";
  state.config = null;
  state.configSignature = "";
  state.memory = null;
  state.traffic = {
    up: 0,
    down: 0,
    upTotal: 0,
    downTotal: 0,
  };
  state.trafficSeries = createEmptySeries();
  state.trafficTransport = "idle";
  state.connections = createEmptyConnectionsSnapshot();
  state.connectionsSignature = "";
  state.connectionsAvailable = false;
  state.proxies = {};
  state.groups = [];
  state.selectedGroup = "";
  state.proxySignature = "";
  state.daeConfigPath = "";
  state.daeConfigOriginal = DEFAULT_CONFIG_PLACEHOLDER;
  state.daeConfigContent = DEFAULT_CONFIG_PLACEHOLDER;
  state.daeConfigSignature = "";
  state.daeConfigSections = createFallbackSections(DEFAULT_CONFIG_PLACEHOLDER);
  state.daeConfigSelected = state.daeConfigSections[0].id;
  state.daeConfigDirty = false;
  state.logs = [];
  state.logsPaused = false;
  state.controllerHintText = DEFAULT_CONTROLLER_HINT;
  state.editorNoteText = DEFAULT_EDITOR_NOTE;
  state.runtimeLogLevelNoteText = DEFAULT_LOG_LEVEL_NOTE;
}

function isEmbeddedUIPath() {
  return window.location.pathname === "/ui" || window.location.pathname === "/ui/" || window.location.pathname.startsWith("/ui/");
}

function locationHashParams() {
  const raw = window.location.hash.replace(/^#\/?/, "").replace(/^\?/, "");
  return new URLSearchParams(raw);
}

function syncControllerInputs() {
  refs.controllerUrl.value = state.controllerUrl;
  refs.controllerToken.value = state.token;
}

function loadPersistedConnection() {
  const query = new URLSearchParams(window.location.search);
  const hash = locationHashParams();
  const urlFromQuery = query.get("controller");
  const tokenFromQuery = query.get("token");
  const tokenFromHash = hash.get("token");
  const servedByEmbeddedUI = isEmbeddedUIPath();
  const sameOriginController = servedByEmbeddedUI ? window.location.origin : "";

  state.controllerUrl = urlFromQuery || sameOriginController || window.localStorage.getItem(STORAGE_KEYS.controller) || "";
  state.token = tokenFromQuery || tokenFromHash || window.localStorage.getItem(STORAGE_KEYS.token) || "";
  syncControllerInputs();
}

function applyLocationCredentialsAndReconnect() {
  const previousUrl = state.controllerUrl;
  const previousToken = state.token;
  loadPersistedConnection();
  renderControllerPanel();
  if (!state.controllerUrl) {
    return;
  }
  if (previousUrl === state.controllerUrl && previousToken === state.token) {
    return;
  }
  connectController();
}

function loadUiPrefs() {
  state.sidebarCollapsed = window.localStorage.getItem(STORAGE_KEYS.sidebarCollapsed) === "true";
  state.connectionSort = window.localStorage.getItem(STORAGE_KEYS.connectionSort) || "download-speed";
}

function persistConnection() {
  window.localStorage.setItem(STORAGE_KEYS.controller, state.controllerUrl);
  window.localStorage.setItem(STORAGE_KEYS.token, state.token);
}

function persistUiPrefs() {
  window.localStorage.setItem(STORAGE_KEYS.sidebarCollapsed, String(state.sidebarCollapsed));
  window.localStorage.setItem(STORAGE_KEYS.connectionSort, state.connectionSort);
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
      // Keep the default HTTP message when the body is not JSON.
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

function clearRetryTimer(name) {
  const record = state.sockets[name];
  if (!record?.retryTimer) {
    return;
  }
  window.clearTimeout(record.retryTimer);
  record.retryTimer = null;
}

function scheduleSocketRetry(name, callback) {
  clearRetryTimer(name);
  state.sockets[name].retryTimer = window.setTimeout(() => {
    state.sockets[name].retryTimer = null;
    callback();
  }, RETRY_DELAY_MS);
}

function closeSocket(name) {
  const record = state.sockets[name];
  if (!record) {
    return;
  }
  clearRetryTimer(name);
  if (record.socket) {
    record.closeIntent = true;
    record.socket.close();
  }
}

function closeAllSockets() {
  Object.keys(state.sockets).forEach((name) => {
    closeSocket(name);
  });
  state.trafficTransport = "idle";
}

function wsState(name) {
  if (!state.controllerUrl) {
    return "idle";
  }
  const record = state.sockets[name];
  if (record?.socket?.readyState === WebSocket.OPEN) {
    return "live";
  }
  if (record?.socket?.readyState === WebSocket.CONNECTING) {
    return "opening";
  }
  if (record?.retryTimer) {
    return "retrying";
  }
  return state.apiStatus.kind === "connected" ? "standby" : "offline";
}

function openSocket(name, path, options) {
  closeSocket(name);

  let url;
  try {
    url = typeof options.buildUrl === "function" ? options.buildUrl() : buildWebSocketUrl(path);
  } catch {
    options.onOpenFailure?.();
    if (options.shouldRetry?.()) {
      scheduleSocketRetry(name, options.retry);
    }
    return;
  }

  let socket;
  try {
    socket = new WebSocket(url);
  } catch {
    options.onOpenFailure?.();
    if (options.shouldRetry?.()) {
      scheduleSocketRetry(name, options.retry);
    }
    return;
  }

  const record = state.sockets[name];
  record.closeIntent = false;
  record.socket = socket;
  options.onStart?.();

  socket.addEventListener("open", () => {
    if (record.socket !== socket) {
      return;
    }
    options.onOpen?.();
  });

  socket.addEventListener("message", (event) => {
    if (record.socket !== socket) {
      return;
    }
    options.onMessage?.(event.data);
  });

  socket.addEventListener("close", () => {
    if (record.socket !== socket) {
      return;
    }
    record.socket = null;
    const intentional = record.closeIntent;
    record.closeIntent = false;
    if (intentional) {
      options.onIntentionalClose?.();
      return;
    }
    options.onClose?.();
    if (options.shouldRetry?.()) {
      scheduleSocketRetry(name, options.retry);
    }
  });
}

function connectTrafficSocket() {
  openSocket("traffic", "/traffic", {
    onStart() {
      state.trafficTransport = "ws connecting";
      renderTrafficMeta();
      renderControllerPanel();
    },
    onOpen() {
      state.trafficTransport = "websocket";
      renderTrafficMeta();
      renderControllerPanel();
    },
    onMessage(data) {
      try {
        applyTrafficSnapshot(JSON.parse(data), true);
      } catch {
        // Ignore malformed frames and keep the chart stable.
      }
    },
    onClose() {
      state.trafficTransport = "ws closed";
      renderTrafficMeta();
      renderControllerPanel();
    },
    onIntentionalClose() {
      renderControllerPanel();
    },
    onOpenFailure() {
      state.trafficTransport = "ws failed";
      renderTrafficMeta();
      renderControllerPanel();
    },
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectTrafficSocket();
      }
    },
  });
}

function connectMemorySocket() {
  openSocket("memory", "/memory", {
    onStart: renderControllerPanel,
    onOpen: renderControllerPanel,
    onMessage(data) {
      try {
        updateMemory(JSON.parse(data));
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose: renderControllerPanel,
    onIntentionalClose: renderControllerPanel,
    onOpenFailure: renderControllerPanel,
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectMemorySocket();
      }
    },
  });
}

function connectVersionSocket() {
  openSocket("version", "/version", {
    onStart: renderControllerPanel,
    onOpen: renderControllerPanel,
    onMessage(data) {
      try {
        applyVersionSnapshot(JSON.parse(data));
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose: renderControllerPanel,
    onIntentionalClose: renderControllerPanel,
    onOpenFailure: renderControllerPanel,
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectVersionSocket();
      }
    },
  });
}

function connectConfigSocket() {
  openSocket("config", "/configs", {
    onStart: renderControllerPanel,
    onOpen: renderControllerPanel,
    onMessage(data) {
      try {
        applyConfigSnapshot(JSON.parse(data));
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose: renderControllerPanel,
    onIntentionalClose: renderControllerPanel,
    onOpenFailure: renderControllerPanel,
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectConfigSocket();
      }
    },
  });
}

function connectProxySocket() {
  openSocket("proxies", "/proxies", {
    onStart: renderControllerPanel,
    onOpen: renderControllerPanel,
    onMessage(data) {
      try {
        const payload = JSON.parse(data);
        applyProxySnapshot(payload.proxies);
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose: renderControllerPanel,
    onIntentionalClose: renderControllerPanel,
    onOpenFailure: renderControllerPanel,
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectProxySocket();
      }
    },
  });
}

function connectConnectionsSocket() {
  if (!state.connectionsAvailable) {
    renderControllerPanel();
    return;
  }
  openSocket("connections", "/connections", {
    buildUrl() {
      const url = buildHttpUrl(`/connections?limit=${CONNECTION_LIMIT}`);
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      if (state.token) {
        url.searchParams.set("token", state.token);
      }
      return url.toString();
    },
    onStart: renderControllerPanel,
    onOpen: renderControllerPanel,
    onMessage(data) {
      try {
        applyConnectionsSnapshot(JSON.parse(data));
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose: renderControllerPanel,
    onIntentionalClose: renderControllerPanel,
    onOpenFailure: renderControllerPanel,
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectConnectionsSocket();
      }
    },
  });
}

function connectDaeConfigSocket() {
  openSocket("daeConfig", "/configs/dae", {
    onStart: renderControllerPanel,
    onOpen: renderControllerPanel,
    onMessage(data) {
      try {
        applyDaeConfigDocument(JSON.parse(data));
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose: renderControllerPanel,
    onIntentionalClose: renderControllerPanel,
    onOpenFailure: renderControllerPanel,
    shouldRetry() {
      return Boolean(state.controllerUrl);
    },
    retry() {
      if (state.controllerUrl) {
        connectDaeConfigSocket();
      }
    },
  });
}

function connectLogSocket() {
  if (state.currentView !== "logs" || state.logsPaused || !state.controllerUrl) {
    return;
  }

  openSocket("logs", "/logs", {
    buildUrl() {
      const url = buildHttpUrl("/logs");
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      if (state.token) {
        url.searchParams.set("token", state.token);
      }
      url.searchParams.set("format", "structured");
      url.searchParams.set("level", state.logsLevel);
      return url.toString();
    },
    onStart() {
      renderControllerPanel();
      renderLogs();
    },
    onOpen() {
      renderControllerPanel();
      renderLogs();
    },
    onMessage(data) {
      try {
        pushLogEntry(JSON.parse(data));
        renderLogs();
      } catch {
        // Ignore malformed frames.
      }
    },
    onClose() {
      renderControllerPanel();
      renderLogs();
    },
    onIntentionalClose() {
      renderControllerPanel();
      renderLogs();
    },
    onOpenFailure() {
      renderControllerPanel();
      renderLogs();
    },
    shouldRetry() {
      return Boolean(state.controllerUrl && state.currentView === "logs" && !state.logsPaused);
    },
    retry() {
      if (state.controllerUrl && state.currentView === "logs" && !state.logsPaused) {
        connectLogSocket();
      }
    },
  });
}

function openLiveChannels() {
  connectVersionSocket();
  connectConfigSocket();
  connectProxySocket();
  connectTrafficSocket();
  connectMemorySocket();
  if (state.connectionsAvailable) {
    connectConnectionsSocket();
  }
  connectDaeConfigSocket();
  if (state.currentView === "logs" && !state.logsPaused) {
    connectLogSocket();
  }
}

function pushLogEntry(entry) {
  state.logs.unshift(entry);
  if (state.logs.length > MAX_LOG_ENTRIES) {
    state.logs.length = MAX_LOG_ENTRIES;
  }
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

function normalizeConnectionsSnapshot(payload) {
  return {
    updatedAt: payload?.updatedAt || "",
    total: Number(payload?.total || 0),
    tcp: Number(payload?.tcp || 0),
    udp: Number(payload?.udp || 0),
    connections: Array.isArray(payload?.connections)
      ? payload.connections.map((conn) => ({
          id: conn?.id || "",
          network: conn?.network || "-",
          state: conn?.state || "-",
          source: conn?.source || "-",
          sourceAddress: conn?.sourceAddress || "",
          sourcePort: Number(conn?.sourcePort || 0),
          destination: conn?.destination || "-",
          destinationAddress: conn?.destinationAddress || "",
          destinationPort: Number(conn?.destinationPort || 0),
          process: conn?.process || "-",
          pid: Number(conn?.pid || 0),
          outbound: conn?.outbound || "-",
          direction: conn?.direction || "-",
          mark: Number(conn?.mark || 0),
          dscp: Number(conn?.dscp || 0),
          must: Boolean(conn?.must),
          hasRouting: Boolean(conn?.hasRouting),
          mac: conn?.mac || "-",
          lastSeen: conn?.lastSeen || "",
          uploadSpeed: Number(conn?.uploadSpeed || 0),
          downloadSpeed: Number(conn?.downloadSpeed || 0),
          uploadTotal: Number(conn?.uploadTotal || 0),
          downloadTotal: Number(conn?.downloadTotal || 0),
        }))
      : [],
  };
}

function applyConnectionsSnapshot(payload, available = true) {
  const signature = connectionsSnapshotSignature(payload, available);
  if (signature === state.connectionsSignature) {
    return;
  }
  state.connectionsSignature = signature;
  state.connections = normalizeConnectionsSnapshot(payload);
  state.connectionsAvailable = Boolean(available);
  if (!state.connectionsAvailable) {
    closeSocket("connections");
  }
  renderHeaderStatus();
  renderConnections();
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
  state.daeConfigPath = doc?.path || "";
  const signature = daeConfigDocumentSignature(doc);
  if (signature === state.daeConfigSignature) {
    renderConfigMeta();
    return;
  }
  state.daeConfigSignature = signature;
  if (!state.daeConfigDirty) {
    const content = typeof doc?.content === "string" ? doc.content : "";
    state.daeConfigOriginal = content;
    state.daeConfigContent = content;
    state.daeConfigSections = parseConfigSections(content);
    if (!state.daeConfigSections.some((section) => section.id === state.daeConfigSelected)) {
      state.daeConfigSelected = state.daeConfigSections[0]?.id || "";
    }
    state.daeConfigDirty = false;
  }
  renderDaeConfigEditor();
  renderSystemStatus();
}

function applyTrafficSnapshot(payload, appendSample) {
  state.traffic = {
    up: Number(payload?.up || 0),
    down: Number(payload?.down || 0),
    upTotal: Number(payload?.upTotal || 0),
    downTotal: Number(payload?.downTotal || 0),
  };

  if (appendSample) {
    state.trafficSeries.up.push(state.traffic.up);
    state.trafficSeries.down.push(state.traffic.down);
    state.trafficSeries.times.push(Date.now());
    trimTrafficSeries();
  }

  renderTrafficMeta();
  renderCharts();
}

function updateMemory(payload) {
  state.memory = {
    inuse: Number(payload?.inuse || 0),
    rss: Number(payload?.rss || 0),
    oslimit: Number(payload?.oslimit || 0),
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

function refreshProxyCollections(rawProxies) {
  state.proxies = rawProxies || {};
  state.groups = Object.values(state.proxies).filter((proxy) => Array.isArray(proxy.all) && proxy.all.length > 0);
  if (!state.groups.some((group) => group.name === state.selectedGroup)) {
    state.selectedGroup = state.groups[0]?.name || "";
  }
}

function currentGroup() {
  return state.groups.find((group) => group.name === state.selectedGroup) || null;
}

function computeLeafStats() {
  const leaves = Object.values(state.proxies).filter((proxy) => !Array.isArray(proxy.all));
  const alive = leaves.filter((proxy) => proxy.alive).length;
  return { leaves, alive };
}

function selectedConfigSection() {
  return state.daeConfigSections.find((section) => section.id === state.daeConfigSelected) || state.daeConfigSections[0] || null;
}

function currentOpenConfigSectionIds() {
  return Array.from(refs.configSectionTabs?.querySelectorAll("[data-section-panel][open]") || []).map(
    (panel) => panel.dataset.sectionPanel || "",
  );
}

function resolveOpenConfigSectionIds(openSectionIds) {
  if (Array.isArray(openSectionIds)) {
    return openSectionIds.filter((sectionId) => state.daeConfigSections.some((section) => section.id === sectionId));
  }

  const openIdsFromDom = currentOpenConfigSectionIds().filter((sectionId) =>
    state.daeConfigSections.some((section) => section.id === sectionId),
  );
  if (openIdsFromDom.length) {
    return openIdsFromDom;
  }
  if (refs.configSectionTabs?.querySelector("[data-section-panel]")) {
    return [];
  }
  return state.daeConfigSelected ? [state.daeConfigSelected] : [];
}

function supportsGuiSection(name) {
  return GUI_CONFIG_SECTIONS.has(name);
}

function normalizeConfigText(value) {
  return String(value || "").replace(/\r\n?/g, "\n");
}

function findTopLevelDelimiter(text, delimiter) {
  let quote = "";
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = "";
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === delimiter) {
      return index;
    }
  }
  return -1;
}

function findMatchingBrace(text, openIndex) {
  let depth = 0;
  let comment = false;
  let quote = "";
  let escaped = false;

  for (let index = openIndex; index < text.length; index += 1) {
    const char = text[index];

    if (comment) {
      if (char === "\n") {
        comment = false;
      }
      continue;
    }

    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = "";
      }
      continue;
    }

    if (char === "#") {
      comment = true;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "{") {
      depth += 1;
      continue;
    }
    if (char === "}") {
      if (depth > 0) {
        depth -= 1;
      }
      if (depth === 0) {
        return index;
      }
    }
  }

  return -1;
}

function findOuterBlockRange(content) {
  const text = normalizeConfigText(content);
  let comment = false;
  let quote = "";
  let escaped = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (comment) {
      if (char === "\n") {
        comment = false;
      }
      continue;
    }

    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = "";
      }
      continue;
    }

    if (char === "#") {
      comment = true;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "{") {
      const closeIndex = findMatchingBrace(text, index);
      if (closeIndex >= 0) {
        return { openIndex: index, closeIndex };
      }
      return null;
    }
  }

  return null;
}

function extractSectionBody(content) {
  const text = normalizeConfigText(content);
  const range = findOuterBlockRange(text);
  if (!range) {
    return text.trim();
  }
  return text.slice(range.openIndex + 1, range.closeIndex);
}

function splitTopLevelChunks(content) {
  const text = normalizeConfigText(content);
  const chunks = [];
  let depth = 0;
  let comment = false;
  let quote = "";
  let escaped = false;
  let chunkStart = 0;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (comment) {
      if (char === "\n") {
        comment = false;
        if (depth === 0) {
          const chunk = text.slice(chunkStart, index + 1);
          if (chunk.trim()) {
            chunks.push(chunk.trim());
          }
          chunkStart = index + 1;
        }
      }
      continue;
    }

    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = "";
      }
      continue;
    }

    if (char === "#") {
      comment = true;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "{") {
      depth += 1;
      continue;
    }
    if (char === "}") {
      if (depth > 0) {
        depth -= 1;
      }
      continue;
    }
    if (char === "\n" && depth === 0) {
      const chunk = text.slice(chunkStart, index + 1);
      if (chunk.trim()) {
        chunks.push(chunk.trim());
      }
      chunkStart = index + 1;
    }
  }

  const tail = text.slice(chunkStart);
  if (tail.trim()) {
    chunks.push(tail.trim());
  }

  return chunks;
}

function dedentBlockBody(content) {
  const lines = normalizeConfigText(content).split("\n");
  while (lines.length && !lines[0].trim()) {
    lines.shift();
  }
  while (lines.length && !lines[lines.length - 1].trim()) {
    lines.pop();
  }
  const indents = lines
    .filter((line) => line.trim())
    .map((line) => line.match(/^\s*/)?.[0].length || 0);
  const minIndent = indents.length ? Math.min(...indents) : 0;
  return lines.map((line) => line.slice(minIndent)).join("\n");
}

function parseNamedBlockChunk(chunk) {
  const text = normalizeConfigText(chunk).trim();
  if (!text || text.startsWith("#")) {
    return null;
  }
  const range = findOuterBlockRange(text);
  if (!range || range.openIndex <= 0) {
    return null;
  }
  const name = text.slice(0, range.openIndex).trim();
  const tail = text.slice(range.closeIndex + 1).trim();
  if (!/^[A-Za-z_][\w-]*$/.test(name) || tail) {
    return null;
  }
  return {
    name,
    body: dedentBlockBody(text.slice(range.openIndex + 1, range.closeIndex)),
  };
}

function parseSimpleConfigLine(line) {
  const text = normalizeConfigText(line).trim();
  if (!text || text.startsWith("#")) {
    return null;
  }
  if (findTopLevelDelimiter(text, "#") >= 0) {
    return null;
  }
  const delimiterIndex = findTopLevelDelimiter(text, ":");
  if (delimiterIndex <= 0 || delimiterIndex >= text.length - 1) {
    return null;
  }
  return {
    key: text.slice(0, delimiterIndex).trim(),
    value: text.slice(delimiterIndex + 1).trim(),
  };
}

function unquoteConfigValue(value) {
  const text = String(value || "").trim();
  if (text.length >= 2 && text[0] === text[text.length - 1] && (text[0] === "'" || text[0] === '"')) {
    const quote = text[0];
    return text
      .slice(1, -1)
      .replaceAll(`\\${quote}`, quote)
      .replaceAll("\\\\", "\\");
  }
  return text;
}

function parseListLine(line) {
  const text = normalizeConfigText(line).trim();
  if (!text || text.startsWith("#")) {
    return null;
  }
  if (findTopLevelDelimiter(text, "#") >= 0) {
    return null;
  }
  if (text.startsWith("'") || text.startsWith('"') || /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(text)) {
    return {
      tag: "",
      value: unquoteConfigValue(text),
    };
  }
  const delimiterIndex = findTopLevelDelimiter(text, ":");
  if (delimiterIndex <= 0 || delimiterIndex >= text.length - 1) {
    return null;
  }
  return {
    tag: unquoteConfigValue(text.slice(0, delimiterIndex).trim()),
    value: unquoteConfigValue(text.slice(delimiterIndex + 1).trim()),
  };
}

function quoteConfigString(value) {
  return `'${String(value || "")
    .replaceAll("\\", "\\\\")
    .replaceAll("'", "\\'")}'`;
}

function formatConfigIdentifier(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  if (/^[A-Za-z_][\w-]*$/.test(text)) {
    return text;
  }
  return quoteConfigString(text);
}

function serializeNamedBlock(name, body) {
  const blockName = String(name || "").trim();
  if (!blockName) {
    return "";
  }
  const text = normalizeConfigText(body).trim();
  if (!text) {
    return `${blockName} {}`;
  }
  const indented = text
    .split("\n")
    .map((line) => (line ? `    ${line}` : ""))
    .join("\n");
  return `${blockName} {\n${indented}\n}`;
}

function wrapConfigSection(name, body) {
  const sectionName = String(name || "").trim();
  if (!sectionName) {
    return normalizeConfigText(body);
  }
  const text = normalizeConfigText(body).trim();
  if (!text) {
    return `${sectionName} {\n}\n`;
  }
  const indented = text
    .split("\n")
    .map((line) => (line ? `    ${line}` : ""))
    .join("\n");
  return `${sectionName} {\n${indented}\n}\n`;
}

function joinAdvancedChunks(chunks) {
  return chunks
    .map((chunk) => normalizeConfigText(chunk).trim())
    .filter(Boolean)
    .join("\n\n");
}

function joinConfigBodyParts(parts) {
  return parts
    .map((part) => normalizeConfigText(part).trim())
    .filter(Boolean)
    .join("\n\n");
}

function createEmptyGlobalFields() {
  return GLOBAL_FIELD_DEFS.reduce((fields, field) => {
    fields[field.key] = "";
    return fields;
  }, {});
}

function createEmptyConfigEditor(name) {
  switch (name) {
    case "global":
      return {
        kind: "global",
        fields: createEmptyGlobalFields(),
        extraOptions: [],
        advancedRaw: "",
      };
    case "subscription":
    case "node":
    case "include":
      return {
        kind: name,
        entries: [],
        advancedRaw: "",
      };
    case "dns":
      return {
        kind: "dns",
        options: [],
        blocks: [],
        advancedRaw: "",
      };
    case "group":
      return {
        kind: "group",
        groups: [],
        advancedRaw: "",
      };
    case "routing":
      return {
        kind: "routing",
        rules: [],
        fallback: "",
        advancedRaw: "",
      };
    default:
      return {
        kind: "raw",
      };
  }
}

function normalizeConfigFieldValue(field, value) {
  const text = String(value || "").trim();
  if (field.type === "boolean") {
    const lowered = text.toLowerCase();
    return lowered === "true" || lowered === "false" ? lowered : "";
  }
  return unquoteConfigValue(text);
}

function serializeConfigFieldValue(field, value) {
  const text = String(value || "").trim();
  if (field.type === "boolean") {
    return text === "true" || text === "false" ? text : "";
  }
  return text;
}

function parseGlobalEditor(content) {
  const editor = createEmptyConfigEditor("global");
  const advanced = [];

  for (const chunk of splitTopLevelChunks(extractSectionBody(content))) {
    const option = parseSimpleConfigLine(chunk);
    if (!option) {
      advanced.push(chunk);
      continue;
    }
    const field = GLOBAL_FIELD_DEFS.find((item) => item.key === option.key);
    if (field) {
      editor.fields[option.key] = normalizeConfigFieldValue(field, option.value);
    } else {
      editor.extraOptions.push({
        key: option.key,
        value: option.value,
      });
    }
  }

  editor.advancedRaw = joinAdvancedChunks(advanced);
  return editor;
}

function parseListEditor(name, content) {
  const editor = createEmptyConfigEditor(name);
  const advanced = [];

  for (const chunk of splitTopLevelChunks(extractSectionBody(content))) {
    const entry = parseListLine(chunk);
    if (!entry) {
      advanced.push(chunk);
      continue;
    }
    if (name === "include" && entry.tag) {
      advanced.push(chunk);
      continue;
    }
    editor.entries.push(entry);
  }

  editor.advancedRaw = joinAdvancedChunks(advanced);
  return editor;
}

function parseDnsEditor(content) {
  const editor = createEmptyConfigEditor("dns");
  const advanced = [];

  for (const chunk of splitTopLevelChunks(extractSectionBody(content))) {
    const block = parseNamedBlockChunk(chunk);
    if (block) {
      editor.blocks.push(block);
      continue;
    }
    const option = parseSimpleConfigLine(chunk);
    if (option) {
      editor.options.push(option);
      continue;
    }
    advanced.push(chunk);
  }

  editor.advancedRaw = joinAdvancedChunks(advanced);
  return editor;
}

function parseGroupEditor(content) {
  const editor = createEmptyConfigEditor("group");
  const advanced = [];

  for (const chunk of splitTopLevelChunks(extractSectionBody(content))) {
    const block = parseNamedBlockChunk(chunk);
    if (block) {
      editor.groups.push(block);
      continue;
    }
    advanced.push(chunk);
  }

  editor.advancedRaw = joinAdvancedChunks(advanced);
  return editor;
}

function parseRoutingEditor(content) {
  const editor = createEmptyConfigEditor("routing");
  const advanced = [];

  for (const chunk of splitTopLevelChunks(extractSectionBody(content))) {
    const line = normalizeConfigText(chunk).trim();
    if (!line) {
      continue;
    }
    if (line.startsWith("#") || findTopLevelDelimiter(line, "#") >= 0 || parseNamedBlockChunk(line)) {
      advanced.push(chunk);
      continue;
    }
    const fallbackMatch = line.match(/^fallback\s*:\s*(.+)$/);
    if (fallbackMatch) {
      editor.fallback = fallbackMatch[1].trim();
      continue;
    }
    editor.rules.push({ value: line });
  }

  editor.advancedRaw = joinAdvancedChunks(advanced);
  return editor;
}

function parseConfigEditor(name, content) {
  switch (name) {
    case "global":
      return parseGlobalEditor(content);
    case "subscription":
    case "node":
    case "include":
      return parseListEditor(name, content);
    case "dns":
      return parseDnsEditor(content);
    case "group":
      return parseGroupEditor(content);
    case "routing":
      return parseRoutingEditor(content);
    default:
      return createEmptyConfigEditor("raw");
  }
}

function serializeGlobalEditor(editor) {
  const lines = [];

  for (const field of GLOBAL_FIELD_DEFS) {
    const value = serializeConfigFieldValue(field, editor.fields[field.key]);
    if (value) {
      lines.push(`${field.key}: ${value}`);
    }
  }

  for (const row of editor.extraOptions) {
    const key = String(row.key || "").trim();
    const value = String(row.value || "").trim();
    if (key && value) {
      lines.push(`${key}: ${value}`);
    }
  }

  return wrapConfigSection("global", joinConfigBodyParts([lines.join("\n"), editor.advancedRaw]));
}

function serializeListEditor(name, editor) {
  const lines = editor.entries
    .map((entry) => {
      const value = String(entry.value || "").trim();
      if (!value) {
        return "";
      }
      if (name !== "include") {
        const tag = formatConfigIdentifier(entry.tag);
        if (tag) {
          return `${tag}: ${quoteConfigString(value)}`;
        }
      }
      return quoteConfigString(value);
    })
    .filter(Boolean)
    .join("\n");

  return wrapConfigSection(name, joinConfigBodyParts([lines, editor.advancedRaw]));
}

function serializeDnsEditor(editor) {
  const options = editor.options
    .map((row) => {
      const key = String(row.key || "").trim();
      const value = String(row.value || "").trim();
      return key && value ? `${key}: ${value}` : "";
    })
    .filter(Boolean)
    .join("\n");

  const blocks = editor.blocks
    .map((block) => serializeNamedBlock(block.name, block.body))
    .filter(Boolean)
    .join("\n\n");

  return wrapConfigSection("dns", joinConfigBodyParts([options, blocks, editor.advancedRaw]));
}

function serializeGroupEditor(editor) {
  const blocks = editor.groups
    .map((group) => serializeNamedBlock(group.name, group.body))
    .filter(Boolean)
    .join("\n\n");

  return wrapConfigSection("group", joinConfigBodyParts([blocks, editor.advancedRaw]));
}

function serializeRoutingEditor(editor) {
  const lines = editor.rules
    .map((rule) => String(rule.value || "").trim())
    .filter(Boolean);
  if (String(editor.fallback || "").trim()) {
    lines.push(`fallback: ${String(editor.fallback).trim()}`);
  }

  return wrapConfigSection("routing", joinConfigBodyParts([lines.join("\n"), editor.advancedRaw]));
}

function serializeConfigSectionContent(name, editorData, fallback = "") {
  switch (editorData?.kind) {
    case "global":
      return serializeGlobalEditor(editorData);
    case "subscription":
    case "node":
    case "include":
      return serializeListEditor(name, editorData);
    case "dns":
      return serializeDnsEditor(editorData);
    case "group":
      return serializeGroupEditor(editorData);
    case "routing":
      return serializeRoutingEditor(editorData);
    default:
      return normalizeConfigText(fallback);
  }
}

function inferConfigSectionName(chunk, index, forcedName = "") {
  if (forcedName) {
    return forcedName;
  }
  const lines = String(chunk || "").split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const match = trimmed.match(/^([A-Za-z_][\w-]*)\s*\{/);
    if (match) {
      return match[1];
    }
    break;
  }
  return index === 0 ? "document" : `section-${index + 1}`;
}

function buildConfigSection(chunk, index, forcedName = "") {
  const content = normalizeConfigText(chunk);
  const name = inferConfigSectionName(content, index, forcedName);
  const editorData = parseConfigEditor(name, content);
  return {
    id: `${name}-${index}`,
    name,
    title: name === "document" ? "Whole Document" : titleCase(name),
    summary: CONFIG_SECTION_DESCRIPTIONS[name] || "编辑该顶层 dae 配置块的原始文本。",
    content,
    mode: supportsGuiSection(name) ? "gui" : "raw",
    editorData,
  };
}

function createConfigSection(name) {
  const editorData = createEmptyConfigEditor(name);
  const content = serializeConfigSectionContent(name, editorData, "");
  return {
    id: `${name}-${Date.now()}`,
    name,
    title: titleCase(name),
    summary: CONFIG_SECTION_DESCRIPTIONS[name] || "编辑该顶层 dae 配置块的原始文本。",
    content,
    mode: supportsGuiSection(name) ? "gui" : "raw",
    editorData,
  };
}

function parseConfigSections(content) {
  const text = normalizeConfigText(content);
  if (!text.trim()) {
    return createFallbackSections("");
  }

  const chunks = [];
  let depth = 0;
  let comment = false;
  let quote = "";
  let escaped = false;
  let chunkStart = 0;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];

    if (comment) {
      if (char === "\n") {
        comment = false;
      }
      continue;
    }

    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (char === "\\") {
        escaped = true;
        continue;
      }
      if (char === quote) {
        quote = "";
      }
      continue;
    }

    if (char === "#") {
      comment = true;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === "{") {
      depth += 1;
      continue;
    }
    if (char === "}") {
      if (depth > 0) {
        depth -= 1;
      }
      if (depth === 0) {
        const chunk = text.slice(chunkStart, index + 1);
        if (chunk.trim()) {
          chunks.push(chunk);
        }
        chunkStart = index + 1;
      }
    }
  }

  const tail = text.slice(chunkStart);
  if (tail.trim()) {
    chunks.push(tail);
  }

  if (!chunks.length) {
    return createFallbackSections(text);
  }

  return chunks.map((chunk, index) => buildConfigSection(chunk, index));
}

function joinConfigSections() {
  return state.daeConfigSections.map((section) => section.content).join("");
}

function updateConfigDirtyState() {
  state.daeConfigContent = joinConfigSections();
  state.daeConfigDirty = state.daeConfigContent !== state.daeConfigOriginal;
  renderConfigMeta();
}

function setApiStatus(kind, message) {
  state.apiStatus = { kind, message };
  renderHeaderStatus();
  renderSystemStatus();
  renderControllerPanel();
}

function setBusyState(busy) {
  state.connecting = busy;
  renderControllerPanel();
}

function renderLayoutState() {
  const connected = state.apiStatus.kind === "connected";
  document.body.classList.toggle("auth-required", !connected);
  document.body.classList.toggle("sidebar-collapsed", state.sidebarCollapsed);
  document.body.classList.toggle("controller-collapsed", connected && !state.controllerExpanded);
  refs.controllerTopToggle.setAttribute("aria-expanded", String(!connected || state.controllerExpanded));
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

function renderVersionTitle() {
  refs.versionLabel.textContent = state.version?.version || "unlinked";
}

function renderHeaderStatus() {
  refs.apiStatusText.textContent = state.apiStatus.message;
  refs.sidebarControllerText.textContent = state.apiStatus.message.toLowerCase();
  refs.sidebarConnectionsValue.textContent = String(state.connections.total);
  refs.topConnectionsValue.textContent = String(state.connections.total);
  refs.apiStatusDot.classList.remove("offline", "warn");
  if (state.apiStatus.kind === "offline") {
    refs.apiStatusDot.classList.add("offline");
  } else if (state.apiStatus.kind === "warn") {
    refs.apiStatusDot.classList.add("warn");
  }
}

function renderSystemStatus() {
  const { leaves, alive } = computeLeafStats();
  const inUse = Number(state.memory?.inuse || 0);
  const rss = Number(state.memory?.rss || 0);

  refs.dashboardModeValue.textContent = state.config?.mode || "-";
  refs.dashboardLogLevelValue.textContent = state.config?.["log-level"] || "-";
  refs.dashboardMemoryValue.textContent = inUse ? humanBytes(inUse) : "-";
  refs.dashboardRssValue.textContent = rss ? humanBytes(rss) : "-";
  refs.dashboardAliveValue.textContent = `${alive} / ${leaves.length}`;
  refs.runtimeVersionValue.textContent = state.version?.version || "-";

  if (!state.logLevelChanging) {
    refs.runtimeLogLevelSelect.value = state.config?.["log-level"] || "info";
  }

  const group = currentGroup();
  refs.currentGroupName.textContent = group?.name || "No group";
  refs.currentGroupMeta.textContent = group
    ? `${group.type} · current: ${group.now || "none"} · ${group.all.length} node(s) · 右上角按钮测延迟`
    : "连接控制器后加载代理组与节点。";
  refs.dashboardCurrentGroupName.textContent = group?.name || "No group";
  refs.dashboardCurrentGroupMeta.textContent = group
    ? `${group.type} · current: ${group.now || "none"} · ${group.all.length} node(s)`
    : "连接控制器后加载代理组与节点。";
  refs.resetGroupButton.disabled = !group || state.busyGroups.has(group.name);
}

function renderTrafficMeta() {
  refs.uploadRate.textContent = formatByteRate(state.traffic.up);
  refs.downloadRate.textContent = formatByteRate(state.traffic.down);
  refs.uploadTotalValue.textContent = humanBytes(state.traffic.upTotal);
  refs.downloadTotalValue.textContent = humanBytes(state.traffic.downTotal);
  refs.trafficUploadTotalValue.textContent = humanBytes(state.traffic.upTotal);
  refs.trafficDownloadTotalValue.textContent = humanBytes(state.traffic.downTotal);
  refs.dashboardUpValue.textContent = formatByteRate(state.traffic.up);
  refs.dashboardDownValue.textContent = formatByteRate(state.traffic.down);
}

function renderConnectionPreviewList(target, connections, emptyMessage = "暂无活动连接。") {
  if (!connections.length) {
    target.innerHTML = `<div class="proxy-empty">${escapeHtml(emptyMessage)}</div>`;
    return;
  }

  target.innerHTML = connections
    .map(
      (conn) => `
        <article class="connection-pill">
          <div class="connection-pill-top">
            <strong>${escapeHtml(conn.process || "-")}</strong>
            <div class="connection-state-badges">
              <span class="network-chip">${escapeHtml(conn.network || "-")}</span>
              <span class="state-chip ${classToken(conn.state, "active")}">${escapeHtml(conn.state || "-")}</span>
            </div>
          </div>
          <code>${escapeHtml(conn.source || "-")} → ${escapeHtml(conn.destination || "-")}</code>
          <div class="connection-pill-bottom">
            <span class="table-secondary">${escapeHtml(conn.outbound || "-")} · ${escapeHtml(conn.direction || "-")}</span>
            <span class="table-secondary">${escapeHtml(formatTimeAgo(conn.lastSeen))}</span>
          </div>
        </article>
      `,
    )
    .join("");
}

function renderTrafficConnectionsTable(connections) {
  const ordered = sortTrafficConnections(connections);
  refs.trafficConnectionsList.innerHTML = ordered
    .map((conn) => {
      const stateClass = classToken(conn.state, "active");
      const processLabel = conn.process || "-";
      const pidLabel = Number(conn.pid) > 0 ? `PID ${conn.pid}` : "PID -";
      const sourceLabel = formatConnectionLabel(conn.source, conn.sourceAddress, conn.sourcePort);
      const destinationLabel = formatConnectionLabel(conn.destination, conn.destinationAddress, conn.destinationPort);
      const sourceEndpoint = formatEndpoint(conn.sourceAddress, conn.sourcePort);
      const destinationEndpoint = formatEndpoint(conn.destinationAddress, conn.destinationPort);
      const outboundLabel = conn.outbound || "-";
      const directionLabel = conn.direction || "-";
      const routingLabel = conn.hasRouting ? "Routing attached" : "Routing missing";
      const policyLabel = conn.must ? "Must route" : "Normal route";
      const macLabel = conn.mac || "-";
      const lastSeenAgo = formatTimeAgo(conn.lastSeen);
      const lastSeenClock = formatClock(conn.lastSeen);
      const downloadRateLabel = formatByteRate(conn.downloadSpeed || 0);
      const uploadRateLabel = formatByteRate(conn.uploadSpeed || 0);
      const downloadTotalLabel = humanBytes(conn.downloadTotal || 0);
      const uploadTotalLabel = humanBytes(conn.uploadTotal || 0);

      if (isCompactMobileViewport()) {
        return `
          <article class="connection-compact-card">
            <div class="connection-compact-head">
              <div class="table-stack">
                <strong>${escapeHtml(processLabel)}</strong>
                <span class="table-secondary">${escapeHtml(pidLabel)} · ${escapeHtml(lastSeenAgo)}</span>
              </div>

              <div class="connection-state-badges">
                <span class="network-chip">${escapeHtml(conn.network || "-")}</span>
                <span class="state-chip ${stateClass}">${escapeHtml(conn.state || "-")}</span>
              </div>
            </div>

            <div class="connection-speed-pills connection-compact-speeds">
              <span class="speed-pill download">↓ ${escapeHtml(downloadRateLabel)}</span>
              <span class="speed-pill upload">↑ ${escapeHtml(uploadRateLabel)}</span>
            </div>

            <div class="connection-compact-route">
              <div class="connection-compact-endpoint">
                <span class="connection-state-label">From</span>
                <strong>${escapeHtml(sourceLabel)}</strong>
                <code class="table-route">${escapeHtml(sourceEndpoint)}</code>
              </div>

              <div class="connection-compact-endpoint">
                <span class="connection-state-label">To</span>
                <strong>${escapeHtml(destinationLabel)}</strong>
                <code class="table-route">${escapeHtml(destinationEndpoint)}</code>
              </div>
            </div>

            <div class="connection-state-meta connection-compact-meta">
              <span class="meta-chip strong">Outbound ${escapeHtml(outboundLabel)}</span>
              <span class="meta-chip">${escapeHtml(directionLabel)}</span>
              <span class="meta-chip">↓ ${escapeHtml(downloadTotalLabel)} · ↑ ${escapeHtml(uploadTotalLabel)}</span>
            </div>
          </article>
        `;
      }

      return `
        <article class="connection-state-card">
          <div class="connection-state-head">
            <div class="table-stack">
              <strong>${escapeHtml(processLabel)}</strong>
              <span class="table-secondary">${escapeHtml(pidLabel)} · ${escapeHtml(lastSeenAgo)}</span>
            </div>

            <div class="connection-state-side">
              <div class="connection-state-badges">
                <span class="network-chip">${escapeHtml(conn.network || "-")}</span>
                <span class="state-chip ${stateClass}">${escapeHtml(conn.state || "-")}</span>
                <span class="direction-chip">${escapeHtml(conn.direction || "-")}</span>
              </div>

              <div class="connection-speed-pills">
                <span class="speed-pill download">↓ ${escapeHtml(downloadRateLabel)}</span>
                <span class="speed-pill upload">↑ ${escapeHtml(uploadRateLabel)}</span>
              </div>
            </div>
          </div>

          <div class="connection-state-grid">
            <div class="connection-state-block is-download">
              <span class="connection-state-label">Download</span>
              <strong>${escapeHtml(downloadRateLabel)}</strong>
              <span class="table-secondary">Total ${escapeHtml(downloadTotalLabel)}</span>
            </div>

            <div class="connection-state-block is-upload">
              <span class="connection-state-label">Upload</span>
              <strong>${escapeHtml(uploadRateLabel)}</strong>
              <span class="table-secondary">Total ${escapeHtml(uploadTotalLabel)}</span>
            </div>

            <div class="connection-state-block is-source">
              <span class="connection-state-label">Source</span>
              <strong>${escapeHtml(sourceLabel)}</strong>
              <code class="table-route">${escapeHtml(sourceEndpoint)}</code>
            </div>

            <div class="connection-state-block is-destination">
              <span class="connection-state-label">Destination</span>
              <strong>${escapeHtml(destinationLabel)}</strong>
              <code class="table-route">${escapeHtml(destinationEndpoint)}</code>
            </div>

            <div class="connection-state-block is-routing">
              <span class="connection-state-label">Routing</span>
              <strong>${escapeHtml(outboundLabel)}</strong>
              <span class="table-secondary">${escapeHtml(directionLabel)} · ${escapeHtml(routingLabel)}</span>
            </div>

            <div class="connection-state-block is-policy">
              <span class="connection-state-label">Policy</span>
              <strong>${escapeHtml(policyLabel)}</strong>
              <span class="table-secondary">Mark ${escapeHtml(conn.mark || 0)} · DSCP ${escapeHtml(conn.dscp || 0)}</span>
            </div>
          </div>

          <div class="connection-state-meta">
            <span class="meta-chip strong meta-outbound">Outbound ${escapeHtml(outboundLabel)}</span>
            <span class="meta-chip meta-pid">${escapeHtml(pidLabel)}</span>
            <span class="meta-chip meta-seen">Seen ${escapeHtml(lastSeenClock)}</span>
            <span class="meta-chip meta-total-down">Down ${escapeHtml(downloadTotalLabel)}</span>
            <span class="meta-chip meta-total-up">Up ${escapeHtml(uploadTotalLabel)}</span>
            <span class="meta-chip meta-routing">${escapeHtml(routingLabel)}</span>
            <span class="meta-chip meta-policy">${escapeHtml(policyLabel)}</span>
            <span class="meta-chip meta-mac">MAC ${escapeHtml(macLabel)}</span>
            <span class="meta-chip meta-id">ID ${escapeHtml(conn.id || "-")}</span>
          </div>
        </article>
      `;
    })
    .join("");
  refs.trafficConnectionsEmpty.textContent = "暂无活动连接。";
  refs.trafficConnectionsEmpty.hidden = connections.length > 0;
}

function renderConnections() {
  refs.dashboardConnectionsTotal.textContent = String(state.connections.total);
  refs.dashboardConnectionsTcp.textContent = String(state.connections.tcp);
  refs.dashboardConnectionsUdp.textContent = String(state.connections.udp);
  refs.dashboardConnectionsUpdated.textContent = !state.connectionsAvailable
    ? "当前 controller 未提供 /connections。"
    : state.connections.updatedAt
      ? `最近更新 ${formatClock(state.connections.updatedAt)}`
      : "等待 /connections 数据。";

  refs.trafficConnectionsTotal.textContent = String(state.connections.total);
  refs.trafficConnectionsTcp.textContent = String(state.connections.tcp);
  refs.trafficConnectionsUdp.textContent = String(state.connections.udp);
  refs.trafficConnectionsUpdated.textContent = !state.connectionsAvailable
    ? "当前 controller 未提供 /connections。"
    : state.connections.updatedAt
      ? `最近更新 ${formatClock(state.connections.updatedAt)}`
      : "等待 /connections 数据。";
  refs.trafficSortSelect.value = state.connectionSort;
  refs.trafficSortSelect.disabled = !state.connectionsAvailable;

  if (!state.connectionsAvailable) {
    renderConnectionPreviewList(refs.dashboardConnectionList, [], "当前 controller 未提供 /connections。");
    refs.trafficConnectionsList.innerHTML = "";
    refs.trafficConnectionsEmpty.textContent = "当前 controller 未提供 /connections。";
    refs.trafficConnectionsEmpty.hidden = false;
    return;
  }

  renderConnectionPreviewList(refs.dashboardConnectionList, state.connections.connections.slice(0, 4));
  renderTrafficConnectionsTable(state.connections.connections.slice(0, 50));
}

function renderControllerPanel() {
  const connected = state.apiStatus.kind === "connected";
  const embedded = isEmbeddedUIPath();
  const authOnlyMode = embedded && !connected;
  const summaryUrl = state.controllerUrl || (embedded ? window.location.origin : "") || "未连接";
  refs.controllerSummaryUrl.textContent = summaryUrl;
  refs.controllerSummaryMeta.textContent = connected
    ? `已连接，${state.token ? "使用 Bearer token" : "未配置 token"}。`
    : authOnlyMode
      ? "当前页面已经运行在 dae 控制器上，只需要输入 token。"
      : "输入地址与 token，连接 dae 控制器。";
  refs.controllerPanelTitle.textContent = connected ? "Controller 已连接" : authOnlyMode ? "登录 dae 控制台" : "连接 dae External Controller";
  refs.controllerHint.textContent =
    authOnlyMode && state.controllerHintText === DEFAULT_CONTROLLER_HINT
      ? "正在访问当前控制器。输入 token 后直接建立连接。"
      : state.controllerHintText;
  refs.runtimeLogLevelNote.textContent = state.runtimeLogLevelNoteText;
  refs.connectButton.disabled = state.connecting;
  refs.connectButton.textContent = state.connecting ? "登录中..." : connected ? "重新连接" : "登录";
  refs.controllerUrlField.hidden = authOnlyMode;
  refs.controllerUrl.readOnly = authOnlyMode;
  refs.controllerUrl.placeholder = embedded ? window.location.origin : "http://127.0.0.1:9090";
  refs.applyLogLevelButton.disabled = !state.controllerUrl || state.logLevelChanging || state.connecting;
  refs.controllerTopToggle.textContent = connected ? "Controller" : "登录";
  refs.controllerTopToggle.hidden = !connected;

  renderLayoutState();
}

function chartBounds() {
  const maxSeriesValue = Math.max(256, ...state.trafficSeries.up, ...state.trafficSeries.down);
  return {
    max: Math.ceil(maxSeriesValue * 1.15),
  };
}

function mapToY(value, height, bounds) {
  if (bounds.max <= 0) {
    return height;
  }
  return height - (value / bounds.max) * height;
}

function createSmoothPath(points, width, height, bounds) {
  const step = width / Math.max(1, points.length - 1);
  return points.map((value, index) => ({
    x: index * step,
    y: mapToY(value, height, bounds),
  }));
}

function drawGrid(ctx, width, height) {
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

function drawSeries(ctx, points, width, height, bounds, options) {
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

function renderScaleLabels(target, bounds) {
  const labels = [
    formatByteRate(bounds.max),
    formatByteRate(bounds.max * 0.75),
    formatByteRate(bounds.max * 0.5),
    formatByteRate(bounds.max * 0.25),
    "0 B/s",
  ];
  target.innerHTML = labels.map((label) => `<span>${label}</span>`).join("");
}

function renderTimeLabels(target, { withSeconds = false } = {}) {
  const lastIndex = state.trafficSeries.times.length - 1;
  const indexes = [0, Math.round(lastIndex * 0.25), Math.round(lastIndex * 0.5), Math.round(lastIndex * 0.75), lastIndex];
  target.innerHTML = indexes
    .map((index) => {
      const timestamp = state.trafficSeries.times[index] || Date.now();
      const label = new Date(timestamp).toLocaleTimeString("zh-CN", {
        hour: "2-digit",
        minute: "2-digit",
        second: withSeconds ? "2-digit" : undefined,
        hour12: false,
      });
      return `<span>${label}</span>`;
    })
    .join("");
}

function renderChartWidget(canvas, scaleTarget, timeTarget, options = {}) {
  if (!canvas || !scaleTarget || !timeTarget) {
    return;
  }

  const ctx = canvas.getContext("2d");
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
  drawGrid(ctx, width, height);
  drawSeries(ctx, state.trafficSeries.up, width, height, scale, {
    stroke: "#1d9b8c",
    fill: "rgba(29, 155, 140, 0.24)",
  });
  drawSeries(ctx, state.trafficSeries.down, width, height, scale, {
    stroke: "#cc7d37",
    fill: "rgba(204, 125, 55, 0.2)",
  });

  renderScaleLabels(scaleTarget, scale);
  renderTimeLabels(timeTarget, options);
}

function renderCharts() {
  renderChartWidget(refs.dashboardTrafficChart, refs.dashboardChartScale, refs.dashboardChartTime, { withSeconds: true });
  renderChartWidget(refs.trafficChart, refs.chartScale, refs.chartTime, { withSeconds: true });
}

let chartRenderFrame = 0;

function scheduleChartRender() {
  if (chartRenderFrame) {
    window.cancelAnimationFrame(chartRenderFrame);
  }
  chartRenderFrame = window.requestAnimationFrame(() => {
    chartRenderFrame = 0;
    renderCharts();
    window.requestAnimationFrame(() => {
      renderCharts();
    });
  });
}

function proxyTabsMarkup() {
  return state.groups.length
    ? state.groups
        .map(
          (group) => `
            <button
              class="proxy-tab ${group.name === state.selectedGroup ? "active" : ""}"
              data-group="${escapeHtml(group.name)}"
              type="button"
            >
              <strong>${escapeHtml(group.name)}</strong>
              <span>${escapeHtml(group.type || "selector")}</span>
            </button>
          `,
        )
        .join("")
    : `<div class="proxy-empty">No proxy groups returned by /proxies.</div>`;
}

function proxyGridMarkup(group, { limit = 0, compact = false } = {}) {
  if (!group) {
    return `<div class="proxy-empty">连接可用 controller 后加载组和节点数据。</div>`;
  }

  const proxyNames = limit > 0 ? group.all.slice(0, limit) : group.all;
  return proxyNames
    .map((proxyName) => {
      const proxy = state.proxies[proxyName] || { name: proxyName, alive: false };
      const delay = proxyDelay(proxy);
      const active = group.now === proxyName;
      const address = proxy.addr || proxy.address || "address unavailable";
      const protocol = proxy.protocol || proxy.type || "unknown";
      const delayText = delay === null ? "pending" : `${delay} ms`;
      const busyDelay = state.busyDelayNodes.has(proxyName);
      const busyGroup = state.busyGroups.has(group.name);

      return `
        <article class="proxy-card ${compact ? "compact" : ""} ${active ? "current" : ""} ${busyDelay ? "busy" : ""}">
          <div class="proxy-top">
            <h3 class="proxy-title">${escapeHtml(proxyName)}</h3>
            <button
              class="refresh"
              type="button"
              aria-label="refresh delay"
              data-action="probe-delay"
              data-name="${escapeHtml(proxyName)}"
              ${busyDelay ? "disabled" : ""}
            ></button>
          </div>

          <div class="proxy-meta">${escapeHtml(address)}</div>
          <p class="proxy-delay">${escapeHtml(delayText)}</p>

          <div class="proxy-badges">
            <span class="proxy-badge">${escapeHtml(protocol)}</span>
            <span class="proxy-badge ${proxy.alive ? "" : "dim"}">${proxy.alive ? "alive" : "down"}</span>
            ${proxy.subscriptionTag ? `<span class="proxy-badge dim">${escapeHtml(proxy.subscriptionTag)}</span>` : ""}
          </div>

          <div class="proxy-actions">
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

function renderProxyTabs() {
  const tabsMarkup = proxyTabsMarkup();
  refs.proxyTabs.innerHTML = tabsMarkup;
  refs.dashboardProxyTabs.innerHTML = tabsMarkup;
}

function renderProxyGrid() {
  const group = currentGroup();
  refs.proxyGrid.innerHTML = proxyGridMarkup(group);
  refs.dashboardProxyGrid.innerHTML = proxyGridMarkup(group, { compact: true });
}

function configSectionCountText(section) {
  const editor = section.editorData;
  switch (editor?.kind) {
    case "global": {
      const fields = GLOBAL_FIELD_DEFS.filter((field) => serializeConfigFieldValue(field, editor.fields[field.key])).length;
      const extras = editor.extraOptions.filter((row) => String(row.key || "").trim() && String(row.value || "").trim()).length;
      return `${fields + extras} options`;
    }
    case "subscription":
    case "node":
    case "include":
      return `${editor.entries.length} item${editor.entries.length === 1 ? "" : "s"}`;
    case "dns":
      return `${editor.options.length} options · ${editor.blocks.length} blocks`;
    case "group":
      return `${editor.groups.length} groups`;
    case "routing": {
      const total = editor.rules.filter((rule) => String(rule.value || "").trim()).length + (editor.fallback ? 1 : 0);
      return `${total} rules`;
    }
    default:
      return section.content.trim() ? "Raw section" : "Empty";
  }
}

function renderConfigModeSwitch(section) {
  if (!supportsGuiSection(section.name)) {
    return "";
  }
  return `
    <div class="config-mode-switch">
      <button
        class="config-mode-button ${section.mode === "gui" ? "active" : ""}"
        data-section="${escapeHtml(section.id)}"
        data-section-mode="gui"
        type="button"
      >
        Builder
      </button>
      <button
        class="config-mode-button ${section.mode === "raw" ? "active" : ""}"
        data-section="${escapeHtml(section.id)}"
        data-section-mode="raw"
        type="button"
      >
        Raw
      </button>
    </div>
  `;
}

function renderConfigAdvancedNote(section) {
  if (!section.editorData?.advancedRaw?.trim()) {
    return "";
  }
  return `<p class="config-advanced-note">检测到未结构化内容，保存时会保留；切到 Raw 可以直接编辑这些内容。</p>`;
}

function renderConfigSectionToolbar(section) {
  return `
    <div class="config-section-toolbar">
      ${renderConfigModeSwitch(section)}
      <button class="config-section-remove" data-remove-section="${escapeHtml(section.id)}" type="button">Delete Section</button>
    </div>
  `;
}

function renderConfigFieldControl(sectionId, field, value) {
  if (field.type === "select") {
    return `
      <select data-section="${escapeHtml(sectionId)}" data-config-field="${escapeHtml(field.key)}">
        <option value="">Not set</option>
        ${field.options
          .map(
            (option) => `
              <option value="${escapeHtml(option)}" ${value === option ? "selected" : ""}>${escapeHtml(option)}</option>
            `,
          )
          .join("")}
      </select>
    `;
  }

  if (field.type === "boolean") {
    return `
      <select data-section="${escapeHtml(sectionId)}" data-config-field="${escapeHtml(field.key)}">
        <option value="" ${!value ? "selected" : ""}>Not set</option>
        <option value="true" ${value === "true" ? "selected" : ""}>true</option>
        <option value="false" ${value === "false" ? "selected" : ""}>false</option>
      </select>
    `;
  }

  return `
    <input
      data-section="${escapeHtml(sectionId)}"
      data-config-field="${escapeHtml(field.key)}"
      type="${field.type === "number" ? "number" : "text"}"
      inputmode="${field.type === "number" ? "numeric" : "text"}"
      placeholder="${escapeHtml(field.placeholder || "")}"
      value="${escapeHtml(value || "")}"
    />
  `;
}

function renderConfigGlobalBuilder(section) {
  const editor = section.editorData;
  const rows = editor.extraOptions
    .map(
      (row, index) => `
        <div class="config-row">
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="extraOptions"
            data-index="${index}"
            data-field="key"
            type="text"
            placeholder="option_key"
            value="${escapeHtml(row.key || "")}"
          />
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="extraOptions"
            data-index="${index}"
            data-field="value"
            type="text"
            placeholder="option value"
            value="${escapeHtml(row.value || "")}"
          />
          <div class="config-row-actions">
            <button
              class="config-row-remove"
              data-section="${escapeHtml(section.id)}"
              data-config-remove="extraOptions"
              data-index="${index}"
              type="button"
            >
              Remove
            </button>
          </div>
        </div>
      `,
    )
    .join("");

  return `
    ${renderConfigSectionToolbar(section)}
    <div class="config-form-grid">
      ${GLOBAL_FIELD_DEFS.map(
        (field) => `
          <div class="config-field">
            <label>${escapeHtml(field.label)}</label>
            ${renderConfigFieldControl(section.id, field, editor.fields[field.key])}
          </div>
        `,
      ).join("")}
    </div>

    <div class="config-builder-panel">
      <div class="config-panel-head">
        <div>
          <h4>Additional Options</h4>
          <p>不在上面表单里的 global 键值，直接以 <code>key: value</code> 追加。</p>
        </div>
        <button
          class="action-button ghost"
          data-section="${escapeHtml(section.id)}"
          data-config-add="extraOptions"
          data-template="key-value"
          type="button"
        >
          Add Option
        </button>
      </div>
      <div class="config-row-list">
        ${rows || '<div class="config-empty-state">暂无额外选项。</div>'}
      </div>
    </div>
    ${renderConfigAdvancedNote(section)}
  `;
}

function renderConfigListBuilder(section) {
  const isInclude = section.name === "include";
  const valuePlaceholder = isInclude
    ? "rules/base.dae"
    : section.name === "subscription"
      ? "https://example.com/subscription"
      : "ss://, vmess://, vless:// ...";

  const rows = section.editorData.entries
    .map(
      (entry, index) => `
        <div class="config-row ${isInclude ? "single-value" : ""}">
          ${
            isInclude
              ? ""
              : `
                <input
                  data-section="${escapeHtml(section.id)}"
                  data-config-collection="entries"
                  data-index="${index}"
                  data-field="tag"
                  type="text"
                  placeholder="tag"
                  value="${escapeHtml(entry.tag || "")}"
                />
              `
          }
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="entries"
            data-index="${index}"
            data-field="value"
            type="text"
            placeholder="${escapeHtml(valuePlaceholder)}"
            value="${escapeHtml(entry.value || "")}"
          />
          <div class="config-row-actions">
            <button
              class="config-row-remove"
              data-section="${escapeHtml(section.id)}"
              data-config-remove="entries"
              data-index="${index}"
              type="button"
            >
              Remove
            </button>
          </div>
        </div>
      `,
    )
    .join("");

  return `
    ${renderConfigSectionToolbar(section)}
    <div class="config-builder-panel">
      <div class="config-panel-head">
        <div>
          <h4>${escapeHtml(section.title)} Entries</h4>
          <p>${escapeHtml(section.summary)}</p>
        </div>
        <button
          class="action-button ghost"
          data-section="${escapeHtml(section.id)}"
          data-config-add="entries"
          data-template="tagged-entry"
          type="button"
        >
          ${isInclude ? "Add Include" : `Add ${escapeHtml(section.title)}`}
        </button>
      </div>
      <div class="config-row-list">
        ${rows || '<div class="config-empty-state">暂无条目。</div>'}
      </div>
    </div>
    ${renderConfigAdvancedNote(section)}
  `;
}

function renderConfigDnsBuilder(section) {
  const optionRows = section.editorData.options
    .map(
      (row, index) => `
        <div class="config-row">
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="options"
            data-index="${index}"
            data-field="key"
            type="text"
            placeholder="option_key"
            value="${escapeHtml(row.key || "")}"
          />
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="options"
            data-index="${index}"
            data-field="value"
            type="text"
            placeholder="option value"
            value="${escapeHtml(row.value || "")}"
          />
          <div class="config-row-actions">
            <button
              class="config-row-remove"
              data-section="${escapeHtml(section.id)}"
              data-config-remove="options"
              data-index="${index}"
              type="button"
            >
              Remove
            </button>
          </div>
        </div>
      `,
    )
    .join("");

  const blockRows = section.editorData.blocks
    .map(
      (block, index) => `
        <div class="config-block-card">
          <div class="config-block-head">
            <div>
              <h4>Nested Block</h4>
              <p>像 <code>upstream</code>、<code>routing</code> 这样的 dns 子块。</p>
            </div>
            <button
              class="config-row-remove"
              data-section="${escapeHtml(section.id)}"
              data-config-remove="blocks"
              data-index="${index}"
              type="button"
            >
              Remove
            </button>
          </div>
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="blocks"
            data-index="${index}"
            data-field="name"
            type="text"
            placeholder="upstream"
            value="${escapeHtml(block.name || "")}"
          />
          <textarea
            class="config-textarea"
            data-section="${escapeHtml(section.id)}"
            data-config-collection="blocks"
            data-index="${index}"
            data-field="body"
            spellcheck="false"
          >${escapeHtml(block.body || "")}</textarea>
        </div>
      `,
    )
    .join("");

  return `
    ${renderConfigSectionToolbar(section)}
    <div class="config-builder-panel">
      <div class="config-panel-head">
        <div>
          <h4>Top-level Options</h4>
          <p>DNS 顶层的简单键值项。</p>
        </div>
        <button
          class="action-button ghost"
          data-section="${escapeHtml(section.id)}"
          data-config-add="options"
          data-template="key-value"
          type="button"
        >
          Add Option
        </button>
      </div>
      <div class="config-row-list">
        ${optionRows || '<div class="config-empty-state">暂无顶层项。</div>'}
      </div>
    </div>

    <div class="config-builder-panel">
      <div class="config-panel-head">
        <div>
          <h4>Nested Blocks</h4>
          <p>GUI 里直接新增 <code>upstream</code>、<code>routing</code> 等块。</p>
        </div>
        <button
          class="action-button ghost"
          data-section="${escapeHtml(section.id)}"
          data-config-add="blocks"
          data-template="named-block"
          type="button"
        >
          Add Block
        </button>
      </div>
      <div class="config-block-list">
        ${blockRows || '<div class="config-empty-state">暂无嵌套块。</div>'}
      </div>
    </div>
    ${renderConfigAdvancedNote(section)}
  `;
}

function renderConfigGroupBuilder(section) {
  const groups = section.editorData.groups
    .map(
      (group, index) => `
        <div class="config-block-card">
          <div class="config-block-head">
            <div>
              <h4>Proxy Group</h4>
              <p>在这里添加分组名，并填 policy、filter 等规则。</p>
            </div>
            <button
              class="config-row-remove"
              data-section="${escapeHtml(section.id)}"
              data-config-remove="groups"
              data-index="${index}"
              type="button"
            >
              Remove
            </button>
          </div>
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="groups"
            data-index="${index}"
            data-field="name"
            type="text"
            placeholder="my_group"
            value="${escapeHtml(group.name || "")}"
          />
          <textarea
            class="config-textarea"
            data-section="${escapeHtml(section.id)}"
            data-config-collection="groups"
            data-index="${index}"
            data-field="body"
            spellcheck="false"
          >${escapeHtml(group.body || "")}</textarea>
        </div>
      `,
    )
    .join("");

  return `
    ${renderConfigSectionToolbar(section)}
    <div class="config-builder-panel">
      <div class="config-panel-head">
        <div>
          <h4>Groups</h4>
          <p>每个 group 单独一个卡片，方便新增和整理策略块。</p>
        </div>
        <button
          class="action-button ghost"
          data-section="${escapeHtml(section.id)}"
          data-config-add="groups"
          data-template="named-block"
          type="button"
        >
          Add Group
        </button>
      </div>
      <div class="config-block-list">
        ${groups || '<div class="config-empty-state">暂无 group。</div>'}
      </div>
    </div>
    ${renderConfigAdvancedNote(section)}
  `;
}

function renderConfigRoutingBuilder(section) {
  const rules = section.editorData.rules
    .map(
      (rule, index) => `
        <div class="config-row single-value">
          <input
            data-section="${escapeHtml(section.id)}"
            data-config-collection="rules"
            data-index="${index}"
            data-field="value"
            type="text"
            placeholder="domain(geosite:cn) -> direct"
            value="${escapeHtml(rule.value || "")}"
          />
          <div class="config-row-actions">
            <button
              class="config-row-remove"
              data-section="${escapeHtml(section.id)}"
              data-config-remove="rules"
              data-index="${index}"
              type="button"
            >
              Remove
            </button>
          </div>
        </div>
      `,
    )
    .join("");

  return `
    ${renderConfigSectionToolbar(section)}
    <div class="config-builder-panel">
      <div class="config-panel-head">
        <div>
          <h4>Routing Rules</h4>
          <p>按顺序添加规则，右侧删除，最后单独维护 fallback。</p>
        </div>
        <button
          class="action-button ghost"
          data-section="${escapeHtml(section.id)}"
          data-config-add="rules"
          data-template="rule"
          type="button"
        >
          Add Rule
        </button>
      </div>
      <div class="config-row-list">
        ${rules || '<div class="config-empty-state">暂无路由规则。</div>'}
      </div>
    </div>

    <div class="config-form-grid">
      <div class="config-field">
        <label>Fallback</label>
        <input
          data-section="${escapeHtml(section.id)}"
          data-config-field="fallback"
          type="text"
          placeholder="my_group"
          value="${escapeHtml(section.editorData.fallback || "")}"
        />
      </div>
    </div>
    ${renderConfigAdvancedNote(section)}
  `;
}

function renderConfigRawEditor(section) {
  return `
    ${renderConfigSectionToolbar(section)}
    <div class="config-raw-shell">
      <textarea
        class="config-textarea config-raw-code"
        data-section="${escapeHtml(section.id)}"
        data-config-raw="content"
        spellcheck="false"
      >${escapeHtml(section.content || "")}</textarea>
    </div>
  `;
}

function renderConfigSectionBody(section) {
  if (section.mode === "raw") {
    return renderConfigRawEditor(section);
  }

  switch (section.editorData?.kind) {
    case "global":
      return renderConfigGlobalBuilder(section);
    case "subscription":
    case "node":
    case "include":
      return renderConfigListBuilder(section);
    case "dns":
      return renderConfigDnsBuilder(section);
    case "group":
      return renderConfigGroupBuilder(section);
    case "routing":
      return renderConfigRoutingBuilder(section);
    default:
      return renderConfigRawEditor(section);
  }
}

function renderConfigSectionTabs(openSectionIds) {
  if (!state.daeConfigSections.length) {
    refs.configSectionTabs.innerHTML = '<div class="config-empty-state">暂无可编辑 section。</div>';
    return;
  }

  const openSet = new Set(resolveOpenConfigSectionIds(openSectionIds));
  refs.configSectionTabs.innerHTML = state.daeConfigSections
    .map((section) => {
      const open = openSet.has(section.id);
      return `
        <details class="config-section-card ${open ? "open" : ""}" data-section-panel="${escapeHtml(section.id)}" ${open ? "open" : ""}>
          <summary
            class="config-section-toggle"
            data-section-toggle="${escapeHtml(section.id)}"
          >
            <div class="config-section-copy">
              <p class="panel-kicker">${escapeHtml(section.name)}</p>
              <h3>${escapeHtml(section.title)}</h3>
              <p>${escapeHtml(section.summary)}</p>
            </div>
            <div class="config-section-side">
              <span class="config-section-count">${escapeHtml(configSectionCountText(section))}</span>
              <span class="config-mode-chip ${section.mode === "raw" ? "raw" : ""}">${section.mode === "raw" ? "Raw" : "GUI"}</span>
              <span class="config-section-arrow" aria-hidden="true"></span>
            </div>
          </summary>
          <div class="config-section-body">${renderConfigSectionBody(section)}</div>
        </details>
      `;
    })
    .join("");
}

function renderConfigMeta() {
  const section = selectedConfigSection();
  refs.configPathValue.textContent = state.daeConfigPath || "-";
  refs.saveConfigButton.disabled = !state.controllerUrl || !state.daeConfigDirty;
  refs.refreshConfigButton.disabled = !state.controllerUrl;
  refs.configSectionTypeSelect.disabled = !state.controllerUrl;
  refs.addConfigSectionButton.disabled = !state.controllerUrl;
  refs.configSectionsCountValue.textContent = String(state.daeConfigSections.length);
  refs.configCurrentSectionValue.textContent = section?.title || "-";
  refs.editorNote.textContent = state.editorNoteText;
}

function renderDaeConfigEditor(openSectionIds) {
  renderConfigSectionTabs(openSectionIds);
  renderConfigMeta();
}

function renderLogs() {
  refs.logsLevelSelect.value = state.logsLevel;
  refs.toggleLogsButton.textContent = state.logsPaused ? "Resume" : "Pause";
  refs.toggleLogsButton.disabled = !state.controllerUrl;
  refs.clearLogsButton.disabled = state.logs.length === 0;
  refs.logsLevelSelect.disabled = !state.controllerUrl;

  let statusText = `Waiting for live events from /logs?format=structured&level=${state.logsLevel}.`;
  const currentState = wsState("logs");
  if (!state.controllerUrl) {
    statusText = "连接 controller 后开启日志流。";
  } else if (state.logsPaused) {
    statusText = "本地已暂停日志流，恢复后继续接收新事件。";
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
  renderLayoutState();
  renderViewState();
  renderVersionTitle();
  renderHeaderStatus();
  renderSystemStatus();
  renderTrafficMeta();
  renderConnections();
  renderControllerPanel();
  renderProxyTabs();
  renderProxyGrid();
  renderDaeConfigEditor();
  renderLogs();
  renderCharts();
}

async function fetchFullSnapshot() {
  const [version, config, proxiesPayload, daeConfig, traffic, memory, connections] = await Promise.all([
    apiFetch("/version"),
    apiFetch("/configs"),
    apiFetch("/proxies"),
    apiFetch("/configs/dae"),
    apiFetch("/traffic"),
    apiFetch("/memory"),
    fetchConnectionsSnapshot(),
  ]);

  return {
    version,
    config,
    proxiesPayload,
    daeConfig,
    traffic,
    memory,
    connections: connections.snapshot,
    connectionsAvailable: connections.available,
  };
}

async function fetchConnectionsSnapshot() {
  try {
    return {
      available: true,
      snapshot: await apiFetch(`/connections?limit=${CONNECTION_LIMIT}`),
    };
  } catch (error) {
    if (error.status === 404 || error.status === 405) {
      return {
        available: false,
        snapshot: createEmptyConnectionsSnapshot(),
      };
    }
    throw error;
  }
}

function applyFullSnapshot(snapshot) {
  applyVersionSnapshot(snapshot.version);
  applyConfigSnapshot(snapshot.config);
  applyProxySnapshot(snapshot.proxiesPayload?.proxies);
  applyDaeConfigDocument(snapshot.daeConfig);
  applyTrafficSnapshot(snapshot.traffic, true);
  updateMemory(snapshot.memory);
  applyConnectionsSnapshot(snapshot.connections, snapshot.connectionsAvailable);
}

async function refreshSnapshot(updateStatus = true) {
  if (!state.controllerUrl || state.refreshing) {
    return;
  }
  state.refreshing = true;
  try {
    const snapshot = await fetchFullSnapshot();
    applyFullSnapshot(snapshot);
    if (updateStatus) {
      setApiStatus("connected", "Connected");
      state.controllerHintText =
        "已连接，实时数据正在同步。";
      state.controllerExpanded = false;
      openLiveChannels();
      renderAll();
    }
  } catch (error) {
    handleConnectionError(error);
  } finally {
    state.refreshing = false;
  }
}

function handleConnectionError(error) {
  closeAllSockets();
  resetLiveState();
  state.controllerExpanded = true;

  if (error.status === 401) {
    setApiStatus("warn", "Unauthorized");
    state.controllerHintText = "登录失败，请确认 token 正确。";
  } else {
    setApiStatus("offline", "Unavailable");
    state.controllerHintText = "无法连接 controller，请确认 dae 正在运行。";
  }

  renderAll();
}

async function connectController() {
  try {
    state.controllerUrl = normalizeControllerUrl(refs.controllerUrl.value);
    state.token = refs.controllerToken.value.trim();
  } catch (error) {
    setApiStatus("warn", error.message);
    state.controllerHintText = error.message;
    renderControllerPanel();
    return;
  }

  syncControllerInputs();
  persistConnection();
  closeAllSockets();
  resetLiveState();
  setBusyState(true);
  setApiStatus("warn", "Connecting");
  state.controllerHintText = "正在连接 controller 并建立实时通道。";
  renderAll();
  await refreshSnapshot(true);
  setBusyState(false);
}

async function loadDaeConfigDocument() {
  if (!state.controllerUrl) {
    return;
  }
  const doc = await apiFetch("/configs/dae");
  state.daeConfigDirty = false;
  applyDaeConfigDocument(doc);
}

async function resyncControllerAfterConfigSave() {
  let lastError = null;
  for (let attempt = 0; attempt < RELOAD_SYNC_ATTEMPTS; attempt += 1) {
    await sleep(RELOAD_SYNC_DELAY_MS);
    try {
      const snapshot = await fetchFullSnapshot();
      state.daeConfigDirty = false;
      applyFullSnapshot(snapshot);
      setApiStatus("connected", "Connected");
      state.controllerHintText = "已连接，实时数据正在同步。";
      openLiveChannels();
      state.editorNoteText = `Saved ${state.daeConfigPath || "config.dae"} and reloaded dae.`;
      renderAll();
      return;
    } catch (error) {
      lastError = error;
    }
  }

  if (lastError) {
    handleConnectionError(lastError);
    state.editorNoteText = `Config was written, but dae did not come back cleanly: ${lastError.message}`;
    renderDaeConfigEditor();
  }
}

async function saveDaeConfig() {
  if (!state.controllerUrl) {
    return;
  }

  refs.saveConfigButton.disabled = true;
  refs.refreshConfigButton.disabled = true;
  try {
    await apiFetch("/configs/dae", {
      method: "PUT",
      body: JSON.stringify({ content: state.daeConfigContent }),
    });
    state.editorNoteText = `Saved ${state.daeConfigPath || "config.dae"}. Waiting for dae to reload...`;
    renderDaeConfigEditor();
    await resyncControllerAfterConfigSave();
  } catch (error) {
    state.editorNoteText = `Failed to save config.dae: ${error.message}`;
    renderDaeConfigEditor();
  }
}

async function updateRuntimeLogLevel() {
  if (!state.controllerUrl) {
    return;
  }

  const level = refs.runtimeLogLevelSelect.value;
  if (!LOG_LEVELS.includes(level)) {
    state.runtimeLogLevelNoteText = `Unsupported log level: ${level}`;
    renderControllerPanel();
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
    state.runtimeLogLevelNoteText = `Runtime log level updated to ${level}.`;
  } catch (error) {
    state.runtimeLogLevelNoteText = `Failed to update runtime log level: ${error.message}`;
  } finally {
    state.logLevelChanging = false;
    renderControllerPanel();
  }
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
    state.editorNoteText = `Latency probe for ${name} returned ${payload.delay} ms from /proxies/${name}/delay.`;
  } catch (error) {
    state.editorNoteText = `Latency probe failed for ${name}: ${error.message}`;
  } finally {
    state.busyDelayNodes.delete(name);
    renderProxyGrid();
    renderDaeConfigEditor();
  }
}

async function selectProxy(name) {
  const group = currentGroup();
  if (!group || !state.controllerUrl) {
    return;
  }

  state.busyGroups.add(group.name);
  renderSystemStatus();
  renderProxyGrid();

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
    state.editorNoteText = `Switched group ${group.name} to ${name} through /proxies/${group.name}.`;
  } catch (error) {
    state.editorNoteText = `Failed to switch ${group.name} to ${name}: ${error.message}`;
  } finally {
    state.busyGroups.delete(group.name);
    renderSystemStatus();
    renderProxyGrid();
    renderDaeConfigEditor();
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
    state.editorNoteText = `Reset group ${group.name} to its default policy via DELETE /proxies/${group.name}.`;
  } catch (error) {
    state.editorNoteText = `Failed to reset ${group.name}: ${error.message}`;
  } finally {
    state.busyGroups.delete(group.name);
    renderSystemStatus();
    renderProxyGrid();
    renderDaeConfigEditor();
  }
}

function toggleSidebar() {
  state.sidebarCollapsed = !state.sidebarCollapsed;
  persistUiPrefs();
  renderLayoutState();
}

function toggleControllerPanel() {
  if (state.apiStatus.kind !== "connected") {
    state.controllerExpanded = true;
    renderControllerPanel();
    (refs.controllerUrlField.hidden ? refs.controllerToken : refs.controllerUrl).focus();
    return;
  }
  state.controllerExpanded = !state.controllerExpanded;
  renderControllerPanel();
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
    closeSocket("logs");
  }
  if (window.innerWidth <= 860) {
    state.sidebarCollapsed = true;
    persistUiPrefs();
    renderLayoutState();
  }
  renderLogs();
  scheduleChartRender();
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

function findConfigSectionById(sectionId) {
  return state.daeConfigSections.find((section) => section.id === sectionId) || null;
}

function syncConfigSectionContent(section) {
  section.content = serializeConfigSectionContent(section.name, section.editorData, section.content);
}

function createConfigTemplateItem(template) {
  switch (template) {
    case "key-value":
      return { key: "", value: "" };
    case "named-block":
      return { name: "", body: "" };
    case "rule":
      return { value: "" };
    case "tagged-entry":
    default:
      return { tag: "", value: "" };
  }
}

function removeConfigSection(sectionId) {
  const index = state.daeConfigSections.findIndex((section) => section.id === sectionId);
  if (index < 0) {
    return;
  }

  const openSectionIds = currentOpenConfigSectionIds().filter((id) => id !== sectionId);
  const [removed] = state.daeConfigSections.splice(index, 1);
  if (!state.daeConfigSections.length) {
    state.daeConfigSections = createFallbackSections("");
    openSectionIds.push(state.daeConfigSections[0].id);
  }

  if (state.daeConfigSelected === sectionId || !findConfigSectionById(state.daeConfigSelected)) {
    state.daeConfigSelected = state.daeConfigSections[Math.min(index, state.daeConfigSections.length - 1)]?.id || "";
  }

  state.editorNoteText = `Removed ${removed.title} section. Save to apply.`;
  updateConfigDirtyState();
  renderDaeConfigEditor(openSectionIds);
}

function handleConfigSectionInput(event) {
  const target = event.target;
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement)) {
    return;
  }

  const section = findConfigSectionById(target.dataset.section || "");
  if (!section) {
    return;
  }

  if (target.dataset.configRaw === "content") {
    section.content = normalizeConfigText(target.value);
    section.editorData = parseConfigEditor(section.name, section.content);
    updateConfigDirtyState();
    return;
  }

  const fieldName = target.dataset.configField;
  if (fieldName) {
    if (section.editorData?.kind === "global" && Object.hasOwn(section.editorData.fields, fieldName)) {
      section.editorData.fields[fieldName] = target.value;
      syncConfigSectionContent(section);
      updateConfigDirtyState();
      return;
    }

    if (section.editorData?.kind === "routing" && fieldName === "fallback") {
      section.editorData.fallback = target.value;
      syncConfigSectionContent(section);
      updateConfigDirtyState();
    }
    return;
  }

  const collectionName = target.dataset.configCollection;
  const field = target.dataset.field;
  const index = Number(target.dataset.index);
  if (!collectionName || !field || Number.isNaN(index)) {
    return;
  }

  const collection = section.editorData?.[collectionName];
  if (!Array.isArray(collection) || !collection[index]) {
    return;
  }

  collection[index][field] = target.value;
  syncConfigSectionContent(section);
  updateConfigDirtyState();
}

function handleConfigSectionClick(event) {
  const toggleButton = event.target.closest("[data-section-toggle]");
  if (toggleButton) {
    const sectionId = toggleButton.dataset.sectionToggle || "";
    if (!sectionId) {
      return;
    }
    state.daeConfigSelected = sectionId;
    window.requestAnimationFrame(() => {
      renderConfigMeta();
    });
    return;
  }

  const modeButton = event.target.closest("[data-section-mode]");
  if (modeButton) {
    const section = findConfigSectionById(modeButton.dataset.section || "");
    if (!section || !supportsGuiSection(section.name)) {
      return;
    }
    section.mode = modeButton.dataset.sectionMode === "raw" ? "raw" : "gui";
    state.daeConfigSelected = section.id;
    renderDaeConfigEditor([...currentOpenConfigSectionIds(), section.id]);
    return;
  }

  const removeSectionButton = event.target.closest("[data-remove-section]");
  if (removeSectionButton) {
    removeConfigSection(removeSectionButton.dataset.removeSection || "");
    return;
  }

  const addButton = event.target.closest("[data-config-add]");
  if (addButton) {
    const section = findConfigSectionById(addButton.dataset.section || "");
    if (!section) {
      return;
    }
    const collection = section.editorData?.[addButton.dataset.configAdd || ""];
    if (!Array.isArray(collection)) {
      return;
    }
    collection.push(createConfigTemplateItem(addButton.dataset.template || ""));
    syncConfigSectionContent(section);
    state.daeConfigSelected = section.id;
    updateConfigDirtyState();
    renderDaeConfigEditor([...currentOpenConfigSectionIds(), section.id]);
    return;
  }

  const removeButton = event.target.closest("[data-config-remove]");
  if (removeButton) {
    const section = findConfigSectionById(removeButton.dataset.section || "");
    if (!section) {
      return;
    }
    const collection = section.editorData?.[removeButton.dataset.configRemove || ""];
    const index = Number(removeButton.dataset.index);
    if (!Array.isArray(collection) || Number.isNaN(index) || !collection[index]) {
      return;
    }
    collection.splice(index, 1);
    syncConfigSectionContent(section);
    state.daeConfigSelected = section.id;
    updateConfigDirtyState();
    renderDaeConfigEditor([...currentOpenConfigSectionIds(), section.id]);
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

  refs.sidebarToggles.forEach((button) => {
    button.addEventListener("click", toggleSidebar);
  });

  refs.controllerTopToggle.addEventListener("click", toggleControllerPanel);

  refs.refreshConfigButton.addEventListener("click", () => {
    loadDaeConfigDocument()
      .then(() => {
        state.editorNoteText = state.daeConfigPath ? `Reloaded ${state.daeConfigPath} from disk.` : "Reloaded config.dae from disk.";
        renderDaeConfigEditor();
      })
      .catch((error) => {
        state.editorNoteText = `Failed to reload config.dae: ${error.message}`;
        renderDaeConfigEditor();
      });
  });

  refs.saveConfigButton.addEventListener("click", () => {
    saveDaeConfig();
  });

  refs.addConfigSectionButton.addEventListener("click", () => {
    const name = refs.configSectionTypeSelect.value;
    if (!CONFIG_SECTION_TYPES.includes(name)) {
      return;
    }
    const existing = state.daeConfigSections.find((section) => section.name === name);
    if (existing) {
      state.daeConfigSelected = existing.id;
      state.editorNoteText = `${existing.title} section already exists.`;
      renderDaeConfigEditor([...currentOpenConfigSectionIds(), existing.id]);
      return;
    }
    const section = createConfigSection(name);
    state.daeConfigSections.push(section);
    state.daeConfigSelected = section.id;
    state.editorNoteText = `Added ${section.title} section.`;
    updateConfigDirtyState();
    renderDaeConfigEditor([...currentOpenConfigSectionIds(), section.id]);
  });

  refs.applyLogLevelButton.addEventListener("click", () => {
    updateRuntimeLogLevel();
  });

  refs.resetGroupButton.addEventListener("click", () => {
    resetGroup();
  });

  refs.reloadProxiesButton.addEventListener("click", () => {
    closeSocket("proxies");
    connectProxySocket();
  });

  const handleProxyTabClick = (event) => {
    const button = event.target.closest("[data-group]");
    if (!button) {
      return;
    }
    state.selectedGroup = button.dataset.group;
    renderSystemStatus();
    renderProxyTabs();
    renderProxyGrid();
  };

  refs.proxyTabs.addEventListener("click", handleProxyTabClick);
  refs.dashboardProxyTabs.addEventListener("click", handleProxyTabClick);

  refs.proxyGrid.addEventListener("click", handleProxyGridClick);
  refs.dashboardProxyGrid.addEventListener("click", handleProxyGridClick);

  refs.configSectionTabs.addEventListener("click", handleConfigSectionClick);
  refs.configSectionTabs.addEventListener("input", handleConfigSectionInput);
  refs.configSectionTabs.addEventListener("change", handleConfigSectionInput);

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
      closeSocket("logs");
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

  refs.trafficSortSelect.addEventListener("change", () => {
    state.connectionSort = refs.trafficSortSelect.value;
    persistUiPrefs();
    renderConnections();
  });

  window.addEventListener("hashchange", applyLocationCredentialsAndReconnect);
  window.addEventListener("resize", () => {
    scheduleChartRender();
    renderConnections();
  });
}

function boot() {
  loadPersistedConnection();
  loadUiPrefs();
  bindEvents();
  refs.logsLevelSelect.value = state.logsLevel;
  refs.trafficSortSelect.value = state.connectionSort;
  refs.runtimeLogLevelSelect.value = "info";
  renderAll();
  if (state.controllerUrl) {
    connectController();
  }
}

boot();
