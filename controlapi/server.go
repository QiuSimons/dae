package controlapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

var (
	errUnauthorized = &HTTPError{Message: "Unauthorized"}
	errBadRequest   = &HTTPError{Message: "Body invalid"}
	errNotFound     = &HTTPError{Message: "Resource not found"}
)

const snapshotStreamInterval = 5 * time.Second

type HTTPError struct {
	Message string `json:"message"`
}

func (e *HTTPError) Error() string {
	return e.Message
}

type ServerConfig struct {
	Addr   string
	Secret string
}

type Server struct {
	cfg      ServerConfig
	provider Provider
	logs     *LogBroker
	ui       *webUI

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
}

type Traffic struct {
	Up        int64 `json:"up"`
	Down      int64 `json:"down"`
	UpTotal   int64 `json:"upTotal"`
	DownTotal int64 `json:"downTotal"`
}

type ConnectionsSnapshot struct {
	UpdatedAt   time.Time    `json:"updatedAt"`
	Total       int          `json:"total"`
	TCP         int          `json:"tcp"`
	UDP         int          `json:"udp"`
	Connections []Connection `json:"connections"`
}

type Connection struct {
	ID                 string    `json:"id"`
	Network            string    `json:"network"`
	State              string    `json:"state"`
	Source             string    `json:"source"`
	SourceAddress      string    `json:"sourceAddress"`
	SourcePort         uint16    `json:"sourcePort"`
	Destination        string    `json:"destination"`
	DestinationAddress string    `json:"destinationAddress"`
	DestinationPort    uint16    `json:"destinationPort"`
	Process            string    `json:"process"`
	PID                uint32    `json:"pid"`
	Outbound           string    `json:"outbound"`
	Direction          string    `json:"direction"`
	Mark               uint32    `json:"mark"`
	DSCP               uint8     `json:"dscp"`
	Must               bool      `json:"must"`
	HasRouting         bool      `json:"hasRouting"`
	Mac                string    `json:"mac"`
	LastSeen           time.Time `json:"lastSeen"`
	UploadSpeed        int64     `json:"uploadSpeed"`
	DownloadSpeed      int64     `json:"downloadSpeed"`
	UploadTotal        int64     `json:"uploadTotal"`
	DownloadTotal      int64     `json:"downloadTotal"`
}

type Memory struct {
	Inuse   uint64 `json:"inuse"`
	RSS     uint64 `json:"rss"`
	OSLimit uint64 `json:"oslimit"`
}

type Config struct {
	Port        int    `json:"port"`
	SocksPort   int    `json:"socks-port"`
	RedirPort   int    `json:"redir-port"`
	TProxyPort  int    `json:"tproxy-port"`
	MixedPort   int    `json:"mixed-port"`
	AllowLan    bool   `json:"allow-lan"`
	BindAddress string `json:"bind-address"`
	Mode        string `json:"mode"`
	LogLevel    string `json:"log-level"`
	IPv6        bool   `json:"ipv6"`
}

type DaeConfigDocument struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type DelayHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type Proxy struct {
	Name            string         `json:"name"`
	Type            string         `json:"type"`
	Alive           bool           `json:"alive"`
	History         []DelayHistory `json:"history"`
	Now             string         `json:"now,omitempty"`
	All             []string       `json:"all,omitempty"`
	UDP             bool           `json:"udp"`
	XUDP            bool           `json:"xudp"`
	Address         string         `json:"addr,omitempty"`
	Protocol        string         `json:"protocol,omitempty"`
	SubscriptionTag string         `json:"subscriptionTag,omitempty"`
}

type Provider interface {
	Hello() string
	Version() string
	Meta() bool
	Config() Config
	DaeConfigDocument() (DaeConfigDocument, error)
	Memory() Memory
	Traffic() Traffic
	Connections(limit int) ConnectionsSnapshot
	Proxies() map[string]Proxy
	Proxy(name string) (Proxy, bool)
	UpdateProxy(groupName, proxyName string) error
	ResetProxy(groupName string) error
	Delay(name, probeURL string, timeout time.Duration) (int, error)
	SetLogLevel(level string) error
	UpdateDaeConfig(content string) error
}

type structuredLogField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type structuredLog struct {
	Time    string               `json:"time"`
	Level   string               `json:"level"`
	Message string               `json:"message"`
	Fields  []structuredLogField `json:"fields"`
}

func NewServer(cfg ServerConfig, provider Provider, logs *LogBroker) *Server {
	s := &Server{
		cfg:      cfg,
		provider: provider,
		logs:     logs,
	}
	if cfg.Secret != "" {
		s.ui = discoverWebUI()
	}
	s.server = &http.Server{
		Addr:    cfg.Addr,
		Handler: s.handler(),
	}
	return s
}

func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	go func() {
		_ = s.server.Serve(listener)
	}()
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var err error
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err = s.server.Shutdown(ctx)
	}
	s.listener = nil
	return err
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	if s.ui != nil {
		mux.HandleFunc("/ui", s.handleWebUI)
		mux.HandleFunc("/ui/", s.handleWebUI)
	}
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/configs", s.handleConfigs)
	mux.HandleFunc("/configs/dae", s.handleDaeConfig)
	mux.HandleFunc("/proxies", s.handleProxies)
	mux.HandleFunc("/proxies/", s.handleProxyByName)
	mux.HandleFunc("/traffic", s.handleTraffic)
	mux.HandleFunc("/connections", s.handleConnections)
	mux.HandleFunc("/memory", s.handleMemory)
	mux.HandleFunc("/logs", s.handleLogs)
	return s.withMiddleware(mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if s.ui != nil && isWebUIPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.Secret != "" && !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, errUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	if wantsWebsocket(r) {
		if token := r.URL.Query().Get("token"); token != "" {
			return safeEqual(token, s.cfg.Secret)
		}
	}

	header := r.Header.Get("Authorization")
	bearer, token, ok := strings.Cut(header, " ")
	return ok && bearer == "Bearer" && safeEqual(token, s.cfg.Secret)
}

func safeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (s *Server) WebUIEnabled() bool {
	return s.ui != nil
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"hello": s.provider.Hello()})
}

func (s *Server) handleWebUI(w http.ResponseWriter, r *http.Request) {
	if s.ui == nil {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	s.ui.serveHTTP(w, r)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	payload := func() any {
		return map[string]any{
			"meta":    s.provider.Meta(),
			"version": s.provider.Version(),
		}
	}
	if wantsWebsocket(r) {
		streamJSONSnapshots(w, r, payload)
		return
	}
	writeJSON(w, http.StatusOK, payload())
}

func (s *Server) handleConfigs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if wantsWebsocket(r) {
			streamJSONSnapshots(w, r, func() any { return s.provider.Config() })
			return
		}
		writeJSON(w, http.StatusOK, s.provider.Config())
	case http.MethodPatch:
		req := struct {
			LogLevel *string `json:"log-level"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		if req.LogLevel != nil {
			if err := s.provider.SetLogLevel(*req.LogLevel); err != nil {
				writeError(w, http.StatusBadRequest, &HTTPError{Message: err.Error()})
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDaeConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if wantsWebsocket(r) {
			streamJSONSnapshotsWithError(w, r, func() (any, error) {
				return s.provider.DaeConfigDocument()
			})
			return
		}
		doc, err := s.provider.DaeConfigDocument()
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, &HTTPError{Message: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, doc)
	case http.MethodPut:
		req := struct {
			Content string `json:"content"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		if err := s.provider.UpdateDaeConfig(req.Content); err != nil {
			writeError(w, http.StatusBadRequest, &HTTPError{Message: err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if wantsWebsocket(r) {
		streamJSONSnapshots(w, r, func() any {
			return map[string]any{"proxies": orderedProxyMap(s.provider.Proxies())}
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"proxies": orderedProxyMap(s.provider.Proxies())})
}

func orderedProxyMap(proxies map[string]Proxy) map[string]Proxy {
	names := make([]string, 0, len(proxies))
	for name := range proxies {
		names = append(names, name)
	}
	sort.Strings(names)
	ordered := make(map[string]Proxy, len(proxies))
	for _, name := range names {
		ordered[name] = proxies[name]
	}
	return ordered
}

func (s *Server) handleProxyByName(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/proxies/")
	path = strings.Trim(path, "/")
	if path == "" {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	name, err := url.PathUnescape(path)
	if err != nil {
		writeError(w, http.StatusBadRequest, errBadRequest)
		return
	}

	if strings.HasSuffix(name, "/delay") {
		base := strings.TrimSuffix(name, "/delay")
		s.handleProxyDelay(w, r, base)
		return
	}

	switch r.Method {
	case http.MethodGet:
		proxy, ok := s.provider.Proxy(name)
		if !ok {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, proxy)
	case http.MethodPut:
		req := struct {
			Name string `json:"name"`
		}{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		if req.Name == "" {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		if err := s.provider.UpdateProxy(name, req.Name); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, providerErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, &HTTPError{Message: err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if err := s.provider.ResetProxy(name); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, providerErrNotFound) {
				status = http.StatusNotFound
			}
			writeError(w, status, &HTTPError{Message: err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProxyDelay(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	timeout := 5 * time.Second
	if timeoutText := r.URL.Query().Get("timeout"); timeoutText != "" {
		timeoutMs, err := strconv.Atoi(timeoutText)
		if err != nil || timeoutMs <= 0 {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		timeout = time.Duration(timeoutMs) * time.Millisecond
	}

	delay, err := s.provider.Delay(name, r.URL.Query().Get("url"), timeout)
	if err != nil {
		status := http.StatusServiceUnavailable
		if strings.Contains(strings.ToLower(err.Error()), "timeout") {
			status = http.StatusGatewayTimeout
		}
		writeError(w, status, &HTTPError{Message: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"delay": delay})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	streamTraffic(w, r, func() Traffic { return s.provider.Traffic() })
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		limit = n
	}

	snapshot := func() any {
		return s.provider.Connections(limit)
	}
	if wantsWebsocket(r) {
		streamJSONSnapshots(w, r, snapshot)
		return
	}
	writeJSON(w, http.StatusOK, snapshot())
}

func (s *Server) handleMemory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	streamMemory(w, r, func() Memory { return s.provider.Memory() })
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	level := logrus.InfoLevel
	if text := r.URL.Query().Get("level"); text != "" {
		parsed, err := logrus.ParseLevel(text)
		if err != nil {
			writeError(w, http.StatusBadRequest, errBadRequest)
			return
		}
		level = parsed
	}

	if s.logs == nil {
		writeError(w, http.StatusServiceUnavailable, &HTTPError{Message: "log stream unavailable"})
		return
	}

	events, unsubscribe := s.logs.Subscribe(level)
	defer unsubscribe()

	structured := r.URL.Query().Get("format") == "structured"
	if wantsWebsocket(r) {
		conn, err := websocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			select {
			case <-r.Context().Done():
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				var payload any = event
				if structured {
					payload = makeStructuredLog(event)
				}
				if err := conn.WriteJSON(payload); err != nil {
					return
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, &HTTPError{Message: "streaming unsupported"})
		return
	}
	encoder := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			var payload any = event
			if structured {
				payload = makeStructuredLog(event)
			}
			if err := encoder.Encode(payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

var websocketUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func wantsWebsocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func streamTraffic(w http.ResponseWriter, r *http.Request, snapshot func() Traffic) {
	if wantsWebsocket(r) {
		conn, err := websocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		ticker := time.NewTicker(snapshotStreamInterval)
		defer ticker.Stop()
		for {
			if err := conn.WriteJSON(snapshot()); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}

	writeJSON(w, http.StatusOK, snapshot())
}

func streamMemory(w http.ResponseWriter, r *http.Request, snapshot func() Memory) {
	if wantsWebsocket(r) {
		conn, err := websocketUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			if err := conn.WriteJSON(snapshot()); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
		}
	}

	writeJSON(w, http.StatusOK, snapshot())
}

func streamJSONSnapshots(w http.ResponseWriter, r *http.Request, snapshot func() any) {
	streamJSONSnapshotsEvery(w, r, snapshotStreamInterval, snapshot)
}

func streamJSONSnapshotsEvery(w http.ResponseWriter, r *http.Request, interval time.Duration, snapshot func() any) {
	streamJSONSnapshotsWithErrorEvery(w, r, interval, func() (any, error) {
		return snapshot(), nil
	})
}

func streamJSONSnapshotsWithError(w http.ResponseWriter, r *http.Request, snapshot func() (any, error)) {
	streamJSONSnapshotsWithErrorEvery(w, r, snapshotStreamInterval, snapshot)
}

func streamJSONSnapshotsWithErrorEvery(w http.ResponseWriter, r *http.Request, interval time.Duration, snapshot func() (any, error)) {
	conn, err := websocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		payload, err := snapshot()
		if err != nil {
			return
		}
		if err := conn.WriteJSON(payload); err != nil {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func makeStructuredLog(event LogEvent) structuredLog {
	level := event.Type
	if level == "warning" {
		level = "warn"
	}
	fields := make([]structuredLogField, 0, len(event.Fields))
	for _, field := range event.Fields {
		fields = append(fields, structuredLogField{
			Key:   field.Key,
			Value: field.Value,
		})
	}
	return structuredLog{
		Time:    event.Time.Format(time.TimeOnly),
		Level:   level,
		Message: event.Payload,
		Fields:  fields,
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		httpErr = &HTTPError{Message: err.Error()}
	}
	writeJSON(w, status, httpErr)
}

var providerErrNotFound = errors.New("not found")
