package controlapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeProvider struct {
	config        Config
	daeConfig     DaeConfigDocument
	traffic       Traffic
	connections   ConnectionsSnapshot
	memory        Memory
	proxies       map[string]Proxy
	version       string
	meta          bool
	updateCalls   []string
	resetCalls    []string
	delayValue    int
	delayErr      error
	lastLogLevel  string
	lastDaeConfig string
}

func (f *fakeProvider) Hello() string   { return "dae" }
func (f *fakeProvider) Version() string { return f.version }
func (f *fakeProvider) Meta() bool      { return f.meta }
func (f *fakeProvider) Config() Config  { return f.config }
func (f *fakeProvider) DaeConfigDocument() (DaeConfigDocument, error) {
	return f.daeConfig, nil
}
func (f *fakeProvider) Memory() Memory   { return f.memory }
func (f *fakeProvider) Traffic() Traffic { return f.traffic }
func (f *fakeProvider) Connections(limit int) ConnectionsSnapshot {
	if limit > 0 && len(f.connections.Connections) > limit {
		snapshot := f.connections
		snapshot.Connections = append([]Connection(nil), snapshot.Connections[:limit]...)
		snapshot.Total = len(f.connections.Connections)
		return snapshot
	}
	return f.connections
}
func (f *fakeProvider) Proxies() map[string]Proxy       { return f.proxies }
func (f *fakeProvider) Proxy(name string) (Proxy, bool) { p, ok := f.proxies[name]; return p, ok }
func (f *fakeProvider) UpdateProxy(groupName, proxyName string) error {
	f.updateCalls = append(f.updateCalls, groupName+"->"+proxyName)
	return nil
}
func (f *fakeProvider) ResetProxy(groupName string) error {
	f.resetCalls = append(f.resetCalls, groupName)
	return nil
}
func (f *fakeProvider) Delay(name, probeURL string, timeout time.Duration) (int, error) {
	return f.delayValue, f.delayErr
}
func (f *fakeProvider) SetLogLevel(level string) error {
	f.lastLogLevel = level
	return nil
}
func (f *fakeProvider) UpdateDaeConfig(content string) error {
	f.lastDaeConfig = content
	return nil
}

func TestVersionAndConfigs(t *testing.T) {
	provider := &fakeProvider{
		version: "test-version",
		config: Config{
			TProxyPort: 12345,
			LogLevel:   "info",
			Mode:       "rule",
		},
		proxies: map[string]Proxy{},
	}
	server := httptest.NewServer(NewServer(ServerConfig{}, provider, nil).handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("version status = %d", resp.StatusCode)
	}

	resp, err = http.Get(server.URL + "/configs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got Config
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.TProxyPort != 12345 {
		t.Fatalf("tproxy port = %d", got.TProxyPort)
	}
}

func TestProxyRoutes(t *testing.T) {
	provider := &fakeProvider{
		version: "test-version",
		proxies: map[string]Proxy{
			"auto": {
				Name: "auto",
				Type: "Selector",
				All:  []string{"node-a", "node-b"},
				Now:  "node-a",
			},
		},
		delayValue: 42,
	}
	server := httptest.NewServer(NewServer(ServerConfig{}, provider, nil).handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/proxies")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxies status = %d", resp.StatusCode)
	}

	body := bytes.NewBufferString(`{"name":"node-b"}`)
	req, err := http.NewRequest(http.MethodPut, server.URL+"/proxies/auto", body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(provider.updateCalls) != 1 || provider.updateCalls[0] != "auto->node-b" {
		t.Fatalf("unexpected update calls: %#v", provider.updateCalls)
	}

	req, err = http.NewRequest(http.MethodDelete, server.URL+"/proxies/auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(provider.resetCalls) != 1 || provider.resetCalls[0] != "auto" {
		t.Fatalf("unexpected reset calls: %#v", provider.resetCalls)
	}

	resp, err = http.Get(server.URL + "/proxies/auto/delay?timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var delay map[string]int
	if err := json.NewDecoder(resp.Body).Decode(&delay); err != nil {
		t.Fatal(err)
	}
	if delay["delay"] != 42 {
		t.Fatalf("delay = %d", delay["delay"])
	}
}

func TestConnectionsRoute(t *testing.T) {
	provider := &fakeProvider{
		connections: ConnectionsSnapshot{
			Total: 2,
			TCP:   1,
			UDP:   1,
			Connections: []Connection{
				{
					ID:                 "tcp|a",
					Network:            "tcp",
					State:              "established",
					Source:             "10.0.0.2:34567",
					SourceAddress:      "10.0.0.2",
					SourcePort:         34567,
					Destination:        "1.1.1.1:443",
					DestinationAddress: "1.1.1.1",
					DestinationPort:    443,
					Process:            "Safari",
					PID:                123,
					Outbound:           "proxy",
					Direction:          "lan-egress",
					Mark:               12,
					DSCP:               46,
					Must:               true,
					HasRouting:         true,
					Mac:                "aa:bb:cc:dd:ee:ff",
				},
				{
					ID:                 "udp|b",
					Network:            "udp",
					State:              "active",
					Source:             "10.0.0.2:5353",
					SourceAddress:      "10.0.0.2",
					SourcePort:         5353,
					Destination:        "8.8.8.8:53",
					DestinationAddress: "8.8.8.8",
					DestinationPort:    53,
					Process:            "mDNSResponder",
					PID:                55,
					Outbound:           "direct",
					Direction:          "lan-egress",
				},
			},
		},
		proxies: map[string]Proxy{},
	}
	server := httptest.NewServer(NewServer(ServerConfig{}, provider, nil).handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/connections?limit=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connections status = %d", resp.StatusCode)
	}

	var got ConnectionsSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 2 {
		t.Fatalf("total = %d", got.Total)
	}
	if len(got.Connections) != 1 {
		t.Fatalf("connections len = %d", len(got.Connections))
	}
	if got.Connections[0].ID != "tcp|a" {
		t.Fatalf("first connection id = %q", got.Connections[0].ID)
	}
	if got.Connections[0].State != "established" {
		t.Fatalf("first connection state = %q", got.Connections[0].State)
	}
	if got.Connections[0].SourceAddress != "10.0.0.2" || got.Connections[0].DestinationPort != 443 {
		t.Fatalf("unexpected connection endpoint payload: %#v", got.Connections[0])
	}
	if !got.Connections[0].Must || !got.Connections[0].HasRouting || got.Connections[0].Mac == "" {
		t.Fatalf("unexpected connection flags: %#v", got.Connections[0])
	}
}

func TestTrafficAndMemoryRoutesReturnSingleSnapshots(t *testing.T) {
	provider := &fakeProvider{
		traffic: Traffic{
			Up:        11,
			Down:      22,
			UpTotal:   33,
			DownTotal: 44,
		},
		memory: Memory{
			Inuse:   1234,
			OSLimit: 5678,
		},
		proxies: map[string]Proxy{},
	}
	server := httptest.NewServer(NewServer(ServerConfig{}, provider, nil).handler())
	defer server.Close()

	client := &http.Client{Timeout: time.Second}

	resp, err := client.Get(server.URL + "/traffic")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("traffic status = %d", resp.StatusCode)
	}
	var traffic Traffic
	if err := json.NewDecoder(resp.Body).Decode(&traffic); err != nil {
		t.Fatal(err)
	}
	if traffic.Up != 11 || traffic.DownTotal != 44 {
		t.Fatalf("unexpected traffic payload: %#v", traffic)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("traffic body should close after one snapshot: %v", err)
	}

	resp, err = client.Get(server.URL + "/memory")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("memory status = %d", resp.StatusCode)
	}
	var memory Memory
	if err := json.NewDecoder(resp.Body).Decode(&memory); err != nil {
		t.Fatal(err)
	}
	if memory.Inuse != 1234 || memory.OSLimit != 5678 {
		t.Fatalf("unexpected memory payload: %#v", memory)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("memory body should close after one snapshot: %v", err)
	}
}

func TestAuthAndPatchConfigs(t *testing.T) {
	provider := &fakeProvider{
		proxies: map[string]Proxy{},
	}
	server := httptest.NewServer(NewServer(ServerConfig{Secret: "secret"}, provider, nil).handler())
	defer server.Close()

	req, err := http.NewRequest(http.MethodPatch, server.URL+"/configs", bytes.NewBufferString(`{"log-level":"debug"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if provider.lastLogLevel != "debug" {
		t.Fatalf("log level = %q", provider.lastLogLevel)
	}

	req, err = http.NewRequest(http.MethodPut, server.URL+"/configs/dae", bytes.NewBufferString(`{"content":"global{} routing{}"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if provider.lastDaeConfig != "global{} routing{}" {
		t.Fatalf("dae config = %q", provider.lastDaeConfig)
	}

	req, err = http.NewRequest(http.MethodGet, server.URL+"/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected unauthorized, got %d body=%s", resp.StatusCode, string(body))
	}
}

func TestGetEditableDaeConfig(t *testing.T) {
	provider := &fakeProvider{
		daeConfig: DaeConfigDocument{
			Path:    "/etc/dae/config.dae",
			Content: "global{} routing{}",
		},
		proxies: map[string]Proxy{},
	}
	server := httptest.NewServer(NewServer(ServerConfig{}, provider, nil).handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/configs/dae")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dae config status = %d", resp.StatusCode)
	}

	var got DaeConfigDocument
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Path != "/etc/dae/config.dae" {
		t.Fatalf("config path = %q", got.Path)
	}
	if got.Content != "global{} routing{}" {
		t.Fatalf("config content = %q", got.Content)
	}
}

func TestWebUIIsServedWithoutBreakingAPIAuth(t *testing.T) {
	provider := &fakeProvider{
		proxies: map[string]Proxy{},
	}
	server := httptest.NewServer(NewServer(ServerConfig{Secret: "secret"}, provider, nil).handler())
	defer server.Close()

	resp, err := http.Get(server.URL + "/ui/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("ui status = %d body=%s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("controllerForm")) {
		t.Fatalf("ui body missing controller form: %s", string(body))
	}

	resp, err = http.Get(server.URL + "/ui/script.js")
	if err != nil {
		t.Fatal(err)
	}
	if cacheControl := resp.Header.Get("Cache-Control"); cacheControl != "no-store, max-age=0" {
		t.Fatalf("unexpected ui cache-control: %q", cacheControl)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ui script status = %d", resp.StatusCode)
	}

	resp, err = http.Get(server.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected version to remain unauthorized, got %d", resp.StatusCode)
	}
}
