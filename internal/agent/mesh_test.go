package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/cache"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

// stagedUpdateRig is a supervisor IPC pair that offers one slot directory, and
// an origin that serves one binary and counts its downloads.
type stagedUpdateRig struct {
	slotDir string
	client  *supervisor.IPCClient
	origin  *httptest.Server
	hits    *atomic.Int64
	sum     string
	payload []byte
	exited  chan int
}

func newStagedUpdateRig(t *testing.T) *stagedUpdateRig {
	t.Helper()
	r := &stagedUpdateRig{slotDir: t.TempDir(), hits: &atomic.Int64{}}
	pipe := supervisor.NewInMemoryPipe()
	t.Cleanup(func() { pipe.Close() })
	srv := supervisor.NewIPCServer()
	t.Cleanup(func() { _ = srv.Stop() })
	srv.RegisterHandler(supervisor.MsgGetInactive, func(*supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{Type: supervisor.MsgInactiveResp, Slot: "slot_b", Path: r.slotDir}, nil
	})
	srv.RegisterHandler(supervisor.MsgRequestRestart, func(*supervisor.IPCMessage) (*supervisor.IPCMessage, error) { return nil, nil })
	if err := srv.Start(pipe); err != nil {
		t.Fatal(err)
	}
	conn, err := pipe.Dial()
	if err != nil {
		t.Fatal(err)
	}
	r.client = supervisor.NewIPCClient(nil, 2*time.Second)
	_ = r.client.Connect(conn)
	t.Cleanup(func() { r.client.Close() })

	r.sum, r.payload = writeTestBinaryBytes(t, "v9.9.9", true)
	r.origin = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.hits.Add(1)
		w.Write(r.payload)
	}))
	t.Cleanup(r.origin.Close)

	origExit, origDelay := updateExitFunc, updateExitDelay
	r.exited = make(chan int, 4)
	updateExitFunc, updateExitDelay = func(code int) { r.exited <- code }, time.Millisecond
	t.Cleanup(func() { updateExitFunc, updateExitDelay = origExit, origDelay })
	t.Cleanup(func() { updateCache.Store(nil) })
	return r
}

func (r *stagedUpdateRig) update(t *testing.T) (string, error) {
	t.Helper()
	source, err := selfUpdateSource(context.Background(), &Config{ServerURL: r.origin.URL},
		protocol.AgentUpdate{URL: r.origin.URL + "/agent", SHA256: r.sum, Version: "v9.9.9"}, r.client)
	if err == nil {
		// The worker exit is scheduled, and must land before the hooks are
		// put back.
		select {
		case <-r.exited:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for the worker exit")
		}
	}
	return source, err
}

func startTestLeader(t *testing.T, originURL string) *cache.Leader {
	t.Helper()
	dir := t.TempDir()
	cert, fp, err := cache.LoadOrCreateCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err := cache.OpenStore(filepath.Join(dir, "cas"), 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := cache.NewServer(cache.ServerConfig{Store: st, Origin: originURL, Cert: cert, Tokens: func() []string { return []string{"tok"} }})
	if err := srv.Start(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return &cache.Leader{Addr: "127.0.0.1:" + strconv.Itoa(srv.Port()), ID: "lead-7", Fingerprint: fp, Token: "tok"}
}

func TestSelfUpdateThroughCacheLeader(t *testing.T) {
	r := newStagedUpdateRig(t)
	l := startTestLeader(t, r.origin.URL)
	updateCache.Store(&cache.Client{Leader: l, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond})

	source, err := r.update(t)
	if err != nil {
		t.Fatalf("update through the cache failed: %v", err)
	}
	if !strings.HasPrefix(source, "cache lead-7 over https") {
		t.Fatalf("source %q should name the cache leader", source)
	}
	got, err := os.ReadFile(filepath.Join(r.slotDir, supervisor.BinaryExecutableName))
	if err != nil || string(got) != string(r.payload) {
		t.Fatalf("staged binary is wrong: %v", err)
	}
	if r.hits.Load() != 1 {
		t.Fatalf("the origin served %d downloads, want 1 (the leader's fill)", r.hits.Load())
	}
	if left, _ := filepath.Glob(filepath.Join(r.slotDir, ".cache-fetch*")); len(left) != 0 {
		t.Fatalf("temporary download files left behind: %v", left)
	}
}

func TestSelfUpdateFallsBackToOriginWhenLeaderIsGone(t *testing.T) {
	r := newStagedUpdateRig(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	updateCache.Store(&cache.Client{
		Leader:     &cache.Leader{Addr: dead, ID: "gone", Fingerprint: strings.Repeat("c", 64), Token: "t"},
		Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond,
	})
	source, err := r.update(t)
	if err != nil {
		t.Fatalf("update must succeed from the origin: %v", err)
	}
	if !strings.HasPrefix(source, "origin (the cache failed") {
		t.Fatalf("source %q should say the origin served it and why", source)
	}
	if r.hits.Load() != 1 {
		t.Fatalf("origin downloads: %d, want 1", r.hits.Load())
	}
}

func TestSelfUpdateWithoutLeaderSaysOrigin(t *testing.T) {
	r := newStagedUpdateRig(t)
	source, err := r.update(t)
	if err != nil || source != "origin" {
		t.Fatalf("source %q err %v, want a plain origin download", source, err)
	}
}

func freeTCPUDPPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		pc.Close()
		if err == nil {
			ln.Close()
			return port
		}
	}
	t.Fatal("no port free for both TCP and UDP")
	return 0
}

func TestMeshApplyStartsRetokensAndStopsLeader(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	var mu sync.Mutex
	var calls []string
	orig := meshFirewallHook
	meshFirewallHook = func(add bool, port int) {
		mu.Lock()
		calls = append(calls, strconv.FormatBool(add)+":"+strconv.Itoa(port))
		mu.Unlock()
	}
	t.Cleanup(func() { meshFirewallHook = orig; updateCache.Store(nil) })

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("artifact bytes")) }))
	defer origin.Close()
	a := New(&Config{ServerURL: origin.URL})
	h := a.hello()
	if !h.CacheCapable || len(h.CacheFingerprint) != 64 {
		t.Fatalf("hello should say the device can lead and give the certificate fingerprint: %+v", h)
	}
	if _, err := os.Stat(filepath.Join(ConfigDir(), "cache.crt")); err != nil {
		t.Fatalf("the certificate must persist in the config directory: %v", err)
	}
	if a.mesh.stats() != nil {
		t.Fatal("a device without an assignment reports no cache role")
	}

	port := freeTCPUDPPort(t)
	cfg := &protocol.CacheConfig{LeaderAddr: "127.0.0.1:" + strconv.Itoa(port), LeaderID: a.cfg.AgentID, Fingerprint: h.CacheFingerprint, Token: "day-1", Serve: true, Port: port, MaxBytes: 1 << 20}
	a.mesh.apply(a, cfg)
	if st := a.mesh.stats(); st == nil || st.Role != "leader" {
		t.Fatalf("stats after becoming leader: %+v", st)
	}

	get := func(token string) int {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cache.PinnedTLS(h.CacheFingerprint)}}
		req, _ := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(port)+"/cas/"+strings.Repeat("0", 64)+"/index", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := cl.Do(req)
		if err != nil {
			return -1
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := get("day-1"); got != 404 {
		t.Fatalf("the leader should accept the token (404 for an unknown artifact), got %d", got)
	}
	if got := get("nope"); got != 401 {
		t.Fatalf("a wrong token must be refused, got %d", got)
	}

	// The next day's token: both it and yesterday's are accepted, a third
	// generation retires the first.
	cfg2 := *cfg
	cfg2.Token = "day-2"
	a.mesh.apply(a, &cfg2)
	if get("day-2") != 404 || get("day-1") != 404 {
		t.Fatal("after a token rollover the leader must accept today's and yesterday's token")
	}
	cfg3 := *cfg
	cfg3.Token = "day-3"
	a.mesh.apply(a, &cfg3)
	if get("day-3") != 404 || get("day-1") != 401 {
		t.Fatal("a token two generations old must be refused")
	}

	// Demoted to member: the server stops and the firewall rule goes.
	member := *cfg
	member.Serve = false
	a.mesh.apply(a, &member)
	if st := a.mesh.stats(); st == nil || st.Role != "member" {
		t.Fatalf("stats after demotion: %+v", st)
	}
	if updateCache.Load() == nil || updateCache.Load().Leader == nil {
		t.Fatal("a member keeps the leader for its downloads")
	}
	if got := get("day-3"); got != -1 {
		t.Fatalf("the demoted device must stop listening, got %d", got)
	}

	a.mesh.apply(a, nil)
	if a.mesh.stats() != nil || updateCache.Load() != nil {
		t.Fatal("clearing the assignment must clear the role and the leader")
	}
	want := "true:" + strconv.Itoa(port) + ",false:" + strconv.Itoa(port)
	// The firewall calls run on a background goroutine, outside the lock.
	var got string
	for i := 0; i < 200; i++ {
		mu.Lock()
		got = strings.Join(calls, ",")
		mu.Unlock()
		if got == want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("firewall calls %s, want %s", got, want)
	}
}

func TestMeshEmptyConfigKeepsAssignment(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	t.Cleanup(func() { updateCache.Store(nil) })
	a := New(&Config{ServerURL: "https://rmm.example"})
	cfg := &protocol.CacheConfig{LeaderAddr: "10.0.0.5:7443", LeaderID: "x", Fingerprint: strings.Repeat("d", 64), Token: "t"}
	a.applyConfig(protocol.AgentConfig{Cache: cfg}, nil, nil)
	// A welcome that carries no config at all says nothing about the cache.
	a.applyConfigRaw(nil)
	if st := a.mesh.stats(); st == nil || st.Role != "member" {
		t.Fatalf("an empty config must not drop the cache assignment: %+v", st)
	}
	a.applyConfig(protocol.AgentConfig{}, nil, nil)
	if a.mesh.stats() != nil {
		t.Fatal("a config without a cache section removes the assignment")
	}
}

func TestMeshLeaderThatCannotBindReportsItAndUsesTheOrigin(t *testing.T) {
	t.Setenv(EnvConfigDir, t.TempDir())
	orig := meshFirewallHook
	meshFirewallHook = func(bool, int) {}
	t.Cleanup(func() { meshFirewallHook = orig; updateCache.Store(nil) })

	// Hold the TCP port so the leader's bind fails.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	a := New(&Config{ServerURL: "https://rmm.example"})
	h := a.hello()
	cfg := &protocol.CacheConfig{LeaderAddr: "127.0.0.1:" + strconv.Itoa(port), LeaderID: a.cfg.AgentID, Fingerprint: h.CacheFingerprint, Token: "t", Serve: true, Port: port, MaxBytes: 1 << 20}
	a.mesh.apply(a, cfg)
	st := a.mesh.stats()
	if st == nil || !st.ServeFailed || st.Serving || st.Role != "member" {
		t.Fatalf("a leader that could not bind must say so: %+v", st)
	}
	if updateCache.Load() != nil {
		t.Fatal("a leader that cannot serve must send its own downloads to the origin, not to itself")
	}

	// Demoted to member (the server picked someone else): it fetches through
	// the new leader again.
	member := *cfg
	member.Serve, member.LeaderID, member.LeaderAddr = false, "other", "127.0.0.1:1"
	a.mesh.apply(a, &member)
	if st := a.mesh.stats(); st == nil || st.ServeFailed || updateCache.Load() == nil {
		t.Fatalf("a member must use its leader: %+v", st)
	}
}
