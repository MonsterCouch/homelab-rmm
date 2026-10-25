package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func iface(name string, ips ...string) protocol.NetIface {
	return protocol.NetIface{Name: name, Up: true, IPs: ips}
}

func member(id, org string, since time.Time, capable bool, ips ...string) meshMember {
	m := meshMember{ID: id, Org: org, Capable: capable, Since: since, IPs: meshSubnets([]protocol.NetIface{iface("eth0", ips...)})}
	if capable {
		m.Fingerprint = strings.Repeat(id[:1], 64)
	}
	return m
}

func testTokenFor(org string) string { return "tok-" + org }

func TestCacheAssignSubnetsNarrowsWideAndSkipsVirtual(t *testing.T) {
	got := meshSubnets([]protocol.NetIface{
		iface("Ethernet", "10.1.2.33/16", "fe80::1/64"),
		iface("Wi-Fi", "192.168.5.20/23"),
		iface("docker0", "172.17.0.1/16"),
		iface("vEthernet (Default Switch)", "172.28.0.1/20"),
		iface("vEthernet (External)", "192.168.9.4/24"),
		iface("Local Area Connection", "10.9.9.9/24"),
		iface("eth9", "169.254.3.4/16"),
		iface("tun0", "10.8.0.2/32"),
		{Name: "down", Up: false, IPs: []string{"10.77.0.1/24"}},
	})
	want := map[string]string{
		"10.1.2.0/24":    "10.1.2.33",
		"192.168.4.0/23": "192.168.5.20",
		"192.168.9.0/24": "192.168.9.4",
		"10.9.9.0/24":    "10.9.9.9",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for p, ip := range got {
		if want[p.String()] != ip.String() {
			t.Fatalf("subnet %s -> %s, want %v", p, ip, want)
		}
	}
	// A /16 is narrowed to the /24 of the address, not kept whole.
	if _, ok := got[netip.MustParsePrefix("10.1.0.0/16")]; ok {
		t.Fatal("a prefix wider than /22 must be narrowed to /24")
	}
}

func TestCacheAssignPlanGroupsByPrefixAndOrganization(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	members := []meshMember{
		member("a1", "org1", t0, true, "192.168.1.10/24"),
		member("b1", "org1", t0.Add(time.Minute), false, "192.168.1.11/24"),
		member("c1", "org1", t0, true, "192.168.2.10/24"), // alone on its subnet
		member("d2", "org2", t0, true, "192.168.1.12/24"), // same prefix, other organization
		member("e2", "org2", t0.Add(time.Second), true, "192.168.1.13/24"),
		member("f1", "org1", t0, true, "10.5.0.1/16"),
		member("g1", "org1", t0.Add(time.Second), true, "10.5.0.77/16"), // the same /24 once narrowed
	}
	plan := meshPlan(members, MeshCacheSettings{Enabled: true}, testTokenFor)
	if plan["c1"] != nil {
		t.Fatal("a device alone on its subnet has nobody to share with")
	}
	for _, id := range []string{"a1", "b1"} {
		if plan[id] == nil || plan[id].LeaderID != "a1" || plan[id].Token != "tok-org1" {
			t.Fatalf("%s should follow a1 with org1's token: %+v", id, plan[id])
		}
	}
	for _, id := range []string{"d2", "e2"} {
		if plan[id] == nil || plan[id].LeaderID != "d2" || plan[id].Token != "tok-org2" {
			t.Fatalf("%s must be grouped inside org2 only: %+v", id, plan[id])
		}
	}
	if plan["f1"] == nil || plan["f1"].LeaderID != "f1" || plan["g1"].LeaderID != "f1" || plan["f1"].LeaderAddr != "10.5.0.1:7443" {
		t.Fatalf("a /16 narrowed to /24 should group f1 and g1 under f1: %+v %+v", plan["f1"], plan["g1"])
	}
}

func TestCacheAssignPlanDeviceOnTwoSubnetsJoinsLargestGroup(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	both := member("h1", "o", t0, true, "192.168.1.5/24", "192.168.2.5/24")
	members := []meshMember{
		both,
		member("a1", "o", t0, true, "192.168.1.6/24"),
		member("b1", "o", t0, true, "192.168.2.6/24"),
		member("c1", "o", t0, true, "192.168.2.7/24"),
	}
	plan := meshPlan(members, MeshCacheSettings{Enabled: true}, testTokenFor)
	// All four started together, so the id breaks the tie and b1 leads.
	if plan["h1"] == nil || plan["h1"].LeaderID != "b1" || plan["h1"].LeaderAddr != "192.168.2.6:7443" {
		t.Fatalf("h1 belongs in the larger 192.168.2.0/24 group, led by b1: %+v", plan["h1"])
	}
	if plan["a1"] != nil {
		t.Fatalf("a1 is left alone once h1 joined the other group: %+v", plan["a1"])
	}
}

func TestCacheAssignPlanLeaderChoiceAndReplacement(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	oldNoCache := member("a1", "o", t0, false, "192.168.1.10/24")
	mid := member("b1", "o", t0.Add(10*time.Minute), true, "192.168.1.11/24")
	young := member("c1", "o", t0.Add(20*time.Minute), true, "192.168.1.12/24")

	plan := meshPlan([]meshMember{oldNoCache, mid, young}, MeshCacheSettings{Enabled: true}, testTokenFor)
	if plan["a1"].LeaderID != "b1" {
		t.Fatalf("the longest online device that is cache capable leads, got %q", plan["a1"].LeaderID)
	}
	if !plan["b1"].Serve || plan["a1"].Serve || plan["c1"].Serve {
		t.Fatal("only the leader serves")
	}

	// b1 goes offline: the next pass picks c1, and a1 is told.
	plan = meshPlan([]meshMember{oldNoCache, young}, MeshCacheSettings{Enabled: true}, testTokenFor)
	if plan["a1"].LeaderID != "c1" || !plan["c1"].Serve {
		t.Fatalf("a replacement leader was not chosen: %+v", plan["a1"])
	}

	// Nobody capable: no cache for anyone.
	plan = meshPlan([]meshMember{oldNoCache, member("d1", "o", t0, false, "192.168.1.13/24")}, MeshCacheSettings{Enabled: true}, testTokenFor)
	if len(plan) != 0 {
		t.Fatalf("a group with no capable device gets no cache: %+v", plan)
	}

	// Equal start times break ties by id, so two passes never disagree.
	x, y := member("x1", "o", t0, true, "192.168.1.20/24"), member("y1", "o", t0, true, "192.168.1.21/24")
	if p := meshPlan([]meshMember{y, x}, MeshCacheSettings{Enabled: true}, testTokenFor); p["y1"].LeaderID != "x1" {
		t.Fatal("ties must break by id")
	}
}

func TestCacheAssignPlanConfigContents(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	members := []meshMember{
		member("l1", "o", t0, true, "192.168.1.5/24"),
		member("m1", "o", t0.Add(time.Minute), true, "192.168.1.6/24"),
	}
	plan := meshPlan(members, MeshCacheSettings{Enabled: true, Port: 9443, MaxBytes: 5 << 30}, testTokenFor)
	l, m := plan["l1"], plan["m1"]
	if l.LeaderAddr != "192.168.1.5:9443" || m.LeaderAddr != l.LeaderAddr {
		t.Fatalf("leader address: %q / %q", l.LeaderAddr, m.LeaderAddr)
	}
	if l.Fingerprint != strings.Repeat("l", 64) || m.Fingerprint != l.Fingerprint || l.LeaderID != "l1" || m.LeaderID != "l1" {
		t.Fatalf("members must pin the leader's fingerprint: %+v %+v", l, m)
	}
	if !l.Serve || l.Port != 9443 || l.MaxBytes != 5<<30 {
		t.Fatalf("the leader is told to serve with the configured port and budget: %+v", l)
	}
	if m.Serve || m.Port != 0 || m.MaxBytes != 0 {
		t.Fatalf("a member is not told to serve: %+v", m)
	}
	if l.Token != "tok-o" || m.Token != "tok-o" {
		t.Fatal("everyone in the organization carries its token")
	}
}

func TestCacheAssignTokenIsDaily(t *testing.T) {
	d1 := time.Date(2026, 10, 24, 23, 59, 0, 0, time.UTC)
	d2 := d1.Add(2 * time.Minute)
	a := meshToken("secret", "org1", d1)
	if a != meshToken("secret", "org1", d1.Add(-20*time.Hour)) {
		t.Fatal("the token is stable within a UTC day")
	}
	if a == meshToken("secret", "org1", d2) {
		t.Fatal("the token changes at midnight UTC")
	}
	if a == meshToken("secret", "org2", d1) || a == meshToken("other", "org1", d1) {
		t.Fatal("the token depends on the organization and the secret")
	}
	if len(a) != 64 {
		t.Fatalf("token %q is not a hex HMAC-SHA256", a)
	}
	// Local time zones must not matter.
	if meshToken("secret", "org1", d1.In(time.FixedZone("x", 14*3600))) != a {
		t.Fatal("the day is the UTC day")
	}
}

// ---- end to end with fake agents ----

type meshAgent struct {
	t       *testing.T
	ws      *websocket.Conn
	mu      sync.Mutex
	wmu     sync.Mutex
	id      string
	latest  protocol.AgentConfig
	pushes  int
	welcome protocol.AgentConfig
}

func dialMesh(t *testing.T, s *Server, url, tok, host string, capable bool, fp string, ips ...string) *meshAgent {
	t.Helper()
	ws, resp, err := websocket.DefaultDialer.Dial(url+"/ws/agent", http.Header{"X-Enroll-Token": []string{tok}})
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", host, err, code)
	}
	h := protocol.Hello{Hostname: host, OS: "linux", Platform: "Test", Arch: "amd64", Version: "test", ProtocolVersion: protocol.Version, CacheCapable: capable, CacheFingerprint: fp}
	if err := ws.WriteJSON(protocol.Envelope{T: protocol.TypeHello, D: protocol.Must(h)}); err != nil {
		t.Fatal(err)
	}
	var env protocol.Envelope
	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := ws.ReadJSON(&env); err != nil || env.T != "welcome" {
		t.Fatalf("welcome for %s: %v %s", host, err, env.T)
	}
	ws.SetReadDeadline(time.Time{})
	var w struct {
		AgentID string               `json:"agent_id"`
		Config  protocol.AgentConfig `json:"config"`
	}
	json.Unmarshal(env.D, &w)
	a := &meshAgent{t: t, ws: ws, id: w.AgentID, welcome: w.Config, latest: w.Config}
	t.Cleanup(func() { ws.Close() })
	waitFor(t, host+" online", func() bool { return s.hub.IsOnline(a.id) })
	inv := &protocol.Inventory{Hostname: host, Network: []protocol.NetIface{{Name: "eth0", Up: true, IPs: ips}}}
	if err := s.db.saveInventory(a.id, inv); err != nil {
		t.Fatal(err)
	}
	go a.loop()
	return a
}

func (a *meshAgent) loop() {
	for {
		var env protocol.Envelope
		if err := a.ws.ReadJSON(&env); err != nil {
			return
		}
		switch env.T {
		case protocol.ReqPing:
			a.wmu.Lock()
			a.ws.WriteJSON(protocol.Envelope{T: protocol.TypePong, ID: env.ID})
			a.wmu.Unlock()
		case protocol.ReqAgentConfig:
			var c protocol.AgentConfig
			if json.Unmarshal(env.D, &c) == nil {
				a.mu.Lock()
				a.latest = c
				a.pushes++
				a.mu.Unlock()
			}
		}
	}
}

func (a *meshAgent) cache() *protocol.CacheConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.latest.Cache
}

func (a *meshAgent) pushCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.pushes
}

func enableMesh(t *testing.T, s *Server, on bool) {
	t.Helper()
	if err := s.db.SetSettingJSON("mesh_cache", MeshCacheSettings{Enabled: on, Port: 7443, MaxBytes: meshDefaultMax}); err != nil {
		t.Fatal(err)
	}
}

func TestCacheAssignAssignPassPushesAndReplacesLeader(t *testing.T) {
	s, ts, _ := newTestServer(t)
	tok := enrollToken(t, s)
	enableMesh(t, s, true)
	u := wsURL(ts)

	a := dialMesh(t, s, u, tok, "alpha", true, strings.Repeat("a", 64), "192.168.1.10/24")
	time.Sleep(20 * time.Millisecond) // a connects measurably before b
	b := dialMesh(t, s, u, tok, "bravo", true, strings.Repeat("b", 64), "192.168.1.11/24")
	c := dialMesh(t, s, u, tok, "charlie", false, "", "192.168.1.12/24")
	d := dialMesh(t, s, u, tok, "delta", true, strings.Repeat("d", 64), "10.20.30.40/24")

	// The welcome of a device that connects before any pass carries no cache.
	if a.welcome.Cache != nil {
		t.Fatalf("no assignment exists yet: %+v", a.welcome.Cache)
	}
	s.meshPass()

	waitFor(t, "assignments pushed", func() bool { return a.cache() != nil && b.cache() != nil && c.cache() != nil })
	if cc := a.cache(); !cc.Serve || cc.LeaderID != a.id || cc.LeaderAddr != "192.168.1.10:7443" {
		t.Fatalf("alpha should lead from its own address: %+v", cc)
	}
	for _, m := range []*meshAgent{b, c} {
		if cc := m.cache(); cc.Serve || cc.LeaderID != a.id || cc.Fingerprint != strings.Repeat("a", 64) || cc.Token == "" {
			t.Fatalf("members follow alpha and pin its certificate: %+v", cc)
		}
	}
	if d.cache() != nil || d.pushCount() != 0 {
		t.Fatalf("delta is alone on its subnet and must be left alone: %+v", d.cache())
	}

	// Nothing changed: a second pass pushes nothing.
	before := a.pushCount() + b.pushCount() + c.pushCount()
	s.meshPass()
	time.Sleep(100 * time.Millisecond)
	if after := a.pushCount() + b.pushCount() + c.pushCount(); after != before {
		t.Fatalf("an unchanged plan was pushed again (%d -> %d)", before, after)
	}

	// The leader goes away: bravo takes over and charlie is told.
	a.ws.Close()
	waitFor(t, "alpha offline", func() bool { return !s.hub.IsOnline(a.id) })
	s.meshPass()
	waitFor(t, "bravo leads", func() bool { cc := b.cache(); return cc != nil && cc.Serve && cc.LeaderID == b.id })
	waitFor(t, "charlie follows bravo", func() bool { cc := c.cache(); return cc != nil && cc.LeaderID == b.id && !cc.Serve })

	// Switching the feature off clears every assignment.
	enableMesh(t, s, false)
	s.meshPass()
	waitFor(t, "assignments cleared", func() bool { return b.cache() == nil && c.cache() == nil })
}

func TestCacheAssignWelcomeCarriesAssignment(t *testing.T) {
	s, ts, _ := newTestServer(t)
	tok := enrollToken(t, s)
	enableMesh(t, s, true)
	u := wsURL(ts)
	a := dialMesh(t, s, u, tok, "alpha", true, strings.Repeat("a", 64), "192.168.7.10/24")
	b := dialMesh(t, s, u, tok, "bravo", true, strings.Repeat("b", 64), "192.168.7.11/24")
	s.meshPass()
	waitFor(t, "pushed", func() bool { return a.cache() != nil && b.cache() != nil })

	// agentConfig is the one builder for welcomes and pushes.
	cfg := s.agentConfig(b.id)
	if cfg.Cache == nil || cfg.Cache.LeaderID != a.id || cfg.Cache.Serve {
		t.Fatalf("a reconnecting member's welcome should carry its assignment: %+v", cfg.Cache)
	}
	cfg = s.agentConfig(a.id)
	if cfg.Cache == nil || !cfg.Cache.Serve || cfg.Cache.Port != 7443 {
		t.Fatalf("a reconnecting leader's welcome should tell it to serve: %+v", cfg.Cache)
	}
}

func TestCacheAssignKickOnOfflineReassignsWithoutWaiting(t *testing.T) {
	old := meshKickDelay
	meshKickDelay = 10 * time.Millisecond
	t.Cleanup(func() { meshKickDelay = old })

	s, ts, _ := newTestServer(t)
	tok := enrollToken(t, s)
	enableMesh(t, s, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.meshLoop(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	u := wsURL(ts)
	a := dialMesh(t, s, u, tok, "alpha", true, strings.Repeat("a", 64), "172.16.5.10/24")
	b := dialMesh(t, s, u, tok, "bravo", true, strings.Repeat("b", 64), "172.16.5.11/24")
	c := dialMesh(t, s, u, tok, "charlie", true, strings.Repeat("c", 64), "172.16.5.12/24")
	// Their inventories were written after each online event, so the passes
	// those events caused may have seen too little; an offline event fires a
	// fresh one that sees all three.
	c.ws.Close()
	waitFor(t, "charlie offline", func() bool { return !s.hub.IsOnline(c.id) })
	waitFor(t, "alpha leads and bravo follows, with no 60 s wait", func() bool {
		x, y := a.cache(), b.cache()
		return x != nil && y != nil && x.Serve && !y.Serve && y.LeaderID == a.id
	})
}

func TestCacheAssignSettingsAPI(t *testing.T) {
	s, _, b := newTestServer(t)
	var got Settings
	b.mustJSON("GET", "/api/settings", nil, &got)
	if got.MeshCache == nil || got.MeshCache.Enabled || got.MeshCache.Port != 7443 || got.MeshCache.MaxBytes != meshDefaultMax {
		t.Fatalf("the cache is off by default with the documented port and budget: %+v", got.MeshCache)
	}
	got.MeshCache = &MeshCacheSettings{Enabled: true, Port: 9100, MaxBytes: 1 << 30}
	got.AgentDefaults.Cache = &protocol.CacheConfig{LeaderAddr: "6.6.6.6:1", Token: "forged"}
	var saved Settings
	b.mustJSON("PUT", "/api/settings", got, &saved)
	if saved.MeshCache == nil || !saved.MeshCache.Enabled || saved.MeshCache.Port != 9100 || saved.MeshCache.MaxBytes != 1<<30 {
		t.Fatalf("saved: %+v", saved.MeshCache)
	}
	if saved.AgentDefaults.Cache != nil || s.agentConfig("nobody").Cache != nil {
		t.Fatal("agent_defaults must never carry a cache section")
	}
	if ms := s.meshSettings(); !ms.Enabled || ms.Port != 9100 {
		t.Fatalf("stored settings: %+v", ms)
	}

	// A save that leaves mesh_cache out keeps it.
	got.MeshCache = nil
	b.mustJSON("PUT", "/api/settings", got, &saved)
	if saved.MeshCache == nil || !saved.MeshCache.Enabled {
		t.Fatalf("an omitted mesh_cache must be kept: %+v", saved.MeshCache)
	}

	// Values nobody could mean are refused.
	for _, bad := range []MeshCacheSettings{{Enabled: true, Port: 80, MaxBytes: 1 << 30}, {Enabled: true, Port: 70000}, {Enabled: true, Port: 9100, MaxBytes: 1000}} {
		got.MeshCache = &bad
		if st, _ := b.do("PUT", "/api/settings", got); st != 400 {
			t.Fatalf("%+v: got %d, want 400", bad, st)
		}
	}
	if ms := s.meshSettings(); ms.Port != 9100 {
		t.Fatal("a refused save must change nothing")
	}
}

func TestCacheAssignPlanSkipsALeaderThatCannotServe(t *testing.T) {
	t0 := time.Now().Add(-time.Hour)
	old := member("b1", "o", t0, true, "192.168.1.11/24")
	next := member("c1", "o", t0.Add(10*time.Minute), true, "192.168.1.12/24")
	old.Failed = true
	plan := meshPlan([]meshMember{old, next}, MeshCacheSettings{Enabled: true}, testTokenFor)
	if plan["b1"].LeaderID != "c1" || plan["b1"].Serve || !plan["c1"].Serve {
		t.Fatalf("a device that reported it cannot bind must not lead: %+v", plan["b1"])
	}
	// When it is the only capable device, nobody leads rather than a dead one.
	if p := meshPlan([]meshMember{old, member("a1", "o", t0, false, "192.168.1.10/24")}, MeshCacheSettings{Enabled: true}, testTokenFor); len(p) != 0 {
		t.Fatalf("a group whose only capable device failed gets no cache: %+v", p)
	}
}

func TestCacheAssignServeFailureIsRememberedUntilItServes(t *testing.T) {
	var m meshAssigner
	if m.setServeFailed("x", nil) || len(m.failedSet()) != 0 {
		t.Fatal("an inventory without a cache role says nothing")
	}
	if !m.setServeFailed("x", &protocol.CacheStats{Role: "member", ServeFailed: true}) || !m.failedSet()["x"] {
		t.Fatal("a failure report must be recorded")
	}
	// Demoted, the device reports a plain member; that must not clear it, or
	// it would be elected again at the next pass.
	if m.setServeFailed("x", &protocol.CacheStats{Role: "member"}) || !m.failedSet()["x"] {
		t.Fatal("a member report must not clear the failure")
	}
	if !m.setServeFailed("x", &protocol.CacheStats{Role: "leader", Serving: true}) || m.failedSet()["x"] {
		t.Fatal("a device that serves again must be cleared")
	}
}
