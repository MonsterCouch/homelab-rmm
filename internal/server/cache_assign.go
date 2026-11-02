package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Subnet cache assignment (docs/plans/2026-10-24-phase4b-mesh-cache.md). The
// server already knows every online device's LAN addresses and which agents
// could lead, so it assigns roles itself instead of letting devices elect a
// leader over multicast.

const (
	meshDefaultPort = 7443
	meshDefaultMax  = int64(2) << 30
	meshMinMax      = int64(64) << 20
	// meshPassEvery is the safety-net cadence of the assignment pass; online
	// and offline events trigger one sooner.
	meshPassEvery = 60 * time.Second
)

// meshKickDelay coalesces a burst of online/offline events (a whole office
// reconnecting after a server restart) into one pass. A variable for tests.
var meshKickDelay = time.Second

// MeshCacheSettings is the operator's switch for the subnet cache, stored in
// the settings table as "mesh_cache". Settings in this product are global, not
// per organization, so the switch is global too; the groups themselves are
// still formed inside each organization, never across them.
type MeshCacheSettings struct {
	Enabled  bool  `json:"enabled"`
	Port     int   `json:"port"`
	MaxBytes int64 `json:"max_bytes"`
}

func normalizeMesh(m MeshCacheSettings) MeshCacheSettings {
	if m.Port <= 0 {
		m.Port = meshDefaultPort
	}
	if m.MaxBytes <= 0 {
		m.MaxBytes = meshDefaultMax
	}
	return m
}

// validateMesh rejects values an operator could not have meant: privileged
// ports, and a budget too small to hold one agent binary.
func validateMesh(m MeshCacheSettings) string {
	if m.Port < 1024 || m.Port > 65535 {
		return "mesh_cache.port must be between 1024 and 65535"
	}
	if m.MaxBytes < meshMinMax {
		return "mesh_cache.max_bytes must be at least 64 MiB"
	}
	return ""
}

func (s *Server) meshSettings() MeshCacheSettings {
	var m MeshCacheSettings
	s.db.SettingJSON("mesh_cache", &m)
	return normalizeMesh(m)
}

// meshSecret is the HMAC key tokens derive from. It is generated on first use
// and kept in settings; losing it only costs members one fallback to the
// origin until the next push.
func (s *Server) meshSecret() string {
	s.mesh.secretMu.Lock()
	defer s.mesh.secretMu.Unlock()
	if v := s.db.Setting("mesh_cache_secret", ""); v != "" {
		return v
	}
	v := randomHex(32)
	if err := s.db.SetSetting("mesh_cache_secret", v); err != nil {
		slog.Warn("cannot save the subnet cache secret", "err", err)
	}
	return v
}

// meshToken is the bearer token members of one organization present to their
// leader on one UTC day: HMAC-SHA256 of the organization and the date under
// the settings secret. It expires by itself at midnight, and the leader keeps
// the previous day's for the push that follows.
func meshToken(secret, org string, day time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("mesh-cache/v1|" + org + "|" + day.UTC().Format("2006-01-02")))
	return hex.EncodeToString(mac.Sum(nil))
}

// meshMember is what the planner needs to know about one online device.
type meshMember struct {
	ID          string
	Org         string
	Capable     bool
	Fingerprint string
	Since       time.Time
	// Failed means the device was assigned to lead and reported that it could
	// not; the planner passes over it for a while.
	Failed bool
	// IPs maps each subnet the device sits on (masked prefix, wider than /22
	// narrowed to /24) to its address there.
	IPs map[netip.Prefix]netip.Addr
}

// The name lists below pick out adapters that exist on one host only (container bridges,
// hypervisor host-only switches, tunnels). Their prefixes repeat across
// unrelated machines - every Docker host has a 172.17.0.0/16 - and would join
// strangers into one group.
var (
	virtualPrefix   = []string{"docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "cni", "flannel", "cali", "kube", "zt", "tailscale"}
	virtualContains = []string{"default switch", "wsl", "host-only", "vmware network adapter"}
)

func isVirtualIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "lo" {
		return true
	}
	// vEthernet is also how Hyper-V names the host's own external switch, a
	// real LAN adapter, so it is exempt from the "veth" prefix of Linux
	// container pairs; its Default Switch and WSL siblings are caught below.
	if !strings.HasPrefix(n, "vethernet") {
		for _, p := range virtualPrefix {
			if strings.HasPrefix(n, p) {
				return true
			}
		}
	}
	for _, p := range virtualContains {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// meshSubnets lists the subnets an inventory says the device is on.
func meshSubnets(network []protocol.NetIface) map[netip.Prefix]netip.Addr {
	out := map[netip.Prefix]netip.Addr{}
	for _, ni := range network {
		if !ni.Up || isVirtualIface(ni.Name) {
			continue
		}
		for _, raw := range ni.IPs {
			p, err := netip.ParsePrefix(raw)
			if err != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			bits := p.Bits()
			if bits > 30 {
				continue // a point-to-point link has no neighbours to share with
			}
			if bits < 22 {
				bits = 24
			}
			key := netip.PrefixFrom(ip, bits).Masked()
			if _, dup := out[key]; !dup {
				out[key] = ip
			}
		}
	}
	return out
}

type meshGroup struct {
	Org     string
	Prefix  netip.Prefix
	Members []int // indexes into the planner's member slice
}

// meshGroups forms the subnet groups. A device on several subnets (wired and
// wireless, say) joins only the largest group it fits, so it has one leader;
// a group left with fewer than two devices has nobody to share with and is
// dropped.
func meshGroups(members []meshMember) []meshGroup {
	cand := map[string]*meshGroup{}
	for i, m := range members {
		for p := range m.IPs {
			k := m.Org + "|" + p.String()
			g := cand[k]
			if g == nil {
				g = &meshGroup{Org: m.Org, Prefix: p}
				cand[k] = g
			}
			g.Members = append(g.Members, i)
		}
	}
	all := make([]*meshGroup, 0, len(cand))
	for _, g := range cand {
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool {
		if len(all[i].Members) != len(all[j].Members) {
			return len(all[i].Members) > len(all[j].Members)
		}
		if all[i].Org != all[j].Org {
			return all[i].Org < all[j].Org
		}
		return all[i].Prefix.String() < all[j].Prefix.String()
	})
	taken := map[int]bool{}
	var out []meshGroup
	for _, g := range all {
		var free []int
		for _, i := range g.Members {
			if !taken[i] {
				free = append(free, i)
			}
		}
		if len(free) < 2 {
			continue
		}
		for _, i := range free {
			taken[i] = true
		}
		out = append(out, meshGroup{Org: g.Org, Prefix: g.Prefix, Members: free})
	}
	return out
}

// meshPlan computes every device's cache assignment. The leader of a group is
// its longest-online device that reported it can lead; a group with no such
// device has no cache, and its members get none.
func meshPlan(members []meshMember, set MeshCacheSettings, tokenFor func(org string) string) map[string]*protocol.CacheConfig {
	set = normalizeMesh(set)
	plan := map[string]*protocol.CacheConfig{}
	for _, g := range meshGroups(members) {
		lead := -1
		for _, i := range g.Members {
			m := members[i]
			if !m.Capable || m.Failed || m.Fingerprint == "" {
				continue
			}
			if lead < 0 || m.Since.Before(members[lead].Since) || (m.Since.Equal(members[lead].Since) && m.ID < members[lead].ID) {
				lead = i
			}
		}
		if lead < 0 {
			continue
		}
		l := members[lead]
		token := tokenFor(g.Org)
		addr := net.JoinHostPort(l.IPs[g.Prefix].String(), strconv.Itoa(set.Port))
		for _, i := range g.Members {
			c := &protocol.CacheConfig{LeaderAddr: addr, LeaderID: l.ID, Fingerprint: l.Fingerprint, Token: token}
			if i == lead {
				c.Serve, c.Port, c.MaxBytes = true, set.Port, set.MaxBytes
			}
			plan[members[i].ID] = c
		}
	}
	return plan
}

// meshAssigner holds the current plan and what each device was last given.
type meshAssigner struct {
	secretMu sync.Mutex

	mu      sync.Mutex
	desired map[string]*protocol.CacheConfig
	sent    map[string]string // JSON of the cache section each device last received
	// failed holds the devices that were assigned to lead and said they could
	// not, with when. It outlives a demotion on purpose: the demoted device
	// reports no failure as a member, and forgetting it would re-elect it at the
	// next pass.
	failed map[string]time.Time

	kickOnce sync.Once
	kickCh   chan struct{}
}

func (m *meshAssigner) kicks() chan struct{} {
	m.kickOnce.Do(func() { m.kickCh = make(chan struct{}, 1) })
	return m.kickCh
}

// kick asks the loop for a pass soon. Never blocks.
func (m *meshAssigner) kick() {
	select {
	case m.kicks() <- struct{}{}:
	default:
	}
}

func cacheJSON(c *protocol.CacheConfig) string {
	if c == nil {
		return "null"
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// configFor is the cache section of a device's config, and records that the
// device is being given it. It is called from the config builder, so what is
// recorded as sent is exactly what goes out, welcome or push alike.
func (m *meshAssigner) configFor(id string) *protocol.CacheConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.desired[id]
	if m.sent == nil {
		m.sent = map[string]string{}
	}
	m.sent[id] = cacheJSON(c)
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// meshFailedTTL is how long a leader that could not bind is passed over before
// it gets another try; a rebooted or reconfigured device is retried sooner, on
// reconnect.
const meshFailedTTL = 6 * time.Hour

// setServeFailed records what a device's inventory said about its leader role
// and reports whether the planner's input changed. Serving clears a failure;
// ServeFailed sets one; a member that is neither leaves the record alone.
func (m *meshAssigner) setServeFailed(id string, cs *protocol.CacheStats) bool {
	if cs == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, was := m.failed[id]
	switch {
	case cs.ServeFailed:
		if m.failed == nil {
			m.failed = map[string]time.Time{}
		}
		m.failed[id] = time.Now()
		return !was
	case cs.Serving && was:
		delete(m.failed, id)
		return true
	}
	return false
}

// failedSet is the devices currently passed over, dropping expired records.
func (m *meshAssigner) failedSet() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for id, at := range m.failed {
		if time.Since(at) > meshFailedTTL {
			delete(m.failed, id)
			continue
		}
		out[id] = true
	}
	return out
}

// meshMembers gathers the online devices with their subnets, organization and
// cache identity. The hub is the authority on who is online and since when;
// the database supplies the organization and the interfaces from the last
// inventory.
func (s *Server) meshMembers() []meshMember {
	type live struct {
		hello protocol.Hello
		since time.Time
	}
	liveByID := map[string]live{}
	failed := s.mesh.failedSet()
	s.hub.mu.RLock()
	for id, ac := range s.hub.agents {
		liveByID[id] = live{ac.hello, ac.connected}
	}
	s.hub.mu.RUnlock()
	if len(liveByID) == 0 {
		return nil
	}
	rows, err := s.db.Query(`SELECT id, COALESCE(org_id, ''),
		CASE WHEN json_valid(inventory) THEN COALESCE(json_extract(inventory, '$.network'), '[]') ELSE '[]' END
		FROM agents WHERE online = 1`)
	if err != nil {
		slog.Warn("subnet cache: cannot read device interfaces", "err", err)
		return nil
	}
	defer rows.Close()
	var out []meshMember
	for rows.Next() {
		var id, org, network string
		if err := rows.Scan(&id, &org, &network); err != nil {
			continue
		}
		lv, ok := liveByID[id]
		if !ok {
			continue
		}
		var ifaces []protocol.NetIface
		_ = json.Unmarshal([]byte(network), &ifaces)
		ips := meshSubnets(ifaces)
		if len(ips) == 0 {
			continue
		}
		out = append(out, meshMember{ID: id, Org: org, Capable: lv.hello.CacheCapable, Fingerprint: lv.hello.CacheFingerprint, Since: lv.since, Failed: failed[id], IPs: ips})
	}
	return out
}

// meshRecompute rebuilds the plan from the live state and stores it, without
// pushing anything. Settings changes call it before pushing every device's
// config themselves.
func (s *Server) meshRecompute() {
	var plan map[string]*protocol.CacheConfig
	if set := s.meshSettings(); set.Enabled {
		secret := s.meshSecret()
		today := time.Now()
		plan = meshPlan(s.meshMembers(), set, func(org string) string { return meshToken(secret, org, today) })
	}
	s.mesh.mu.Lock()
	s.mesh.desired = plan
	s.mesh.mu.Unlock()
}

// meshPass recomputes the plan and pushes the new cache section to every
// online device whose assignment changed: a new leader, a member whose leader
// went away, the next day's token, the feature switched off.
func (s *Server) meshPass() {
	s.meshRecompute()
	online := s.hub.OnlineIDs()
	s.mesh.mu.Lock()
	var push []string
	known := map[string]bool{}
	for _, id := range online {
		known[id] = true
		prev, ok := s.mesh.sent[id]
		if !ok {
			prev = "null"
		}
		if prev != cacheJSON(s.mesh.desired[id]) {
			push = append(push, id)
		}
	}
	for id := range s.mesh.sent {
		if !known[id] {
			delete(s.mesh.failed, id) // a reconnect is the chance to try again
		}
	}
	s.mesh.mu.Unlock()
	for _, id := range push {
		s.pushAgentConfig(id)
	}
	if len(push) > 0 {
		slog.Info("subnet cache assignments changed", "devices", len(push))
	}
}

// meshLoop runs the assignment pass every minute and shortly after any
// online/offline event, until ctx ends.
func (s *Server) meshLoop(ctx context.Context) {
	t := time.NewTicker(meshPassEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.mesh.kicks():
			select {
			case <-ctx.Done():
				return
			case <-time.After(meshKickDelay):
			}
		}
		s.meshPass()
	}
}
