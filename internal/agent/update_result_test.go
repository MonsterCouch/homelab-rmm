package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/cache"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func (r *stagedUpdateRig) result(t *testing.T) (protocol.AgentUpdateResult, error) {
	t.Helper()
	res, err := selfUpdateResult(context.Background(), &Config{ServerURL: r.origin.URL},
		protocol.AgentUpdate{URL: r.origin.URL + "/agent", SHA256: r.sum, Version: "v9.9.9"}, r.client)
	if err == nil {
		select {
		case <-r.exited:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for the worker exit")
		}
	}
	return res, err
}

// The agent.update reply carries the same source string selfUpdateSource
// reports, with the size and the version, and encodes under the names the
// server decodes.
func TestUpdateResultCarriesSource(t *testing.T) {
	r := newStagedUpdateRig(t)
	res, err := r.result(t)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "origin" || res.Version != "v9.9.9" || res.Bytes != int64(len(r.payload)) {
		t.Fatalf("result = %+v, want origin, v9.9.9 and %d bytes", res, len(r.payload))
	}
	b, _ := json.Marshal(res)
	if !strings.Contains(string(b), `"source":"origin"`) || !strings.Contains(string(b), `"bytes":`) {
		t.Fatalf("encoded reply = %s", b)
	}
}

func TestUpdateResultNamesCacheLeader(t *testing.T) {
	r := newStagedUpdateRig(t)
	l := startTestLeader(t, r.origin.URL)
	updateCache.Store(&cache.Client{Leader: l, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond})
	res, err := r.result(t)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Source, "cache lead-7 over https") || res.Bytes != int64(len(r.payload)) {
		t.Fatalf("result = %+v, want the cache leader as the source", res)
	}
}
