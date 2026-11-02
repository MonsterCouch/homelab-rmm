package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// addSourceAgent connects a fake agent that answers agent.update with the given
// reply body. A nil reply is an agent that predates AgentUpdateResult: it
// answers with no body at all.
func (f *signFixture) addSourceAgent(name string, reply *protocol.AgentUpdateResult) string {
	f.t.Helper()
	ra := f.enroll("", name, "linux")
	go func() {
		for {
			var env protocol.Envelope
			if err := ra.ws.ReadJSON(&env); err != nil {
				return
			}
			if env.T != protocol.ReqAgentUpdate {
				continue
			}
			out := protocol.Envelope{T: protocol.TypeReply, ID: env.ID}
			if reply != nil {
				out.D = protocol.Must(reply)
			}
			ra.ws.WriteJSON(out)
		}
	}()
	waitFor(f.t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })
	return ra.id
}

type updateEventRow struct {
	Kind    string         `json:"kind"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields"`
}

// updateEvents reads a device's "update" events where the console reads them.
func updateEvents(t *testing.T, f *signFixture, id string, want int) []updateEventRow {
	t.Helper()
	var out []updateEventRow
	waitFor(t, "update events of "+id, func() bool {
		var all []updateEventRow
		f.admin.mustJSON("GET", "/api/agents/"+id+"/events", nil, &all)
		out = nil
		for _, e := range all {
			if e.Kind == "update" {
				out = append(out, e)
			}
		}
		return len(out) >= want
	})
	return out
}

const cacheSource = "cache leader-1 over h3"

// A device's reply to agent.update, with the place its bytes came from, is
// recorded on its event list and in the audit entry and handed back to the
// console, which reads the event list and the reply of the update call.
func TestUpdateSingleDeviceRecordsSource(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	id := f.addSourceAgent("box", &protocol.AgentUpdateResult{Source: cacheSource, Bytes: 1234, ResumedChunks: 2, Version: "v1"})

	st, raw := f.admin.do("POST", "/api/agents/"+id+"/update", nil)
	var res struct {
		OK     bool                       `json:"ok"`
		Result protocol.AgentUpdateResult `json:"result"`
	}
	json.Unmarshal(raw, &res)
	if st != 200 || !res.OK || res.Result.Source != cacheSource || res.Result.Bytes != 1234 || res.Result.ResumedChunks != 2 {
		t.Fatalf("update reply = %d %s", st, raw)
	}

	ev := updateEvents(t, f, id, 1)[0]
	if ev.Fields["source"] != cacheSource || ev.Fields["source_kind"] != "cache" || ev.Fields["bytes"] != float64(1234) || !strings.Contains(ev.Message, cacheSource) {
		t.Fatalf("event = %+v, want the source recorded", ev)
	}

	var details string
	waitFor(t, "audit entry", func() bool {
		return f.s.db.QueryRow(`SELECT details FROM audit WHERE action = 'agent.self_update' AND target = ?`, id).Scan(&details) == nil
	})
	var d map[string]any
	json.Unmarshal([]byte(details), &d)
	if d["source"] != cacheSource {
		t.Fatalf("audit details = %s, want the source", details)
	}
}

// An agent that predates the reply answers with no body: the update still
// counts as done, with an empty source, and the event list still says it.
func TestUpdateOldAgentEmptyReplyStillDone(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	id := f.addSourceAgent("old", nil)

	st, raw := f.admin.do("POST", "/api/agents/"+id+"/update", nil)
	var res struct {
		OK     bool                       `json:"ok"`
		Result protocol.AgentUpdateResult `json:"result"`
	}
	json.Unmarshal(raw, &res)
	if st != 200 || !res.OK || res.Result.Source != "" {
		t.Fatalf("update reply = %d %s, want done with no source", st, raw)
	}
	ev := updateEvents(t, f, id, 1)[0]
	if ev.Fields["source"] != "" || ev.Fields["source_kind"] != "unreported" {
		t.Fatalf("event = %+v, want an empty source", ev)
	}

	// The same through a batch: accepted, listed, counted as unreported.
	b, _, raw := postBatch(t, f, id)
	if b.Accepted != 1 || b.DispatchedTo != 1 {
		t.Fatalf("batch = %s, want the old agent accepted", raw)
	}
}

// A batch reports each device's own source and counts devices by source kind.
func TestFleetUpdateBatchReportsSources(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	cacheID := f.addSourceAgent("cached", &protocol.AgentUpdateResult{Source: cacheSource, Bytes: 10})
	originID := f.addSourceAgent("wan", &protocol.AgentUpdateResult{Source: "origin (the cache failed: leader unreachable)", Bytes: 10})

	st, raw := f.admin.do("POST", "/api/agents/update-batch", map[string]any{"agent_ids": []string{cacheID, originID}})
	if st != 200 {
		t.Fatalf("update-batch = %d %s", st, raw)
	}
	var res struct {
		Accepted int `json:"accepted"`
		Results  []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Source string `json:"source"`
			Bytes  int64  `json:"bytes"`
		} `json:"results"`
		BySource map[string]int `json:"by_source"`
	}
	json.Unmarshal(raw, &res)
	got := map[string]string{}
	for _, r := range res.Results {
		got[r.ID] = r.Source
	}
	if res.Accepted != 2 || len(res.Results) != 2 || got[cacheID] != cacheSource || got[originID] != "origin (the cache failed: leader unreachable)" {
		t.Fatalf("batch = %s, want each device's own source", raw)
	}
	if res.BySource["cache"] != 1 || res.BySource["origin_cache_failed"] != 1 || res.BySource["origin"] != 0 || res.BySource["unreported"] != 0 {
		t.Fatalf("by_source = %v", res.BySource)
	}
	if ev := updateEvents(t, f, originID, 1)[0]; ev.Fields["source_kind"] != "origin_cache_failed" {
		t.Fatalf("event = %+v", ev)
	}
	rows := fleetAuditRows(t, f.s)
	if len(rows) == 0 {
		t.Fatal("no fleet.update audit row")
	}
}

func TestUpdateSourceKind(t *testing.T) {
	for in, want := range map[string]string{
		"":                               "unreported",
		"origin":                         "origin",
		"cache abc over https":           "cache",
		"origin (the cache failed: why)": "origin_cache_failed",
	} {
		if got := updateSourceKind(in); got != want {
			t.Errorf("updateSourceKind(%q) = %q, want %q", in, got, want)
		}
	}
}

// A device that answers after the handler stopped waiting still gets its
// source recorded: the handler says it is installing, and the event list
// gains the update when the late reply arrives.
func TestUpdateLateReplyIsStillRecorded(t *testing.T) {
	withoutDevDist(t)
	window := fleetUpdateReplyWindow
	fleetUpdateReplyWindow = 100 * time.Millisecond
	t.Cleanup(func() { fleetUpdateReplyWindow = window })
	f := newSignFixture(t, "", 1, 10)
	stageAgentBinary(t, f.s, "linux", "amd64")
	ra := f.enroll("", "slow", "linux")
	go func() {
		for {
			var env protocol.Envelope
			if err := ra.ws.ReadJSON(&env); err != nil {
				return
			}
			if env.T != protocol.ReqAgentUpdate {
				continue
			}
			time.Sleep(500 * time.Millisecond)
			ra.ws.WriteJSON(protocol.Envelope{T: protocol.TypeReply, ID: env.ID,
				D: protocol.Must(&protocol.AgentUpdateResult{Source: cacheSource, Bytes: 99, Version: "v1"})})
		}
	}()
	waitFor(t, "agent online", func() bool { return f.s.hub.IsOnline(ra.id) })

	st, raw := f.admin.do("POST", "/api/agents/"+ra.id+"/update", nil)
	var res struct {
		Installing bool `json:"installing"`
	}
	json.Unmarshal(raw, &res)
	if st != 200 || !res.Installing {
		t.Fatalf("update reply = %d %s, want installing", st, raw)
	}
	ev := updateEvents(t, f, ra.id, 1)[0]
	if ev.Fields["source"] != cacheSource || ev.Fields["bytes"] != float64(99) {
		t.Fatalf("late event = %+v, want the source recorded", ev)
	}
}

// An answer with no source must not be worded as a staged download: the device
// may have skipped the update because it already runs the build.
func TestUpdateEventMessageWithoutSourceDoesNotClaimStaging(t *testing.T) {
	got := updateEventMessage("box", protocol.AgentUpdateResult{Version: "v1"})
	if strings.Contains(got, "staged") || !strings.Contains(got, "accepted by box (v1)") || !strings.Contains(got, "no download source reported") {
		t.Fatalf("message without a source = %q", got)
	}
	got = updateEventMessage("box", protocol.AgentUpdateResult{Version: "v1", Source: cacheSource})
	if got != "Agent update staged on box (v1); downloaded from "+cacheSource {
		t.Fatalf("message with a source = %q", got)
	}
}

// A device that reported the pushed build's digest is not sent the update
// unless the operator forces it, and the answer to a forced one is on the
// device's event list and on the live event stream.
func TestUpdateSingleDeviceSkipForceAndBroadcast(t *testing.T) {
	withoutDevDist(t)
	f := newSignFixture(t, "", 1, 10)
	_, sum := stageAgentBinary(t, f.s, "linux", "amd64")
	id := f.addSourceAgent("fresh", &protocol.AgentUpdateResult{Source: "origin", Bytes: 99, Version: "v2"})
	f.s.db.Exec(`UPDATE agents SET binary_sha256 = ?, binary_sha256_at = ? WHERE id = ?`, sum, time.Now().Unix(), id)

	st, raw := f.admin.do("POST", "/api/agents/"+id+"/update", nil)
	var skip struct {
		OK       bool                        `json:"ok"`
		UpToDate bool                        `json:"up_to_date"`
		Result   *protocol.AgentUpdateResult `json:"result"`
	}
	json.Unmarshal(raw, &skip)
	if st != 200 || !skip.OK || !skip.UpToDate || skip.Result != nil {
		t.Fatalf("unforced reply = %d %s, want up_to_date and nothing sent", st, raw)
	}
	time.Sleep(100 * time.Millisecond)
	var n int
	f.s.db.QueryRow(`SELECT COUNT(*) FROM agent_events WHERE agent_id = ? AND kind = 'update'`, id).Scan(&n)
	if n != 0 {
		t.Fatalf("%d update events after a skipped update, want 0", n)
	}

	ch, unsub := f.s.hub.subscribe()
	defer unsub()
	st, raw = f.admin.do("POST", "/api/agents/"+id+"/update?force=1", nil)
	var forced struct {
		OK       bool                       `json:"ok"`
		UpToDate bool                       `json:"up_to_date"`
		Result   protocol.AgentUpdateResult `json:"result"`
	}
	json.Unmarshal(raw, &forced)
	if st != 200 || !forced.OK || forced.UpToDate || forced.Result.Source != "origin" || forced.Result.Bytes != 99 {
		t.Fatalf("forced reply = %d %s, want the update sent", st, raw)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("no update event was broadcast")
		case ev := <-ch:
			if ev.Kind != "event" || ev.AgentID != id {
				continue
			}
			data, _ := ev.Data.(map[string]any)
			if data["kind"] != "update" || data["message"] == "" || data["ts"] == nil || data["fields"] == nil {
				t.Fatalf("event data = %+v, want an update event", data)
			}
			return
		}
	}
}
