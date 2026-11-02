// Package telemetry stores the per-device metrics series. Everything
// transactional stays in the server's SQLite file; the one table that grows by
// every device every few seconds can live in SQLite (the default), in an
// embedded Pebble LSM, or in a ClickHouse server reached over its HTTP
// interface. See docs/plans/2026-10-24-phase4a-telemetry-store.md.
package telemetry

import (
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// MetricRow is one sample, or one averaged bucket of samples, as returned to
// the UI.
type MetricRow struct {
	TS       int64                `json:"ts"`
	CPU      float64              `json:"cpu"`
	MemUsed  uint64               `json:"mem_used"`
	MemTotal uint64               `json:"mem_total"`
	Disks    []protocol.DiskUsage `json:"disks"`
	NetRx    uint64               `json:"net_rx"`
	NetTx    uint64               `json:"net_tx"`
	Uptime   uint64               `json:"uptime"`
	Load1    float64              `json:"load1"`
	Procs    int                  `json:"procs"`
}

// Store is the narrow surface the server needs from a metrics engine.
type Store interface {
	// WriteMetrics records one sample at m.TS. Writing the same agent and
	// timestamp again replaces the earlier sample.
	WriteMetrics(agentID string, m protocol.Metrics) error
	// MetricHistory returns the samples of one device between from and to
	// (both inclusive), averaged into at most maxPoints buckets. Within a
	// bucket the numeric fields are averaged and Disks and Uptime come from the
	// bucket's last sample.
	MetricHistory(agentID string, from, to int64, maxPoints int) ([]MetricRow, error)
	// Purge removes every sample older than the given Unix time.
	Purge(before int64) error
	// DeleteAgent removes every sample of one device.
	DeleteAgent(agentID string) error
	Close() error
}

// Sample is one device's sample in a bulk write.
type Sample struct {
	AgentID string
	Metrics protocol.Metrics
}

// BatchWriter is implemented by every store here. It writes many samples with
// one durable commit, which is what the migration needs: a synced commit per
// sample would take hours for a month of history.
type BatchWriter interface {
	WriteBatch(samples []Sample) error
}

// Inspector reports what the stats endpoint shows.
type Inspector interface {
	// Engine is "sqlite", "pebble" or "clickhouse".
	Engine() string
	// SizeBytes is an approximate on-disk size of the series. An error means
	// the engine cannot say, not that the store is unhealthy.
	SizeBytes() (int64, error)
}

// MaxPoints caps the buckets one chart may ask for. Without it ?points=100000000
// made the bucket one second wide and streamed every stored sample for the
// device through the engine.
const MaxPoints = 2000

// bucketing turns a history request into the bounds and the bucket width in
// seconds that every engine uses, so the three return the same grid.
func bucketing(from, to int64, maxPoints int) (lo, hi, bucket int64) {
	if maxPoints <= 0 {
		maxPoints = 600
	}
	if maxPoints > MaxPoints {
		maxPoints = MaxPoints
	}
	if from < 0 {
		from = 0
	}
	span := to - from
	if span <= 0 {
		span = 1
	}
	bucket = span / int64(maxPoints)
	if bucket < 1 {
		bucket = 1
	}
	return from, to, bucket
}

// rollupAfter is the span in seconds above which Pebble answers from its
// five-minute rollups instead of raw samples.
const rollupAfter = 6 * 3600

// rollupWidth is the width in seconds of one Pebble rollup bucket.
const rollupWidth = 300
