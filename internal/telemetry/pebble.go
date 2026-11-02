package telemetry

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"

	"github.com/cockroachdb/pebble/v2"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// quietLogger drops Pebble's informational log lines. By default it writes
// "Found 0 WALs" and every flush and compaction to the standard logger, which
// on a server with its own structured log is noise on every start. Errors are
// kept and go to slog, because Pebble reports a failed background flush or
// compaction (a full disk, for one) only through the logger.
type quietLogger struct{}

func (quietLogger) Infof(string, ...interface{}) {}
func (quietLogger) Errorf(format string, args ...interface{}) {
	slog.Error("the Pebble telemetry store reported an error", "message", fmt.Sprintf(format, args...))
}
func (quietLogger) Fatalf(format string, args ...interface{}) {
	panic(fmt.Sprintf(format, args...))
}

// pebbleStore keeps two key spaces in one Pebble database:
//
//	'm' + agent id + 0x00 + ts (8 bytes big-endian)            one sample
//	'r' + agent id + 0x00 + bucket start (8 bytes big-endian)  a 5-minute rollup
//
// The 0x00 terminator keeps one device's keys contiguous and out of another
// device's range even when one id is a prefix of the other. Rollups are kept
// on ingest so a 30-day chart reads about 8,600 small values per device rather
// than 86,000 samples that each carry their disks JSON.
type pebbleStore struct {
	db *pebble.DB
	// mu serializes writers: a rollup is read, changed and written back, and
	// two samples landing in the same bucket would otherwise lose one update.
	mu sync.Mutex
	// life guards closed: every operation holds it shared for its duration and
	// Close takes it exclusively, so a call that arrives after (or races with)
	// shutdown gets an error. Pebble panics when used after Close.
	life   sync.RWMutex
	closed bool
}

var errPebbleClosed = errors.New("the Pebble telemetry store is closed")

// use runs fn unless the store has been closed.
func (p *pebbleStore) use(fn func() error) error {
	p.life.RLock()
	defer p.life.RUnlock()
	if p.closed {
		return errPebbleClosed
	}
	return fn()
}

// OpenPebble opens or creates the database in dir.
func OpenPebble(dir string) (Store, error) {
	db, err := pebble.Open(dir, &pebble.Options{Logger: quietLogger{}})
	if err != nil {
		return nil, fmt.Errorf("opening the Pebble telemetry store in %s: %w", dir, err)
	}
	return &pebbleStore{db: db}, nil
}

func (p *pebbleStore) Engine() string { return "pebble" }

// HasSamples reports whether any sample is stored, by looking for one key
// rather than counting them all.
func (p *pebbleStore) HasSamples() (has bool, err error) {
	err = p.use(func() error {
		it, ierr := p.db.NewIter(&pebble.IterOptions{LowerBound: []byte{'m'}, UpperBound: []byte{'n'}})
		if ierr != nil {
			return ierr
		}
		defer it.Close()
		has = it.First()
		return it.Error()
	})
	return has, err
}

func (p *pebbleStore) SizeBytes() (n int64, err error) {
	err = p.use(func() error {
		n = int64(p.db.Metrics().DiskSpaceUsage())
		return nil
	})
	return n, err
}

func (p *pebbleStore) Close() error {
	p.life.Lock()
	defer p.life.Unlock()
	if p.closed {
		return nil // a shutdown path may reach here twice
	}
	p.closed = true
	return p.db.Close()
}

func prefixedKey(space byte, agent string, ts int64) []byte {
	if ts < 0 {
		ts = 0
	}
	k := make([]byte, 0, 1+len(agent)+1+8)
	k = append(k, space)
	k = append(k, agent...)
	k = append(k, 0)
	return binary.BigEndian.AppendUint64(k, uint64(ts))
}

// agentRange is the half-open key range of one device in one key space.
func agentRange(space byte, agent string) (lo, hi []byte) {
	lo = append(append([]byte{space}, agent...), 0)
	hi = append(append([]byte{space}, agent...), 1)
	return lo, hi
}

func keyTS(k []byte) int64 { return int64(binary.BigEndian.Uint64(k[len(k)-8:])) }

// scaled turns a fractional reading into the thousandths a varint can hold.
func scaled(f float64) uint64 {
	if f <= 0 || math.IsNaN(f) {
		return 0
	}
	return uint64(math.Round(f * 1000))
}

func nonNeg(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// sample is the decoded form of one stored value.
type sample struct {
	cpu, memUsed, memTotal, rx, tx, uptime, load1, procs uint64
	disks                                                []byte
}

func newSample(m protocol.Metrics) sample {
	return sample{
		cpu: scaled(m.CPUPct), memUsed: m.MemUsed, memTotal: m.MemTotal, rx: m.NetRxBps, tx: m.NetTxBps,
		uptime: m.Uptime, load1: scaled(m.Load1), procs: nonNeg(m.ProcCount), disks: []byte(jsonText(m.Disks)),
	}
}

func (s sample) encode() []byte {
	b := make([]byte, 0, 8*binary.MaxVarintLen64+len(s.disks))
	for _, v := range []uint64{s.cpu, s.memUsed, s.memTotal, s.rx, s.tx, s.uptime, s.load1, s.procs} {
		b = binary.AppendUvarint(b, v)
	}
	return append(b, s.disks...)
}

var errCorrupt = errors.New("a stored telemetry value is truncated or corrupt")

// readUvarints decodes n varints and returns them with the remaining bytes.
func readUvarints(b []byte, n int) ([]uint64, []byte, error) {
	out := make([]uint64, n)
	for i := range out {
		v, w := binary.Uvarint(b)
		if w <= 0 {
			return nil, nil, errCorrupt
		}
		out[i], b = v, b[w:]
	}
	return out, b, nil
}

func decodeSample(b []byte) (sample, error) {
	v, rest, err := readUvarints(b, 8)
	if err != nil {
		return sample{}, err
	}
	return sample{cpu: v[0], memUsed: v[1], memTotal: v[2], rx: v[3], tx: v[4], uptime: v[5], load1: v[6], procs: v[7], disks: rest}, nil
}

// rollup is the five-minute aggregate: how many samples, the sums of the
// numeric fields, and the newest sample's timestamp, uptime and disks.
type rollup struct {
	count                                        uint64
	cpu, memUsed, memTotal, rx, tx, load1, procs uint64
	lastTS                                       int64
	uptime                                       uint64
	disks                                        []byte
}

func (r *rollup) encode() []byte {
	b := make([]byte, 0, 10*binary.MaxVarintLen64+len(r.disks))
	for _, v := range []uint64{r.count, r.cpu, r.memUsed, r.memTotal, r.rx, r.tx, r.load1, r.procs, uint64(r.lastTS), r.uptime} {
		b = binary.AppendUvarint(b, v)
	}
	return append(b, r.disks...)
}

func decodeRollup(b []byte) (*rollup, error) {
	v, rest, err := readUvarints(b, 10)
	if err != nil {
		return nil, err
	}
	return &rollup{count: v[0], cpu: v[1], memUsed: v[2], memTotal: v[3], rx: v[4], tx: v[5], load1: v[6], procs: v[7],
		lastTS: int64(v[8]), uptime: v[9], disks: rest}, nil
}

func (r *rollup) add(ts int64, s sample) {
	r.count++
	r.cpu += s.cpu
	r.memUsed += s.memUsed
	r.memTotal += s.memTotal
	r.rx += s.rx
	r.tx += s.tx
	r.load1 += s.load1
	r.procs += s.procs
	// Disks and uptime follow the newest sample, as the SQLite query's bare
	// columns do; an equal timestamp is a replacement and wins.
	if r.count == 1 || ts >= r.lastTS {
		r.lastTS, r.uptime, r.disks = ts, s.uptime, s.disks
	}
}

// sub takes a replaced sample back out. The rollup keeps its disks and uptime:
// a replacement has the same timestamp and is added straight after.
func (r *rollup) sub(s sample) {
	r.count--
	r.cpu -= s.cpu
	r.memUsed -= s.memUsed
	r.memTotal -= s.memTotal
	r.rx -= s.rx
	r.tx -= s.tx
	r.load1 -= s.load1
	r.procs -= s.procs
}

func (p *pebbleStore) WriteMetrics(id string, m protocol.Metrics) error {
	return p.WriteBatch([]Sample{{AgentID: id, Metrics: m}})
}

// WriteBatch commits all samples and the rollups they touch in one batch with
// a synced WAL write, so a sample the server acknowledged survives a crash.
func (p *pebbleStore) WriteBatch(samples []Sample) error {
	return p.use(func() error { return p.writeBatch(samples) })
}

func (p *pebbleStore) writeBatch(samples []Sample) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.db.NewBatch()
	defer b.Close()
	pendingSamples := map[string][]byte{}
	pendingRollups := map[string]*rollup{}
	get := func(key []byte) ([]byte, error) {
		v, closer, err := p.db.Get(key)
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		defer closer.Close()
		return append([]byte(nil), v...), nil
	}
	for _, sm := range samples {
		ts := sm.Metrics.TS
		if ts < 0 {
			ts = 0
		}
		sk := prefixedKey('m', sm.AgentID, ts)
		rk := prefixedKey('r', sm.AgentID, ts-ts%rollupWidth)
		r, ok := pendingRollups[string(rk)]
		if !ok {
			raw, err := get(rk)
			if err != nil {
				return err
			}
			r = &rollup{}
			if raw != nil {
				if r, err = decodeRollup(raw); err != nil {
					return err
				}
			}
			pendingRollups[string(rk)] = r
		}
		old, seen := pendingSamples[string(sk)]
		if !seen {
			var err error
			if old, err = get(sk); err != nil {
				return err
			}
		}
		if old != nil {
			prev, err := decodeSample(old)
			if err != nil {
				return err
			}
			r.sub(prev)
		}
		s := newSample(sm.Metrics)
		val := s.encode()
		r.add(ts, s)
		pendingSamples[string(sk)] = val
		if err := b.Set(sk, val, nil); err != nil {
			return err
		}
	}
	for k, r := range pendingRollups {
		var err error
		if r.count == 0 {
			err = b.Delete([]byte(k), nil)
		} else {
			err = b.Set([]byte(k), r.encode(), nil)
		}
		if err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}

// bucketAgg accumulates samples or rollups that fall in one output bucket.
type bucketAgg struct {
	ts                                           int64
	n                                            float64
	cpu, memUsed, memTotal, rx, tx, load1, procs float64
	lastTS                                       int64
	uptime                                       uint64
	disks                                        []byte
	any                                          bool
}

func (a *bucketAgg) add(weight uint64, cpu, memUsed, memTotal, rx, tx, load1, procs uint64, lastTS int64, uptime uint64, disks []byte) {
	a.n += float64(weight)
	a.cpu += float64(cpu)
	a.memUsed += float64(memUsed)
	a.memTotal += float64(memTotal)
	a.rx += float64(rx)
	a.tx += float64(tx)
	a.load1 += float64(load1)
	a.procs += float64(procs)
	if !a.any || lastTS >= a.lastTS {
		a.lastTS, a.uptime, a.disks = lastTS, uptime, append(a.disks[:0], disks...)
	}
	a.any = true
}

func (a *bucketAgg) row() MetricRow {
	r := MetricRow{
		TS: a.ts, CPU: a.cpu / 1000 / a.n, Load1: a.load1 / 1000 / a.n,
		MemUsed: uint64(a.memUsed / a.n), MemTotal: uint64(a.memTotal / a.n),
		NetRx: uint64(a.rx / a.n), NetTx: uint64(a.tx / a.n), Procs: int(a.procs / a.n), Uptime: a.uptime,
	}
	json.Unmarshal(a.disks, &r.Disks)
	return r
}

func (p *pebbleStore) MetricHistory(id string, from, to int64, maxPoints int) (rows []MetricRow, err error) {
	err = p.use(func() error {
		rows, err = p.metricHistory(id, from, to, maxPoints)
		return err
	})
	return rows, err
}

func (p *pebbleStore) metricHistory(id string, from, to int64, maxPoints int) ([]MetricRow, error) {
	from, to, bucket := bucketing(from, to, maxPoints)
	out := []MetricRow{}
	var cur *bucketAgg
	flush := func() {
		if cur != nil {
			out = append(out, cur.row())
		}
	}
	// scan folds the keys of one key space in [lo, hi) into the buckets. The
	// pieces below are scanned in time order, so a bucket is never reopened.
	scan := func(space byte, lo, hi []byte) error {
		it, err := p.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
		if err != nil {
			return err
		}
		defer it.Close()
		for ok := it.First(); ok; ok = it.Next() {
			ts := keyTS(it.Key())
			b := (ts / bucket) * bucket
			if cur == nil || cur.ts != b {
				flush()
				cur = &bucketAgg{ts: b}
			}
			if space == 'm' {
				s, err := decodeSample(it.Value())
				if err != nil {
					return err
				}
				cur.add(1, s.cpu, s.memUsed, s.memTotal, s.rx, s.tx, s.load1, s.procs, ts, s.uptime, s.disks)
			} else {
				r, err := decodeRollup(it.Value())
				if err != nil {
					return err
				}
				cur.add(r.count, r.cpu, r.memUsed, r.memTotal, r.rx, r.tx, r.load1, r.procs, r.lastTS, r.uptime, r.disks)
			}
		}
		return it.Error()
	}
	raw := func(a, b int64) error { // samples with a <= ts < b
		if a >= b {
			return nil
		}
		return scan('m', prefixedKey('m', id, a), prefixedKey('m', id, b))
	}
	// A rollup stands in for raw samples only when it lies wholly inside one
	// output bucket and wholly inside [from, to]. That needs buckets that are a
	// multiple of the rollup width (the grid is aligned to multiples of the
	// bucket, like rollups are to multiples of their width) and it leaves the
	// partial rollups at both ends to be read as raw samples, so the answer is
	// the same as the SQLite engine's rather than a coarser one.
	if to-from > rollupAfter && bucket >= rollupWidth && bucket%rollupWidth == 0 {
		rlo := (from + rollupWidth - 1) / rollupWidth * rollupWidth
		rhi := (to + 1) / rollupWidth * rollupWidth
		if rlo < rhi {
			if err := raw(from, rlo); err != nil {
				return nil, err
			}
			if err := scan('r', prefixedKey('r', id, rlo), prefixedKey('r', id, rhi)); err != nil {
				return nil, err
			}
			if err := raw(rhi, to+1); err != nil {
				return nil, err
			}
			flush()
			return out, nil
		}
	}
	if err := raw(from, to+1); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}

// agents lists the device ids that have keys in one key space, jumping from
// one device's range to the next rather than reading every key.
func (p *pebbleStore) agents(space byte) ([]string, error) {
	it, err := p.db.NewIter(&pebble.IterOptions{LowerBound: []byte{space}, UpperBound: []byte{space + 1}})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	var ids []string
	for ok := it.First(); ok; {
		k := it.Key()
		end := len(k) - 9 // the 0x00 terminator and the 8-byte timestamp
		if end < 1 {
			ok = it.Next()
			continue
		}
		id := string(k[1:end])
		ids = append(ids, id)
		_, hi := agentRange(space, id)
		ok = it.SeekGE(hi)
	}
	return ids, it.Error()
}

// Purge is one DeleteRange per device and key space; a range tombstone makes
// it independent of how many samples fall inside it.
func (p *pebbleStore) Purge(before int64) error {
	return p.use(func() error { return p.purge(before) })
}

func (p *pebbleStore) purge(before int64) error {
	if before <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.db.NewBatch()
	defer b.Close()
	for _, space := range []byte{'m', 'r'} {
		ids, err := p.agents(space)
		if err != nil {
			return err
		}
		end := before
		if space == 'r' {
			// A rollup that straddles the cutoff still holds samples that are
			// kept, so only buckets that end at or before it go.
			end -= before % rollupWidth
		}
		for _, id := range ids {
			if end <= 0 {
				continue
			}
			if err := b.DeleteRange(prefixedKey(space, id, 0), prefixedKey(space, id, end), nil); err != nil {
				return err
			}
		}
	}
	return b.Commit(pebble.Sync)
}

func (p *pebbleStore) DeleteAgent(id string) error {
	return p.use(func() error { return p.deleteAgent(id) })
}

func (p *pebbleStore) deleteAgent(id string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.db.NewBatch()
	defer b.Close()
	for _, space := range []byte{'m', 'r'} {
		lo, hi := agentRange(space, id)
		if err := b.DeleteRange(lo, hi, nil); err != nil {
			return err
		}
	}
	return b.Commit(pebble.Sync)
}
