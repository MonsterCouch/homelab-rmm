package telemetry

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

type sqliteStore struct{ db *sql.DB }

// OpenSQLite wraps the server's own database handle. Closing the store does
// not close the handle, which the server owns.
func OpenSQLite(db *sql.DB) Store { return &sqliteStore{db: db} }

func (s *sqliteStore) Engine() string { return "sqlite" }

func jsonText(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

const sqliteInsert = `INSERT OR REPLACE INTO metrics(agent_id, ts, cpu, mem_used, mem_total, disks, net_rx, net_tx, uptime, load1, procs)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`

func (s *sqliteStore) WriteMetrics(id string, m protocol.Metrics) error {
	_, err := s.db.Exec(sqliteInsert, id, m.TS, m.CPUPct, m.MemUsed, m.MemTotal, jsonText(m.Disks), m.NetRxBps, m.NetTxBps, m.Uptime, m.Load1, m.ProcCount)
	return err
}

func (s *sqliteStore) WriteBatch(samples []Sample) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, sm := range samples {
		m := sm.Metrics
		if _, err := tx.Exec(sqliteInsert, sm.AgentID, m.TS, m.CPUPct, m.MemUsed, m.MemTotal, jsonText(m.Disks), m.NetRxBps, m.NetTxBps, m.Uptime, m.Load1, m.ProcCount); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *sqliteStore) MetricHistory(id string, from, to int64, maxPoints int) ([]MetricRow, error) {
	from, to, bucket := bucketing(from, to, maxPoints)
	// Bucket to at most maxPoints by averaging within buckets; SQLite does the
	// grouping so a 30-day range does not ship a million rows to the browser.
	//
	// disks and uptime are bare columns beside exactly one max() aggregate,
	// which SQLite defines as coming from the row that produced that maximum:
	// the LAST sample in the bucket. MAX(disks) was a lexicographic maximum
	// over JSON text, so the disk series was an arbitrary sample that
	// corresponded to no real point in time.
	rows, err := s.db.Query(`SELECT (ts / ?) * ?, AVG(cpu), AVG(mem_used), AVG(mem_total), AVG(net_rx), AVG(net_tx), AVG(load1), AVG(procs), MAX(ts), disks, uptime
		FROM metrics WHERE agent_id = ? AND ts BETWEEN ? AND ? GROUP BY 1 ORDER BY 1`, bucket, bucket, id, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MetricRow{}
	for rows.Next() {
		var r MetricRow
		var disks string
		var mem, memTotal, rx, tx, procs float64
		var lastTS int64
		if err := rows.Scan(&r.TS, &r.CPU, &mem, &memTotal, &rx, &tx, &r.Load1, &procs, &lastTS, &disks, &r.Uptime); err != nil {
			return nil, err
		}
		r.MemUsed, r.MemTotal, r.NetRx, r.NetTx, r.Procs = uint64(mem), uint64(memTotal), uint64(rx), uint64(tx), int(procs)
		json.Unmarshal([]byte(disks), &r.Disks)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Purge deletes in bounded time slices so a single statement never holds the
// one SQLite connection for long: an unqualified DELETE over months of metrics
// blocked every HTTP request, agent write and alert evaluation behind it.
func (s *sqliteStore) Purge(before int64) error {
	const window = int64(6 * 3600)
	for i := 0; i < 2000; i++ { // bounded so a clock jump cannot spin here
		var oldest sql.NullInt64
		if err := s.db.QueryRow(`SELECT MIN(ts) FROM metrics`).Scan(&oldest); err != nil {
			return err
		}
		if !oldest.Valid || oldest.Int64 >= before {
			return nil
		}
		step := oldest.Int64 + window
		if step > before {
			step = before
		}
		if _, err := s.db.Exec(`DELETE FROM metrics WHERE ts < ?`, step); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) DeleteAgent(id string) error {
	_, err := s.db.Exec(`DELETE FROM metrics WHERE agent_id = ?`, id)
	return err
}

// SizeBytes uses the dbstat virtual table when the build has it.
func (s *sqliteStore) SizeBytes() (int64, error) {
	var n sql.NullInt64
	if err := s.db.QueryRow(`SELECT SUM(pgsize) FROM dbstat WHERE name IN ('metrics', 'idx_metrics_ts')`).Scan(&n); err != nil {
		return 0, err
	}
	return n.Int64, nil
}

func (s *sqliteStore) Close() error { return nil }

// CopyFromSQLite copies every row of the metrics table into dst in timestamp
// order, in batches, and returns how many it copied. progress is called after
// each batch with the running total. Paging is by (ts, agent_id) so it neither
// holds a read transaction open for the whole copy nor skips rows that share a
// timestamp.
func CopyFromSQLite(src *sql.DB, dst Store, progress func(done int64)) (int64, error) {
	const batch = 5000
	bw, _ := dst.(BatchWriter)
	var lastTS int64 = -1 << 62
	lastAgent := ""
	var total int64
	for {
		rows, err := src.Query(`SELECT agent_id, ts, cpu, mem_used, mem_total, disks, net_rx, net_tx, uptime, load1, procs
			FROM metrics WHERE (ts, agent_id) > (?, ?) ORDER BY ts, agent_id LIMIT ?`, lastTS, lastAgent, batch)
		if err != nil {
			return total, err
		}
		var chunk []Sample
		for rows.Next() {
			var sm Sample
			var disks string
			m := &sm.Metrics
			if err := rows.Scan(&sm.AgentID, &m.TS, &m.CPUPct, &m.MemUsed, &m.MemTotal, &disks, &m.NetRxBps, &m.NetTxBps, &m.Uptime, &m.Load1, &m.ProcCount); err != nil {
				rows.Close()
				return total, err
			}
			json.Unmarshal([]byte(disks), &m.Disks)
			chunk = append(chunk, sm)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return total, err
		}
		if len(chunk) == 0 {
			return total, nil
		}
		if bw != nil {
			err = bw.WriteBatch(chunk)
		} else {
			for _, sm := range chunk {
				if err = dst.WriteMetrics(sm.AgentID, sm.Metrics); err != nil {
					break
				}
			}
		}
		if err != nil {
			return total, fmt.Errorf("writing a batch after %d samples: %w", total, err)
		}
		total += int64(len(chunk))
		last := chunk[len(chunk)-1]
		lastTS, lastAgent = last.Metrics.TS, last.AgentID
		if progress != nil {
			progress(total)
		}
	}
}

// DropSQLite deletes every row of the metrics table in bounded slices and
// returns how many it removed. It does not VACUUM: that needs free disk space
// equal to the database and holds the connection, so the operator chooses when.
func DropSQLite(db *sql.DB) (int64, error) {
	var total int64
	for {
		res, err := db.Exec(`DELETE FROM metrics WHERE (agent_id, ts) IN (SELECT agent_id, ts FROM metrics LIMIT 20000)`)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n == 0 {
			return total, nil
		}
	}
}
