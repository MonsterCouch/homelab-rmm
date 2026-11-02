package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// clickhouseTable is the one table the store owns.
const clickhouseTable = "rmm_metrics"

const (
	// clickhouseFlushRows and clickhouseFlushEvery are how a write is batched:
	// ClickHouse wants few large inserts, not one per sample.
	clickhouseFlushRows  = 500
	clickhouseFlushEvery = time.Second
	// clickhouseMaxBuffered bounds what is kept while the server is
	// unreachable. Past it the oldest samples are dropped, because a metrics
	// outage must not grow the console's memory without limit.
	clickhouseMaxBuffered = 50000
)

// clickhouseStore talks to ClickHouse over its HTTP interface with net/http
// and no driver. Values reach the server as typed query parameters
// ({name:Type} with param_name in the URL), never spliced into the SQL.
type clickhouseStore struct {
	base   string // scheme://host:port with the query string kept for settings such as database
	extra  url.Values
	user   string
	pass   string
	client *http.Client

	mu      sync.Mutex // guards buf
	buf     [][]byte
	flushMu sync.Mutex // one insert at a time, so rows keep their order

	// kick wakes the flusher when the buffer is full, so the ingest path never
	// waits on a ClickHouse round trip.
	kick chan struct{}

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

// OpenClickHouse connects to the HTTP interface at dsn (for example
// http://clickhouse:8123, optionally with ?database=rmm and user:password@),
// creates the table when it is missing and starts the batching flusher.
// user and password override credentials embedded in the DSN.
func OpenClickHouse(dsn, user, password string) (Store, error) {
	u, err := url.Parse(strings.TrimSpace(dsn))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		// The DSN is deliberately left out: a mistyped one often still carries
		// user:password@, and url.Parse errors embed their input too.
		return nil, errors.New("the ClickHouse DSN must look like http://host:8123 or https://host:8443 (the value is not shown because it may contain a password)")
	}
	if u.User != nil {
		if user == "" {
			user = u.User.Username()
		}
		if password == "" {
			password, _ = u.User.Password()
		}
	}
	c := &clickhouseStore{
		base:   u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"),
		extra:  u.Query(),
		user:   user,
		pass:   password,
		client: &http.Client{Timeout: 30 * time.Second},
		kick:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	if _, err := c.do(`CREATE TABLE IF NOT EXISTS `+clickhouseTable+` (
	agent_id String,
	ts Int64,
	cpu Float64,
	mem_used UInt64,
	mem_total UInt64,
	disks String,
	net_rx UInt64,
	net_tx UInt64,
	uptime UInt64,
	load1 Float64,
	procs Int64
) ENGINE = MergeTree ORDER BY (agent_id, ts)`, nil, nil); err != nil {
		return nil, fmt.Errorf("preparing the ClickHouse telemetry table: %w", err)
	}
	go c.flusher()
	return c, nil
}

func (c *clickhouseStore) Engine() string { return "clickhouse" }

// do sends one statement. With a body the statement travels in the URL and the
// body is the data to insert; without one the statement is the body.
func (c *clickhouseStore) do(sql string, params map[string]string, data []byte) ([]byte, error) {
	q := url.Values{}
	for k, v := range c.extra {
		q[k] = v
	}
	for k, v := range params {
		if name, ok := strings.CutPrefix(k, "setting_"); ok {
			q.Set(name, v) // a server setting rather than a query parameter
			continue
		}
		q.Set("param_"+k, v)
	}
	var body io.Reader
	if data != nil {
		q.Set("query", sql)
		body = bytes.NewReader(data)
	} else {
		body = strings.NewReader(sql)
	}
	// 64-bit integers as plain numbers rather than quoted strings.
	q.Set("output_format_json_quote_64bit_integers", "0")
	req, err := http.NewRequest(http.MethodPost, c.base+"/?"+q.Encode(), body)
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.SetBasicAuth(c.user, c.pass)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching ClickHouse: %w", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("ClickHouse answered %d: %s", resp.StatusCode, msg)
	}
	return out, nil
}

type clickhouseRow struct {
	AgentID  string  `json:"agent_id"`
	TS       int64   `json:"ts"`
	CPU      float64 `json:"cpu"`
	MemUsed  uint64  `json:"mem_used"`
	MemTotal uint64  `json:"mem_total"`
	Disks    string  `json:"disks"`
	NetRx    uint64  `json:"net_rx"`
	NetTx    uint64  `json:"net_tx"`
	Uptime   uint64  `json:"uptime"`
	Load1    float64 `json:"load1"`
	Procs    int64   `json:"procs"`
}

func encodeRow(id string, m protocol.Metrics) []byte {
	b, _ := json.Marshal(clickhouseRow{AgentID: id, TS: m.TS, CPU: m.CPUPct, MemUsed: m.MemUsed, MemTotal: m.MemTotal,
		Disks: jsonText(m.Disks), NetRx: m.NetRxBps, NetTx: m.NetTxBps, Uptime: m.Uptime, Load1: m.Load1, Procs: int64(m.ProcCount)})
	return b
}

func (c *clickhouseStore) WriteMetrics(id string, m protocol.Metrics) error {
	c.mu.Lock()
	c.buf = append(c.buf, encodeRow(id, m))
	full := len(c.buf) >= clickhouseFlushRows
	c.mu.Unlock()
	if full {
		// Never flush inline: the caller is an agent's read loop, and a
		// blackholed ClickHouse would hold it for the 30 s HTTP timeout. The
		// buffer is already capped by clickhouseMaxBuffered, so deferring the
		// insert to the flusher loses nothing that an outage would not.
		select {
		case c.kick <- struct{}{}:
		default:
		}
	}
	return nil
}

// WriteBatch inserts straight away: its caller is the migration, which wants
// to know about a failure before it moves on.
func (c *clickhouseStore) WriteBatch(samples []Sample) error {
	c.mu.Lock()
	for _, s := range samples {
		c.buf = append(c.buf, encodeRow(s.AgentID, s.Metrics))
	}
	c.mu.Unlock()
	return c.flush()
}

// flush sends what is buffered. On failure the rows go back in front of
// anything that arrived meanwhile, so the next flush retries them in order.
func (c *clickhouseStore) flush() error {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()
	c.mu.Lock()
	rows := c.buf
	c.buf = nil
	c.mu.Unlock()
	if len(rows) == 0 {
		return nil
	}
	body := append(bytes.Join(rows, []byte("\n")), '\n')
	if _, err := c.do("INSERT INTO "+clickhouseTable+" FORMAT JSONEachRow", nil, body); err != nil {
		c.mu.Lock()
		c.buf = append(rows, c.buf...)
		if over := len(c.buf) - clickhouseMaxBuffered; over > 0 {
			c.buf = c.buf[over:]
		}
		c.mu.Unlock()
		return err
	}
	return nil
}

func (c *clickhouseStore) flusher() {
	defer close(c.done)
	t := time.NewTicker(clickhouseFlushEvery)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-c.kick:
			if err := c.flush(); err != nil {
				slog.Warn("telemetry: ClickHouse insert failed, will retry", "err", err)
			}
		case <-t.C:
			if err := c.flush(); err != nil {
				slog.Warn("telemetry: ClickHouse insert failed, will retry", "err", err)
			}
		}
	}
}

// historyRow decodes with json.Number so the same code reads numbers whether
// the server quotes 64-bit integers or not.
type historyRow struct {
	TS         json.Number `json:"bts"`
	CPU        json.Number `json:"a_cpu"`
	MemUsed    json.Number `json:"a_mem_used"`
	MemTotal   json.Number `json:"a_mem_total"`
	NetRx      json.Number `json:"a_net_rx"`
	NetTx      json.Number `json:"a_net_tx"`
	Load1      json.Number `json:"a_load1"`
	Procs      json.Number `json:"a_procs"`
	LastDisks  string      `json:"last_disks"`
	LastUptime json.Number `json:"last_uptime"`
}

func num(n json.Number) float64 {
	f, _ := n.Float64()
	return f
}

func (c *clickhouseStore) MetricHistory(id string, from, to int64, maxPoints int) ([]MetricRow, error) {
	// A sample still waiting for its batch is as much history as a stored one.
	if err := c.flush(); err != nil {
		return nil, err
	}
	from, to, bucket := bucketing(from, to, maxPoints)
	out, err := c.do(`SELECT intDiv(ts, {bucket:Int64}) * {bucket:Int64} AS bts, avg(cpu) AS a_cpu, avg(mem_used) AS a_mem_used, avg(mem_total) AS a_mem_total, avg(net_rx) AS a_net_rx, avg(net_tx) AS a_net_tx, avg(load1) AS a_load1, avg(procs) AS a_procs, argMax(disks, ts) AS last_disks, argMax(uptime, ts) AS last_uptime FROM `+clickhouseTable+` WHERE agent_id = {agent:String} AND ts BETWEEN {from:Int64} AND {to:Int64} GROUP BY bts ORDER BY bts FORMAT JSONEachRow`,
		map[string]string{
			"bucket": strconv.FormatInt(bucket, 10), "agent": id,
			"from": strconv.FormatInt(from, 10), "to": strconv.FormatInt(to, 10),
		}, nil)
	if err != nil {
		return nil, err
	}
	rows := []MetricRow{}
	dec := json.NewDecoder(bytes.NewReader(out))
	for dec.More() {
		var h historyRow
		if err := dec.Decode(&h); err != nil {
			return nil, fmt.Errorf("reading the ClickHouse history answer: %w", err)
		}
		r := MetricRow{
			TS: int64(num(h.TS)), CPU: num(h.CPU), Load1: num(h.Load1),
			MemUsed: uint64(num(h.MemUsed)), MemTotal: uint64(num(h.MemTotal)),
			NetRx: uint64(num(h.NetRx)), NetTx: uint64(num(h.NetTx)),
			Procs: int(num(h.Procs)), Uptime: uint64(num(h.LastUptime)),
		}
		json.Unmarshal([]byte(h.LastDisks), &r.Disks)
		rows = append(rows, r)
	}
	return rows, nil
}

// Purge and DeleteAgent are mutations, which ClickHouse runs in the
// background; mutations_sync makes the call return when they are done so the
// next read cannot see rows the operator just removed.
func (c *clickhouseStore) Purge(before int64) error {
	if err := c.flush(); err != nil {
		return err
	}
	_, err := c.do(`ALTER TABLE `+clickhouseTable+` DELETE WHERE ts < {before:Int64}`,
		map[string]string{"before": strconv.FormatInt(before, 10), "setting_mutations_sync": "1"}, nil)
	return err
}

func (c *clickhouseStore) DeleteAgent(id string) error {
	if err := c.flush(); err != nil {
		return err
	}
	_, err := c.do(`ALTER TABLE `+clickhouseTable+` DELETE WHERE agent_id = {agent:String}`,
		map[string]string{"agent": id, "setting_mutations_sync": "1"}, nil)
	return err
}

func (c *clickhouseStore) scalar(sql string) (int64, error) {
	out, err := c.do(sql+" FORMAT TabSeparated", nil, nil)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ClickHouse returned %q where a number was expected", strings.TrimSpace(string(out)))
	}
	return n, nil
}

// Count is how many samples the table holds; the migration refuses to append
// to a table that already has data, because MergeTree would keep duplicates.
func (c *clickhouseStore) Count() (int64, error) {
	return c.scalar(`SELECT count() FROM ` + clickhouseTable)
}

// HasSamples reports whether the table holds any sample.
func (c *clickhouseStore) HasSamples() (bool, error) {
	n, err := c.Count()
	return n > 0, err
}

func (c *clickhouseStore) SizeBytes() (int64, error) {
	return c.scalar(`SELECT sum(bytes_on_disk) FROM system.parts WHERE database = currentDatabase() AND table = '` + clickhouseTable + `' AND active`)
}

func (c *clickhouseStore) Close() error {
	c.once.Do(func() { close(c.stop) })
	<-c.done
	err := c.flush()
	c.client.CloseIdleConnections()
	return err
}

// Populated is implemented by a store that can say whether it holds any
// sample at all; drop-sqlite uses it to be sure history exists elsewhere.
type Populated interface {
	HasSamples() (bool, error)
}

// Counter is implemented by a store that can say how many samples it holds.
type Counter interface {
	Count() (int64, error)
}
