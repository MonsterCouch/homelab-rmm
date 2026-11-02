package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/server"
	"github.com/MonsterCouch/homelab-rmm/internal/telemetry"
)

// runTelemetry is the `telemetry` subcommand: migrate the metrics series out
// of SQLite into another engine, and drop the SQLite copy once the operator
// has switched. Both refuse to run while a server holds the data directory,
// because a copy taken under a writing server is missing whatever arrived
// after it passed, and a drop under it would delete live samples.
func runTelemetry(args []string) int {
	return telemetryMain(args, os.Stdout, os.Stderr)
}

func telemetryMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("telemetry "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	data := fs.String("data", server.DefaultDataDir(), "data directory holding rmm.db")
	to := fs.String("to", "", "engine to copy the metrics to: pebble or clickhouse (migrate only)")
	dsn := fs.String("telemetry-dsn", "", "ClickHouse HTTP address, e.g. http://clickhouse:8123 (default RMM_TELEMETRY_DSN)")
	engine := fs.String("telemetry", "", "the engine the server now runs with, to confirm the switch (drop-sqlite only; default RMM_TELEMETRY)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	// The flags are the fallback and the environment wins, as for `run` and
	// `user`.
	cfg := server.Config{DataDir: *data, Telemetry: *engine, TelemetryDSN: *dsn}.FromEnv()

	switch sub {
	case "migrate":
		return telemetryMigrate(cfg, strings.ToLower(strings.TrimSpace(*to)), stdout, stderr)
	case "drop-sqlite":
		return telemetryDropSQLite(cfg, stdout, stderr)
	default:
		usage()
		return 2
	}
}

// lockedDatabase checks the database exists, takes the data directory lock and
// opens the database. The returned function releases both.
func lockedDatabase(cfg server.Config, stderr io.Writer) (*server.DB, func(), bool) {
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "rmm.db")); err != nil {
		fmt.Fprintf(stderr, "no database at %s (wrong --data?)\n", filepath.Join(cfg.DataDir, "rmm.db"))
		return nil, nil, false
	}
	unlock, err := telemetry.LockDataDir(cfg.DataDir)
	if err != nil {
		if errors.Is(err, telemetry.ErrDataDirBusy) {
			fmt.Fprintf(stderr, "%s: %v\n", cfg.DataDir, err)
		} else {
			fmt.Fprintln(stderr, err)
		}
		return nil, nil, false
	}
	db, err := server.OpenDatabase(cfg)
	if err != nil {
		unlock()
		fmt.Fprintln(stderr, err)
		return nil, nil, false
	}
	return db, func() { db.Close(); unlock() }, true
}

func telemetryMigrate(cfg server.Config, to string, stdout, stderr io.Writer) int {
	switch to {
	case "pebble", "clickhouse":
	case "":
		fmt.Fprintln(stderr, "--to is required: pebble or clickhouse")
		return 2
	default:
		fmt.Fprintf(stderr, "--to %q is not a target engine; use pebble or clickhouse\n", to)
		return 2
	}
	cfg.Telemetry = to
	if err := server.CheckTelemetryConfig(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	db, release, ok := lockedDatabase(cfg, stderr)
	if !ok {
		return 1
	}
	defer release()

	var dst telemetry.Store
	var err error
	if to == "pebble" {
		dst, err = telemetry.OpenPebble(filepath.Join(cfg.DataDir, "telemetry"))
	} else {
		dst, err = telemetry.OpenClickHouse(cfg.TelemetryDSN, cfg.TelemetryUser, server.TelemetryPassword(cfg))
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	closed := false
	closeDst := func() error {
		if closed {
			return nil
		}
		closed = true
		return dst.Close()
	}
	defer closeDst()
	// Pebble replaces a sample it already holds, so migrating twice is safe.
	// ClickHouse keeps duplicates, so it must start empty.
	if c, ok := dst.(telemetry.Counter); ok {
		n, err := c.Count()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if n > 0 {
			fmt.Fprintf(stderr, "the ClickHouse table already holds %d samples; copying again would duplicate them. Empty it (TRUNCATE TABLE rmm_metrics) and re-run if that is what you want.\n", n)
			return 1
		}
	}

	var total int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM metrics`).Scan(&total); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "Copying %d samples to %s...\n", total, to)
	next := int64(50000)
	n, err := telemetry.CopyFromSQLite(db.DB, dst, func(done int64) {
		if done >= next {
			fmt.Fprintf(stdout, "  %d of %d samples copied\n", done, total)
			for next <= done {
				next += 50000
			}
		}
	})
	if err != nil {
		fmt.Fprintf(stderr, "migration stopped after %d samples: %v\nNothing was deleted from rmm.db. ClickHouse keeps what was copied and a second run refuses a table that is not empty, so fix the cause, run TRUNCATE TABLE rmm_metrics in ClickHouse and migrate again from the start.\n", n, err)
		return 1
	}
	// Close flushes the destination's buffer, which is part of the copy.
	if err := closeDst(); err != nil {
		fmt.Fprintf(stderr, "the destination did not close cleanly: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Copied %d samples to %s.\n\n", n, to)
	fmt.Fprintf(stdout, "Start the server with: %s\n", serverFlagFor(to, cfg))
	fmt.Fprintln(stdout, "The SQLite rows were not deleted. After the server runs on the new engine, `rmm-server telemetry drop-sqlite` removes them.")
	return 0
}

// serverFlagFor renders the flags that make the server use the engine just
// migrated to. The ClickHouse password is never printed: it belongs in
// RMM_TELEMETRY_PASSWORD, and a service install keeps it in a 0600 file in the data directory.
func serverFlagFor(engine string, cfg server.Config) string {
	s := "--telemetry " + engine
	if engine == "clickhouse" {
		s += " --telemetry-dsn " + redactDSN(cfg.TelemetryDSN)
	}
	return s + "   (or RMM_TELEMETRY=" + engine + ")"
}

// redactDSN hides a password embedded in a DSN.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	return u.Redacted()
}

func telemetryDropSQLite(cfg server.Config, stdout, stderr io.Writer) int {
	if cfg.TelemetryEngine() == "sqlite" {
		fmt.Fprintln(stderr, "refusing to drop: the engine given by --telemetry or RMM_TELEMETRY is sqlite, so rmm.db's metrics are the live data. "+
			"Switch the server first, then pass the engine it now runs with (--telemetry pebble or clickhouse) to confirm.")
		return 1
	}
	if err := server.CheckTelemetryConfig(cfg); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	db, release, ok := lockedDatabase(cfg, stderr)
	if !ok {
		return 1
	}
	defer release()
	// The engine name alone proves nothing: it may be mistyped, or migrate may
	// never have run against this data directory. Open the named engine and
	// refuse unless it actually holds the history, because the drop cannot be
	// undone.
	if msg := checkTargetHoldsData(cfg); msg != "" {
		fmt.Fprintln(stderr, msg)
		return 1
	}
	n, err := telemetry.DropSQLite(db.DB)
	if err != nil {
		fmt.Fprintf(stderr, "dropped %d samples before failing: %v\n", n, err)
		return 1
	}
	fmt.Fprintf(stdout, "Deleted %d samples from rmm.db. The file does not shrink until it is vacuumed; with the server stopped, `sqlite3 rmm.db VACUUM` reclaims the space.\n", n)
	return 0
}

// checkTargetHoldsData opens the engine the operator named and returns a
// refusal message unless it holds samples; "" means it is safe to drop.
func checkTargetHoldsData(cfg server.Config) string {
	engine := cfg.TelemetryEngine()
	var st telemetry.Store
	var err error
	if engine == "pebble" {
		dir := filepath.Join(cfg.DataDir, "telemetry")
		if _, serr := os.Stat(dir); serr != nil {
			return fmt.Sprintf("refusing to drop: there is no Pebble telemetry directory at %s, so the history has not been migrated into this data directory. Run `rmm-server telemetry migrate --to pebble` first.", dir)
		}
		st, err = telemetry.OpenPebble(dir)
	} else {
		st, err = telemetry.OpenClickHouse(cfg.TelemetryDSN, cfg.TelemetryUser, server.TelemetryPassword(cfg))
	}
	if err != nil {
		return fmt.Sprintf("refusing to drop: the %s engine could not be opened to confirm it holds the history: %v", engine, err)
	}
	defer st.Close()
	p, ok := st.(telemetry.Populated)
	if !ok {
		return fmt.Sprintf("refusing to drop: the %s engine cannot confirm that it holds any samples.", engine)
	}
	has, err := p.HasSamples()
	if err != nil {
		return fmt.Sprintf("refusing to drop: the %s engine could not say whether it holds samples: %v", engine, err)
	}
	if !has {
		return fmt.Sprintf("refusing to drop: the %s engine holds no samples, so rmm.db is the only copy of the history. Run `rmm-server telemetry migrate --to %s` first.", engine, engine)
	}
	return ""
}
