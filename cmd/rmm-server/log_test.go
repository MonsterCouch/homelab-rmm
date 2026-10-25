package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// logFixture serves the two public log endpoints from a translog.Log with the
// same JSON shapes the real server uses. The log can be swapped to model a
// server whose history was rewritten.
type logFixture struct {
	t       *testing.T
	keyFile string
	mu      sync.Mutex
	log     *translog.Log
	ts      *httptest.Server
	state   string
}

func newLogFixture(t *testing.T) *logFixture {
	t.Helper()
	dir := t.TempDir()
	f := &logFixture{t: t, keyFile: filepath.Join(dir, "log.key"), state: filepath.Join(dir, "state.json")}
	f.log = f.open(translog.NewMemStorage())
	mux := http.NewServeMux()
	mux.HandleFunc("/api/log/head", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		tree, note, err := f.log.Head()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"size": tree.N, "hash": tree.Hash.String(), "key": f.log.VerifierKey(),
			"note": base64.StdEncoding.EncodeToString(note),
		})
	})
	mux.HandleFunc("/api/log/consistency", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
		to, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
		proof, err := f.log.ProveConsistency(from, to)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"from": from, "to": to, "proof": translog.EncodeProof(proof)})
	})
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

// open uses one key file for every log, so a "rewritten" log is signed by the
// same key, which is what a compromised server would do.
func (f *logFixture) open(st translog.Storage) *translog.Log {
	l, err := translog.Open(st, f.keyFile)
	if err != nil {
		f.t.Fatal(err)
	}
	return l
}

func (f *logFixture) grow(prefix string, n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 0; i < n; i++ {
		if _, err := f.log.Append("audit", []byte(prefix+strconv.Itoa(i))); err != nil {
			f.t.Fatal(err)
		}
	}
}

func (f *logFixture) replace(prefix string, n int) {
	f.mu.Lock()
	f.log = f.open(translog.NewMemStorage())
	f.mu.Unlock()
	f.grow(prefix, n)
}

func (f *logFixture) verify() (string, error) {
	return verifyLog(f.ts.Client(), f.ts.URL, f.log.VerifierKey(), f.state)
}

func TestLogVerifyFirstRunPinsTheHead(t *testing.T) {
	f := newLogFixture(t)
	f.grow("a", 5)
	line, err := f.verify()
	if err != nil {
		t.Fatal(err)
	}
	tree, _, _ := f.log.Head()
	if want := "log ok: size 5, head " + tree.Hash.String(); line != want {
		t.Fatalf("got %q, want %q", line, want)
	}
	if _, err := f.verify(); err != nil {
		t.Fatalf("an unchanged log must verify again: %v", err)
	}
}

func TestLogVerifyAcceptsAGrownLog(t *testing.T) {
	f := newLogFixture(t)
	f.grow("a", 5)
	if _, err := f.verify(); err != nil {
		t.Fatal(err)
	}
	f.grow("b", 7)
	line, err := f.verify()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "log ok: size 12, head ") {
		t.Fatalf("got %q", line)
	}
}

func TestLogVerifyRefusesARewrittenLog(t *testing.T) {
	for name, n := range map[string]int{"same size": 5, "larger": 9} {
		t.Run(name, func(t *testing.T) {
			f := newLogFixture(t)
			f.grow("a", 5)
			if _, err := f.verify(); err != nil {
				t.Fatal(err)
			}
			f.replace("evil", n)
			_, err := f.verify()
			if err == nil || !strings.Contains(err.Error(), "rewritten") {
				t.Fatalf("a rewritten log must be refused as such, got %v", err)
			}
		})
	}
}

func TestLogVerifyRefusesAShrunkLog(t *testing.T) {
	f := newLogFixture(t)
	f.grow("a", 5)
	if _, err := f.verify(); err != nil {
		t.Fatal(err)
	}
	f.replace("a", 3)
	_, err := f.verify()
	if err == nil || !strings.Contains(err.Error(), "shrank") {
		t.Fatalf("got %v", err)
	}
}

func TestLogVerifyRefusesAWrongKey(t *testing.T) {
	f := newLogFixture(t)
	f.grow("a", 3)
	other, err := translog.Open(translog.NewMemStorage(), filepath.Join(t.TempDir(), "other.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyLog(f.ts.Client(), f.ts.URL, other.VerifierKey(), f.state)
	if err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("got %v", err)
	}
	if _, serr := verifyLog(f.ts.Client(), f.ts.URL, "garbage", f.state); serr == nil {
		t.Fatal("a garbage key must be refused")
	}
}

func TestLogVerifyUnreachableServer(t *testing.T) {
	f := newLogFixture(t)
	f.ts.Close()
	_, err := f.verify()
	if err == nil || !strings.Contains(err.Error(), "could not be reached") {
		t.Fatalf("got %v", err)
	}
}

func TestLogCommandUsage(t *testing.T) {
	if code := runLog(nil); code != 2 {
		t.Fatalf("no subcommand: exit %d", code)
	}
	if code := runLog([]string{"verify", "--server", "http://x"}); code != 2 {
		t.Fatalf("missing key: exit %d", code)
	}
}
