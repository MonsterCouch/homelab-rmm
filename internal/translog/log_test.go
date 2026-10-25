package translog

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
	_ "modernc.org/sqlite"
)

func storages(t *testing.T) map[string]func() Storage {
	return map[string]func() Storage{
		"mem": func() Storage { return NewMemStorage() },
		"sql": func() Storage {
			// One connection: each pooled connection to :memory: would be its own database.
			db, err := sql.Open("sqlite", ":memory:")
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { db.Close() })
			if _, err := db.Exec(Schema); err != nil {
				t.Fatal(err)
			}
			return NewSQLStorage(db)
		},
	}
}

func leafData(i int) []byte { return []byte(fmt.Sprintf(`{"kind":"manifest","n":%d}`, i)) }

func newLog(t *testing.T, mk func() Storage) *Log {
	t.Helper()
	l, err := Open(mk(), filepath.Join(t.TempDir(), "log.key"))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestInclusionAndConsistencyEverySize(t *testing.T) {
	const total = 40
	for name, mk := range storages(t) {
		t.Run(name, func(t *testing.T) {
			l := newLog(t, mk)
			heads := map[int64]tlog.Tree{}
			tree, signed, err := l.Head()
			if err != nil || tree.N != 0 {
				t.Fatalf("empty head: %v %v", tree, err)
			}
			if got, err := ParseHead(l.VerifierKey(), signed); err != nil || got != tree {
				t.Fatalf("empty head does not verify: %v", err)
			}
			for i := 0; i < total; i++ {
				idx, err := l.Append("manifest", leafData(i))
				if err != nil || idx != int64(i) {
					t.Fatalf("append %d: idx %d err %v", i, idx, err)
				}
				tr, sn, err := l.Head()
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := ParseHead(l.VerifierKey(), sn)
				if err != nil || parsed != tr || tr.N != int64(i+1) {
					t.Fatalf("head %d: %v %v", i+1, parsed, err)
				}
				heads[tr.N] = tr
			}
			final := heads[total]
			for i := int64(0); i < total; i++ {
				p, err := l.ProveInclusion(i, total)
				if err != nil {
					t.Fatal(err)
				}
				dec, err := DecodeProof(EncodeProof(p))
				if err != nil {
					t.Fatal(err)
				}
				if err := CheckInclusion(final, i, leafData(int(i)), dec); err != nil {
					t.Fatalf("inclusion %d: %v", i, err)
				}
				if CheckInclusion(final, i, append(leafData(int(i)), ' '), dec) == nil {
					t.Fatalf("tampered leaf %d accepted", i)
				}
				if CheckInclusion(final, (i+1)%total, leafData(int(i)), dec) == nil {
					t.Fatalf("wrong index for leaf %d accepted", i)
				}
				// Proofs at older sizes verify against the older heads.
				for size := i + 1; size <= total; size += 7 {
					p, err := l.ProveInclusion(i, size)
					if err != nil {
						t.Fatal(err)
					}
					if err := CheckInclusion(heads[size], i, leafData(int(i)), p); err != nil {
						t.Fatalf("inclusion %d at %d: %v", i, size, err)
					}
				}
			}
			for from := int64(1); from <= total; from++ {
				for to := from; to <= total; to++ {
					p, err := l.ProveConsistency(from, to)
					if err != nil {
						t.Fatal(err)
					}
					if err := CheckConsistency(heads[from], heads[to], p); err != nil {
						t.Fatalf("consistency %d to %d: %v", from, to, err)
					}
				}
			}
			// A forked history is not consistent with the real one.
			fork := heads[10]
			fork.Hash[0] ^= 1
			p, _ := l.ProveConsistency(10, 20)
			if CheckConsistency(fork, heads[20], p) == nil {
				t.Fatal("forked head accepted")
			}
			if _, err := l.ProveInclusion(total, total); err == nil {
				t.Fatal("proof for an index past the end")
			}
			if _, err := l.ProveInclusion(0, total+1); err == nil {
				t.Fatal("proof for a size past the end")
			}
			kind, data, ts, err := l.Leaf(3)
			if err != nil || kind != "manifest" || string(data) != string(leafData(3)) || ts == 0 {
				t.Fatalf("leaf: %q %q %d %v", kind, data, ts, err)
			}
			if _, _, _, err := l.Leaf(total); err == nil {
				t.Fatal("leaf past the end")
			}
		})
	}
}

func TestHeadSignatureAndKey(t *testing.T) {
	l := newLog(t, storages(t)["mem"])
	l.Append("audit", []byte("a"))
	_, signed, _ := l.Head()

	other := newLog(t, storages(t)["mem"])
	if _, err := ParseHead(other.VerifierKey(), signed); err == nil {
		t.Fatal("head accepted under a different log key")
	}
	tampered := []byte(strings.Replace(string(signed), "\n1\n", "\n2\n", 1))
	if _, err := ParseHead(l.VerifierKey(), tampered); err == nil {
		t.Fatal("tampered head text accepted")
	}
	// Corrupt the signature line itself.
	i := strings.LastIndex(string(signed), "— ")
	if i < 0 {
		t.Fatal("no signature line in the note")
	}
	bad := append([]byte(nil), signed...)
	last := len(bad) - 3
	if bad[last] == 'A' {
		bad[last] = 'B'
	} else {
		bad[last] = 'A'
	}
	if _, err := ParseHead(l.VerifierKey(), bad); err == nil {
		t.Fatal("tampered head signature accepted")
	}
	if _, err := ParseHead("not a key", signed); err == nil {
		t.Fatal("garbage key accepted")
	}
	if _, err := DecodeProof([]string{"!!"}); err == nil {
		t.Fatal("garbage proof accepted")
	}
}

func TestOpenKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.key")
	a, err := Open(NewMemStorage(), path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(NewMemStorage(), path)
	if err != nil {
		t.Fatal(err)
	}
	if a.VerifierKey() != b.VerifierKey() || !strings.HasPrefix(a.VerifierKey(), KeyName+"+") {
		t.Fatalf("keys differ or have the wrong shape: %q %q", a.VerifierKey(), b.VerifierKey())
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("key file mode %v is readable by others", st.Mode().Perm())
		}
	}
	// A verifier line that belongs to another key is refused.
	other := newLog(t, storages(t)["mem"])
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	os.WriteFile(path, []byte(lines[0]+"\n"+other.VerifierKey()+"\n"), 0o600)
	if _, err := Open(NewMemStorage(), path); err == nil {
		t.Fatal("mismatched key pair accepted")
	}
	os.WriteFile(path, []byte(lines[0]+"\n"), 0o600)
	if _, err := Open(NewMemStorage(), path); err == nil {
		t.Fatal("one-line key file accepted")
	}
}

func TestHeadCacheInvalidatedByAppend(t *testing.T) {
	l := newLog(t, storages(t)["sql"])
	l.Append("audit", []byte("a"))
	h1, _, _ := l.Head()
	l.Append("audit", []byte("b"))
	h2, _, _ := l.Head()
	if h1.N != 1 || h2.N != 2 || h1.Hash == h2.Hash {
		t.Fatalf("stale head: %v %v", h1, h2)
	}
}
