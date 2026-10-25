package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// Phase 3C, device side: the last transparency log head this device accepted
// (log_head.json) and the hash-chained record of what it executed
// (executed.log). Both live next to trust.json and are only ever written by
// the agent.

func logHeadPath() string  { return filepath.Join(ConfigDir(), "log_head.json") }
func executedPath() string { return filepath.Join(ConfigDir(), "executed.log") }

// logHead is the stored head: size and root hash for the comparisons, and the
// signed note so an operator can see exactly what the server presented.
type logHead struct {
	Size int64  `json:"size"`
	Hash string `json:"hash"`
	Note string `json:"note"`
}

func (h logHead) tree() (tlog.Tree, error) {
	hash, err := tlog.ParseHash(h.Hash)
	if err != nil {
		return tlog.Tree{}, err
	}
	return tlog.Tree{N: h.Size, Hash: hash}, nil
}

// logState is the 3C half of trustState. logMu serialises the
// check-then-persist of the head so two concurrent requests cannot both
// advance from the same stored size.
type logState struct {
	logMu    sync.Mutex
	head     *logHead
	headErr  error // log_head.json exists but cannot be used
	headPath string

	execMu    sync.Mutex
	execPath  string
	execHead  string // base64 sha256 of the last executed.log line, "" for none
	execReady bool
}

// loadLogHead reads log_head.json. A missing file is a device that has never
// accepted a head; an unreadable or malformed one is remembered as damaged,
// for the same reason trust.json is: silently starting over would let anyone
// who can corrupt one file make the device accept a rewound log.
func (t *trustState) loadLogHead() {
	t.headPath = logHeadPath()
	raw, err := os.ReadFile(t.headPath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err == nil {
		var h logHead
		if err = json.Unmarshal(raw, &h); err == nil {
			if _, err = h.tree(); err == nil && h.Size < 1 {
				err = errors.New("the stored size is not positive")
			}
			if err == nil {
				t.head = &h
				return
			}
		}
	}
	t.headErr = fmt.Errorf("log_head.json is damaged (%v); delete it on the device once you have confirmed the server's log is the one you trust", err)
	slog.Error("LOG HEAD UNUSABLE: refusing protected requests that need a log proof until log_head.json is deleted on this device",
		"path", t.headPath, "err", err)
}

// logSize is the size of the head this device holds, 0 for none. It is what
// hello advertises and what replies carry in Envelope.Log.
func (t *trustState) logSize() int64 {
	t.logMu.Lock()
	defer t.logMu.Unlock()
	if t.head == nil {
		return 0
	}
	return t.head.Size
}

func (t *trustState) persistLogHead(h logHead) error {
	if err := EnsureConfigDir(); err != nil {
		return err
	}
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tmp := t.headPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, t.headPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// checkLogProof applies the device rules of the 3C design to a request that
// already passed Verifier.Check. auth may be nil (a request without a
// manifest), in which case only the damaged-head rule applies. The error is
// the reason, phrased for an operator; nil means the request may go on
// (including "no proof needed"). The int64 is the leaf index to record in
// executed.log, -1 when no proof was checked.
func (t *trustState) checkLogProof(b *actionauth.Bundle, auth *protocol.ActionAuth) (int64, error) {
	if b == nil {
		return -1, nil
	}
	if b.LogKey == "" {
		if auth != nil && b.Policy.RequireLogProof {
			return -1, errors.New("the trust bundle requires log proofs but pins no log key")
		}
		return -1, nil
	}
	if t.headErr != nil {
		return -1, t.headErr
	}
	if auth == nil {
		return -1, nil
	}
	l := auth.L
	if l == nil {
		if b.Policy.RequireLogProof {
			return -1, errors.New("the request carried no proof that the manifest is in the transparency log")
		}
		return -1, nil
	}
	signed, err := base64.StdEncoding.DecodeString(l.Head)
	if err != nil {
		return -1, errors.New("the log head is not valid base64")
	}
	tree, err := translog.ParseHead(b.LogKey, signed)
	if err != nil {
		return -1, err
	}
	leaf, err := actionauth.ManifestLeaf(auth)
	if err != nil {
		return -1, fmt.Errorf("the log leaf for this manifest cannot be rebuilt: %w", err)
	}
	proof, err := translog.DecodeProof(l.Proof)
	if err != nil {
		return -1, fmt.Errorf("the inclusion proof is malformed: %w", err)
	}
	if err := translog.CheckInclusion(tree, l.Index, leaf, proof); err != nil {
		return -1, err
	}

	t.logMu.Lock()
	defer t.logMu.Unlock()
	if t.head == nil {
		slog.Info("accepted the first transparency log head", "size", tree.N, "hash", tree.Hash.String())
	} else {
		old, err := t.head.tree()
		if err != nil {
			return -1, fmt.Errorf("log_head.json is damaged: %w", err)
		}
		switch {
		case tree.N < old.N:
			return -1, errors.New("the server presented a log head older than the last one this device accepted")
		case tree.N == old.N:
			if tree.Hash != old.Hash {
				return -1, fmt.Errorf("the server presented a different log head for size %d than the one this device accepted: the log was forked or rewritten", tree.N)
			}
			return l.Index, nil
		default:
			if l.From != old.N {
				return -1, fmt.Errorf("the consistency proof starts at size %d but this device holds a head of size %d", l.From, old.N)
			}
			cp, err := translog.DecodeProof(l.Consistency)
			if err != nil {
				return -1, fmt.Errorf("the consistency proof is malformed: %w", err)
			}
			if err := translog.CheckConsistency(old, tree, cp); err != nil {
				return -1, err
			}
		}
	}
	nh := logHead{Size: tree.N, Hash: tree.Hash.String(), Note: l.Head}
	if err := t.persistLogHead(nh); err != nil {
		return -1, fmt.Errorf("cannot save log_head.json: %w", err)
	}
	t.head = &nh
	return l.Index, nil
}

// ---- executed.log ----

// executedLine is one record. prev chains each line to the one before it, so
// deleting or editing a line changes every head reported after it.
type executedLine struct {
	Prev       string `json:"prev"`
	TS         int64  `json:"ts"`
	ManifestID string `json:"manifest_id"`
	Op         string `json:"op"`
	LogIndex   int64  `json:"log_index"`
}

func lineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// lastLine returns the last non-empty line of the file, reading only its tail
// (a line is a couple of hundred bytes), and whether the file ends in a newline.
func lastLine(path string) (line []byte, endsNL bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	const tail = 64 << 10
	off := st.Size() - tail
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return nil, false, err
	}
	endsNL = len(buf) > 0 && buf[len(buf)-1] == '\n'
	buf = bytes.TrimRight(buf, "\r\n")
	if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
		buf = buf[i+1:]
	}
	return buf, endsNL, nil
}

// loadExecuted recovers the chain head. A missing or unreadable file starts a
// new chain (its first line has an empty prev), with a warning in the agent
// log: the device cannot tell a wiped file from a fresh install, but the
// server can, because the reported head stops extending the one it stored.
func (t *trustState) loadExecuted() {
	t.execPath = executedPath()
	t.execReady = true
	line, _, err := lastLine(t.execPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		slog.Warn("executed.log cannot be read; starting a new chain", "path", t.execPath, "err", err)
	case len(line) == 0:
	default:
		var l executedLine
		if json.Unmarshal(line, &l) != nil {
			slog.Warn("the last line of executed.log is not valid; starting a new chain", "path", t.execPath)
			return
		}
		t.execHead = lineHash(line)
	}
}

// executedHead is what hello and inventory report.
func (t *trustState) executedHead() string {
	t.execMu.Lock()
	defer t.execMu.Unlock()
	return t.execHead
}

// recordExecuted appends one line for a manifest the device is about to run.
// It never blocks the request: a disk problem is logged, and the head the
// device reports then simply does not move, which the server can see.
func (t *trustState) recordExecuted(manifestID, op string, logIndex int64) {
	t.execMu.Lock()
	defer t.execMu.Unlock()
	if !t.execReady {
		return
	}
	line, err := json.Marshal(executedLine{Prev: t.execHead, TS: time.Now().Unix(), ManifestID: manifestID, Op: op, LogIndex: logIndex})
	if err != nil {
		return
	}
	if err := EnsureConfigDir(); err != nil {
		slog.Error("executed.log cannot be written", "err", err)
		return
	}
	// A crash can leave a partial last line; start on a fresh line so the new
	// record stays parseable. The partial line is not part of the chain.
	out := append(append([]byte(nil), line...), '\n')
	if _, endsNL, err := lastLine(t.execPath); err == nil && !endsNL {
		if st, serr := os.Stat(t.execPath); serr == nil && st.Size() > 0 {
			out = append([]byte{'\n'}, out...)
		}
	}
	f, err := os.OpenFile(t.execPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("executed.log cannot be written", "path", t.execPath, "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(out); err != nil {
		slog.Error("executed.log write failed", "path", t.execPath, "err", err)
		return
	}
	t.execHead = lineHash(line)
}
