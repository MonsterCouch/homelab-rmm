// Package translog is the server's append-only Merkle log (RFC 6962 hashing
// via golang.org/x/mod/sumdb/tlog) with Ed25519-signed tree heads
// (golang.org/x/mod/sumdb/note). The verification half has no dependency on
// a Log, so the agent and the CLI share it.
package translog

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// KeyName is the name embedded in the log's signing and verifier keys.
const KeyName = "homelab-rmm-log"

// Log is a signed, append-only Merkle log over a Storage.
type Log struct {
	mu       sync.Mutex
	storage  Storage
	signer   note.Signer
	vkey     string
	headSize int64 // size the cached head is for
	// size is the number of leaves, kept in memory so that Head and Append
	// need no COUNT query on the server's single database connection. Only
	// this Log writes the storage, so it cannot drift; sizeKnown is false
	// until the first read.
	size      int64
	sizeKnown bool
	head      tlog.Tree
	headNote  []byte
}

// Open loads or generates the key file and returns a Log over st. The file
// holds the signer key on line 1 and the verifier key on line 2, mode 0600.
func Open(st Storage, keyFile string) (*Log, error) {
	skey, vkey, err := loadOrCreateKey(keyFile)
	if err != nil {
		return nil, err
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, fmt.Errorf("the log key file %s holds an unusable signer key: %w", keyFile, err)
	}
	return &Log{storage: st, signer: signer, vkey: vkey}, nil
}

func loadOrCreateKey(path string) (skey, vkey string, err error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		skey, vkey, err = note.GenerateKey(rand.Reader, KeyName)
		if err != nil {
			return "", "", err
		}
		// O_EXCL so two servers starting together cannot overwrite each
		// other's freshly generated key.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", "", fmt.Errorf("cannot create the log key file %s: %w", path, err)
		}
		_, werr := f.WriteString(skey + "\n" + vkey + "\n")
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(path)
			return "", "", fmt.Errorf("cannot write the log key file %s: %w", path, werr)
		}
		return skey, vkey, nil
	}
	if err != nil {
		return "", "", fmt.Errorf("cannot read the log key file %s: %w", path, err)
	}
	lines := strings.Split(strings.ReplaceAll(strings.TrimSpace(string(raw)), "\r\n", "\n"), "\n")
	if len(lines) != 2 {
		return "", "", fmt.Errorf("the log key file %s must have two lines (signer key, verifier key), found %d", path, len(lines))
	}
	skey, vkey = strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	signer, err := note.NewSigner(skey)
	if err != nil {
		return "", "", fmt.Errorf("the log key file %s holds an unusable signer key: %w", path, err)
	}
	ver, err := note.NewVerifier(vkey)
	if err != nil {
		return "", "", fmt.Errorf("the log key file %s holds an unusable verifier key: %w", path, err)
	}
	if signer.Name() != ver.Name() || signer.KeyHash() != ver.KeyHash() {
		return "", "", fmt.Errorf("the log key file %s has a signer key and a verifier key that do not belong together", path)
	}
	return skey, vkey, nil
}

// VerifierKey is the note verifier key bundles pin as log_key, for example
// "homelab-rmm-log+9f3c1a2b+AAAA...".
func (l *Log) VerifierKey() string { return l.vkey }

// Append adds a leaf and returns its index.
func (l *Log) Append(kind string, data []byte) (int64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.sizeLocked()
	if err != nil {
		return 0, err
	}
	hashes, err := tlog.StoredHashes(n, data, hashReader{l.storage})
	if err != nil {
		return 0, err
	}
	idx, err := l.storage.AppendLeaf(kind, data, hashes)
	if err != nil {
		return 0, err
	}
	if idx != n {
		return 0, fmt.Errorf("the transparency log stored an entry at %d, expected %d", idx, n)
	}
	l.headNote = nil // invalidate the cached head
	l.size = n + 1
	return idx, nil
}

// sizeLocked returns the leaf count, asking the storage only the first time.
func (l *Log) sizeLocked() (int64, error) {
	if l.sizeKnown {
		return l.size, nil
	}
	n, err := l.storage.Size()
	if err != nil {
		return 0, err
	}
	l.size, l.sizeKnown = n, true
	return n, nil
}

// Head returns the current tree and its signed note. An empty log yields a
// tree with N=0, signed like any other. The result is cached per size.
func (l *Log) Head() (tlog.Tree, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.sizeLocked()
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	if l.headNote != nil && l.headSize == n {
		return l.head, append([]byte(nil), l.headNote...), nil
	}
	h, err := tlog.TreeHash(n, hashReader{l.storage})
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	tree := tlog.Tree{N: n, Hash: h}
	signed, err := note.Sign(&note.Note{Text: string(tlog.FormatTree(tree))}, l.signer)
	if err != nil {
		return tlog.Tree{}, nil, err
	}
	l.headSize, l.head, l.headNote = n, tree, signed
	return tree, append([]byte(nil), signed...), nil
}

// ProveInclusion proves leaf index is in the tree of the given size.
func (l *Log) ProveInclusion(index, size int64) (tlog.RecordProof, error) {
	if err := l.checkSize(size); err != nil {
		return nil, err
	}
	if index < 0 || index >= size {
		return nil, fmt.Errorf("entry %d is not inside a log of %d entries", index, size)
	}
	return tlog.ProveRecord(size, index, hashReader{l.storage})
}

// ProveConsistency proves the tree of size to extends the tree of size from.
func (l *Log) ProveConsistency(from, to int64) (tlog.TreeProof, error) {
	if err := l.checkSize(to); err != nil {
		return nil, err
	}
	if from < 1 || from > to {
		return nil, fmt.Errorf("cannot prove consistency from size %d to size %d", from, to)
	}
	return tlog.ProveTree(to, from, hashReader{l.storage})
}

// Leaf returns the stored entry.
func (l *Log) Leaf(index int64) (kind string, data []byte, ts int64, err error) {
	return l.storage.ReadLeaf(index)
}

func (l *Log) checkSize(size int64) error {
	n, err := l.storage.Size()
	if err != nil {
		return err
	}
	if size < 1 || size > n {
		return fmt.Errorf("the log has %d entries, so a proof for size %d is not possible", n, size)
	}
	return nil
}

type hashReader struct{ s Storage }

func (r hashReader) ReadHashes(ix []int64) ([]tlog.Hash, error) { return r.s.ReadHashes(ix) }

// ParseHead verifies the signed head note against the verifier key and
// returns the tree it commits to.
func ParseHead(verifierKey string, signed []byte) (tlog.Tree, error) {
	v, err := note.NewVerifier(verifierKey)
	if err != nil {
		return tlog.Tree{}, fmt.Errorf("the log key is not usable: %w", err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		return tlog.Tree{}, fmt.Errorf("the log head is not signed by the pinned log key: %w", err)
	}
	t, err := tlog.ParseTree([]byte(n.Text))
	if err != nil {
		return tlog.Tree{}, fmt.Errorf("the log head is malformed: %w", err)
	}
	return t, nil
}

// CheckInclusion verifies that leaf data sits at index in tree t.
func CheckInclusion(t tlog.Tree, index int64, leaf []byte, proof tlog.RecordProof) error {
	if index < 0 || index >= t.N {
		return fmt.Errorf("entry %d is outside the log head of %d entries", index, t.N)
	}
	if err := tlog.CheckRecord(proof, t.N, t.Hash, index, tlog.RecordHash(leaf)); err != nil {
		return fmt.Errorf("the manifest is not in the log at index %d: %w", index, err)
	}
	return nil
}

// CheckConsistency verifies that tree new extends tree old.
func CheckConsistency(old, new tlog.Tree, proof tlog.TreeProof) error {
	if old.N < 1 {
		return errors.New("there is no earlier log head to check consistency against")
	}
	if err := tlog.CheckTree(proof, new.N, new.Hash, old.N, old.Hash); err != nil {
		return fmt.Errorf("the log head of %d entries does not extend the earlier head of %d entries: %w", new.N, old.N, err)
	}
	return nil
}

// EncodeProof renders hashes as standard base64 strings.
func EncodeProof(p []tlog.Hash) []string {
	out := make([]string, len(p))
	for i, h := range p {
		out[i] = base64.StdEncoding.EncodeToString(h[:])
	}
	return out
}

// DecodeProof is the inverse of EncodeProof.
func DecodeProof(s []string) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(s))
	for i, e := range s {
		b, err := base64.StdEncoding.DecodeString(e)
		if err != nil || len(b) != tlog.HashSize {
			return nil, fmt.Errorf("proof hash %d is not a base64 SHA-256 value", i)
		}
		copy(out[i][:], b)
	}
	return out, nil
}
