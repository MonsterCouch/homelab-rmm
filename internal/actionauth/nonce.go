package actionauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NonceStore remembers consumed action nonces until they expire.
type NonceStore interface {
	// Consume records nonce as used until exp. It returns ErrReplay when the
	// nonce was already consumed and has not expired.
	Consume(nonce string, exp time.Time) error
}

// MemoryNonceStore is a NonceStore for tests and for the server's own early
// checks; the agent uses FileNonceStore so a restart cannot reopen a replay
// window (a replayed reboot would otherwise work again after the reboot it
// caused).
type MemoryNonceStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
	now  func() time.Time
}

func NewMemoryNonceStore() *MemoryNonceStore { return &MemoryNonceStore{seen: map[string]time.Time{}} }

func (s *MemoryNonceStore) Consume(nonce string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return consume(s.seen, nonce, exp, clock(s.now))
}

func clock(f func() time.Time) time.Time {
	if f != nil {
		return f()
	}
	return time.Now()
}

func consume(seen map[string]time.Time, nonce string, exp, now time.Time) error {
	for n, e := range seen {
		if !now.Before(e) {
			delete(seen, n)
		}
	}
	if _, ok := seen[nonce]; ok {
		return ErrReplay
	}
	seen[nonce] = exp
	return nil
}

// FileNonceStore persists consumed nonces in one small JSON file, rewritten
// atomically (temp file + rename) on every consume. Live nonces are bounded
// by the action lifetime ceiling (10 minutes), so the file stays tiny.
type FileNonceStore struct {
	mu   sync.Mutex
	path string
	seen map[string]time.Time
	now  func() time.Time
}

// OpenFileNonceStore loads (or creates) the store at path. A corrupt file is
// an error rather than an empty store: silently forgetting consumed nonces
// is exactly the replay window the store exists to close.
func OpenFileNonceStore(path string) (*FileNonceStore, error) {
	s := &FileNonceStore{path: path, seen: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	var stored map[string]int64
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("nonce store %s is corrupt: %w", path, err)
	}
	for n, e := range stored {
		s.seen[n] = time.Unix(e, 0)
	}
	return s, nil
}

func (s *FileNonceStore) Consume(nonce string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := consume(s.seen, nonce, exp, clock(s.now)); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		// Not persisted means not protected across a restart: refuse the
		// action rather than run it unprotected.
		delete(s.seen, nonce)
		return fmt.Errorf("nonce store: %w", err)
	}
	return nil
}

func (s *FileNonceStore) save() error {
	out := make(map[string]int64, len(s.seen))
	for n, e := range s.seen {
		out[n] = e.Unix()
	}
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".nonces-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
