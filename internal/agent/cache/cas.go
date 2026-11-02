package cache

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ChunkSize is the unit the index hashes and a member fetches and resumes by.
// 2 MiB keeps a cut connection cheap to resume while a 100 MB agent binary
// still needs only about fifty requests.
const ChunkSize = 2 << 20

// DefaultMaxBytes is the store budget when the server names none.
const DefaultMaxBytes int64 = 2 << 30

// ErrTooLarge means an artifact cannot be stored: it is bigger than the budget
// or than the free space on the volume.
var ErrTooLarge = errors.New("the artifact is too large for the cache")

// ErrNotFound means the artifact is not in the store.
var ErrNotFound = errors.New("the artifact is not in the cache")

// MismatchError is a fill whose bytes did not hash to the name they were
// requested under. Nothing is kept when it happens.
type MismatchError struct{ Want, Got string }

func (e *MismatchError) Error() string {
	return fmt.Sprintf("the downloaded artifact does not match its hash: expected %s, got %s", e.Want, e.Got)
}

// Stats are the counters the agent reports in its inventory. They are atomic
// because the leader's handlers and the agent's reporter touch them from
// different goroutines.
type Stats struct {
	Hits, Misses, BytesServed, BytesStored atomic.Int64
}

// Index is the chunk list of one stored artifact: the SHA-256 of every
// ChunkSize piece (the last one may be shorter), in hex.
type Index struct {
	Size      int64    `json:"size"`
	ChunkSize int      `json:"chunk_size"`
	Chunks    []string `json:"chunks"`
}

var sumRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NormalizeSum lower-cases a SHA-256 and reports whether it is one. Everything
// that becomes a file name goes through it first, so a request can never name
// a path.
func NormalizeSum(s string) (string, bool) {
	s = strings.ToLower(s)
	return s, sumRE.MatchString(s)
}

type fill struct {
	done chan struct{}
	err  error
}

// Store is the content-addressable directory: <dir>/<sha256> holds the whole
// artifact and <dir>/<sha256>.idx the chunk hashes. A file's presence under
// its final name is the commit marker, so a crash mid-fill leaves only a
// temporary file that the next start removes.
type Store struct {
	dir   string
	stats *Stats

	mu    sync.Mutex
	max   int64
	inuse map[string]int
	fills map[string]*fill
}

// OpenStore prepares dir as a store holding at most maxBytes (DefaultMaxBytes
// when not positive). stats may be nil.
func OpenStore(dir string, maxBytes int64, stats *Stats) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create the cache store %s: %w", dir, err)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if stats == nil {
		stats = &Stats{}
	}
	s := &Store{dir: dir, max: maxBytes, stats: stats, inuse: map[string]int{}, fills: map[string]*fill{}}
	if tmps, err := filepath.Glob(filepath.Join(dir, ".fill-*")); err == nil {
		for _, t := range tmps {
			_ = os.Remove(t)
		}
	}
	// An index with no artifact is what a crash between writing the index and
	// the rename leaves; nothing counts it toward the budget or removes it.
	if idxs, err := filepath.Glob(filepath.Join(dir, "*.idx")); err == nil {
		for _, ix := range idxs {
			if _, err := os.Stat(strings.TrimSuffix(ix, ".idx")); os.IsNotExist(err) {
				_ = os.Remove(ix)
			}
		}
	}
	return s, nil
}

// Admit refuses an artifact of the given size before any byte is downloaded:
// one over the budget, or one that would not fit on the volume even after
// evicting everything evictable.
func (s *Store) Admit(size int64) error {
	s.mu.Lock()
	max := s.max
	s.mu.Unlock()
	if size > max {
		return fmt.Errorf("%w: %d bytes exceeds the cache budget of %d", ErrTooLarge, size, max)
	}
	if free, ok := freeSpace(s.dir); ok && size > free+s.Size() {
		return fmt.Errorf("%w: %d bytes needed but only %d are free on the volume", ErrTooLarge, size, free)
	}
	return nil
}

// SetMax changes the budget and evicts down to it.
func (s *Store) SetMax(maxBytes int64) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	s.mu.Lock()
	s.max = maxBytes
	s.evictLocked("")
	s.mu.Unlock()
}

// Dir is the store directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(sum string) string { return filepath.Join(s.dir, sum) }

// Has reports whether the whole artifact is stored.
func (s *Store) Has(sum string) bool {
	sum, ok := NormalizeSum(sum)
	if !ok {
		return false
	}
	st, err := os.Stat(s.path(sum))
	return err == nil && st.Mode().IsRegular()
}

// Acquire opens a stored artifact for reading and marks it in use, which keeps
// eviction away from it until release is called. Opening counts as use for the
// LRU order.
func (s *Store) Acquire(sum string) (f *os.File, size int64, release func(), err error) {
	sum, ok := NormalizeSum(sum)
	if !ok {
		return nil, 0, nil, ErrNotFound
	}
	s.mu.Lock()
	s.inuse[sum]++
	s.mu.Unlock()
	drop := func() {
		s.mu.Lock()
		if s.inuse[sum]--; s.inuse[sum] <= 0 {
			delete(s.inuse, sum)
		}
		s.mu.Unlock()
	}
	f, err = os.Open(s.path(sum))
	if err != nil {
		drop()
		if os.IsNotExist(err) {
			return nil, 0, nil, ErrNotFound
		}
		return nil, 0, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		drop()
		return nil, 0, nil, err
	}
	now := time.Now()
	_ = os.Chtimes(s.path(sum), now, now)
	var once sync.Once
	return f, st.Size(), func() { once.Do(func() { f.Close(); drop() }) }, nil
}

// Index returns the chunk list of a stored artifact. A missing or damaged
// index file is rebuilt from the artifact, so it never has to be trusted.
func (s *Store) Index(sum string) (Index, error) {
	sum, ok := NormalizeSum(sum)
	if !ok {
		return Index{}, ErrNotFound
	}
	f, size, release, err := s.Acquire(sum)
	if err != nil {
		return Index{}, err
	}
	defer release()
	want := int((size + ChunkSize - 1) / ChunkSize)
	if b, err := os.ReadFile(s.path(sum) + ".idx"); err == nil {
		lines := strings.Fields(string(b))
		good := len(lines) == want
		for _, l := range lines {
			if _, ok := NormalizeSum(l); !ok {
				good = false
			}
		}
		if good {
			return Index{Size: size, ChunkSize: ChunkSize, Chunks: lines}, nil
		}
	}
	ch := &chunkHasher{}
	if _, err := io.Copy(ch, bufio.NewReaderSize(f, 1<<20)); err != nil {
		return Index{}, fmt.Errorf("rebuild the chunk index: %w", err)
	}
	chunks := ch.finish()
	_ = os.WriteFile(s.path(sum)+".idx", []byte(strings.Join(chunks, "\n")+"\n"), 0o600)
	return Index{Size: size, ChunkSize: ChunkSize, Chunks: chunks}, nil
}

// chunkHasher hashes a stream in ChunkSize pieces.
type chunkHasher struct {
	cur    hash.Hash
	n      int
	chunks []string
}

func (c *chunkHasher) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if c.cur == nil {
			c.cur = sha256.New()
		}
		take := min(len(p), ChunkSize-c.n)
		c.cur.Write(p[:take])
		c.n += take
		p = p[take:]
		if c.n == ChunkSize {
			c.chunks = append(c.chunks, hex.EncodeToString(c.cur.Sum(nil)))
			c.cur, c.n = nil, 0
		}
	}
	return total, nil
}

func (c *chunkHasher) finish() []string {
	if c.cur != nil && c.n > 0 {
		c.chunks = append(c.chunks, hex.EncodeToString(c.cur.Sum(nil)))
		c.cur, c.n = nil, 0
	}
	return c.chunks
}

// Put streams r into the store under sum, hashing as it goes, and keeps it
// only when the hash is sum. The index is written before the artifact is
// renamed into place, so a visible artifact always has its index.
func (s *Store) Put(sum string, r io.Reader) error {
	sum, ok := NormalizeSum(sum)
	if !ok {
		return errors.New("the artifact name is not a SHA-256")
	}
	tmp, err := os.CreateTemp(s.dir, ".fill-*")
	if err != nil {
		return fmt.Errorf("create a temporary cache file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()
	// Cap the copy at the budget: a body without a Content-Length (or a lying
	// one) must not fill the volume before eviction ever runs.
	s.mu.Lock()
	max := s.max
	s.mu.Unlock()
	whole, ch := sha256.New(), &chunkHasher{}
	n, err := io.Copy(io.MultiWriter(tmp, whole, ch), io.LimitReader(r, max+1))
	if err != nil {
		return fmt.Errorf("download the artifact into the cache: %w", err)
	}
	if n > max {
		return fmt.Errorf("%w: it exceeds the cache budget of %d bytes", ErrTooLarge, max)
	}
	if got := hex.EncodeToString(whole.Sum(nil)); got != sum {
		return &MismatchError{Want: sum, Got: got}
	}
	if n == 0 {
		return errors.New("the artifact is empty")
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("flush the cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close the cache file: %w", err)
	}
	if err := os.WriteFile(s.path(sum)+".idx", []byte(strings.Join(ch.finish(), "\n")+"\n"), 0o600); err != nil {
		_ = os.Remove(s.path(sum) + ".idx")
		return fmt.Errorf("write the chunk index: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(tmpPath, s.path(sum)); err != nil {
		_ = os.Remove(s.path(sum) + ".idx")
		return fmt.Errorf("move the artifact into the cache: %w", err)
	}
	committed = true
	s.stats.BytesStored.Add(n)
	s.evictLocked(sum)
	return nil
}

// Fill makes sure sum is stored, calling fetch for the bytes when it is not.
// Concurrent callers for one hash share a single fetch: the first runs it and
// the rest wait for its outcome, so a subnet asking for the same new build at
// once costs the WAN one download. ctx only bounds a waiter's patience; the
// fetch itself runs under the first caller's context.
func (s *Store) Fill(ctx context.Context, sum string, fetch func(context.Context) (io.ReadCloser, error)) error {
	sum, ok := NormalizeSum(sum)
	if !ok {
		return errors.New("the artifact name is not a SHA-256")
	}
	s.mu.Lock()
	if f := s.fills[sum]; f != nil {
		s.mu.Unlock()
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.Has(sum) {
		s.mu.Unlock()
		return nil
	}
	f := &fill{done: make(chan struct{})}
	s.fills[sum] = f
	s.mu.Unlock()

	f.err = func() error {
		body, err := fetch(ctx)
		if err != nil {
			return err
		}
		defer body.Close()
		return s.Put(sum, body)
	}()
	s.mu.Lock()
	delete(s.fills, sum)
	s.mu.Unlock()
	close(f.done)
	return f.err
}

// Size is the bytes the store currently holds.
func (s *Store) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := int64(0)
	for _, e := range s.entriesLocked() {
		total += e.size
	}
	return total
}

type storeEntry struct {
	sum   string
	size  int64 // artifact plus index
	mtime time.Time
}

func (s *Store) entriesLocked() []storeEntry {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []storeEntry
	for _, e := range ents {
		name := e.Name()
		if !sumRE.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		size := info.Size()
		if ii, err := os.Stat(s.path(name) + ".idx"); err == nil {
			size += ii.Size()
		}
		out = append(out, storeEntry{sum: name, size: size, mtime: info.ModTime()})
	}
	return out
}

// evictLocked removes least recently used artifacts until the store fits its
// budget. An artifact being streamed (in use) and the one just stored (keep)
// are never removed, so a single artifact larger than the budget is still
// served rather than deleted the moment it lands.
func (s *Store) evictLocked(keep string) {
	ents := s.entriesLocked()
	total := int64(0)
	for _, e := range ents {
		total += e.size
	}
	if total <= s.max {
		return
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].mtime.Before(ents[j].mtime) })
	for _, e := range ents {
		if total <= s.max {
			return
		}
		if e.sum == keep || s.inuse[e.sum] > 0 {
			continue
		}
		if err := os.Remove(s.path(e.sum)); err != nil {
			continue
		}
		_ = os.Remove(s.path(e.sum) + ".idx")
		total -= e.size
	}
}
