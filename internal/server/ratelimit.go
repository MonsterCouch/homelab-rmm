package server

import (
	"sync"
	"time"
)

// rateLimiter is a tiny fixed-window counter keyed by string (client IP),
// enough to blunt online password guessing without a dependency.
type rateLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string]*rlEntry
}

type rlEntry struct {
	n     int
	reset time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{max: max, window: window, hits: map[string]*rlEntry{}}
}

func (r *rateLimiter) allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	nowT := time.Now()
	e := r.hits[key]
	if e == nil || nowT.After(e.reset) {
		e = &rlEntry{reset: nowT.Add(r.window)}
		r.hits[key] = e
		if len(r.hits) > 10000 {
			for k, v := range r.hits {
				if nowT.After(v.reset) {
					delete(r.hits, k)
				}
			}
		}
	}
	e.n++
	return e.n <= r.max
}

func (r *rateLimiter) reset(key string) {
	r.mu.Lock()
	delete(r.hits, key)
	r.mu.Unlock()
}

// forgive takes back one hit, for an attempt that turned out to be
// legitimate. It is what a successful login uses instead of reset: the key is
// a client address that several accounts share, and deleting it let anyone
// with a working account wipe out the failures counted against everyone
// else's, so guessing another user's password or code was never limited.
func (r *rateLimiter) forgive(key string) {
	r.mu.Lock()
	if e := r.hits[key]; e != nil && e.n > 0 {
		e.n--
	}
	r.mu.Unlock()
}
