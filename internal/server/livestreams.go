package server

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// liveRecheckEvery is the backstop interval for re-authorizing open operator
// streams. Revocations made through this server re-check at once; the sweep
// is for the ones it cannot see happen: a session that expires, a password
// reset from the CLI in another process, a device moved to another
// organization.
const liveRecheckEvery = 30 * time.Second

// liveStream is one long-lived operator connection: a terminal, a remote
// desktop or the event stream. Each was authorized once, on the request that
// opened it, and then ran for as long as the peer kept it open. Signing out,
// a password reset, a demotion, a narrower organization scope and deleting
// the account only changed database rows, so none of them reached a stream
// that was already running - a SYSTEM shell stayed usable by a session that
// no longer existed.
type liveStream struct {
	// token is the session cookie the stream was opened with.
	token string
	// still re-runs the stream's own authorization against the account as
	// it is now. It is not called for a session that no longer resolves.
	still func(u *User) bool
	// end closes the stream. It is called from another goroutine than the
	// handler's and may be called while the handler is already returning.
	end func()
}

// liveStreams is the registry of them.
type liveStreams struct {
	mu   sync.Mutex
	next uint64
	m    map[uint64]*liveStream
}

// trackStream registers an open stream for re-authorization and returns the
// func that removes it; defer that in the handler. still and end must be safe
// to call from another goroutine.
func (s *Server) trackStream(r *http.Request, still func(u *User) bool, end func()) (untrack func()) {
	token := ""
	if c, _ := r.Cookie(sessionCookie); c != nil {
		token = c.Value
	}
	ls := &s.live
	ls.mu.Lock()
	if ls.m == nil {
		ls.m = map[uint64]*liveStream{}
	}
	ls.next++
	id := ls.next
	ls.m[id] = &liveStream{token: token, still: still, end: end}
	ls.mu.Unlock()
	return func() {
		ls.mu.Lock()
		delete(ls.m, id)
		ls.mu.Unlock()
	}
}

// recheckStreams ends every open stream whose session is gone or whose
// account may no longer have it. It is called after anything that revokes
// access and on a timer. The database is read outside the lock, and a stream
// is removed before it is ended so a second pass cannot end it twice.
func (s *Server) recheckStreams() {
	ls := &s.live
	ls.mu.Lock()
	open := make(map[uint64]*liveStream, len(ls.m))
	for id, st := range ls.m {
		open[id] = st
	}
	ls.mu.Unlock()

	for id, st := range open {
		u := s.db.userBySession(st.token)
		if u != nil && st.still(u) {
			continue
		}
		ls.mu.Lock()
		_, live := ls.m[id]
		delete(ls.m, id)
		ls.mu.Unlock()
		if live {
			st.end()
		}
	}
}

// watchStreams runs the backstop sweep until ctx ends.
func (s *Server) watchStreams(ctx context.Context) {
	t := time.NewTicker(liveRecheckEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.recheckStreams()
		}
	}
}

// mayOperate is the re-check for a terminal or remote desktop on agentID: the
// account must still be able to change state and still reach the device's
// organization, read fresh because the device may have moved.
func (s *Server) mayOperate(u *User, agentID string) bool {
	if !u.CanWrite() {
		return false
	}
	a, err := s.db.GetAgent(agentID)
	return err == nil && s.canAccessAgent(u, a.OrgID)
}
