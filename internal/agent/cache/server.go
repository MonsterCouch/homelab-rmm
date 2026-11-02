package cache

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// ServerConfig is everything the leader needs.
type ServerConfig struct {
	Store *Store
	// Origin is the server URL the agent is enrolled with. A miss is filled
	// only from a URL on this host and scheme: a member names the URL in
	// X-Origin, and without the restriction any device holding the token could
	// turn the leader into a proxy for arbitrary hosts.
	Origin string
	// OriginClient fetches from Origin (it carries the agent's certificate
	// pin). Nil means a default client.
	OriginClient *http.Client
	// Tokens returns the bearer tokens currently acceptable, newest first.
	Tokens func() []string
	Cert   tls.Certificate
	Stats  *Stats
	// FillTimeout bounds one fill from the origin (default 15 minutes).
	FillTimeout time.Duration
}

// Server is the leader: HTTPS on TCP and HTTP/3 on UDP, one port, one
// certificate, one handler.
type Server struct {
	cfg    ServerConfig
	client *http.Client
	origin *url.URL

	base   context.Context
	cancel context.CancelFunc

	mu    sync.Mutex
	https *http.Server
	h3    *http3.Server
	port  int
	h3ok  bool
	wg    sync.WaitGroup
}

// NewServer builds a leader that is not listening yet.
func NewServer(cfg ServerConfig) *Server {
	if cfg.Stats == nil {
		cfg.Stats = cfg.Store.stats
	}
	if cfg.FillTimeout <= 0 {
		cfg.FillTimeout = 15 * time.Minute
	}
	s := &Server{cfg: cfg}
	s.origin, _ = url.Parse(cfg.Origin)
	c := http.Client{Timeout: 0}
	if cfg.OriginClient != nil {
		c = *cfg.OriginClient
	}
	// A redirect off the origin host would defeat the restriction above.
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("the origin redirected too many times")
		}
		if s.origin == nil || !strings.EqualFold(req.URL.Host, s.origin.Host) {
			return errors.New("the origin redirected to another host")
		}
		return nil
	}
	s.client = &c
	s.base, s.cancel = context.WithCancel(context.Background())
	return s
}

// Start binds port on every interface, TCP for HTTPS and UDP for HTTP/3, and
// serves until Close. Port 0 picks a free port (tests). A UDP port that cannot
// be bound leaves the leader serving HTTPS only, which members handle by
// falling back from HTTP/3.
func (s *Server) Start(port int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.https != nil {
		return errors.New("the cache server is already running")
	}
	tcfg := &tls.Config{Certificates: []tls.Certificate{s.cfg.Cert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	var ln net.Listener
	var pc net.PacketConn
	var err error
	if port == 0 {
		// Any free port will do, but TCP and UDP have to agree on it. TCP goes
		// first: Windows excludes whole ranges of TCP ports (Hyper-V, WinNAT)
		// that a UDP bind to :0 happily lands in, so picking the UDP port
		// first fails on such machines attempt after attempt. When no port
		// takes both within a few tries the leader keeps the last TCP port and
		// serves HTTPS only, as it does when a fixed UDP port is taken.
		for attempt := 0; attempt < 32; attempt++ {
			ln, err = net.Listen("tcp", ":0")
			if err != nil {
				continue
			}
			pc, err = net.ListenPacket("udp", ":"+strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
			if err == nil || attempt == 31 {
				break
			}
			ln.Close()
			ln = nil
		}
		if ln == nil {
			return fmt.Errorf("find a free port for the cache: %w", err)
		}
	} else {
		ln, err = net.Listen("tcp", ":"+strconv.Itoa(port))
		if err != nil {
			return fmt.Errorf("listen for the cache on TCP port %d: %w", port, err)
		}
		pc, err = net.ListenPacket("udp", ":"+strconv.Itoa(port))
	}
	s.port = ln.Addr().(*net.TCPAddr).Port
	handler := s.Handler()
	s.https = &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: 2 * time.Minute}
	s.wg.Add(1)
	go func(srv *http.Server) {
		defer s.wg.Done()
		if err := srv.Serve(tls.NewListener(ln, tcfg)); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("the cache HTTPS listener stopped", "err", err)
		}
	}(s.https)
	if err != nil {
		slog.Warn("the cache cannot listen on UDP, so HTTP/3 is off and members use HTTPS", "port", s.port, "err", err)
		return nil
	}
	s.h3 = &http3.Server{Handler: handler, TLSConfig: http3.ConfigureTLSConfig(tcfg), IdleTimeout: 2 * time.Minute}
	s.h3ok = true
	s.wg.Add(1)
	go func(srv *http3.Server) {
		defer s.wg.Done()
		if err := srv.Serve(pc); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Debug("the cache HTTP/3 listener stopped", "err", err)
		}
	}(s.h3)
	return nil
}

// Port is the port the leader is bound to (0 before Start).
func (s *Server) Port() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.port
}

// HTTP3 reports whether the UDP listener is up.
func (s *Server) HTTP3() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.h3ok
}

// Close stops both listeners and abandons fills in progress.
func (s *Server) Close() {
	s.cancel()
	s.mu.Lock()
	hs, h3s := s.https, s.h3
	s.https, s.h3, s.h3ok = nil, nil, false
	s.mu.Unlock()
	if hs != nil {
		_ = hs.Close()
	}
	if h3s != nil {
		_ = h3s.Close()
	}
	s.wg.Wait()
}

// Handler is the leader's HTTP surface, exposed so tests can drive it
// without sockets:
//
//	GET /cas/{sha256}               the whole artifact, Range supported
//	GET /cas/{sha256}/index         the chunk list as JSON
//	GET /cas/{sha256}/chunk/{i}     one chunk
//
// Every request needs the bearer token. A miss is filled from X-Origin.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /cas/{sum}", s.handleWhole)
	mux.HandleFunc("GET /cas/{sum}/index", s.handleIndex)
	mux.HandleFunc("GET /cas/{sum}/chunk/{i}", s.handleChunk)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "The cache token is missing or not valid today.", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" || s.cfg.Tokens == nil {
		return false
	}
	got := sha256.Sum256([]byte(tok))
	match := 0
	for _, t := range s.cfg.Tokens() {
		if t == "" {
			continue
		}
		want := sha256.Sum256([]byte(t))
		match |= subtle.ConstantTimeCompare(got[:], want[:])
	}
	return match == 1
}

// originAllowed reports whether raw is a URL the leader may fetch for a
// member: the same scheme and host as the server the agent is enrolled with.
func (s *Server) originAllowed(raw string) (*url.URL, error) {
	if s.origin == nil || s.origin.Host == "" {
		return nil, errors.New("this leader has no server URL to fill from")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("the origin URL is not valid: %w", err)
	}
	if u.User != nil || u.Host == "" || !strings.EqualFold(u.Scheme, s.origin.Scheme) || !strings.EqualFold(u.Host, s.origin.Host) {
		return nil, errors.New("the origin URL is not on the server this leader belongs to")
	}
	return u, nil
}

// ensure makes the artifact present, filling it when the request names an
// origin. It writes the error response itself and reports whether the
// artifact is now in the store. count says whether this request is the one
// that counts as a hit or a miss (chunk requests do not, so a fetch of fifty
// chunks is one hit, not fifty).
func (s *Server) ensure(w http.ResponseWriter, r *http.Request, sum string, count bool) bool {
	if s.cfg.Store.Has(sum) {
		if count {
			s.cfg.Stats.Hits.Add(1)
		}
		return true
	}
	if count {
		s.cfg.Stats.Misses.Add(1)
	}
	raw := r.Header.Get("X-Origin")
	if raw == "" {
		http.Error(w, "The artifact is not cached and the request names no origin.", http.StatusNotFound)
		return false
	}
	u, err := s.originAllowed(raw)
	if err != nil {
		http.Error(w, err.Error()+".", http.StatusForbidden)
		return false
	}
	ctx, cancel := context.WithTimeout(s.base, s.cfg.FillTimeout)
	defer cancel()
	err = s.cfg.Store.Fill(ctx, sum, func(ctx context.Context) (io.ReadCloser, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch the artifact from the origin: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("the origin answered %s", resp.Status)
		}
		if resp.ContentLength > 0 {
			if err := s.cfg.Store.Admit(resp.ContentLength); err != nil {
				resp.Body.Close()
				return nil, err
			}
		}
		return resp.Body, nil
	})
	if err != nil {
		var mm *MismatchError
		if errors.As(err, &mm) {
			slog.Warn("the cache refused an artifact whose hash does not match", "want", mm.Want, "got", mm.Got)
		} else {
			slog.Warn("the cache could not fill an artifact", "sha256", sum, "err", err)
		}
		code := http.StatusBadGateway
		if errors.Is(err, ErrTooLarge) {
			code = http.StatusInsufficientStorage
		}
		http.Error(w, err.Error(), code)
		return false
	}
	return true
}

func sumOf(w http.ResponseWriter, r *http.Request) (string, bool) {
	sum, ok := NormalizeSum(r.PathValue("sum"))
	if !ok {
		http.Error(w, "The artifact name is not a SHA-256.", http.StatusBadRequest)
	}
	return sum, ok
}

type countingWriter struct {
	http.ResponseWriter
	n *Stats
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n.BytesServed.Add(int64(n))
	return n, err
}

func (s *Server) handleWhole(w http.ResponseWriter, r *http.Request) {
	sum, ok := sumOf(w, r)
	if !ok || !s.ensure(w, r, sum, true) {
		return
	}
	f, _, release, err := s.cfg.Store.Acquire(sum)
	if err != nil {
		http.Error(w, "The artifact left the cache while the request was being served.", http.StatusNotFound)
		return
	}
	defer release()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "The cached artifact cannot be read.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(countingWriter{w, s.cfg.Stats}, r, "", st.ModTime(), f)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	sum, ok := sumOf(w, r)
	if !ok || !s.ensure(w, r, sum, true) {
		return
	}
	idx, err := s.cfg.Store.Index(sum)
	if err != nil {
		http.Error(w, "The chunk index cannot be read.", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(idx)
}

func (s *Server) handleChunk(w http.ResponseWriter, r *http.Request) {
	sum, ok := sumOf(w, r)
	if !ok {
		return
	}
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil || i < 0 {
		http.Error(w, "The chunk number is not valid.", http.StatusBadRequest)
		return
	}
	if !s.ensure(w, r, sum, false) {
		return
	}
	f, size, release, err := s.cfg.Store.Acquire(sum)
	if err != nil {
		http.Error(w, "The artifact left the cache while the request was being served.", http.StatusNotFound)
		return
	}
	defer release()
	off := int64(i) * ChunkSize
	if off >= size {
		http.Error(w, "The chunk is past the end of the artifact.", http.StatusNotFound)
		return
	}
	n := min(int64(ChunkSize), size-off)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
	written, _ := io.Copy(w, io.NewSectionReader(f, off, n))
	s.cfg.Stats.BytesServed.Add(written)
}
