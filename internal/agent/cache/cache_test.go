package cache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testData(n int, seed int64) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newStore(t *testing.T, max int64) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "cache"), max, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// origin serves one artifact and counts how often it is asked.
type origin struct {
	*httptest.Server
	hits atomic.Int64
	data []byte
	wait time.Duration
}

func newOrigin(t *testing.T, data []byte, wait time.Duration) *origin {
	t.Helper()
	o := &origin{data: data, wait: wait}
	o.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		if o.wait > 0 {
			time.Sleep(o.wait)
		}
		w.Write(o.data)
	}))
	t.Cleanup(o.Close)
	return o
}

func startLeader(t *testing.T, originURL string, max int64) (*Server, *Leader, *Stats) {
	t.Helper()
	dir := t.TempDir()
	cert, fp, err := LoadOrCreateCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	stats := &Stats{}
	st, err := OpenStore(filepath.Join(dir, "cas"), max, stats)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(ServerConfig{Store: st, Origin: originURL, Cert: cert, Stats: stats,
		Tokens: func() []string { return []string{"tok-today", "tok-yesterday"} }})
	if err := srv.Start(0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv, &Leader{Addr: "127.0.0.1:" + strconv.Itoa(srv.Port()), ID: "leader-1", Fingerprint: fp, Token: "tok-today"}, stats
}

// do asks the leader directly over HTTPS with the pinned certificate.
func do(t *testing.T, l *Leader, path, token, originHdr string, hdr map[string]string) (int, []byte) {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: PinnedTLS(l.Fingerprint)}}
	req, _ := http.NewRequest("GET", "https://"+l.Addr+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if originHdr != "" {
		req.Header.Set("X-Origin", originHdr)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestCASPutAndChunkIndex(t *testing.T) {
	s := newStore(t, 0)
	data := testData(2*ChunkSize+777, 1)
	sum := sumHex(data)
	if err := s.Put(sum, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(sum) || !s.Has(strings.ToUpper(sum)) {
		t.Fatal("a stored artifact must be found by its hash in either case")
	}
	idx, err := s.Index(sum)
	if err != nil {
		t.Fatal(err)
	}
	if idx.Size != int64(len(data)) || len(idx.Chunks) != 3 {
		t.Fatalf("index size %d with %d chunks, want %d with 3", idx.Size, len(idx.Chunks), len(data))
	}
	for i, c := range idx.Chunks {
		end := min((i+1)*ChunkSize, len(data))
		if c != sumHex(data[i*ChunkSize:end]) {
			t.Fatalf("chunk %d hash is wrong", i)
		}
	}
	// A deleted index is rebuilt from the artifact.
	os.Remove(filepath.Join(s.Dir(), sum+".idx"))
	idx2, err := s.Index(sum)
	if err != nil || strings.Join(idx2.Chunks, ",") != strings.Join(idx.Chunks, ",") {
		t.Fatalf("index was not rebuilt identically: %v", err)
	}
}

func TestCASHashMismatchRefused(t *testing.T) {
	s := newStore(t, 0)
	data := testData(5000, 2)
	other := sumHex(testData(5000, 3))
	err := s.Put(other, bytes.NewReader(data))
	if _, ok := err.(*MismatchError); !ok {
		t.Fatalf("want a MismatchError, got %v", err)
	}
	if s.Has(other) {
		t.Fatal("a mismatching artifact must not be kept")
	}
	if tmps, _ := filepath.Glob(filepath.Join(s.Dir(), ".fill-*")); len(tmps) != 0 {
		t.Fatalf("temporary files left behind: %v", tmps)
	}
}

func TestCASLRUEviction(t *testing.T) {
	s := newStore(t, 3000)
	var sums []string
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 3; i++ {
		d := testData(1000, int64(10+i))
		sum := sumHex(d)
		if err := s.Put(sum, bytes.NewReader(d)); err != nil {
			t.Fatal(err)
		}
		// Older first: artifact 0 is the least recently used.
		os.Chtimes(filepath.Join(s.Dir(), sum), base.Add(time.Duration(i)*time.Minute), base.Add(time.Duration(i)*time.Minute))
		sums = append(sums, sum)
	}
	// Index files count toward the budget, so three artifacts are already over.
	s.SetMax(2300)
	if s.Has(sums[0]) {
		t.Fatal("the least recently used artifact should have been evicted")
	}
	if !s.Has(sums[1]) || !s.Has(sums[2]) {
		t.Fatal("newer artifacts should have been kept")
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), sums[0]+".idx")); err == nil {
		t.Fatal("an evicted artifact's index must go with it")
	}

	// An artifact in use is skipped even when it is the oldest.
	f, _, release, err := s.Acquire(sums[1])
	if err != nil {
		t.Fatal(err)
	}
	_ = f
	os.Chtimes(filepath.Join(s.Dir(), sums[1]), base, base)
	s.SetMax(1200)
	if !s.Has(sums[1]) {
		t.Fatal("an artifact being streamed must not be evicted")
	}
	release()

	// An artifact over the whole budget is refused up front rather than stored
	// and then kept past the limit.
	big := testData(5000, 99)
	if err := s.Put(sumHex(big), bytes.NewReader(big)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an artifact over the budget returned %v, want ErrTooLarge", err)
	}
}

func TestCASSingleFlightFill(t *testing.T) {
	s := newStore(t, 0)
	data := testData(300000, 4)
	sum := sumHex(data)
	var calls atomic.Int64
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.Fill(context.Background(), sum, func(context.Context) (io.ReadCloser, error) {
				calls.Add(1)
				time.Sleep(150 * time.Millisecond)
				return io.NopCloser(bytes.NewReader(data)), nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("eight concurrent fills ran the fetch %d times, want 1", calls.Load())
	}
	if !s.Has(sum) {
		t.Fatal("the artifact should be stored")
	}
}

func TestServerFillTokenRangeAndChunks(t *testing.T) {
	data := testData(2*ChunkSize+4321, 5)
	sum := sumHex(data)
	o := newOrigin(t, data, 0)
	srv, l, stats := startLeader(t, o.URL, 0)
	_ = srv
	originURL := o.URL + "/agent.exe"

	if st, _ := do(t, l, "/cas/"+sum+"/index", "", originURL, nil); st != 401 {
		t.Fatalf("no token: got %d, want 401", st)
	}
	if st, _ := do(t, l, "/cas/"+sum+"/index", "wrong", originURL, nil); st != 401 {
		t.Fatalf("wrong token: got %d, want 401", st)
	}
	if o.hits.Load() != 0 {
		t.Fatal("an unauthenticated request must never reach the origin")
	}
	if st, _ := do(t, l, "/cas/"+sum+"/index", "tok-today", "", nil); st != 404 {
		t.Fatalf("a miss without X-Origin: got %d, want 404", st)
	}
	st, body := do(t, l, "/cas/"+sum+"/index", "tok-yesterday", originURL, nil)
	if st != 200 {
		t.Fatalf("index: got %d: %s", st, body)
	}
	var idx Index
	if err := json.Unmarshal(body, &idx); err != nil || len(idx.Chunks) != 3 || idx.Size != int64(len(data)) {
		t.Fatalf("bad index %+v: %v", idx, err)
	}
	st, body = do(t, l, "/cas/"+sum, "tok-today", "", nil)
	if st != 200 || !bytes.Equal(body, data) {
		t.Fatalf("whole file: status %d, equal=%v", st, bytes.Equal(body, data))
	}
	st, body = do(t, l, "/cas/"+sum, "tok-today", "", map[string]string{"Range": "bytes=100-199"})
	if st != 206 || !bytes.Equal(body, data[100:200]) {
		t.Fatalf("range: status %d, equal=%v", st, bytes.Equal(body, data[100:200]))
	}
	st, body = do(t, l, "/cas/"+sum+"/chunk/2", "tok-today", "", nil)
	if st != 200 || !bytes.Equal(body, data[2*ChunkSize:]) {
		t.Fatalf("last chunk: status %d, len %d", st, len(body))
	}
	if st, _ := do(t, l, "/cas/"+sum+"/chunk/3", "tok-today", "", nil); st != 404 {
		t.Fatalf("chunk past the end: got %d, want 404", st)
	}
	if st, _ := do(t, l, "/cas/not-a-hash/index", "tok-today", originURL, nil); st != 400 {
		t.Fatalf("bad hash: got %d, want 400", st)
	}
	if o.hits.Load() != 1 {
		t.Fatalf("the origin was asked %d times, want 1", o.hits.Load())
	}
	if stats.Misses.Load() != 2 || stats.Hits.Load() < 2 || stats.BytesServed.Load() < int64(len(data)) || stats.BytesStored.Load() != int64(len(data)) {
		t.Fatalf("stats off: hits %d misses %d served %d stored %d", stats.Hits.Load(), stats.Misses.Load(), stats.BytesServed.Load(), stats.BytesStored.Load())
	}
}

func TestServerOriginRestriction(t *testing.T) {
	data := testData(1000, 6)
	sum := sumHex(data)
	good := newOrigin(t, data, 0)
	evil := newOrigin(t, data, 0)
	_, l, _ := startLeader(t, good.URL, 0)

	for _, bad := range []string{evil.URL + "/x", "file:///etc/passwd", "http://user:pw@" + strings.TrimPrefix(good.URL, "http://") + "/x", "https://" + strings.TrimPrefix(good.URL, "http://") + "/x"} {
		if st, _ := do(t, l, "/cas/"+sum+"/index", "tok-today", bad, nil); st != 403 {
			t.Fatalf("origin %q: got %d, want 403", bad, st)
		}
	}
	if evil.hits.Load() != 0 || good.hits.Load() != 0 {
		t.Fatalf("a refused origin must not be fetched (evil %d, good %d)", evil.hits.Load(), good.hits.Load())
	}
	if st, _ := do(t, l, "/cas/"+sum+"/index", "tok-today", good.URL+"/ok", nil); st != 200 {
		t.Fatalf("the configured origin must work, got %d", st)
	}
}

func TestServerRefusesHashMismatchFill(t *testing.T) {
	data := testData(1000, 7)
	o := newOrigin(t, data, 0)
	_, l, _ := startLeader(t, o.URL, 0)
	wrong := sumHex(testData(1000, 8))
	st, body := do(t, l, "/cas/"+wrong+"/index", "tok-today", o.URL+"/x", nil)
	if st != 502 || !strings.Contains(string(body), "does not match") {
		t.Fatalf("want 502 with the mismatch, got %d: %s", st, body)
	}
	if st, _ := do(t, l, "/cas/"+wrong, "tok-today", "", nil); st != 404 {
		t.Fatalf("the bad artifact must not be stored, got %d", st)
	}
}

func TestServerConcurrentFillsShareOneDownload(t *testing.T) {
	data := testData(ChunkSize+10, 9)
	sum := sumHex(data)
	o := newOrigin(t, data, 300*time.Millisecond)
	_, l, _ := startLeader(t, o.URL, 0)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st, b := do(t, l, "/cas/"+sum+"/index", "tok-today", o.URL+"/a", nil); st != 200 {
				t.Errorf("concurrent index: %d %s", st, b)
			}
		}()
	}
	wg.Wait()
	if o.hits.Load() != 1 {
		t.Fatalf("six concurrent requests caused %d origin downloads, want 1", o.hits.Load())
	}
}

func TestCertPersistsAndPins(t *testing.T) {
	dir := t.TempDir()
	_, fp1, err := LoadOrCreateCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := LoadOrCreateCert(dir)
	if err != nil || fp1 != fp2 {
		t.Fatalf("the certificate must survive a restart: %s vs %s (%v)", fp1, fp2, err)
	}
	if len(fp1) != 64 {
		t.Fatalf("fingerprint %q is not a SHA-256", fp1)
	}
}

func fetchTo(t *testing.T, c *Client, originURL, sum string) (Result, []byte, error) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "artifact")
	res, err := c.Fetch(context.Background(), originURL, sum, dst)
	if err != nil {
		return res, nil, err
	}
	b, rerr := os.ReadFile(dst)
	if rerr != nil {
		t.Fatal(rerr)
	}
	return res, b, nil
}

func TestFetchFromLeaderOverHTTPSAndHTTP3(t *testing.T) {
	data := testData(2*ChunkSize+99, 11)
	sum := sumHex(data)
	o := newOrigin(t, data, 0)
	srv, l, _ := startLeader(t, o.URL, 0)
	for _, tr := range []string{"https", "h3"} {
		if tr == "h3" && !srv.HTTP3() {
			t.Skip("the UDP listener is unavailable in this environment")
		}
		stats := &Stats{}
		c := &Client{Leader: l, Stats: stats, Transports: []string{tr}, RetryDelay: 10 * time.Millisecond}
		res, got, err := fetchTo(t, c, o.URL+"/agent.exe", sum)
		if err != nil {
			t.Fatalf("%s: %v", tr, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("%s: the downloaded bytes differ", tr)
		}
		if res.Source != "cache" || res.Transport != tr || res.LeaderID != "leader-1" || stats.Hits.Load() != 1 {
			t.Fatalf("%s: result %+v hits %d", tr, res, stats.Hits.Load())
		}
	}
	if o.hits.Load() != 1 {
		t.Fatalf("two member fetches cost the origin %d downloads, want 1", o.hits.Load())
	}
}

func TestFetchHTTP3FallsBackToHTTPS(t *testing.T) {
	data := testData(5000, 12)
	sum := sumHex(data)
	o := newOrigin(t, data, 0)
	srv, l, _ := startLeader(t, o.URL, 0)
	// Take the UDP side away: the leader only answers on TCP.
	if srv.h3 != nil {
		srv.h3.Close()
	}
	c := &Client{Leader: l, RetryDelay: 10 * time.Millisecond}
	res, got, err := fetchTo(t, c, o.URL+"/a", sum)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("fetch failed: %v", err)
	}
	if res.Source != "cache" || res.Transport != "https" {
		t.Fatalf("want the cache over https after h3 failed, got %+v", res)
	}
}

// cuttingLeader wraps a real leader's handler and aborts the first response
// for one chunk halfway through, counting every chunk request.
func cuttingLeader(t *testing.T, inner http.Handler, fingerprintCert tls.Certificate, cutChunk string) (*Leader, map[string]*atomic.Int64) {
	t.Helper()
	counts := map[string]*atomic.Int64{"0": {}, "1": {}, "2": {}}
	var cut atomic.Bool
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; strings.Contains(p, "/chunk/") {
			i := p[strings.LastIndex(p, "/chunk/")+len("/chunk/"):]
			if c := counts[i]; c != nil {
				c.Add(1)
			}
			if i == cutChunk && cut.CompareAndSwap(false, true) {
				rec := httptest.NewRecorder()
				inner.ServeHTTP(rec, r)
				w.Header().Set("Content-Length", strconv.Itoa(rec.Body.Len()))
				w.WriteHeader(200)
				w.Write(rec.Body.Bytes()[:rec.Body.Len()/2])
				panic(http.ErrAbortHandler)
			}
		}
		inner.ServeHTTP(w, r)
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{fingerprintCert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	host := strings.TrimPrefix(ts.URL, "https://")
	return &Leader{Addr: host, ID: "cutter", Fingerprint: Fingerprint(fingerprintCert.Certificate[0]), Token: "tok-today"}, counts
}

func TestFetchResumesAfterCutChunk(t *testing.T) {
	data := testData(2*ChunkSize+500, 13)
	sum := sumHex(data)
	o := newOrigin(t, data, 0)
	dir := t.TempDir()
	cert, _, _ := LoadOrCreateCert(dir)
	st, _ := OpenStore(filepath.Join(dir, "cas"), 0, nil)
	real := NewServer(ServerConfig{Store: st, Origin: o.URL, Cert: cert, Tokens: func() []string { return []string{"tok-today"} }})
	t.Cleanup(real.Close)
	l, counts := cuttingLeader(t, real.Handler(), cert, "1")

	c := &Client{Leader: l, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond}
	res, got, err := fetchTo(t, c, o.URL+"/a", sum)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("fetch failed: %v", err)
	}
	if res.Source != "cache" || res.Resumed != 1 {
		t.Fatalf("want a cache fetch resuming after chunk 0, got %+v", res)
	}
	if counts["0"].Load() != 1 || counts["1"].Load() != 2 || counts["2"].Load() != 1 {
		t.Fatalf("chunk requests 0/1/2 = %d/%d/%d, want 1/2/1", counts["0"].Load(), counts["1"].Load(), counts["2"].Load())
	}
}

func TestFetchFallsBackToOrigin(t *testing.T) {
	data := testData(5000, 14)
	sum := sumHex(data)
	o := newOrigin(t, data, 0)

	// A leader that is not there.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := ln.Addr().String()
	ln.Close()
	stats := &Stats{}
	c := &Client{Leader: &Leader{Addr: dead, ID: "gone", Fingerprint: strings.Repeat("a", 64), Token: "t"}, Stats: stats, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond}
	res, got, err := fetchTo(t, c, o.URL+"/a", sum)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("fetch failed: %v", err)
	}
	if res.Source != "origin" || res.Fallback == "" || stats.Misses.Load() != 1 || stats.Hits.Load() != 0 {
		t.Fatalf("want an origin fetch that says why, got %+v misses %d", res, stats.Misses.Load())
	}

	// A leader whose certificate is not the pinned one.
	_, l, _ := startLeader(t, o.URL, 0)
	l.Fingerprint = strings.Repeat("b", 64)
	c = &Client{Leader: l, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond}
	res, got, err = fetchTo(t, c, o.URL+"/a", sum)
	if err != nil || !bytes.Equal(got, data) || res.Source != "origin" || !strings.Contains(res.Fallback, "fingerprint") {
		t.Fatalf("a wrong pin must fall back to the origin: %+v %v", res, err)
	}

	// A wrong token is refused by the leader and also falls back.
	_, l, _ = startLeader(t, o.URL, 0)
	l.Token = "stolen"
	c = &Client{Leader: l, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond}
	res, _, err = fetchTo(t, c, o.URL+"/a", sum)
	if err != nil || res.Source != "origin" {
		t.Fatalf("a wrong token must fall back to the origin: %+v %v", res, err)
	}
}

func TestFetchRejectsLeaderServingWrongBytes(t *testing.T) {
	good := testData(ChunkSize+100, 15)
	sum := sumHex(good)
	o := newOrigin(t, good, 0)
	// A leader whose index and chunks agree with each other but are not the
	// artifact the server named.
	evil := testData(ChunkSize+100, 16)
	idx := Index{Size: int64(len(evil)), ChunkSize: ChunkSize, Chunks: []string{sumHex(evil[:ChunkSize]), sumHex(evil[ChunkSize:])}}
	dir := t.TempDir()
	cert, _, _ := LoadOrCreateCert(dir)
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/index"):
			json.NewEncoder(w).Encode(idx)
		case strings.HasSuffix(r.URL.Path, "/chunk/0"):
			w.Write(evil[:ChunkSize])
		case strings.HasSuffix(r.URL.Path, "/chunk/1"):
			w.Write(evil[ChunkSize:])
		}
	}))
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	defer ts.Close()
	l := &Leader{Addr: strings.TrimPrefix(ts.URL, "https://"), ID: "evil", Fingerprint: Fingerprint(cert.Certificate[0]), Token: "x"}
	c := &Client{Leader: l, Transports: []string{"https"}, RetryDelay: 10 * time.Millisecond}
	res, got, err := fetchTo(t, c, o.URL+"/a", sum)
	if err != nil || !bytes.Equal(got, good) {
		t.Fatalf("the member must end with the real artifact: %v", err)
	}
	if res.Source != "origin" || !strings.Contains(res.Fallback, "does not match") {
		t.Fatalf("want an origin fetch after the leader's bytes failed the hash, got %+v", res)
	}
}

func TestFetchWithoutLeaderUsesOriginAndChecksHash(t *testing.T) {
	data := testData(3000, 17)
	o := newOrigin(t, data, 0)
	c := &Client{}
	res, got, err := fetchTo(t, c, o.URL+"/a", sumHex(data))
	if err != nil || !bytes.Equal(got, data) || res.Source != "origin" || res.Fallback != "" {
		t.Fatalf("plain origin fetch: %+v %v", res, err)
	}
	dst := filepath.Join(t.TempDir(), "x")
	if _, err := c.Fetch(context.Background(), o.URL+"/a", sumHex(testData(3000, 18)), dst); err == nil {
		t.Fatal("an origin download that does not match the hash must fail")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("a mismatching download must not be left at the destination")
	}
}

func TestPutRefusesAnArtifactOverTheBudgetAndLeavesNothing(t *testing.T) {
	s := newStore(t, 1000)
	data := testData(5000, 7)
	if err := s.Admit(int64(len(data))); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Admit over the budget returned %v, want ErrTooLarge", err)
	}
	// A body that claims no length must still be cut off at the budget.
	if err := s.Put(sumHex(data), bytes.NewReader(data)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Put over the budget returned %v, want ErrTooLarge", err)
	}
	if s.Has(sumHex(data)) {
		t.Fatal("an oversized artifact was kept")
	}
	if left, _ := filepath.Glob(filepath.Join(s.Dir(), ".fill-*")); len(left) != 0 {
		t.Fatalf("temporary files remain: %v", left)
	}
}

func TestOpenStoreSweepsAnIndexWithoutItsArtifact(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(dir, sumHex([]byte("gone"))+".idx")
	if err := os.WriteFile(orphan, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir, 1000, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("the orphan index was not removed: %v", err)
	}
}
