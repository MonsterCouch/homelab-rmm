package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Leader is the subnet leader a member was assigned.
type Leader struct {
	Addr        string // host:port
	ID          string
	Fingerprint string // SHA-256 of the leader certificate, pinned
	Token       string // bearer token for the day
}

// Result says where the bytes of a Fetch came from, so the update path can
// tell the operator.
type Result struct {
	Source    string // "cache" or "origin"
	Transport string // "h3" or "https" for the cache, "" for the origin
	LeaderID  string
	// Bytes is what was transferred in this call; Resumed is how many chunks
	// an earlier interrupted attempt had already stored and were reused.
	Bytes   int64
	Resumed int
	// Fallback is why the cache was not used when a leader was assigned but
	// the origin served the bytes.
	Fallback string
}

// Client fetches artifacts, from the leader when one is assigned and from the
// origin otherwise.
type Client struct {
	// Leader is nil when this device has no leader (the feature is off, or it
	// is alone on its subnet).
	Leader *Leader
	// OriginClient downloads from the origin URL and carries the agent's
	// certificate pin. Nil means a plain client.
	OriginClient *http.Client
	// Stats receives Hits when the leader served a fetch and Misses when it
	// did not and the origin did. May be nil.
	Stats *Stats
	// RetryDelay is the pause before the one retry (default 1s).
	RetryDelay time.Duration
	// Transports overrides the leader transports tried, in order; the default
	// is HTTP/3 then HTTPS. Tests use it to exercise one at a time.
	Transports []string
}

// errBadArtifact marks a fetch whose whole-file hash did not match: the leader
// is not retried, because a second attempt would fetch the same bytes.
var errBadArtifact = errors.New("the leader sent an artifact that does not match its hash")

// Fetch downloads rawURL, which must hash to sum, into dst. With a leader it
// tries HTTP/3 then HTTPS chunk by chunk, verifying each chunk against the
// leader's index and the whole file against sum, resuming an interrupted
// transfer from the last verified chunk; after one retry, or on any failure,
// it downloads from the origin as an agent without a cache would. Integrity
// never depends on the leader: sum is the hash the server named.
func (c *Client) Fetch(ctx context.Context, rawURL, sum, dst string) (Result, error) {
	sum, ok := NormalizeSum(sum)
	if !ok {
		return Result{}, errors.New("the artifact hash is not a SHA-256")
	}
	var why string
	if c.Leader != nil && c.Leader.Addr != "" {
		res, err := c.fromLeader(ctx, rawURL, sum, dst)
		if err == nil {
			if c.Stats != nil {
				c.Stats.Hits.Add(1)
			}
			return res, nil
		}
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		why = err.Error()
		slog.Warn("the subnet cache could not serve the download, using the origin", "leader", c.Leader.ID, "addr", c.Leader.Addr, "err", err)
		if c.Stats != nil {
			c.Stats.Misses.Add(1)
		}
	}
	res, err := c.fromOrigin(ctx, rawURL, sum, dst)
	res.Fallback = why
	return res, err
}

func (c *Client) fromOrigin(ctx context.Context, rawURL, sum, dst string) (Result, error) {
	cl := c.OriginClient
	if cl == nil {
		cl = &http.Client{Timeout: 10 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("create the download request: %w", err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("download from the origin: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("download failed: HTTP %s", resp.Status)
	}
	part := dst + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("create the download file: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(part)
		return Result{}, fmt.Errorf("download from the origin: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		os.Remove(part)
		return Result{}, &MismatchError{Want: sum, Got: got}
	}
	if err := os.Rename(part, dst); err != nil {
		os.Remove(part)
		return Result{}, fmt.Errorf("move the download into place: %w", err)
	}
	return Result{Source: "origin", Bytes: n}, nil
}

func (c *Client) fromLeader(ctx context.Context, rawURL, sum, dst string) (Result, error) {
	transports := c.Transports
	if len(transports) == 0 {
		transports = []string{"h3", "https"}
	}
	delay := c.RetryDelay
	if delay <= 0 {
		delay = time.Second
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			case <-time.After(delay):
			}
		}
		for _, tr := range transports {
			res, err := c.leaderOnce(ctx, tr, rawURL, sum, dst)
			if err == nil {
				return res, nil
			}
			lastErr = fmt.Errorf("%s: %w", tr, err)
			if errors.Is(err, errBadArtifact) || ctx.Err() != nil {
				return Result{}, lastErr
			}
		}
	}
	return Result{}, lastErr
}

// maxArtifact bounds what an index may claim, so a hostile leader cannot make
// a member plan for an absurd download.
const maxArtifact = 8 << 30

func (c *Client) httpClient(transport string) (*http.Client, func(), error) {
	pin := PinnedTLS(c.Leader.Fingerprint)
	switch transport {
	case "https":
		tr := &http.Transport{TLSClientConfig: pin, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second}
		return &http.Client{Transport: tr}, tr.CloseIdleConnections, nil
	case "h3":
		tr := &http3.Transport{TLSClientConfig: pin, QUICConfig: &quic.Config{HandshakeIdleTimeout: 4 * time.Second, MaxIdleTimeout: 30 * time.Second}}
		return &http.Client{Transport: tr}, func() { _ = tr.Close() }, nil
	}
	return nil, nil, fmt.Errorf("unknown cache transport %q", transport)
}

func (c *Client) get(ctx context.Context, cl *http.Client, path, origin string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+c.Leader.Addr+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Leader.Token)
	req.Header.Set("X-Origin", origin)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("the leader answered %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

func (c *Client) leaderOnce(ctx context.Context, transport, rawURL, sum, dst string) (Result, error) {
	cl, closeFn, err := c.httpClient(transport)
	if err != nil {
		return Result{}, err
	}
	defer closeFn()

	// The index request is the one that makes the leader fill from the
	// origin, which can take as long as the WAN download does.
	ictx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	resp, err := c.get(ictx, cl, "/cas/"+sum+"/index", rawURL)
	if err != nil {
		cancel()
		return Result{}, err
	}
	var idx Index
	err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&idx)
	resp.Body.Close()
	cancel()
	if err != nil {
		return Result{}, fmt.Errorf("read the chunk index: %w", err)
	}
	n := int((idx.Size + ChunkSize - 1) / ChunkSize)
	if idx.ChunkSize != ChunkSize || idx.Size <= 0 || idx.Size > maxArtifact || len(idx.Chunks) != n {
		return Result{}, errors.New("the leader sent a chunk index that is not valid")
	}
	for _, h := range idx.Chunks {
		if _, ok := NormalizeSum(h); !ok {
			return Result{}, errors.New("the leader sent a chunk index that is not valid")
		}
	}

	part := dst + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return Result{}, fmt.Errorf("create the download file: %w", err)
	}
	defer f.Close()
	have, err := verifiedChunks(f, idx)
	if err != nil {
		return Result{}, err
	}
	if err := f.Truncate(chunkEnd(idx, have)); err != nil {
		return Result{}, fmt.Errorf("trim the download file: %w", err)
	}
	if _, err := f.Seek(chunkEnd(idx, have), io.SeekStart); err != nil {
		return Result{}, err
	}
	res := Result{Source: "cache", Transport: transport, LeaderID: c.Leader.ID, Resumed: have}

	for i := have; i < n; i++ {
		want := chunkEnd(idx, i+1) - chunkEnd(idx, i)
		cctx, ccancel := context.WithTimeout(ctx, 5*time.Minute)
		resp, err := c.get(cctx, cl, fmt.Sprintf("/cas/%s/chunk/%d", sum, i), rawURL)
		if err != nil {
			ccancel()
			return res, err
		}
		buf, err := io.ReadAll(io.LimitReader(resp.Body, want+1))
		resp.Body.Close()
		ccancel()
		if err != nil {
			return res, fmt.Errorf("read chunk %d: %w", i, err)
		}
		if int64(len(buf)) != want {
			return res, fmt.Errorf("chunk %d is %d bytes, expected %d", i, len(buf), want)
		}
		got := sha256.Sum256(buf)
		if hex.EncodeToString(got[:]) != idx.Chunks[i] {
			return res, fmt.Errorf("chunk %d does not match the leader's index", i)
		}
		if _, err := f.Write(buf); err != nil {
			return res, fmt.Errorf("store chunk %d: %w", i, err)
		}
		res.Bytes += int64(len(buf))
	}

	if err := f.Sync(); err != nil {
		return res, fmt.Errorf("flush the download file: %w", err)
	}
	// The whole file is checked against the hash the server named, not the
	// leader's index: a leader that lied consistently in both is caught here.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return res, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return res, fmt.Errorf("verify the download: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		f.Close()
		os.Remove(part)
		return res, fmt.Errorf("%w: expected %s, got %s", errBadArtifact, sum, got)
	}
	if err := f.Close(); err != nil {
		return res, fmt.Errorf("close the download file: %w", err)
	}
	if err := os.Rename(part, dst); err != nil {
		return res, fmt.Errorf("move the download into place: %w", err)
	}
	return res, nil
}

// chunkEnd is the byte offset where chunk i-1 ends, i.e. where chunk i starts.
func chunkEnd(idx Index, i int) int64 { return min(int64(i)*ChunkSize, idx.Size) }

// verifiedChunks counts the leading chunks of a partial file that are whole
// and match the index; the transfer resumes after them.
func verifiedChunks(f *os.File, idx Index) (int, error) {
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	have := 0
	for i := range idx.Chunks {
		start, end := chunkEnd(idx, i), chunkEnd(idx, i+1)
		if end > st.Size() {
			break
		}
		buf := make([]byte, end-start)
		if _, err := f.ReadAt(buf, start); err != nil {
			break
		}
		got := sha256.Sum256(buf)
		if hex.EncodeToString(got[:]) != idx.Chunks[i] {
			break
		}
		have++
	}
	return have, nil
}
