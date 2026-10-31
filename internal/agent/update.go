package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/agent/cache"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

var (
	cachedSelfSHA string
	cachedSHAMu   sync.Mutex

	// updateExitFunc and updateExitDelay allow deterministic unit testing of worker exit
	updateExitFunc  = os.Exit
	updateExitDelay = 500 * time.Millisecond
)

// currentBinarySHA256 calculates and caches the SHA256 of the running agent executable
func currentBinarySHA256() string {
	cachedSHAMu.Lock()
	defer cachedSHAMu.Unlock()
	if cachedSelfSHA != "" {
		return cachedSelfSHA
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	f, err := os.Open(exe)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	cachedSelfSHA = hex.EncodeToString(h.Sum(nil))
	return cachedSelfSHA
}

// sha256HexRE is a whole SHA-256 in hex and nothing else.
var sha256HexRE = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// selfUpdate downloads a new binary, verifies its hash, and stages it into the inactive slot.
// If running under supervisor, it requests supervisor restart and gracefully exits.
// If running in standalone mode, it adheres to the standalone fallback policy.
func selfUpdate(ctx context.Context, cfg *Config, req protocol.AgentUpdate, ipc ...*supervisor.IPCClient) error {
	_, err := selfUpdateSource(ctx, cfg, req, ipc...)
	return err
}

// selfUpdateSource is selfUpdate that also says where the bytes came from
// ("cache <leader id> over h3", "origin", ...; "" when nothing was
// downloaded), which the agent.update reply carries to the operator.
func selfUpdateSource(ctx context.Context, cfg *Config, req protocol.AgentUpdate, ipc ...*supervisor.IPCClient) (string, error) {
	res, err := selfUpdateResult(ctx, cfg, req, ipc...)
	return res.Source, err
}

// selfUpdateResult is selfUpdate that returns the whole agent.update reply:
// the source, the bytes downloaded and the chunks a retry resumed.
func selfUpdateResult(ctx context.Context, cfg *Config, req protocol.AgentUpdate, ipc ...*supervisor.IPCClient) (protocol.AgentUpdateResult, error) {
	var client *supervisor.IPCClient
	if len(ipc) > 0 && ipc[0] != nil {
		client = ipc[0]
	}
	return applyStagedUpdate(ctx, cfg, req, client)
}

// ApplyStagedUpdate executes the full staged update workflow.
func ApplyStagedUpdate(ctx context.Context, cfg *Config, req protocol.AgentUpdate, ipc *supervisor.IPCClient) error {
	_, err := applyStagedUpdate(ctx, cfg, req, ipc)
	return err
}

func applyStagedUpdate(ctx context.Context, cfg *Config, req protocol.AgentUpdate, ipc *supervisor.IPCClient) (protocol.AgentUpdateResult, error) {
	none := protocol.AgentUpdateResult{Version: req.Version}
	// Pre-flight check: SHA-256 must be exactly 64 hex characters
	if !sha256HexRE.MatchString(req.SHA256) {
		return none, errors.New("agent update: sha256 must be 64 hex characters")
	}

	// Pre-flight check: URL scheme and server trust boundaries
	if err := checkUpdateURL(cfg.ServerURL, req.URL); err != nil {
		return none, err
	}

	// A push of the build this device already runs has nothing to install, and
	// would still download it, flip the slots and restart the worker, so it is
	// answered as done. That comes before the standalone check, because a device
	// that is already on the build has what was asked for whether or not it
	// could have updated itself. The request has passed authorization by now, so
	// this skips no verification.
	if cur := currentBinarySHA256(); cur != "" && strings.EqualFold(cur, req.SHA256) {
		slog.Info("agent update skipped: this device already runs that build", "sha256", req.SHA256, "version", req.Version)
		return none, nil
	}

	// Standalone fallback handling
	if ipc == nil {
		if os.Getenv("RMM_ALLOW_LEGACY_UPDATE") == "1" {
			slog.Warn("supervisor IPC not available, falling back to legacy in-place update")
			return none, doLegacySelfUpdate(ctx, cfg, req.URL, req.SHA256)
		}
		slog.Warn("self-update unavailable in standalone mode: supervisor IPC required",
			"url", req.URL,
			"version", req.Version,
		)
		return none, errors.New("self-update unavailable: agent is running in standalone mode without supervisor IPC")
	}

	// Step 1: Query supervisor for inactive slot path over IPC
	resp, err := ipc.RoundTrip(&supervisor.IPCMessage{
		Type: supervisor.MsgGetInactive,
		PID:  os.Getpid(),
	})
	if err != nil {
		return none, fmt.Errorf("query inactive slot from supervisor: %w", err)
	}
	if resp.Type != supervisor.MsgInactiveResp || resp.Path == "" {
		return none, fmt.Errorf("unexpected supervisor response for inactive slot: type=%s, path=%s", resp.Type, resp.Path)
	}

	inactiveDir := resp.Path
	slog.Info("staging agent update into inactive partition",
		"slot", resp.Slot,
		"dir", inactiveDir,
		"target_version", req.Version,
	)

	// Step 2: Download binary payload with TLS pinning, through the subnet
	// cache leader when this device has one and from the origin otherwise.
	body, res, err := openUpdatePayload(ctx, cfg, req, inactiveDir)
	if err != nil {
		return none, err
	}
	defer body.Close()

	// Step 3: Stream payload into inactive slot with header sniffing and checksum verification
	targetBin := filepath.Join(inactiveDir, supervisor.BinaryExecutableName)
	if err := stageBinaryToSlot(body, inactiveDir, targetBin, req.SHA256); err != nil {
		return none, fmt.Errorf("stage binary into %s: %w", inactiveDir, err)
	}

	slog.Info("agent update binary verified and staged",
		"binary", targetBin,
		"sha256", req.SHA256,
		"version", req.Version,
		"source", res.Source,
	)

	// Step 4: Request supervisor restart and slot flip
	restartMsg := &supervisor.IPCMessage{
		Type:    supervisor.MsgRequestRestart,
		PID:     os.Getpid(),
		Reason:  "update_staged",
		Version: req.Version,
	}
	if err := ipc.Send(restartMsg); err != nil {
		return none, fmt.Errorf("send restart request to supervisor: %w", err)
	}

	// Step 5: Schedule graceful worker exit to allow server reply flush
	scheduleWorkerExit(req.Version)

	return res, nil
}

// updateCache is the subnet cache client the running agent built from its
// cache assignment, nil when it has no leader. It is a package variable
// because selfUpdate is reached from the request dispatcher, the auto-update
// loop and tests alike, none of which can all carry the Agent, and a process
// runs exactly one agent.
var updateCache atomic.Pointer[cache.Client]

// openUpdatePayload opens the bytes of the new binary and says where they
// came from. With a cache leader assigned they come through cache.Fetch,
// which verifies every chunk and the whole file and falls back to the origin
// by itself; the result is read from a temporary file in dir that goes away
// with the returned closer. Without a leader the origin is read directly, as
// before the cache existed.
func openUpdatePayload(ctx context.Context, cfg *Config, req protocol.AgentUpdate, dir string) (io.ReadCloser, protocol.AgentUpdateResult, error) {
	pinned := &http.Transport{TLSClientConfig: TLSConfig(cfg.Fingerprint)}
	if cl := updateCache.Load(); cl != nil && cl.Leader != nil {
		c := *cl
		c.OriginClient = &http.Client{Timeout: 10 * time.Minute, Transport: pinned}
		tmp := filepath.Join(dir, ".cache-fetch.tmp")
		res, err := c.Fetch(ctx, req.URL, req.SHA256, tmp)
		if err != nil {
			os.Remove(tmp + ".part")
			return nil, protocol.AgentUpdateResult{}, fmt.Errorf("download update payload: %w", err)
		}
		f, err := os.Open(tmp)
		if err != nil {
			os.Remove(tmp)
			return nil, protocol.AgentUpdateResult{}, fmt.Errorf("open the downloaded update payload: %w", err)
		}
		source := "origin"
		if res.Source == "cache" {
			source = fmt.Sprintf("cache %s over %s", res.LeaderID, res.Transport)
		} else if res.Fallback != "" {
			source = "origin (the cache failed: " + res.Fallback + ")"
		}
		slog.Info("agent update payload downloaded", "source", source, "bytes", res.Bytes, "resumed_chunks", res.Resumed)
		return &tempFile{File: f, path: tmp}, protocol.AgentUpdateResult{Source: source, Bytes: res.Bytes, ResumedChunks: res.Resumed, Version: req.Version}, nil
	}
	client := &http.Client{Timeout: 10 * time.Minute, Transport: pinned}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return nil, protocol.AgentUpdateResult{}, fmt.Errorf("create download request: %w", err)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, protocol.AgentUpdateResult{}, fmt.Errorf("download update payload: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		httpResp.Body.Close()
		return nil, protocol.AgentUpdateResult{}, fmt.Errorf("download failed: HTTP %s", httpResp.Status)
	}
	return httpResp.Body, protocol.AgentUpdateResult{Source: "origin", Bytes: max(httpResp.ContentLength, 0), Version: req.Version}, nil
}

// tempFile removes its file when closed.
type tempFile struct {
	*os.File
	path string
}

func (t *tempFile) Close() error {
	err := t.File.Close()
	os.Remove(t.path)
	return err
}

// stageBinaryToSlot streams binary payload from r into a temporary staging file in targetDir,
// verifies PE/ELF binary header and SHA-256 digest, sets permissions, and atomically replaces targetBin.
func stageBinaryToSlot(r io.Reader, targetDir, targetBin, expectedSHA string) error {
	tmpFile, err := os.CreateTemp(targetDir, ".stage-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp staging file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	hasher := sha256.New()
	tee := io.TeeReader(r, hasher)

	// Read and validate the first 4 bytes for PE/ELF header magic
	header := make([]byte, 4)
	n, err := io.ReadFull(tee, header)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("read binary header: %w", err)
	}
	if n < 2 {
		return fmt.Errorf("staged binary too small (%d bytes)", n)
	}
	if err := supervisor.ValidateBinaryHeader(header[:n]); err != nil {
		return fmt.Errorf("validate binary header: %w", err)
	}

	// Write header bytes to temp file
	if _, err := tmpFile.Write(header[:n]); err != nil {
		return fmt.Errorf("write binary header: %w", err)
	}

	// Stream remaining binary content
	if _, err := io.Copy(tmpFile, tee); err != nil {
		return fmt.Errorf("stream binary content: %w", err)
	}

	// Verify SHA-256 checksum
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedSHA, actualSHA)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("sync staged binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close staged binary: %w", err)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod staged binary: %w", err)
	}

	if err := replaceBinaryAtomic(tmpPath, targetBin); err != nil {
		return fmt.Errorf("replace staged binary: %w", err)
	}

	if err := supervisor.ValidateBinaryFile(targetBin); err != nil {
		_ = os.Remove(targetBin)
		return fmt.Errorf("validate staged binary file: %w", err)
	}

	cleanedUp = true
	return nil
}

// replaceBinaryAtomic atomically replaces dst with src with retry backoff on Windows.
func replaceBinaryAtomic(src, dst string) error {
	var lastErr error
	for i := 0; i < 5; i++ {
		if err := os.Rename(src, dst); err == nil {
			return nil
		} else {
			lastErr = err
		}
		time.Sleep(10 * time.Millisecond)
	}

	_ = os.Remove(dst)
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return fmt.Errorf("replace binary %s -> %s: %w", src, dst, lastErr)
}

func scheduleWorkerExit(version string) {
	go func() {
		if updateExitDelay > 0 {
			time.Sleep(updateExitDelay)
		}
		slog.Info("agent update staged successfully, worker exiting for supervisor promotion and restart",
			"version", version,
		)
		updateExitFunc(0)
	}()
}

// doSelfUpdate maintains compatibility for legacy callers and unit tests.
func doSelfUpdate(ctx context.Context, cfg *Config, binURL, sum string) error {
	req := protocol.AgentUpdate{
		URL:    binURL,
		SHA256: sum,
	}
	return ApplyStagedUpdate(ctx, cfg, req, nil)
}

// doLegacySelfUpdate implements the legacy in-place file swap for standalone fallback.
func doLegacySelfUpdate(ctx context.Context, cfg *Config, binURL, sum string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", exe, err)
	}
	exe = resolved
	client := &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{TLSClientConfig: TLSConfig(cfg.Fingerprint)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, binURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("download failed: " + resp.Status)
	}
	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), sum) {
		os.Remove(tmp)
		return errors.New("checksum mismatch")
	}
	old := exe + ".old"
	if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
		old = fmt.Sprintf("%s.old.%d", exe, time.Now().UnixNano())
	}
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		os.Remove(tmp)
		return err
	}
	slog.Info("agent update applied successfully in legacy mode, restarting service", "exe", exe)
	go func() {
		time.Sleep(1 * time.Second)
		if runtime.GOOS == "windows" {
			_ = exec.Command("cmd.exe", "/c", "timeout /t 2 /nobreak >nul & net start "+ServiceName).Start()
		}
		os.Exit(1)
	}()
	return nil
}

// checkUpdateURL bounds where a new binary may come from. https is accepted
// (the fingerprint the agent pins is applied to it when there is one), and
// plain http only from the server the agent is already configured to talk to,
// which is the documented --insecure deployment behind a TLS-terminating
// proxy. Anything else - a file://, an ftp://, an http:// host of the
// sender's choosing - is refused before a byte is fetched.
func checkUpdateURL(serverURL, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("agent update: %w", err)
	}
	if u.Host == "" {
		return errors.New("agent update: the url has no host")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if s, err := url.Parse(serverURL); err == nil && s.Host != "" && strings.EqualFold(u.Host, s.Host) {
			return nil
		}
		return errors.New("agent update: a plain http url is only accepted from the configured server")
	}
	return fmt.Errorf("agent update: unsupported url scheme %q", u.Scheme)
}
