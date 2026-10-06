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
	"time"

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
	var client *supervisor.IPCClient
	if len(ipc) > 0 && ipc[0] != nil {
		client = ipc[0]
	}
	return ApplyStagedUpdate(ctx, cfg, req, client)
}

// ApplyStagedUpdate executes the full staged update workflow.
func ApplyStagedUpdate(ctx context.Context, cfg *Config, req protocol.AgentUpdate, ipc *supervisor.IPCClient) error {
	// Pre-flight check: SHA-256 must be exactly 64 hex characters
	if !sha256HexRE.MatchString(req.SHA256) {
		return errors.New("agent update: sha256 must be 64 hex characters")
	}

	// Pre-flight check: URL scheme and server trust boundaries
	if err := checkUpdateURL(cfg.ServerURL, req.URL); err != nil {
		return err
	}

	// Standalone fallback handling
	if ipc == nil {
		if os.Getenv("RMM_ALLOW_LEGACY_UPDATE") == "1" {
			slog.Warn("supervisor IPC not available, falling back to legacy in-place update")
			return doLegacySelfUpdate(ctx, cfg, req.URL, req.SHA256)
		}
		slog.Warn("self-update unavailable in standalone mode: supervisor IPC required",
			"url", req.URL,
			"version", req.Version,
		)
		return errors.New("self-update unavailable: agent is running in standalone mode without supervisor IPC")
	}

	// Step 1: Query supervisor for inactive slot path over IPC
	resp, err := ipc.RoundTrip(&supervisor.IPCMessage{
		Type: supervisor.MsgGetInactive,
		PID:  os.Getpid(),
	})
	if err != nil {
		return fmt.Errorf("query inactive slot from supervisor: %w", err)
	}
	if resp.Type != supervisor.MsgInactiveResp || resp.Path == "" {
		return fmt.Errorf("unexpected supervisor response for inactive slot: type=%s, path=%s", resp.Type, resp.Path)
	}

	inactiveDir := resp.Path
	slog.Info("staging agent update into inactive partition",
		"slot", resp.Slot,
		"dir", inactiveDir,
		"target_version", req.Version,
	)

	// Step 2: Download binary payload with TLS pinning
	client := &http.Client{
		Timeout:   10 * time.Minute,
		Transport: &http.Transport{TLSClientConfig: TLSConfig(cfg.Fingerprint)},
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, req.URL, nil)
	if err != nil {
		return fmt.Errorf("create download request: %w", err)
	}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("download update payload: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %s", httpResp.Status)
	}

	// Step 3: Stream payload into inactive slot with header sniffing and checksum verification
	targetBin := filepath.Join(inactiveDir, supervisor.BinaryExecutableName)
	if err := stageBinaryToSlot(httpResp.Body, inactiveDir, targetBin, req.SHA256); err != nil {
		return fmt.Errorf("stage binary into %s: %w", inactiveDir, err)
	}

	slog.Info("agent update binary verified and staged",
		"binary", targetBin,
		"sha256", req.SHA256,
		"version", req.Version,
	)

	// Step 4: Request supervisor restart and slot flip
	restartMsg := &supervisor.IPCMessage{
		Type:    supervisor.MsgRequestRestart,
		PID:     os.Getpid(),
		Reason:  "update_staged",
		Version: req.Version,
	}
	if err := ipc.Send(restartMsg); err != nil {
		return fmt.Errorf("send restart request to supervisor: %w", err)
	}

	// Step 5: Schedule graceful worker exit to allow server reply flush
	scheduleWorkerExit(req.Version)

	return nil
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
