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
)

var (
	cachedSelfSHA string
	cachedSHAMu   sync.Mutex
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

// selfUpdate downloads a new binary, verifies its hash and swaps it in next
// to the running one. The service manager restarts the agent afterwards
// (Windows: the service restarts on exit; systemd: Restart=always).
func selfUpdate(ctx context.Context, cfg *Config, req protocol.AgentUpdate) error {
	return doSelfUpdate(ctx, cfg, req.URL, req.SHA256)
}

func doSelfUpdate(ctx context.Context, cfg *Config, binURL, sum string) error {
	// What this installs runs as SYSTEM/root on the next restart, so the hash
	// is not optional: an empty one used to skip verification altogether and
	// leave the download as the only thing standing - over a TLS config that
	// pins nothing when the agent has no fingerprint.
	if !sha256HexRE.MatchString(sum) {
		return errors.New("agent update: sha256 must be 64 hex characters")
	}
	if err := checkUpdateURL(cfg.ServerURL, binURL); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// EvalSymlinks returns ("", err) on failure, and swallowing that left exe
	// empty: the binary was downloaded to a stray ".new" in whatever the
	// service's working directory happens to be, and the swap then failed on
	// a rename with no path in the message.
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
	// A previous generation's image can still be mapped - on Windows the
	// desktop helper runs from the same file and outlives a service restart -
	// and Windows refuses to delete or overwrite a mapped executable. Ignoring
	// that failure left the rename below to hit the same refusal and wedge
	// every future update, so move aside to a name nothing can be holding.
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
	slog.Info("agent update applied successfully, restarting service", "exe", exe)
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
