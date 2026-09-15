package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// selfUpdate downloads a new binary, verifies its hash and swaps it in next
// to the running one. The service manager restarts the agent afterwards
// (Windows: the service restarts on exit; systemd: Restart=always).
func selfUpdate(ctx context.Context, cfg *Config, req protocol.AgentUpdate) error {
	return doSelfUpdate(ctx, cfg, req.URL, req.SHA256)
}

func doSelfUpdate(ctx context.Context, cfg *Config, url, sum string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	client := &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{TLSClientConfig: TLSConfig(cfg.Fingerprint)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	if sum != "" && hex.EncodeToString(h.Sum(nil)) != sum {
		os.Remove(tmp)
		return errors.New("checksum mismatch")
	}
	old := exe + ".old"
	os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		return err
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe)
		return err
	}
	go func() {
		time.Sleep(2 * time.Second)
		os.Exit(0) // the service manager restarts us on the new binary
	}()
	return nil
}
