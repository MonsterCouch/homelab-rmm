package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MonsterCouch/homelab-rmm/internal/portalpipe"
)

// startPortalPipe serves client portal passes to the tray app (Windows only;
// a no-op elsewhere).
func (a *Agent) startPortalPipe(ctx context.Context) {
	portalpipe.Serve(ctx, portalpipe.Name, func(ctx context.Context, acct portalpipe.Account) (string, error) {
		return a.requestPortalPass(ctx, acct.User, acct.Local)
	})
}

// requestPortalPass asks the server, authenticated by this agent's key, for a
// one-time client portal pass for user on this device.
func (a *Agent) requestPortalPass(ctx context.Context, user string, workgroup bool) (string, error) {
	base := a.cfg.ServerURL
	if !strings.HasPrefix(base, "https://") && !strings.HasPrefix(base, "http://") {
		base = "https://" + base
	}
	body, _ := json.Marshal(map[string]any{"user": user, "is_workgroup": workgroup})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/api/agent/portal-pass", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.Key)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: TLSConfig(a.cfg.Fingerprint)}}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server said %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Pass string `json:"pass"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.Pass == "" {
		return "", fmt.Errorf("bad pass reply: %s", data)
	}
	return out.Pass, nil
}
