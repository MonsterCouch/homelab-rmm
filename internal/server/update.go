package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

type ServerVersionInfo struct {
	Version      string        `json:"version"`
	OS           string        `json:"os"`
	Arch         string        `json:"arch"`
	PID          int           `json:"pid"`
	ExePath      string        `json:"exe_path"`
	StagedUpdate *StagedUpdate `json:"staged_update,omitempty"`
}

type StagedUpdate struct {
	Available bool   `json:"available"`
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ModTime   int64  `json:"mod_time"`
	SHA256    string `json:"sha256"`
	Differs   bool   `json:"differs"`
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func (s *Server) findStagedServerBinary() (string, os.FileInfo, error) {
	binName := "rmm-server"
	if runtime.GOOS == "windows" {
		binName = fmt.Sprintf("rmm-server-%s-%s.exe", runtime.GOOS, runtime.GOARCH)
	} else {
		binName = fmt.Sprintf("rmm-server-%s-%s", runtime.GOOS, runtime.GOARCH)
	}

	candidates := []string{
		filepath.Join(s.cfg.DataDir, "update", binName),
		filepath.Join(s.cfg.DataDir, "update", "rmm-server"),
		filepath.Join(s.cfg.DataDir, "update", "rmm-server.exe"),
	}
	if dev := devDistDir(); dev != "" {
		candidates = append(candidates,
			filepath.Join(dev, binName),
			filepath.Join(dev, "rmm-server"),
			filepath.Join(dev, "rmm-server.exe"),
		)
	}

	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() && st.Size() > 0 {
			return c, st, nil
		}
	}
	return "", nil, errors.New("no staged server binary found")
}

// handleServerVersionInfo reports version and whether a newer build is staged in dist/
func (s *Server) handleServerVersionInfo(w http.ResponseWriter, r *http.Request) {
	exe, _ := os.Executable()
	info := ServerVersionInfo{
		Version: Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
		PID:     os.Getpid(),
		ExePath: exe,
	}

	if stagedPath, st, err := s.findStagedServerBinary(); err == nil {
		curSHA, _ := fileSHA256(exe)
		stagedSHA, _ := fileSHA256(stagedPath)
		info.StagedUpdate = &StagedUpdate{
			Available: true,
			Path:      stagedPath,
			Size:      st.Size(),
			ModTime:   st.ModTime().Unix(),
			SHA256:    stagedSHA,
			Differs:   stagedSHA != "" && curSHA != stagedSHA,
		}
	}

	writeJSON(w, http.StatusOK, info)
}

// handleServerUpdate performs an in-place binary swap of rmm-server and restarts the service
func (s *Server) handleServerUpdate(w http.ResponseWriter, r *http.Request) {
	exe, err := os.Executable()
	if err != nil {
		fail(w, fmt.Errorf("unable to resolve running executable: %w", err))
		return
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err == nil {
		exe = resolved
	}

	stagedPath, _, err := s.findStagedServerBinary()
	if err != nil {
		writeErr(w, http.StatusNotFound, "no staged update binary found; compile first with tools/build.ps1")
		return
	}

	stagedDir := filepath.Dir(stagedPath)
	targetAgentDir := s.cfg.path("agents")
	exeDir := filepath.Dir(exe)
	altAgentDir := filepath.Join(exeDir, "agents")

	// 1. Sync agent binaries from staged directory to server's agents/ folders
	agentFiles, _ := filepath.Glob(filepath.Join(stagedDir, "rmm-agent*"))
	for _, af := range agentFiles {
		base := filepath.Base(af)
		_ = copyFile(af, filepath.Join(targetAgentDir, base))
		if altAgentDir != targetAgentDir {
			_ = copyFile(af, filepath.Join(altAgentDir, base))
		}
	}

	// Also sync desktop tray if present in dist
	desktopFiles := []string{"Homelab-RMM.exe", "Homelab-RMM-Agent.exe"}
	for _, df := range desktopFiles {
		src := filepath.Join(stagedDir, df)
		if st, err := os.Stat(src); err == nil && !st.IsDir() {
			_ = copyFile(src, filepath.Join(exeDir, df))
		}
	}

	// 2. In-place swap server binary
	old := exe + ".old"
	_ = os.Remove(old)
	if err := os.Rename(exe, old); err != nil {
		fail(w, fmt.Errorf("failed to move running executable to .old: %w", err))
		return
	}

	if err := copyFile(stagedPath, exe); err != nil {
		_ = os.Rename(old, exe)
		fail(w, fmt.Errorf("failed to copy new binary into place: %w", err))
		return
	}

	me := userFrom(r.Context())
	uName := "admin"
	if me != nil {
		uName = me.Username
	}
	s.db.Audit(uName, r.RemoteAddr, "server.update", "server", fmt.Sprintf("updated from %s", stagedPath))
	slog.Info("server binary updated successfully, initiating restart", "path", exe, "from", stagedPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "Server binary updated successfully. Restarting service...",
	})

	// 3. Trigger restart after response is sent
	go func() {
		time.Sleep(1 * time.Second)
		if runtime.GOOS == "windows" {
			// Restart Windows service HomelabRMMServer
			_ = exec.Command("cmd.exe", "/c", "timeout /t 1 /nobreak >nul & net stop HomelabRMMServer & net start HomelabRMMServer").Start()
		} else {
			_ = exec.Command("systemctl", "restart", "homelab-rmm-server").Start()
		}
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}()
}

// handleAgentUpdateCheck is called by agents to see if an updated binary is available
func (s *Server) handleAgentUpdateCheck(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeErr(w, http.StatusUnauthorized, "missing agent key")
		return
	}
	agentKey := strings.TrimPrefix(authz, "Bearer ")
	agentID, ok := s.db.agentByKey(agentKey)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown agent key")
		return
	}

	q := r.URL.Query()
	osName := q.Get("os")
	arch := q.Get("arch")
	clientSHA := q.Get("sha256")

	if osName == "" || arch == "" {
		writeErr(w, http.StatusBadRequest, "os and arch required")
		return
	}

	serverSHA := s.agentBinarySHA256(osName, arch)
	binPath := s.agentBinaryPath(osName, arch)
	if serverSHA == "" || binPath == "" {
		writeJSON(w, http.StatusOK, map[string]any{"update_available": false})
		return
	}

	// Update is available if the binary hash differs
	if clientSHA != "" && strings.EqualFold(serverSHA, clientSHA) {
		writeJSON(w, http.StatusOK, map[string]any{"update_available": false})
		return
	}

	filename := filepath.Base(binPath)
	downloadURL := fmt.Sprintf("%s/api/agent-download/%s", s.PublicURL(), filename)

	slog.Info("agent update check: update available", "agent_id", agentID, "os", osName, "arch", arch, "sha", serverSHA)
	writeJSON(w, http.StatusOK, map[string]any{
		"update_available": true,
		"version":          Version,
		"sha256":           serverSHA,
		"url":              downloadURL,
	})
}

// handleDispatchAgentUpdate pushes ReqAgentUpdate to a specific agent
func (s *Server) handleDispatchAgentUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}

	fam := agentOSFamily(a)
	arch := "amd64"
	if a.Inventory != nil && a.Inventory.Arch != "" {
		arch = a.Inventory.Arch
	}

	serverSHA := s.agentBinarySHA256(fam, arch)
	binPath := s.agentBinaryPath(fam, arch)
	if serverSHA == "" || binPath == "" {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("no agent binary available on server for %s/%s", fam, arch))
		return
	}

	downloadURL := fmt.Sprintf("%s/api/agent-download/%s", s.PublicURL(), filepath.Base(binPath))
	req := protocol.AgentUpdate{
		URL:     downloadURL,
		SHA256:  serverSHA,
		Version: Version,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	if err := s.hub.Request(ctx, id, protocol.ReqAgentUpdate, req, nil); err != nil {
		fail(w, fmt.Errorf("failed to dispatch update to agent: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": fmt.Sprintf("Update command sent to agent %s (%s)", a.DisplayName, Version),
	})
}

// handleDispatchAllAgentsUpdate pushes ReqAgentUpdate to all online agents
func (s *Server) handleDispatchAllAgentsUpdate(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		fail(w, err)
		return
	}

	count := 0
	for _, a := range agents {
		if !s.hub.IsOnline(a.ID) {
			continue
		}
		fam := agentOSFamily(a)
		arch := "amd64"
		if a.Inventory != nil && a.Inventory.Arch != "" {
			arch = a.Inventory.Arch
		}
		serverSHA := s.agentBinarySHA256(fam, arch)
		binPath := s.agentBinaryPath(fam, arch)
		if serverSHA == "" || binPath == "" {
			continue
		}
		downloadURL := fmt.Sprintf("%s/api/agent-download/%s", s.PublicURL(), filepath.Base(binPath))
		req := protocol.AgentUpdate{
			URL:     downloadURL,
			SHA256:  serverSHA,
			Version: Version,
		}
		go func(agentID string, uReq protocol.AgentUpdate) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = s.hub.Request(ctx, agentID, protocol.ReqAgentUpdate, uReq, nil)
		}(a.ID, req)
		count++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"dispatched_to": count,
		"message":       fmt.Sprintf("Dispatched update command to %d online agent(s)", count),
	})
}
