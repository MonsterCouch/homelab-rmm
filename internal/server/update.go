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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
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

	// Recorded before anything else is decided, because every mode polls,
	// including an enforcing organization that is never advertised a build.
	s.db.recordBinaryDigest(agentID, clientSHA)

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

	// In an organization that enforces signed actions the device would refuse
	// an install it was merely told about, and report the refusal, so
	// advertising a new build to a whole fleet every five minutes would only
	// raise alerts. Such an organization pushes the build signed from the
	// console (update-batch). Audit mode keeps advertising, because audit
	// exists to show which paths are still unsigned and the device reports the
	// unsigned install. The device still decides for itself; this only removes
	// the noise.
	org := s.agentOrgID(agentID)
	if b := s.activeBundle(org); b != nil && b.Mode() == actionauth.ModeEnforce {
		writeJSON(w, http.StatusOK, map[string]any{
			"update_available":       false,
			"signed_update_required": true,
			"version":                Version,
			"sha256":                 serverSHA,
		})
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

// binaryDigestMaxAge is how long a digest a device reported is believed. The
// device reports every five minutes while it runs, so an older one means it has
// been off or unable to reach the server, and it may have been updated by other
// means meanwhile; asking for a signature is then the safe answer.
const binaryDigestMaxAge = 24 * time.Hour

var hex64Re = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// recordBinaryDigest remembers the digest of the binary a device says it runs.
// Anything that is not a SHA-256 in hex is ignored rather than stored.
func (d *DB) recordBinaryDigest(agentID, sum string) {
	if !hex64Re.MatchString(sum) {
		return
	}
	d.Exec(`UPDATE agents SET binary_sha256 = ?, binary_sha256_at = ? WHERE id = ?`, strings.ToLower(sum), time.Now().Unix(), agentID)
}

// runsBuild reports whether a device reported, within binaryDigestMaxAge, that
// it runs the binary with this digest.
func (d *DB) runsBuild(agentID, sum string) bool {
	if sum == "" {
		return false
	}
	var n int
	err := d.QueryRow(`SELECT COUNT(*) FROM agents WHERE id = ? AND binary_sha256 = ? AND binary_sha256_at >= ?`,
		agentID, strings.ToLower(sum), time.Now().Add(-binaryDigestMaxAge).Unix()).Scan(&n)
	return err == nil && n > 0
}

// agentBuildArch is the architecture of the agent build a device runs: the one
// it announced when it connected, and amd64 as the last resort. The inventory
// is left out on purpose. The fleet listing does not load inventories while a
// single lookup does, so asking the inventory first put a device in one group
// for update-all and in another for update-batch, and a single device whose
// inventory disagreed with its hello made the whole group it was listed in
// impossible to sign. The hello is rewritten on every connect, and for an honest
// agent both are the same runtime.GOARCH. Every update handler asks here, so a
// device lands in the same group however it was looked up.
func agentBuildArch(a *Agent) string {
	if a.Arch != "" {
		return a.Arch
	}
	return "amd64"
}

// agentUpdateFor is the update the server pushes to a device that runs the
// given build, or false when it has no binary for that build. Every handler
// that pushes an update builds the request here, so the payload an operator
// signs for one device is byte for byte the payload every device of that build
// receives.
func (s *Server) agentUpdateFor(fam, arch string) (protocol.AgentUpdate, bool) {
	serverSHA := s.agentBinarySHA256(fam, arch)
	binPath := s.agentBinaryPath(fam, arch)
	if serverSHA == "" || binPath == "" {
		return protocol.AgentUpdate{}, false
	}
	return protocol.AgentUpdate{
		URL:     fmt.Sprintf("%s/api/agent-download/%s", s.PublicURL(), filepath.Base(binPath)),
		SHA256:  serverSHA,
		Version: Version,
	}, true
}

// handleDispatchAgentUpdate pushes ReqAgentUpdate to a specific agent
func (s *Server) handleDispatchAgentUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}

	fam := agentOSFamily(a)
	arch := agentBuildArch(a)
	req, ok := s.agentUpdateFor(fam, arch)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("no agent binary available on server for %s/%s", fam, arch))
		return
	}

	// A device that reported the pushed build's digest has nothing to install,
	// so it is not worth a signature. force=1 is for the operator who wants the
	// binary reinstalled anyway.
	if r.URL.Query().Get("force") != "1" && s.db.runsBuild(id, req.SHA256) {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":         true,
			"up_to_date": true,
			"message":    fmt.Sprintf("%s already runs this build (%s)", agentLabel(a), Version),
		})
		return
	}

	// agent.update replaces the agent's own code: high-risk, and the signed
	// payload carries the binary's SHA-256, which the agent checks after the
	// download, so a server cannot swap the binary under an operator's signature.
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqAgentUpdate, Targets: []string{id}, Payload: req,
		Summary: fmt.Sprintf("Update the agent on %s to %s (binary SHA-256 %s)", agentLabel(a), Version, clip(req.SHA256, 16)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			// Detached from the request like the batch: a browser that closes
			// must not cancel a dispatch that has already been sent.
			ctx, cancel := context.WithTimeout(context.Background(), fleetUpdateReplyWindow)
			defer cancel()
			if err := s.hub.RequestA(ctx, id, protocol.ReqAgentUpdate, req, nil, auth); err != nil {
				switch {
				case errors.Is(err, context.DeadlineExceeded):
					// The device answers once the binary is downloaded and
					// staged, so silence means it is still at it.
					writeJSON(w, http.StatusOK, map[string]any{
						"ok":         true,
						"installing": true,
						"message":    fmt.Sprintf("%s is still downloading and checking the binary; it will restart on its own when done", agentLabel(a)),
					})
				case errors.Is(err, ErrAgentOffline):
					fail(w, fmt.Errorf("failed to dispatch update to agent: %w", err))
				default:
					writeErr(w, http.StatusBadRequest, err.Error())
				}
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":      true,
				"message": fmt.Sprintf("Update command sent to agent %s (%s)", a.DisplayName, Version),
			})
		},
	})
}

// signedUpdateGroup is online devices of one organization that signs its
// actions and run one agent build, at most maxUpdateBatch of them: what a
// single signed update can cover, because a manifest names one organization
// and binds one payload.
type signedUpdateGroup struct {
	Org      string   `json:"org"`
	OrgName  string   `json:"org_name"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	Version  string   `json:"version"`
	SHA256   string   `json:"sha256"`
	AgentIDs []string `json:"agent_ids"`
}

// handleDispatchAllAgentsUpdate pushes ReqAgentUpdate to all online agents of
// organizations that do not sign their actions. The others cannot be reached
// by one unsigned push, and one manifest cannot cover them either: it names
// one organization and binds one payload, while the payload (download URL and
// binary SHA-256) differs per operating system and architecture. Their devices
// are left alone and come back as signed_groups, one per organization and
// build, and each group is signed as one high-risk manifest through
// POST /api/agents/update-batch. That is also why a build run by more than
// maxUpdateBatch online devices of one organization comes back as several
// groups: a group is only worth handing out if update-batch will take it.
func (s *Server) handleDispatchAllAgentsUpdate(w http.ResponseWriter, r *http.Request) {
	agents, err := s.db.ListAgents()
	if err != nil {
		fail(w, err)
		return
	}

	// An organization's bundle costs a database read and a parse, and a build's
	// digest a few file stats, so each is resolved once rather than once per
	// device. That also keeps a group on one digest if a binary is replaced
	// while this runs.
	type build struct{ fam, arch string }
	type groupKey struct{ org, fam, arch string }
	bundles := map[string]*actionauth.Bundle{}
	updates := map[build]*protocol.AgentUpdate{}
	groups := map[groupKey]*signedUpdateGroup{}

	count, skipped, upToDate := 0, 0, 0
	for _, a := range agents {
		if !s.hub.IsOnline(a.ID) {
			continue
		}
		fam, arch := agentOSFamily(a), agentBuildArch(a)
		req, seen := updates[build{fam, arch}]
		if !seen {
			if u, ok := s.agentUpdateFor(fam, arch); ok {
				req = &u
			}
			updates[build{fam, arch}] = req
		}
		if req == nil {
			// Not a device that is up to date: one this server has nothing to
			// send, which the reply counts so that the console does not read
			// an empty result as "nothing needed doing".
			skipped++
			continue
		}
		if s.db.runsBuild(a.ID, req.SHA256) {
			// Already on this build: nothing to send and nothing to sign.
			upToDate++
			continue
		}
		b, seen := bundles[a.OrgID]
		if !seen {
			b = s.activeBundle(a.OrgID)
			bundles[a.OrgID] = b
		}
		if b != nil {
			// Not sent: unsigned, the device would refuse the update (enforce)
			// or install it and report it (audit), so the console is handed
			// the group to get it signed instead.
			k := groupKey{a.OrgID, fam, arch}
			g := groups[k]
			if g == nil {
				g = &signedUpdateGroup{Org: a.OrgID, OrgName: a.OrgName, OS: fam, Arch: arch, Version: req.Version, SHA256: req.SHA256, AgentIDs: []string{}}
				groups[k] = g
			}
			g.AgentIDs = append(g.AgentIDs, a.ID)
			continue
		}
		go func(agentID string, uReq protocol.AgentUpdate) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			_ = s.hub.Request(ctx, agentID, protocol.ReqAgentUpdate, uReq, nil)
		}(a.ID, *req)
		count++
	}

	// The builds are put in order before any of them is cut into pieces: the
	// pieces of one build tie on organization, system and architecture, so an
	// order imposed afterwards would leave theirs to chance.
	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		x, y := keys[i], keys[j]
		if x.org != y.org {
			return x.org < y.org
		}
		if x.fam != y.fam {
			return x.fam < y.fam
		}
		return x.arch < y.arch
	})
	signed := make([]signedUpdateGroup, 0, len(groups))
	devices, orgs := 0, map[string]bool{}
	for _, k := range keys {
		g := groups[k]
		sort.Strings(g.AgentIDs)
		devices += len(g.AgentIDs)
		orgs[g.Org] = true
		// update-batch refuses more than maxUpdateBatch devices at a time, so a
		// bigger group goes out as pieces it accepts, each signed on its own.
		for ids := g.AgentIDs; len(ids) > 0; {
			n := min(len(ids), maxUpdateBatch)
			piece := *g
			piece.AgentIDs = ids[:n:n]
			signed = append(signed, piece)
			ids = ids[n:]
		}
	}

	msg := fmt.Sprintf("Dispatched update command to %d online agent(s)", count)
	if len(signed) > 0 {
		msg += fmt.Sprintf("; %d device(s) in %d organization(s) that sign actions need a signed update", devices, len(orgs))
	}
	if upToDate > 0 {
		msg += fmt.Sprintf("; %d online device(s) already run this build", upToDate)
	}
	if skipped > 0 {
		msg += fmt.Sprintf("; %d online device(s) skipped because this server has no agent build for them", skipped)
	}
	// The unsigned pushes above leave no other record: each signed group is
	// audited by update-batch when it is sent.
	s.audit(r, "fleet.update_all", "", map[string]any{
		"version": Version, "dispatched": count, "signed_groups": len(signed), "signed_devices": devices, "skipped_no_build": skipped, "up_to_date": upToDate,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               true,
		"dispatched_to":    count,
		"signed_groups":    signed,
		"skipped_no_build": skipped,
		"up_to_date":       upToDate,
		"message":          msg,
	})
}

// maxUpdateBatch bounds one signed update. The manifest lists every device it
// covers and travels to each of them with the request, so this keeps both the
// manifest and the fan-out of a single click bounded.
const maxUpdateBatch = 2000

// fleetUpdateReplyWindow is how long a batch waits for its devices to answer.
// agent.update is answered once the binary is downloaded and staged, which a
// slow link can stretch past this, so a device still silent when the window
// closes is reported as installing, not failed. A variable so that a test need
// not wait it out.
var fleetUpdateReplyWindow = 20 * time.Second

// fleetUpdateFailure is a device that did not take an update because it
// answered with an error, or because the request to it could not be completed.
// The name is for the person reading the reply, who knows devices by it and not
// by ID.
type fleetUpdateFailure struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Error string `json:"error"`
}

// Most failures one fleet.update audit entry names, and the longest reason it
// keeps for each. A batch covers up to maxUpdateBatch devices and a device
// writes its own reason, so a fleet that fails in one way would otherwise put
// thousands of long lines in a single audit row. The reply to the operator
// carries every device regardless.
const (
	maxAuditedFailures  = 20
	maxAuditedReasonLen = 200
)

// auditedFailures is what the audit entry keeps of the devices that failed: the
// first few, each with its reason clipped.
func auditedFailures(failed []fleetUpdateFailure) []fleetUpdateFailure {
	n := min(len(failed), maxAuditedFailures)
	out := make([]fleetUpdateFailure, n)
	for i, f := range failed[:n] {
		f.Error = clip(f.Error, maxAuditedReasonLen)
		out[i] = f
	}
	return out
}

// fleetUpdateMessage says what a batch update did, leaving out whatever did not
// happen. The count in front is the devices that took the update (accepted it,
// or are still installing it) out of every device in the batch, so it never
// stands beside buckets that are not part of it. A device is only said to be
// out of reach when it was offline: one that answered with an error was
// reached, and one whose connection dropped half-way may have been.
func fleetUpdateMessage(accepted, installing, offline, failed int) string {
	took := accepted + installing
	var parts []string
	for _, p := range []struct {
		n    int
		what string
	}{{accepted, "accepted"}, {installing, "still installing"}, {offline, "offline"}, {failed, "failed"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.what))
		}
	}
	list := strings.Join(parts, ", ")
	switch {
	case took == 0 && failed == 0:
		return "No device could be reached"
	case took == 0:
		return fmt.Sprintf("No device took the update (%s)", list)
	case offline+failed == 0:
		return fmt.Sprintf("Update command sent to %d device(s): %s", took, list)
	}
	return fmt.Sprintf("%d of %d device(s) took the update: %s", took, took+offline+failed, list)
}

// handleDispatchAgentBatchUpdate pushes one ReqAgentUpdate to a set of devices
// of one organization that run one agent build. It is how an organization that
// signs its actions takes a fleet update: the operator signs a single
// high-risk manifest that names every device and binds the one payload they
// all receive. The sets to send are the signed_groups that POST
// /api/agents/update-all hands back; for an organization that does not sign,
// the same request just sends the update at once.
func (s *Server) handleDispatchAgentBatchUpdate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentIDs []string `json:"agent_ids"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	ids := sortedCopy(in.AgentIDs)
	if len(ids) == 0 {
		writeErr(w, http.StatusBadRequest, "agent_ids required")
		return
	}
	if len(ids) > maxUpdateBatch {
		writeErr(w, http.StatusBadRequest, "too many devices in one update; split the request")
		return
	}
	agents := make([]*Agent, 0, len(ids))
	labels := make(map[string]string, len(ids))
	for _, id := range ids {
		a, err := s.db.GetAgent(id)
		if err != nil {
			fail(w, err)
			return
		}
		agents = append(agents, a)
		labels[id] = agentLabel(a)
	}

	// One manifest names one organization and binds one payload, and the
	// payload is a build's download and digest, so the set must share both.
	org, err := s.orgOfAgents(ids)
	if errors.Is(err, errMixedOrgs) {
		writeErr(w, http.StatusBadRequest, "these devices belong to different organizations; a signed update covers one organization at a time")
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	fam, arch := agentOSFamily(agents[0]), agentBuildArch(agents[0])
	for _, a := range agents {
		f := agentOSFamily(a)
		if f == "" {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("the operating system of %s is unknown", agentLabel(a)))
			return
		}
		if f != fam || agentBuildArch(a) != arch {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("these devices run different agent builds (%s runs %s/%s, %s runs %s/%s); a signed update covers one operating system and architecture at a time",
				agentLabel(a), f, agentBuildArch(a), agentLabel(agents[0]), fam, arch))
			return
		}
	}
	req, ok := s.agentUpdateFor(fam, arch)
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("no agent binary available on server for %s/%s", fam, arch))
		return
	}

	// Devices that reported this build need no update and no signature. They
	// are dropped before the manifest is built, so it names only what is sent.
	upToDate := 0
	keep := ids[:0:0]
	keepAgents := agents[:0:0]
	for i, id := range ids {
		if s.db.runsBuild(id, req.SHA256) {
			upToDate++
			continue
		}
		keep = append(keep, id)
		keepAgents = append(keepAgents, agents[i])
	}
	if len(keep) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"dispatched_to": 0,
			"up_to_date":    upToDate,
			"signed":        false,
			"message":       "every device already runs this build",
		})
		return
	}
	ids, agents = keep, keepAgents

	suffix := ""
	if name := agents[0].OrgName; name != "" {
		suffix = " in " + name
	}
	// agent.update replaces the agent's own code, so this is high-risk like the
	// single-device update, and the same SHA-256 in the signed payload is what
	// every device checks its download against.
	s.runSigned(w, r, signedAction{
		Org: org, Op: protocol.ReqAgentUpdate, Targets: ids, Payload: req,
		Summary: fmt.Sprintf("Update the agent on %d device(s) running %s/%s%s to %s (binary SHA-256 %s)", len(ids), fam, arch, suffix, Version, clip(req.SHA256, 16)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			// Detached from the request on purpose: a console that disconnects
			// half-way would otherwise cancel every dispatch still in flight and
			// leave the update half sent, and the operator is waiting for the
			// answer anyway.
			ctx, cancel := context.WithTimeout(context.Background(), fleetUpdateReplyWindow)
			defer cancel()
			var (
				mu         sync.Mutex
				wg         sync.WaitGroup
				accepted   int
				installing int
				offline    int
				failed     = []fleetUpdateFailure{}
			)
			for _, id := range ids {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					err := s.hub.RequestA(ctx, id, protocol.ReqAgentUpdate, req, nil, auth)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						accepted++
					case errors.Is(err, ErrAgentOffline):
						offline++
					case errors.Is(err, context.DeadlineExceeded):
						// agent.update answers only once the binary is downloaded
						// and staged, so no answer within the window means the
						// device is still at it, not that it failed.
						installing++
					default:
						failed = append(failed, fleetUpdateFailure{ID: id, Name: labels[id], Error: err.Error()})
					}
				}(id)
			}
			wg.Wait()
			sort.Slice(failed, func(i, j int) bool { return failed[i].ID < failed[j].ID })

			// On record before the answer goes out, as the other handlers that
			// reach devices do. r speaks for the operator who asked for the
			// update, at their address, whoever completed the signatures.
			details := map[string]any{
				"targets": len(ids), "os": fam, "arch": arch, "version": Version, "sha256": req.SHA256,
				"accepted": accepted, "installing": installing, "offline": offline, "failed": len(failed), "up_to_date": upToDate,
			}
			// Who failed and why is kept the way the other handlers keep a
			// refusal, so the log can still answer it after the toast is gone.
			if len(failed) > 0 {
				details["failures"] = auditedFailures(failed)
			}
			s.audit(r, "fleet.update", org, details)

			// Whether the update went out under a signature is the reply's to
			// say. It is not the same as the organization signing: audit mode
			// lets an operator continue unsigned, and an organization can stop
			// signing between the listing and here.
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":            true,
				"dispatched_to": accepted + installing,
				"signed":        auth != nil,
				"accepted":      accepted,
				"installing":    installing,
				"offline":       offline,
				"failed":        failed,
				"up_to_date":    upToDate,
				"message":       fleetUpdateMessage(accepted, installing, offline, len(failed)),
			})
		},
	})
}
