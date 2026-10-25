package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
	"github.com/MonsterCouch/homelab-rmm/internal/supervisor"
)

// writeTestBinaryBytes creates an executable test binary payload with valid or invalid header.
func writeTestBinaryBytes(t *testing.T, version string, valid bool) (string, []byte) {
	t.Helper()
	var payload []byte
	if valid {
		if runtime.GOOS == "windows" {
			// PE MZ header: 0x4D, 0x5A
			payload = append([]byte{0x4D, 0x5A, 0x90, 0x00}, []byte("HomelabRMM-Binary-"+version)...)
		} else {
			// ELF header: \x7fELF
			payload = append([]byte{0x7F, 'E', 'L', 'F'}, []byte("HomelabRMM-Binary-"+version)...)
		}
	} else {
		payload = []byte("INVALID_HEADER_DATA_" + version)
	}
	h := sha256.Sum256(payload)
	return hex.EncodeToString(h[:]), payload
}

// What agent.update installs runs as SYSTEM/root on the next restart. An
// empty sha256 used to skip verification entirely, and the transport is no
// backstop: a device with no pinned fingerprint gets a plain tls.Config, and
// the URL was unconstrained, so http:// bypassed TLS altogether (upd-01).
func TestSelfUpdateRequiresAHashAndRefusesBeforeFetching(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("payload"))
	}))
	defer srv.Close()
	cfg := &Config{ServerURL: srv.URL}

	for _, sum := range []string{
		"",
		"deadbeef",
		strings.Repeat("z", 64),
		strings.Repeat("a", 63),
		" " + strings.Repeat("a", 64),
	} {
		err := doSelfUpdate(context.Background(), cfg, srv.URL+"/rmm-agent", sum)
		if err == nil {
			t.Errorf("sha256 %q was accepted", sum)
			continue
		}
		if !strings.Contains(err.Error(), "sha256") {
			t.Errorf("sha256 %q: the refusal must name the reason, got %v", sum, err)
		}
	}
	if hits != 0 {
		t.Errorf("the binary was downloaded %d times before the hash was checked", hits)
	}
}

// The URL decides which host gets to hand this machine its next SYSTEM
// binary, so it is bounded too.
func TestCheckUpdateURL(t *testing.T) {
	const server = "http://rmm.lan:18080"
	for _, u := range []string{
		"https://rmm.lan:8443/api/agent-download/rmm-agent-windows-amd64.exe",
		"https://releases.example.com/rmm-agent",
		"http://rmm.lan:18080/api/agent-download/rmm-agent-linux-amd64",
		"HTTP://RMM.LAN:18080/x", // the host comparison is case-insensitive
	} {
		if err := checkUpdateURL(server, u); err != nil {
			t.Errorf("%s should be allowed: %v", u, err)
		}
	}
	for _, u := range []string{
		"http://attacker.example/x.exe",
		"http://rmm.lan:9999/x.exe", // same name, another port, another server
		"file:///C:/Windows/Temp/x.exe",
		"ftp://rmm.lan/x.exe",
		"/relative/path",
		"",
	} {
		if err := checkUpdateURL(server, u); err == nil {
			t.Errorf("%s must be refused", u)
		}
	}
	// A server the agent cannot parse is not a reason to trust plain http.
	if err := checkUpdateURL("", "http://rmm.lan/x"); err == nil {
		t.Error("plain http was accepted with no configured server to match")
	}
}

func TestSelfUpdate_StagedFlow(t *testing.T) {
	slotDir := t.TempDir()

	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	restartReqCh := make(chan *supervisor.IPCMessage, 1)

	srv.RegisterHandler(supervisor.MsgGetInactive, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{
			Type: supervisor.MsgInactiveResp,
			Slot: "slot_b",
			Path: slotDir,
		}, nil
	})

	srv.RegisterHandler(supervisor.MsgRequestRestart, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		restartReqCh <- msg
		return nil, nil
	})

	if err := srv.Start(pipe); err != nil {
		t.Fatalf("start srv: %v", err)
	}

	clientConn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(clientConn)
	defer client.Close()

	targetVersion := "v2.0.0"
	sum, payload := writeTestBinaryBytes(t, targetVersion, true)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	}))
	defer httpSrv.Close()

	// Intercept worker exit
	origExit := updateExitFunc
	origDelay := updateExitDelay
	exitCalled := make(chan int, 1)
	updateExitFunc = func(code int) {
		exitCalled <- code
	}
	updateExitDelay = 10 * time.Millisecond
	defer func() {
		updateExitFunc = origExit
		updateExitDelay = origDelay
	}()

	cfg := &Config{ServerURL: httpSrv.URL}
	req := protocol.AgentUpdate{
		URL:     httpSrv.URL + "/download",
		SHA256:  sum,
		Version: targetVersion,
	}

	err = ApplyStagedUpdate(context.Background(), cfg, req, client)
	if err != nil {
		t.Fatalf("ApplyStagedUpdate failed: %v", err)
	}

	// Verify target binary written in slotDir
	targetBin := filepath.Join(slotDir, supervisor.BinaryExecutableName)
	data, err := os.ReadFile(targetBin)
	if err != nil {
		t.Fatalf("target binary not found: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("payload content mismatch")
	}

	// Verify restart message sent
	select {
	case msg := <-restartReqCh:
		if msg.Reason != "update_staged" {
			t.Errorf("expected reason 'update_staged', got %s", msg.Reason)
		}
		if msg.Version != targetVersion {
			t.Errorf("expected version %s, got %s", targetVersion, msg.Version)
		}
		if msg.PID != os.Getpid() {
			t.Errorf("expected PID %d, got %d", os.Getpid(), msg.PID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for MsgRequestRestart")
	}

	// Verify worker exit scheduled
	select {
	case code := <-exitCalled:
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for worker exit")
	}
}

func TestSelfUpdate_RejectsInvalidHeader(t *testing.T) {
	slotDir := t.TempDir()

	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	srv.RegisterHandler(supervisor.MsgGetInactive, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{
			Type: supervisor.MsgInactiveResp,
			Slot: "slot_b",
			Path: slotDir,
		}, nil
	})

	_ = srv.Start(pipe)

	clientConn, _ := pipe.Dial()
	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(clientConn)
	defer client.Close()

	sum, invalidPayload := writeTestBinaryBytes(t, "v2.0.0", false)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(invalidPayload)
	}))
	defer httpSrv.Close()

	cfg := &Config{ServerURL: httpSrv.URL}
	req := protocol.AgentUpdate{
		URL:     httpSrv.URL + "/download",
		SHA256:  sum,
		Version: "v2.0.0",
	}

	err := ApplyStagedUpdate(context.Background(), cfg, req, client)
	if err == nil {
		t.Fatal("expected error on invalid binary header, got nil")
	}
	if !strings.Contains(err.Error(), "validate binary header") {
		t.Errorf("expected 'validate binary header' in error, got: %v", err)
	}

	// Target binary must not have been created
	targetBin := filepath.Join(slotDir, supervisor.BinaryExecutableName)
	if _, err := os.Stat(targetBin); !os.IsNotExist(err) {
		t.Errorf("target binary should not exist after rejection")
	}
}

func TestSelfUpdate_ChecksumMismatch(t *testing.T) {
	slotDir := t.TempDir()

	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()

	srv := supervisor.NewIPCServer()
	defer srv.Stop()

	srv.RegisterHandler(supervisor.MsgGetInactive, func(msg *supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
		return &supervisor.IPCMessage{
			Type: supervisor.MsgInactiveResp,
			Slot: "slot_b",
			Path: slotDir,
		}, nil
	})

	_ = srv.Start(pipe)

	clientConn, _ := pipe.Dial()
	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(clientConn)
	defer client.Close()

	_, payload := writeTestBinaryBytes(t, "v2.0.0", true)

	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer httpSrv.Close()

	cfg := &Config{ServerURL: httpSrv.URL}
	req := protocol.AgentUpdate{
		URL:     httpSrv.URL + "/download",
		SHA256:  strings.Repeat("a", 64), // Mismatched SHA-256
		Version: "v2.0.0",
	}

	err := ApplyStagedUpdate(context.Background(), cfg, req, client)
	if err == nil {
		t.Fatal("expected error on checksum mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("expected 'checksum mismatch' in error, got: %v", err)
	}

	targetBin := filepath.Join(slotDir, supervisor.BinaryExecutableName)
	if _, err := os.Stat(targetBin); !os.IsNotExist(err) {
		t.Errorf("target binary should not exist after checksum mismatch")
	}
}

func TestSelfUpdate_StandaloneMode(t *testing.T) {
	t.Setenv("RMM_ALLOW_LEGACY_UPDATE", "")

	cfg := &Config{ServerURL: "https://rmm.lan:8443"}
	req := protocol.AgentUpdate{
		URL:     "https://rmm.lan:8443/download",
		SHA256:  strings.Repeat("a", 64),
		Version: "v2.0.0",
	}

	err := ApplyStagedUpdate(context.Background(), cfg, req, nil)
	if err == nil {
		t.Fatal("expected error in standalone mode without supervisor IPC, got nil")
	}
	if !strings.Contains(err.Error(), "standalone mode") {
		t.Errorf("expected 'standalone mode' in error, got: %v", err)
	}
}

// A push of the build the device already runs has nothing to install, so it is
// answered as done without touching the network, the supervisor or the process:
// no download, no slot staged or flipped, no restart. The running executable is
// the test binary, so its own digest is the build in question. A different
// digest still goes the whole way (TestSelfUpdate_StagedFlow); the same digest
// in capitals is the same digest, and is answered as done as well.
func TestSelfUpdate_SameBuildIsAlreadyDone(t *testing.T) {
	cur := currentBinarySHA256()
	if cur == "" {
		t.Skip("the running test binary cannot be hashed here")
	}

	var downloads atomic.Int32
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer httpSrv.Close()

	pipe := supervisor.NewInMemoryPipe()
	defer pipe.Close()
	srv := supervisor.NewIPCServer()
	defer srv.Stop()
	var asked atomic.Int32
	for _, typ := range []supervisor.MessageType{supervisor.MsgGetInactive, supervisor.MsgRequestRestart} {
		srv.RegisterHandler(typ, func(*supervisor.IPCMessage) (*supervisor.IPCMessage, error) {
			asked.Add(1)
			return nil, errors.New("the supervisor must not be asked")
		})
	}
	if err := srv.Start(pipe); err != nil {
		t.Fatalf("start srv: %v", err)
	}
	clientConn, err := pipe.Dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	client := supervisor.NewIPCClient(nil, 2*time.Second)
	_ = client.Connect(clientConn)
	defer client.Close()

	origExit, origDelay := updateExitFunc, updateExitDelay
	var exits atomic.Int32
	updateExitFunc = func(int) { exits.Add(1) }
	updateExitDelay = time.Millisecond
	defer func() { updateExitFunc, updateExitDelay = origExit, origDelay }()

	cfg := &Config{ServerURL: httpSrv.URL}
	for _, sha := range []string{cur, strings.ToUpper(cur)} {
		req := protocol.AgentUpdate{URL: httpSrv.URL + "/download", SHA256: sha, Version: "v9.9.9"}
		if err := ApplyStagedUpdate(context.Background(), cfg, req, client); err != nil {
			t.Fatalf("a push of the running build (%s) must be answered as done, got %v", sha[:8], err)
		}
		// Standalone, where an update cannot be applied at all: the device is
		// still on the build it was asked for.
		if err := ApplyStagedUpdate(context.Background(), cfg, req, nil); err != nil {
			t.Fatalf("a standalone device already on the build must answer as done, got %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := downloads.Load(); n != 0 {
		t.Errorf("the build the device already runs was downloaded %d times", n)
	}
	if n := asked.Load(); n != 0 {
		t.Errorf("the supervisor was asked %d times to stage or restart for a build that is already running", n)
	}
	if n := exits.Load(); n != 0 {
		t.Errorf("the worker was scheduled to exit %d times", n)
	}

	// The pre-flight checks still come first: an invalid request for the running
	// build is refused, not waved through as done.
	if err := ApplyStagedUpdate(context.Background(), cfg, protocol.AgentUpdate{URL: "file:///etc/passwd", SHA256: cur}, client); err == nil {
		t.Error("a url outside the server was accepted because the digest matched the running build")
	}
}
