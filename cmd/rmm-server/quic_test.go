package main

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/server"
)

// clearQUICEnv keeps a developer's own RMM_QUIC settings out of these tests.
func clearQUICEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RMM_QUIC", "")
	t.Setenv("RMM_QUIC_PORT", "")
}

func TestParseFlagsReadsTheQUICFlags(t *testing.T) {
	clearQUICEnv(t)
	cfg := parseFlags([]string{"--quic", "--quic-port", "9443"})
	if !cfg.QUIC || cfg.QUICPort != 9443 {
		t.Fatalf("QUIC, QUICPort = %v, %d, want true, 9443", cfg.QUIC, cfg.QUICPort)
	}
	if cfg := parseFlags(nil); cfg.QUIC || cfg.QUICPort != 0 {
		t.Fatalf("defaults = %v, %d, want QUIC off and port 0", cfg.QUIC, cfg.QUICPort)
	}
}

func TestQUICEnvironmentWinsOverFlags(t *testing.T) {
	clearQUICEnv(t)
	t.Setenv("RMM_QUIC", "false")
	t.Setenv("RMM_QUIC_PORT", " 9555 ")
	cfg := parseFlags([]string{"--quic", "--quic-port", "9443"})
	if cfg.QUIC || cfg.QUICPort != 9555 {
		t.Fatalf("QUIC, QUICPort = %v, %d, want the environment's false, 9555", cfg.QUIC, cfg.QUICPort)
	}
	t.Setenv("RMM_QUIC", "1")
	if cfg := parseFlags(nil); !cfg.QUIC {
		t.Fatal("RMM_QUIC=1 did not turn QUIC on")
	}
}

func TestQUICEnvironmentTyposAreLoggedAndIgnored(t *testing.T) {
	clearQUICEnv(t)
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	t.Setenv("RMM_QUIC", "yes")
	t.Setenv("RMM_QUIC_PORT", "abc")
	cfg := quicEnv(server.Config{QUICPort: 7})
	if cfg.QUIC || cfg.QUICPort != 7 {
		t.Fatalf("QUIC, QUICPort = %v, %d, want a bad value to leave the flags alone", cfg.QUIC, cfg.QUICPort)
	}
	out := buf.String()
	if !strings.Contains(out, "RMM_QUIC is not a boolean") || !strings.Contains(out, "RMM_QUIC_PORT is not a number") {
		t.Fatalf("log = %q, want a warning for each bad variable", out)
	}
}

func TestInstallArgsCarryTheQUICFlags(t *testing.T) {
	cfg := server.Config{Listen: ":8443", DataDir: "d", QUIC: true, QUICPort: 9443}
	args := installArgs(cfg)
	if want := []string{"--listen", ":8443", "--data", "d", "--quic", "--quic-port", "9443"}; !reflect.DeepEqual(args, want) {
		t.Fatalf("installArgs = %v, want %v", args, want)
	}
	// What the service is started with must parse back to the same settings.
	clearQUICEnv(t)
	back := parseFlags(args)
	if !back.QUIC || back.QUICPort != 9443 {
		t.Fatalf("round trip = %v, %d, want true, 9443", back.QUIC, back.QUICPort)
	}
	cfg.QUICPort = 0
	if args := installArgs(cfg); strings.Contains(strings.Join(args, " "), "--quic-port") {
		t.Fatalf("installArgs = %v, want no --quic-port for the default", args)
	}
	cfg.QUIC = false
	if args := installArgs(cfg); strings.Contains(strings.Join(args, " "), "--quic") {
		t.Fatalf("installArgs = %v, want no QUIC flags when it is off", args)
	}
}

func TestValidateConfigChecksQUICSettings(t *testing.T) {
	base := server.Config{Listen: "127.0.0.1:8443", DataDir: filepath.Join(t.TempDir(), "data")}

	ok := base
	ok.QUIC, ok.QUICPort = true, 8443
	if err := validateConfig(ok); err != nil {
		t.Fatalf("valid QUIC config refused: %v", err)
	}

	insecure := ok
	insecure.Insecure = true
	if err := validateConfig(insecure); err == nil || !strings.Contains(err.Error(), "--insecure") {
		t.Fatalf("--quic with --insecure: err = %v, want a refusal naming --insecure", err)
	}

	for _, port := range []int{-1, 65536} {
		bad := ok
		bad.QUICPort = port
		if err := validateConfig(bad); err == nil || !strings.Contains(err.Error(), "--quic-port") {
			t.Fatalf("--quic-port %d: err = %v, want a refusal naming --quic-port", port, err)
		}
	}

	// With QUIC off the QUIC settings are not looked at.
	off := base
	off.Insecure, off.QUICPort = true, 99999
	if err := validateConfig(off); err != nil {
		t.Fatalf("QUIC off, insecure on: %v", err)
	}
}
