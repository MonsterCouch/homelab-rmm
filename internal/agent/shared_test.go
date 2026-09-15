package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

func TestScriptRunnerStreamsAndExitCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash test")
	}
	r := newScriptRunner()
	var chunks []protocol.ScriptChunk
	res := r.run(context.Background(), protocol.ScriptRun{RunID: "r1", Language: "bash", Body: "echo out1\necho err1 >&2\necho \"$1 $RMM_RUN_ID\"\nexit 7", Args: []string{"arg"}, Timeout: 10}, func(c protocol.ScriptChunk) {
		chunks = append(chunks, c)
	})
	if res.ExitCode != 7 || res.TimedOut || res.Error != "" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !strings.Contains(res.Stdout, "out1") || !strings.Contains(res.Stdout, "arg r1") || !strings.Contains(res.Stderr, "err1") {
		t.Fatalf("output wrong: %+v", res)
	}
	var sawErr bool
	for _, c := range chunks {
		if c.Stream == "stderr" && strings.Contains(c.Data, "err1") {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatal("stderr was not streamed")
	}
}

func TestScriptRunnerTimeoutAndCancel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash test")
	}
	r := newScriptRunner()
	start := time.Now()
	res := r.run(context.Background(), protocol.ScriptRun{RunID: "t1", Language: "bash", Body: "sleep 30", Timeout: 1}, func(protocol.ScriptChunk) {})
	if !res.TimedOut {
		t.Fatalf("expected timeout, got %+v", res)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("timeout did not kill the process promptly (%s)", time.Since(start))
	}
	// cancel
	done := make(chan *protocol.ScriptResult, 1)
	go func() {
		done <- r.run(context.Background(), protocol.ScriptRun{RunID: "c1", Language: "bash", Body: "sleep 30", Timeout: 60}, func(protocol.ScriptChunk) {})
	}()
	time.Sleep(300 * time.Millisecond)
	r.cancel("c1")
	select {
	case res := <-done:
		if res.Error != "cancelled" {
			t.Fatalf("expected cancelled, got %+v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not stop the script")
	}
}

func TestScriptRunnerRejectsUnknownLanguage(t *testing.T) {
	r := newScriptRunner()
	res := r.run(context.Background(), protocol.ScriptRun{RunID: "x", Language: "cobol", Body: "x"}, func(protocol.ScriptChunk) {})
	if res.Error == "" {
		t.Fatal("expected an error for an unknown language")
	}
}

func TestFilesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "f.txt")
	if err := fsWrite(protocol.FsWrite{Path: p, Data: []byte("hello ")}); err != nil {
		t.Fatal(err)
	}
	if err := fsWrite(protocol.FsWrite{Path: p, Data: []byte("world"), Append: true}); err != nil {
		t.Fatal(err)
	}
	rd, err := fsRead(protocol.FsRead{Path: p, Offset: 6, Length: 100})
	if err != nil || string(rd.Data) != "world" || !rd.EOF || rd.Size != 11 {
		t.Fatalf("read wrong: %+v %v", rd, err)
	}
	ls, err := fsList(filepath.Join(dir, "sub"))
	if err != nil || len(ls.Entries) != 1 || ls.Entries[0].Name != "f.txt" || ls.Entries[0].Size != 11 {
		t.Fatalf("list wrong: %+v %v", ls, err)
	}
	roots, err := fsList("")
	if err != nil || len(roots.Entries) == 0 {
		t.Fatalf("roots wrong: %+v %v", roots, err)
	}
	if err := fsDelete("/"); err == nil {
		t.Fatal("deleting root must be refused")
	}
	if err := fsDelete(filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("delete did not remove the directory")
	}
	if _, err := fsRead(protocol.FsRead{Path: dir}); err == nil {
		t.Fatal("reading a directory must fail")
	}
}

func TestMagicPacket(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no udp:", err)
	}
	defer pc.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	// send to loopback instead of broadcast by abusing the broadcast parameter
	if err := sendMagicPacketTo("aa:bb:cc:dd:ee:ff", "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 200)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 102 || buf[0] != 0xff || buf[6] != 0xaa || buf[101] != 0xff {
		t.Fatalf("malformed magic packet: n=%d", n)
	}
	if err := sendMagicPacket("zz", ""); err == nil {
		t.Fatal("bad MAC must fail")
	}
}

func TestCollectMetricsAndInventory(t *testing.T) {
	m := collectMetrics(nil)
	if m.MemTotal == 0 || m.TS == 0 {
		t.Fatalf("metrics look empty: %+v", m)
	}
	inv, err := collectInventory()
	if err != nil {
		t.Fatal(err)
	}
	if inv.Hostname == "" || inv.CPUThreads == 0 || inv.MemTotal == 0 {
		t.Fatalf("inventory incomplete: host=%q threads=%d mem=%d", inv.Hostname, inv.CPUThreads, inv.MemTotal)
	}
}
