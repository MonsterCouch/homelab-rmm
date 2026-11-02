package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/MonsterCouch/homelab-rmm/internal/actionauth"
	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// uploadRaw posts a raw file body the way the console's fsUpload does.
func uploadRaw(t *testing.T, b *browser, agentID, dest string, data []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", b.base+"/api/agents/"+agentID+"/fs/upload?path="+url.QueryEscape(dest), bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Requested-With", "fetch")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

type stagedReply struct {
	Staged         bool   `json:"staged"`
	CommitRequired bool   `json:"commit_required"`
	UploadID       string `json:"upload_id"`
	Bytes          int64  `json:"bytes"`
	SHA256         string `json:"sha256"`
}

// A file far past the old 1 MiB cap uploads to a device that enforces
// signatures: the bytes are staged unsigned, and the operator signs a commit
// naming only the destination, size and digest.
func TestSignedUploadStagesThenCommits(t *testing.T) {
	f := newSignFixture(t, actionauth.ModeEnforce, 1, 10)
	ag := f.addAgent("box")
	data := make([]byte, 3<<20+12345)
	rand.Read(data)
	sum := sha256.Sum256(data)
	dest := "/srv/drop/tool.bin"

	st, raw := uploadRaw(t, f.admin, ag.ID(), dest, data)
	if st != 200 {
		t.Fatalf("upload = %d %s", st, raw)
	}
	var sr stagedReply
	json.Unmarshal(raw, &sr)
	if !sr.Staged || !sr.CommitRequired || sr.Bytes != int64(len(data)) || sr.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("staging reply %+v", sr)
	}
	// The agent got the whole file as unsigned fs.stage chunks, in order,
	// and needed no signature for them.
	var staged []byte
	for _, x := range ag.requests(protocol.ReqFsStage) {
		var fs protocol.FsStage
		json.Unmarshal(x.Env.D, &fs)
		if fs.UploadID != sr.UploadID || fs.Offset != int64(len(staged)) || !x.Dec.Allow || x.Dec.Err != nil {
			t.Fatalf("stage chunk %+v decision %+v", fs, x.Dec)
		}
		staged = append(staged, fs.Data...)
	}
	if !bytes.Equal(staged, data) {
		t.Fatalf("staged %d bytes, uploaded %d", len(staged), len(data))
	}
	if len(ag.requests(protocol.ReqFsWrite)) != 0 {
		t.Error("a signing org fell back to unsigned fs.write")
	}

	// The commit asks for a signature over a digest, not over the bytes.
	commit := map[string]any{"upload_id": sr.UploadID}
	path := "/api/agents/" + ag.ID() + "/fs/commit"
	st, raw = f.admin.do("POST", path, commit)
	if st != 428 {
		t.Fatalf("unsigned commit = %d %s", st, raw)
	}
	var ch challenge
	json.Unmarshal(raw, &ch)
	m := ch.parsed(t)
	var fc protocol.FsCommit
	json.Unmarshal(m.Payload, &fc)
	if m.Op != protocol.ReqFsCommit || fc.Path != dest || fc.Size != int64(len(data)) || fc.SHA256 != sr.SHA256 || len(ch.bytes(t)) > 4096 {
		t.Fatalf("commit manifest %s (%d bytes)", ch.bytes(t), len(ch.bytes(t)))
	}

	// Another operator cannot commit (or even see) this upload.
	if st, raw := f.bob.do("POST", path, commit); st != 410 {
		t.Errorf("bob committing admin's upload = %d %s", st, raw)
	}

	if st, raw := f.admin.doHdr("POST", path, commit, ch.signedBy(t, f.ka)); st != 200 {
		t.Fatalf("signed commit = %d %s", st, raw)
	}
	got := ag.wait(protocol.ReqFsCommit, 1)[0]
	if got.Env.A == nil || !got.Dec.Verified || !got.Dec.Allow {
		t.Fatalf("commit reached the agent without a verifying signature: %+v", got.Dec)
	}
	var ran protocol.FsCommit
	json.Unmarshal(got.Dec.Payload, &ran)
	if ran != fc {
		t.Errorf("agent would commit %+v, signed %+v", ran, fc)
	}
	// Done: the same upload cannot be committed twice.
	if st, _ := f.admin.do("POST", path, commit); st != 410 {
		t.Errorf("second commit of a finished upload = %d", st)
	}
}

// Without a trust bundle nothing changes: the file goes straight out as
// fs.write chunks and no commit is needed.
func TestUnsignedOrgUploadUnchanged(t *testing.T) {
	f := newSignFixture(t, "", 1, 10)
	ag := f.addAgent("box")
	data := bytes.Repeat([]byte("x"), 70_000)
	st, raw := uploadRaw(t, f.admin, ag.ID(), "/tmp/plain.txt", data)
	if st != 200 {
		t.Fatalf("upload = %d %s", st, raw)
	}
	var sr stagedReply
	json.Unmarshal(raw, &sr)
	if sr.CommitRequired || len(ag.requests(protocol.ReqFsStage)) != 0 || len(ag.wait(protocol.ReqFsWrite, 1)) == 0 {
		t.Fatalf("an org without a bundle took the staging path: %s", raw)
	}
}
