package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/MonsterCouch/homelab-rmm/internal/protocol"
)

// Uploads to devices that check signatures. An operator cannot sign a file's
// bytes - they would have to travel inside the manifest - so the upload is
// streamed with fs.stage into the agent's private staging area, and what the
// operator signs is fs.commit: the destination, the size and the SHA-256 the
// server computed while streaming. The agent recomputes the digest over the
// bytes it actually moves into place, so a server that staged anything else
// gets a refusal, not a file. See internal/agent/files_stage.go.

// stagedUploadTTL matches the agent's: an upload not committed within the hour
// is gone on both sides.
const stagedUploadTTL = 3600

type stagedUpload struct {
	agentID   string
	path      string
	size      int64
	sha256    string
	userID    int64
	expiresAt int64
}

func (st *signingState) putStaged(id string, u *stagedUpload) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()
	if st.staged == nil {
		st.staged = map[string]*stagedUpload{}
	}
	st.staged[id] = u
}

// stagedFor returns the upload only to the operator who staged it, for the
// agent it was staged on.
func (st *signingState) stagedFor(id string, userID int64, agentID string) *stagedUpload {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sweepLocked()
	u := st.staged[id]
	if u == nil || u.userID != userID || u.agentID != agentID {
		return nil
	}
	return u
}

func (st *signingState) dropStaged(id string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	delete(st.staged, id)
}

// stageUpload streams the request body to the agent's staging area and
// answers with what the console must ask the operator to sign.
func (s *Server) stageUpload(w http.ResponseWriter, r *http.Request, a *Agent, dest string) {
	u := userFrom(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	uploadID := "upl_" + randomToken(18)
	ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
	defer cancel()
	h := sha256.New()
	buf := make([]byte, fsChunk)
	var off int64
	first := true
	for {
		n, rerr := io.ReadFull(r.Body, buf)
		if n > 0 || first { // an empty file still needs its (empty) staging file
			chunk := buf[:n]
			if err := s.hub.Request(ctx, a.ID, protocol.ReqFsStage, protocol.FsStage{UploadID: uploadID, Offset: off, Data: chunk}, nil); err != nil {
				fail(w, err)
				return
			}
			h.Write(chunk)
			off += int64(n)
			first = false
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			fail(w, rerr)
			return
		}
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.signing.putStaged(uploadID, &stagedUpload{agentID: a.ID, path: dest, size: off, sha256: sum, userID: u.ID, expiresAt: now() + stagedUploadTTL})
	writeJSON(w, 200, map[string]any{"staged": true, "commit_required": true, "upload_id": uploadID, "bytes": off, "sha256": sum})
}

// handleFsCommit asks the agent to move a staged upload into place. It goes
// through the signing flow like any other action; the signed payload names
// the digest, never the bytes.
func (s *Server) handleFsCommit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a, ok := s.getScopedAgent(w, r, id)
	if !ok {
		return
	}
	var in struct {
		UploadID string `json:"upload_id"`
	}
	if err := readJSON(r, &in); err != nil {
		fail(w, err)
		return
	}
	u := userFrom(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "not signed in")
		return
	}
	up := s.signing.stagedFor(in.UploadID, u.ID, id)
	if up == nil {
		writeErr(w, http.StatusGone, "this upload is unknown or has expired; upload the file again")
		return
	}
	payload := protocol.FsCommit{UploadID: in.UploadID, Path: up.path, Size: up.size, SHA256: up.sha256}
	s.runSigned(w, r, signedAction{
		Org: a.OrgID, Op: protocol.ReqFsCommit, Targets: []string{id}, Payload: payload,
		Summary: fmt.Sprintf("Write %s (%d bytes, SHA-256 %s) on %s", up.path, up.size, up.sha256, agentLabel(a)),
		Run: func(w http.ResponseWriter, r *http.Request, auth *protocol.ActionAuth) {
			ctx, cancel := context.WithTimeout(r.Context(), longTimeout)
			defer cancel()
			if err := s.hub.RequestA(ctx, id, protocol.ReqFsCommit, payload, nil, auth); err != nil {
				fail(w, err)
				return
			}
			s.signing.dropStaged(in.UploadID)
			s.audit(r, "file.upload", id, map[string]any{"path": up.path, "bytes": up.size, "sha256": up.sha256})
			writeJSON(w, 200, map[string]any{"ok": true, "bytes": up.size})
		},
	})
}
