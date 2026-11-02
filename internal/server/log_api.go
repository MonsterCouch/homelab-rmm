package server

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/MonsterCouch/homelab-rmm/internal/translog"
)

// The transparency log endpoints. Heads and proofs are public on purpose:
// they carry only hashes and sizes, and an auditor outside the console (the
// `rmm-server log verify` command, a device operator with curl) must be able
// to check that the log only grew without holding a session. What the leaves
// say (who ran what, where) needs an administrator.

func (s *Server) logOr503(w http.ResponseWriter) *translog.Log {
	if s.tlog == nil {
		writeErr(w, http.StatusServiceUnavailable, "this server has no transparency log")
		return nil
	}
	return s.tlog
}

// logFailed answers an unauthenticated caller without the error text: storage
// and proof errors name tables and sizes that are the operator's business.
func logFailed(w http.ResponseWriter, what string, err error) {
	slog.Warn("transparency log request failed", "request", what, "err", err)
	writeErr(w, http.StatusInternalServerError, "the transparency log could not answer")
}

// handleLogHead answers the current signed head.
func (s *Server) handleLogHead(w http.ResponseWriter, r *http.Request) {
	l := s.logOr503(w)
	if l == nil {
		return
	}
	tree, note, err := l.Head()
	if err != nil {
		logFailed(w, "head", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"size": tree.N, "hash": tree.Hash.String(), "key": l.VerifierKey(),
		"note": base64.StdEncoding.EncodeToString(note),
	})
}

// handleLogProof answers the inclusion proof of one leaf at the current head.
func (s *Server) handleLogProof(w http.ResponseWriter, r *http.Request) {
	l := s.logOr503(w)
	if l == nil {
		return
	}
	index, err := strconv.ParseInt(r.URL.Query().Get("index"), 10, 64)
	if err != nil || index < 0 {
		writeErr(w, http.StatusBadRequest, "index must be a leaf number, zero or more")
		return
	}
	tree, note, err := l.Head()
	if err != nil {
		logFailed(w, "proof", err)
		return
	}
	if index >= tree.N {
		writeErr(w, http.StatusNotFound, "the log has no leaf "+strconv.FormatInt(index, 10)+" yet; it holds "+strconv.FormatInt(tree.N, 10))
		return
	}
	proof, err := l.ProveInclusion(index, tree.N)
	if err != nil {
		logFailed(w, "proof", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"size": tree.N, "hash": tree.Hash.String(), "note": base64.StdEncoding.EncodeToString(note),
		"index": index, "proof": translog.EncodeProof(proof),
	})
}

// handleLogConsistency proves that the head of size `from` is a prefix of the
// head of size `to` (the current size when omitted).
func (s *Server) handleLogConsistency(w http.ResponseWriter, r *http.Request) {
	l := s.logOr503(w)
	if l == nil {
		return
	}
	q := r.URL.Query()
	from, err := strconv.ParseInt(q.Get("from"), 10, 64)
	if err != nil || from < 1 {
		writeErr(w, http.StatusBadRequest, "from must be a log size of at least 1")
		return
	}
	tree, _, err := l.Head()
	if err != nil {
		logFailed(w, "consistency", err)
		return
	}
	to := tree.N
	if v := q.Get("to"); v != "" {
		if to, err = strconv.ParseInt(v, 10, 64); err != nil {
			writeErr(w, http.StatusBadRequest, "to must be a log size")
			return
		}
	}
	if to < from || to > tree.N {
		writeErr(w, http.StatusBadRequest, "to must be at least from and at most the log's current size of "+strconv.FormatInt(tree.N, 10))
		return
	}
	if from > tree.N {
		writeErr(w, http.StatusBadRequest, "from is larger than the log's current size of "+strconv.FormatInt(tree.N, 10))
		return
	}
	proof, err := l.ProveConsistency(from, to)
	if err != nil {
		logFailed(w, "consistency", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "proof": translog.EncodeProof(proof)})
}

// handleLogEntry answers one leaf's content (administrators only).
func (s *Server) handleLogEntry(w http.ResponseWriter, r *http.Request) {
	l := s.logOr503(w)
	if l == nil {
		return
	}
	index, err := strconv.ParseInt(r.PathValue("index"), 10, 64)
	if err != nil || index < 0 {
		writeErr(w, http.StatusBadRequest, "index must be a leaf number, zero or more")
		return
	}
	kind, data, ts, err := l.Leaf(index)
	if err != nil {
		writeErr(w, http.StatusNotFound, "the log has no leaf "+strconv.FormatInt(index, 10))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"index": index, "kind": kind, "data": base64.StdEncoding.EncodeToString(data), "ts": ts,
	})
}
